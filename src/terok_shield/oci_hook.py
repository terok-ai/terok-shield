# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""OCI hook entry point for container firewall.

This module is invoked by podman as an OCI hook at ``createRuntime``
and ``poststop`` stages.  It reads annotations from the OCI state and
applies the hook-mode firewall.

The hook is fail-closed: if any step fails during ``createRuntime``,
it exits non-zero and the container must not start with unrestricted
network access.

Provides ``HookExecutor`` (Command pattern) for the actual firewall
application, and ``hook_main()`` as a thin entry point.
"""

from __future__ import annotations

import ipaddress
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from . import state
from .audit import AuditLogger
from .config import (
    ANNOTATION_AUDIT_ENABLED_KEY,
    ANNOTATION_LOOPBACK_PORTS_KEY,
    ANNOTATION_STATE_DIR_KEY,
    ANNOTATION_VERSION_KEY,
)
from .nft import RulesetBuilder
from .podman_info import parse_resolv_conf
from .run import ExecError, SubprocessRunner

if TYPE_CHECKING:
    from .run import CommandRunner

_PRIVATE_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
)

_BROAD_PREFIX_V4 = 16
_BROAD_PREFIX_V6 = 48


# ── Classification helpers ───────────────────────────────


def _classify_cidr(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> tuple[bool, bool]:
    """Classify a CIDR as private and/or broad.

    Returns:
        Tuple of (is_private, is_broad).
    """
    threshold = _BROAD_PREFIX_V4 if net.version == 4 else _BROAD_PREFIX_V6
    is_broad = net.prefixlen <= threshold
    is_private = any(
        net.subnet_of(priv) for priv in _PRIVATE_NETWORKS if net.version == priv.version
    )
    return is_private, is_broad


def _is_private_addr(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if a single address falls within a private range."""
    return any(addr in priv for priv in _PRIVATE_NETWORKS if addr.version == priv.version)


def _classify_ips(ips: list[str]) -> tuple[list[str], list[str]]:
    """Classify IPs into private-range and broad-range lists for logging.

    Handles both IPv4 (RFC 1918/RFC 3927) and IPv6 (RFC 4193/RFC 4291).

    Returns:
        Tuple of (private_ips, broad_cidrs). Does not affect which IPs
        are added to the allow set -- classification is logging-only.
    """
    private: list[str] = []
    broad: list[str] = []
    for ip_str in ips:
        try:
            if "/" in ip_str:
                is_priv, is_broad = _classify_cidr(ipaddress.ip_network(ip_str, strict=False))
                if is_broad:
                    broad.append(ip_str)
                if is_priv:
                    private.append(ip_str)
            else:
                if _is_private_addr(ipaddress.ip_address(ip_str)):
                    private.append(ip_str)
        except ValueError:
            continue
    return private, broad


# ── OCI state parsing ────────────────────────────────────


def _parse_oci_state(stdin_data: str) -> tuple[str, str, dict[str, str]]:
    """Parse OCI state JSON from stdin.

    Returns:
        Tuple of (container_id, pid, annotations).  ``pid`` is an empty
        string when absent or zero (expected for ``poststop`` hooks).

    Raises:
        ValueError: If the state is missing ``id`` or is not valid JSON.
    """
    try:
        oci_state = json.loads(stdin_data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid OCI state JSON: {e}") from e
    if not isinstance(oci_state, dict):
        raise ValueError(f"OCI state must be a JSON object: {oci_state!r}")
    cid = oci_state.get("id")
    if not cid:
        raise ValueError(f"OCI state missing id: {oci_state!r}")
    pid = oci_state.get("pid", 0)
    annotations = oci_state.get("annotations", {})
    if not isinstance(annotations, dict):
        annotations = {}
    # Normalize values to strings (OCI spec says string, but be defensive)
    annotations = {str(k): str(v) for k, v in annotations.items()}
    return str(cid), str(pid) if pid else "", annotations


def _parse_loopback_ports(raw: str) -> tuple[int, ...]:
    """Parse comma-separated loopback ports from annotation value."""
    if not raw:
        return ()
    ports: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            port = int(part)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            ports.append(port)
    return tuple(ports)


# ── HookExecutor (Command) ──────────────────────────────


class HookExecutor:
    """Command: apply the shield firewall inside a container's network namespace.

    Runtime counterpart of ``HookMode``: while ``HookMode`` prepares
    containers (DNS resolution, hook installation, podman args),
    ``HookExecutor`` actually applies the firewall when podman triggers
    the OCI hook.
    """

    def __init__(
        self,
        *,
        runner: CommandRunner,
        audit: AuditLogger,
        ruleset: RulesetBuilder,
        state_dir: Path,
    ) -> None:
        """Create a hook executor.

        Args:
            runner: Command runner for nft subprocess calls.
            audit: Audit logger for event logging.
            ruleset: Ruleset builder for generation and verification.
            state_dir: Per-container state directory.
        """
        self._runner = runner
        self._audit = audit
        self._ruleset = ruleset
        self._state_dir = state_dir

    def apply(self, container: str, pid: str) -> None:
        """Apply ruleset, load cached IPs, verify.  Fail-closed.

        Intentionally logs two "setup" audit events at different granularity:
        ``_apply_ruleset`` logs the raw nft apply, this method logs the
        high-level summary with IP count.
        """
        self._apply_ruleset(container, pid)
        ip_count = self._load_and_add_ips(container, pid)
        self._verify(container, pid)
        self._audit.log_event(container, "setup", detail=f"applied with {ip_count} allowed IPs")

    def _apply_ruleset(self, container: str, pid: str) -> None:
        """Apply the hook ruleset to the container."""
        self._nft_exec(
            container,
            pid,
            stdin=self._ruleset.build_hook(),
        )
        self._audit.log_event(container, "setup", detail="ruleset applied")

    def _load_and_add_ips(self, container: str, pid: str) -> int:
        """Read cached IPs, classify, log, and add to the allow set."""
        try:
            ips = self._read_allowed_ips()
        except (OSError, UnicodeError) as e:
            self._audit.log_event(container, "error", detail=f"resolved cache read failed: {e}")
            raise RuntimeError(f"Failed to read resolved cache: {e}") from e

        self._audit.log_event(container, "setup", detail=f"read {len(ips)} cached IPs")
        if not ips:
            return 0

        self._audit.log_event(container, "setup", detail=f"[ips] cached: {', '.join(ips)}")

        private_ips, broad_cidrs = _classify_ips(ips)
        if private_ips:
            self._audit.log_event(
                container,
                "note",
                detail=f"private range whitelisted: {', '.join(private_ips)}",
            )
        for cidr in broad_cidrs:
            self._audit.log_event(container, "note", detail=f"broad range whitelisted: {cidr}")

        elements_cmd = self._ruleset.add_elements_dual(ips)
        if elements_cmd:
            self._nft_exec(container, pid, stdin=elements_cmd, action="add-elements")
            self._audit.log_event(
                container,
                "setup",
                detail=f"[ips] added to allow sets: {', '.join(ips)}",
            )

        return len(ips)

    def _verify(self, container: str, pid: str) -> None:
        """Verify the applied ruleset."""
        output = self._nft_exec(container, pid, "list", "ruleset")
        errors = self._ruleset.verify_hook(output)
        if errors:
            detail = "; ".join(errors)
            self._audit.log_event(container, "error", detail=f"verification failed: {detail}")
            raise RuntimeError(f"Ruleset verification failed: {detail}")
        self._audit.log_event(container, "setup", detail="verification passed")

    def _read_allowed_ips(self) -> list[str]:
        """Read effective IPs: (profile ∪ live) minus deny.list."""
        return state.read_effective_ips(self._state_dir)

    def _nft_exec(
        self,
        container: str,
        pid: str,
        *args: str,
        stdin: str | None = None,
        action: str = "",
    ) -> str:
        """Run nft in the container netns, logging and raising on failure."""
        try:
            return self._runner.nft_via_nsenter(container, *args, pid=pid, stdin=stdin)
        except ExecError as e:
            label = action or (args[0] if args else "apply")
            self._audit.log_event(container, "error", detail=f"{label} failed: {e}")
            raise RuntimeError(f"nft {label} failed: {e}") from e

    @staticmethod
    def parse_oci_state(stdin_data: str) -> tuple[str, str, dict[str, str]]:
        """Parse OCI state JSON from stdin.

        Returns:
            Tuple of (container_id, pid, annotations).  ``pid`` is an empty
            string when absent or zero (expected for ``poststop`` hooks).

        Raises:
            ValueError: If the state is missing ``id`` or is not valid JSON.
        """
        return _parse_oci_state(stdin_data)


# ── DNS detection ─────────────────────────────────────────


def _read_container_dns(pid: str) -> str:
    """Read the DNS nameserver from a container's resolv.conf.

    At ``createRuntime`` hook time, the mount namespace is set up and
    ``/proc/{pid}/root/etc/resolv.conf`` is accessible (OCI spec
    guarantees mounts are performed before ``createRuntime`` hooks).

    Raises:
        RuntimeError: If resolv.conf is missing or contains no nameserver.
    """
    resolv_path = Path(f"/proc/{pid}/root/etc/resolv.conf")
    try:
        text = resolv_path.read_text()
    except OSError as e:
        raise RuntimeError(
            f"Cannot read container resolv.conf at {resolv_path}: {e}. "
            "The container's network may not be configured correctly."
        ) from e
    dns = parse_resolv_conf(text)
    if not dns:
        raise RuntimeError(
            f"No nameserver found in {resolv_path}. "
            "The container's network may not be configured correctly."
        )
    return dns


# ── Entry point ──────────────────────────────────────────


def hook_main(stdin_data: str | None = None, stage: str = "createRuntime") -> int:
    """OCI hook entry point.

    Reads OCI state from stdin, extracts configuration from annotations,
    and dispatches to the appropriate handler.

    Args:
        stdin_data: OCI state JSON (reads from stdin if None).
        stage: OCI hook stage (``createRuntime`` or ``poststop``).

    Returns:
        Exit code (0 = success, 1 = failure).
    """
    if stdin_data is None:
        stdin_data = sys.stdin.read()

    try:
        container_id, pid, annotations = _parse_oci_state(stdin_data)
    except ValueError as e:
        print(f"terok-shield hook: {e}", file=sys.stderr)
        return 1

    try:
        if stage == "poststop":
            return 0

        # createRuntime (default)
        if not pid:
            raise RuntimeError("Hook mode requires a valid PID in OCI state")

        # Read config from annotations
        state_dir_str = annotations.get(ANNOTATION_STATE_DIR_KEY)
        if not state_dir_str:
            raise RuntimeError(
                f"Missing {ANNOTATION_STATE_DIR_KEY} annotation. "
                "Container was not started with terok-shield pre_start()."
            )
        sd = Path(state_dir_str)
        if not sd.is_absolute():
            raise RuntimeError(
                f"{ANNOTATION_STATE_DIR_KEY} must be an absolute path: {state_dir_str!r}"
            )
        sd = sd.resolve()

        version_str = annotations.get(ANNOTATION_VERSION_KEY, "")
        if not version_str:
            raise RuntimeError(f"Missing {ANNOTATION_VERSION_KEY} annotation.")
        try:
            version = int(version_str)
        except ValueError as e:
            raise RuntimeError(
                f"Invalid {ANNOTATION_VERSION_KEY} annotation: {version_str!r}"
            ) from e
        if version != state.BUNDLE_VERSION:
            raise RuntimeError(
                f"Bundle version mismatch: annotation={version}, "
                f"expected={state.BUNDLE_VERSION}. Re-run pre_start()."
            )

        loopback_ports = _parse_loopback_ports(annotations.get(ANNOTATION_LOOPBACK_PORTS_KEY, ""))
        raw_audit = annotations.get(ANNOTATION_AUDIT_ENABLED_KEY, "true").strip().lower()
        audit_enabled = raw_audit not in ("false", "0")

        # Read DNS from the container's resolv.conf (mounts are done
        # at createRuntime per OCI spec).
        dns = _read_container_dns(pid)

        runner = SubprocessRunner()
        audit = AuditLogger(
            audit_path=state.audit_path(sd),
            enabled=audit_enabled,
        )
        ruleset = RulesetBuilder(dns=dns, loopback_ports=loopback_ports)
        executor = HookExecutor(
            runner=runner,
            audit=audit,
            ruleset=ruleset,
            state_dir=sd,
        )
        executor.apply(container_id, pid)
    except RuntimeError as e:
        print(f"terok-shield hook: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    _stage = sys.argv[1] if len(sys.argv) > 1 else "createRuntime"
    sys.exit(hook_main(stage=_stage))
