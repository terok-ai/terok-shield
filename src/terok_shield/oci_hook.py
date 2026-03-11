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

from .audit import configure_audit, log_event
from .config import load_shield_config, shield_resolved_dir
from .nft import add_elements_dual, hook_ruleset, verify_ruleset
from .run import ExecError, nft_via_nsenter
from .validation import SAFE_NAME

if TYPE_CHECKING:
    from .audit import AuditLogger
    from .nft import RulesetBuilder
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

    Handles both IPv4 (RFC1918/link-local) and IPv6 (ULA/link-local).

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
        resolved_dir: Path,
    ) -> None:
        """Create a hook executor.

        Args:
            runner: Command runner for nft subprocess calls.
            audit: Audit logger for event logging.
            ruleset: Ruleset builder for generation and verification.
            resolved_dir: Directory containing per-container ``.resolved`` files.
        """
        self._runner = runner
        self._audit = audit
        self._ruleset = ruleset
        self._resolved_dir = resolved_dir

    def apply(self, container: str, pid: str) -> None:
        """Apply ruleset, load cached IPs, verify.  Fail-closed."""
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
            ips = self._read_resolved_ips(container)
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

    def _read_resolved_ips(self, container: str) -> list[str]:
        """Read pre-resolved IPs for a container."""
        if not SAFE_NAME.fullmatch(container):
            return []
        path = self._resolved_dir / f"{container}.resolved"
        if not path.is_file():
            return []
        return [line.strip() for line in path.read_text().splitlines() if line.strip()]

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


# ── Module-level free functions (backwards compat) ───────


def _parse_oci_state(stdin_data: str) -> tuple[str, str, dict[str, str]]:
    """Parse OCI state JSON from stdin.

    Returns:
        Tuple of (container_id, pid, annotations).  ``pid`` is an empty
        string when absent or zero (expected for ``poststop`` hooks).

    Raises:
        ValueError: If the state is missing ``id`` or is not valid JSON.
    """
    try:
        state = json.loads(stdin_data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid OCI state JSON: {e}") from e
    if not isinstance(state, dict):
        raise ValueError(f"OCI state must be a JSON object: {state!r}")
    cid = state.get("id")
    if not cid:
        raise ValueError(f"OCI state missing id: {state!r}")
    pid = state.get("pid", 0)
    annotations = state.get("annotations", {})
    if not isinstance(annotations, dict):
        annotations = {}
    return str(cid), str(pid) if pid else "", annotations


def _read_resolved_ips(container: str) -> list[str]:
    """Read pre-resolved IPs for a container.

    Returns an empty list if no cache file exists or the name is invalid.
    """
    if not SAFE_NAME.fullmatch(container):
        return []
    path = shield_resolved_dir() / f"{container}.resolved"
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def _nft_exec(
    container: str, pid: str, *args: str, stdin: str | None = None, action: str = ""
) -> str:
    """Run nft in the container netns, logging and raising on failure."""
    try:
        return nft_via_nsenter(container, *args, pid=pid, stdin=stdin)
    except ExecError as e:
        label = action or (args[0] if args else "apply")
        log_event(container, "error", detail=f"{label} failed: {e}")
        raise RuntimeError(f"nft {label} failed: {e}") from e


def _load_and_add_ips(container: str, pid: str) -> int:
    """Read cached IPs, classify, log, and add to the "allow" set.

    Returns the total number of IPs read from the cache.
    """
    try:
        ips = _read_resolved_ips(container)
    except (OSError, UnicodeError) as e:
        log_event(container, "error", detail=f"resolved cache read failed: {e}")
        raise RuntimeError(f"Failed to read resolved cache: {e}") from e

    log_event(container, "setup", detail=f"read {len(ips)} cached IPs")
    if not ips:
        return 0

    log_event(container, "setup", detail=f"[ips] cached: {', '.join(ips)}")

    # Classify for logging (IPs are routed to correct set by add_elements_dual)
    private_ips, broad_cidrs = _classify_ips(ips)
    if private_ips:
        log_event(container, "note", detail=f"private range whitelisted: {', '.join(private_ips)}")
    for cidr in broad_cidrs:
        log_event(container, "note", detail=f"broad range whitelisted: {cidr}")

    elements_cmd = add_elements_dual(ips)
    if elements_cmd:
        _nft_exec(container, pid, stdin=elements_cmd, action="add-elements")
        log_event(container, "setup", detail=f"[ips] added to allow sets: {', '.join(ips)}")

    return len(ips)


def apply_hook(container: str, pid: str, loopback_ports: tuple[int, ...] = ()) -> None:
    """Apply the hook-mode firewall to a container.

    This is the core hook logic, separated from stdin parsing
    for testability.

    Args:
        container: Container ID or name.
        pid: Host PID of the container's init process.
        loopback_ports: TCP ports to allow on the loopback interface.

    Raises:
        RuntimeError: If ruleset application or verification fails.
    """
    _nft_exec(container, pid, stdin=hook_ruleset(loopback_ports=loopback_ports))
    log_event(container, "setup", detail="ruleset applied")

    ip_count = _load_and_add_ips(container, pid)

    output = _nft_exec(container, pid, "list", "ruleset")
    errors = verify_ruleset(output)
    if errors:
        detail = "; ".join(errors)
        log_event(container, "error", detail=f"verification failed: {detail}")
        raise RuntimeError(f"Ruleset verification failed: {detail}")
    log_event(container, "setup", detail="verification passed")

    log_event(container, "setup", detail=f"applied with {ip_count} allowed IPs")


def hook_main(stdin_data: str | None = None, stage: str = "createRuntime") -> int:
    """OCI hook entry point.

    Reads OCI state from stdin, determines the firewall mode from
    annotations, and dispatches to the appropriate handler.

    Args:
        stdin_data: OCI state JSON (reads from stdin if None).
        stage: OCI hook stage (``createRuntime`` or ``poststop``).

    Returns:
        Exit code (0 = success, 1 = failure).
    """
    if stdin_data is None:
        stdin_data = sys.stdin.read()

    try:
        # _annotations intentionally captured -- preserves mode-dispatch infrastructure
        container_id, pid, _annotations = _parse_oci_state(stdin_data)
    except ValueError as e:
        print(f"terok-shield hook: {e}", file=sys.stderr)
        return 1

    try:
        if stage == "poststop":
            return 0

        # createRuntime (default)
        if not pid:
            raise RuntimeError("Hook mode requires a valid PID in OCI state")
        cfg = load_shield_config()
        configure_audit(enabled=cfg.audit_enabled)
        apply_hook(container_id, pid, loopback_ports=cfg.loopback_ports)
    except RuntimeError as e:
        print(f"terok-shield hook: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    _stage = sys.argv[1] if len(sys.argv) > 1 else "createRuntime"
    sys.exit(hook_main(stage=_stage))
