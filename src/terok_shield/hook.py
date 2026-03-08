# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""OCI hook entry point for standard-mode firewall.

This module is invoked by podman as a ``createRuntime`` OCI hook.
It receives the OCI state as JSON on stdin and applies nftables
rules inside the container's network namespace.

The hook is fail-closed: if any step fails, it exits non-zero and
the container must not start with unrestricted network access.
"""


import ipaddress
import json
import re
import sys

from .audit import log_event
from .config import shield_resolved_dir
from .nft import add_elements, standard_ruleset, verify_ruleset
from .run import ExecError, nft_via_nsenter

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

_RFC1918_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("169.254.0.0/16"),
)

_BROAD_PREFIX_THRESHOLD = 16


def _classify_ips(ips: list[str]) -> tuple[list[str], list[str]]:
    """Classify IPs into RFC1918 and broad-range lists for logging.

    Returns:
        Tuple of (rfc1918_ips, broad_cidrs). Does not affect which IPs
        are added to the allow set — classification is logging-only.
    """
    rfc1918: list[str] = []
    broad: list[str] = []
    for ip_str in ips:
        try:
            if "/" in ip_str:
                net = ipaddress.IPv4Network(ip_str, strict=False)
                if net.prefixlen <= _BROAD_PREFIX_THRESHOLD:
                    broad.append(ip_str)
                if any(net.subnet_of(rfc) for rfc in _RFC1918_NETWORKS):
                    rfc1918.append(ip_str)
            else:
                addr = ipaddress.IPv4Address(ip_str)
                if any(addr in rfc for rfc in _RFC1918_NETWORKS):
                    rfc1918.append(ip_str)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            continue
    return rfc1918, broad


def _parse_oci_state(stdin_data: str) -> tuple[str, str]:
    """Parse OCI state JSON from stdin.

    Returns:
        Tuple of (container_id, pid).

    Raises:
        ValueError: If the state is missing required fields.
    """
    try:
        state = json.loads(stdin_data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid OCI state JSON: {e}") from e
    if not isinstance(state, dict):
        raise ValueError(f"OCI state must be a JSON object: {state!r}")
    cid = state.get("id")
    pid = state.get("pid")
    if not cid or not pid:
        raise ValueError(f"OCI state missing id or pid: {state!r}")
    return str(cid), str(pid)


def _read_resolved_ips(container: str) -> list[str]:
    """Read pre-resolved IPs for a container.

    Returns an empty list if no cache file exists or the name is invalid.
    """
    if not _SAFE_NAME.fullmatch(container):
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

    # Classify for logging (all IPs go to allow_v4 regardless)
    rfc1918_ips, broad_cidrs = _classify_ips(ips)
    if rfc1918_ips:
        log_event(container, "note", detail=f"rfc1918 whitelisted: {', '.join(rfc1918_ips)}")
    for cidr in broad_cidrs:
        log_event(container, "note", detail=f"broad range whitelisted: {cidr}")

    elements_cmd = add_elements("allow_v4", ips)
    if elements_cmd:
        _nft_exec(container, pid, stdin=elements_cmd, action="add-elements")
        log_event(container, "setup", detail=f"[ips] added to allow_v4: {', '.join(ips)}")

    return len(ips)


def apply_hook(container: str, pid: str) -> None:
    """Apply the standard-mode firewall to a container.

    This is the core hook logic, separated from stdin parsing
    for testability.

    Args:
        container: Container ID or name.
        pid: Host PID of the container's init process.

    Raises:
        RuntimeError: If ruleset application or verification fails.
    """
    _nft_exec(container, pid, stdin=standard_ruleset())
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


def hook_main(stdin_data: str | None = None) -> int:
    """OCI hook entry point.

    Reads OCI state from stdin, applies the firewall, and returns
    an exit code (0 = success, 1 = failure).
    """
    if stdin_data is None:
        stdin_data = sys.stdin.read()

    try:
        container, pid = _parse_oci_state(stdin_data)
    except ValueError as e:
        print(f"terok-shield hook: {e}", file=sys.stderr)
        return 1

    try:
        apply_hook(container, pid)
    except RuntimeError as e:
        print(f"terok-shield hook: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(hook_main())
