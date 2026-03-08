# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Hardened mode: named bridge + rootless-netns.

Uses a dedicated bridge network (``ctr-egress``) and applies nftables
rules in podman's rootless-netns.  All container traffic traverses the
bridge and is filtered at the forward chain.  Requires both the bridge
network and ``dnsmasq`` to be present on the host.
"""

import ipaddress
import re

from .config import (
    BRIDGE_GATEWAY,
    BRIDGE_NETWORK,
    BRIDGE_SUBNET,
    ShieldConfig,
    ensure_shield_dirs,
    shield_resolved_dir,
)
from .dns import resolve_and_cache
from .nft import (
    add_elements,
    create_set,
    forward_rule,
    hardened_ruleset,
    safe_ip,
    safe_name,
)
from .nft_constants import NFT_TABLE_NAME
from .profiles import compose_profiles
from .run import ExecError, nft_via_rootless_netns, podman_inspect, run as run_cmd

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def setup(_config: ShieldConfig) -> None:
    """Verify bridge network exists and create directories.

    Args:
        _config: Shield configuration (unused, kept for API consistency).

    Raises:
        RuntimeError: If the bridge network does not exist.
    """
    ensure_shield_dirs()
    try:
        run_cmd(["podman", "network", "exists", BRIDGE_NETWORK])
    except ExecError:
        raise RuntimeError(
            f"Bridge network '{BRIDGE_NETWORK}' not found. "
            f"Create it with: podman network create "
            f"--subnet {BRIDGE_SUBNET} --gateway {BRIDGE_GATEWAY} {BRIDGE_NETWORK}"
        ) from None


def _ensure_netns(gate_port: int) -> None:
    """Ensure rootless-netns has the shield nft table (idempotent).

    Args:
        gate_port: Gate server port for the ruleset.

    Raises:
        RuntimeError: If the table cannot be loaded.
    """
    out = nft_via_rootless_netns(
        "list",
        "table",
        "inet",
        "terok_shield",
        check=False,
    )
    if "terok_shield" in out:
        return

    nft_via_rootless_netns(
        stdin=hardened_ruleset(BRIDGE_GATEWAY, BRIDGE_SUBNET, gate_port),
    )

    out = nft_via_rootless_netns(
        "list",
        "table",
        "inet",
        "terok_shield",
        check=False,
    )
    if "terok_shield" not in out:
        raise RuntimeError("Failed to load nft table in rootless-netns")


def pre_start(
    config: ShieldConfig,
    container: str,
    profiles: list[str],
) -> list[str]:
    """Prepare for container start in hardened mode.

    Ensures the rootless-netns table is loaded, resolves DNS profiles,
    and returns podman CLI arguments.

    Args:
        config: Shield configuration.
        container: Container name (used as DNS cache key).
        profiles: Profile names to compose and resolve.

    Returns:
        Extra arguments for ``podman run``.
    """
    _ensure_netns(config.gate_port)

    entries = compose_profiles(profiles)
    if entries:
        resolve_and_cache(entries, container)

    return [
        "--network",
        BRIDGE_NETWORK,
        "--dns",
        BRIDGE_GATEWAY,
        "--cap-drop",
        "NET_ADMIN",
        "--cap-drop",
        "NET_RAW",
        "--security-opt",
        "no-new-privileges",
    ]


def _read_resolved_cache(container: str) -> list[str]:
    """Read pre-resolved IPs from the cache file for a container.

    Returns an empty list if the file does not exist or the name is invalid.
    """
    if not _SAFE_NAME.fullmatch(container):
        return []
    path = shield_resolved_dir() / f"{container}.resolved"
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def post_start(
    _config: ShieldConfig,
    container: str,
    profiles: list[str],
) -> None:
    """Post-start: create per-container nft set and load IPs.

    Must be called after ``podman run`` succeeds.  Inspects the container
    for its bridge IP, creates a per-container allow set, loads resolved
    IPs, and adds a forward rule.

    Args:
        config: Shield configuration.
        container: Container name.
        profiles: Profile names (for dnsmasq nftset generation).
    """
    ip = podman_inspect(
        container,
        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
    )

    nft_via_rootless_netns(stdin=create_set(container))

    ips = _read_resolved_cache(container)
    if ips:
        safe = safe_name(container)
        cmd = add_elements(f"{safe}_allow_v4", ips)
        if cmd:
            nft_via_rootless_netns(stdin=cmd, check=False)

    nft_via_rootless_netns(stdin=forward_rule(container, ip))

    entries = compose_profiles(profiles)
    domains = [e for e in entries if not _is_ip_entry(e)]
    _update_dnsmasq_nftsets(container, domains)


def pre_stop(container: str) -> None:
    """Remove per-container forward rules and allow set.

    Call before ``podman stop`` to clean up hardened-mode nft state.

    Args:
        container: Container name.
    """
    safe = safe_name(container)

    out = nft_via_rootless_netns(
        "-a",
        "list",
        "chain",
        "inet",
        "terok_shield",
        "forward",
        check=False,
    )
    for line in out.splitlines():
        if f"terok_shield:{safe}" in line and "handle" in line:
            parts = line.strip().split()
            try:
                h = parts[parts.index("handle") + 1]
                nft_via_rootless_netns(
                    "delete",
                    "rule",
                    "inet",
                    "terok_shield",
                    "forward",
                    "handle",
                    h,
                    check=False,
                )
            except (ValueError, IndexError):
                pass

    nft_via_rootless_netns(
        "delete",
        "set",
        "inet",
        "terok_shield",
        f"{safe}_allow_v4",
        check=False,
    )


def allow_ip(container: str, ip: str) -> None:
    """Live-allow an IP for a running container in rootless-netns.

    Args:
        container: Container name or ID.
        ip: IPv4 address or CIDR to allow.
    """
    safe_ip(ip)
    safe = safe_name(container)
    nft_via_rootless_netns(
        "add",
        "element",
        "inet",
        "terok_shield",
        f"{safe}_allow_v4",
        f"{{ {ip} }}",
    )


def deny_ip(container: str, ip: str) -> None:
    """Live-deny an IP for a running container in rootless-netns.

    Args:
        container: Container name or ID.
        ip: IPv4 address or CIDR to deny.
    """
    safe_ip(ip)
    safe = safe_name(container)
    nft_via_rootless_netns(
        "delete",
        "element",
        "inet",
        "terok_shield",
        f"{safe}_allow_v4",
        f"{{ {ip} }}",
    )


def list_rules(container: str) -> str:
    """List per-container allow set in rootless-netns.

    Args:
        container: Container name or ID.

    Returns:
        The nft set output, or empty string on failure.
    """
    safe = safe_name(container)
    return nft_via_rootless_netns(
        "list",
        "set",
        "inet",
        "terok_shield",
        f"{safe}_allow_v4",
        check=False,
    )


def _is_ip_entry(entry: str) -> bool:
    """Return True if entry is an IPv4 address or CIDR."""
    try:
        if "/" in entry:
            ipaddress.IPv4Network(entry, strict=False)
        else:
            ipaddress.IPv4Address(entry)
        return True
    except ValueError:
        return False


def _update_dnsmasq_nftsets(container: str, domains: list[str]) -> None:
    """Write dnsmasq nftset config for a container (best-effort).

    Args:
        container: Container name.
        domains: Domain names to include in nftset rules.
    """
    if not domains:
        return
    safe = safe_name(container)
    lines = [f"nftset=/{d}/4#inet#{NFT_TABLE_NAME}#{safe}_allow_v4" for d in domains]
    nftset_file = shield_resolved_dir() / f"{safe}.dnsmasq-nftset"
    nftset_file.write_text("\n".join(lines) + "\n")
