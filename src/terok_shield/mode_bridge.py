# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Bridge mode: named bridge + rootless-netns.

Uses a dedicated bridge network (``ctr-egress``) and applies nftables
rules in podman's rootless-netns.  All container traffic traverses the
bridge and is filtered at the forward chain.  Requires both the bridge
network and ``dnsmasq`` to be present on the host.
"""

import logging
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
    bridge_ruleset,
    create_set,
    forward_rule,
    safe_ip,
    safe_name,
)
from .nft_constants import NFT_TABLE_NAME
from .profiles import compose_profiles
from .run import ExecError, nft_via_rootless_netns, podman_inspect, run as run_cmd
from .util import is_ipv4

logger = logging.getLogger(__name__)

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SAFE_DOMAIN = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*\.?$"
)


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
    """Ensure rootless-netns has the shield nft table with current gate_port.

    If the table exists but uses a different gate port, it is replaced.

    Args:
        gate_port: Gate server port for the ruleset.

    Raises:
        RuntimeError: If the table cannot be loaded.
    """
    expected = bridge_ruleset(BRIDGE_GATEWAY, BRIDGE_SUBNET, gate_port)

    out = nft_via_rootless_netns(
        "list",
        "ruleset",
        "inet",
        check=False,
    )
    if "terok_shield" in out:
        if f"th dport {gate_port}" in out:
            return
        # Gate port changed — delete stale table before reloading.
        nft_via_rootless_netns(
            "delete",
            "table",
            "inet",
            "terok_shield",
            check=False,
        )

    nft_via_rootless_netns(stdin=expected)

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
    """Prepare for container start in bridge mode.

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
        _config: Shield configuration (unused, kept for API consistency).
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
    domains = [e for e in entries if not is_ipv4(e)]
    _update_dnsmasq_nftsets(container, domains)


def pre_stop(container: str) -> None:
    """Remove per-container forward rules and allow set.

    Call before ``podman stop`` to clean up bridge-mode nft state.

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

    (shield_resolved_dir() / f"{safe}.dnsmasq-nftset").unlink(missing_ok=True)


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


def _safe_domain(domain: str) -> bool:
    """Return True if domain is safe for use in dnsmasq nftset directives."""
    return bool(_SAFE_DOMAIN.fullmatch(domain)) and len(domain) <= 253


def _update_dnsmasq_nftsets(container: str, domains: list[str]) -> None:
    """Write dnsmasq nftset config for a container (best-effort).

    Domains that fail validation are skipped with a warning.

    Args:
        container: Container name.
        domains: Domain names to include in nftset rules.
    """
    if not domains:
        return
    safe = safe_name(container)
    valid = []
    for d in domains:
        if _safe_domain(d):
            valid.append(d)
        else:
            logger.warning("Skipping invalid domain %r for container %s", d, container)
    if not valid:
        return
    lines = [f"nftset=/{d}/4#inet#{NFT_TABLE_NAME}#{safe}_allow_v4" for d in valid]
    nftset_file = shield_resolved_dir() / f"{safe}.dnsmasq-nftset"
    nftset_file.write_text("\n".join(lines) + "\n")
