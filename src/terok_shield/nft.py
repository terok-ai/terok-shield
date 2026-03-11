# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""nftables ruleset generation.

+=====================================================+
|  SECURITY BOUNDARY -- read this file first.         |
|                                                     |
|  Every nftables ruleset is generated here.          |
|  All inputs are validated before interpolation.     |
|  Only stdlib + nft_constants.py imports allowed.    |
+=====================================================+
"""

import ipaddress
import re
import textwrap

from .nft_constants import (
    BYPASS_LOG_PREFIX,
    NFT_TABLE,
    PASTA_DNS,
    PRIVATE_RANGES,
)

# ── Validation ───────────────────────────────────────────


def _safe_port(port: int) -> int:
    """Validate a port number.  Raises ValueError for out-of-range or non-int."""
    if isinstance(port, bool) or not isinstance(port, int):
        raise ValueError(f"Port must be an integer, got {type(port).__name__}")
    if not 1 <= port <= 65535:
        raise ValueError(f"Port out of range: {port}")
    return port


def safe_ip(value: str) -> str:
    """Validate an IPv4 or IPv6 address or CIDR notation.

    Prevents nft command injection by ensuring the value is a valid
    IP address or network.  Raises ValueError on invalid input.
    """
    v = value.strip()
    try:
        if "/" in v:
            ipaddress.ip_network(v, strict=False)
        else:
            ipaddress.ip_address(v)
    except ValueError as e:
        raise ValueError(f"Invalid IP/CIDR: {v!r}") from e
    return v


def _is_v4(value: str) -> bool:
    """Return True if a validated IP string is IPv4."""
    try:
        if "/" in value:
            return isinstance(ipaddress.ip_network(value, strict=False), ipaddress.IPv4Network)
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


# ── Rulesets ─────────────────────────────────────────────


def _private_range_rules(prefix: str = "TEROK_SHIELD_PRIVATE") -> str:
    """Generate private-range reject rules (RFC1918 + IPv6 ULA/link-local).

    Auto-detects address family for the ``daddr`` selector and uses
    cross-family ``icmpx`` reject for all ranges.
    """
    return "\n".join(
        f"        {'ip' if _is_v4(net) else 'ip6'} daddr {net}"
        f' log prefix "{prefix}: " reject with icmpx admin-prohibited'
        for net in PRIVATE_RANGES
    )


def _audit_deny_rule() -> str:
    """Generate the deny-all rule with audit logging.

    Uses ``icmpx`` for cross-family reject in ``inet`` tables —
    auto-selects ICMP (IPv4) or ICMPv6 (IPv6).
    """
    return (
        '        log prefix "TEROK_SHIELD_DENIED: " counter\n'
        "        reject with icmpx admin-prohibited"
    )


def _audit_allow_rules() -> str:
    """Generate audit rules for allowed traffic (IPv4 + IPv6).

    No rate limit — only new connections reach these rules because
    ``ct state established,related accept`` is earlier in the chain.
    """
    return (
        '        ip daddr @allow_v4 log prefix "TEROK_SHIELD_ALLOWED: " counter accept\n'
        '        ip6 daddr @allow_v6 log prefix "TEROK_SHIELD_ALLOWED: " counter accept'
    )


def _loopback_port_rules(ports: tuple[int, ...]) -> str:
    """Generate nft accept rules for loopback ports."""
    return "\n".join(f'            tcp dport {p} oifname "lo" accept' for p in ports)


def hook_ruleset(dns: str = PASTA_DNS, loopback_ports: tuple[int, ...] = ()) -> str:
    """Generate a per-container nftables ruleset for hook mode.

    Applied by the OCI hook into the container's own netns.
    Dual-stack: both IPv4 and IPv6 use deny-all + allowlist.

    Chain order (output):
        loopback -> established -> DNS -> loopback ports -> allow sets -> private-range reject -> deny

    Args:
        dns: DNS server address (pasta default forwarder).
        loopback_ports: TCP ports to allow on the loopback interface.
    """
    safe_ip(dns)
    for p in loopback_ports:
        _safe_port(p)
    port_rules = _loopback_port_rules(loopback_ports)
    port_block = f"\n{port_rules}\n" if port_rules else "\n"
    dns_af = "ip" if _is_v4(dns) else "ip6"
    return textwrap.dedent(f"""\
        table {NFT_TABLE} {{
            set allow_v4 {{ type ipv4_addr; flags interval; }}
            set allow_v6 {{ type ipv6_addr; flags interval; }}

            chain output {{
                type filter hook output priority filter; policy drop;
                oifname "lo" accept
                ct state established,related accept
                udp dport 53 {dns_af} daddr {dns} accept
                tcp dport 53 {dns_af} daddr {dns} accept{port_block}\
        {_audit_allow_rules()}
        {_private_range_rules()}
        {_audit_deny_rule()}
            }}

            chain input {{
                type filter hook input priority filter; policy drop;
                iifname "lo" accept
                ct state established,related accept
                udp sport 53 accept
                tcp sport 53 accept
                drop
            }}
        }}
    """)


def bypass_ruleset(
    dns: str = PASTA_DNS,
    loopback_ports: tuple[int, ...] = (),
    *,
    allow_all: bool = False,
) -> str:
    """Generate a bypass (accept-all + log) nftables ruleset.

    Same structure as ``hook_ruleset()`` but output chain policy is accept
    and new connections are logged with the bypass prefix.  Private-range
    reject rules (private ranges) are kept unless
    *allow_all* is True.

    Args:
        dns: DNS server address (pasta default forwarder).
        loopback_ports: TCP ports to allow on the loopback interface.
        allow_all: If True, remove private-range reject rules.
    """
    safe_ip(dns)
    for p in loopback_ports:
        _safe_port(p)
    port_rules = _loopback_port_rules(loopback_ports)
    port_block = f"\n{port_rules}\n" if port_rules else "\n"
    dns_af = "ip" if _is_v4(dns) else "ip6"
    private_block = "" if allow_all else f"\n{_private_range_rules()}"
    bypass_log = f'        ct state new log prefix "{BYPASS_LOG_PREFIX}: " counter'
    return textwrap.dedent(f"""\
        table {NFT_TABLE} {{
            set allow_v4 {{ type ipv4_addr; flags interval; }}
            set allow_v6 {{ type ipv6_addr; flags interval; }}

            chain output {{
                type filter hook output priority filter; policy accept;
                oifname "lo" accept
                ct state established,related accept
                udp dport 53 {dns_af} daddr {dns} accept
                tcp dport 53 {dns_af} daddr {dns} accept{port_block}\
        {bypass_log}{private_block}
            }}

            chain input {{
                type filter hook input priority filter; policy drop;
                iifname "lo" accept
                ct state established,related accept
                udp sport 53 accept
                tcp sport 53 accept
                drop
            }}
        }}
    """)


# ── Set operations ───────────────────────────────────────


def add_elements(set_name: str, ips: list[str], table: str = NFT_TABLE) -> str:
    """Generate nft command to add validated IPs to a set.

    Returns empty string if no valid IPs.
    """
    valid = [safe_ip(ip) for ip in ips if _try_validate(ip)]
    if not valid:
        return ""
    return f"add element {table} {set_name} {{ {', '.join(valid)} }}\n"


def add_elements_dual(ips: list[str], table: str = NFT_TABLE) -> str:
    """Classify IPs by family and generate add-element commands for both sets.

    IPv4 addresses go to ``allow_v4``, IPv6 to ``allow_v6``.
    Returns empty string if no valid IPs.
    """
    v4: list[str] = []
    v6: list[str] = []
    for ip in ips:
        if _try_validate(ip):
            (v4 if _is_v4(ip) else v6).append(ip)
    parts: list[str] = []
    cmd = add_elements("allow_v4", v4, table)
    if cmd:
        parts.append(cmd)
    cmd = add_elements("allow_v6", v6, table)
    if cmd:
        parts.append(cmd)
    return "".join(parts)


# ── Verification ─────────────────────────────────────────


def _verify_private_blocks(nft_output: str) -> list[str]:
    """Check private-range reject rules (RFC1918 + IPv6) are present.

    Uses a regex to match reject rule context (``ip[6] daddr <net> ... reject``)
    rather than bare CIDR presence, so set elements don't produce false passes.
    Auto-detects address family from the CIDR.
    """
    errors: list[str] = []
    for net in PRIVATE_RANGES:
        selector = "ip" if _is_v4(net) else "ip6"
        pattern = rf"{selector} daddr {re.escape(net)}.*reject"
        if not re.search(pattern, nft_output):
            errors.append(f"Private-range reject rule for {net} missing")
    return errors


def verify_ruleset(nft_output: str) -> list[str]:
    """Check applied ruleset invariants.  Returns errors (empty = OK).

    Verifies:
    - Default policy is drop
    - Both output and input chains exist
    - Reject type is present
    - Deny log prefix is present
    - All private ranges are present (RFC1918 + IPv6 ULA/link-local)
    - Dual-stack allow sets are declared
    """
    errors: list[str] = []
    if "policy drop" not in nft_output:
        errors.append("policy is not drop")
    for chain in ("output", "input"):
        if f"chain {chain}" not in nft_output:
            errors.append(f"{chain} chain missing")
    if "admin-prohibited" not in nft_output:
        errors.append("reject type missing")
    if "TEROK_SHIELD_DENIED" not in nft_output:
        errors.append("deny log prefix missing")
    if "allow_v4" not in nft_output:
        errors.append("allow_v4 set missing")
    if "allow_v6" not in nft_output:
        errors.append("allow_v6 set missing")
    errors.extend(_verify_private_blocks(nft_output))
    return errors


def verify_bypass_ruleset(nft_output: str, *, allow_all: bool = False) -> list[str]:
    """Check applied bypass ruleset invariants.  Returns errors (empty = OK).

    Verifies:
    - Output chain has policy accept
    - Input chain has policy drop
    - Bypass log prefix is present
    - Dual-stack allow sets are declared
    - Private-range reject rules present (unless *allow_all*)
    """
    errors: list[str] = []
    if "policy accept" not in nft_output:
        errors.append("output policy is not accept")
    if "policy drop" not in nft_output:
        errors.append("input policy is not drop")
    for chain in ("output", "input"):
        if f"chain {chain}" not in nft_output:
            errors.append(f"{chain} chain missing")
    if BYPASS_LOG_PREFIX not in nft_output:
        errors.append("bypass log prefix missing")
    if "allow_v4" not in nft_output:
        errors.append("allow_v4 set missing")
    if "allow_v6" not in nft_output:
        errors.append("allow_v6 set missing")
    if not allow_all:
        errors.extend(_verify_private_blocks(nft_output))
    return errors


def _try_validate(ip: str) -> bool:
    """Return True if ip is a valid IP address/CIDR, False otherwise."""
    try:
        safe_ip(ip)
        return True
    except ValueError:
        return False
