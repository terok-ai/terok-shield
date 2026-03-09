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
    DEFAULT_GATE_PORT,
    NFT_TABLE,
    PASTA_DNS,
    RFC1918,
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
    """Validate IPv4 address or CIDR notation.

    Prevents nft command injection by ensuring the value is a valid
    IPv4 address or network.  Raises ValueError on invalid input.
    """
    v = value.strip()
    try:
        if "/" in v:
            ipaddress.IPv4Network(v, strict=False)
        else:
            ipaddress.IPv4Address(v)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
        raise ValueError(f"Invalid IP/CIDR: {v!r}") from e
    return v


# ── Rulesets ─────────────────────────────────────────────


def _rfc1918_rules(prefix: str = "TEROK_SHIELD_RFC1918") -> str:
    """Generate RFC1918 reject rules.  Used by both modes."""
    return "\n".join(
        f'        ip daddr {net} log prefix "{prefix}: " reject with icmp type admin-prohibited'
        for net in RFC1918
    )


def _audit_deny_rule() -> str:
    """Generate the deny-all rule with audit logging."""
    return (
        '        log prefix "TEROK_SHIELD_DENIED: " counter\n'
        "        reject with icmp type admin-prohibited"
    )


def _audit_allow_rule() -> str:
    """Generate an audit rule for allowed traffic (rate-limited)."""
    return '        ip daddr @allow_v4 limit rate 10/second log prefix "TEROK_SHIELD_ALLOWED: " counter accept'


def hook_ruleset(dns: str = PASTA_DNS, gate_port: int = DEFAULT_GATE_PORT) -> str:
    """Generate a per-container nftables ruleset for hook mode.

    Applied by the OCI hook into the container's own netns.

    Chain order (output):
        IPv6 drop -> loopback -> established -> DNS -> gate port -> allow set -> RFC1918 reject -> deny

    Args:
        dns: DNS server address (pasta default forwarder).
        gate_port: Gate server port to allow on loopback.
    """
    safe_ip(dns)
    _safe_port(gate_port)
    return textwrap.dedent(f"""\
        table {NFT_TABLE} {{
            set allow_v4 {{ type ipv4_addr; flags interval; }}

            chain output {{
                type filter hook output priority filter; policy drop;
                meta nfproto ipv6 drop
                oifname "lo" accept
                ct state established,related accept
                udp dport 53 ip daddr {dns} accept
                tcp dport 53 ip daddr {dns} accept
                tcp dport {gate_port} oifname "lo" accept
        {_audit_allow_rule()}
                ip daddr @allow_v4 accept
        {_rfc1918_rules()}
        {_audit_deny_rule()}
            }}

            chain input {{
                type filter hook input priority filter; policy drop;
                meta nfproto ipv6 drop
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


# ── Verification ─────────────────────────────────────────


def _has_leading_ipv6_drop(nft_output: str, chain: str) -> bool:
    """Check that IPv6 drop is the first rule in a chain (before any accept)."""
    pattern = rf"chain {chain} \{{.*?policy drop;\s*meta nfproto ipv6 drop"
    return re.search(pattern, nft_output, re.DOTALL) is not None


def _verify_rfc1918_blocks(nft_output: str) -> list[str]:
    """Check RFC1918 reject rules are present in the ruleset.

    Uses a regex to match reject rule context (``ip daddr <net> ... reject``)
    rather than bare CIDR presence, so set elements don't produce false passes.
    """
    errors: list[str] = []
    for net in RFC1918:
        pattern = rf"ip daddr {re.escape(net)}.*reject"
        if not re.search(pattern, nft_output):
            errors.append(f"RFC1918 reject rule for {net} missing")
    return errors


def verify_ruleset(nft_output: str) -> list[str]:
    """Check applied ruleset invariants.  Returns errors (empty = OK).

    Verifies:
    - Default policy is drop
    - IPv6 drop is the first rule in every chain
    - Reject type is present
    - Deny log prefix is present
    - All RFC1918 ranges are present (reject rules for non-whitelisted LAN traffic)
    """
    errors: list[str] = []
    if "policy drop" not in nft_output:
        errors.append("policy is not drop")
    for chain in ("output", "input", "forward"):
        if f"chain {chain}" in nft_output and not _has_leading_ipv6_drop(nft_output, chain):
            errors.append(f"IPv6 drop rule missing or misplaced in {chain} chain")
    if "admin-prohibited" not in nft_output:
        errors.append("reject type missing")
    if "TEROK_SHIELD_DENIED" not in nft_output:
        errors.append("deny log prefix missing")
    errors.extend(_verify_rfc1918_blocks(nft_output))
    return errors


def _try_validate(ip: str) -> bool:
    """Return True if ip is a valid IPv4 address/CIDR, False otherwise."""
    try:
        safe_ip(ip)
        return True
    except ValueError:
        return False
