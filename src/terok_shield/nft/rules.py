# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""nftables ruleset generation and verification.

Generates per-container nftables rulesets (deny-all and bypass modes),
provides set operations for runtime allowlist/denylist management, and
verifies applied rulesets against security invariants.

Security boundary: only stdlib + nft_constants.py imports allowed.
All inputs are validated before interpolation into nft commands.
"""
# WAYPOINT: Shield (__init__), HookMode (mode_hook)

import ipaddress
import re
import textwrap

from .constants import (
    ALLOWED_LOG_PREFIX,
    BLOCKED_LOG_PREFIX,
    BYPASS_LOG_PREFIX,
    DENIED_LOG_PREFIX,
    NFLOG_GROUP,
    NFT_TABLE,
    PASTA_DNS,
    PASTA_HOST_LOOPBACK_MAP,
    PRIVATE_LOG_PREFIX,
    PRIVATE_RANGES,
)

_SAFE_TIMEOUT_RE = re.compile(r"^\d+[smhd]$")
_SAFE_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


# ── RulesetBuilder ──────────────────────────────────────


class RulesetBuilder:
    """Builder for nftables ruleset generation and verification.

    Security boundary: only stdlib + nft_constants imports.
    All inputs validated before interpolation.

    Binds ``dns`` and ``loopback_ports`` once at construction so
    callers do not repeat them on every generation or verification call.
    """

    def __init__(
        self,
        *,
        dns: str = PASTA_DNS,
        loopback_ports: tuple[int, ...] = (),
        set_timeout: str = "",
    ) -> None:
        """Create a builder with validated DNS and loopback port config.

        Args:
            dns: DNS server address (pasta default forwarder).
            loopback_ports: TCP ports to allow on the loopback interface.
                When set, gateway port rules reference ``@gateway_v4``/
                ``@gateway_v6`` sets populated at runtime by the OCI hook.
            set_timeout: nft set element timeout (e.g. ``30m``).  When set,
                allow sets use ``flags interval, timeout`` so dnsmasq-populated
                IPs expire and are refreshed on the next DNS query.
        """
        dns = safe_ip(dns)
        for p in loopback_ports:
            _safe_port(p)
        if set_timeout:
            _safe_timeout(set_timeout)
        self._dns = dns
        self._loopback_ports = loopback_ports
        self._set_timeout = set_timeout

    def build_hook(self) -> str:
        """Generate the hook-mode (deny-all) nftables ruleset."""
        return hook_ruleset(
            dns=self._dns,
            loopback_ports=self._loopback_ports,
            set_timeout=self._set_timeout,
        )

    def build_bypass(self, *, allow_all: bool = False) -> str:
        """Generate the bypass-mode (accept-all + log) ruleset."""
        return bypass_ruleset(
            dns=self._dns,
            loopback_ports=self._loopback_ports,
            allow_all=allow_all,
            set_timeout=self._set_timeout,
        )

    def verify_hook(self, nft_output: str) -> list[str]:
        """Check applied hook ruleset invariants.  Returns errors (empty = OK)."""
        return verify_ruleset(nft_output)

    def build_block(self) -> str:
        """Generate the block-mode (total blackout) ruleset."""
        return block_ruleset()

    def verify_block(self, nft_output: str) -> list[str]:
        """Check applied block ruleset invariants.  Returns errors (empty = OK)."""
        return verify_block_ruleset(nft_output)

    def verify_bypass(self, nft_output: str, *, allow_all: bool = False) -> list[str]:
        """Check applied bypass ruleset invariants.  Returns errors (empty = OK)."""
        return verify_bypass_ruleset(nft_output, allow_all=allow_all)

    def add_elements_dual(self, ips: list[str]) -> str:
        """Classify IPs by family and generate add-element commands for both sets.

        When the builder has a ``set_timeout`` configured (dnsmasq tier),
        permanent IPs are written with ``timeout 0s`` so they do not auto-expire
        along with dnsmasq-learned entries.
        """
        return add_elements_dual(ips, permanent=bool(self._set_timeout))


# ── Ruleset generation ──────────────────────────────────


def hook_ruleset(
    dns: str = PASTA_DNS,
    loopback_ports: tuple[int, ...] = (),
    set_timeout: str = "",
) -> str:
    """Generate a per-container nftables ruleset for hook mode.

    Applied by the OCI hook into the container's own netns.
    Dual-stack: both IPv4 and IPv6 use deny-all + allowlist.

    ``gateway_v4`` and ``gateway_v6`` sets are always defined but start
    empty.  The OCI hook populates them from ``/proc/{pid}/net/route``
    after applying this ruleset; ``shield_up()`` repopulates them from
    the persisted ``state/gateway`` file.

    Chain order (output):
        loopback -> established -> DNS -> gateway ports -> loopback ports
        -> allow sets -> deny sets -> private-range reject -> terminal deny

    The terminal rule always logs with ``BLOCKED`` prefix to NFLOG.
    NFLOG is fire-and-forget: if a clearance handler is listening it can
    prompt the operator; if nobody subscribes the events are silently
    dropped by the kernel at near-zero cost.

    Args:
        dns: DNS server address (pasta default forwarder).
        loopback_ports: TCP ports to allow on the loopback interface.
        set_timeout: nft set element timeout (e.g. ``30m``).
    """
    dns = safe_ip(dns)
    if set_timeout:
        _safe_timeout(set_timeout)
    for p in loopback_ports:
        _safe_port(p)
    port_rules = _loopback_port_rules(loopback_ports)
    gw_rules = _gateway_port_rules(loopback_ports)
    infra_block = ""
    if gw_rules:
        infra_block += f"\n{gw_rules}"
    if port_rules:
        infra_block += f"\n{port_rules}"
    infra_block += "\n"
    dns_af = "ip" if _is_v4(dns) else "ip6"
    set_v4 = _set_declaration("allow_v4", "ipv4_addr", set_timeout)
    set_v6 = _set_declaration("allow_v6", "ipv6_addr", set_timeout)
    set_deny_v4 = _set_declaration("deny_v4", "ipv4_addr")
    set_deny_v6 = _set_declaration("deny_v6", "ipv6_addr")
    allow_rules = _audit_allow_rules()
    deny_rules = _deny_set_rules()
    private_rules = _private_range_rules()
    terminal_rule = _terminal_deny_rule()
    return textwrap.dedent(f"""\
        table {NFT_TABLE} {{
            {set_v4}
            {set_v6}
            {set_deny_v4}
            {set_deny_v6}
            set gateway_v4 {{ type ipv4_addr; }}
            set gateway_v6 {{ type ipv6_addr; }}

            chain output {{
                type filter hook output priority filter; policy drop;
                oifname "lo" accept
                ct state established,related accept
                udp dport 53 {dns_af} daddr {dns} accept
                tcp dport 53 {dns_af} daddr {dns} accept{infra_block}\
        {allow_rules}
        {deny_rules}
        {private_rules}
        {terminal_rule}
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
    set_timeout: str = "",
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
        set_timeout: nft set element timeout (e.g. ``30m``).
    """
    dns = safe_ip(dns)
    if set_timeout:
        _safe_timeout(set_timeout)
    for p in loopback_ports:
        _safe_port(p)
    port_rules = _loopback_port_rules(loopback_ports)
    gw_rules = _gateway_port_rules(loopback_ports)
    infra_block = ""
    if gw_rules:
        infra_block += f"\n{gw_rules}"
    if port_rules:
        infra_block += f"\n{port_rules}"
    infra_block += "\n"
    dns_af = "ip" if _is_v4(dns) else "ip6"
    set_v4 = _set_declaration("allow_v4", "ipv4_addr", set_timeout)
    set_v6 = _set_declaration("allow_v6", "ipv6_addr", set_timeout)
    private_rules = _private_range_rules()
    private_block = "" if allow_all else f"\n{private_rules}"
    bypass_log = (
        f'        ct state new log group {NFLOG_GROUP} prefix "{BYPASS_LOG_PREFIX}: " counter'
    )
    return textwrap.dedent(f"""\
        table {NFT_TABLE} {{
            {set_v4}
            {set_v6}
            set gateway_v4 {{ type ipv4_addr; }}
            set gateway_v6 {{ type ipv6_addr; }}

            chain output {{
                type filter hook output priority filter; policy accept;
                oifname "lo" accept
                ct state established,related accept
                udp dport 53 {dns_af} daddr {dns} accept
                tcp dport 53 {dns_af} daddr {dns} accept{infra_block}\
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


def block_ruleset() -> str:
    """Generate a total-blackout nftables ruleset for panic scenarios.

    Drops all traffic except loopback and established connections.
    No DNS, no allowlists, no gateway ports.  Forensic logging only.
    """
    blocked_log = f'        log group {NFLOG_GROUP} prefix "{BLOCKED_LOG_PREFIX}: " drop'
    return textwrap.dedent(f"""\
        table {NFT_TABLE} {{
            chain output {{
                type filter hook output priority filter; policy drop;
                oifname "lo" accept
                ct state established,related accept
        {blocked_log}
            }}

            chain input {{
                type filter hook input priority filter; policy drop;
                iifname "lo" accept
                ct state established,related accept
                drop
            }}
        }}
    """)


def verify_block_ruleset(nft_output: str) -> list[str]:
    """Check applied block ruleset invariants.  Returns errors (empty = OK).

    Verifies:
    - Both chains present with policy drop
    - Blocked log prefix present
    - No allow sets (total blackout means no allowlists)
    """
    errors: list[str] = []
    if "policy drop" not in nft_output:
        errors.append("policy is not drop")
    for chain in ("output", "input"):
        if f"chain {chain}" not in nft_output:
            errors.append(f"{chain} chain missing")
    if BLOCKED_LOG_PREFIX not in nft_output:
        errors.append("blocked nflog prefix missing")
    if "allow_v4" in nft_output:
        errors.append("allow_v4 set present in block mode")
    if "allow_v6" in nft_output:
        errors.append("allow_v6 set present in block mode")
    return errors


def _set_declaration(name: str, family: str, set_timeout: str = "") -> str:
    """Generate an nft set declaration with optional timeout.

    Args:
        name: Set name (e.g. ``allow_v4``).
        family: Address type (``ipv4_addr`` or ``ipv6_addr``).
        set_timeout: Element timeout (e.g. ``30m``).  When set, adds
            ``timeout`` flag so elements auto-expire.
    """
    if set_timeout:
        return f"set {name} {{ type {family}; flags interval, timeout; timeout {set_timeout}; }}"
    return f"set {name} {{ type {family}; flags interval; }}"


# ── Set operations ──────────────────────────────────────


def add_elements_dual(ips: list[str], *, permanent: bool = False) -> str:
    """Classify IPs by family and generate add-element commands for both sets.

    IPv4 addresses go to ``allow_v4``, IPv6 to ``allow_v6``.
    Returns empty string if no valid IPs.

    Args:
        permanent: When ``True``, elements are annotated with ``timeout 0s``
            so they never expire in sets that carry a default timeout
            (dnsmasq tier).  Permanent IPs (profile/live allowlists) must
            not be evicted by the same 30-minute expiry used for
            dnsmasq-learned IPs.
    """
    v4: list[str] = []
    v6: list[str] = []
    for ip in ips:
        try:
            sanitized = safe_ip(ip)
        except ValueError:
            continue
        (v4 if _is_v4(sanitized) else v6).append(sanitized)
    parts: list[str] = []
    cmd = add_elements("allow_v4", v4, timeout_zero=permanent)
    if cmd:
        parts.append(cmd)
    cmd = add_elements("allow_v6", v6, timeout_zero=permanent)
    if cmd:
        parts.append(cmd)
    return "".join(parts)


def add_deny_elements_dual(ips: list[str]) -> str:
    """Classify IPs by family and generate add-element commands for deny sets.

    IPv4 addresses go to ``deny_v4``, IPv6 to ``deny_v6``.
    Returns empty string if no valid IPs.
    """
    v4: list[str] = []
    v6: list[str] = []
    for ip in ips:
        try:
            sanitized = safe_ip(ip)
        except ValueError:
            continue
        (v4 if _is_v4(sanitized) else v6).append(sanitized)
    parts: list[str] = []
    cmd = add_elements("deny_v4", v4)
    if cmd:
        parts.append(cmd)
    cmd = add_elements("deny_v6", v6)
    if cmd:
        parts.append(cmd)
    return "".join(parts)


def delete_deny_elements_dual(ips: list[str]) -> str:
    """Classify IPs by family and generate delete-element commands for deny sets.

    IPv4 addresses target ``deny_v4``, IPv6 target ``deny_v6``.
    Returns empty string if no valid IPs.
    """
    v4: list[str] = []
    v6: list[str] = []
    for ip in ips:
        try:
            sanitized = safe_ip(ip)
        except ValueError:
            continue
        (v4 if _is_v4(sanitized) else v6).append(sanitized)
    parts: list[str] = []
    cmd = delete_elements("deny_v4", v4)
    if cmd:
        parts.append(cmd)
    cmd = delete_elements("deny_v6", v6)
    if cmd:
        parts.append(cmd)
    return "".join(parts)


def add_elements(
    set_name: str, ips: list[str], table: str = NFT_TABLE, *, timeout_zero: bool = False
) -> str:
    """Generate nft command to add validated IPs to a set.

    Both ``set_name`` and ``table`` are validated against injection.
    Returns empty string if no valid IPs.

    Args:
        timeout_zero: When ``True``, each element is annotated with
            ``timeout 0s`` so it never expires, even in sets that carry a
            default element timeout (dnsmasq tier).
    """
    set_name = _safe_ident(set_name)
    table = " ".join(_safe_ident(part) for part in table.split())
    valid = [safe_ip(ip) for ip in ips if _try_validate(ip)]
    if not valid:
        return ""
    if timeout_zero:
        elements = ", ".join(f"{ip} timeout 0s" for ip in valid)
    else:
        elements = ", ".join(valid)
    return f"add element {table} {set_name} {{ {elements} }}\n"


def delete_elements(set_name: str, ips: list[str], table: str = NFT_TABLE) -> str:
    """Generate nft command to delete validated IPs from a set.

    Both ``set_name`` and ``table`` are validated against injection.
    Returns empty string if no valid IPs.
    """
    set_name = _safe_ident(set_name)
    table = " ".join(_safe_ident(part) for part in table.split())
    valid = [safe_ip(ip) for ip in ips if _try_validate(ip)]
    if not valid:
        return ""
    elements = ", ".join(valid)
    return f"delete element {table} {set_name} {{ {elements} }}\n"


# ── Verification ────────────────────────────────────────


def verify_ruleset(nft_output: str) -> list[str]:
    """Check applied ruleset invariants.  Returns errors (empty = OK).

    Verifies:
    - Default policy is drop
    - Both output and input chains exist
    - Reject type is present
    - Dual-stack allow sets are declared
    - Dual-stack deny sets are declared
    - All private ranges are present (RFC 1918 + RFC 4193/4291)
    - Terminal deny-all rule with BLOCKED prefix present
    """
    errors: list[str] = []
    if "policy drop" not in nft_output:
        errors.append("policy is not drop")
    for chain in ("output", "input"):
        if f"chain {chain}" not in nft_output:
            errors.append(f"{chain} chain missing")
    if "admin-prohibited" not in nft_output:
        errors.append("reject type missing")
    if "allow_v4" not in nft_output:
        errors.append("allow_v4 set missing")
    if "allow_v6" not in nft_output:
        errors.append("allow_v6 set missing")
    if "deny_v4" not in nft_output:
        errors.append("deny_v4 set missing")
    if "deny_v6" not in nft_output:
        errors.append("deny_v6 set missing")
    # Verify the terminal deny-all rule — a standalone log+reject with the
    # BLOCKED prefix (no daddr selector, unlike deny-set rules).
    _terminal_deny_re = re.compile(
        rf'^\s*log\s+.*prefix\s+"{re.escape(BLOCKED_LOG_PREFIX)}',
        re.MULTILINE,
    )
    if not _terminal_deny_re.search(nft_output):
        errors.append("terminal deny-all rule missing")
    errors.extend(_verify_private_blocks(nft_output))
    return errors


def verify_bypass_ruleset(nft_output: str, *, allow_all: bool = False) -> list[str]:
    """Check applied bypass ruleset invariants.  Returns errors (empty = OK).

    Verifies:
    - Output chain has policy accept
    - Input chain has policy drop
    - Bypass nflog prefix is present
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
        errors.append("bypass nflog prefix missing")
    if "allow_v4" not in nft_output:
        errors.append("allow_v4 set missing")
    if "allow_v6" not in nft_output:
        errors.append("allow_v6 set missing")
    if not allow_all:
        errors.extend(_verify_private_blocks(nft_output))
    return errors


def _verify_private_blocks(nft_output: str) -> list[str]:
    """Check private-range reject rules (RFC 1918 + RFC 4193/4291) are present.

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


# ── Rule fragment generators ────────────────────────────


def _audit_allow_rules() -> str:
    """Generate audit rules for allowed traffic (IPv4 + IPv6).

    No rate limit -- only new connections reach these rules because
    ``ct state established,related accept`` is earlier in the chain.
    """
    return (
        f'        ip daddr @allow_v4 log group {NFLOG_GROUP} prefix "{ALLOWED_LOG_PREFIX}: " counter accept\n'
        f'        ip6 daddr @allow_v6 log group {NFLOG_GROUP} prefix "{ALLOWED_LOG_PREFIX}: " counter accept'
    )


def _terminal_deny_rule() -> str:
    """Generate the terminal default-deny rule with NFLOG audit.

    Unclassified packets (not in any allow or deny set) are rejected and
    logged with the ``BLOCKED`` prefix.  NFLOG is fire-and-forget: if a
    clearance handler subscribes it can prompt the operator; otherwise
    events are silently dropped by the kernel.

    Uses ``icmpx`` for cross-family reject in ``inet`` tables —
    auto-selects ICMP (IPv4) or ICMPv6 (IPv6).
    """
    return (
        f'        log group {NFLOG_GROUP} prefix "{BLOCKED_LOG_PREFIX}: " '
        f"counter reject with icmpx admin-prohibited"
    )


def _deny_set_rules() -> str:
    """Generate deny-set match rules (IPv4 + IPv6).

    Packets matching the deny sets are immediately rejected with an ICMP error.
    Placed after allow-set rules, before private-range reject.
    """
    return (
        f'        ip daddr @deny_v4 log group {NFLOG_GROUP} prefix "{DENIED_LOG_PREFIX}: " counter reject with icmpx admin-prohibited\n'
        f'        ip6 daddr @deny_v6 log group {NFLOG_GROUP} prefix "{DENIED_LOG_PREFIX}: " counter reject with icmpx admin-prohibited'
    )


def _private_range_rules() -> str:
    """Generate private-range reject rules (RFC 1918 + RFC 4193/4291).

    Auto-detects address family for the ``daddr`` selector and uses
    cross-family ``icmpx`` reject for all ranges.
    """
    return "\n".join(
        f"        {'ip' if _is_v4(net) else 'ip6'} daddr {net}"
        f' log group {NFLOG_GROUP} prefix "{PRIVATE_LOG_PREFIX}: " reject with icmpx admin-prohibited'
        for net in PRIVATE_RANGES
    )


def _loopback_port_rules(ports: tuple[int, ...]) -> str:
    """Generate nft accept rules for host-loopback-proxy ports.

    Traffic to ``PASTA_HOST_LOOPBACK_MAP`` (169.254.1.2) goes via pasta's
    virtual interface, not ``lo``.  pasta's ``--map-host-loopback`` translates
    this address to ``127.0.0.1`` on the host, enabling container→host
    loopback access without the pasta 2.x "two loopbacks" splice bug.
    These rules are placed before the private-range reject block so that
    link-local traffic to 169.254.1.2 is accepted for the allowed ports.
    """
    return "\n".join(
        f"            tcp dport {p} ip daddr {PASTA_HOST_LOOPBACK_MAP} accept" for p in ports
    )


def _gateway_port_rules(ports: tuple[int, ...]) -> str:
    """Generate nft accept rules for gateway ports using dynamic gateway sets.

    References ``@gateway_v4`` and ``@gateway_v6`` sets, which are populated
    at container creation by the OCI hook reading ``/proc/{pid}/net/route``.
    Placed before private-range reject rules so gateway traffic (e.g. to
    slirp4netns 10.0.2.2) is not blocked by RFC 1918 filtering.
    Returns empty string if *ports* is empty.
    """
    if not ports:
        return ""
    lines = []
    for p in ports:
        lines.append(f"        tcp dport {p} ip daddr @gateway_v4 accept")
        lines.append(f"        tcp dport {p} ip6 daddr @gateway_v6 accept")
    return "\n".join(lines)


# ── Validation ──────────────────────────────────────────


def safe_ip(value: str) -> str:
    """Validate and normalize an IPv4 or IPv6 address or CIDR notation.

    Prevents nft command injection by ensuring the value is a valid
    IP address or network.  Returns the canonical string form so that
    string comparisons across state files (profile.allowed, live.allowed,
    deny.list) are reliable regardless of input notation.

    Raises ValueError on invalid input.
    """
    v = value.strip()
    try:
        if "/" in v:
            return str(ipaddress.ip_network(v, strict=False))
        return str(ipaddress.ip_address(v))
    except ValueError as e:
        raise ValueError(f"Invalid IP/CIDR: {v!r}") from e


def _safe_port(port: int) -> int:
    """Validate a port number.  Raises ValueError for out-of-range or non-int."""
    if isinstance(port, bool) or not isinstance(port, int):
        raise ValueError(f"Port must be an integer, got {type(port).__name__}")
    if not 1 <= port <= 65535:
        raise ValueError(f"Port out of range: {port}")
    return port


def _is_v4(value: str) -> bool:
    """Return True if a validated IP string is IPv4."""
    try:
        if "/" in value:
            return isinstance(ipaddress.ip_network(value, strict=False), ipaddress.IPv4Network)
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def _try_validate(ip: str) -> bool:
    """Return True if ip is a valid IP address/CIDR, False otherwise."""
    try:
        safe_ip(ip)
        return True
    except ValueError:
        return False


def _safe_timeout(value: str) -> str:
    """Validate an nft timeout value (e.g. ``30m``, ``1h``, ``60s``).

    Raises ValueError on invalid input.  Prevents injection via
    timeout strings in nft set declarations.
    """
    if not _SAFE_TIMEOUT_RE.fullmatch(value):
        raise ValueError(f"Invalid nft timeout: {value!r} (expected e.g. '30m', '1h', '60s')")
    return value


def _safe_ident(value: str) -> str:
    """Validate an nft identifier (table/set name) against injection.

    Raises:
        ValueError: If the identifier contains unsafe characters.
    """
    if not _SAFE_IDENT_RE.fullmatch(value):
        raise ValueError(f"Unsafe nft identifier: {value!r}")
    return value
