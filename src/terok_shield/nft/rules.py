# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""nftables ruleset generation and verification.

Generates per-container nftables rulesets as an ordered **tier policy** and
provides set operations for runtime allow/deny/override management, plus
verification of applied rulesets against security invariants.

The UP ruleset is a single output chain whose body is an ordered list of
tier rules.  nft evaluates them top to bottom: an ``accept``/``reject`` is a
terminal verdict (short-circuit), and a non-match falls through to the next
tier (a ``Pass``).  Tier order *is* the authority order::

    preamble          accept lo / established / DNS / infra ports
    t00 hard-deny     reject @HARD_DENY_RANGES   (link-local/IMDS — absolute)
    t10 override      accept @override           (break-glass, above the deny)
    t20 security-deny reject @deny + @PRIVATE_RANGES  (vault hosts + RFC1918)
    t30/40 allow      accept @allow              (provider + project)
    bypass window     accept @bypass_window      (kernel-timed allow-all)
    terminal          reject (log BLOCKED)

Because the deny tier sits *above* the allow tier, an explicit deny wins over
an allow; an override (t10) sits above the deny and is the only way to reach
a security-denied host.  The hard-deny floor (t00) sits above the override and
is absolute.

Security boundary: only stdlib + ``nft.constants`` imports.  All inputs are
validated before interpolation into nft commands.
"""
# WAYPOINT: Shield (__init__), HookMode (hooks.mode)

import ipaddress
import re
import textwrap
from collections.abc import Callable
from typing import Any

from .constants import (
    ALLOWED_LOG_PREFIX,
    BLOCKED_LOG_PREFIX,
    BYPASS_LOG_PREFIX,
    DENIED_LOG_PREFIX,
    HARD_DENY_RANGES,
    NFLOG_GROUP,
    NFT_TABLE,
    PASTA_DNS,
    PASTA_HOST_LOOPBACK_MAP,
    PRIVATE_LOG_PREFIX,
    PRIVATE_RANGES,
    SET_BYPASS_WINDOW,
    TIER_OVERRIDE,
    TIER_PROJECT_ALLOW,
    TIER_PROVIDER_ALLOW,
    TIER_SECURITY_DENY,
)

_SAFE_TIMEOUT_RE = re.compile(r"^\d+[smhd]$")
_SAFE_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# ``nft list`` prints element timeouts as compound durations (``1h22m10s``);
# authored timeouts stay restricted to the single-unit _SAFE_TIMEOUT_RE.
_ELEMENT_TIMEOUT_RE = re.compile(r"^(?:\d+[dhms])+$")
_ELEMENTS_BLOCK_RE = re.compile(r"elements = \{(.*?)\}", re.DOTALL)

# Cross-family reject (auto-selects ICMP / ICMPv6 in an ``inet`` table).
_REJECT = "reject with icmpx admin-prohibited"

# The tier sets, in chain order; each is dual-stack (``_v4`` / ``_v6``).  Names
# mirror the ``policy/<NN>-<name>`` bundle files 1:1 (``t<NN>_<name>``) so the
# file→rule mapping is self-evident.  ``t40_project_allow`` carries the dnsmasq
# element timeout (learned IPs); ``bypass_window`` always carries the timeout
# flag so its elements expire to close the timed allow-all window.
_TIER_SETS = (
    TIER_OVERRIDE,
    TIER_SECURITY_DENY,
    TIER_PROVIDER_ALLOW,
    TIER_PROJECT_ALLOW,
    SET_BYPASS_WINDOW,
)

_INPUT_CHAIN = """\
    chain input {
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
        ct state established,related accept
        drop
    }"""


# ── RulesetBuilder ──────────────────────────────────────


class RulesetBuilder:
    """Builder for nftables ruleset generation and verification.

    Security boundary: only stdlib + nft.constants imports.
    All inputs validated before interpolation.

    Binds ``dns``, ``loopback_ports``, gateways, and the dnsmasq set timeout
    once at construction so callers do not repeat them on every call.
    """

    def __init__(
        self,
        *,
        dns: str = PASTA_DNS,
        loopback_ports: tuple[int, ...] = (),
        gateway_v4: str = "",
        gateway_v6: str = "",
        set_timeout: str = "",
    ) -> None:
        """Create a builder with validated DNS, gateway, and port config.

        Args:
            dns: DNS server address (pasta default forwarder).
            loopback_ports: TCP ports to allow on the host-loopback map address.
            gateway_v4: IPv4 gateway address (e.g. slirp4netns ``10.0.2.2``).
            gateway_v6: IPv6 gateway address (e.g. slirp4netns ``fd00::2``).
            set_timeout: dnsmasq-tier element timeout for the allow sets (e.g. ``30m``).
        """
        dns = safe_ip(dns)
        for p in loopback_ports:
            _safe_port(p)
        if set_timeout:
            _safe_timeout(set_timeout)
        self._dns = dns
        self._loopback_ports = loopback_ports
        self._gateway_v4 = _safe_ipv4(gateway_v4) if gateway_v4 else ""
        self._gateway_v6 = _safe_ipv6(gateway_v6) if gateway_v6 else ""
        self._set_timeout = set_timeout

    # ── Ruleset generation ─────────────────────────────

    def build_up(self) -> str:
        """Generate the UP (deny-all + ordered tiers) ruleset.

        Applied by the OCI hook into the container's own netns.  Dual-stack.
        Infra ports (DNS, host-loopback proxy, gateway) are accepted in the
        preamble *before* any tier, so the control plane survives the hard-deny
        of link-local space.  See the module docstring for the tier order.
        """
        body = self._join(
            self._preamble_lines(),
            self._range_reject(HARD_DENY_RANGES, PRIVATE_LOG_PREFIX),  # t00 absolute
            self._match(TIER_OVERRIDE, "accept", ALLOWED_LOG_PREFIX),  # t10 break-glass
            self._match(TIER_SECURITY_DENY, _REJECT, DENIED_LOG_PREFIX),  # t20 deny set
            self._range_reject(PRIVATE_RANGES, PRIVATE_LOG_PREFIX),  # t20 RFC1918
            self._match(TIER_PROVIDER_ALLOW, "accept", ALLOWED_LOG_PREFIX),  # t30 provider
            self._match(TIER_PROJECT_ALLOW, "accept", ALLOWED_LOG_PREFIX),  # t40 project
            self._match(SET_BYPASS_WINDOW, "accept", BYPASS_LOG_PREFIX),  # timed window
            self._terminal(),  # terminal deny
        )
        return self._table(self._set_decls(), body, policy="drop")

    def build_down(self, *, disengaged: bool = False) -> str:
        """Generate the DOWN-posture (manual ``shield down``) ruleset.

        Output policy is ``accept`` and every new connection is logged with
        the bypass prefix.  Plain DOWN still enforces the hard-deny floor and
        the security-deny tier (deny set + private ranges), with the t10
        override kept *above* the deny — a break-glass host must stay
        reachable in every posture that enforces the deny.

        Args:
            disengaged: If True (DISENGAGED), enforce nothing: no hard-deny
                floor, no deny set, no private-range rejects — every
                destination is accepted and logged.  The tier sets stay
                declared (unreferenced) so allow-set contents survive the
                round trip back to ``shield up``.  Private addresses below
                the deny are reachable in the other postures through a t10
                override — a host, or a whole CIDR (logged as a warning);
                DISENGAGED opens everything without one.
        """
        sections = [self._preamble_lines()]
        if not disengaged:
            sections.extend(
                (
                    self._range_reject(HARD_DENY_RANGES, PRIVATE_LOG_PREFIX),
                    self._match(TIER_OVERRIDE, "accept", BYPASS_LOG_PREFIX),
                    self._match(TIER_SECURITY_DENY, _REJECT, DENIED_LOG_PREFIX),
                    self._range_reject(PRIVATE_RANGES, PRIVATE_LOG_PREFIX),
                )
            )
        sections.append(
            f'        ct state new log group {NFLOG_GROUP} prefix "{BYPASS_LOG_PREFIX}: " counter'
        )
        return self._table(self._set_decls(), self._join(*sections), policy="accept")

    @staticmethod
    def build_quarantine() -> str:
        """Generate the quarantine-mode (total blackout) ruleset.

        Drops all traffic except loopback and established connections.
        No DNS, no allowlists, no gateway ports.  All dropped packets
        are tagged for the audit log.
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

    # ── Verification ───────────────────────────────────

    def verify_up(self, nft_output: str) -> list[str]:
        """Check applied UP ruleset invariants.  Returns errors (empty = OK).

        Expects output from ``nft list table inet terok_shield`` (scoped to the
        managed table), not ``nft list ruleset``.  Verifies the table header,
        ``policy drop``, both chains, the reject type, every tier set, the
        terminal deny-all rule, and both range-reject floors.
        """
        errors: list[str] = []
        if f"table {NFT_TABLE}" not in nft_output:
            errors.append(f"managed table '{NFT_TABLE}' not found in output")
        if "policy drop" not in nft_output:
            errors.append("policy is not drop")
        errors.extend(self._verify_common(nft_output))
        # Terminal deny-all: a standalone log+reject with the BLOCKED prefix
        # (no daddr selector, unlike the tier rules).  Require the ``reject``
        # verdict on the same rule so a regression to a silent ``drop`` fails
        # verification instead of passing on the log line alone.
        if not re.search(
            rf'^\s*log\s+.*prefix\s+"{re.escape(BLOCKED_LOG_PREFIX)}.*\breject\b',
            nft_output,
            re.MULTILINE,
        ):
            errors.append("terminal reject-all rule missing")
        errors.extend(self._verify_ranges(nft_output, HARD_DENY_RANGES, "Hard-deny"))
        errors.extend(self._verify_ranges(nft_output, PRIVATE_RANGES, "Private-range"))
        return errors

    def verify_down(self, nft_output: str, *, disengaged: bool = False) -> list[str]:
        """Check applied DOWN-posture ruleset invariants.  Returns errors (empty = OK).

        Verifies the table header, ``policy accept`` on output / ``drop`` on
        input, both chains, every tier set, and the bypass nflog prefix.
        Plain DOWN must carry both range-reject floors; DISENGAGED must carry
        neither floor nor the deny-set reject — a partially applied ruleset
        that keeps any reject must not pass as DISENGAGED.
        """
        errors: list[str] = []
        if f"table {NFT_TABLE}" not in nft_output:
            errors.append(f"managed table '{NFT_TABLE}' not found in output")
        if "policy accept" not in nft_output:
            errors.append("output policy is not accept")
        if "policy drop" not in nft_output:
            errors.append("input policy is not drop")
        errors.extend(self._verify_common(nft_output, expect_reject=not disengaged))
        if BYPASS_LOG_PREFIX not in nft_output:
            errors.append("bypass nflog prefix missing")
        floors = ((HARD_DENY_RANGES, "Hard-deny"), (PRIVATE_RANGES, "Private-range"))
        if disengaged:
            for nets, label in floors:
                errors.extend(self._verify_ranges_absent(nft_output, nets, label))
            if re.search(rf"@{TIER_SECURITY_DENY}_v[46]\b.*\breject\b", nft_output):
                errors.append("deny-set reject rule present in DISENGAGED ruleset")
        else:
            for nets, label in floors:
                errors.extend(self._verify_ranges(nft_output, nets, label))
        return errors

    @staticmethod
    def verify_quarantine(nft_output: str) -> list[str]:
        """Check applied quarantine ruleset invariants.  Returns errors (empty = OK).

        Verifies the table header, both chains with ``policy drop``, the blocked
        log prefix, and that no allow sets exist (total blackout).
        """
        errors: list[str] = []
        if f"table {NFT_TABLE}" not in nft_output:
            errors.append(f"managed table '{NFT_TABLE}' not found in output")
        if "policy drop" not in nft_output:
            errors.append("policy is not drop")
        for chain in ("output", "input"):
            if f"chain {chain}" not in nft_output:
                errors.append(f"{chain} chain missing")
        if BLOCKED_LOG_PREFIX not in nft_output:
            errors.append("blocked nflog prefix missing")
        for base in (TIER_PROVIDER_ALLOW, TIER_PROJECT_ALLOW):
            for fam in ("v4", "v6"):
                sname = f"{base}_{fam}"
                if sname in nft_output:
                    errors.append(f"{sname} set present in quarantine mode")
        return errors

    # ── Set operations (instance) ──────────────────────

    def add_elements_dual(self, ips: list[str]) -> str:
        """Add IPs to the tier-40 project-allow sets, honouring the dnsmasq permanent-element rule.

        When a ``set_timeout`` is configured (dnsmasq tier), profile/live IPs are
        written with ``timeout 0s`` so they do not auto-expire with the
        dnsmasq-learned entries.
        """
        return add_elements_dual(ips, permanent=bool(self._set_timeout))

    # ── Private helpers ────────────────────────────────

    @staticmethod
    def _join(*sections: str) -> str:
        """Join non-empty rule sections with newlines."""
        return "\n".join(s for s in sections if s)

    @staticmethod
    def _table(set_decls: str, output_body: str, *, policy: str) -> str:
        """Wrap set declarations and an output-chain body into the managed table."""
        return (
            f"table {NFT_TABLE} {{\n"
            f"{set_decls}\n\n"
            f"    chain output {{\n"
            f"        type filter hook output priority filter; policy {policy};\n"
            f"{output_body}\n"
            f"    }}\n\n"
            f"{_INPUT_CHAIN}\n"
            f"}}\n"
        )

    def _set_decls(self) -> str:
        """Declare every tier set (dual-stack), with the right flags per tier."""
        lines: list[str] = []
        for base in _TIER_SETS:
            timeout = self._set_timeout if base == TIER_PROJECT_ALLOW else ""
            timed = base == SET_BYPASS_WINDOW
            lines.append(f"    {self._decl(f'{base}_v4', 'ipv4_addr', timeout, timed=timed)}")
            lines.append(f"    {self._decl(f'{base}_v6', 'ipv6_addr', timeout, timed=timed)}")
        return "\n".join(lines)

    @staticmethod
    def _decl(name: str, family: str, set_timeout: str = "", *, timed: bool = False) -> str:
        """Generate one nft set declaration.

        Args:
            set_timeout: a default element timeout (dnsmasq tier) — adds the
                ``timeout`` flag *and* a default.
            timed: declare the ``timeout`` flag with no default, so elements
                carry their own timeout (the bypass window).
        """
        if set_timeout:
            return (
                f"set {name} {{ type {family}; flags interval, timeout; timeout {set_timeout}; }}"
            )
        if timed:
            return f"set {name} {{ type {family}; flags interval, timeout; }}"
        return f"set {name} {{ type {family}; flags interval; }}"

    def _preamble_lines(self) -> str:
        """Validate inputs and build the always-accept preamble (DNS + infra ports)."""
        dns = safe_ip(self._dns)
        if self._set_timeout:
            _safe_timeout(self._set_timeout)
        for p in self._loopback_ports:
            _safe_port(p)
        dns_af = "ip" if _is_v4(dns) else "ip6"
        lines = [
            '        oifname "lo" accept',
            "        ct state established,related accept",
            f"        udp dport 53 {dns_af} daddr {dns} accept",
            f"        tcp dport 53 {dns_af} daddr {dns} accept",
        ]
        gw = self._gateway_port_rules(self._loopback_ports, self._gateway_v4, self._gateway_v6)
        if gw:
            lines.append(gw)
        lp = self._loopback_port_rules(self._loopback_ports)
        if lp:
            lines.append(lp)
        return "\n".join(lines)

    @staticmethod
    def _match(base: str, verdict: str, prefix: str = "") -> str:
        """Emit the dual-stack set-match rules for tier *base* (``@base_v4``/``_v6``).

        *verdict* is ``accept`` or the reject expression.  A *prefix* adds an
        NFLOG audit tag (only new connections reach these rules, since
        ``established,related`` is accepted in the preamble).
        """
        log = f'log group {NFLOG_GROUP} prefix "{prefix}: " counter ' if prefix else ""
        return (
            f"        ip daddr @{base}_v4 {log}{verdict}\n"
            f"        ip6 daddr @{base}_v6 {log}{verdict}"
        )

    @staticmethod
    def _range_reject(nets: tuple[str, ...], prefix: str) -> str:
        """Emit reject rules for a tuple of static CIDR ranges (auto v4/v6)."""
        return "\n".join(
            f"        {'ip' if _is_v4(net) else 'ip6'} daddr {net} "
            f'log group {NFLOG_GROUP} prefix "{prefix}: " {_REJECT}'
            for net in nets
        )

    @staticmethod
    def _terminal() -> str:
        """Emit the terminal default-deny rule with NFLOG audit (BLOCKED prefix)."""
        return f'        log group {NFLOG_GROUP} prefix "{BLOCKED_LOG_PREFIX}: " counter {_REJECT}'

    @staticmethod
    def _verify_common(nft_output: str, *, expect_reject: bool = True) -> list[str]:
        """Check the chains, every tier set, and (when *expect_reject*) the reject type."""
        errors: list[str] = []
        for chain in ("output", "input"):
            if f"chain {chain}" not in nft_output:
                errors.append(f"{chain} chain missing")
        if expect_reject and "admin-prohibited" not in nft_output:
            errors.append("reject type missing")
        for base in _TIER_SETS:
            for fam in ("v4", "v6"):
                if f"{base}_{fam}" not in nft_output:
                    errors.append(f"{base}_{fam} set missing")
        return errors

    @staticmethod
    def _verify_ranges(nft_output: str, nets: tuple[str, ...], label: str) -> list[str]:
        """Check each range has a reject rule (matches rule context, not bare CIDR)."""
        errors: list[str] = []
        for net in nets:
            selector = "ip" if _is_v4(net) else "ip6"
            if not re.search(rf"{selector} daddr {re.escape(net)}.*reject", nft_output):
                errors.append(f"{label} reject rule for {net} missing")
        return errors

    @staticmethod
    def _verify_ranges_absent(nft_output: str, nets: tuple[str, ...], label: str) -> list[str]:
        """Check no range carries a reject rule — the DISENGAGED invariant."""
        errors: list[str] = []
        for net in nets:
            selector = "ip" if _is_v4(net) else "ip6"
            if re.search(rf"{selector} daddr {re.escape(net)}.*reject", nft_output):
                errors.append(f"{label} reject rule for {net} present in DISENGAGED ruleset")
        return errors

    @staticmethod
    def _loopback_port_rules(ports: tuple[int, ...]) -> str:
        """Accept rules for host-loopback-proxy ports (via the pasta map address).

        Traffic to ``PASTA_HOST_LOOPBACK_MAP`` (169.254.1.2) is translated by
        pasta to ``127.0.0.1`` on the host.  Emitted in the preamble, before the
        hard-deny of link-local space, so the broker/signer/gate stay reachable.
        """
        return "\n".join(
            f"        tcp dport {p} ip daddr {PASTA_HOST_LOOPBACK_MAP} accept" for p in ports
        )

    @staticmethod
    def _gateway_port_rules(
        ports: tuple[int, ...], gateway_v4: str = "", gateway_v6: str = ""
    ) -> str:
        """Accept rules for gateway (slirp4netns) host-service ports.

        Literal gateway IPs baked in at generation time; emitted in the preamble
        before the private-range reject so RFC 1918 traffic to the gateway is
        accepted.
        """
        if not ports or not (gateway_v4 or gateway_v6):
            return ""
        lines: list[str] = []
        for p in ports:
            if gateway_v4:
                lines.append(f"        tcp dport {p} ip daddr {safe_ip(gateway_v4)} accept")
            if gateway_v6:
                lines.append(f"        tcp dport {p} ip6 daddr {safe_ip(gateway_v6)} accept")
        return "\n".join(lines)


# ── Set operations ──────────────────────────────────────


def add_elements_dual(ips: list[str], *, permanent: bool = False) -> str:
    """Add IPs to the tier-40 project-allow sets, split by address family.

    Args:
        permanent: annotate elements with ``timeout 0s`` so profile/live IPs
            never expire in the dnsmasq-tier allow set (which carries a default
            element timeout for learned IPs).
    """
    return _emit_dual(add_elements, TIER_PROJECT_ALLOW, ips, timeout_zero=permanent)


def add_deny_elements_dual(ips: list[str]) -> str:
    """Add IPs to the tier-20 security-deny sets, split by address family."""
    return _emit_dual(add_elements, TIER_SECURITY_DENY, ips)


def add_override_elements_dual(ips: list[str]) -> str:
    """Add IPs to the tier-10 override (break-glass) sets, split by address family."""
    return _emit_dual(add_elements, TIER_OVERRIDE, ips)


def delete_deny_elements_dual(ips: list[str]) -> str:
    """Remove IPs from the tier-20 security-deny sets, split by address family."""
    return _emit_dual(delete_elements, TIER_SECURITY_DENY, ips)


def arm_bypass_window(timeout: str) -> str:
    """Open the timed allow-all window.

    Adds ``0.0.0.0/0`` / ``::/0`` to the ``bypass_window`` sets with a kernel
    ``timeout`` so the window closes itself when the element expires — no
    userspace timer, fail-closed (any disruption only closes it sooner).
    """
    _safe_timeout(timeout)
    return (
        f"add element {NFT_TABLE} {SET_BYPASS_WINDOW}_v4 {{ 0.0.0.0/0 timeout {timeout} }}\n"
        f"add element {NFT_TABLE} {SET_BYPASS_WINDOW}_v6 {{ ::/0 timeout {timeout} }}\n"
    )


def disarm_bypass_window() -> str:
    """Close the timed allow-all window immediately by flushing both sets."""
    return (
        f"flush set {NFT_TABLE} {SET_BYPASS_WINDOW}_v4\n"
        f"flush set {NFT_TABLE} {SET_BYPASS_WINDOW}_v6\n"
    )


def parse_set_elements(nft_output: str) -> list[tuple[str, str]]:
    """Parse ``nft list set`` output into ``(ip, timeout)`` pairs.

    *timeout* is the element's printed timeout token (``"30m"``, ``"0s"``,
    compound ``"1h22m"``) or ``""`` when the element carries none.  The
    remaining ``expires`` countdown is deliberately dropped — a restore via
    [`restore_elements`][terok_shield.nft.rules.restore_elements] re-grants
    the full timeout.  Atoms that fail validation are skipped rather than
    raised: the snapshot/restore path is best-effort by design (a dropped
    learned IP is re-learned on the workload's next DNS answer), and a
    parse quirk must never abort a shield state transition.
    """
    block = _ELEMENTS_BLOCK_RE.search(nft_output)
    if not block:
        return []
    pairs: list[tuple[str, str]] = []
    for atom in block.group(1).split(","):
        tokens = atom.split()
        if not tokens:
            continue
        try:
            ip = safe_ip(tokens[0])
        except ValueError:
            continue
        timeout = ""
        if len(tokens) >= 3 and tokens[1] == "timeout" and _ELEMENT_TIMEOUT_RE.fullmatch(tokens[2]):
            timeout = tokens[2]
        pairs.append((ip, timeout))
    return pairs


def restore_elements(set_name: str, elements: list[tuple[str, str]], table: str = NFT_TABLE) -> str:
    """Generate an nft command re-adding dumped ``(ip, timeout)`` elements.

    Counterpart of [`parse_set_elements`][terok_shield.nft.rules.parse_set_elements]:
    every input is re-validated before interpolation (the snapshot crosses a
    subprocess boundary, so it is treated as untrusted like any other input).
    Timed elements are re-granted their full timeout.  Returns ``""`` when
    there is nothing to restore.
    """
    set_name = _safe_ident(set_name)
    table = " ".join(_safe_ident(part) for part in table.split())
    parts: list[str] = []
    for ip, timeout in elements:
        ip = safe_ip(ip)
        if not timeout:
            parts.append(ip)
            continue
        if not _ELEMENT_TIMEOUT_RE.fullmatch(timeout):
            raise ValueError(f"Invalid element timeout: {timeout!r}")
        parts.append(f"{ip} timeout {timeout}")
    if not parts:
        return ""
    return f"add element {table} {set_name} {{ {', '.join(parts)} }}\n"


def add_elements(
    set_name: str, ips: list[str], table: str = NFT_TABLE, *, timeout_zero: bool = False
) -> str:
    """Generate an nft command to add validated IPs to a set.

    Both ``set_name`` and ``table`` are validated against injection.
    Returns empty string if no valid IPs.

    Args:
        timeout_zero: annotate each element with ``timeout 0s`` so it never
            expires, even in a set that carries a default element timeout.
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
    """Generate an nft command to delete validated IPs from a set.

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


def _emit_dual(op: Callable[..., str], base: str, ips: list[str], **kwargs: Any) -> str:
    """Split *ips* by family and apply *op* to the ``base_v4`` / ``base_v6`` sets."""
    parts: list[str] = []
    for fam, group in zip(("v4", "v6"), _split_family(ips), strict=True):
        cmd = op(f"{base}_{fam}", group, **kwargs)
        if cmd:
            parts.append(cmd)
    return "".join(parts)


def _split_family(ips: list[str]) -> tuple[list[str], list[str]]:
    """Partition validated IPs into ``(ipv4, ipv6)``; invalid entries are dropped."""
    v4: list[str] = []
    v6: list[str] = []
    for ip in ips:
        try:
            sanitized = safe_ip(ip)
        except ValueError:
            continue
        (v4 if _is_v4(sanitized) else v6).append(sanitized)
    return v4, v6


# ── Validation ──────────────────────────────────────────


def safe_ip(value: str) -> str:
    """Validate and normalize an IPv4 or IPv6 address or CIDR notation.

    Prevents nft command injection by ensuring the value is a valid IP address
    or network.  Returns the canonical string form so comparisons across state
    files are reliable regardless of input notation.

    Raises ValueError on invalid input.
    """
    v = value.strip()
    try:
        if "/" in v:
            return str(ipaddress.ip_network(v, strict=False))
        return str(ipaddress.ip_address(v))
    except ValueError as e:
        raise ValueError(f"Invalid IP/CIDR: {v!r}") from e


def _safe_ipv4(value: str) -> str:
    """Validate *value* as an IPv4 address.  Raises ValueError if IPv6 or invalid."""
    addr = ipaddress.ip_address(value.strip())
    if addr.version != 4:
        raise ValueError(f"Expected IPv4, got IPv6: {value!r}")
    return str(addr)


def _safe_ipv6(value: str) -> str:
    """Validate *value* as an IPv6 address.  Raises ValueError if IPv4 or invalid."""
    addr = ipaddress.ip_address(value.strip())
    if addr.version != 6:
        raise ValueError(f"Expected IPv6, got IPv4: {value!r}")
    return str(addr)


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

    Raises ValueError on invalid input.  Prevents injection via timeout strings
    in nft set declarations and element commands.
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
