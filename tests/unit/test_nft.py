# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for nft.py -- the auditable security boundary.

These tests intentionally optimize for explicit security-property checks over
maximum DRYness. Small helpers and parametrization are used only when they make
the asserted invariant clearer; they should never hide rule ordering,
allow-vs-deny semantics, or input-validation guarantees.
"""

import pytest

from terok_shield.nft.constants import (
    BLOCKED_LOG_PREFIX,
    BYPASS_LOG_PREFIX,
    HARD_DENY_RANGES,
    NFT_TABLE,
    PASTA_HOST_LOOPBACK_MAP,
    PRIVATE_RANGES,
)
from terok_shield.nft.rules import (
    RulesetBuilder,
    _is_v4,
    _safe_timeout,
    add_deny_elements_dual,
    add_elements,
    add_elements_dual,
    add_override_elements_dual,
    arm_bypass_window,
    delete_deny_elements_dual,
    disarm_bypass_window,
    parse_set_elements,
    restore_elements,
    safe_ip,
)

from ..testnet import (
    AWS_IMDS_V6,
    IPV4_CIDR_HOST_BITS,
    IPV4_CIDR_HOST_BITS_CANONICAL,
    IPV6_CLOUDFLARE,
    IPV6_NET1,
    IPV6_VERBOSE,
    IPV6_VERBOSE_CANONICAL,
    LINK_LOCAL_DNS,
    SLIRP4NETNS_DNS,
    TEST_DOMAIN,
    TEST_IP1,
    TEST_IP2,
    TEST_NET1,
)

_ALLOW_V4_SET = "set t40_project_allow_v4 { type ipv4_addr; flags interval; }"
_ALLOW_V6_SET = "set t40_project_allow_v6 { type ipv6_addr; flags interval; }"
_DENY_V4_SET = "set t20_security_deny_v4 { type ipv4_addr; flags interval; }"
_DENY_V6_SET = "set t20_security_deny_v6 { type ipv6_addr; flags interval; }"
_ALLOW_LOG_PREFIX = "TEROK_SHIELD_ALLOWED"
_DENY_LOG_PREFIX = "TEROK_SHIELD_DENIED"
_ALLOWED_LOG_PREFIX = "TEROK_SHIELD_ALLOWED"
_BYPASS_LOG_PREFIX = "TEROK_SHIELD_BYPASS"
_BLOCKED_LOG_PREFIX = "TEROK_SHIELD_BLOCKED"
_ADMIN_PROHIBITED = "admin-prohibited"
_INPUT_CHAIN = "chain input"
_OUTPUT_CHAIN = "chain output"
_LOOPBACK_ACCEPT = 'oifname "lo" accept'
_UNSAFE_SET_NAME = "t40_project_allow_v4; drop"
_UNSAFE_TABLE_NAME = f"{NFT_TABLE}; drop"


def _private_reject_rule(net: str) -> str:
    """Return the expected reject rule fragment for one private range."""
    selector = "ip" if "." in net else "ip6"
    return f"{selector} daddr {net} reject with icmpx admin-prohibited"


def _private_reject_rules(ranges: tuple[str, ...] = PRIVATE_RANGES) -> str:
    """Render the private-range reject rules expected by verification tests."""
    return "\n".join(_private_reject_rule(net) for net in ranges)


def _add_element_command(set_name: str, *ips: str) -> str:
    """Build the exact add-element command expected from nft.py."""
    return f"add element {NFT_TABLE} {set_name} {{ {', '.join(ips)} }}\n"


def _dns_accept_rules(ruleset: str) -> set[str]:
    """Return the exact DNS exception lines from a rendered ruleset."""
    return {line.strip() for line in ruleset.splitlines() if "dport 53" in line}


# ── safe_ip() ---------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param(TEST_IP1, TEST_IP1, id="ipv4-address"),
        pytest.param(TEST_NET1, TEST_NET1, id="ipv4-cidr"),
        pytest.param(f"  {TEST_IP1}  ", TEST_IP1, id="strips-whitespace"),
        pytest.param(IPV6_CLOUDFLARE, IPV6_CLOUDFLARE, id="ipv6-address"),
        pytest.param(IPV6_NET1, IPV6_NET1, id="ipv6-cidr"),
        pytest.param(IPV6_VERBOSE, IPV6_VERBOSE_CANONICAL, id="normalizes-ipv6"),
        pytest.param(
            IPV4_CIDR_HOST_BITS,
            IPV4_CIDR_HOST_BITS_CANONICAL,
            id="normalizes-ipv4-cidr-host-bits",
        ),
    ],
)
def test_safe_ip_accepts_and_normalizes_valid_input(raw: str, expected: str) -> None:
    """safe_ip() accepts only valid IPs/CIDRs and returns canonical forms."""
    assert safe_ip(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(TEST_DOMAIN, id="hostname"),
        pytest.param(f"{TEST_IP1}; drop", id="command-injection"),
        pytest.param("", id="empty-string"),
        pytest.param("not-an-ip", id="nonsense"),
    ],
)
def test_safe_ip_rejects_invalid_input(raw: str) -> None:
    """safe_ip() rejects hostnames, injections, and malformed addresses."""
    with pytest.raises(ValueError):
        safe_ip(raw)


# ── _is_v4() -------------------------------------------------------------


def test_is_v4_returns_false_for_garbage() -> None:
    """_is_v4() returns False (not raises) for unparseable input."""
    assert _is_v4("not-an-ip") is False


# ── build_up() ------------------------------------------------------


@pytest.mark.parametrize(
    "fragment",
    [
        pytest.param("policy drop", id="output-policy-drop"),
        pytest.param(_OUTPUT_CHAIN, id="output-chain"),
        pytest.param(_INPUT_CHAIN, id="input-chain"),
        pytest.param(_ALLOW_V4_SET, id="allow-v4-set"),
        pytest.param(_ALLOW_V6_SET, id="allow-v6-set"),
        pytest.param(_DENY_V4_SET, id="deny-v4-set"),
        pytest.param(_DENY_V6_SET, id="deny-v6-set"),
        pytest.param(_LOOPBACK_ACCEPT, id="loopback-accept"),
        pytest.param(_ALLOW_LOG_PREFIX, id="allow-log-prefix"),
        pytest.param(_DENY_LOG_PREFIX, id="deny-log-prefix"),
        pytest.param(_ADMIN_PROHIBITED, id="reject-type"),
    ],
)
def test_hook_ruleset_contains_required_fragments(fragment: str) -> None:
    """The enforcing ruleset contains the expected top-level invariants."""
    assert fragment in RulesetBuilder().build_up()


def test_hook_ruleset_blocks_all_private_and_hard_deny_ranges() -> None:
    """Every hard-deny (link-local/IMDS) and private (RFC1918/ULA) range is rejected."""
    rs = RulesetBuilder().build_up()
    for net in HARD_DENY_RANGES + PRIVATE_RANGES:
        assert net in rs, f"Range {net!r} missing from hook ruleset"


def test_hook_ruleset_accepts_dns_to_the_configured_forwarder() -> None:
    """Only the configured DNS forwarder is granted the DNS exception."""
    ruleset = RulesetBuilder(dns=LINK_LOCAL_DNS).build_up()
    assert _dns_accept_rules(ruleset) == {
        f"udp dport 53 ip daddr {LINK_LOCAL_DNS} accept",
        f"tcp dport 53 ip daddr {LINK_LOCAL_DNS} accept",
    }


def test_hook_ruleset_default_tcp_rules_are_dns_only() -> None:
    """Without loopback ports, TCP port rules must be limited to DNS."""
    tcp_rules = [
        line.strip() for line in RulesetBuilder().build_up().splitlines() if "tcp dport" in line
    ]
    assert tcp_rules
    assert all(line.startswith("tcp dport 53 ") for line in tcp_rules)


@pytest.mark.parametrize(
    ("ports", "expected_rules"),
    [
        pytest.param(
            (9418,),
            [f"tcp dport 9418 ip daddr {PASTA_HOST_LOOPBACK_MAP} accept"],
            id="single-loopback-port",
        ),
        pytest.param(
            (8080, 9090),
            [
                f"tcp dport 8080 ip daddr {PASTA_HOST_LOOPBACK_MAP} accept",
                f"tcp dport 9090 ip daddr {PASTA_HOST_LOOPBACK_MAP} accept",
            ],
            id="multiple-loopback-ports",
        ),
    ],
)
def test_hook_ruleset_emits_one_rule_per_loopback_port(
    ports: tuple[int, ...],
    expected_rules: list[str],
) -> None:
    """Each configured loopback port gets its own accept rule before private-range reject."""
    ruleset = RulesetBuilder(loopback_ports=ports).build_up()
    for rule in expected_rules:
        assert rule in ruleset
        # Loopback port rules must fire before the 169.254.0.0/16 private-range reject
        assert ruleset.index(rule) < ruleset.index("169.254.0.0/16")


def test_hook_ruleset_tier_order_is_authority_order() -> None:
    """Tier order is the authority order: hard-deny < override < deny < private < allow.

    The deny tier sits ABOVE the allow tier, so an explicit deny wins over an
    allow; the override tier sits above the deny (the only way past a
    security-deny); and the hard-deny floor (link-local/IMDS) sits above the
    override — absolute, not even override-able.
    """
    rs = RulesetBuilder().build_up()
    hard_deny = rs.index(HARD_DENY_RANGES[0])  # 169.254.0.0/16
    override = rs.index("@t10_override_v4")
    deny = rs.index("@t20_security_deny_v4")
    private = rs.index(PRIVATE_RANGES[0])  # 10.0.0.0/8
    allow = rs.index("@t40_project_allow_v4")
    assert hard_deny < override < deny < private < allow


def test_v6_imds_floor_is_absolute() -> None:
    """The AWS v6 metadata endpoint is hard-denied ABOVE the override tier.

    It lives inside ULA ``fc00::/7``, whose reject sits *below* the override
    — so without its own t00 entry, a deliberate ULA carve-out override
    would reach the v6 metadata service and the absolute-IMDS guarantee
    would be v4-only.
    """
    rs = RulesetBuilder().build_up()
    imds = rs.index(f"ip6 daddr {AWS_IMDS_V6} ")
    assert imds < rs.index("@t10_override_v4")
    # Bare-address form: nft strips /128 on listing, so verification
    # round-trips only the bare literal.
    assert f"{AWS_IMDS_V6}/128" not in rs


# ── Terminal deny rule (BLOCKED prefix) ───────────────


def test_hook_ruleset_uses_blocked_prefix() -> None:
    """Terminal deny rule uses the BLOCKED prefix for unclassified connections."""
    ruleset = RulesetBuilder().build_up()
    assert _BLOCKED_LOG_PREFIX in ruleset


def test_hook_ruleset_terminal_rule_is_standalone_log_reject() -> None:
    """Terminal deny rule is a standalone log+reject (no daddr selector)."""
    lines = RulesetBuilder().build_up().splitlines()
    terminal = [
        ln.strip()
        for ln in lines
        if ln.strip().startswith("log group") and _BLOCKED_LOG_PREFIX in ln and "reject" in ln
    ]
    assert len(terminal) == 1, "Exactly one terminal BLOCKED rule expected"


def test_hook_ruleset_deny_sets_use_denied_prefix() -> None:
    """Deny set rules use the DENIED prefix (not BLOCKED)."""
    ruleset = RulesetBuilder().build_up()
    assert "@t20_security_deny_v4" in ruleset, "t20_security_deny_v4 set rule missing from ruleset"
    assert "@t20_security_deny_v6" in ruleset, "t20_security_deny_v6 set rule missing from ruleset"
    # Deny set rules have a daddr selector + DENIED prefix
    lines = [
        ln
        for ln in ruleset.splitlines()
        if "@t20_security_deny_v4" in ln or "@t20_security_deny_v6" in ln
    ]
    assert all(_DENY_LOG_PREFIX in ln for ln in lines)
    assert not any(_BLOCKED_LOG_PREFIX in ln for ln in lines)


def test_hook_ruleset_has_no_queued_prefix() -> None:
    """Hook ruleset must not contain the legacy QUEUED log prefix."""
    assert "QUEUED" not in RulesetBuilder().build_up()


def test_verify_ruleset_checks_deny_sets() -> None:
    """verify_ruleset() requires t20_security_deny_v4 and t20_security_deny_v6 sets."""
    minimal = (
        f"policy drop {_ADMIN_PROHIBITED} "
        f'log group 100 prefix "{_BLOCKED_LOG_PREFIX}" '
        f"t40_project_allow_v4 t40_project_allow_v6 {_OUTPUT_CHAIN} {_INPUT_CHAIN}\n"
        f"{_private_reject_rules()}"
    )
    errors = RulesetBuilder().verify_up(minimal)
    assert "t20_security_deny_v4 set missing" in errors
    assert "t20_security_deny_v6 set missing" in errors


def test_ruleset_builder_rejects_invalid_dns() -> None:
    """RulesetBuilder rejects non-IP DNS values before interpolation."""
    with pytest.raises(ValueError):
        RulesetBuilder(dns="not-an-ip")


@pytest.mark.parametrize(
    "ports",
    [
        pytest.param((0,), id="port-too-low"),
        pytest.param((99999,), id="port-too-high"),
        pytest.param((True,), id="bool-port"),
    ],
)
def test_ruleset_builder_rejects_invalid_loopback_ports(
    ports: tuple[int, ...],
) -> None:
    """RulesetBuilder rejects out-of-range and boolean loopback ports."""
    with pytest.raises(ValueError):
        RulesetBuilder(loopback_ports=ports)


# ── add_elements() / add_elements_dual() ------------------------------


@pytest.mark.parametrize(
    ("ips", "expected"),
    [
        pytest.param(
            [TEST_IP1, TEST_IP2],
            _add_element_command("t40_project_allow_v4", TEST_IP1, TEST_IP2),
            id="valid-ipv4s",
        ),
        pytest.param(
            [TEST_IP1, "invalid", TEST_IP2],
            _add_element_command("t40_project_allow_v4", TEST_IP1, TEST_IP2),
            id="skips-invalid-inputs",
        ),
        pytest.param(
            [IPV4_CIDR_HOST_BITS],
            _add_element_command("t40_project_allow_v4", IPV4_CIDR_HOST_BITS_CANONICAL),
            id="canonicalizes-cidrs",
        ),
    ],
)
def test_add_elements_emits_only_valid_canonicalized_values(ips: list[str], expected: str) -> None:
    """add_elements() filters invalid values and normalizes the rest."""
    assert add_elements("t40_project_allow_v4", ips) == expected


@pytest.mark.parametrize(
    "ips",
    [pytest.param([], id="empty-list"), pytest.param(["bad", "worse"], id="all-invalid")],
)
def test_add_elements_returns_empty_when_no_ips_survive_validation(ips: list[str]) -> None:
    """add_elements() returns no command when every candidate is invalid."""
    assert add_elements("t40_project_allow_v4", ips) == ""


@pytest.mark.parametrize(
    ("set_name", "table"),
    [
        pytest.param(_UNSAFE_SET_NAME, NFT_TABLE, id="unsafe-set-name"),
        pytest.param("t40_project_allow_v4", _UNSAFE_TABLE_NAME, id="unsafe-table-name"),
    ],
)
def test_add_elements_rejects_unsafe_identifiers(set_name: str, table: str) -> None:
    """Set names and table names are validated against nft injection."""
    with pytest.raises(ValueError):
        add_elements(set_name, [TEST_IP1], table=table)


@pytest.mark.parametrize(
    ("ips", "expected"),
    [
        pytest.param(
            [TEST_IP1, TEST_IP2],
            _add_element_command("t40_project_allow_v4", TEST_IP1, TEST_IP2),
            id="ipv4-only",
        ),
        pytest.param(
            [IPV6_CLOUDFLARE],
            _add_element_command("t40_project_allow_v6", IPV6_CLOUDFLARE),
            id="ipv6-only",
        ),
        pytest.param(
            [TEST_IP1, IPV6_CLOUDFLARE],
            _add_element_command("t40_project_allow_v4", TEST_IP1)
            + _add_element_command("t40_project_allow_v6", IPV6_CLOUDFLARE),
            id="mixed-families",
        ),
        pytest.param(
            [TEST_IP1, "invalid", IPV6_CLOUDFLARE],
            _add_element_command("t40_project_allow_v4", TEST_IP1)
            + _add_element_command("t40_project_allow_v6", IPV6_CLOUDFLARE),
            id="skips-invalid-and-preserves-family-order",
        ),
        pytest.param(
            [IPV4_CIDR_HOST_BITS, IPV6_VERBOSE],
            _add_element_command("t40_project_allow_v4", IPV4_CIDR_HOST_BITS_CANONICAL)
            + _add_element_command("t40_project_allow_v6", IPV6_VERBOSE_CANONICAL),
            id="canonicalizes-both-families",
        ),
    ],
)
def test_add_elements_dual_classifies_by_address_family(ips: list[str], expected: str) -> None:
    """add_elements_dual() emits IPv4 commands before IPv6 commands."""
    assert add_elements_dual(ips) == expected


@pytest.mark.parametrize(
    "ips",
    [pytest.param([], id="empty-list"), pytest.param(["bad", "worse"], id="all-invalid")],
)
def test_add_elements_dual_returns_empty_when_no_valid_ips_remain(ips: list[str]) -> None:
    """add_elements_dual() returns an empty command batch when all inputs are invalid."""
    assert add_elements_dual(ips) == ""


# ── add_deny_elements_dual() / delete_deny_elements_dual() -----------


def _deny_add_element_command(set_name: str, *ips: str) -> str:
    """Build the exact add-element command expected for deny sets."""
    return f"add element {NFT_TABLE} {set_name} {{ {', '.join(ips)} }}\n"


def _deny_delete_element_command(set_name: str, *ips: str) -> str:
    """Build the exact delete-element command expected for deny sets."""
    return f"delete element {NFT_TABLE} {set_name} {{ {', '.join(ips)} }}\n"


@pytest.mark.parametrize(
    ("ips", "expected"),
    [
        pytest.param(
            [TEST_IP1, TEST_IP2],
            _deny_add_element_command("t20_security_deny_v4", TEST_IP1, TEST_IP2),
            id="ipv4-only",
        ),
        pytest.param(
            [IPV6_CLOUDFLARE],
            _deny_add_element_command("t20_security_deny_v6", IPV6_CLOUDFLARE),
            id="ipv6-only",
        ),
        pytest.param(
            [TEST_IP1, IPV6_CLOUDFLARE],
            _deny_add_element_command("t20_security_deny_v4", TEST_IP1)
            + _deny_add_element_command("t20_security_deny_v6", IPV6_CLOUDFLARE),
            id="mixed-families",
        ),
        pytest.param(
            [TEST_IP1, "invalid", IPV6_CLOUDFLARE],
            _deny_add_element_command("t20_security_deny_v4", TEST_IP1)
            + _deny_add_element_command("t20_security_deny_v6", IPV6_CLOUDFLARE),
            id="skips-invalid",
        ),
    ],
)
def test_add_deny_elements_dual_classifies_by_family(ips: list[str], expected: str) -> None:
    """add_deny_elements_dual() emits IPv4 deny commands before IPv6 deny commands."""
    assert add_deny_elements_dual(ips) == expected


@pytest.mark.parametrize(
    "ips",
    [pytest.param([], id="empty-list"), pytest.param(["bad", "worse"], id="all-invalid")],
)
def test_add_deny_elements_dual_returns_empty_when_no_valid_ips(ips: list[str]) -> None:
    """add_deny_elements_dual() returns empty when all inputs are invalid."""
    assert add_deny_elements_dual(ips) == ""


@pytest.mark.parametrize(
    ("ips", "expected"),
    [
        pytest.param(
            [TEST_IP1, TEST_IP2],
            _deny_delete_element_command("t20_security_deny_v4", TEST_IP1, TEST_IP2),
            id="ipv4-only",
        ),
        pytest.param(
            [IPV6_CLOUDFLARE],
            _deny_delete_element_command("t20_security_deny_v6", IPV6_CLOUDFLARE),
            id="ipv6-only",
        ),
        pytest.param(
            [TEST_IP1, IPV6_CLOUDFLARE],
            _deny_delete_element_command("t20_security_deny_v4", TEST_IP1)
            + _deny_delete_element_command("t20_security_deny_v6", IPV6_CLOUDFLARE),
            id="mixed-families",
        ),
    ],
)
def test_delete_deny_elements_dual_classifies_by_family(ips: list[str], expected: str) -> None:
    """delete_deny_elements_dual() emits IPv4 delete commands before IPv6 ones."""
    assert delete_deny_elements_dual(ips) == expected


@pytest.mark.parametrize(
    "ips",
    [pytest.param([], id="empty-list"), pytest.param(["bad", "worse"], id="all-invalid")],
)
def test_delete_deny_elements_dual_returns_empty_when_no_valid_ips(ips: list[str]) -> None:
    """delete_deny_elements_dual() returns empty when all inputs are invalid."""
    assert delete_deny_elements_dual(ips) == ""


# ── override set + bypass window ─────────────────────────


def test_add_override_elements_dual_targets_the_override_set() -> None:
    """add_override_elements_dual() routes IPs to the tier-10 override sets."""
    cmd = add_override_elements_dual([TEST_IP1, IPV6_CLOUDFLARE])
    assert _add_element_command("t10_override_v4", TEST_IP1) in cmd
    assert _add_element_command("t10_override_v6", IPV6_CLOUDFLARE) in cmd


def test_arm_bypass_window_adds_default_routes_with_timeout() -> None:
    """arm_bypass_window() adds 0.0.0.0/0 and ::/0 to the timed sets with the timeout."""
    cmd = arm_bypass_window("30m")
    assert f"add element {NFT_TABLE} bypass_window_v4 {{ 0.0.0.0/0 timeout 30m }}" in cmd
    assert f"add element {NFT_TABLE} bypass_window_v6 {{ ::/0 timeout 30m }}" in cmd


def test_arm_bypass_window_rejects_bad_timeout() -> None:
    """arm_bypass_window() validates the timeout before interpolating it."""
    with pytest.raises(ValueError):
        arm_bypass_window("30m; drop")


def test_disarm_bypass_window_flushes_both_families() -> None:
    """disarm_bypass_window() flushes the v4 and v6 timed sets."""
    cmd = disarm_bypass_window()
    assert f"flush set {NFT_TABLE} bypass_window_v4" in cmd
    assert f"flush set {NFT_TABLE} bypass_window_v6" in cmd


# ── verify_up() -----------------------------------------------------

_builder = RulesetBuilder()


def test_verify_up_accepts_the_generated_hook_ruleset() -> None:
    """verify_up() accepts the enforcing ruleset generated by RulesetBuilder."""
    assert _builder.verify_up(_builder.build_up()) == []


@pytest.mark.parametrize(
    ("nft_output", "expected_error"),
    [
        pytest.param("some random text", "policy is not drop", id="missing-policy-drop"),
        pytest.param(
            "chain input { policy drop;\nTEROK_SHIELD_DENIED admin-prohibited t40_project_allow_v4 t40_project_allow_v6 }",
            "output chain missing",
            id="missing-output-chain",
        ),
        pytest.param(
            "chain output { policy drop;\nTEROK_SHIELD_DENIED admin-prohibited t40_project_allow_v4 t40_project_allow_v6 }",
            "input chain missing",
            id="missing-input-chain",
        ),
        pytest.param(
            "chain output { type filter hook output priority filter; policy drop;\n"
            "chain input { policy drop;\n"
            f"{_DENY_LOG_PREFIX} admin-prohibited\n{_private_reject_rules()}\n@t40_project_allow_v6 }}",
            "t40_project_allow_v4 set missing",
            id="missing-allow-v4-set",
        ),
        pytest.param(
            "chain output { type filter hook output priority filter; policy drop;\n"
            "chain input { policy drop;\n"
            f"{_DENY_LOG_PREFIX} admin-prohibited\n{_private_reject_rules()}\n@t40_project_allow_v4 }}",
            "t40_project_allow_v6 set missing",
            id="missing-allow-v6-set",
        ),
    ],
)
def test_verify_up_reports_missing_top_level_invariants(
    nft_output: str,
    expected_error: str,
) -> None:
    """verify_up() names the missing high-level up-posture invariant."""
    assert expected_error in _builder.verify_up(nft_output)


def test_verify_up_reports_each_missing_private_range_rule() -> None:
    """Every missing private-range reject rule should produce its own error."""
    errors = _builder.verify_up(
        f"policy drop {_ADMIN_PROHIBITED} {_DENY_LOG_PREFIX} t40_project_allow_v4 t40_project_allow_v6 {_OUTPUT_CHAIN} {_INPUT_CHAIN}"
    )
    range_errors = [error for error in errors if "Private-range" in error]
    assert len(range_errors) == len(PRIVATE_RANGES)


def test_verify_up_reports_missing_ipv6_private_ranges_independently() -> None:
    """Missing IPv6 private-range rejects are reported separately from IPv4 ones."""
    ipv4_private = tuple(n for n in PRIVATE_RANGES if "." in n)
    ipv6_private = tuple(n for n in PRIVATE_RANGES if ":" in n)
    errors = _builder.verify_up(
        "chain output { type filter hook output priority filter; policy drop;\n"
        "chain input { policy drop;\n"
        f"{_DENY_LOG_PREFIX} {_ADMIN_PROHIBITED} t40_project_allow_v4 t40_project_allow_v6\n"
        f"{_private_reject_rules(ipv4_private)}\n@t40_project_allow_v4 }}"
    )
    ipv6_errors = [e for e in errors if "Private-range" in e and ":" in e]
    assert len(ipv6_errors) == len(ipv6_private)


def test_verify_up_rejects_a_down_ruleset() -> None:
    """A down ruleset must not satisfy up-posture verification."""
    errors = _builder.verify_up(_builder.build_down())
    assert errors
    assert any("terminal reject-all rule" in error for error in errors)


def test_verify_up_rejects_silent_drop_terminal() -> None:
    """A BLOCKED terminal that silently drops (no reject) fails verification."""
    ruleset = _builder.build_up()
    silent = ruleset.replace(
        f'prefix "{_BLOCKED_LOG_PREFIX}: " counter reject with icmpx {_ADMIN_PROHIBITED}',
        f'prefix "{_BLOCKED_LOG_PREFIX}: " counter drop',
    )
    assert silent != ruleset  # sanity: the terminal reject was rewritten to drop
    assert "terminal reject-all rule missing" in _builder.verify_up(silent)


def test_verify_up_accepts_prefix_before_group_ordering() -> None:
    """verify_up() handles nft output where prefix appears before group.

    Newer nft versions reorder log statement attributes: ``log prefix "..." group N``
    instead of ``log group N prefix "..."``.  The terminal deny-all check must
    accept both orderings.
    """
    ruleset = _builder.build_up()
    # Simulate newer nft output ordering: swap group/prefix in log lines
    reordered = ruleset.replace(
        f'log group 100 prefix "{_BLOCKED_LOG_PREFIX}: "',
        f'log prefix "{_BLOCKED_LOG_PREFIX}: " group 100',
    )
    assert reordered != ruleset  # sanity: replacement happened
    assert _builder.verify_up(reordered) == []


def test_verify_up_checks_private_ranges_by_rule_not_by_position() -> None:
    """Private-range rejects pass verification even if moved after the allow-set match."""
    ruleset = (
        f"policy drop {_ADMIN_PROHIBITED} {_DENY_LOG_PREFIX} @t40_project_allow_v4 accept t40_project_allow_v6\n"
        f"{_private_reject_rules()}"
    )
    range_errors = [error for error in _builder.verify_up(ruleset) if "Private-range" in error]
    assert range_errors == []


def test_verify_up_reports_errors_for_empty_input() -> None:
    """Empty nft output should fail up-posture verification."""
    assert _builder.verify_up("")


# ── build_down() ----------------------------------------------------


@pytest.mark.parametrize(
    "fragment",
    [
        pytest.param("policy accept", id="output-policy-accept"),
        pytest.param("policy drop", id="input-policy-drop"),
        pytest.param(_ALLOW_V4_SET, id="allow-v4-set"),
        pytest.param(_ALLOW_V6_SET, id="allow-v6-set"),
        pytest.param(BYPASS_LOG_PREFIX, id="bypass-log-prefix"),
        pytest.param("ct state new log group", id="logs-new-connections"),
    ],
)
def test_down_ruleset_contains_required_fragments(fragment: str) -> None:
    """The down ruleset preserves the expected top-level invariants."""
    assert fragment in RulesetBuilder().build_down()


def test_down_ruleset_blocks_all_private_ranges_by_default() -> None:
    """The down posture still rejects all private-range traffic unless disengaged=True."""
    rs = RulesetBuilder().build_down()
    for net in PRIVATE_RANGES:
        assert net in rs, f"Private range {net!r} missing from down ruleset"


def test_down_ruleset_disengaged_enforces_nothing() -> None:
    """disengaged=True drops every reject: hard-deny floor, private ranges, and the deny set."""
    rs = RulesetBuilder().build_down(disengaged=True)
    for net in HARD_DENY_RANGES + PRIVATE_RANGES:
        assert net not in rs, f"Range {net!r} should be absent when disengaged=True"
    assert _DENY_LOG_PREFIX not in rs
    assert "reject" not in rs
    assert BYPASS_LOG_PREFIX in rs  # still logs every new connection


def test_down_ruleset_includes_deny_sets() -> None:
    """Shield-down ruleset includes deny sets so deny.list is enforced."""
    rs = RulesetBuilder().build_down()
    assert "t20_security_deny_v4" in rs
    assert "t20_security_deny_v6" in rs
    assert _DENY_LOG_PREFIX in rs


def test_down_ruleset_keeps_override_above_deny() -> None:
    """The down posture keeps the t10 override match above the deny — a break-glass
    host must stay reachable in every posture that enforces the deny."""
    rs = RulesetBuilder().build_down()
    assert rs.index("@t10_override_v4") < rs.index("@t20_security_deny_v4")


def _rule_for(ruleset: str, set_name: str) -> str:
    """The single rule line matching *set_name* in *ruleset*."""
    return next(ln for ln in ruleset.splitlines() if f"@{set_name} " in ln)


def test_override_accept_is_audited_in_both_postures() -> None:
    """A break-glass accept carries an NFLOG tag — it is terminal, so nothing else logs it.

    The t10 verdict ends evaluation before the tiers (and, in the down posture, before
    the catch-all ``ct state new`` log), so an untagged accept would make
    exactly the traffic an auditor cares about most the only traffic that
    leaves no trace.
    """
    assert _ALLOWED_LOG_PREFIX in _rule_for(RulesetBuilder().build_up(), "t10_override_v4")
    assert _BYPASS_LOG_PREFIX in _rule_for(RulesetBuilder().build_down(), "t10_override_v4")


def test_down_ruleset_emits_loopback_port_rules() -> None:
    """Host-loopback-proxy port exceptions survive in the down posture, before private-range reject."""
    ruleset = RulesetBuilder(loopback_ports=(9418,)).build_down()
    accept_rule = f"tcp dport 9418 ip daddr {PASTA_HOST_LOOPBACK_MAP} accept"
    assert accept_rule in ruleset
    assert ruleset.index(accept_rule) < ruleset.index("169.254.0.0/16")


def test_down_ruleset_accepts_dns_to_the_configured_forwarder() -> None:
    """The down posture retains the explicit DNS exception for the configured forwarder."""
    ruleset = RulesetBuilder(dns=LINK_LOCAL_DNS).build_down()
    assert _dns_accept_rules(ruleset) == {
        f"udp dport 53 ip daddr {LINK_LOCAL_DNS} accept",
        f"tcp dport 53 ip daddr {LINK_LOCAL_DNS} accept",
    }


# ── verify_down() ---------------------------------------------------


@pytest.mark.parametrize(
    ("ruleset", "disengaged"),
    [
        pytest.param(_builder.build_down(), False, id="down"),
        pytest.param(_builder.build_down(disengaged=True), True, id="disengaged"),
    ],
)
def test_verify_down_accepts_generated_down_rulesets(ruleset: str, disengaged: bool) -> None:
    """verify_down() accepts down rulesets produced by RulesetBuilder."""
    assert _builder.verify_down(ruleset, disengaged=disengaged) == []


@pytest.mark.parametrize(
    ("nft_output", "expected_error"),
    [
        pytest.param(
            "policy drop TEROK_SHIELD_BYPASS",
            "output policy is not accept",
            id="missing-accept-policy",
        ),
        pytest.param(
            "policy accept TEROK_SHIELD_BYPASS",
            "input policy is not drop",
            id="missing-drop-policy",
        ),
        pytest.param(
            "policy accept policy drop", "bypass nflog prefix missing", id="missing-bypass-prefix"
        ),
        pytest.param(
            "chain input { policy drop;\nTEROK_SHIELD_BYPASS t40_project_allow_v4 t40_project_allow_v6 }",
            "output chain missing",
            id="missing-output-chain",
        ),
        pytest.param(
            "chain output { policy accept;\nTEROK_SHIELD_BYPASS t40_project_allow_v4 t40_project_allow_v6 }",
            "input chain missing",
            id="missing-input-chain",
        ),
        pytest.param(
            f"{_OUTPUT_CHAIN} policy accept {_INPUT_CHAIN} policy drop {BYPASS_LOG_PREFIX} t40_project_allow_v6",
            "t40_project_allow_v4 set missing",
            id="missing-allow-v4-set",
        ),
        pytest.param(
            f"{_OUTPUT_CHAIN} policy accept {_INPUT_CHAIN} policy drop {BYPASS_LOG_PREFIX} t40_project_allow_v4",
            "t40_project_allow_v6 set missing",
            id="missing-allow-v6-set",
        ),
    ],
)
def test_verify_down_reports_missing_top_level_invariants(
    nft_output: str,
    expected_error: str,
) -> None:
    """verify_down() names the missing high-level down-posture invariant."""
    assert expected_error in _builder.verify_down(nft_output)


def test_verify_down_reports_private_ranges_when_disengaged_is_false() -> None:
    """Private-range reject rules remain mandatory in the default down posture."""
    errors = _builder.verify_down(
        f"{_OUTPUT_CHAIN} policy accept {_INPUT_CHAIN} policy drop {BYPASS_LOG_PREFIX} t40_project_allow_v4 t40_project_allow_v6"
    )
    range_errors = [error for error in errors if "Private-range" in error]
    assert len(range_errors) == len(PRIVATE_RANGES)


def test_verify_down_accepts_absent_private_ranges_in_disengaged_mode() -> None:
    """disengaged=True treats absent private-range rejects as correct."""
    errors = _builder.verify_down(
        f"{_OUTPUT_CHAIN} policy accept {_INPUT_CHAIN} policy drop {BYPASS_LOG_PREFIX} t40_project_allow_v4 t40_project_allow_v6",
        disengaged=True,
    )
    range_errors = [error for error in errors if "Private-range" in error]
    assert range_errors == []


def test_verify_down_tells_down_and_disengaged_apart() -> None:
    """The reject invariants are mutually exclusive: each posture fails the other's verifier."""
    down, disengaged = _builder.build_down(), _builder.build_down(disengaged=True)
    assert _builder.verify_down(down, disengaged=True)
    assert _builder.verify_down(disengaged, disengaged=False)


@pytest.mark.parametrize(
    ("leaked_rule", "expected_error"),
    [
        pytest.param(
            f'ip daddr {PRIVATE_RANGES[0]} log group 100 prefix "X: " reject with icmpx admin-prohibited',
            f"Private-range reject rule for {PRIVATE_RANGES[0]} present",
            id="private-range",
        ),
        pytest.param(
            f'ip daddr {HARD_DENY_RANGES[0]} log group 100 prefix "X: " reject with icmpx admin-prohibited',
            f"Hard-deny reject rule for {HARD_DENY_RANGES[0]} present",
            id="hard-deny",
        ),
        pytest.param(
            'ip daddr @t20_security_deny_v4 log group 100 prefix "X: " counter reject with icmpx admin-prohibited',
            "deny-set reject rule present",
            id="deny-set",
        ),
    ],
)
def test_verify_down_disengaged_flags_a_retained_reject(
    leaked_rule: str, expected_error: str
) -> None:
    """A single reject left behind must fail DISENGAGED verification, not pass as disengaged."""
    marker = "        ct state new log"
    leaked = _builder.build_down(disengaged=True).replace(
        marker, f"        {leaked_rule}\n{marker}", 1
    )
    assert any(expected_error in error for error in _builder.verify_down(leaked, disengaged=True))


def test_verify_down_rejects_an_up_ruleset() -> None:
    """An up ruleset must not satisfy down-posture verification."""
    errors = _builder.verify_down(_builder.build_up())
    assert errors
    assert any("accept" in error for error in errors)


def test_verify_down_reports_errors_for_empty_input() -> None:
    """Empty nft output should fail down-posture verification."""
    assert _builder.verify_down("")


# ── build_quarantine() ─────────────────────────────────────────


@pytest.mark.parametrize(
    "fragment",
    [
        pytest.param("policy drop", id="output-policy-drop"),
        pytest.param(_INPUT_CHAIN, id="input-chain"),
        pytest.param(_OUTPUT_CHAIN, id="output-chain"),
        pytest.param(_LOOPBACK_ACCEPT, id="loopback-accept"),
        pytest.param("ct state established,related accept", id="established"),
        pytest.param(BLOCKED_LOG_PREFIX, id="blocked-log-prefix"),
    ],
)
def test_quarantine_ruleset_contains_required_fragments(fragment: str) -> None:
    """The quarantine ruleset preserves the expected security invariants."""
    assert fragment in RulesetBuilder.build_quarantine()


def test_quarantine_ruleset_has_no_allow_sets() -> None:
    """Block mode must have no allowlists -- total blackout."""
    rs = RulesetBuilder.build_quarantine()
    assert "t40_project_allow_v4" not in rs
    assert "t40_project_allow_v6" not in rs


def test_quarantine_ruleset_has_no_deny_sets() -> None:
    """Block mode needs no deny sets -- everything is dropped anyway."""
    rs = RulesetBuilder.build_quarantine()
    assert "t20_security_deny_v4" not in rs
    assert "t20_security_deny_v6" not in rs


def test_quarantine_ruleset_has_no_dns_rules() -> None:
    """Block mode drops DNS -- no external resolution allowed."""
    rs = RulesetBuilder.build_quarantine()
    assert "dport 53" not in rs


def test_quarantine_ruleset_has_no_port_accept_rules() -> None:
    """Block mode allows only loopback + established -- no port-specific accepts."""
    rs = RulesetBuilder.build_quarantine()
    assert "tcp dport" not in rs


def test_quarantine_ruleset_does_not_include_bypass_or_deny_prefixes() -> None:
    """Block mode uses only the BLOCKED prefix, not BYPASS or DENIED."""
    rs = RulesetBuilder.build_quarantine()
    assert _DENY_LOG_PREFIX not in rs
    assert BYPASS_LOG_PREFIX not in rs


# ── verify_quarantine() ─────────────────────────────────────────


def test_verify_quarantine_accepts_generated_block_ruleset() -> None:
    """verify_quarantine() returns no errors for a valid quarantine ruleset."""
    assert RulesetBuilder.verify_quarantine(RulesetBuilder.build_quarantine()) == []


def test_verify_quarantine_rejects_hook_ruleset() -> None:
    """Hook (deny-all with allowlists) must not satisfy block verification."""
    errors = RulesetBuilder.verify_quarantine(_builder.build_up())
    assert errors
    assert any("t40_project_allow_v4" in e for e in errors)


def test_verify_quarantine_rejects_down_ruleset() -> None:
    """A down (accept-by-default) ruleset must not satisfy blackout verification."""
    errors = RulesetBuilder.verify_quarantine(_builder.build_down())
    assert errors


def test_verify_quarantine_reports_missing_chain() -> None:
    """Missing chains are reported."""
    minimal = f"table {NFT_TABLE} {{ chain output {{ policy drop; {BLOCKED_LOG_PREFIX} }} }}"
    errors = RulesetBuilder.verify_quarantine(minimal)
    assert "input chain missing" in errors


def test_verify_quarantine_reports_missing_prefix() -> None:
    """Missing blocked log prefix is reported."""
    minimal = (
        f"table {NFT_TABLE} {{ chain output {{ policy drop; }} chain input {{ policy drop; }} }}"
    )
    errors = RulesetBuilder.verify_quarantine(minimal)
    assert "blocked nflog prefix missing" in errors


def test_verify_quarantine_reports_errors_for_empty_input() -> None:
    """Empty nft output should fail quarantine-mode verification."""
    assert RulesetBuilder.verify_quarantine("")


# ── Gateway sets and port rules ──────────────────────────


class TestGatewayPortRules:
    """Tests for hardcoded gateway IP rules in rulesets."""

    _GW_V4 = SLIRP4NETNS_DNS.replace(".3", ".2")  # 10.0.2.2
    _GW_V6 = "fd00::2"

    def _gw_builder(self, *, ports: tuple[int, ...] = (9418,)) -> RulesetBuilder:
        """Create a RulesetBuilder with gateway config."""
        return RulesetBuilder(
            dns=SLIRP4NETNS_DNS,
            loopback_ports=ports,
            gateway_v4=self._GW_V4,
            gateway_v6=self._GW_V6,
        )

    def test_hook_ruleset_contains_literal_gateway_ips(self) -> None:
        """build_up() with gateway params contains literal IP accept rules."""
        rs = self._gw_builder().build_up()
        assert f"tcp dport 9418 ip daddr {self._GW_V4} accept" in rs
        assert f"tcp dport 9418 ip6 daddr {self._GW_V6} accept" in rs

    def test_down_ruleset_contains_literal_gateway_ips(self) -> None:
        """build_down() with gateway params contains literal IP accept rules."""
        rs = self._gw_builder().build_down()
        assert f"tcp dport 9418 ip daddr {self._GW_V4} accept" in rs
        assert f"tcp dport 9418 ip6 daddr {self._GW_V6} accept" in rs

    def test_gateway_rules_before_private_range(self) -> None:
        """Gateway accept rules appear before private-range reject rules."""
        rs = self._gw_builder().build_up()
        gw_pos = rs.index(f"ip daddr {self._GW_V4} accept")
        private_pos = rs.index(PRIVATE_RANGES[0])
        assert gw_pos < private_pos

    def test_gateway_multiple_ports(self) -> None:
        """Literal gateway IP rules are generated for each loopback port."""
        rs = self._gw_builder(ports=(9418, 8080)).build_up()
        assert f"tcp dport 9418 ip daddr {self._GW_V4} accept" in rs
        assert f"tcp dport 8080 ip daddr {self._GW_V4} accept" in rs
        assert f"tcp dport 9418 ip6 daddr {self._GW_V6} accept" in rs
        assert f"tcp dport 8080 ip6 daddr {self._GW_V6} accept" in rs

    def test_no_gateway_rules_without_ports(self) -> None:
        """build_up() with no loopback_ports produces no gateway rules."""
        rs = RulesetBuilder(dns=SLIRP4NETNS_DNS, loopback_ports=()).build_up()
        assert f"ip daddr {self._GW_V4} accept" not in rs

    def test_swapped_gateway_families_rejected(self) -> None:
        """RulesetBuilder rejects IPv6 in gateway_v4 and vice versa."""
        with pytest.raises(ValueError, match="Expected IPv4"):
            RulesetBuilder(gateway_v4="fd00::2")
        with pytest.raises(ValueError, match="Expected IPv6"):
            RulesetBuilder(gateway_v6="10.0.2.2")


# ── _safe_timeout validation ─────────────────────────────


class TestSafeTimeout:
    """Security boundary: timeout validation prevents nft injection."""

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("30m", id="minutes"),
            pytest.param("1h", id="hours"),
            pytest.param("60s", id="seconds"),
            pytest.param("7d", id="days"),
        ],
    )
    def test_accepts_valid_timeout(self, value: str) -> None:
        """Valid nft timeout values are accepted."""
        assert _safe_timeout(value) == value

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("", id="empty"),
            pytest.param("30", id="no-unit"),
            pytest.param("m30", id="unit-first"),
            pytest.param("30x", id="invalid-unit"),
            pytest.param("30m; drop", id="injection"),
            pytest.param("-1m", id="negative"),
        ],
    )
    def test_rejects_invalid_timeout(self, value: str) -> None:
        """Invalid timeout values are rejected."""
        with pytest.raises(ValueError, match="Invalid nft timeout"):
            _safe_timeout(value)


# ── set_timeout in rulesets ──────────────────────────────


class TestSetTimeout:
    """nft set declarations with optional timeout for dnsmasq mode."""

    def test_hook_ruleset_without_timeout(self) -> None:
        """Without set_timeout, the allow sets carry no element timeout.

        (The bypass_window set always declares the ``timeout`` flag — its
        elements expire to close the timed allow-all window — so a blanket
        "timeout absent" assertion no longer holds.)
        """
        rs = RulesetBuilder().build_up()
        assert "set t40_project_allow_v4 { type ipv4_addr; flags interval; }" in rs
        assert "timeout 30m" not in rs  # no dnsmasq-tier default element timeout

    def test_hook_ruleset_with_timeout(self) -> None:
        """With set_timeout, sets get interval+timeout flags."""
        rs = RulesetBuilder(set_timeout="30m").build_up()
        assert "flags interval, timeout; timeout 30m;" in rs

    def test_down_ruleset_with_timeout(self) -> None:
        """Down rulesets also support set_timeout."""
        rs = RulesetBuilder(set_timeout="1h").build_down()
        assert "flags interval, timeout; timeout 1h;" in rs

    def test_builder_rejects_invalid_timeout(self) -> None:
        """Invalid set_timeout in RulesetBuilder is rejected."""
        with pytest.raises(ValueError):
            RulesetBuilder(set_timeout="bad")


# ── Set-element snapshot parsing / restore ──────────────


def _list_set_output(elements: str) -> str:
    """Wrap an elements block in realistic ``nft list set`` output."""
    return (
        "table inet terok_shield {\n"
        "\tset t40_project_allow_v4 {\n"
        "\t\ttype ipv4_addr\n"
        "\t\tflags interval,timeout\n"
        "\t\ttimeout 30m\n"
        f"\t\telements = {{ {elements} }}\n"
        "\t}\n"
        "}\n"
    )


class TestParseSetElements:
    """parse_set_elements() — snapshotting a live allow set."""

    def test_parses_timed_permanent_and_bare_elements(self) -> None:
        """Learned (timed), seeded (0s), and untimed elements all round out."""
        out = _list_set_output(
            f"{TEST_IP1} timeout 30m expires 22m10s,\n"
            f"\t\t\t     {TEST_IP2} timeout 0s,\n"
            f"\t\t\t     {TEST_NET1} }}"
        )
        assert parse_set_elements(out) == [
            (TEST_IP1, "30m"),
            (TEST_IP2, "0s"),
            (TEST_NET1, ""),
        ]

    def test_compound_timeout_is_preserved(self) -> None:
        """nft prints compound durations (1h22m10s) — kept verbatim."""
        out = _list_set_output(f"{TEST_IP1} timeout 1h22m10s expires 5s")
        assert parse_set_elements(out) == [(TEST_IP1, "1h22m10s")]

    def test_invalid_atoms_are_skipped(self) -> None:
        """Garbage atoms never abort the snapshot (best-effort by design)."""
        out = _list_set_output(f"not-an-ip timeout 5m, {TEST_IP1}")
        assert parse_set_elements(out) == [(TEST_IP1, "")]

    def test_no_elements_block_yields_empty(self) -> None:
        """A set without elements (or non-set output) snapshots to nothing."""
        assert parse_set_elements("table inet terok_shield {\n\tset x {\n\t}\n}") == []
        assert parse_set_elements("") == []

    def test_empty_atoms_are_skipped(self) -> None:
        """A trailing comma or blank atom contributes nothing."""
        out = _list_set_output(f"{TEST_IP1}, ")
        assert parse_set_elements(out) == [(TEST_IP1, "")]


class TestRestoreElements:
    """restore_elements() — replaying a snapshot into a rebuilt table."""

    def test_emits_single_grouped_add(self) -> None:
        """All elements of one set land in one add command, timeouts intact."""
        cmd = restore_elements(
            "t40_project_allow_v4", [(TEST_IP1, "30m"), (TEST_IP2, "0s"), (TEST_NET1, "")]
        )
        assert cmd == (
            f"add element inet terok_shield t40_project_allow_v4 "
            f"{{ {TEST_IP1} timeout 30m, {TEST_IP2} timeout 0s, {TEST_NET1} }}\n"
        )

    def test_round_trips_a_parsed_snapshot(self) -> None:
        """parse → restore reproduces every element with its timeout."""
        out = _list_set_output(f"{TEST_IP1} timeout 30m expires 2m, {TEST_IP2} timeout 0s")
        cmd = restore_elements("t40_project_allow_v4", parse_set_elements(out))
        assert f"{TEST_IP1} timeout 30m" in cmd
        assert f"{TEST_IP2} timeout 0s" in cmd
        assert "expires" not in cmd  # a restore re-grants the full timeout

    def test_empty_snapshot_restores_nothing(self) -> None:
        """No elements → no command."""
        assert restore_elements("t40_project_allow_v4", []) == ""

    @pytest.mark.parametrize("timeout", ["30m; drop", "abc", "5"])
    def test_rejects_unsafe_timeouts(self, timeout: str) -> None:
        """A timeout that is not a pure nft duration never reaches the shell."""
        with pytest.raises(ValueError):
            restore_elements("t40_project_allow_v4", [(TEST_IP1, timeout)])

    def test_rejects_unsafe_identifiers_and_ips(self) -> None:
        """Set names and IPs are validated like every other nft input."""
        with pytest.raises(ValueError):
            restore_elements("bad; flush ruleset", [(TEST_IP1, "")])
        with pytest.raises(ValueError):
            restore_elements("t40_project_allow_v4", [("not-an-ip", "")])
