# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for nft.py -- the auditable security boundary.

These tests intentionally optimize for explicit security-property checks over
maximum DRYness. Small helpers and parametrization are used only when they make
the asserted invariant clearer; they should never hide rule ordering,
allow-vs-deny semantics, or input-validation guarantees.
"""

from collections.abc import Callable

import pytest

from terok_shield.nft import (
    _is_v4,
    _safe_timeout,
    add_elements,
    add_elements_dual,
    bypass_ruleset,
    hook_ruleset,
    safe_ip,
    verify_bypass_ruleset,
    verify_ruleset,
)
from terok_shield.nft_constants import (
    BYPASS_LOG_PREFIX,
    IPV6_PRIVATE,
    NFT_TABLE,
    PASTA_HOST_LOOPBACK_MAP,
    PRIVATE_RANGES,
    RFC1918,
)

from ..testnet import (
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

_ALLOW_V4_SET = "set allow_v4 { type ipv4_addr; flags interval; }"
_ALLOW_V6_SET = "set allow_v6 { type ipv6_addr; flags interval; }"
_ALLOW_LOG_PREFIX = "TEROK_SHIELD_ALLOWED"
_DENY_LOG_PREFIX = "TEROK_SHIELD_DENIED"
_ADMIN_PROHIBITED = "admin-prohibited"
_INPUT_CHAIN = "chain input"
_OUTPUT_CHAIN = "chain output"
_LOOPBACK_ACCEPT = 'oifname "lo" accept'
_UNSAFE_SET_NAME = "allow_v4; drop"
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


# ── hook_ruleset() ----------------------------------------------------


@pytest.mark.parametrize(
    "fragment",
    [
        pytest.param("policy drop", id="output-policy-drop"),
        pytest.param(_OUTPUT_CHAIN, id="output-chain"),
        pytest.param(_INPUT_CHAIN, id="input-chain"),
        pytest.param(_ALLOW_V4_SET, id="allow-v4-set"),
        pytest.param(_ALLOW_V6_SET, id="allow-v6-set"),
        pytest.param(_LOOPBACK_ACCEPT, id="loopback-accept"),
        pytest.param(_ALLOW_LOG_PREFIX, id="allow-log-prefix"),
        pytest.param(_DENY_LOG_PREFIX, id="deny-log-prefix"),
        pytest.param(_ADMIN_PROHIBITED, id="reject-type"),
    ],
)
def test_hook_ruleset_contains_required_fragments(fragment: str) -> None:
    """The enforcing ruleset contains the expected top-level invariants."""
    assert fragment in hook_ruleset()


def test_hook_ruleset_blocks_all_private_ranges() -> None:
    """Every RFC1918 and IPv6 private/link-local range must be rejected in enforce mode."""
    rs = hook_ruleset()
    for net in PRIVATE_RANGES:
        assert net in rs, f"Private range {net!r} missing from hook ruleset"


def test_hook_ruleset_accepts_dns_to_the_configured_forwarder() -> None:
    """Only the configured DNS forwarder is granted the DNS exception."""
    ruleset = hook_ruleset(dns=LINK_LOCAL_DNS)
    assert _dns_accept_rules(ruleset) == {
        f"udp dport 53 ip daddr {LINK_LOCAL_DNS} accept",
        f"tcp dport 53 ip daddr {LINK_LOCAL_DNS} accept",
    }


def test_hook_ruleset_default_tcp_rules_are_dns_only() -> None:
    """Without loopback ports, TCP port rules must be limited to DNS."""
    tcp_rules = [line.strip() for line in hook_ruleset().splitlines() if "tcp dport" in line]
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
    ruleset = hook_ruleset(loopback_ports=ports)
    for rule in expected_rules:
        assert rule in ruleset
        # Loopback port rules must fire before the 169.254.0.0/16 private-range reject
        assert ruleset.index(rule) < ruleset.index("169.254.0.0/16")


def test_hook_ruleset_places_allow_sets_before_private_range_rejects() -> None:
    """Allow-set accepts must precede the private-range reject rules."""
    ruleset = hook_ruleset()
    assert ruleset.index("@allow_v4") < ruleset.index(RFC1918[0])


@pytest.mark.parametrize(
    "builder",
    [pytest.param(hook_ruleset, id="hook"), pytest.param(bypass_ruleset, id="bypass")],
)
def test_ruleset_builders_reject_invalid_dns(builder: Callable[..., str]) -> None:
    """Both ruleset builders reject non-IP DNS values before interpolation."""
    with pytest.raises(ValueError):
        builder(dns="not-an-ip")


@pytest.mark.parametrize(
    ("builder", "ports"),
    [
        pytest.param(hook_ruleset, (0,), id="hook-port-too-low"),
        pytest.param(hook_ruleset, (99999,), id="hook-port-too-high"),
        pytest.param(hook_ruleset, (True,), id="hook-bool-port"),
        pytest.param(bypass_ruleset, (0,), id="bypass-port-too-low"),
        pytest.param(bypass_ruleset, (99999,), id="bypass-port-too-high"),
        pytest.param(bypass_ruleset, (True,), id="bypass-bool-port"),
    ],
)
def test_ruleset_builders_reject_invalid_loopback_ports(
    builder: Callable[..., str],
    ports: tuple[int, ...],
) -> None:
    """Both ruleset builders reject out-of-range and boolean loopback ports."""
    with pytest.raises(ValueError):
        builder(loopback_ports=ports)


# ── add_elements() / add_elements_dual() ------------------------------


@pytest.mark.parametrize(
    ("ips", "expected"),
    [
        pytest.param(
            [TEST_IP1, TEST_IP2],
            _add_element_command("allow_v4", TEST_IP1, TEST_IP2),
            id="valid-ipv4s",
        ),
        pytest.param(
            [TEST_IP1, "invalid", TEST_IP2],
            _add_element_command("allow_v4", TEST_IP1, TEST_IP2),
            id="skips-invalid-inputs",
        ),
        pytest.param(
            [IPV4_CIDR_HOST_BITS],
            _add_element_command("allow_v4", IPV4_CIDR_HOST_BITS_CANONICAL),
            id="canonicalizes-cidrs",
        ),
    ],
)
def test_add_elements_emits_only_valid_canonicalized_values(ips: list[str], expected: str) -> None:
    """add_elements() filters invalid values and normalizes the rest."""
    assert add_elements("allow_v4", ips) == expected


@pytest.mark.parametrize(
    "ips",
    [pytest.param([], id="empty-list"), pytest.param(["bad", "worse"], id="all-invalid")],
)
def test_add_elements_returns_empty_when_no_ips_survive_validation(ips: list[str]) -> None:
    """add_elements() returns no command when every candidate is invalid."""
    assert add_elements("allow_v4", ips) == ""


@pytest.mark.parametrize(
    ("set_name", "table"),
    [
        pytest.param(_UNSAFE_SET_NAME, NFT_TABLE, id="unsafe-set-name"),
        pytest.param("allow_v4", _UNSAFE_TABLE_NAME, id="unsafe-table-name"),
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
            _add_element_command("allow_v4", TEST_IP1, TEST_IP2),
            id="ipv4-only",
        ),
        pytest.param(
            [IPV6_CLOUDFLARE],
            _add_element_command("allow_v6", IPV6_CLOUDFLARE),
            id="ipv6-only",
        ),
        pytest.param(
            [TEST_IP1, IPV6_CLOUDFLARE],
            _add_element_command("allow_v4", TEST_IP1)
            + _add_element_command("allow_v6", IPV6_CLOUDFLARE),
            id="mixed-families",
        ),
        pytest.param(
            [TEST_IP1, "invalid", IPV6_CLOUDFLARE],
            _add_element_command("allow_v4", TEST_IP1)
            + _add_element_command("allow_v6", IPV6_CLOUDFLARE),
            id="skips-invalid-and-preserves-family-order",
        ),
        pytest.param(
            [IPV4_CIDR_HOST_BITS, IPV6_VERBOSE],
            _add_element_command("allow_v4", IPV4_CIDR_HOST_BITS_CANONICAL)
            + _add_element_command("allow_v6", IPV6_VERBOSE_CANONICAL),
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


# ── verify_ruleset() --------------------------------------------------


def test_verify_ruleset_accepts_the_generated_hook_ruleset() -> None:
    """verify_ruleset() accepts the enforcing ruleset generated by nft.py."""
    assert verify_ruleset(hook_ruleset()) == []


@pytest.mark.parametrize(
    ("nft_output", "expected_error"),
    [
        pytest.param("some random text", "policy is not drop", id="missing-policy-drop"),
        pytest.param(
            "chain input { policy drop;\nTEROK_SHIELD_DENIED admin-prohibited allow_v4 allow_v6 }",
            "output chain missing",
            id="missing-output-chain",
        ),
        pytest.param(
            "chain output { policy drop;\nTEROK_SHIELD_DENIED admin-prohibited allow_v4 allow_v6 }",
            "input chain missing",
            id="missing-input-chain",
        ),
        pytest.param(
            "chain output { type filter hook output priority filter; policy drop;\n"
            "chain input { policy drop;\n"
            f"{_DENY_LOG_PREFIX} admin-prohibited\n{_private_reject_rules()}\n@allow_v6 }}",
            "allow_v4 set missing",
            id="missing-allow-v4-set",
        ),
        pytest.param(
            "chain output { type filter hook output priority filter; policy drop;\n"
            "chain input { policy drop;\n"
            f"{_DENY_LOG_PREFIX} admin-prohibited\n{_private_reject_rules()}\n@allow_v4 }}",
            "allow_v6 set missing",
            id="missing-allow-v6-set",
        ),
    ],
)
def test_verify_ruleset_reports_missing_top_level_invariants(
    nft_output: str,
    expected_error: str,
) -> None:
    """verify_ruleset() names the missing high-level enforce-mode invariant."""
    assert expected_error in verify_ruleset(nft_output)


def test_verify_ruleset_reports_each_missing_private_range_rule() -> None:
    """Every missing private-range reject rule should produce its own error."""
    errors = verify_ruleset(
        f"policy drop {_ADMIN_PROHIBITED} {_DENY_LOG_PREFIX} allow_v4 allow_v6 {_OUTPUT_CHAIN} {_INPUT_CHAIN}"
    )
    range_errors = [error for error in errors if "Private-range" in error]
    assert len(range_errors) == len(PRIVATE_RANGES)


def test_verify_ruleset_reports_missing_ipv6_private_ranges_independently() -> None:
    """Missing IPv6 private-range rejects are reported separately from IPv4 ones."""
    errors = verify_ruleset(
        "chain output { type filter hook output priority filter; policy drop;\n"
        "chain input { policy drop;\n"
        f"{_DENY_LOG_PREFIX} {_ADMIN_PROHIBITED} allow_v4 allow_v6\n{_private_reject_rules(RFC1918)}\n@allow_v4 }}"
    )
    ipv6_errors = [error for error in errors if "Private-range" in error and ":" in error]
    assert len(ipv6_errors) == len(IPV6_PRIVATE)


def test_verify_ruleset_rejects_a_bypass_ruleset() -> None:
    """Bypass mode must not satisfy enforce-mode verification."""
    errors = verify_ruleset(bypass_ruleset())
    assert errors
    assert any("deny nflog prefix" in error for error in errors)


def test_verify_ruleset_checks_private_ranges_by_rule_not_by_position() -> None:
    """Private-range rejects pass verification even if moved after the allow-set match."""
    ruleset = (
        f"policy drop {_ADMIN_PROHIBITED} {_DENY_LOG_PREFIX} @allow_v4 accept allow_v6\n"
        f"{_private_reject_rules()}"
    )
    range_errors = [error for error in verify_ruleset(ruleset) if "Private-range" in error]
    assert range_errors == []


def test_verify_ruleset_reports_errors_for_empty_input() -> None:
    """Empty nft output should fail enforce-mode verification."""
    assert verify_ruleset("")


# ── bypass_ruleset() --------------------------------------------------


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
def test_bypass_ruleset_contains_required_fragments(fragment: str) -> None:
    """The bypass ruleset preserves the expected top-level invariants."""
    assert fragment in bypass_ruleset()


def test_bypass_ruleset_blocks_all_private_ranges_by_default() -> None:
    """Bypass mode still rejects all private-range traffic unless allow_all=True."""
    rs = bypass_ruleset()
    for net in PRIVATE_RANGES:
        assert net in rs, f"Private range {net!r} missing from bypass ruleset"


def test_bypass_ruleset_allow_all_removes_all_private_range_rejects() -> None:
    """allow_all=True removes every RFC1918 and IPv6 private-range reject rule."""
    rs = bypass_ruleset(allow_all=True)
    for net in PRIVATE_RANGES:
        assert net not in rs, f"Private range {net!r} should be absent when allow_all=True"


def test_bypass_ruleset_does_not_include_the_enforce_deny_rule() -> None:
    """Bypass mode must log new flows without appending the enforce-mode deny rule."""
    assert _DENY_LOG_PREFIX not in bypass_ruleset()


def test_bypass_ruleset_emits_loopback_port_rules() -> None:
    """Host-loopback-proxy port exceptions survive in bypass mode, before private-range reject."""
    ruleset = bypass_ruleset(loopback_ports=(9418,))
    accept_rule = f"tcp dport 9418 ip daddr {PASTA_HOST_LOOPBACK_MAP} accept"
    assert accept_rule in ruleset
    assert ruleset.index(accept_rule) < ruleset.index("169.254.0.0/16")


def test_bypass_ruleset_accepts_dns_to_the_configured_forwarder() -> None:
    """Bypass mode retains the explicit DNS exception for the configured forwarder."""
    ruleset = bypass_ruleset(dns=LINK_LOCAL_DNS)
    assert _dns_accept_rules(ruleset) == {
        f"udp dport 53 ip daddr {LINK_LOCAL_DNS} accept",
        f"tcp dport 53 ip daddr {LINK_LOCAL_DNS} accept",
    }


# ── verify_bypass_ruleset() ------------------------------------------


@pytest.mark.parametrize(
    ("ruleset", "allow_all"),
    [
        pytest.param(bypass_ruleset(), False, id="default-bypass"),
        pytest.param(bypass_ruleset(allow_all=True), True, id="allow-all-bypass"),
    ],
)
def test_verify_bypass_ruleset_accepts_generated_bypass_rulesets(
    ruleset: str, allow_all: bool
) -> None:
    """verify_bypass_ruleset() accepts bypass rulesets produced by nft.py."""
    assert verify_bypass_ruleset(ruleset, allow_all=allow_all) == []


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
            "chain input { policy drop;\nTEROK_SHIELD_BYPASS allow_v4 allow_v6 }",
            "output chain missing",
            id="missing-output-chain",
        ),
        pytest.param(
            "chain output { policy accept;\nTEROK_SHIELD_BYPASS allow_v4 allow_v6 }",
            "input chain missing",
            id="missing-input-chain",
        ),
        pytest.param(
            f"{_OUTPUT_CHAIN} policy accept {_INPUT_CHAIN} policy drop {BYPASS_LOG_PREFIX} allow_v6",
            "allow_v4 set missing",
            id="missing-allow-v4-set",
        ),
        pytest.param(
            f"{_OUTPUT_CHAIN} policy accept {_INPUT_CHAIN} policy drop {BYPASS_LOG_PREFIX} allow_v4",
            "allow_v6 set missing",
            id="missing-allow-v6-set",
        ),
    ],
)
def test_verify_bypass_ruleset_reports_missing_top_level_invariants(
    nft_output: str,
    expected_error: str,
) -> None:
    """verify_bypass_ruleset() names the missing high-level bypass invariant."""
    assert expected_error in verify_bypass_ruleset(nft_output)


def test_verify_bypass_ruleset_reports_private_ranges_when_allow_all_is_false() -> None:
    """Private-range reject rules remain mandatory in default bypass mode."""
    errors = verify_bypass_ruleset(
        f"{_OUTPUT_CHAIN} policy accept {_INPUT_CHAIN} policy drop {BYPASS_LOG_PREFIX} allow_v4 allow_v6"
    )
    range_errors = [error for error in errors if "Private-range" in error]
    assert len(range_errors) == len(PRIVATE_RANGES)


def test_verify_bypass_ruleset_skips_private_range_checks_in_allow_all_mode() -> None:
    """allow_all=True disables private-range verification in bypass mode."""
    errors = verify_bypass_ruleset(
        f"{_OUTPUT_CHAIN} policy accept {_INPUT_CHAIN} policy drop {BYPASS_LOG_PREFIX} allow_v4 allow_v6",
        allow_all=True,
    )
    range_errors = [error for error in errors if "Private-range" in error]
    assert range_errors == []


def test_verify_bypass_ruleset_rejects_an_enforcing_hook_ruleset() -> None:
    """Enforce mode must not satisfy bypass-mode verification."""
    errors = verify_bypass_ruleset(hook_ruleset())
    assert errors
    assert any("accept" in error for error in errors)


def test_verify_bypass_ruleset_reports_errors_for_empty_input() -> None:
    """Empty nft output should fail bypass-mode verification."""
    assert verify_bypass_ruleset("")


# ── Gateway sets and port rules ──────────────────────────


class TestGatewayPortRules:
    """Tests for dynamic gateway sets (gateway_v4/gateway_v6) and loopback port rules."""

    def test_hook_ruleset_always_defines_gateway_sets(self) -> None:
        """hook_ruleset() always includes gateway_v4 and gateway_v6 set declarations."""
        rs = hook_ruleset()
        assert "set gateway_v4 { type ipv4_addr; }" in rs
        assert "set gateway_v6 { type ipv6_addr; }" in rs

    def test_bypass_ruleset_always_defines_gateway_sets(self) -> None:
        """bypass_ruleset() always includes gateway_v4 and gateway_v6 set declarations."""
        rs = bypass_ruleset()
        assert "set gateway_v4 { type ipv4_addr; }" in rs
        assert "set gateway_v6 { type ipv6_addr; }" in rs

    def test_gateway_port_rules_reference_sets(self) -> None:
        """hook_ruleset() with loopback_ports generates rules referencing @gateway_v4/@gateway_v6."""
        rs = hook_ruleset(dns=SLIRP4NETNS_DNS, loopback_ports=(9418,))
        assert "tcp dport 9418 ip daddr @gateway_v4 accept" in rs
        assert "tcp dport 9418 ip6 daddr @gateway_v6 accept" in rs

    def test_gateway_rules_before_private_range(self) -> None:
        """Gateway accept rules appear before private-range reject rules."""
        rs = hook_ruleset(dns=SLIRP4NETNS_DNS, loopback_ports=(9418,))
        gw_pos = rs.index("@gateway_v4 accept")
        private_pos = rs.index(RFC1918[0])
        assert gw_pos < private_pos

    def test_gateway_multiple_ports(self) -> None:
        """Both @gateway_v4 and @gateway_v6 rules are generated for each loopback port."""
        rs = hook_ruleset(dns=SLIRP4NETNS_DNS, loopback_ports=(9418, 8080))
        assert "tcp dport 9418 ip daddr @gateway_v4 accept" in rs
        assert "tcp dport 8080 ip daddr @gateway_v4 accept" in rs
        assert "tcp dport 9418 ip6 daddr @gateway_v6 accept" in rs
        assert "tcp dport 8080 ip6 daddr @gateway_v6 accept" in rs

    def test_no_gateway_rules_without_ports(self) -> None:
        """hook_ruleset() with no loopback_ports produces no @gateway_v4/@gateway_v6 rules."""
        rs = hook_ruleset(dns=SLIRP4NETNS_DNS, loopback_ports=())
        assert "@gateway_v4 accept" not in rs
        assert "@gateway_v6 accept" not in rs


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
        """Default rulesets have no timeout in set declarations."""
        rs = hook_ruleset()
        assert "flags interval;" in rs
        assert "timeout" not in rs

    def test_hook_ruleset_with_timeout(self) -> None:
        """With set_timeout, sets get interval+timeout flags."""
        rs = hook_ruleset(set_timeout="30m")
        assert "flags interval, timeout; timeout 30m;" in rs

    def test_bypass_ruleset_with_timeout(self) -> None:
        """Bypass rulesets also support set_timeout."""
        rs = bypass_ruleset(set_timeout="1h")
        assert "flags interval, timeout; timeout 1h;" in rs

    def test_hook_ruleset_rejects_invalid_timeout(self) -> None:
        """Invalid timeout in hook_ruleset is rejected."""
        with pytest.raises(ValueError):
            hook_ruleset(set_timeout="bad")

    def test_bypass_ruleset_rejects_invalid_timeout(self) -> None:
        """Invalid timeout in bypass_ruleset is rejected by _safe_timeout."""
        with pytest.raises(ValueError):
            bypass_ruleset(set_timeout="bad")
