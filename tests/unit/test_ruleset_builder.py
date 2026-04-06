# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the RulesetBuilder class (OOP API)."""

import pytest

from terok_shield.core.nft import RulesetBuilder
from terok_shield.core.nft_constants import BLOCKED_LOG_PREFIX, BYPASS_LOG_PREFIX

from ..testnet import EXPECTED_PRIVATE_RANGES, IPV6_CLOUDFLARE, LINK_LOCAL_DNS, TEST_IP1, TEST_IP2


class TestRulesetBuilderInit:
    """Test RulesetBuilder construction."""

    def test_default_init(self) -> None:
        """Default construction succeeds."""
        builder = RulesetBuilder()
        assert isinstance(builder, RulesetBuilder)

    def test_custom_dns(self) -> None:
        """Accept a custom DNS address."""
        builder = RulesetBuilder(dns=LINK_LOCAL_DNS)
        rs = builder.build_hook()
        assert LINK_LOCAL_DNS in rs

    def test_with_loopback_ports(self) -> None:
        """Accept loopback ports."""
        builder = RulesetBuilder(loopback_ports=(8080, 9090))
        rs = builder.build_hook()
        assert "tcp dport 8080" in rs
        assert "tcp dport 9090" in rs

    def test_invalid_dns_raises(self) -> None:
        """Reject invalid DNS address."""
        with pytest.raises(ValueError):
            RulesetBuilder(dns="not-an-ip")

    def test_invalid_port_raises(self) -> None:
        """Reject invalid port."""
        with pytest.raises(ValueError):
            RulesetBuilder(loopback_ports=(0,))

    def test_bool_port_raises(self) -> None:
        """Reject boolean port."""
        with pytest.raises(ValueError):
            RulesetBuilder(loopback_ports=(True,))


class TestRulesetBuilderBuildHook:
    """Test RulesetBuilder.build_hook()."""

    def test_produces_drop_policy(self) -> None:
        """Hook ruleset has drop policy."""
        builder = RulesetBuilder()
        rs = builder.build_hook()
        assert "policy drop" in rs

    def test_includes_deny_log(self) -> None:
        """Hook ruleset includes deny nflog prefix."""
        builder = RulesetBuilder()
        rs = builder.build_hook()
        assert "TEROK_SHIELD_DENIED" in rs


class TestRulesetBuilderBuildBypass:
    """Test RulesetBuilder.build_bypass()."""

    def test_produces_accept_policy(self) -> None:
        """Bypass ruleset has accept policy."""
        builder = RulesetBuilder()
        rs = builder.build_bypass()
        assert "policy accept" in rs

    def test_includes_bypass_log(self) -> None:
        """Bypass ruleset includes bypass nflog prefix."""
        builder = RulesetBuilder()
        rs = builder.build_bypass()
        assert BYPASS_LOG_PREFIX in rs

    def test_allow_all(self) -> None:
        """Bypass with allow_all omits private-range rules."""
        builder = RulesetBuilder()
        rs = builder.build_bypass(allow_all=True)
        assert EXPECTED_PRIVATE_RANGES[0] not in rs  # 10.0.0.0/8


class TestRulesetBuilderBuildBlock:
    """Test RulesetBuilder.build_block()."""

    def test_produces_drop_policy(self) -> None:
        """Block ruleset has drop policy."""
        builder = RulesetBuilder()
        rs = builder.build_block()
        assert "policy drop" in rs

    def test_includes_blocked_log(self) -> None:
        """Block ruleset includes blocked nflog prefix."""
        builder = RulesetBuilder()
        rs = builder.build_block()
        assert BLOCKED_LOG_PREFIX in rs

    def test_has_no_allow_sets(self) -> None:
        """Block ruleset has no allowlist sets."""
        builder = RulesetBuilder()
        rs = builder.build_block()
        assert "allow_v4" not in rs
        assert "allow_v6" not in rs


class TestRulesetBuilderVerify:
    """Test RulesetBuilder verification methods."""

    def test_verify_block_passes(self) -> None:
        """verify_block returns empty for valid block ruleset."""
        builder = RulesetBuilder()
        rs = builder.build_block()
        assert builder.verify_block(rs) == []

    def test_verify_block_fails_on_hook(self) -> None:
        """verify_block fails on hook ruleset (has allow sets)."""
        builder = RulesetBuilder()
        rs = builder.build_hook()
        assert len(builder.verify_block(rs)) > 0

    def test_verify_hook_passes(self) -> None:
        """verify_hook returns empty for valid hook ruleset."""
        builder = RulesetBuilder()
        rs = builder.build_hook()
        errors = builder.verify_hook(rs)
        assert errors == []

    def test_verify_hook_fails_on_bypass(self) -> None:
        """verify_hook fails on bypass ruleset."""
        builder = RulesetBuilder()
        rs = builder.build_bypass()
        errors = builder.verify_hook(rs)
        assert len(errors) > 0

    def test_verify_bypass_passes(self) -> None:
        """verify_bypass returns empty for valid bypass ruleset."""
        builder = RulesetBuilder()
        rs = builder.build_bypass()
        errors = builder.verify_bypass(rs)
        assert errors == []

    def test_verify_bypass_fails_on_hook(self) -> None:
        """verify_bypass fails on hook ruleset."""
        builder = RulesetBuilder()
        rs = builder.build_hook()
        errors = builder.verify_bypass(rs)
        assert len(errors) > 0


class TestRulesetBuilderAddElementsDual:
    """Test RulesetBuilder.add_elements_dual()."""

    def test_add_elements_dual_v4_only(self) -> None:
        """add_elements_dual with IPv4 only."""
        result = RulesetBuilder().add_elements_dual([TEST_IP1, TEST_IP2])
        assert "allow_v4" in result
        assert "allow_v6" not in result

    def test_add_elements_dual_mixed(self) -> None:
        """add_elements_dual with mixed IPs."""
        result = RulesetBuilder().add_elements_dual([TEST_IP1, IPV6_CLOUDFLARE])
        assert "allow_v4" in result
        assert "allow_v6" in result

    def test_add_elements_dual_empty(self) -> None:
        """add_elements_dual with empty list."""
        result = RulesetBuilder().add_elements_dual([])
        assert result == ""

    def test_add_elements_dual_without_timeout_has_no_timeout_zero(self) -> None:
        """add_elements_dual on a builder without set_timeout emits plain IPs."""
        builder = RulesetBuilder()  # no set_timeout
        result = builder.add_elements_dual([TEST_IP1])
        assert "timeout 0s" not in result
        assert TEST_IP1 in result

    def test_add_elements_dual_with_set_timeout_adds_timeout_zero(self) -> None:
        """add_elements_dual on a dnsmasq-tier builder emits 'timeout 0s' per element.

        Permanent IPs must not expire with the 30-minute set default timeout
        that dnsmasq-learned entries use.
        """
        builder = RulesetBuilder(set_timeout="30m")
        result = builder.add_elements_dual([TEST_IP1])
        assert f"{TEST_IP1} timeout 0s" in result
