# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the RulesetBuilder class (OOP API)."""

import pytest

from terok_shield.nft.constants import BLOCKED_LOG_PREFIX, BYPASS_LOG_PREFIX
from terok_shield.nft.rules import RulesetBuilder

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
        rs = builder.build_up()
        assert LINK_LOCAL_DNS in rs

    def test_with_loopback_ports(self) -> None:
        """Accept loopback ports."""
        builder = RulesetBuilder(loopback_ports=(8080, 9090))
        rs = builder.build_up()
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
    """Test RulesetBuilder.build_up()."""

    def test_produces_drop_policy(self) -> None:
        """Hook ruleset has drop policy."""
        builder = RulesetBuilder()
        rs = builder.build_up()
        assert "policy drop" in rs

    def test_includes_deny_log(self) -> None:
        """Hook ruleset includes deny nflog prefix."""
        builder = RulesetBuilder()
        rs = builder.build_up()
        assert "TEROK_SHIELD_DENIED" in rs


class TestRulesetBuilderBuildDown:
    """Test RulesetBuilder.build_down()."""

    def test_produces_accept_policy(self) -> None:
        """Down ruleset has accept policy."""
        builder = RulesetBuilder()
        rs = builder.build_down()
        assert "policy accept" in rs

    def test_includes_bypass_log(self) -> None:
        """Down ruleset includes the bypass nflog prefix."""
        builder = RulesetBuilder()
        rs = builder.build_down()
        assert BYPASS_LOG_PREFIX in rs

    def test_disengaged(self) -> None:
        """Down with disengaged=True omits every reject, private ranges included."""
        builder = RulesetBuilder()
        rs = builder.build_down(disengaged=True)
        assert EXPECTED_PRIVATE_RANGES[0] not in rs  # 10.0.0.0/8


class TestRulesetBuilderBuildBlock:
    """Test RulesetBuilder.build_quarantine()."""

    def test_produces_drop_policy(self) -> None:
        """Quarantine ruleset has drop policy."""
        builder = RulesetBuilder()
        rs = builder.build_quarantine()
        assert "policy drop" in rs

    def test_includes_blocked_log(self) -> None:
        """Quarantine ruleset includes blocked nflog prefix."""
        builder = RulesetBuilder()
        rs = builder.build_quarantine()
        assert BLOCKED_LOG_PREFIX in rs

    def test_has_no_allow_sets(self) -> None:
        """Quarantine ruleset has no allowlist sets."""
        builder = RulesetBuilder()
        rs = builder.build_quarantine()
        assert "t30_provider_allow" not in rs
        assert "t40_project_allow" not in rs


class TestRulesetBuilderVerify:
    """Test RulesetBuilder verification methods."""

    def test_verify_quarantine_passes(self) -> None:
        """verify_quarantine returns empty for valid quarantine ruleset."""
        builder = RulesetBuilder()
        rs = builder.build_quarantine()
        assert builder.verify_quarantine(rs) == []

    def test_verify_quarantine_fails_on_hook(self) -> None:
        """verify_quarantine fails on hook ruleset (has allow sets)."""
        builder = RulesetBuilder()
        rs = builder.build_up()
        assert len(builder.verify_quarantine(rs)) > 0

    def test_verify_up_passes(self) -> None:
        """verify_up returns empty for valid hook ruleset."""
        builder = RulesetBuilder()
        rs = builder.build_up()
        errors = builder.verify_up(rs)
        assert errors == []

    def test_verify_up_fails_on_down(self) -> None:
        """verify_up fails on a down ruleset."""
        builder = RulesetBuilder()
        rs = builder.build_down()
        errors = builder.verify_up(rs)
        assert len(errors) > 0

    def test_verify_down_passes(self) -> None:
        """verify_down returns empty for a valid down ruleset."""
        builder = RulesetBuilder()
        rs = builder.build_down()
        errors = builder.verify_down(rs)
        assert errors == []

    def test_verify_down_fails_on_up(self) -> None:
        """verify_down fails on an up ruleset."""
        builder = RulesetBuilder()
        rs = builder.build_up()
        errors = builder.verify_down(rs)
        assert len(errors) > 0


class TestRulesetBuilderAddElementsDual:
    """Test RulesetBuilder.add_elements_dual()."""

    def test_add_elements_dual_v4_only(self) -> None:
        """add_elements_dual with IPv4 only."""
        result = RulesetBuilder().add_elements_dual([TEST_IP1, TEST_IP2])
        assert "t40_project_allow_v4" in result
        assert "t40_project_allow_v6" not in result

    def test_add_elements_dual_mixed(self) -> None:
        """add_elements_dual with mixed IPs."""
        result = RulesetBuilder().add_elements_dual([TEST_IP1, IPV6_CLOUDFLARE])
        assert "t40_project_allow_v4" in result
        assert "t40_project_allow_v6" in result

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
