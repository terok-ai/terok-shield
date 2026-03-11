# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the RulesetBuilder class (OOP API)."""

import unittest

from terok_shield.nft import RulesetBuilder
from terok_shield.nft_constants import BYPASS_LOG_PREFIX

from ..testnet import EXPECTED_PRIVATE_RANGES, IPV6_CLOUDFLARE, LINK_LOCAL_DNS, TEST_IP1, TEST_IP2


class TestRulesetBuilderInit(unittest.TestCase):
    """Test RulesetBuilder construction."""

    def test_default_init(self) -> None:
        """Default construction succeeds."""
        builder = RulesetBuilder()
        self.assertIsNotNone(builder)

    def test_custom_dns(self) -> None:
        """Accept a custom DNS address."""
        builder = RulesetBuilder(dns=LINK_LOCAL_DNS)
        rs = builder.build_hook()
        self.assertIn(LINK_LOCAL_DNS, rs)

    def test_with_loopback_ports(self) -> None:
        """Accept loopback ports."""
        builder = RulesetBuilder(loopback_ports=(8080, 9090))
        rs = builder.build_hook()
        self.assertIn("tcp dport 8080", rs)
        self.assertIn("tcp dport 9090", rs)

    def test_invalid_dns_raises(self) -> None:
        """Reject invalid DNS address."""
        with self.assertRaises(ValueError):
            RulesetBuilder(dns="not-an-ip")

    def test_invalid_port_raises(self) -> None:
        """Reject invalid port."""
        with self.assertRaises(ValueError):
            RulesetBuilder(loopback_ports=(0,))

    def test_bool_port_raises(self) -> None:
        """Reject boolean port."""
        with self.assertRaises(ValueError):
            RulesetBuilder(loopback_ports=(True,))


class TestRulesetBuilderBuildHook(unittest.TestCase):
    """Test RulesetBuilder.build_hook()."""

    def test_produces_drop_policy(self) -> None:
        """Hook ruleset has drop policy."""
        builder = RulesetBuilder()
        rs = builder.build_hook()
        self.assertIn("policy drop", rs)

    def test_includes_deny_log(self) -> None:
        """Hook ruleset includes deny log prefix."""
        builder = RulesetBuilder()
        rs = builder.build_hook()
        self.assertIn("TEROK_SHIELD_DENIED", rs)


class TestRulesetBuilderBuildBypass(unittest.TestCase):
    """Test RulesetBuilder.build_bypass()."""

    def test_produces_accept_policy(self) -> None:
        """Bypass ruleset has accept policy."""
        builder = RulesetBuilder()
        rs = builder.build_bypass()
        self.assertIn("policy accept", rs)

    def test_includes_bypass_log(self) -> None:
        """Bypass ruleset includes bypass log prefix."""
        builder = RulesetBuilder()
        rs = builder.build_bypass()
        self.assertIn(BYPASS_LOG_PREFIX, rs)

    def test_allow_all(self) -> None:
        """Bypass with allow_all omits private-range rules."""
        builder = RulesetBuilder()
        rs = builder.build_bypass(allow_all=True)
        self.assertNotIn(EXPECTED_PRIVATE_RANGES[0], rs)  # 10.0.0.0/8


class TestRulesetBuilderVerify(unittest.TestCase):
    """Test RulesetBuilder verification methods."""

    def test_verify_hook_passes(self) -> None:
        """verify_hook returns empty for valid hook ruleset."""
        builder = RulesetBuilder()
        rs = builder.build_hook()
        errors = builder.verify_hook(rs)
        self.assertEqual(errors, [])

    def test_verify_hook_fails_on_bypass(self) -> None:
        """verify_hook fails on bypass ruleset."""
        builder = RulesetBuilder()
        rs = builder.build_bypass()
        errors = builder.verify_hook(rs)
        self.assertGreater(len(errors), 0)

    def test_verify_bypass_passes(self) -> None:
        """verify_bypass returns empty for valid bypass ruleset."""
        builder = RulesetBuilder()
        rs = builder.build_bypass()
        errors = builder.verify_bypass(rs)
        self.assertEqual(errors, [])

    def test_verify_bypass_fails_on_hook(self) -> None:
        """verify_bypass fails on hook ruleset."""
        builder = RulesetBuilder()
        rs = builder.build_hook()
        errors = builder.verify_bypass(rs)
        self.assertGreater(len(errors), 0)


class TestRulesetBuilderStaticMethods(unittest.TestCase):
    """Test RulesetBuilder static methods."""

    def test_safe_ip_valid(self) -> None:
        """safe_ip accepts valid IP."""
        self.assertEqual(RulesetBuilder.safe_ip(TEST_IP1), TEST_IP1)

    def test_safe_ip_invalid(self) -> None:
        """safe_ip rejects invalid input."""
        with self.assertRaises(ValueError):
            RulesetBuilder.safe_ip("evil.com")

    def test_add_elements_dual_v4_only(self) -> None:
        """add_elements_dual with IPv4 only."""
        result = RulesetBuilder.add_elements_dual([TEST_IP1, TEST_IP2])
        self.assertIn("allow_v4", result)
        self.assertNotIn("allow_v6", result)

    def test_add_elements_dual_mixed(self) -> None:
        """add_elements_dual with mixed IPs."""
        result = RulesetBuilder.add_elements_dual([TEST_IP1, IPV6_CLOUDFLARE])
        self.assertIn("allow_v4", result)
        self.assertIn("allow_v6", result)

    def test_add_elements_dual_empty(self) -> None:
        """add_elements_dual with empty list."""
        result = RulesetBuilder.add_elements_dual([])
        self.assertEqual(result, "")
