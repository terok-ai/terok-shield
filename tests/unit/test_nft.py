# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for nft.py -- the auditable security boundary."""

import unittest

from terok_shield.nft import (
    RFC1918,
    add_elements,
    bypass_ruleset,
    hook_ruleset,
    safe_ip,
    verify_bypass_ruleset,
    verify_ruleset,
)
from terok_shield.nft_constants import BYPASS_LOG_PREFIX

from ..testnet import LINK_LOCAL_DNS, TEST_IP1, TEST_IP2, TEST_NET1


class TestSafeIp(unittest.TestCase):
    """Tests for safe_ip validator."""

    def test_valid_ipv4(self) -> None:
        """Accept valid IPv4 address."""
        self.assertEqual(safe_ip(TEST_IP1), TEST_IP1)

    def test_valid_cidr(self) -> None:
        """Accept valid CIDR notation."""
        self.assertEqual(safe_ip(TEST_NET1), TEST_NET1)

    def test_strips_whitespace(self) -> None:
        """Strip surrounding whitespace."""
        self.assertEqual(safe_ip(f"  {TEST_IP1}  "), TEST_IP1)

    def test_rejects_hostname(self) -> None:
        """Reject hostnames."""
        with self.assertRaises(ValueError):
            safe_ip("evil.com")

    def test_rejects_injection(self) -> None:
        """Reject nft command injection."""
        with self.assertRaises(ValueError):
            safe_ip(f"{TEST_IP1}; drop")

    def test_rejects_empty(self) -> None:
        """Reject empty string."""
        with self.assertRaises(ValueError):
            safe_ip("")

    def test_rejects_ipv6(self) -> None:
        """Reject IPv6 addresses."""
        with self.assertRaises(ValueError):
            safe_ip("::1")


class TestHookRuleset(unittest.TestCase):
    """Tests for hook mode ruleset generation."""

    def test_contains_policy_drop(self) -> None:
        """Default policy must be drop."""
        rs = hook_ruleset()
        self.assertIn("policy drop", rs)

    def test_ipv6_dropped(self) -> None:
        """IPv6 traffic must be dropped before any accept rules."""
        rs = hook_ruleset()
        ipv6_pos = rs.index("meta nfproto ipv6 drop")
        first_accept_pos = rs.index('oifname "lo" accept')
        self.assertLess(ipv6_pos, first_accept_pos, "IPv6 drop must precede first accept rule")

    def test_contains_loopback_accept(self) -> None:
        """Loopback traffic must be accepted."""
        rs = hook_ruleset()
        self.assertIn('oifname "lo" accept', rs)

    def test_contains_dns_accept(self) -> None:
        """DNS traffic to the forwarder must be accepted."""
        rs = hook_ruleset(dns=LINK_LOCAL_DNS)
        self.assertIn(LINK_LOCAL_DNS, rs)

    def test_no_loopback_ports_by_default(self) -> None:
        """Default ruleset has no port-specific loopback rules."""
        rs = hook_ruleset()
        # Only tcp dport lines should be for DNS (port 53)
        tcp_lines = [ln.strip() for ln in rs.splitlines() if "tcp dport" in ln]
        for line in tcp_lines:
            self.assertIn("53", line, f"Unexpected non-DNS tcp dport rule: {line}")

    def test_single_loopback_port(self) -> None:
        """Single loopback port appears in ruleset."""
        rs = hook_ruleset(loopback_ports=(9418,))
        self.assertIn('tcp dport 9418 oifname "lo" accept', rs)

    def test_multiple_loopback_ports(self) -> None:
        """Multiple loopback ports each get a rule."""
        rs = hook_ruleset(loopback_ports=(8080, 9090))
        self.assertIn('tcp dport 8080 oifname "lo" accept', rs)
        self.assertIn('tcp dport 9090 oifname "lo" accept', rs)

    def test_allow_before_rfc1918(self) -> None:
        """Allow set must appear before RFC1918 reject rules."""
        rs = hook_ruleset()
        allow_pos = rs.index("@allow_v4")
        rfc_pos = rs.index(RFC1918[0])
        self.assertLess(allow_pos, rfc_pos, "Allow set must precede RFC1918 reject")

    def test_all_rfc1918_present(self) -> None:
        """All RFC1918 ranges must be blocked."""
        rs = hook_ruleset()
        for net in RFC1918:
            self.assertIn(net, rs)

    def test_deny_log_present(self) -> None:
        """Deny log prefix must be present."""
        rs = hook_ruleset()
        self.assertIn("TEROK_SHIELD_DENIED", rs)

    def test_reject_type_present(self) -> None:
        """ICMP reject type must be present."""
        rs = hook_ruleset()
        self.assertIn("admin-prohibited", rs)

    def test_audit_allow_present(self) -> None:
        """Allow audit log prefix must be present without rate limit."""
        rs = hook_ruleset()
        self.assertIn("TEROK_SHIELD_ALLOWED", rs)
        self.assertNotIn("limit rate", rs)

    def test_input_chain_present(self) -> None:
        """Input chain must be present."""
        rs = hook_ruleset()
        self.assertIn("chain input", rs)

    def test_rejects_invalid_dns(self) -> None:
        """Reject invalid DNS address."""
        with self.assertRaises(ValueError):
            hook_ruleset(dns="not-an-ip")

    def test_rejects_invalid_loopback_port(self) -> None:
        """Reject out-of-range loopback port."""
        with self.assertRaises(ValueError):
            hook_ruleset(loopback_ports=(0,))
        with self.assertRaises(ValueError):
            hook_ruleset(loopback_ports=(99999,))

    def test_rejects_bool_loopback_port(self) -> None:
        """Reject boolean port (bool is subclass of int)."""
        with self.assertRaises(ValueError):
            hook_ruleset(loopback_ports=(True,))


class TestAddElements(unittest.TestCase):
    """Tests for add_elements."""

    def test_valid_ips(self) -> None:
        """Generate command with valid IPs."""
        result = add_elements("allow_v4", [TEST_IP1, TEST_IP2])
        self.assertIn(TEST_IP1, result)
        self.assertIn(TEST_IP2, result)

    def test_empty_list(self) -> None:
        """Return empty string for empty list."""
        result = add_elements("allow_v4", [])
        self.assertEqual(result, "")

    def test_skips_invalid(self) -> None:
        """Skip invalid IPs, keep valid ones."""
        result = add_elements("allow_v4", [TEST_IP1, "invalid", TEST_IP2])
        self.assertIn(TEST_IP1, result)
        self.assertIn(TEST_IP2, result)
        self.assertNotIn("invalid", result)

    def test_all_invalid(self) -> None:
        """Return empty string when all IPs are invalid."""
        result = add_elements("allow_v4", ["bad", "worse"])
        self.assertEqual(result, "")


class TestVerifyRuleset(unittest.TestCase):
    """Tests for verify_ruleset."""

    def test_valid_ruleset(self) -> None:
        """Hook ruleset passes all checks."""
        rs = hook_ruleset()
        errors = verify_ruleset(rs)
        self.assertEqual(errors, [])

    def test_missing_policy(self) -> None:
        """Report missing policy drop."""
        errors = verify_ruleset("some random text")
        self.assertTrue(any("policy" in e for e in errors))

    def test_missing_rfc1918(self) -> None:
        """Report all missing RFC1918 blocks."""
        errors = verify_ruleset("policy drop admin-prohibited TEROK_SHIELD_DENIED")
        rfc_errors = [e for e in errors if "RFC1918" in e]
        self.assertEqual(len(rfc_errors), len(RFC1918))

    def test_empty_input(self) -> None:
        """Report errors for empty input."""
        errors = verify_ruleset("")
        self.assertGreater(len(errors), 0)

    def test_missing_ipv6_drop(self) -> None:
        """Report missing IPv6 drop rule."""
        rfc_rules = "\n".join(
            f"ip daddr {net} reject with icmp type admin-prohibited" for net in RFC1918
        )
        bad = (
            "chain output { type filter hook output priority filter; policy drop;\n"
            f"TEROK_SHIELD_DENIED\n{rfc_rules}\n@allow_v4 }}"
        )
        errors = verify_ruleset(bad)
        self.assertTrue(any("IPv6" in e for e in errors))

    def test_ipv6_drop_misplaced(self) -> None:
        """Report IPv6 drop after accept rule."""
        rfc_rules = "\n".join(
            f"ip daddr {net} reject with icmp type admin-prohibited" for net in RFC1918
        )
        bad = (
            "chain output { type filter hook output priority filter; policy drop;\n"
            'oifname "lo" accept\n'
            "meta nfproto ipv6 drop\n"
            f"TEROK_SHIELD_DENIED\n{rfc_rules}\n@allow_v4 }}"
        )
        errors = verify_ruleset(bad)
        self.assertTrue(any("misplaced" in e for e in errors))

    def test_missing_output_chain(self) -> None:
        """Report missing output chain."""
        errors = verify_ruleset(
            "chain input { policy drop; meta nfproto ipv6 drop\n"
            "TEROK_SHIELD_DENIED admin-prohibited }"
        )
        self.assertTrue(any("output chain missing" in e for e in errors))

    def test_missing_input_chain(self) -> None:
        """Report missing input chain."""
        errors = verify_ruleset(
            "chain output { policy drop; meta nfproto ipv6 drop\n"
            "TEROK_SHIELD_DENIED admin-prohibited }"
        )
        self.assertTrue(any("input chain missing" in e for e in errors))

    def test_rejects_bypass_ruleset(self) -> None:
        """verify_ruleset must reject a bypass ruleset (output policy accept)."""
        rs = bypass_ruleset()
        errors = verify_ruleset(rs)
        self.assertGreater(len(errors), 0, "bypass ruleset must not pass enforce verification")
        self.assertTrue(
            any("deny log prefix" in e for e in errors),
            f"Expected deny log prefix error, got: {errors}",
        )

    def test_rfc1918_present_regardless_of_position(self) -> None:
        """RFC1918 presence is checked regardless of position relative to allow set."""
        rfc_rules = "\n".join(
            f"ip daddr {net} reject with icmp type admin-prohibited" for net in RFC1918
        )
        rs = f"policy drop admin-prohibited TEROK_SHIELD_DENIED @allow_v4 accept\n{rfc_rules}"
        errors = verify_ruleset(rs)
        rfc_errors = [e for e in errors if "RFC1918" in e]
        self.assertEqual(rfc_errors, [], "RFC1918 blocks present — no ordering errors expected")


class TestBypassRuleset(unittest.TestCase):
    """Tests for bypass mode ruleset generation."""

    def test_output_policy_accept(self) -> None:
        """Output chain policy must be accept."""
        rs = bypass_ruleset()
        self.assertIn("policy accept", rs)

    def test_input_policy_drop(self) -> None:
        """Input chain policy must still be drop."""
        rs = bypass_ruleset()
        self.assertIn("policy drop", rs)

    def test_ipv6_dropped(self) -> None:
        """IPv6 traffic must be dropped before any accept rules."""
        rs = bypass_ruleset()
        ipv6_pos = rs.index("meta nfproto ipv6 drop")
        first_accept_pos = rs.index('oifname "lo" accept')
        self.assertLess(ipv6_pos, first_accept_pos)

    def test_bypass_log_present(self) -> None:
        """Bypass log prefix must be present."""
        rs = bypass_ruleset()
        self.assertIn(BYPASS_LOG_PREFIX, rs)

    def test_bypass_logs_new_connections(self) -> None:
        """Bypass log rule uses ct state new."""
        rs = bypass_ruleset()
        self.assertIn("ct state new log", rs)

    def test_rfc1918_present_by_default(self) -> None:
        """RFC1918 reject rules present by default."""
        rs = bypass_ruleset()
        for net in RFC1918:
            self.assertIn(net, rs)

    def test_rfc1918_absent_with_allow_all(self) -> None:
        """RFC1918 reject rules absent when allow_all=True."""
        rs = bypass_ruleset(allow_all=True)
        for net in RFC1918:
            self.assertNotIn(net, rs)

    def test_allow_set_preserved(self) -> None:
        """allow_v4 set declaration is preserved for transition back."""
        rs = bypass_ruleset()
        self.assertIn("set allow_v4", rs)

    def test_no_deny_rule(self) -> None:
        """Bypass ruleset has no deny log or reject-all rule."""
        rs = bypass_ruleset()
        self.assertNotIn("TEROK_SHIELD_DENIED", rs)

    def test_loopback_ports(self) -> None:
        """Loopback ports appear in bypass ruleset."""
        rs = bypass_ruleset(loopback_ports=(9418,))
        self.assertIn('tcp dport 9418 oifname "lo" accept', rs)

    def test_rejects_invalid_dns(self) -> None:
        """Reject invalid DNS address."""
        with self.assertRaises(ValueError):
            bypass_ruleset(dns="not-an-ip")

    def test_rejects_invalid_loopback_port(self) -> None:
        """Reject out-of-range loopback port."""
        with self.assertRaises(ValueError):
            bypass_ruleset(loopback_ports=(0,))


class TestVerifyBypassRuleset(unittest.TestCase):
    """Tests for verify_bypass_ruleset."""

    def test_valid_bypass_ruleset(self) -> None:
        """Bypass ruleset passes all checks."""
        rs = bypass_ruleset()
        errors = verify_bypass_ruleset(rs)
        self.assertEqual(errors, [])

    def test_valid_bypass_allow_all(self) -> None:
        """Bypass ruleset with allow_all passes all checks."""
        rs = bypass_ruleset(allow_all=True)
        errors = verify_bypass_ruleset(rs)
        self.assertEqual(errors, [])

    def test_missing_accept_policy(self) -> None:
        """Report missing accept policy."""
        errors = verify_bypass_ruleset("policy drop TEROK_SHIELD_BYPASS")
        self.assertTrue(any("accept" in e for e in errors))

    def test_missing_drop_policy(self) -> None:
        """Report missing input drop policy."""
        errors = verify_bypass_ruleset("policy accept TEROK_SHIELD_BYPASS")
        self.assertTrue(any("drop" in e for e in errors))

    def test_missing_bypass_prefix(self) -> None:
        """Report missing bypass log prefix."""
        errors = verify_bypass_ruleset("policy accept policy drop")
        self.assertTrue(any("bypass" in e for e in errors))

    def test_missing_output_chain(self) -> None:
        """Report missing output chain in bypass verification."""
        errors = verify_bypass_ruleset(
            "chain input { policy drop; meta nfproto ipv6 drop\nTEROK_SHIELD_BYPASS }"
        )
        self.assertTrue(any("output chain missing" in e for e in errors))

    def test_missing_input_chain(self) -> None:
        """Report missing input chain in bypass verification."""
        errors = verify_bypass_ruleset(
            "chain output { policy accept; meta nfproto ipv6 drop\nTEROK_SHIELD_BYPASS }"
        )
        self.assertTrue(any("input chain missing" in e for e in errors))

    def test_rejects_hook_ruleset(self) -> None:
        """verify_bypass_ruleset must reject a hook (enforce) ruleset."""
        rs = hook_ruleset()
        errors = verify_bypass_ruleset(rs)
        self.assertGreater(len(errors), 0, "hook ruleset must not pass bypass verification")
        self.assertTrue(
            any("accept" in e for e in errors),
            f"Expected missing accept policy error, got: {errors}",
        )

    def test_empty_input(self) -> None:
        """Report errors for empty input."""
        errors = verify_bypass_ruleset("")
        self.assertGreater(len(errors), 0)
