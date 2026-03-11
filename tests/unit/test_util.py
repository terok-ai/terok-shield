# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for shared utility functions."""

import unittest

from terok_shield.util import is_ip, is_ipv4, is_ipv6

from ..testnet import IPV6_CLOUDFLARE, TEST_IP1, TEST_NET1


class TestIsIpv4(unittest.TestCase):
    """Tests for is_ipv4."""

    def test_ipv4_address(self) -> None:
        """Detect plain IPv4 address."""
        self.assertTrue(is_ipv4(TEST_IP1))

    def test_cidr(self) -> None:
        """Detect CIDR notation."""
        self.assertTrue(is_ipv4(TEST_NET1))

    def test_domain(self) -> None:
        """Reject domain names."""
        self.assertFalse(is_ipv4("example.com"))

    def test_empty(self) -> None:
        """Reject empty string."""
        self.assertFalse(is_ipv4(""))

    def test_ipv6_rejected(self) -> None:
        """Reject IPv6 addresses."""
        self.assertFalse(is_ipv4("::1"))


class TestIsIpv6(unittest.TestCase):
    """Tests for is_ipv6."""

    def test_ipv6_address(self) -> None:
        """Detect plain IPv6 address."""
        self.assertTrue(is_ipv6(IPV6_CLOUDFLARE))

    def test_cidr(self) -> None:
        """Detect CIDR notation."""
        self.assertTrue(is_ipv6("fc00::/7"))

    def test_domain(self) -> None:
        """Reject domain names."""
        self.assertFalse(is_ipv6("example.com"))

    def test_empty(self) -> None:
        """Reject empty string."""
        self.assertFalse(is_ipv6(""))

    def test_ipv4_rejected(self) -> None:
        """Reject IPv4 addresses."""
        self.assertFalse(is_ipv6(TEST_IP1))


class TestIsIp(unittest.TestCase):
    """Tests for is_ip."""

    def test_ipv4(self) -> None:
        """Accept IPv4 address."""
        self.assertTrue(is_ip(TEST_IP1))

    def test_ipv6(self) -> None:
        """Accept IPv6 address."""
        self.assertTrue(is_ip("::1"))

    def test_domain(self) -> None:
        """Reject domain names."""
        self.assertFalse(is_ip("example.com"))
