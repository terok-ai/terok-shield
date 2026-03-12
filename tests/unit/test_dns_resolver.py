# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the DnsResolver class."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from terok_shield.dns import DnsResolver

from ..testfs import NONEXISTENT_DIR
from ..testnet import (
    CLOUDFLARE_DOMAIN,
    GOOGLE_DNS_DOMAIN,
    IPV6_CLOUDFLARE,
    NONEXISTENT_DOMAIN,
    TEST_DOMAIN,
    TEST_DOMAIN2,
    TEST_IP1,
    TEST_IP2,
)


class TestDnsResolverInit(unittest.TestCase):
    """Test DnsResolver construction."""

    def test_direct_init(self) -> None:
        """Construct with explicit runner."""
        runner = mock.MagicMock()
        resolver = DnsResolver(runner=runner)
        self.assertIs(resolver._runner, runner)


class TestDnsResolverCache(unittest.TestCase):
    """Test DnsResolver._read_cache and _write_cache."""

    def test_read_cache_missing_file(self) -> None:
        """Return empty list for missing cache file."""
        result = DnsResolver._read_cache(NONEXISTENT_DIR / "file.resolved")
        self.assertEqual(result, [])

    def test_read_write_roundtrip(self) -> None:
        """Write then read cache produces same IPs."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.resolved"
            DnsResolver._write_cache(path, [TEST_IP1, TEST_IP2])
            result = DnsResolver._read_cache(path)
            self.assertEqual(result, [TEST_IP1, TEST_IP2])

    def test_write_creates_parent_dirs(self) -> None:
        """_write_cache creates parent directories."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "subdir" / "test.resolved"
            DnsResolver._write_cache(path, [TEST_IP1])
            self.assertTrue(path.is_file())

    def test_write_empty_list(self) -> None:
        """_write_cache writes empty content for empty list."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.resolved"
            DnsResolver._write_cache(path, [])
            self.assertEqual(path.read_text(), "")


class TestDnsResolverResolveDomains(unittest.TestCase):
    """Test DnsResolver.resolve_domains()."""

    def test_resolves_multiple(self) -> None:
        """Resolve multiple domains and deduplicate."""
        runner = mock.MagicMock()
        runner.dig_all.side_effect = [[TEST_IP1, IPV6_CLOUDFLARE], [TEST_IP2]]
        resolver = DnsResolver(runner=runner)

        result = resolver.resolve_domains([CLOUDFLARE_DOMAIN, GOOGLE_DNS_DOMAIN])
        self.assertEqual(result, [TEST_IP1, IPV6_CLOUDFLARE, TEST_IP2])

    def test_deduplicates(self) -> None:
        """Duplicate IPs across domains are deduplicated."""
        runner = mock.MagicMock()
        runner.dig_all.side_effect = [[TEST_IP1], [TEST_IP1, TEST_IP2]]
        resolver = DnsResolver(runner=runner)

        result = resolver.resolve_domains([TEST_DOMAIN, TEST_DOMAIN2])
        self.assertEqual(result, [TEST_IP1, TEST_IP2])

    def test_logs_warning_for_unresolvable(self) -> None:
        """Log warning when a domain resolves to no IPs."""
        runner = mock.MagicMock()
        runner.dig_all.side_effect = [[TEST_IP1], []]
        resolver = DnsResolver(runner=runner)

        with self.assertLogs("terok_shield.dns", level="WARNING") as cm:
            resolver.resolve_domains([CLOUDFLARE_DOMAIN, NONEXISTENT_DOMAIN])
        self.assertEqual(len(cm.output), 1)
        self.assertIn(NONEXISTENT_DOMAIN, cm.output[0])

    def test_empty_input(self) -> None:
        """Empty domain list returns empty result."""
        runner = mock.MagicMock()
        resolver = DnsResolver(runner=runner)
        result = resolver.resolve_domains([])
        self.assertEqual(result, [])
        runner.dig_all.assert_not_called()


class TestDnsResolverResolveAndCache(unittest.TestCase):
    """Test DnsResolver.resolve_and_cache()."""

    def test_resolves_and_writes_cache(self) -> None:
        """Resolve domains and write cache file."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.MagicMock()
            runner.dig_all.return_value = [TEST_IP1]
            resolver = DnsResolver(runner=runner)

            cache_path = Path(tmp) / "profile.allowed"
            result = resolver.resolve_and_cache([TEST_DOMAIN], cache_path)
            self.assertEqual(result, [TEST_IP1])
            self.assertTrue(cache_path.is_file())

    def test_returns_cached_if_fresh(self) -> None:
        """Return cached IPs without resolving if cache is fresh."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.MagicMock()
            resolver = DnsResolver(runner=runner)
            cache_path = Path(tmp) / "profile.allowed"
            cache_path.write_text(f"{TEST_IP1}\n{TEST_IP2}\n")

            result = resolver.resolve_and_cache([TEST_DOMAIN], cache_path, max_age=3600)
            self.assertEqual(result, [TEST_IP1, TEST_IP2])
            runner.dig_all.assert_not_called()

    def test_re_resolves_stale_cache(self) -> None:
        """Re-resolve when cache is stale."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.MagicMock()
            runner.dig_all.return_value = [TEST_IP2]
            resolver = DnsResolver(runner=runner)
            cache_path = Path(tmp) / "profile.allowed"
            cache_path.write_text(f"{TEST_IP1}\n")
            os.utime(cache_path, (0, 0))  # epoch = very stale

            result = resolver.resolve_and_cache([TEST_DOMAIN], cache_path, max_age=3600)
            self.assertEqual(result, [TEST_IP2])
            runner.dig_all.assert_called_once()

    def test_mixed_entries(self) -> None:
        """Handle mix of domains and raw IPs."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.MagicMock()
            runner.dig_all.return_value = [TEST_IP2]
            resolver = DnsResolver(runner=runner)

            cache_path = Path(tmp) / "profile.allowed"
            result = resolver.resolve_and_cache([TEST_IP1, TEST_DOMAIN], cache_path)
            self.assertIn(TEST_IP1, result)
            self.assertIn(TEST_IP2, result)
