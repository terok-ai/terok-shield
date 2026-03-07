# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for DNS resolution and caching."""

import time
import unittest
import unittest.mock

from terok_shield.dns import (
    _cache_fresh,
    _cache_path,
    _is_ip,
    _split_entries,
    resolve_and_cache,
    resolve_domains,
)

from .testnet import TEST_IP1, TEST_IP2, TEST_IP3, TEST_NET1


class TestIsIp(unittest.TestCase):
    """Tests for _is_ip helper."""

    def test_ipv4_address(self) -> None:
        """Detect plain IPv4 address."""
        self.assertTrue(_is_ip(TEST_IP1))

    def test_cidr(self) -> None:
        """Detect CIDR notation."""
        self.assertTrue(_is_ip(TEST_NET1))

    def test_domain(self) -> None:
        """Reject domain names."""
        self.assertFalse(_is_ip("example.com"))

    def test_empty(self) -> None:
        """Reject empty string."""
        self.assertFalse(_is_ip(""))


class TestSplitEntries(unittest.TestCase):
    """Tests for _split_entries."""

    def test_mixed(self) -> None:
        """Split mixed entries into domains and IPs."""
        domains, ips = _split_entries(["example.com", TEST_IP1, "test.org", TEST_NET1])
        self.assertEqual(domains, ["example.com", "test.org"])
        self.assertEqual(ips, [TEST_IP1, TEST_NET1])

    def test_all_domains(self) -> None:
        """All domains, no IPs."""
        domains, ips = _split_entries(["a.com", "b.org"])
        self.assertEqual(domains, ["a.com", "b.org"])
        self.assertEqual(ips, [])

    def test_all_ips(self) -> None:
        """All IPs, no domains."""
        domains, ips = _split_entries([TEST_IP1, TEST_IP2])
        self.assertEqual(domains, [])
        self.assertEqual(ips, [TEST_IP1, TEST_IP2])


class TestResolveDomains(unittest.TestCase):
    """Tests for resolve_domains."""

    @unittest.mock.patch("terok_shield.dns.dig")
    def test_resolves_multiple(self, mock_dig: unittest.mock.Mock) -> None:
        """Resolve multiple domains and deduplicate."""
        mock_dig.side_effect = [[TEST_IP1, TEST_IP2], [TEST_IP2, TEST_IP3]]
        result = resolve_domains(["a.com", "b.com"])
        self.assertEqual(result, [TEST_IP1, TEST_IP2, TEST_IP3])

    @unittest.mock.patch("terok_shield.dns.dig")
    def test_skips_failed(self, mock_dig: unittest.mock.Mock) -> None:
        """Skip domains that fail to resolve."""
        mock_dig.side_effect = [[TEST_IP1], []]
        result = resolve_domains(["good.com", "bad.com"])
        self.assertEqual(result, [TEST_IP1])

    @unittest.mock.patch("terok_shield.dns.dig")
    def test_empty_input(self, mock_dig: unittest.mock.Mock) -> None:
        """Empty domain list returns empty result."""
        result = resolve_domains([])
        mock_dig.assert_not_called()
        self.assertEqual(result, [])


class TestCacheFreshness(unittest.TestCase):
    """Tests for cache freshness checking."""

    def test_fresh_cache(self, tmp_path=None) -> None:
        """Cache file younger than max_age is fresh."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.resolved"
            path.write_text(f"{TEST_IP1}\n")
            self.assertTrue(_cache_fresh(path, max_age=3600))

    def test_stale_cache(self) -> None:
        """Cache file older than max_age is stale."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.resolved"
            path.write_text(f"{TEST_IP1}\n")
            # Backdate the file
            old_time = time.time() - 7200
            import os

            os.utime(path, (old_time, old_time))
            self.assertFalse(_cache_fresh(path, max_age=3600))

    def test_missing_cache(self) -> None:
        """Missing cache file is not fresh."""
        from pathlib import Path

        self.assertFalse(_cache_fresh(Path("/nonexistent/test.resolved"), max_age=3600))


class TestCachePath(unittest.TestCase):
    """Tests for _cache_path validation."""

    @unittest.mock.patch("terok_shield.dns.shield_resolved_dir")
    def test_valid_name(self, mock_dir: unittest.mock.Mock) -> None:
        """Accept valid container names."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            path = _cache_path("my-container.123")
            self.assertEqual(path.name, "my-container.123.resolved")

    def test_rejects_path_traversal(self) -> None:
        """Reject names with path traversal."""
        with self.assertRaises(ValueError):
            _cache_path("../etc/passwd")

    def test_rejects_slash(self) -> None:
        """Reject names with slashes."""
        with self.assertRaises(ValueError):
            _cache_path("foo/bar")

    def test_rejects_empty(self) -> None:
        """Reject empty name."""
        with self.assertRaises(ValueError):
            _cache_path("")


class TestResolveAndCache(unittest.TestCase):
    """Tests for resolve_and_cache."""

    @unittest.mock.patch("terok_shield.dns.dig")
    @unittest.mock.patch("terok_shield.dns.shield_resolved_dir")
    def test_resolves_and_writes_cache(
        self, mock_dir: unittest.mock.Mock, mock_dig: unittest.mock.Mock
    ) -> None:
        """Resolve domains and write cache file."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            mock_dig.return_value = [TEST_IP1]
            result = resolve_and_cache(["example.com"], "test-ctr")
            self.assertEqual(result, [TEST_IP1])
            cache = Path(tmp) / "test-ctr.resolved"
            self.assertTrue(cache.is_file())
            self.assertIn(TEST_IP1, cache.read_text())

    @unittest.mock.patch("terok_shield.dns.dig")
    @unittest.mock.patch("terok_shield.dns.shield_resolved_dir")
    def test_returns_cached_if_fresh(
        self, mock_dir: unittest.mock.Mock, mock_dig: unittest.mock.Mock
    ) -> None:
        """Return cached IPs without resolving if cache is fresh."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            cache = Path(tmp) / "test-ctr.resolved"
            cache.write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
            result = resolve_and_cache(["example.com"], "test-ctr", max_age=3600)
            self.assertEqual(result, [TEST_IP1, TEST_IP2])
            mock_dig.assert_not_called()

    @unittest.mock.patch("terok_shield.dns.dig")
    @unittest.mock.patch("terok_shield.dns.shield_resolved_dir")
    def test_re_resolves_stale_cache(
        self, mock_dir: unittest.mock.Mock, mock_dig: unittest.mock.Mock
    ) -> None:
        """Re-resolve when cache is stale."""
        import os
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            cache = Path(tmp) / "test-ctr.resolved"
            cache.write_text(f"{TEST_IP1}\n")
            os.utime(cache, (0, 0))  # epoch = very stale
            mock_dig.return_value = [TEST_IP2]
            result = resolve_and_cache(["example.com"], "test-ctr", max_age=3600)
            self.assertEqual(result, [TEST_IP2])
            mock_dig.assert_called_once()

    @unittest.mock.patch("terok_shield.dns.dig")
    @unittest.mock.patch("terok_shield.dns.shield_resolved_dir")
    def test_mixed_entries(
        self, mock_dir: unittest.mock.Mock, mock_dig: unittest.mock.Mock
    ) -> None:
        """Handle mix of domains and raw IPs."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            mock_dig.return_value = [TEST_IP2]
            result = resolve_and_cache([TEST_IP1, "example.com"], "test-ctr")
            self.assertIn(TEST_IP1, result)
            self.assertIn(TEST_IP2, result)

    @unittest.mock.patch("terok_shield.dns.dig")
    @unittest.mock.patch("terok_shield.dns.shield_resolved_dir")
    def test_fresh_cache_ignores_changed_entries(
        self, mock_dir: unittest.mock.Mock, mock_dig: unittest.mock.Mock
    ) -> None:
        """Fresh cache returns cached IPs regardless of new entries."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            # First call: resolve and cache
            mock_dig.return_value = [TEST_IP1]
            resolve_and_cache(["example.com"], "test-ctr")
            # Second call with different entries — cache is still fresh
            result = resolve_and_cache(["other.example.com"], "test-ctr", max_age=3600)
            self.assertEqual(result, [TEST_IP1])
            # dig was only called once (for the first resolve)
            mock_dig.assert_called_once()
