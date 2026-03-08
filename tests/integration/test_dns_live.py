# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: DNS resolution with real dig."""


import shutil
import tempfile
from pathlib import Path

import pytest

from terok_shield.dns import resolve_and_cache, resolve_domains

from ..testnet import CLOUDFLARE_DOMAIN, GOOGLE_DNS_DOMAIN, NONEXISTENT_DOMAIN, TEST_IP1

dig_missing = pytest.mark.skipif(not shutil.which("dig"), reason="dig not installed")


@pytest.mark.integration
@dig_missing
class TestResolveLive:
    """DNS resolution against real nameservers."""

    def test_resolves_known_domain(self) -> None:
        """Resolve a well-known domain to at least one IP."""
        ips = resolve_domains([CLOUDFLARE_DOMAIN])
        assert len(ips) >= 1
        assert any("." in ip for ip in ips)  # IPv4

    def test_unresolvable_domain_returns_empty(self) -> None:
        """Non-existent domain returns empty list."""
        ips = resolve_domains([NONEXISTENT_DOMAIN])
        assert ips == []

    def test_multiple_domains(self) -> None:
        """Resolve multiple domains and deduplicate."""
        ips = resolve_domains([CLOUDFLARE_DOMAIN, GOOGLE_DNS_DOMAIN])
        # Both should resolve; at least 2 distinct IPs
        assert len(ips) >= 2


@pytest.mark.integration
@dig_missing
class TestResolveAndCacheLive:
    """Full resolve-and-cache pipeline with real DNS."""

    def test_cache_roundtrip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Resolve, cache, and return cached IPs on second call."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)

            # First call: resolves and writes cache
            ips1 = resolve_and_cache([CLOUDFLARE_DOMAIN], "dns-itest")
            assert len(ips1) >= 1
            cache = Path(tmp) / "resolved" / "dns-itest.resolved"
            assert cache.is_file()

            # Second call: returns from cache (no DNS needed)
            ips2 = resolve_and_cache([CLOUDFLARE_DOMAIN], "dns-itest", max_age=3600)
            assert ips2 == ips1

    def test_mixed_entries(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Raw IPs pass through alongside resolved domains."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)

            ips = resolve_and_cache([TEST_IP1, CLOUDFLARE_DOMAIN], "mixed-itest")
            assert TEST_IP1 in ips
            assert len(ips) >= 2  # raw IP + at least one resolved
