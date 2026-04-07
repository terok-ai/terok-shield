# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: DNS resolution with real dig."""

import tempfile
from pathlib import Path

import pytest

from terok_shield.dns.resolver import DnsResolver
from terok_shield.run import SubprocessRunner
from tests.testnet import CLOUDFLARE_DOMAIN, GOOGLE_DNS_DOMAIN, NONEXISTENT_DOMAIN, TEST_IP1

from ..conftest import dig_missing


@pytest.mark.needs_internet
@dig_missing
class TestResolveLive:
    """DNS resolution against real nameservers."""

    def test_resolves_known_domain(self) -> None:
        """Resolve a well-known domain to at least one IP."""
        resolver = DnsResolver(runner=SubprocessRunner())
        ips = resolver.resolve_domains([CLOUDFLARE_DOMAIN])
        assert len(ips) >= 1
        assert any("." in ip for ip in ips)  # IPv4

    def test_unresolvable_domain_returns_empty(self) -> None:
        """Non-existent domain returns empty list."""
        resolver = DnsResolver(runner=SubprocessRunner())
        ips = resolver.resolve_domains([NONEXISTENT_DOMAIN])
        assert ips == []

    def test_multiple_domains(self) -> None:
        """Resolve multiple domains and deduplicate."""
        resolver = DnsResolver(runner=SubprocessRunner())
        ips = resolver.resolve_domains([CLOUDFLARE_DOMAIN, GOOGLE_DNS_DOMAIN])
        # Both should resolve; at least 2 distinct IPs
        assert len(ips) >= 2


@pytest.mark.needs_internet
@dig_missing
class TestResolveAndCacheLive:
    """Full resolve-and-cache pipeline with real DNS."""

    def test_cache_roundtrip(self) -> None:
        """Resolve, cache, and return cached IPs on second call."""
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "profile.allowed"
            resolver = DnsResolver(runner=SubprocessRunner())

            # First call: resolves and writes cache
            ips1 = resolver.resolve_and_cache([CLOUDFLARE_DOMAIN], cache_path)
            assert len(ips1) >= 1
            assert cache_path.is_file()

            # Second call: returns from cache (no DNS needed)
            ips2 = resolver.resolve_and_cache([CLOUDFLARE_DOMAIN], cache_path, max_age=3600)
            assert ips2 == ips1

    def test_mixed_entries(self) -> None:
        """Raw IPs pass through alongside resolved domains."""
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "profile.allowed"
            resolver = DnsResolver(runner=SubprocessRunner())

            ips = resolver.resolve_and_cache([TEST_IP1, CLOUDFLARE_DOMAIN], cache_path)
            assert TEST_IP1 in ips
            assert len(ips) >= 2  # raw IP + at least one resolved
