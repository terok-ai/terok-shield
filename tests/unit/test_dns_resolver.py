# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the DnsResolver class."""

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import pytest

from terok_shield import state
from terok_shield.dns.resolver import DnsResolver
from terok_shield.run import DigNotFoundError

from ..testfs import NONEXISTENT_DIR, TEST_CACHE_FILENAME, TEST_SUBDIR_NAME
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


@dataclass
class ResolverHarness:
    """A ``DnsResolver`` plus its injected runner mock."""

    resolver: DnsResolver
    runner: mock.MagicMock


ResolverHarnessFactory = Callable[..., ResolverHarness]


@pytest.fixture
def make_resolver() -> ResolverHarnessFactory:
    """Build a resolver plus its injected runner mock."""

    def _make_resolver(**runner_kwargs: object) -> ResolverHarness:
        runner = mock.MagicMock(**runner_kwargs)
        return ResolverHarness(resolver=DnsResolver(runner=runner), runner=runner)

    return _make_resolver


def test_direct_init() -> None:
    """Construct with an explicit runner."""
    runner = mock.MagicMock()
    assert DnsResolver(runner=runner)._runner is runner


def test_read_cache_missing_file() -> None:
    """_read_cache() returns an empty list for a missing cache file."""
    assert DnsResolver._read_cache(NONEXISTENT_DIR / TEST_CACHE_FILENAME) == []


def test_read_write_roundtrip(tmp_path: Path) -> None:
    """_write_cache() and _read_cache() round-trip cached IPs."""
    cache_path = tmp_path / TEST_CACHE_FILENAME
    DnsResolver._write_cache(cache_path, [TEST_IP1, TEST_IP2])
    assert DnsResolver._read_cache(cache_path) == [TEST_IP1, TEST_IP2]


def test_write_cache_creates_parent_dirs(tmp_path: Path) -> None:
    """_write_cache() creates missing parent directories."""
    cache_path = tmp_path / TEST_SUBDIR_NAME / TEST_CACHE_FILENAME
    DnsResolver._write_cache(cache_path, [TEST_IP1])
    assert cache_path.is_file()


def test_write_cache_empty_list(tmp_path: Path) -> None:
    """_write_cache() writes an empty file for an empty IP list."""
    cache_path = tmp_path / TEST_CACHE_FILENAME
    DnsResolver._write_cache(cache_path, [])
    assert cache_path.read_text() == ""


@pytest.mark.parametrize(
    ("side_effect", "domains", "expected"),
    [
        pytest.param(
            [[TEST_IP1, IPV6_CLOUDFLARE], [TEST_IP2]],
            [CLOUDFLARE_DOMAIN, GOOGLE_DNS_DOMAIN],
            [TEST_IP1, IPV6_CLOUDFLARE, TEST_IP2],
            id="multiple-domains",
        ),
        pytest.param(
            [[TEST_IP1], [TEST_IP1, TEST_IP2]],
            [TEST_DOMAIN, TEST_DOMAIN2],
            [TEST_IP1, TEST_IP2],
            id="deduplicates",
        ),
    ],
)
def test_resolve_domains(
    make_resolver: ResolverHarnessFactory,
    side_effect: list[list[str]],
    domains: list[str],
    expected: list[str],
) -> None:
    """resolve_domains() merges results while preserving first-seen order."""
    harness = make_resolver()
    harness.runner.dig_all.side_effect = side_effect
    assert harness.resolver.resolve_domains(domains) == expected


def test_logs_warning_for_unresolvable(
    make_resolver: ResolverHarnessFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """resolve_domains() logs a warning when a domain resolves to no IPs."""
    harness = make_resolver()
    harness.runner.dig_all.side_effect = [[TEST_IP1], []]

    with caplog.at_level("WARNING", logger="terok_shield.dns.resolver"):
        harness.resolver.resolve_domains([CLOUDFLARE_DOMAIN, NONEXISTENT_DOMAIN])

    assert len(caplog.messages) == 1
    assert NONEXISTENT_DOMAIN in caplog.messages[0]


def test_resolve_domains_empty_input(make_resolver: ResolverHarnessFactory) -> None:
    """resolve_domains() returns an empty list and skips DNS for empty input."""
    harness = make_resolver()
    assert harness.resolver.resolve_domains([]) == []
    harness.runner.dig_all.assert_not_called()


def test_resolve_and_cache_writes_cache(
    tmp_path: Path,
    make_resolver: ResolverHarnessFactory,
) -> None:
    """resolve_and_cache() resolves entries and writes the cache file."""
    harness = make_resolver()
    harness.runner.dig_all.return_value = [TEST_IP1]

    cache_path = state.profile_allowed_path(tmp_path)
    assert harness.resolver.resolve_and_cache([TEST_DOMAIN], cache_path) == [TEST_IP1]
    assert cache_path.is_file()


def test_resolve_and_cache_returns_fresh_cache(
    tmp_path: Path,
    make_resolver: ResolverHarnessFactory,
) -> None:
    """resolve_and_cache() returns fresh cached IPs without re-resolving DNS."""
    harness = make_resolver()
    cache_path = state.profile_allowed_path(tmp_path)
    cache_path.write_text(f"{TEST_IP1}\n{TEST_IP2}\n")

    assert harness.resolver.resolve_and_cache([TEST_DOMAIN], cache_path, max_age=3600) == [
        TEST_IP1,
        TEST_IP2,
    ]
    harness.runner.dig_all.assert_not_called()


def test_resolve_and_cache_re_resolves_stale_cache(
    tmp_path: Path,
    make_resolver: ResolverHarnessFactory,
) -> None:
    """resolve_and_cache() refreshes stale cache files."""
    harness = make_resolver()
    harness.runner.dig_all.return_value = [TEST_IP2]

    cache_path = state.profile_allowed_path(tmp_path)
    cache_path.write_text(f"{TEST_IP1}\n")
    os.utime(cache_path, (0, 0))

    assert harness.resolver.resolve_and_cache([TEST_DOMAIN], cache_path, max_age=3600) == [TEST_IP2]
    harness.runner.dig_all.assert_called_once()


def test_resolve_and_cache_mixed_entries(
    tmp_path: Path,
    make_resolver: ResolverHarnessFactory,
) -> None:
    """resolve_and_cache() preserves raw IPs while resolving domain entries."""
    harness = make_resolver()
    harness.runner.dig_all.return_value = [TEST_IP2]

    cache_path = state.profile_allowed_path(tmp_path)
    result = harness.resolver.resolve_and_cache([TEST_IP1, TEST_DOMAIN], cache_path)
    assert TEST_IP1 in result
    assert TEST_IP2 in result


def test_resolve_domains_falls_back_to_getent(
    make_resolver: ResolverHarnessFactory,
) -> None:
    """resolve_domains() falls back to getent when dig is not found."""
    harness = make_resolver()
    harness.runner.dig_all.side_effect = DigNotFoundError("dig not found")
    harness.runner.getent_hosts.side_effect = [[TEST_IP1], [TEST_IP2]]

    result = harness.resolver.resolve_domains([CLOUDFLARE_DOMAIN, GOOGLE_DNS_DOMAIN])
    assert result == [TEST_IP1, TEST_IP2]
    harness.runner.getent_hosts.assert_called()


def test_resolve_domains_getent_fallback_deduplicates(
    make_resolver: ResolverHarnessFactory,
) -> None:
    """getent fallback still deduplicates IPs."""
    harness = make_resolver()
    harness.runner.dig_all.side_effect = DigNotFoundError("dig not found")
    harness.runner.getent_hosts.side_effect = [[TEST_IP1], [TEST_IP1]]

    result = harness.resolver.resolve_domains([CLOUDFLARE_DOMAIN, GOOGLE_DNS_DOMAIN])
    assert result == [TEST_IP1]
