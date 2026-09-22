# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the DnsResolver class."""

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import pytest

from terok_shield.dns.resolver import DnsResolver
from terok_shield.state import StateBundle

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
def make_resolver(tmp_path: Path) -> ResolverHarnessFactory:
    """Build a resolver plus its injected runner mock (``dig`` present by default).

    The shared cache lands under the test's own directory unless a test
    names one, so no test touches the operator's state root.
    """

    def _make_resolver(
        *, host_cache_dir: Path | None = None, **runner_kwargs: object
    ) -> ResolverHarness:
        runner = mock.MagicMock(**runner_kwargs)
        runner.has.return_value = True  # dig present unless a test says otherwise
        return ResolverHarness(
            resolver=DnsResolver(
                runner=runner, host_cache_dir=host_cache_dir or tmp_path / "dns-cache"
            ),
            runner=runner,
        )

    return _make_resolver


def _dig_returns(runner: mock.MagicMock, mapping: dict[str, list[str]]) -> None:
    """Answer ``lookup_all`` per domain — thread-order-independent (the pool is concurrent)."""
    runner.lookup_all.side_effect = lambda domain, **_kw: list(mapping.get(domain, []))


def _getent_returns(runner: mock.MagicMock, mapping: dict[str, list[str]]) -> None:
    """Answer ``getent_hosts`` per domain."""
    runner.getent_hosts.side_effect = lambda domain, **_kw: list(mapping.get(domain, []))


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


def test_write_cache_is_atomic_and_leaves_no_temp(tmp_path: Path) -> None:
    """_write_cache() writes via a temp file + rename, leaving only the target."""
    cache_path = tmp_path / TEST_CACHE_FILENAME
    DnsResolver._write_cache(cache_path, [TEST_IP1])
    assert cache_path.is_file()
    assert list(tmp_path.iterdir()) == [cache_path]  # no .tmp sibling left behind


def test_write_cache_concurrent_same_path_no_collision(tmp_path: Path) -> None:
    """Concurrent writes to one shared host-cache path each use a distinct temp.

    The host cache is content-hash keyed, so two same-process threads launching
    containers with the same allowlist target one file at once — a pid-only
    temp name would collide; ``mkstemp`` gives each write its own.
    """
    from concurrent.futures import ThreadPoolExecutor

    cache_path = tmp_path / "shared.resolved"
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(
            pool.map(
                lambda _n: DnsResolver._write_cache(cache_path, [TEST_IP1, TEST_IP2]), range(32)
            )
        )

    assert DnsResolver._read_cache(cache_path) == [TEST_IP1, TEST_IP2]  # a full write won
    assert [p for p in tmp_path.iterdir() if p.name.startswith(".")] == []  # no temp leftovers


def test_write_cache_cleans_up_temp_on_rename_failure(tmp_path: Path) -> None:
    """A failed rename removes the temp file and re-raises — no partial artifact."""
    cache_path = tmp_path / TEST_CACHE_FILENAME
    with mock.patch("terok_shield.dns.resolver.os.replace", side_effect=OSError("boom")):
        with pytest.raises(OSError, match="boom"):
            DnsResolver._write_cache(cache_path, [TEST_IP1])
    assert list(tmp_path.iterdir()) == []  # temp cleaned up, target never created


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


# ── resolve_domains: concurrency, dedup, probe-once ─────


@pytest.mark.parametrize(
    ("mapping", "domains", "expected"),
    [
        pytest.param(
            {CLOUDFLARE_DOMAIN: [TEST_IP1, IPV6_CLOUDFLARE], GOOGLE_DNS_DOMAIN: [TEST_IP2]},
            [CLOUDFLARE_DOMAIN, GOOGLE_DNS_DOMAIN],
            [TEST_IP1, IPV6_CLOUDFLARE, TEST_IP2],
            id="multiple-domains",
        ),
        pytest.param(
            {TEST_DOMAIN: [TEST_IP1], TEST_DOMAIN2: [TEST_IP1, TEST_IP2]},
            [TEST_DOMAIN, TEST_DOMAIN2],
            [TEST_IP1, TEST_IP2],
            id="deduplicates",
        ),
    ],
)
def test_resolve_domains_merges_in_input_order(
    make_resolver: ResolverHarnessFactory,
    mapping: dict[str, list[str]],
    domains: list[str],
    expected: list[str],
) -> None:
    """resolve_domains() merges concurrent results in first-seen (input) order.

    The per-domain mapping is answered regardless of thread completion order,
    so a pass proves the result order tracks the input, not whichever lookup
    finished first.
    """
    harness = make_resolver()
    _dig_returns(harness.runner, mapping)
    assert harness.resolver.resolve_domains(domains) == expected


def test_resolve_domains_empty_input(make_resolver: ResolverHarnessFactory) -> None:
    """resolve_domains() returns an empty list and skips DNS for empty input."""
    harness = make_resolver()
    assert harness.resolver.resolve_domains([]) == []
    harness.runner.lookup_all.assert_not_called()
    harness.runner.has.assert_not_called()  # no probe when there is nothing to resolve


def test_resolve_domains_probes_dig_once_no_getent_when_dig_answers(
    make_resolver: ResolverHarnessFactory,
) -> None:
    """When dig answers, getent is never touched (probe once, no per-domain retry)."""
    harness = make_resolver()
    _dig_returns(harness.runner, {TEST_DOMAIN: [TEST_IP1], TEST_DOMAIN2: [TEST_IP2]})
    harness.resolver.resolve_domains([TEST_DOMAIN, TEST_DOMAIN2])
    harness.runner.getent_hosts.assert_not_called()


def test_logs_warning_for_unresolvable(
    make_resolver: ResolverHarnessFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """resolve_domains() warns once when a domain yields no IPs from any tier."""
    harness = make_resolver()
    _dig_returns(harness.runner, {CLOUDFLARE_DOMAIN: [TEST_IP1]})  # NONEXISTENT → []
    _getent_returns(harness.runner, {})  # getent retry also empty

    with caplog.at_level("WARNING", logger="terok_shield.dns.resolver"):
        harness.resolver.resolve_domains([CLOUDFLARE_DOMAIN, NONEXISTENT_DOMAIN])

    unresolvable = [m for m in caplog.messages if NONEXISTENT_DOMAIN in m]
    assert len(unresolvable) == 1


# ── dig-missing and broken-dig fallbacks ────────────────


def test_resolve_domains_uses_getent_when_dig_absent(
    make_resolver: ResolverHarnessFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """No dig on the host → resolve via getent, warning once for the whole batch."""
    harness = make_resolver()
    harness.runner.has.return_value = False
    _getent_returns(harness.runner, {CLOUDFLARE_DOMAIN: [TEST_IP1], GOOGLE_DNS_DOMAIN: [TEST_IP2]})

    with caplog.at_level("WARNING", logger="terok_shield.dns.resolver"):
        result = harness.resolver.resolve_domains([CLOUDFLARE_DOMAIN, GOOGLE_DNS_DOMAIN])

    assert result == [TEST_IP1, TEST_IP2]
    harness.runner.lookup_all.assert_not_called()
    assert sum("neither dig nor drill found" in m for m in caplog.messages) == 1


def test_resolve_domains_getent_fallback_deduplicates(
    make_resolver: ResolverHarnessFactory,
) -> None:
    """getent-only path still deduplicates IPs across domains."""
    harness = make_resolver()
    harness.runner.has.return_value = False
    _getent_returns(harness.runner, {CLOUDFLARE_DOMAIN: [TEST_IP1], GOOGLE_DNS_DOMAIN: [TEST_IP1]})

    assert harness.resolver.resolve_domains([CLOUDFLARE_DOMAIN, GOOGLE_DNS_DOMAIN]) == [TEST_IP1]


def test_resolve_domains_empty_dig_retries_via_getent(
    make_resolver: ResolverHarnessFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A dig that runs but yields nothing retries that domain via getent (broken-dig env)."""
    harness = make_resolver()
    _dig_returns(harness.runner, {CLOUDFLARE_DOMAIN: []})
    _getent_returns(harness.runner, {CLOUDFLARE_DOMAIN: [TEST_IP1]})

    with caplog.at_level("WARNING", logger="terok_shield.dns.resolver"):
        result = harness.resolver.resolve_domains([CLOUDFLARE_DOMAIN])

    assert result == [TEST_IP1]
    assert any("the tool is broken" in m for m in caplog.messages)


def test_resolve_domains_empty_dig_retry_is_per_domain(
    make_resolver: ResolverHarnessFactory,
) -> None:
    """One empty dig answer retries only that domain — others keep their dig results."""
    harness = make_resolver()
    _dig_returns(harness.runner, {CLOUDFLARE_DOMAIN: [], GOOGLE_DNS_DOMAIN: [TEST_IP2]})
    _getent_returns(harness.runner, {CLOUDFLARE_DOMAIN: [TEST_IP1]})

    result = harness.resolver.resolve_domains([CLOUDFLARE_DOMAIN, GOOGLE_DNS_DOMAIN])
    assert result == [TEST_IP1, TEST_IP2]
    harness.runner.getent_hosts.assert_called_once()  # only the empty domain retried


# ── resolve_and_cache: per-container layer ──────────────


def test_resolve_and_cache_writes_cache(
    tmp_path: Path,
    make_resolver: ResolverHarnessFactory,
) -> None:
    """resolve_and_cache() resolves entries and writes the cache file."""
    harness = make_resolver()
    _dig_returns(harness.runner, {TEST_DOMAIN: [TEST_IP1]})

    cache_path = StateBundle(tmp_path).resolved_cache
    assert harness.resolver.resolve_and_cache([TEST_DOMAIN], cache_path) == [TEST_IP1]
    assert cache_path.is_file()


def test_resolve_and_cache_returns_fresh_cache(
    tmp_path: Path,
    make_resolver: ResolverHarnessFactory,
) -> None:
    """resolve_and_cache() returns fresh cached IPs without re-resolving DNS."""
    harness = make_resolver()
    cache_path = StateBundle(tmp_path).resolved_cache
    cache_path.write_text(f"{TEST_IP1}\n{TEST_IP2}\n")

    assert harness.resolver.resolve_and_cache([TEST_DOMAIN], cache_path) == [
        TEST_IP1,
        TEST_IP2,
    ]
    harness.runner.lookup_all.assert_not_called()


def test_resolve_and_cache_force_re_resolves_a_fresh_cache(
    tmp_path: Path,
    make_resolver: ResolverHarnessFactory,
) -> None:
    """resolve_and_cache(force=True) resolves again even when the cache is fresh."""
    harness = make_resolver()
    _dig_returns(harness.runner, {TEST_DOMAIN: [TEST_IP2]})
    cache_path = StateBundle(tmp_path).resolved_cache
    cache_path.write_text(f"{TEST_IP1}\n")

    assert harness.resolver.resolve_and_cache([TEST_DOMAIN], cache_path, force=True) == [TEST_IP2]
    harness.runner.lookup_all.assert_called_once()


def test_resolve_and_cache_re_resolves_stale_cache(
    tmp_path: Path,
    make_resolver: ResolverHarnessFactory,
) -> None:
    """resolve_and_cache() refreshes stale cache files."""
    harness = make_resolver()
    _dig_returns(harness.runner, {TEST_DOMAIN: [TEST_IP2]})

    cache_path = StateBundle(tmp_path).resolved_cache
    cache_path.write_text(f"{TEST_IP1}\n")
    os.utime(cache_path, (0, 0))

    assert harness.resolver.resolve_and_cache([TEST_DOMAIN], cache_path) == [TEST_IP2]
    harness.runner.lookup_all.assert_called_once()


def test_resolve_and_cache_re_resolves_when_source_is_newer(
    tmp_path: Path,
    make_resolver: ResolverHarnessFactory,
) -> None:
    """A cache older than ``source_mtime`` is re-resolved even within the freshness window."""
    harness = make_resolver()
    _dig_returns(harness.runner, {TEST_DOMAIN: [TEST_IP2]})

    cache_path = StateBundle(tmp_path).resolved_cache
    cache_path.write_text(f"{TEST_IP1}\n")
    edited_after = cache_path.stat().st_mtime + 10  # authored allowlist changed later

    result = harness.resolver.resolve_and_cache(
        [TEST_DOMAIN], cache_path, source_mtime=edited_after
    )
    assert result == [TEST_IP2]
    harness.runner.lookup_all.assert_called_once()


def test_resolve_and_cache_keeps_cache_when_source_is_older(
    tmp_path: Path,
    make_resolver: ResolverHarnessFactory,
) -> None:
    """A cache newer than ``source_mtime`` stays fresh — no re-resolution."""
    harness = make_resolver()

    cache_path = StateBundle(tmp_path).resolved_cache
    cache_path.write_text(f"{TEST_IP1}\n")
    edited_before = cache_path.stat().st_mtime - 10

    result = harness.resolver.resolve_and_cache(
        [TEST_DOMAIN], cache_path, source_mtime=edited_before
    )
    assert result == [TEST_IP1]
    harness.runner.lookup_all.assert_not_called()


def test_resolve_and_cache_mixed_entries(
    tmp_path: Path,
    make_resolver: ResolverHarnessFactory,
) -> None:
    """resolve_and_cache() preserves raw IPs while resolving domain entries."""
    harness = make_resolver()
    _dig_returns(harness.runner, {TEST_DOMAIN: [TEST_IP2]})

    cache_path = StateBundle(tmp_path).resolved_cache
    result = harness.resolver.resolve_and_cache([TEST_IP1, TEST_DOMAIN], cache_path)
    assert TEST_IP1 in result
    assert TEST_IP2 in result


# ── resolve_and_cache: shared host-level cache (opt-in) ──


def _host_files(host_dir: Path) -> list[Path]:
    """The materialized host-cache files (ignoring any in-flight temp file)."""
    return [p for p in host_dir.iterdir() if not p.name.startswith(".")]


def test_host_cache_lives_under_the_shield_state_root_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without a named directory, the shared cache is the one every container on the host uses."""
    shared = tmp_path / "shared"
    monkeypatch.setattr("terok_shield.dns.resolver.dns_cache_dir", lambda: shared)
    runner = mock.MagicMock()
    runner.has.return_value = True
    _dig_returns(runner, {TEST_DOMAIN: [TEST_IP1]})

    DnsResolver(runner=runner).resolve_and_cache(
        [TEST_DOMAIN], StateBundle(tmp_path / "ctr").resolved_cache
    )

    assert len(_host_files(shared)) == 1


def test_a_batch_says_what_the_wait_is_for(
    tmp_path: Path,
    make_resolver: ResolverHarnessFactory,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A resolution that runs is announced before and reported after; a cache hit is silent."""
    harness = make_resolver()
    _dig_returns(harness.runner, {TEST_DOMAIN: [TEST_IP1]})
    _getent_returns(harness.runner, {})
    cache_path = StateBundle(tmp_path / "ctr").resolved_cache

    harness.resolver.resolve_and_cache([TEST_DOMAIN, NONEXISTENT_DOMAIN], cache_path)
    err = capsys.readouterr().err
    assert "Resolving 2 allowlist names" in err
    assert "Resolved to 1 addresses" in err
    assert f"No address for {NONEXISTENT_DOMAIN}." in err

    harness.resolver.resolve_and_cache([TEST_DOMAIN, NONEXISTENT_DOMAIN], cache_path)
    assert capsys.readouterr().err == ""


def test_host_cache_miss_writes_both_layers(
    tmp_path: Path,
    make_resolver: ResolverHarnessFactory,
) -> None:
    """A cold resolve writes the per-container file AND the shared host file."""
    host_dir = tmp_path / "dns-cache"
    harness = make_resolver(host_cache_dir=host_dir)
    _dig_returns(harness.runner, {TEST_DOMAIN: [TEST_IP1]})
    cache_path = StateBundle(tmp_path / "ctr").resolved_cache

    harness.resolver.resolve_and_cache([TEST_DOMAIN], cache_path)
    assert cache_path.read_text().split() == [TEST_IP1]
    assert len(_host_files(host_dir)) == 1


def test_host_cache_hit_skips_resolution(
    tmp_path: Path,
    make_resolver: ResolverHarnessFactory,
) -> None:
    """A second container with the same allowlist reads the host file, never resolving."""
    host_dir = tmp_path / "dns-cache"
    first = make_resolver(host_cache_dir=host_dir)
    _dig_returns(first.runner, {TEST_DOMAIN: [TEST_IP1]})
    first.resolver.resolve_and_cache([TEST_DOMAIN], StateBundle(tmp_path / "a").resolved_cache)

    second = make_resolver(host_cache_dir=host_dir)
    cache_b = StateBundle(tmp_path / "b").resolved_cache
    result = second.resolver.resolve_and_cache([TEST_DOMAIN], cache_b)

    assert result == [TEST_IP1]
    second.runner.lookup_all.assert_not_called()  # served from the shared layer
    assert cache_b.read_text().split() == [TEST_IP1]  # materialized per-container


def test_host_cache_is_content_keyed(
    tmp_path: Path,
    make_resolver: ResolverHarnessFactory,
) -> None:
    """A changed allowlist lands on a fresh key — the edit re-resolves, no stale hit."""
    host_dir = tmp_path / "dns-cache"
    harness = make_resolver(host_cache_dir=host_dir)
    _dig_returns(harness.runner, {TEST_DOMAIN: [TEST_IP1], TEST_DOMAIN2: [TEST_IP2]})

    harness.resolver.resolve_and_cache([TEST_DOMAIN], StateBundle(tmp_path / "a").resolved_cache)
    harness.resolver.resolve_and_cache(
        [TEST_DOMAIN, TEST_DOMAIN2], StateBundle(tmp_path / "b").resolved_cache
    )
    assert len(_host_files(host_dir)) == 2  # distinct entry lists → distinct files


def test_host_cache_not_poisoned_by_total_failure(
    tmp_path: Path,
    make_resolver: ResolverHarnessFactory,
) -> None:
    """An all-domains-failed resolve is kept per-container but never shared."""
    host_dir = tmp_path / "dns-cache"
    harness = make_resolver(host_cache_dir=host_dir)
    _dig_returns(harness.runner, {})  # every domain fails
    _getent_returns(harness.runner, {})
    cache_path = StateBundle(tmp_path / "ctr").resolved_cache

    result = harness.resolver.resolve_and_cache([TEST_DOMAIN], cache_path)
    assert result == []
    assert cache_path.is_file()  # per-container view written (existing semantics)
    assert _host_files(host_dir) == []  # but the host layer is NOT poisoned


def test_host_cache_shares_when_raw_ips_only(
    tmp_path: Path,
    make_resolver: ResolverHarnessFactory,
) -> None:
    """A literal-IP-only list has nothing to fail, so it populates the shared layer."""
    host_dir = tmp_path / "dns-cache"
    harness = make_resolver(host_cache_dir=host_dir)
    cache_path = StateBundle(tmp_path / "ctr").resolved_cache

    result = harness.resolver.resolve_and_cache([TEST_IP1], cache_path)
    assert result == [TEST_IP1]
    assert len(_host_files(host_dir)) == 1
