# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the watch module (DNS log tailing and event stream)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from terok_shield.config import DnsTier
from terok_shield.watch import _QUERY_RE, DnsLogWatcher, WatchEvent
from tests.testnet import BLOCKED_DOMAIN, BLOCKED_SUBDOMAIN, TEST_DOMAIN, TEST_DOMAIN2

_CONTAINER = "test-container"


# ── WatchEvent ──────────────────────────────────────────


class TestWatchEvent:
    """Test WatchEvent dataclass and serialization."""

    def test_to_json_round_trips(self) -> None:
        """JSON output can be parsed back to the same fields."""
        event = WatchEvent(
            ts="2026-03-31T12:00:00+00:00",
            source="dns",
            action="blocked_query",
            domain=BLOCKED_DOMAIN,
            query_type="A",
            container=_CONTAINER,
        )
        parsed = json.loads(event.to_json())
        assert parsed["domain"] == BLOCKED_DOMAIN
        assert parsed["action"] == "blocked_query"
        assert parsed["source"] == "dns"
        assert parsed["query_type"] == "A"
        assert parsed["container"] == _CONTAINER

    def test_to_json_is_compact(self) -> None:
        """JSON output uses compact separators (no spaces)."""
        event = WatchEvent(
            ts="2026-01-01T00:00:00+00:00",
            source="dns",
            action="blocked_query",
            domain=BLOCKED_DOMAIN,
            query_type="AAAA",
            container=_CONTAINER,
        )
        raw = event.to_json()
        assert ": " not in raw
        assert ", " not in raw


# ── Query regex ─────────────────────────────────────────


class TestQueryRegex:
    """Test the dnsmasq query log line regex."""

    @pytest.mark.parametrize(
        ("line", "expected_type", "expected_domain"),
        [
            pytest.param(
                f"Mar 31 12:00:00 dnsmasq[123]: query[A] {BLOCKED_DOMAIN} from 127.0.0.1",
                "A",
                BLOCKED_DOMAIN,
                id="query-A",
            ),
            pytest.param(
                f"Mar 31 12:00:00 dnsmasq[123]: query[AAAA] {BLOCKED_DOMAIN} from 127.0.0.1",
                "AAAA",
                BLOCKED_DOMAIN,
                id="query-AAAA",
            ),
        ],
    )
    def test_matches_query_lines(self, line: str, expected_type: str, expected_domain: str) -> None:
        """Regex extracts query type and domain from dnsmasq log lines."""
        m = _QUERY_RE.search(line)
        assert m is not None
        assert m.group(1) == expected_type
        assert m.group(2) == expected_domain

    @pytest.mark.parametrize(
        "line",
        [
            pytest.param(
                f"Mar 31 12:00:00 dnsmasq[123]: reply {BLOCKED_DOMAIN} is 1.2.3.4",
                id="reply-line",
            ),
            pytest.param(
                f"Mar 31 12:00:00 dnsmasq[123]: forwarded {BLOCKED_DOMAIN} to 169.254.1.1",
                id="forwarded-line",
            ),
            pytest.param(
                "Mar 31 12:00:00 dnsmasq[123]: started, cache size 150",
                id="startup-line",
            ),
            pytest.param("", id="empty-line"),
        ],
    )
    def test_ignores_non_query_lines(self, line: str) -> None:
        """Regex does not match non-query dnsmasq log lines."""
        assert _QUERY_RE.search(line) is None


# ── DnsLogWatcher ───────────────────────────────────────


class TestDnsLogWatcher:
    """Test DnsLogWatcher file tailing and domain classification."""

    @pytest.fixture
    def state_dir(self, tmp_path: Path) -> Path:
        """Create a minimal state dir with profile.domains."""
        sd = tmp_path / "state"
        sd.mkdir()
        # Write allowed domains
        (sd / "profile.domains").write_text(f"{TEST_DOMAIN}\n{TEST_DOMAIN2}\n")
        # Create the log file
        (sd / "dnsmasq.log").write_text("")
        return sd

    def test_blocked_domain_produces_event(self, state_dir: Path) -> None:
        """A query for a non-allowed domain yields a blocked_query event."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        # Append a query line after watcher opened (seeks to end)
        log.write_text(f"query[A] {BLOCKED_DOMAIN} from 127.0.0.1\n")
        events = watcher.poll()
        watcher.close()
        assert len(events) == 1
        assert events[0].domain == BLOCKED_DOMAIN
        assert events[0].action == "blocked_query"

    def test_allowed_domain_produces_no_event(self, state_dir: Path) -> None:
        """A query for an allowed domain yields no event."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        log.write_text(f"query[A] {TEST_DOMAIN} from 127.0.0.1\n")
        events = watcher.poll()
        watcher.close()
        assert events == []

    def test_subdomain_of_allowed_is_allowed(self, state_dir: Path) -> None:
        """Subdomains of allowed domains are also allowed (nftset behavior)."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        log.write_text(f"query[A] api.{TEST_DOMAIN} from 127.0.0.1\n")
        events = watcher.poll()
        watcher.close()
        assert events == []

    def test_subdomain_of_blocked_is_blocked(self, state_dir: Path) -> None:
        """Subdomains of non-allowed domains are also blocked."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        log.write_text(f"query[A] {BLOCKED_SUBDOMAIN} from 127.0.0.1\n")
        events = watcher.poll()
        watcher.close()
        assert len(events) == 1
        assert events[0].domain == BLOCKED_SUBDOMAIN

    def test_empty_read_produces_no_events(self, state_dir: Path) -> None:
        """poll() returns empty list when no new lines are available."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        events = watcher.poll()
        watcher.close()
        assert events == []

    def test_multiple_queries_in_batch(self, state_dir: Path) -> None:
        """Multiple queries appended at once are all processed."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        log.write_text(
            f"query[A] {BLOCKED_DOMAIN} from 127.0.0.1\n"
            f"query[AAAA] {BLOCKED_DOMAIN} from 127.0.0.1\n"
            f"query[A] {TEST_DOMAIN} from 127.0.0.1\n"
        )
        events = watcher.poll()
        watcher.close()
        assert len(events) == 2
        assert {e.query_type for e in events} == {"A", "AAAA"}

    def test_non_query_lines_are_skipped(self, state_dir: Path) -> None:
        """Reply and forwarded lines do not produce events."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        log.write_text(
            f"reply {BLOCKED_DOMAIN} is 1.2.3.4\nforwarded {BLOCKED_DOMAIN} to 169.254.1.1\n"
        )
        events = watcher.poll()
        watcher.close()
        assert events == []

    def test_fileno_returns_int(self, state_dir: Path) -> None:
        """fileno() returns a valid file descriptor for select()."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        assert isinstance(watcher.fileno(), int)
        watcher.close()


# ── Tier validation ─────────────────────────────────────


class TestRunWatchValidation:
    """Test run_watch() tier validation."""

    def test_rejects_dig_tier(self, tmp_path: Path) -> None:
        """run_watch() exits with error on dig tier."""
        sd = tmp_path / "state"
        sd.mkdir()
        (sd / "dns.tier").write_text(DnsTier.DIG.value)
        with pytest.raises(SystemExit, match="1"):
            from terok_shield.watch import run_watch

            run_watch(sd, _CONTAINER)

    def test_rejects_getent_tier(self, tmp_path: Path) -> None:
        """run_watch() exits with error on getent tier."""
        sd = tmp_path / "state"
        sd.mkdir()
        (sd / "dns.tier").write_text(DnsTier.GETENT.value)
        with pytest.raises(SystemExit, match="1"):
            from terok_shield.watch import run_watch

            run_watch(sd, _CONTAINER)

    def test_rejects_missing_tier(self, tmp_path: Path) -> None:
        """run_watch() exits with error when dns.tier is missing."""
        sd = tmp_path / "state"
        sd.mkdir()
        with pytest.raises(SystemExit, match="1"):
            from terok_shield.watch import run_watch

            run_watch(sd, _CONTAINER)
