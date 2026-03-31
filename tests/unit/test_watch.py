# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the watch module (DNS log tailing and event stream)."""

from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path
from unittest.mock import patch

import pytest

import terok_shield.watch as _watch_mod
from terok_shield.config import DnsTier
from terok_shield.watch import (
    _DOMAIN_REFRESH_INTERVAL,
    _QUERY_RE,
    DnsLogWatcher,
    WatchEvent,
    _ensure_log_file,
    _handle_signal,
    run_watch,
)
from tests.testnet import BLOCKED_DOMAIN, BLOCKED_SUBDOMAIN, TEST_DOMAIN, TEST_DOMAIN2

_CONTAINER = "test-container"


@pytest.fixture(autouse=False)
def _restore_running() -> Generator[None, None, None]:
    """Capture and restore ``terok_shield.watch._running`` around tests that mutate it."""
    original = _watch_mod._running
    yield
    _watch_mod._running = original


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
        with log.open("a") as f:
            f.write(f"query[A] {BLOCKED_DOMAIN} from 127.0.0.1\n")
        events = watcher.poll()
        watcher.close()
        assert len(events) == 1
        assert events[0].domain == BLOCKED_DOMAIN
        assert events[0].action == "blocked_query"

    def test_allowed_domain_produces_no_event(self, state_dir: Path) -> None:
        """A query for an allowed domain yields no event."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        with log.open("a") as f:
            f.write(f"query[A] {TEST_DOMAIN} from 127.0.0.1\n")
        events = watcher.poll()
        watcher.close()
        assert events == []

    def test_subdomain_of_allowed_is_allowed(self, state_dir: Path) -> None:
        """Subdomains of allowed domains are also allowed (nftset behavior)."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        with log.open("a") as f:
            f.write(f"query[A] api.{TEST_DOMAIN} from 127.0.0.1\n")
        events = watcher.poll()
        watcher.close()
        assert events == []

    def test_subdomain_of_blocked_is_blocked(self, state_dir: Path) -> None:
        """Subdomains of non-allowed domains are also blocked."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        with log.open("a") as f:
            f.write(f"query[A] {BLOCKED_SUBDOMAIN} from 127.0.0.1\n")
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
        with log.open("a") as f:
            f.write(
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
        with log.open("a") as f:
            f.write(
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

    def test_init_closes_fh_on_refresh_failure(self, tmp_path: Path) -> None:
        """File handle is closed if _refresh_domains() raises during __init__."""
        sd = tmp_path / "state"
        sd.mkdir()
        log = sd / "dnsmasq.log"
        log.write_text("")
        # Make read_merged_domains raise by putting an unreadable file
        domains = sd / "profile.domains"
        domains.write_text(f"{TEST_DOMAIN}\n")
        with patch("terok_shield.watch.dnsmasq.read_merged_domains", side_effect=OSError("boom")):
            with pytest.raises(OSError, match="boom"):
                DnsLogWatcher(log, sd, _CONTAINER)
        # File handle should be closed — opening again must succeed (not leak fds)
        with log.open() as f:
            assert f.readable()


# ── Tier validation ─────────────────────────────────────


class TestRunWatchValidation:
    """Test run_watch() tier validation."""

    def test_rejects_dig_tier(self, tmp_path: Path) -> None:
        """run_watch() exits with error on dig tier."""
        sd = tmp_path / "state"
        sd.mkdir()
        (sd / "dns.tier").write_text(DnsTier.DIG.value)
        with pytest.raises(SystemExit, match="1"):
            run_watch(sd, _CONTAINER)

    def test_rejects_getent_tier(self, tmp_path: Path) -> None:
        """run_watch() exits with error on getent tier."""
        sd = tmp_path / "state"
        sd.mkdir()
        (sd / "dns.tier").write_text(DnsTier.GETENT.value)
        with pytest.raises(SystemExit, match="1"):
            run_watch(sd, _CONTAINER)

    def test_rejects_missing_tier(self, tmp_path: Path) -> None:
        """run_watch() exits with error when dns.tier is missing."""
        sd = tmp_path / "state"
        sd.mkdir()
        with pytest.raises(SystemExit, match="1"):
            run_watch(sd, _CONTAINER)


# ── Domain refresh ──────────────────────────────────────


class TestDomainRefresh:
    """Test that DnsLogWatcher refreshes its domain set after the interval."""

    def test_poll_refreshes_domains_after_interval(self, tmp_path: Path) -> None:
        """poll() reloads the allowed domain set when the refresh interval elapses."""
        sd = tmp_path / "state"
        sd.mkdir()
        (sd / "profile.domains").write_text(f"{TEST_DOMAIN}\n")
        log = sd / "dnsmasq.log"
        log.write_text("")

        # Monotonic clock: returns 0 during init to set _last_refresh
        with patch("terok_shield.watch._monotonic", return_value=0.0):
            watcher = DnsLogWatcher(log, sd, _CONTAINER)

        # Add BLOCKED_DOMAIN to allowed set *after* watcher was created
        (sd / "profile.domains").write_text(f"{TEST_DOMAIN}\n{BLOCKED_DOMAIN}\n")

        # Append a query — before refresh, BLOCKED_DOMAIN would be blocked
        with log.open("a") as f:
            f.write(f"query[A] {BLOCKED_DOMAIN} from 127.0.0.1\n")

        # Force the clock past the refresh threshold
        with patch("terok_shield.watch._monotonic", return_value=_DOMAIN_REFRESH_INTERVAL + 1.0):
            events = watcher.poll()
        watcher.close()

        # After refresh, the domain is now allowed — no event
        assert events == []


# ── Signal handler ──────────────────────────────────────


@pytest.mark.usefixtures("_restore_running")
class TestSignalHandler:
    """Test the SIGINT/SIGTERM handler."""

    def test_handle_signal_sets_running_false(self) -> None:
        """_handle_signal() clears the module-level _running flag."""
        _watch_mod._running = True
        _handle_signal(2, None)
        assert _watch_mod._running is False


# ── run_watch happy path ────────────────────────────────


@pytest.mark.usefixtures("_restore_running")
class TestRunWatchHappyPath:
    """Test run_watch() select loop, event output, and log file creation."""

    @pytest.fixture
    def dnsmasq_state(self, tmp_path: Path) -> Path:
        """State dir with dnsmasq tier, profile domains, and dnsmasq config."""
        sd = tmp_path / "state"
        sd.mkdir()
        (sd / "dns.tier").write_text(DnsTier.DNSMASQ.value)
        (sd / "profile.domains").write_text(f"{TEST_DOMAIN}\n")
        (sd / "dnsmasq.conf").write_text("# stub config\n")
        return sd

    def test_creates_log_file_if_missing(self, dnsmasq_state: Path) -> None:
        """run_watch() creates dnsmasq.log if it does not exist yet."""
        log = dnsmasq_state / "dnsmasq.log"
        assert not log.exists()

        # Stop after one iteration
        call_count = 0

        def _stop_after_one(*_args: object, **_kwargs: object) -> tuple[list, list, list]:
            nonlocal call_count
            call_count += 1
            _watch_mod._running = False
            return ([], [], [])

        with patch("terok_shield.watch.select.select", side_effect=_stop_after_one):
            run_watch(dnsmasq_state, _CONTAINER)

        assert log.is_file()

    def test_outputs_blocked_event_as_json(
        self, dnsmasq_state: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """run_watch() prints a JSON line for each blocked query."""
        log = dnsmasq_state / "dnsmasq.log"
        log.write_text("")

        iteration = 0

        def _select_then_stop(*_args: object, **_kwargs: object) -> tuple[list, list, list]:
            nonlocal iteration
            iteration += 1
            if iteration == 1:
                # Simulate dnsmasq writing a query between select calls
                with log.open("a") as f:
                    f.write(f"query[A] {BLOCKED_DOMAIN} from 127.0.0.1\n")
                return ([True], [], [])
            # Stop on second iteration
            _watch_mod._running = False
            return ([], [], [])

        with patch("terok_shield.watch.select.select", side_effect=_select_then_stop):
            run_watch(dnsmasq_state, _CONTAINER)

        output = capsys.readouterr().out.strip()
        parsed = json.loads(output)
        assert parsed["domain"] == BLOCKED_DOMAIN
        assert parsed["action"] == "blocked_query"

    def test_allowed_domain_produces_no_output(
        self, dnsmasq_state: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """run_watch() produces no output for queries to allowed domains."""
        log = dnsmasq_state / "dnsmasq.log"
        log.write_text("")

        iteration = 0

        def _select_then_stop(*_args: object, **_kwargs: object) -> tuple[list, list, list]:
            nonlocal iteration
            iteration += 1
            if iteration == 1:
                with log.open("a") as f:
                    f.write(f"query[A] {TEST_DOMAIN} from 127.0.0.1\n")
                return ([True], [], [])
            _watch_mod._running = False
            return ([], [], [])

        with patch("terok_shield.watch.select.select", side_effect=_select_then_stop):
            run_watch(dnsmasq_state, _CONTAINER)

        assert capsys.readouterr().out == ""


# ── _ensure_log_file ────────────────────────────────────


class TestEnsureLogFile:
    """Test log file creation for shield watch."""

    def test_creates_missing_file(self, tmp_path: Path) -> None:
        """Creates the log file when it does not exist."""
        log = tmp_path / "dnsmasq.log"
        _ensure_log_file(log)
        assert log.is_file()

    def test_idempotent_on_existing_file(self, tmp_path: Path) -> None:
        """No-op when the log file already exists."""
        log = tmp_path / "dnsmasq.log"
        log.write_text("existing content\n")
        _ensure_log_file(log)
        assert log.read_text() == "existing content\n"
