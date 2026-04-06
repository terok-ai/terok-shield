# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the NFLOG interactive connection handler."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest import mock

import pytest

from terok_shield.cli.interactive import (
    _INPUT_MAP,
    _NSENTER_ENV,
    _RAW_ENV,
    CliSessionIO,
    InteractiveSession,
    JsonSessionIO,
    _append_unique,
    _handle_signal,
    _main,
    _PendingPacket,
    run_interactive,
)
from terok_shield.core import state
from terok_shield.lib.watchers import WatchEvent

from ..testnet import (
    DNSMASQ_DOMAIN,
    DNSMASQ_DOMAIN2,
    KEPT_DOMAIN,
    TEST_IP1,
    TEST_IP2,
)

_CONTAINER = "test-ctr"


# ── Helpers ───────────────────────────────────────────────


def _make_session(tmp_path: Path) -> InteractiveSession:
    """Create an InteractiveSession with a mock runner rooted at tmp_path."""
    runner = mock.MagicMock()
    return InteractiveSession(
        runner=runner,
        state_dir=tmp_path,
        container=_CONTAINER,
    )


def _make_event(dest: str, port: int = 443, proto: int = 6) -> WatchEvent:
    """Build a minimal WatchEvent with action=queued_connection."""
    return WatchEvent(
        ts="2026-01-01T00:00:00",
        source="nflog",
        action="queued_connection",
        container=_CONTAINER,
        dest=dest,
        port=port,
        proto=proto,
    )


# ── _handle_signal ────────────────────────────────────────


class TestHandleSignal:
    """Tests for the module-level signal handler."""

    def test_sets_running_false(self) -> None:
        """_handle_signal sets the module-level _running flag to False."""
        import terok_shield.cli.interactive as mod

        mod._running = True
        _handle_signal(2, None)
        assert mod._running is False


# ── _PendingPacket ────────────────────────────────────────


class TestPendingPacket:
    """Tests for the _PendingPacket dataclass."""

    def test_fields_and_defaults(self) -> None:
        """_PendingPacket stores all fields with correct defaults."""
        pkt = _PendingPacket(dest=TEST_IP1, port=443, proto=6, queued_at=1.0)
        assert pkt.dest == TEST_IP1
        assert pkt.port == 443
        assert pkt.proto == 6
        assert pkt.queued_at == 1.0
        assert pkt.domain == ""
        assert pkt.packet_id == 0

    def test_explicit_optional_fields(self) -> None:
        """_PendingPacket accepts explicit domain and packet_id."""
        pkt = _PendingPacket(
            dest=TEST_IP2,
            port=80,
            proto=6,
            queued_at=2.0,
            domain=DNSMASQ_DOMAIN,
            packet_id=42,
        )
        assert pkt.domain == DNSMASQ_DOMAIN
        assert pkt.packet_id == 42


# ── _append_unique ────────────────────────────────────────


class TestAppendUnique:
    """Tests for the _append_unique helper."""

    def test_appends_new_value(self, tmp_path: Path) -> None:
        """_append_unique writes a value to a new file."""
        path = tmp_path / "test.list"
        _append_unique(path, TEST_IP1)
        assert TEST_IP1 in path.read_text()

    def test_deduplicates(self, tmp_path: Path) -> None:
        """_append_unique does not write the same value twice."""
        path = tmp_path / "test.list"
        _append_unique(path, TEST_IP1)
        _append_unique(path, TEST_IP1)
        lines = [line for line in path.read_text().splitlines() if line.strip()]
        assert lines.count(TEST_IP1) == 1

    def test_appends_second_value(self, tmp_path: Path) -> None:
        """_append_unique adds distinct values to the same file."""
        path = tmp_path / "test.list"
        _append_unique(path, TEST_IP1)
        _append_unique(path, TEST_IP2)
        content = path.read_text()
        assert TEST_IP1 in content
        assert TEST_IP2 in content

    def test_creates_file_if_missing(self, tmp_path: Path) -> None:
        """_append_unique creates the file if it does not exist."""
        path = tmp_path / "test.list"
        _append_unique(path, TEST_IP1)
        assert path.is_file()


# ── InteractiveSession._handle_nflog_event ────────────────


class TestHandleNflogEvent:
    """Tests for InteractiveSession._handle_nflog_event."""

    def test_emits_pending_json(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """_handle_nflog_event emits a pending JSON line on stdout."""
        session = _make_session(tmp_path)
        event = _make_event(TEST_IP1)
        session._handle_nflog_event(event)
        out = json.loads(capsys.readouterr().out.strip())
        assert out["type"] == "pending"
        assert out["id"] == 1
        assert out["dest"] == TEST_IP1
        assert out["port"] == 443
        assert out["proto"] == 6

    def test_deduplicates_by_ip(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Second event to the same IP is silently dropped."""
        session = _make_session(tmp_path)
        session._handle_nflog_event(_make_event(TEST_IP1))
        capsys.readouterr()  # clear first output
        session._handle_nflog_event(_make_event(TEST_IP1, port=80))
        assert capsys.readouterr().out == ""

    def test_different_ips_get_different_ids(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Each unique IP gets a monotonically increasing id."""
        session = _make_session(tmp_path)
        session._handle_nflog_event(_make_event(TEST_IP1))
        out1 = json.loads(capsys.readouterr().out.strip())
        session._handle_nflog_event(_make_event(TEST_IP2))
        out2 = json.loads(capsys.readouterr().out.strip())
        assert out1["id"] == 1
        assert out2["id"] == 2

    def test_includes_domain_from_cache(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """_handle_nflog_event looks up domain from the IP-to-domain cache."""
        session = _make_session(tmp_path)
        session._domain_cache._mapping[TEST_IP1] = DNSMASQ_DOMAIN
        session._handle_nflog_event(_make_event(TEST_IP1))
        out = json.loads(capsys.readouterr().out.strip())
        assert out["domain"] == DNSMASQ_DOMAIN


# ── InteractiveSession._process_command ───────────────────


class TestProcessCommand:
    """Tests for InteractiveSession._process_command."""

    def _setup_pending(self, session: InteractiveSession) -> int:
        """Inject a pending packet with id=1 and return the id."""
        pkt = _PendingPacket(
            dest=TEST_IP1, port=443, proto=6, queued_at=time.monotonic(), packet_id=1
        )
        session._pending_by_ip[TEST_IP1] = pkt
        return 1

    def test_accept_verdict(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Accept verdict emits verdict_applied with ok=True."""
        session = _make_session(tmp_path)
        pkt_id = self._setup_pending(session)
        with mock.patch.object(session, "_apply_verdict", return_value=True):
            session._process_command(
                json.dumps({"type": "verdict", "id": pkt_id, "action": "accept"})
            )
        out = json.loads(capsys.readouterr().out.strip())
        assert out["type"] == "verdict_applied"
        assert out["action"] == "accept"
        assert out["ok"] is True

    def test_deny_verdict(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Deny verdict emits verdict_applied with ok=True."""
        session = _make_session(tmp_path)
        pkt_id = self._setup_pending(session)
        with mock.patch.object(session, "_apply_verdict", return_value=True):
            session._process_command(
                json.dumps({"type": "verdict", "id": pkt_id, "action": "deny"})
            )
        out = json.loads(capsys.readouterr().out.strip())
        assert out["action"] == "deny"
        assert out["ok"] is True

    def test_invalid_json_logged(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Invalid JSON on stdin is logged as a warning."""
        session = _make_session(tmp_path)
        session._process_command("not json at all")
        assert "Invalid JSON" in caplog.text

    def test_non_dict_json_logged(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """A JSON array (non-dict) is logged as a warning."""
        session = _make_session(tmp_path)
        session._process_command("[1, 2, 3]")
        assert "Expected JSON object" in caplog.text

    def test_unknown_type_logged(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Unknown command type is logged as a warning."""
        session = _make_session(tmp_path)
        session._process_command(json.dumps({"type": "ping"}))
        assert "Unknown command type" in caplog.text

    def test_bool_id_rejected(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Boolean id is rejected (bool is subclass of int)."""
        session = _make_session(tmp_path)
        session._process_command(json.dumps({"type": "verdict", "id": True, "action": "accept"}))
        assert "must be an integer" in caplog.text

    def test_string_id_rejected(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """String id is rejected."""
        session = _make_session(tmp_path)
        session._process_command(json.dumps({"type": "verdict", "id": "one", "action": "accept"}))
        assert "must be an integer" in caplog.text

    def test_invalid_action_rejected(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Action other than accept/deny is rejected."""
        session = _make_session(tmp_path)
        session._process_command(json.dumps({"type": "verdict", "id": 1, "action": "drop"}))
        assert "must be 'accept' or 'deny'" in caplog.text

    def test_unknown_id_logged(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Verdict for a non-existent pending packet is logged."""
        session = _make_session(tmp_path)
        session._process_command(json.dumps({"type": "verdict", "id": 999, "action": "accept"}))
        assert "No pending packet" in caplog.text


# ── InteractiveSession._apply_verdict ─────────────────────


class TestApplyVerdict:
    """Tests for InteractiveSession._apply_verdict."""

    def test_accept_persists_to_live_allowed(self, tmp_path: Path) -> None:
        """Accept verdict persists IP to live.allowed."""
        session = _make_session(tmp_path)
        pkt = _PendingPacket(dest=TEST_IP1, port=443, proto=6, queued_at=1.0, packet_id=1)
        with mock.patch("terok_shield.cli.interactive.add_elements_dual", return_value="nft add"):
            result = session._apply_verdict(pkt, accept=True)
        assert result is True
        assert TEST_IP1 in state.live_allowed_path(tmp_path).read_text()

    def test_deny_persists_to_deny_list(self, tmp_path: Path) -> None:
        """Deny verdict persists IP to deny.list."""
        session = _make_session(tmp_path)
        pkt = _PendingPacket(dest=TEST_IP1, port=443, proto=6, queued_at=1.0, packet_id=1)
        with mock.patch(
            "terok_shield.cli.interactive.add_deny_elements_dual", return_value="nft add"
        ):
            result = session._apply_verdict(pkt, accept=False)
        assert result is True
        assert TEST_IP1 in state.deny_path(tmp_path).read_text()

    def test_nft_failure_returns_false(self, tmp_path: Path) -> None:
        """nft command failure causes _apply_verdict to return False."""
        session = _make_session(tmp_path)
        session._runner.nft_via_nsenter.side_effect = RuntimeError("nft failed")
        pkt = _PendingPacket(dest=TEST_IP1, port=443, proto=6, queued_at=1.0, packet_id=1)
        with mock.patch(
            "terok_shield.cli.interactive.add_elements_dual", return_value="nft add x\n"
        ):
            result = session._apply_verdict(pkt, accept=True)
        assert result is False

    def test_accept_uses_permanent_for_dnsmasq_tier(self, tmp_path: Path) -> None:
        """Accept verdict uses permanent=True when dnsmasq tier is active."""
        session = _make_session(tmp_path)
        state.dns_tier_path(tmp_path).write_text("dnsmasq\n")
        pkt = _PendingPacket(dest=TEST_IP1, port=443, proto=6, queued_at=1.0, packet_id=1)
        with mock.patch("terok_shield.cli.interactive.add_elements_dual", return_value="") as m:
            session._apply_verdict(pkt, accept=True)
        m.assert_called_once_with([TEST_IP1], permanent=True)

    def test_accept_uses_non_permanent_for_dig_tier(self, tmp_path: Path) -> None:
        """Accept verdict uses permanent=False when dig tier is active."""
        session = _make_session(tmp_path)
        state.dns_tier_path(tmp_path).write_text("dig\n")
        pkt = _PendingPacket(dest=TEST_IP1, port=443, proto=6, queued_at=1.0, packet_id=1)
        with mock.patch("terok_shield.cli.interactive.add_elements_dual", return_value="") as m:
            session._apply_verdict(pkt, accept=True)
        m.assert_called_once_with([TEST_IP1], permanent=False)


# ── InteractiveSession._nft_apply edge cases ─────────────


class TestNftApplyEdgeCases:
    """Tests for _nft_apply edge cases."""

    def test_empty_lines_skipped(self, tmp_path: Path) -> None:
        """_nft_apply skips empty lines in multi-line nft commands."""
        session = _make_session(tmp_path)
        result = session._nft_apply("add element foo\n\n\nadd element bar\n")
        assert result is True
        assert session._runner.nft_via_nsenter.call_count == 2

    def test_is_dnsmasq_tier_oserror(self, tmp_path: Path) -> None:
        """_is_dnsmasq_tier returns False on OSError reading the tier file."""
        session = _make_session(tmp_path)
        with mock.patch.object(Path, "is_file", side_effect=OSError("boom")):
            assert session._is_dnsmasq_tier() is False


# ── _drain_watcher / _readable_fds ──────────────────────


class TestDrainWatcherAndReadableFds:
    """Tests for the _drain_watcher method and _readable_fds helper."""

    def test_drain_watcher_processes_queued_events(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """_drain_watcher processes queued_connection events."""
        session = _make_session(tmp_path)
        mock_watcher = mock.MagicMock()
        mock_watcher.poll.return_value = [_make_event(TEST_IP1)]
        session._drain_watcher(mock_watcher)
        out = capsys.readouterr().out
        assert "pending" in out

    def test_drain_watcher_ignores_non_queued(self, tmp_path: Path) -> None:
        """_drain_watcher ignores events that are not queued_connection."""
        from terok_shield.lib.watchers import WatchEvent

        session = _make_session(tmp_path)
        mock_watcher = mock.MagicMock()
        mock_watcher.poll.return_value = [
            WatchEvent(
                ts="t",
                source="nflog",
                action="blocked_connection",
                container="c",
                dest=TEST_IP1,
                port=443,
                proto=6,
            )
        ]
        session._drain_watcher(mock_watcher)
        assert TEST_IP1 not in session._seen_ips

    def test_readable_fds_with_int_and_object(self) -> None:
        """_readable_fds handles both raw ints and objects with fileno()."""
        from terok_shield.cli.interactive import _readable_fds

        obj = mock.MagicMock()
        obj.fileno.return_value = 42
        result = _readable_fds([7, obj])
        assert result == {7, 42}


# ── DomainCache (via InteractiveSession) ──────────────────


class TestDomainCacheIntegration:
    """Tests for DomainCache as used by InteractiveSession."""

    def test_parses_dnsmasq_log(self, tmp_path: Path) -> None:
        """DomainCache parses dnsmasq 'reply' lines into IP-to-domain mapping."""
        log_path = state.dnsmasq_log_path(tmp_path)
        log_path.write_text(
            f"reply {DNSMASQ_DOMAIN} is {TEST_IP1}\nreply {DNSMASQ_DOMAIN2} is {TEST_IP2}\n"
        )
        from terok_shield.lib.watchers import DomainCache

        cache = DomainCache(tmp_path)
        cache.refresh()
        assert cache.lookup(TEST_IP1) == DNSMASQ_DOMAIN
        assert cache.lookup(TEST_IP2) == DNSMASQ_DOMAIN2

    def test_parses_cached_lines(self, tmp_path: Path) -> None:
        """DomainCache parses dnsmasq 'cached' lines (cache-hit responses)."""
        log_path = state.dnsmasq_log_path(tmp_path)
        log_path.write_text(
            f"cached {DNSMASQ_DOMAIN} is {TEST_IP1}\ncached {DNSMASQ_DOMAIN2} is {TEST_IP2}\n"
        )
        from terok_shield.lib.watchers import DomainCache

        cache = DomainCache(tmp_path)
        cache.refresh()
        assert cache.lookup(TEST_IP1) == DNSMASQ_DOMAIN
        assert cache.lookup(TEST_IP2) == DNSMASQ_DOMAIN2

    def test_oserror_preserves_cache(self, tmp_path: Path) -> None:
        """OSError when reading dnsmasq log preserves the previous cache."""
        from terok_shield.lib.watchers import DomainCache

        cache = DomainCache(tmp_path)
        cache._mapping[TEST_IP1] = KEPT_DOMAIN
        # dnsmasq.log does not exist, so read_text raises OSError
        cache.refresh()
        assert cache.lookup(TEST_IP1) == KEPT_DOMAIN

    def test_replaces_stale_entries(self, tmp_path: Path) -> None:
        """A new log replaces the entire cache (old entries disappear)."""
        from terok_shield.lib.watchers import DomainCache

        log_path = state.dnsmasq_log_path(tmp_path)
        log_path.write_text(f"reply {DNSMASQ_DOMAIN} is {TEST_IP1}\n")
        cache = DomainCache(tmp_path)
        cache.refresh()
        assert cache.lookup(TEST_IP1) == DNSMASQ_DOMAIN
        log_path.write_text(f"reply {DNSMASQ_DOMAIN2} is {TEST_IP2}\n")
        cache.refresh()
        assert cache.lookup(TEST_IP1) == ""
        assert cache.lookup(TEST_IP2) == DNSMASQ_DOMAIN2

    def test_strips_trailing_dot(self, tmp_path: Path) -> None:
        """Trailing dots in domain names are stripped."""
        from terok_shield.lib.watchers import DomainCache

        log_path = state.dnsmasq_log_path(tmp_path)
        log_path.write_text(f"reply {DNSMASQ_DOMAIN}. is {TEST_IP1}\n")
        cache = DomainCache(tmp_path)
        cache.refresh()
        assert cache.lookup(TEST_IP1) == DNSMASQ_DOMAIN

    def test_lookup_unknown_ip(self, tmp_path: Path) -> None:
        """lookup returns empty string for unknown IPs."""
        from terok_shield.lib.watchers import DomainCache

        cache = DomainCache(tmp_path)
        assert cache.lookup(TEST_IP1) == ""


# ── InteractiveSession._read_stdin ────────────────────────


class TestReadStdin:
    """Tests for InteractiveSession._read_stdin."""

    @staticmethod
    def _mock_stdin() -> mock.MagicMock:
        """Return a mock stdin with a stable fileno()."""
        fake_stdin = mock.MagicMock()
        fake_stdin.fileno.return_value = 0
        return fake_stdin

    def test_eof_returns_none(self, tmp_path: Path) -> None:
        """Empty read (EOF) returns None."""
        session = _make_session(tmp_path)
        with (
            mock.patch("terok_shield.cli.interactive.sys.stdin", self._mock_stdin()),
            mock.patch("terok_shield.cli.interactive.os.read", return_value=b""),
        ):
            result = session._read_stdin("")
        assert result is None

    def test_oserror_returns_buf(self, tmp_path: Path) -> None:
        """OSError from os.read returns the current buffer unchanged."""
        session = _make_session(tmp_path)
        with (
            mock.patch("terok_shield.cli.interactive.sys.stdin", self._mock_stdin()),
            mock.patch("terok_shield.cli.interactive.os.read", side_effect=OSError("broken pipe")),
        ):
            result = session._read_stdin("partial")
        assert result == "partial"

    def test_processes_complete_lines(self, tmp_path: Path) -> None:
        """Complete lines are passed to _process_command; remainder stays in buffer."""
        session = _make_session(tmp_path)
        line = json.dumps({"type": "verdict", "id": 1, "action": "accept"})
        data = (line + "\npartial").encode()
        with (
            mock.patch("terok_shield.cli.interactive.sys.stdin", self._mock_stdin()),
            mock.patch("terok_shield.cli.interactive.os.read", return_value=data),
        ):
            with mock.patch.object(session, "_process_command") as mock_cmd:
                result = session._read_stdin("")
        mock_cmd.assert_called_once_with(line)
        assert result == "partial"


# ── run_interactive ───────────────────────────────────────


class TestRunInteractive:
    """Tests for the run_interactive entry point."""

    def test_nsenter_reexec_when_not_in_netns(self, tmp_path: Path) -> None:
        """run_interactive calls nsenter reexec when not inside the container netns."""
        with mock.patch("terok_shield.cli.interactive._nsenter_reexec") as mock_reexec:
            run_interactive(tmp_path, _CONTAINER)
        mock_reexec.assert_called_once_with(tmp_path, _CONTAINER, raw=False)

    def test_dispatches_to_session_inside_netns(self, tmp_path: Path) -> None:
        """run_interactive creates a session when already inside the container netns."""
        with (
            mock.patch.dict("os.environ", {_NSENTER_ENV: "1"}),
            mock.patch("terok_shield.cli.interactive.SubprocessRunner") as mock_runner_cls,
            mock.patch("terok_shield.cli.interactive.InteractiveSession") as mock_session_cls,
        ):
            run_interactive(tmp_path, _CONTAINER)
        mock_runner_cls.assert_called_once()
        mock_session_cls.assert_called_once()
        mock_session_cls.return_value.run.assert_called_once()


# ── __main__ block ───────────────────────────────────────


class TestMainBlock:
    """Tests for the :func:`_main` entry point."""

    def test_wrong_argc_exits_2(self) -> None:
        """Exits with code 2 when argument count is wrong."""
        with (
            mock.patch("sys.argv", []),
            pytest.raises(SystemExit) as ctx,
        ):
            _main()
        assert ctx.value.code == 2

    def test_correct_args_calls_run_interactive(self, tmp_path: Path) -> None:
        """Correct argc dispatches to run_interactive with parsed args."""
        with (
            mock.patch("sys.argv", ["prog", str(tmp_path), "test-ctr"]),
            mock.patch("terok_shield.cli.interactive.run_interactive") as mock_run,
        ):
            _main()
        mock_run.assert_called_once_with(tmp_path, "test-ctr", raw=False)

    def test_raw_env_selects_raw_mode(self, tmp_path: Path) -> None:
        """_main passes raw=True when _RAW_ENV is set."""
        with (
            mock.patch("sys.argv", ["prog", str(tmp_path), "test-ctr"]),
            mock.patch.dict("os.environ", {_RAW_ENV: "1"}),
            mock.patch("terok_shield.cli.interactive.run_interactive") as mock_run,
        ):
            _main()
        mock_run.assert_called_once_with(tmp_path, "test-ctr", raw=True)


# ── _nsenter_reexec ──────────────────────────────────────


class TestNsenterReexec:
    """Tests for the _nsenter_reexec helper."""

    def test_builds_nsenter_command(self, tmp_path: Path) -> None:
        """_nsenter_reexec invokes podman unshare nsenter with correct args."""
        from terok_shield.cli.interactive import _nsenter_reexec

        with (
            mock.patch("terok_shield.cli.interactive.SubprocessRunner") as mock_runner_cls,
            mock.patch("subprocess.run") as mock_run,
        ):
            mock_runner_cls.return_value.podman_inspect.return_value = "12345"
            _nsenter_reexec(tmp_path, _CONTAINER, raw=False)

        cmd = mock_run.call_args[0][0]
        assert cmd[:3] == ["podman", "unshare", "nsenter"]
        assert "-t" in cmd and "12345" in cmd
        assert "-n" in cmd
        assert str(tmp_path) in cmd
        assert _CONTAINER in cmd
        env = mock_run.call_args[1]["env"]
        assert env[_NSENTER_ENV] == "1"
        assert _RAW_ENV not in env

    def test_subprocess_failure_raises_systemexit(self, tmp_path: Path) -> None:
        """_nsenter_reexec raises SystemExit on subprocess failure."""
        import subprocess

        from terok_shield.cli.interactive import _nsenter_reexec

        with (
            mock.patch("terok_shield.cli.interactive.SubprocessRunner") as mock_runner_cls,
            mock.patch(
                "subprocess.run",
                side_effect=subprocess.CalledProcessError(42, "nsenter"),
            ),
            pytest.raises(SystemExit) as ctx,
        ):
            mock_runner_cls.return_value.podman_inspect.return_value = "12345"
            _nsenter_reexec(tmp_path, _CONTAINER, raw=False)
        assert ctx.value.code == 42


# ── InteractiveSession.run / _loop coverage ──────────────


class TestInteractiveSessionRun:
    """Tests for InteractiveSession.run() and _loop() event loop."""

    def test_run_exits_if_watcher_unavailable(self, tmp_path: Path) -> None:
        """run() exits with code 1 if NflogWatcher.create returns None."""
        session = _make_session(tmp_path)
        with (
            mock.patch("terok_shield.cli.interactive.NflogWatcher.create", return_value=None),
            pytest.raises(SystemExit) as ctx,
        ):
            session.run()
        assert ctx.value.code == 1

    def test_run_creates_watcher_and_loops(self, tmp_path: Path) -> None:
        """run() creates a watcher, enters the loop, and closes on signal."""
        import terok_shield.cli.interactive as mod

        session = _make_session(tmp_path)
        mock_watcher = mock.MagicMock()
        mock_watcher.fileno.return_value = 99

        # Stop the loop after one iteration
        original_running = mod._running

        def stop_after_one(*_args: object, **_kw: object) -> tuple[list, list, list]:
            mod._running = False
            return ([], [], [])

        mock_stdin = mock.MagicMock()
        mock_stdin.fileno.return_value = 0
        with (
            mock.patch(
                "terok_shield.cli.interactive.NflogWatcher.create", return_value=mock_watcher
            ),
            mock.patch("terok_shield.cli.interactive._set_nonblocking"),
            mock.patch("terok_shield.cli.interactive.select.select", side_effect=stop_after_one),
            mock.patch("terok_shield.cli.interactive.sys.stdin", mock_stdin),
        ):
            session.run()
        mock_watcher.close.assert_called_once()
        mod._running = original_running

    def test_loop_breaks_on_select_error(self, tmp_path: Path) -> None:
        """_loop() exits cleanly when select raises OSError."""
        import terok_shield.cli.interactive as mod

        session = _make_session(tmp_path)
        mock_watcher = mock.MagicMock()
        mock_watcher.fileno.return_value = 99
        original = mod._running
        mod._running = True
        with mock.patch(
            "terok_shield.cli.interactive.select.select", side_effect=OSError("broken")
        ):
            session._loop(mock_watcher, 0)
        mod._running = original

    def test_loop_processes_nflog_events(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """_loop() processes queued_connection events from the watcher."""
        import terok_shield.cli.interactive as mod

        session = _make_session(tmp_path)
        mock_watcher = mock.MagicMock()
        mock_watcher.fileno.return_value = 99
        event = _make_event(TEST_IP1)
        mock_watcher.poll.return_value = [event]

        call_count = 0

        def select_twice(*_a: object, **_k: object) -> tuple[list, list, list]:
            nonlocal call_count
            call_count += 1
            if call_count > 1:
                mod._running = False
                return ([], [], [])
            return ([mock_watcher], [], [])

        original = mod._running
        mod._running = True
        with mock.patch("terok_shield.cli.interactive.select.select", side_effect=select_twice):
            session._loop(mock_watcher, 99)
        mod._running = original
        out = capsys.readouterr().out.strip()
        assert "pending" in out

    def test_loop_reads_stdin_eof(self, tmp_path: Path) -> None:
        """_loop() exits when stdin returns EOF."""
        import terok_shield.cli.interactive as mod

        session = _make_session(tmp_path)
        mock_watcher = mock.MagicMock()
        mock_watcher.fileno.return_value = 99

        def select_stdin(*_a: object, **_k: object) -> tuple[list, list, list]:
            return ([42], [], [])  # stdin_fd=42

        original = mod._running
        mod._running = True
        with (
            mock.patch("terok_shield.cli.interactive.select.select", side_effect=select_stdin),
            mock.patch("terok_shield.cli.interactive.os.read", return_value=b""),
            mock.patch("terok_shield.cli.interactive.sys.stdin") as mock_stdin,
        ):
            mock_stdin.fileno.return_value = 42
            session._loop(mock_watcher, 42)
        mod._running = original


# ── _set_nonblocking coverage ─────────────────────────────


class TestSetNonblocking:
    """Tests for the _set_nonblocking helper."""

    def test_sets_nonblocking_flag(self) -> None:
        """_set_nonblocking calls fcntl to set O_NONBLOCK."""
        import fcntl as real_fcntl

        from terok_shield.cli.interactive import _set_nonblocking

        mock_fcntl = mock.MagicMock()
        mock_fcntl.F_GETFL = real_fcntl.F_GETFL
        mock_fcntl.F_SETFL = real_fcntl.F_SETFL
        mock_fcntl.fcntl.return_value = 0
        with mock.patch.dict("sys.modules", {"fcntl": mock_fcntl}):
            _set_nonblocking(5)
        assert mock_fcntl.fcntl.call_count == 2


# ── Verdict removes pending entry ─────────────────────────


class TestVerdictRemovesPending:
    """Verify that successful verdicts consume the pending entry."""

    def test_successful_verdict_removes_pending(self, tmp_path: Path) -> None:
        """A successful accept verdict removes the IP from _pending_by_ip."""
        session = _make_session(tmp_path)
        pkt = _PendingPacket(
            dest=TEST_IP1, port=443, proto=6, queued_at=time.monotonic(), packet_id=1
        )
        session._pending_by_ip[TEST_IP1] = pkt
        with mock.patch.object(session, "_apply_verdict", return_value=True):
            session._process_command(json.dumps({"type": "verdict", "id": 1, "action": "accept"}))
        assert TEST_IP1 not in session._pending_by_ip

    def test_failed_verdict_keeps_pending(self, tmp_path: Path) -> None:
        """A failed verdict keeps the entry for retry."""
        session = _make_session(tmp_path)
        pkt = _PendingPacket(
            dest=TEST_IP1, port=443, proto=6, queued_at=time.monotonic(), packet_id=1
        )
        session._pending_by_ip[TEST_IP1] = pkt
        with mock.patch.object(session, "_apply_verdict", return_value=False):
            session._process_command(json.dumps({"type": "verdict", "id": 1, "action": "accept"}))
        assert TEST_IP1 in session._pending_by_ip


# ── JsonSessionIO ───────────────────────────────────────


class TestJsonSessionIO:
    """Tests for the JSON-lines machine protocol I/O."""

    def test_emit_pending_writes_json_line(self, capsys: pytest.CaptureFixture[str]) -> None:
        """emit_pending prints a compact JSON line with all fields."""
        io = JsonSessionIO()
        io.emit_pending(1, TEST_IP1, 443, 6, DNSMASQ_DOMAIN)
        out = json.loads(capsys.readouterr().out.strip())
        assert out == {
            "type": "pending",
            "id": 1,
            "dest": TEST_IP1,
            "port": 443,
            "proto": 6,
            "domain": DNSMASQ_DOMAIN,
        }

    def test_emit_verdict_applied_writes_json_line(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """emit_verdict_applied prints a compact JSON line."""
        io = JsonSessionIO()
        io.emit_verdict_applied(1, TEST_IP1, "accept", ok=True)
        out = json.loads(capsys.readouterr().out.strip())
        assert out == {
            "type": "verdict_applied",
            "id": 1,
            "dest": TEST_IP1,
            "action": "accept",
            "ok": True,
        }

    def test_parse_command_valid_verdict(self) -> None:
        """parse_command returns (id, action) for a valid verdict."""
        io = JsonSessionIO()
        result = io.parse_command('{"type":"verdict","id":1,"action":"accept"}')
        assert result == (1, "accept")

    def test_parse_command_deny(self) -> None:
        """parse_command handles deny action."""
        io = JsonSessionIO()
        result = io.parse_command('{"type":"verdict","id":2,"action":"deny"}')
        assert result == (2, "deny")

    def test_parse_command_invalid_json(self) -> None:
        """parse_command returns None for invalid JSON."""
        io = JsonSessionIO()
        assert io.parse_command("not json") is None

    def test_parse_command_non_dict(self) -> None:
        """parse_command returns None for non-object JSON."""
        io = JsonSessionIO()
        assert io.parse_command("[1,2,3]") is None

    def test_parse_command_wrong_type(self) -> None:
        """parse_command returns None for unknown command type."""
        io = JsonSessionIO()
        assert io.parse_command('{"type":"other","id":1,"action":"accept"}') is None

    def test_parse_command_bool_id(self) -> None:
        """parse_command returns None when id is a boolean."""
        io = JsonSessionIO()
        assert io.parse_command('{"type":"verdict","id":true,"action":"accept"}') is None

    def test_parse_command_invalid_action(self) -> None:
        """parse_command returns None for unknown action."""
        io = JsonSessionIO()
        assert io.parse_command('{"type":"verdict","id":1,"action":"drop"}') is None

    def test_emit_banner_is_noop(self, capsys: pytest.CaptureFixture[str]) -> None:
        """emit_banner produces no output for the machine protocol."""
        io = JsonSessionIO()
        io.emit_banner()
        assert capsys.readouterr().out == ""


# ── CliSessionIO ────────────────────────────────────────


class TestCliSessionIO:
    """Tests for the human-friendly CLI session I/O."""

    def test_emit_pending_shows_blocked_with_domain(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """emit_pending renders a [BLOCKED] line with domain label."""
        io = CliSessionIO()
        io.emit_pending(1, TEST_IP1, 443, 6, DNSMASQ_DOMAIN)
        out = capsys.readouterr().out
        assert "[BLOCKED]" in out
        assert TEST_IP1 in out
        assert DNSMASQ_DOMAIN in out
        assert ":443" in out

    def test_emit_pending_shows_ip_without_domain(self, capsys: pytest.CaptureFixture[str]) -> None:
        """emit_pending shows just the IP when no domain is known."""
        io = CliSessionIO()
        io.emit_pending(1, TEST_IP1, 80, 6, "")
        out = capsys.readouterr().out
        assert "[BLOCKED]" in out
        assert TEST_IP1 in out
        assert ":80" in out

    def test_emit_pending_queues_second_packet(self, capsys: pytest.CaptureFixture[str]) -> None:
        """A second pending packet is shown as queued, then prompt re-rendered."""
        io = CliSessionIO()
        io.emit_pending(1, TEST_IP1, 443, 6, DNSMASQ_DOMAIN)
        io.emit_pending(2, TEST_IP2, 80, 6, DNSMASQ_DOMAIN2)
        out = capsys.readouterr().out
        assert "(queued)" in out
        # Prompt for head-of-queue (packet 1) must be re-rendered after the queued line.
        queued_pos = out.index("(queued)")
        last_prompt_pos = out.rindex("allow/deny?")
        assert last_prompt_pos > queued_pos

    def test_emit_verdict_applied_accept(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Accept verdict shows a checkmark."""
        io = CliSessionIO()
        io.emit_pending(1, TEST_IP1, 443, 6, DNSMASQ_DOMAIN)
        capsys.readouterr()  # discard pending output
        io.emit_verdict_applied(1, TEST_IP1, "accept", ok=True)
        out = capsys.readouterr().out
        assert "\u2713" in out
        assert "allowed" in out
        assert DNSMASQ_DOMAIN in out

    def test_emit_verdict_applied_deny(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Deny verdict shows a cross."""
        io = CliSessionIO()
        io.emit_pending(1, TEST_IP1, 443, 6, "")
        capsys.readouterr()
        io.emit_verdict_applied(1, TEST_IP1, "deny", ok=True)
        out = capsys.readouterr().out
        assert "\u2717" in out
        assert "denied" in out

    def test_emit_verdict_applied_failure(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Failed verdict shows an error marker and keeps the packet queued."""
        io = CliSessionIO()
        io.emit_pending(1, TEST_IP1, 443, 6, "")
        capsys.readouterr()
        io.emit_verdict_applied(1, TEST_IP1, "accept", ok=False)
        out = capsys.readouterr().out
        assert "failed" in out
        # Packet must remain queued for retry.
        assert 1 in io._queue
        assert 1 in io._info

    def test_verdict_prompts_next_queued(self, capsys: pytest.CaptureFixture[str]) -> None:
        """After resolving the first packet, the next queued one is prompted."""
        io = CliSessionIO()
        io.emit_pending(1, TEST_IP1, 443, 6, DNSMASQ_DOMAIN)
        io.emit_pending(2, TEST_IP2, 80, 6, DNSMASQ_DOMAIN2)
        capsys.readouterr()
        io.emit_verdict_applied(1, TEST_IP1, "accept", ok=True)
        out = capsys.readouterr().out
        assert "[BLOCKED]" in out
        assert DNSMASQ_DOMAIN2 in out

    def test_parse_command_a(self) -> None:
        """'a' maps to accept for the oldest pending packet."""
        io = CliSessionIO()
        io.emit_pending(1, TEST_IP1, 443, 6, "")
        assert io.parse_command("a") == (1, "accept")

    def test_parse_command_d(self) -> None:
        """'d' maps to deny."""
        io = CliSessionIO()
        io.emit_pending(1, TEST_IP1, 443, 6, "")
        assert io.parse_command("d") == (1, "deny")

    def test_parse_command_allow(self) -> None:
        """'allow' maps to accept."""
        io = CliSessionIO()
        io.emit_pending(1, TEST_IP1, 443, 6, "")
        assert io.parse_command("allow") == (1, "accept")

    def test_parse_command_deny(self) -> None:
        """'deny' maps to deny."""
        io = CliSessionIO()
        io.emit_pending(1, TEST_IP1, 443, 6, "")
        assert io.parse_command("deny") == (1, "deny")

    def test_parse_command_case_insensitive(self) -> None:
        """Input is case-insensitive."""
        io = CliSessionIO()
        io.emit_pending(1, TEST_IP1, 443, 6, "")
        assert io.parse_command("Allow") == (1, "accept")
        assert io.parse_command("DENY") == (1, "deny")

    def test_parse_command_unknown_input(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Unknown input prints a hint, re-prompts, and returns None."""
        io = CliSessionIO()
        io.emit_pending(1, TEST_IP1, 443, 6, DNSMASQ_DOMAIN)
        capsys.readouterr()
        assert io.parse_command("x") is None
        out = capsys.readouterr().out
        assert "Unknown input" in out
        # Prompt must be re-rendered after invalid input.
        assert "allow/deny?" in out

    def test_parse_command_empty_queue(self) -> None:
        """Returns None when no packets are pending."""
        io = CliSessionIO()
        assert io.parse_command("a") is None

    def test_prompt_head_missing_info(self, capsys: pytest.CaptureFixture[str]) -> None:
        """_prompt_head is a no-op when _info lacks the head-of-queue entry."""
        io = CliSessionIO()
        io._queue.append(99)  # ID with no matching _info entry
        io._prompt_head()
        assert capsys.readouterr().out == ""

    def test_parse_fifo_order(self) -> None:
        """Input targets the oldest pending packet (FIFO)."""
        io = CliSessionIO()
        io.emit_pending(1, TEST_IP1, 443, 6, "")
        io.emit_pending(2, TEST_IP2, 80, 6, "")
        result = io.parse_command("a")
        assert result == (1, "accept")

    def test_emit_banner(self, capsys: pytest.CaptureFixture[str]) -> None:
        """emit_banner prints a startup message."""
        io = CliSessionIO()
        io.emit_banner()
        out = capsys.readouterr().out
        assert "Watching" in out
        assert "Ctrl-C" in out

    def test_input_map_coverage(self) -> None:
        """All expected input tokens are in _INPUT_MAP."""
        assert _INPUT_MAP["a"] == "accept"
        assert _INPUT_MAP["allow"] == "accept"
        assert _INPUT_MAP["d"] == "deny"
        assert _INPUT_MAP["deny"] == "deny"
        assert len(_INPUT_MAP) == 4


# ── --raw flag propagation ──────────────────────────────


class TestSessionIOInjection:
    """Tests for SessionIO injection into InteractiveSession."""

    def test_falsy_session_io_is_preserved(self, tmp_path: Path) -> None:
        """A non-None but falsy SessionIO is stored, not replaced by default."""

        class _FalsyIO(JsonSessionIO):
            def __bool__(self) -> bool:
                return False

        io = _FalsyIO()
        session = InteractiveSession(
            runner=mock.MagicMock(), state_dir=tmp_path, container="ctr", io=io
        )
        assert session._io is io


class TestRawFlagPropagation:
    """Tests for --raw flag through run_interactive and nsenter re-exec."""

    def test_run_interactive_raw_false_uses_cli_io(self, tmp_path: Path) -> None:
        """run_interactive defaults to CliSessionIO."""

        with (
            mock.patch.dict("os.environ", {_NSENTER_ENV: "1"}),
            mock.patch("terok_shield.cli.interactive.SubprocessRunner"),
            mock.patch("terok_shield.cli.interactive.InteractiveSession") as mock_cls,
        ):
            run_interactive(tmp_path, _CONTAINER)
        io_arg = mock_cls.call_args[1]["io"]
        assert isinstance(io_arg, CliSessionIO)

    def test_run_interactive_raw_true_uses_json_io(self, tmp_path: Path) -> None:
        """run_interactive with raw=True uses JsonSessionIO."""

        with (
            mock.patch.dict("os.environ", {_NSENTER_ENV: "1"}),
            mock.patch("terok_shield.cli.interactive.SubprocessRunner"),
            mock.patch("terok_shield.cli.interactive.InteractiveSession") as mock_cls,
        ):
            run_interactive(tmp_path, _CONTAINER, raw=True)
        io_arg = mock_cls.call_args[1]["io"]
        assert isinstance(io_arg, JsonSessionIO)

    def test_nsenter_propagates_raw_env(self, tmp_path: Path) -> None:
        """_nsenter_reexec sets _RAW_ENV when raw=True."""
        from terok_shield.cli.interactive import _nsenter_reexec

        with (
            mock.patch("terok_shield.cli.interactive.SubprocessRunner") as mock_runner_cls,
            mock.patch("subprocess.run") as mock_run,
        ):
            mock_runner_cls.return_value.podman_inspect.return_value = "12345"
            _nsenter_reexec(tmp_path, _CONTAINER, raw=True)
        env = mock_run.call_args[1]["env"]
        assert env[_RAW_ENV] == "1"

    def test_nsenter_omits_raw_env_when_false(self, tmp_path: Path) -> None:
        """_nsenter_reexec does not set _RAW_ENV when raw=False."""
        from terok_shield.cli.interactive import _nsenter_reexec

        with (
            mock.patch("terok_shield.cli.interactive.SubprocessRunner") as mock_runner_cls,
            mock.patch("subprocess.run") as mock_run,
        ):
            mock_runner_cls.return_value.podman_inspect.return_value = "12345"
            _nsenter_reexec(tmp_path, _CONTAINER, raw=False)
        env = mock_run.call_args[1]["env"]
        assert _RAW_ENV not in env


# ── Domain-level allow/deny in _apply_verdict ────────────


class TestApplyVerdictDomain:
    """Tests for domain-level dnsmasq allow/deny in _apply_verdict."""

    def test_accept_calls_allow_domain_when_dnsmasq(self, tmp_path: Path) -> None:
        """Accept verdict calls _allow_domain when domain is known and tier is dnsmasq."""
        session = _make_session(tmp_path)
        state.dns_tier_path(tmp_path).write_text("dnsmasq\n")
        pkt = _PendingPacket(
            dest=TEST_IP1, port=443, proto=6, queued_at=1.0, packet_id=1, domain=DNSMASQ_DOMAIN
        )
        with (
            mock.patch("terok_shield.cli.interactive.add_elements_dual", return_value=""),
            mock.patch.object(session, "_allow_domain") as mock_allow,
        ):
            session._apply_verdict(pkt, accept=True)
        mock_allow.assert_called_once_with(DNSMASQ_DOMAIN)

    def test_deny_calls_deny_domain_when_dnsmasq(self, tmp_path: Path) -> None:
        """Deny verdict calls _deny_domain when domain is known and tier is dnsmasq."""
        session = _make_session(tmp_path)
        state.dns_tier_path(tmp_path).write_text("dnsmasq\n")
        pkt = _PendingPacket(
            dest=TEST_IP1, port=443, proto=6, queued_at=1.0, packet_id=1, domain=DNSMASQ_DOMAIN
        )
        with (
            mock.patch("terok_shield.cli.interactive.add_deny_elements_dual", return_value=""),
            mock.patch.object(session, "_deny_domain") as mock_deny,
        ):
            session._apply_verdict(pkt, accept=False)
        mock_deny.assert_called_once_with(DNSMASQ_DOMAIN)

    def test_accept_skips_domain_when_no_domain(self, tmp_path: Path) -> None:
        """Accept verdict skips dnsmasq calls when domain is empty."""
        session = _make_session(tmp_path)
        state.dns_tier_path(tmp_path).write_text("dnsmasq\n")
        pkt = _PendingPacket(dest=TEST_IP1, port=443, proto=6, queued_at=1.0, packet_id=1)
        with (
            mock.patch("terok_shield.cli.interactive.add_elements_dual", return_value=""),
            mock.patch.object(session, "_allow_domain") as mock_allow,
        ):
            session._apply_verdict(pkt, accept=True)
        mock_allow.assert_not_called()

    def test_accept_skips_domain_when_not_dnsmasq_tier(self, tmp_path: Path) -> None:
        """Accept verdict skips dnsmasq calls when tier is dig."""
        session = _make_session(tmp_path)
        state.dns_tier_path(tmp_path).write_text("dig\n")
        pkt = _PendingPacket(
            dest=TEST_IP1, port=443, proto=6, queued_at=1.0, packet_id=1, domain=DNSMASQ_DOMAIN
        )
        with (
            mock.patch("terok_shield.cli.interactive.add_elements_dual", return_value=""),
            mock.patch.object(session, "_allow_domain") as mock_allow,
        ):
            session._apply_verdict(pkt, accept=True)
        mock_allow.assert_not_called()


# ── _allow_domain / _deny_domain / _reload_dnsmasq ──────


class TestDnsmasqDomainHelpers:
    """Tests for _allow_domain, _deny_domain, and _reload_dnsmasq."""

    def test_allow_domain_delegates_to_dnsmasq(self, tmp_path: Path) -> None:
        """_allow_domain calls dnsmasq.add_domain and _reload_dnsmasq."""
        session = _make_session(tmp_path)
        with (
            mock.patch("terok_shield.core.dnsmasq.add_domain", return_value=True) as mock_add,
            mock.patch.object(session, "_reload_dnsmasq") as mock_reload,
        ):
            session._allow_domain(DNSMASQ_DOMAIN)
        mock_add.assert_called_once_with(tmp_path, DNSMASQ_DOMAIN)
        mock_reload.assert_called_once()

    def test_allow_domain_skips_reload_when_unchanged(self, tmp_path: Path) -> None:
        """_allow_domain does not reload when add_domain returns False (already present)."""
        session = _make_session(tmp_path)
        with (
            mock.patch("terok_shield.core.dnsmasq.add_domain", return_value=False),
            mock.patch.object(session, "_reload_dnsmasq") as mock_reload,
        ):
            session._allow_domain(DNSMASQ_DOMAIN)
        mock_reload.assert_not_called()

    def test_deny_domain_delegates_to_dnsmasq(self, tmp_path: Path) -> None:
        """_deny_domain calls dnsmasq.remove_domain and _reload_dnsmasq."""
        session = _make_session(tmp_path)
        with (
            mock.patch("terok_shield.core.dnsmasq.remove_domain", return_value=True) as mock_rm,
            mock.patch.object(session, "_reload_dnsmasq") as mock_reload,
        ):
            session._deny_domain(DNSMASQ_DOMAIN)
        mock_rm.assert_called_once_with(tmp_path, DNSMASQ_DOMAIN)
        mock_reload.assert_called_once()

    def test_deny_domain_skips_reload_when_unchanged(self, tmp_path: Path) -> None:
        """_deny_domain does not reload when remove_domain returns False."""
        session = _make_session(tmp_path)
        with (
            mock.patch("terok_shield.core.dnsmasq.remove_domain", return_value=False),
            mock.patch.object(session, "_reload_dnsmasq") as mock_reload,
        ):
            session._deny_domain(DNSMASQ_DOMAIN)
        mock_reload.assert_not_called()

    def test_reload_dnsmasq_reads_upstream_and_reloads(self, tmp_path: Path) -> None:
        """_reload_dnsmasq reads upstream DNS and calls dnsmasq.reload."""
        session = _make_session(tmp_path)
        state.upstream_dns_path(tmp_path).write_text("169.254.0.1\n")
        with (
            mock.patch(
                "terok_shield.core.dnsmasq.read_merged_domains", return_value={DNSMASQ_DOMAIN}
            ) as mock_read,
            mock.patch("terok_shield.core.dnsmasq.reload") as mock_reload,
        ):
            session._reload_dnsmasq()
        mock_read.assert_called_once_with(tmp_path)
        mock_reload.assert_called_once_with(tmp_path, "169.254.0.1", {DNSMASQ_DOMAIN})

    def test_reload_dnsmasq_logs_on_missing_upstream(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """_reload_dnsmasq logs a warning when upstream DNS file is missing."""
        session = _make_session(tmp_path)
        session._reload_dnsmasq()
        assert "upstream DNS" in caplog.text

    def test_reload_dnsmasq_logs_on_reload_failure(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """_reload_dnsmasq logs an exception when dnsmasq.reload raises."""
        session = _make_session(tmp_path)
        state.upstream_dns_path(tmp_path).write_text("169.254.0.1\n")
        with (
            mock.patch("terok_shield.core.dnsmasq.read_merged_domains", return_value=set()),
            mock.patch(
                "terok_shield.core.dnsmasq.reload", side_effect=RuntimeError("dnsmasq crashed")
            ),
        ):
            session._reload_dnsmasq()
        assert "dnsmasq reload failed" in caplog.text


# ── Eager domain cache refresh ────────────────────────────


class TestEagerDomainRefresh:
    """Tests for eager DomainCache refresh on unknown IPs in _handle_nflog_event."""

    def test_refreshes_cache_on_unknown_ip(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """_handle_nflog_event refreshes the cache when IP is not in the mapping."""
        session = _make_session(tmp_path)
        # Write a dnsmasq log with the IP→domain entry
        log_path = state.dnsmasq_log_path(tmp_path)
        log_path.write_text(f"reply {DNSMASQ_DOMAIN} is {TEST_IP1}\n")
        event = _make_event(TEST_IP1)
        session._handle_nflog_event(event)
        out = json.loads(capsys.readouterr().out.strip())
        assert out["domain"] == DNSMASQ_DOMAIN

    def test_domain_stays_empty_for_direct_ip(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Domain stays empty when the IP has no DNS entry (direct IP connection)."""
        session = _make_session(tmp_path)
        # No dnsmasq log → cache refresh finds nothing
        event = _make_event(TEST_IP1)
        session._handle_nflog_event(event)
        out = json.loads(capsys.readouterr().out.strip())
        assert out["domain"] == ""

    def test_skips_refresh_when_already_cached(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """_handle_nflog_event does not refresh when the IP is already cached."""
        session = _make_session(tmp_path)
        session._domain_cache._mapping[TEST_IP1] = DNSMASQ_DOMAIN
        with mock.patch.object(session._domain_cache, "refresh") as mock_refresh:
            session._handle_nflog_event(_make_event(TEST_IP1))
        mock_refresh.assert_not_called()
        out = json.loads(capsys.readouterr().out.strip())
        assert out["domain"] == DNSMASQ_DOMAIN

    def test_nsenter_clears_inherited_raw_env(self, tmp_path: Path) -> None:
        """_nsenter_reexec strips inherited _RAW_ENV when raw=False."""
        from terok_shield.cli.interactive import _nsenter_reexec

        with (
            mock.patch.dict("os.environ", {_RAW_ENV: "1"}, clear=False),
            mock.patch("terok_shield.cli.interactive.SubprocessRunner") as mock_runner_cls,
            mock.patch("subprocess.run") as mock_run,
        ):
            mock_runner_cls.return_value.podman_inspect.return_value = "12345"
            _nsenter_reexec(tmp_path, _CONTAINER, raw=False)
        env = mock_run.call_args[1]["env"]
        assert _RAW_ENV not in env

    def test_run_interactive_passes_raw_to_nsenter(self, tmp_path: Path) -> None:
        """run_interactive forwards raw=True to _nsenter_reexec."""

        with mock.patch("terok_shield.cli.interactive._nsenter_reexec") as mock_reexec:
            run_interactive(tmp_path, _CONTAINER, raw=True)
        mock_reexec.assert_called_once_with(tmp_path, _CONTAINER, raw=True)
