# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the interactive NFQUEUE verdict loop."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from unittest import mock

import pytest

from terok_shield import state
from terok_shield.interactive import (
    InteractiveSession,
    _append_unique,
    _handle_signal,
    _PendingPacket,
    run_interactive,
)
from terok_shield.nfqueue import QueuedPacket

from ..testnet import (
    DNSMASQ_DOMAIN,
    DNSMASQ_DOMAIN2,
    FRESH_DOMAIN,
    KEPT_DOMAIN,
    STALE_DOMAIN,
    TEST_IP1,
    TEST_IP2,
)


def _make_session(tmp_path: Path, **kwargs) -> InteractiveSession:
    """Create an InteractiveSession with a mock runner."""
    state.ensure_state_dirs(tmp_path)
    return InteractiveSession(
        runner=mock.MagicMock(),
        state_dir=tmp_path,
        container="test-ctr",
        **kwargs,
    )


def _make_pkt(packet_id: int = 1, dest: str = TEST_IP1, port: int = 443) -> QueuedPacket:
    """Create a test QueuedPacket."""
    return QueuedPacket(packet_id=packet_id, dest=dest, port=port, proto=6)


# ── _handle_signal ────────────────────────────────────


class TestHandleSignal:
    """Signal handler sets the stop flag."""

    def test_sets_running_false(self) -> None:
        """_handle_signal sets _running to False."""
        import terok_shield.interactive as mod

        mod._running = True
        _handle_signal(2, None)
        assert mod._running is False


# ── _append_unique ─────────────────────────────────────


class TestAppendUnique:
    """File append helper deduplicates entries."""

    def test_appends_new_entry(self, tmp_path: Path) -> None:
        """New value is appended."""
        p = tmp_path / "test.txt"
        _append_unique(p, "a")
        assert p.read_text() == "a\n"

    def test_deduplicates(self, tmp_path: Path) -> None:
        """Duplicate value is not appended twice."""
        p = tmp_path / "test.txt"
        _append_unique(p, "a")
        _append_unique(p, "a")
        assert p.read_text() == "a\n"

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        """Parent directories are created if missing."""
        p = tmp_path / "sub" / "dir" / "test.txt"
        _append_unique(p, "x")
        assert p.read_text() == "x\n"


# ── _PendingPacket ─────────────────────────────────────


class TestPendingPacket:
    """PendingPacket dataclass."""

    def test_fields(self) -> None:
        """Stores packet, queued_at, domain."""
        pkt = _make_pkt()
        pp = _PendingPacket(packet=pkt, queued_at=1.0, domain=DNSMASQ_DOMAIN)
        assert pp.packet is pkt
        assert pp.queued_at == 1.0
        assert pp.domain == DNSMASQ_DOMAIN

    def test_default_domain(self) -> None:
        """Domain defaults to empty string."""
        pp = _PendingPacket(packet=_make_pkt(), queued_at=0.0)
        assert pp.domain == ""


# ── InteractiveSession._handle_queued ──────────────────


class TestHandleQueued:
    """_handle_queued emits pending events and tracks packets."""

    def test_emits_pending_event(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """Queued packet produces a JSON pending event on stdout."""
        session = _make_session(tmp_path)
        pkt = _make_pkt(packet_id=42)
        session._handle_queued(pkt)

        out = capsys.readouterr().out.strip()
        event = json.loads(out)
        assert event["type"] == "pending"
        assert event["id"] == 42
        assert event["dest"] == TEST_IP1

    def test_tracks_in_pending(self, tmp_path: Path) -> None:
        """Queued packet is added to _pending dict."""
        session = _make_session(tmp_path)
        pkt = _make_pkt(packet_id=7)
        session._handle_queued(pkt)
        assert 7 in session._pending

    def test_includes_domain_when_cached(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """Domain is included when IP is in the domain cache."""
        session = _make_session(tmp_path)
        session._ip_to_domain[TEST_IP1] = DNSMASQ_DOMAIN
        session._handle_queued(_make_pkt())

        event = json.loads(capsys.readouterr().out.strip())
        assert event["domain"] == DNSMASQ_DOMAIN


# ── InteractiveSession._process_command ────────────────


class TestProcessCommand:
    """_process_command handles verdict JSON commands."""

    def test_accept_verdict(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """Accept verdict issues NF_ACCEPT and emits verdict_applied."""
        session = _make_session(tmp_path)
        handler = mock.MagicMock()
        pkt = _make_pkt(packet_id=10)
        session._pending[10] = _PendingPacket(packet=pkt, queued_at=time.monotonic())

        session._process_command(
            handler, json.dumps({"type": "verdict", "id": 10, "action": "accept"})
        )

        handler.verdict.assert_called_once_with(10, accept=True)
        event = json.loads(capsys.readouterr().out.strip())
        assert event["type"] == "verdict_applied"
        assert event["action"] == "accept"
        # Check file persistence
        assert TEST_IP1 in state.live_allowed_path(tmp_path).read_text()

    def test_deny_verdict(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """Deny verdict issues NF_DROP and persists to deny.list."""
        session = _make_session(tmp_path)
        handler = mock.MagicMock()
        pkt = _make_pkt(packet_id=20)
        session._pending[20] = _PendingPacket(packet=pkt, queued_at=time.monotonic())

        session._process_command(
            handler, json.dumps({"type": "verdict", "id": 20, "action": "deny"})
        )

        handler.verdict.assert_called_once_with(20, accept=False)
        event = json.loads(capsys.readouterr().out.strip())
        assert event["type"] == "verdict_applied"
        assert TEST_IP1 in state.deny_path(tmp_path).read_text()

    def test_invalid_json_ignored(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Invalid JSON is logged and ignored."""
        import logging

        session = _make_session(tmp_path)
        handler = mock.MagicMock()
        with caplog.at_level(logging.WARNING):
            session._process_command(handler, "not json")
        handler.verdict.assert_not_called()
        assert "invalid JSON" in caplog.text

    def test_wrong_type_ignored(self, tmp_path: Path) -> None:
        """Non-verdict type is silently ignored."""
        session = _make_session(tmp_path)
        handler = mock.MagicMock()
        session._process_command(handler, json.dumps({"type": "other", "id": 1}))
        handler.verdict.assert_not_called()

    def test_bool_id_rejected(self, tmp_path: Path) -> None:
        """Boolean packet_id is rejected (type guard)."""
        session = _make_session(tmp_path)
        handler = mock.MagicMock()
        session._process_command(
            handler, json.dumps({"type": "verdict", "id": True, "action": "accept"})
        )
        handler.verdict.assert_not_called()

    def test_non_string_action_rejected(self, tmp_path: Path) -> None:
        """Non-string action is rejected (type guard)."""
        session = _make_session(tmp_path)
        handler = mock.MagicMock()
        session._process_command(handler, json.dumps({"type": "verdict", "id": 1, "action": 42}))
        handler.verdict.assert_not_called()

    def test_unknown_packet_id_ignored(self, tmp_path: Path) -> None:
        """Verdict for unknown/timed-out packet_id is silently ignored."""
        session = _make_session(tmp_path)
        handler = mock.MagicMock()
        session._process_command(
            handler, json.dumps({"type": "verdict", "id": 999, "action": "accept"})
        )
        handler.verdict.assert_not_called()

    def test_nft_failure_emits_verdict_failed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """Failed nft update emits verdict_failed instead of verdict_applied."""
        session = _make_session(tmp_path)
        session._runner.nft_via_nsenter.side_effect = RuntimeError("nft failed")
        handler = mock.MagicMock()
        pkt = _make_pkt(packet_id=30)
        session._pending[30] = _PendingPacket(packet=pkt, queued_at=time.monotonic())

        session._process_command(
            handler, json.dumps({"type": "verdict", "id": 30, "action": "accept"})
        )

        event = json.loads(capsys.readouterr().out.strip())
        assert event["type"] == "verdict_failed"


# ── InteractiveSession._sweep_timeouts ─────────────────


class TestSweepTimeouts:
    """Timeout sweep drops expired packets."""

    def test_expired_packet_dropped(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """Packet past timeout is dropped with verdict_timeout event."""
        session = _make_session(tmp_path, timeout=1)
        handler = mock.MagicMock()
        pkt = _make_pkt(packet_id=50)
        session._pending[50] = _PendingPacket(packet=pkt, queued_at=time.monotonic() - 2.0)

        session._sweep_timeouts(handler)

        handler.verdict.assert_called_once_with(50, accept=False)
        assert 50 not in session._pending
        event = json.loads(capsys.readouterr().out.strip())
        assert event["type"] == "verdict_timeout"

    def test_fresh_packet_not_dropped(self, tmp_path: Path) -> None:
        """Packet within timeout is not dropped."""
        session = _make_session(tmp_path, timeout=60)
        handler = mock.MagicMock()
        pkt = _make_pkt(packet_id=51)
        session._pending[51] = _PendingPacket(packet=pkt, queued_at=time.monotonic())

        session._sweep_timeouts(handler)

        handler.verdict.assert_not_called()
        assert 51 in session._pending


# ── InteractiveSession._drain_pending ──────────────────


class TestDrainPending:
    """Drain drops all remaining packets on shutdown."""

    def test_drains_all(self, tmp_path: Path) -> None:
        """All pending packets are rejected on drain."""
        session = _make_session(tmp_path)
        handler = mock.MagicMock()
        for i in range(3):
            session._pending[i] = _PendingPacket(
                packet=_make_pkt(packet_id=i), queued_at=time.monotonic()
            )

        session._drain_pending(handler)

        assert handler.verdict.call_count == 3
        assert len(session._pending) == 0


# ── InteractiveSession._refresh_domain_cache ───────────


class TestRefreshDomainCache:
    """Domain cache refresh from dnsmasq log."""

    def test_parses_reply_lines(self, tmp_path: Path) -> None:
        """Reply lines in dnsmasq log populate the IP→domain cache."""
        state.ensure_state_dirs(tmp_path)
        log = state.dnsmasq_log_path(tmp_path)
        log.write_text(
            f"reply {DNSMASQ_DOMAIN} is {TEST_IP1}\nreply {DNSMASQ_DOMAIN2} is {TEST_IP2}\n"
        )

        session = _make_session(tmp_path)
        session._refresh_domain_cache()

        assert session._ip_to_domain[TEST_IP1] == DNSMASQ_DOMAIN
        assert session._ip_to_domain[TEST_IP2] == DNSMASQ_DOMAIN2

    def test_rebuilds_fresh_on_each_call(self, tmp_path: Path) -> None:
        """Cache is rebuilt from scratch, dropping stale entries after log rotation."""
        state.ensure_state_dirs(tmp_path)
        log = state.dnsmasq_log_path(tmp_path)
        log.write_text(f"reply {STALE_DOMAIN} is {TEST_IP1}\n")

        session = _make_session(tmp_path)
        session._refresh_domain_cache()
        assert TEST_IP1 in session._ip_to_domain

        # Simulate log rotation
        log.write_text(f"reply {FRESH_DOMAIN} is {TEST_IP2}\n")
        session._refresh_domain_cache()
        assert TEST_IP1 not in session._ip_to_domain
        assert session._ip_to_domain[TEST_IP2] == FRESH_DOMAIN

    def test_missing_log_no_error(self, tmp_path: Path) -> None:
        """Missing log file doesn't raise."""
        session = _make_session(tmp_path)
        session._refresh_domain_cache()  # should not raise
        assert session._ip_to_domain == {}

    def test_oserror_preserves_previous_cache(self, tmp_path: Path) -> None:
        """OSError during read keeps the previous cache intact."""
        state.ensure_state_dirs(tmp_path)
        log = state.dnsmasq_log_path(tmp_path)
        log.write_text(f"reply {KEPT_DOMAIN} is {TEST_IP1}\n")

        session = _make_session(tmp_path)
        session._refresh_domain_cache()
        assert session._ip_to_domain[TEST_IP1] == KEPT_DOMAIN

        # Simulate OSError on next read (e.g. permission denied mid-rotation)
        with mock.patch.object(type(log), "read_text", side_effect=OSError("perm")):
            session._refresh_domain_cache()
        assert session._ip_to_domain[TEST_IP1] == KEPT_DOMAIN


# ── InteractiveSession._apply_verdict ──────────────────


class TestApplyVerdict:
    """Verdict persistence logic."""

    def test_accept_persists_to_live_allowed(self, tmp_path: Path) -> None:
        """Accept writes IP to live.allowed."""
        session = _make_session(tmp_path)
        pkt = _make_pkt()
        pending = _PendingPacket(packet=pkt, queued_at=time.monotonic())

        ok = session._apply_verdict(pending, accept=True)

        assert ok is True
        assert TEST_IP1 in state.live_allowed_path(tmp_path).read_text()

    def test_deny_persists_to_deny_list(self, tmp_path: Path) -> None:
        """Deny writes IP to deny.list."""
        session = _make_session(tmp_path)
        pkt = _make_pkt()
        pending = _PendingPacket(packet=pkt, queued_at=time.monotonic())

        ok = session._apply_verdict(pending, accept=False)

        assert ok is True
        assert TEST_IP1 in state.deny_path(tmp_path).read_text()

    def test_nft_failure_returns_false(self, tmp_path: Path) -> None:
        """Failed nft command returns False."""
        session = _make_session(tmp_path)
        session._runner.nft_via_nsenter.side_effect = RuntimeError("fail")
        pkt = _make_pkt()
        pending = _PendingPacket(packet=pkt, queued_at=time.monotonic())

        ok = session._apply_verdict(pending, accept=True)
        assert ok is False


# ── run_interactive entry point ────────────────────────


class TestRunInteractive:
    """run_interactive validates state before starting."""

    def test_exits_if_not_interactive(self, tmp_path: Path) -> None:
        """Exits with code 1 if interactive flag file is missing."""
        state.ensure_state_dirs(tmp_path)
        with pytest.raises(SystemExit, match="1"):
            run_interactive(tmp_path, "ctr")

    def test_starts_if_interactive_enabled(self, tmp_path: Path) -> None:
        """Creates session when interactive flag is present (NFQUEUE bind fails → exit 1)."""
        state.ensure_state_dirs(tmp_path)
        state.interactive_path(tmp_path).write_text("1\n")

        with (
            mock.patch("terok_shield.interactive.SubprocessRunner"),
            mock.patch("terok_shield.interactive.NfqueueHandler.create", return_value=None),
        ):
            with pytest.raises(SystemExit, match="1"):
                run_interactive(tmp_path, "ctr")


# ── InteractiveSession._loop / select helpers ────────


class TestLoopHelpers:
    """Cover the small select-loop helper methods."""

    def test_select_readable(self, tmp_path: Path) -> None:
        """_select_readable returns fd set from select() results."""
        session = _make_session(tmp_path)
        handler = mock.MagicMock()
        handler.fileno.return_value = 5
        with mock.patch("terok_shield.interactive.select") as sel:
            sel.select.return_value = ([handler, 3], [], [])
            result = session._select_readable(handler, 3)
        assert result == {5, 3}

    def test_poll_nfqueue_triggers_handle(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """_poll_nfqueue calls _handle_queued when handler fd is ready."""
        session = _make_session(tmp_path)
        handler = mock.MagicMock()
        handler.fileno.return_value = 5
        handler.poll.return_value = [_make_pkt(packet_id=88)]
        session._poll_nfqueue(handler, {5})
        assert 88 in session._pending

    def test_poll_nfqueue_noop_when_not_ready(self, tmp_path: Path) -> None:
        """_poll_nfqueue does nothing when handler fd not in ready set."""
        session = _make_session(tmp_path)
        handler = mock.MagicMock()
        handler.fileno.return_value = 5
        session._poll_nfqueue(handler, {3})
        handler.poll.assert_not_called()

    def test_poll_stdin_returns_buf_when_not_ready(self, tmp_path: Path) -> None:
        """_poll_stdin returns buffer unchanged when stdin not in ready set."""
        session = _make_session(tmp_path)
        with mock.patch("sys.stdin") as stdin:
            stdin.fileno.return_value = 0
            result = session._poll_stdin(mock.MagicMock(), "partial", {5})
        assert result == "partial"

    def test_maybe_refresh_domains_triggers_refresh(self, tmp_path: Path) -> None:
        """_maybe_refresh_domains calls refresh when interval elapsed."""
        session = _make_session(tmp_path)
        session._last_domain_refresh = 0.0  # far in the past
        with mock.patch.object(session, "_refresh_domain_cache") as refresh:
            session._maybe_refresh_domains()
        refresh.assert_called_once()

    def test_maybe_refresh_domains_skips_when_fresh(self, tmp_path: Path) -> None:
        """_maybe_refresh_domains does nothing when recently refreshed."""
        session = _make_session(tmp_path)
        session._last_domain_refresh = time.monotonic()
        with mock.patch.object(session, "_refresh_domain_cache") as refresh:
            session._maybe_refresh_domains()
        refresh.assert_not_called()


# ── InteractiveSession._read_stdin ────────────────────


class TestReadStdin:
    """Cover the _read_stdin I/O method."""

    def _patch_stdin_fd(self) -> mock._patch:
        """Return a context manager that stubs sys.stdin.fileno → 0."""
        return mock.patch("sys.stdin", **{"fileno.return_value": 0})

    def test_returns_none_on_eof(self, tmp_path: Path) -> None:
        """Returns None when os.read returns empty bytes (EOF)."""
        session = _make_session(tmp_path)
        handler = mock.MagicMock()
        with self._patch_stdin_fd(), mock.patch("os.read", return_value=b""):
            result = session._read_stdin(handler, "")
        assert result is None

    def test_returns_buf_on_oserror(self, tmp_path: Path) -> None:
        """Returns existing buffer on OSError."""
        session = _make_session(tmp_path)
        handler = mock.MagicMock()
        with self._patch_stdin_fd(), mock.patch("os.read", side_effect=OSError):
            result = session._read_stdin(handler, "leftover")
        assert result == "leftover"

    def test_processes_complete_line(self, tmp_path: Path) -> None:
        """Complete JSON line is processed, remainder returned as buffer."""
        session = _make_session(tmp_path)
        handler = mock.MagicMock()
        line = json.dumps({"type": "verdict", "id": 77, "action": "accept"})
        pkt = _make_pkt(packet_id=77)
        session._pending[77] = _PendingPacket(packet=pkt, queued_at=time.monotonic())

        with (
            self._patch_stdin_fd(),
            mock.patch("os.read", return_value=f"{line}\nremainder".encode()),
        ):
            result = session._read_stdin(handler, "")
        assert result == "remainder"
        handler.verdict.assert_called_once()

    def test_buffers_incomplete_line(self, tmp_path: Path) -> None:
        """Incomplete line is buffered for next read."""
        session = _make_session(tmp_path)
        handler = mock.MagicMock()
        with self._patch_stdin_fd(), mock.patch("os.read", return_value=b"partial"):
            result = session._read_stdin(handler, "")
        assert result == "partial"
        handler.verdict.assert_not_called()


# ── InteractiveSession._loop ─────────────────────────


class TestLoop:
    """Cover the main _loop method."""

    def test_loop_exits_on_stdin_eof(self, tmp_path: Path) -> None:
        """_loop exits when _poll_stdin returns None (EOF)."""
        session = _make_session(tmp_path)
        handler = mock.MagicMock()
        handler.fileno.return_value = 5

        with mock.patch("terok_shield.interactive.select") as sel:
            sel.select.return_value = ([0], [], [])
            with mock.patch("os.read", return_value=b""):
                with mock.patch("sys.stdin") as stdin:
                    stdin.fileno.return_value = 0
                    import terok_shield.interactive as mod

                    mod._running = True
                    session._loop(handler, 0)
        # If we get here, _loop exited (didn't hang)

    def test_loop_exits_on_running_false(self, tmp_path: Path) -> None:
        """_loop exits when _running flag is cleared."""
        session = _make_session(tmp_path)
        handler = mock.MagicMock()
        handler.fileno.return_value = 5

        import terok_shield.interactive as mod

        mod._running = False
        session._loop(handler, 0)


# ── InteractiveSession.run (success path) ────────────


class TestRunMethod:
    """Cover the run() orchestration method."""

    def test_run_creates_handler_and_loops(self, tmp_path: Path) -> None:
        """run() creates handler, sets up signals, calls _loop, then drains."""
        session = _make_session(tmp_path)
        mock_handler = mock.MagicMock()
        mock_handler.fileno.return_value = 5

        import terok_shield.interactive as mod

        mod._running = True

        with (
            mock.patch.object(type(session), "_loop", side_effect=lambda h, fd: None),
            mock.patch("terok_shield.interactive.NfqueueHandler.create", return_value=mock_handler),
            mock.patch("terok_shield.interactive._set_nonblocking"),
            mock.patch("sys.stdin", **{"fileno.return_value": 0}),
        ):
            session.run()

        mock_handler.close.assert_called_once()


# ── _set_nonblocking ─────────────────────────────────


class TestSetNonblocking:
    """Cover the _set_nonblocking helper."""

    def test_sets_o_nonblock_flag(self) -> None:
        """_set_nonblocking sets O_NONBLOCK on the fd via a real pipe."""
        import fcntl

        from terok_shield.interactive import _set_nonblocking

        r, w = os.pipe()
        try:
            _set_nonblocking(r)
            flags = fcntl.fcntl(r, fcntl.F_GETFL)
            assert flags & os.O_NONBLOCK
        finally:
            os.close(r)
            os.close(w)
