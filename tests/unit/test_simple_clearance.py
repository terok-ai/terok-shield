# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the terminal clearance fallback CLI."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from terok_shield.cli import simple_clearance

from ..testnet import TEST_DOMAIN, TEST_IP1, TEST_IP2

_CONTAINER = "c1"


# ── Hub-liveness guard ────────────────────────────────────────────────


class TestDbusHubActive:
    """The guard must reliably detect whether the hub already owns the name."""

    def test_dbus_send_reports_owner_returns_true(self) -> None:
        fake_result = SimpleNamespace(returncode=0, stdout="   boolean true\n", stderr="")
        with mock.patch.object(
            simple_clearance.subprocess, "run", return_value=fake_result
        ) as m_run:
            assert simple_clearance._dbus_hub_active() is True
        cmd = m_run.call_args[0][0]
        assert cmd[0] == "dbus-send"
        assert any(arg.endswith("org.terok.Shield1") for arg in cmd)

    def test_dbus_send_reports_no_owner_returns_false(self) -> None:
        fake_result = SimpleNamespace(returncode=0, stdout="   boolean false\n", stderr="")
        with mock.patch.object(simple_clearance.subprocess, "run", return_value=fake_result):
            assert simple_clearance._dbus_hub_active() is False

    def test_missing_dbus_send_returns_false(self) -> None:
        with mock.patch.object(simple_clearance.subprocess, "run", side_effect=FileNotFoundError):
            assert simple_clearance._dbus_hub_active() is False


# ── Entry-point guard behaviour ───────────────────────────────────────


class TestRunSimpleClearance:
    """``run_simple_clearance`` must refuse when the D-Bus hub is already active."""

    def test_refuses_when_hub_active(self, tmp_path: Path) -> None:
        with mock.patch.object(simple_clearance, "_dbus_hub_active", return_value=True):
            with pytest.raises(SystemExit):
                simple_clearance.run_simple_clearance(tmp_path, _CONTAINER)

    def test_starts_session_when_hub_absent(self, tmp_path: Path) -> None:
        with (
            mock.patch.object(simple_clearance, "_dbus_hub_active", return_value=False),
            mock.patch.object(simple_clearance, "ClearanceSession") as cls,
        ):
            simple_clearance.run_simple_clearance(tmp_path, _CONTAINER)
        cls.assert_called_once_with(state_dir=tmp_path, container=_CONTAINER)
        cls.return_value.run.assert_called_once_with()


# ── Event handling ────────────────────────────────────────────────────


def _session(tmp_path: Path) -> simple_clearance.ClearanceSession:
    """Build a session rooted under *tmp_path* with no reader attached."""
    return simple_clearance.ClearanceSession(state_dir=tmp_path, container=_CONTAINER)


class TestHandleReaderEvent:
    """Reader ``pending`` events enqueue a prompt; other types are ignored."""

    def test_pending_event_is_enqueued_and_prompts(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        session = _session(tmp_path)
        event = {
            "type": "pending",
            "id": f"{_CONTAINER}:1",
            "dest": TEST_IP1,
            "port": 443,
            "domain": TEST_DOMAIN,
        }
        session._handle_reader_event(json.dumps(event))
        assert len(session._queue) == 1
        assert session._queue[0].dest == TEST_IP1
        assert "[BLOCKED]" in capsys.readouterr().out

    def test_unknown_type_is_ignored(self, tmp_path: Path) -> None:
        session = _session(tmp_path)
        session._handle_reader_event('{"type":"container_started","container":"c1"}')
        assert session._queue == []

    def test_invalid_json_is_ignored(self, tmp_path: Path) -> None:
        session = _session(tmp_path)
        session._handle_reader_event("not json")
        assert session._queue == []

    def test_second_pending_is_queued_with_marker(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        session = _session(tmp_path)
        session._handle_reader_event(
            json.dumps(
                {"type": "pending", "id": "c1:1", "dest": TEST_IP1, "port": 80, "domain": ""}
            )
        )
        capsys.readouterr()  # drain first prompt
        session._handle_reader_event(
            json.dumps(
                {"type": "pending", "id": "c1:2", "dest": TEST_IP2, "port": 443, "domain": ""}
            )
        )
        assert len(session._queue) == 2
        assert "queued" in capsys.readouterr().out


# ── Operator input ────────────────────────────────────────────────────


class TestHandleOperatorInput:
    """Operator keystrokes apply to the head of the queue via terok-shield allow/deny."""

    def _enqueue(self, session: simple_clearance.ClearanceSession) -> None:
        session._queue.append(
            simple_clearance._Pending(
                request_id="c1:1", dest=TEST_IP1, port=443, domain=TEST_DOMAIN
            )
        )

    def test_allow_invokes_shield_allow(self, tmp_path: Path) -> None:
        session = _session(tmp_path)
        self._enqueue(session)
        fake_result = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        with mock.patch.object(
            simple_clearance.subprocess, "run", return_value=fake_result
        ) as m_run:
            session._handle_operator_input("a")
        cmd = m_run.call_args[0][0]
        assert "allow" in cmd
        assert _CONTAINER in cmd
        assert TEST_IP1 in cmd
        assert session._queue == []

    def test_deny_invokes_shield_deny(self, tmp_path: Path) -> None:
        session = _session(tmp_path)
        self._enqueue(session)
        fake_result = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        with mock.patch.object(
            simple_clearance.subprocess, "run", return_value=fake_result
        ) as m_run:
            session._handle_operator_input("deny")
        cmd = m_run.call_args[0][0]
        assert "deny" in cmd

    def test_unknown_input_leaves_queue_intact(self, tmp_path: Path) -> None:
        session = _session(tmp_path)
        self._enqueue(session)
        with mock.patch.object(simple_clearance.subprocess, "run") as m_run:
            session._handle_operator_input("xyz")
        m_run.assert_not_called()
        assert len(session._queue) == 1

    def test_failed_verdict_keeps_entry_for_retry(self, tmp_path: Path) -> None:
        session = _session(tmp_path)
        self._enqueue(session)
        fake_result = SimpleNamespace(returncode=1, stdout=b"", stderr=b"")
        with mock.patch.object(simple_clearance.subprocess, "run", return_value=fake_result):
            session._handle_operator_input("a")
        assert len(session._queue) == 1


# ── Buffer helpers ────────────────────────────────────────────────────


class TestBufferHelpers:
    """``_drain_lines`` + ``_tail_partial`` together implement line-buffered reads."""

    def test_complete_lines_are_drained(self) -> None:
        assert simple_clearance._drain_lines("a\nb\nc\n") == ["a", "b", "c"]

    def test_partial_trailing_segment_is_kept(self) -> None:
        assert simple_clearance._drain_lines("a\nb\npartial") == ["a", "b"]
        assert simple_clearance._tail_partial("a\nb\npartial") == "partial"

    def test_no_newline_drains_nothing(self) -> None:
        assert simple_clearance._drain_lines("partial") == []
        assert simple_clearance._tail_partial("partial") == "partial"


# ── Drain helpers (reader / stdin) ────────────────────────────────────


def _make_session() -> simple_clearance.ClearanceSession:
    """Test fixture: a bare ClearanceSession with no real subprocess."""
    return simple_clearance.ClearanceSession(state_dir=Path("/tmp/sd"), container="c1")


class TestDrainReader:
    """``_drain_reader`` ticks the reader pipe, handling EOF + not-readable."""

    def test_not_readable_returns_buf_unchanged(self) -> None:
        session = _make_session()
        buf, eof = session._drain_reader(reader_fd=5, buf="stale", readable=[])
        assert buf == "stale"
        assert eof is False

    def test_readable_dispatches_complete_lines(self) -> None:
        session = _make_session()
        with mock.patch.object(simple_clearance, "_read_into_buffer", return_value=("x\n", False)):
            session._handle_reader_event = mock.MagicMock()  # type: ignore[method-assign]
            buf, eof = session._drain_reader(reader_fd=5, buf="", readable=[5])
        session._handle_reader_event.assert_called_once_with("x")
        assert buf == ""
        assert eof is False

    def test_eof_is_propagated(self) -> None:
        session = _make_session()
        with mock.patch.object(simple_clearance, "_read_into_buffer", return_value=("", True)):
            _, eof = session._drain_reader(reader_fd=5, buf="", readable=[5])
        assert eof is True


class TestDrainStdin:
    """``_drain_stdin`` ticks the operator prompt pipe, same contract as reader."""

    def test_not_readable_returns_buf_unchanged(self) -> None:
        session = _make_session()
        buf, eof = session._drain_stdin(stdin_fd=0, buf="  ", readable=[])
        assert buf == "  "
        assert eof is False

    def test_dispatches_stripped_input(self) -> None:
        session = _make_session()
        with mock.patch.object(simple_clearance, "_read_into_buffer", return_value=("a\n", False)):
            session._handle_operator_input = mock.MagicMock()  # type: ignore[method-assign]
            session._drain_stdin(stdin_fd=0, buf="", readable=[0])
        session._handle_operator_input.assert_called_once_with("a")


# ── Reader spawn + shutdown ───────────────────────────────────────────


class TestSpawnReader:
    """Missing reader script exits with SystemExit; happy path returns Popen."""

    def test_missing_reader_script_exits(self) -> None:
        session = _make_session()
        with mock.patch.object(Path, "exists", return_value=False):
            with pytest.raises(SystemExit, match="1"):
                session._spawn_reader()

    def test_spawn_passes_expected_argv(self) -> None:
        session = simple_clearance.ClearanceSession(state_dir=Path("/sd"), container="cname")
        fake_proc = mock.MagicMock()
        with (
            mock.patch.object(Path, "exists", return_value=True),
            mock.patch.object(
                simple_clearance.subprocess, "Popen", return_value=fake_proc
            ) as popen,
        ):
            result = session._spawn_reader()
        assert result is fake_proc
        argv = popen.call_args[0][0]
        assert argv[-4:] == [str(simple_clearance._READER_SCRIPT), "/sd", "cname", "--emit=json"]


class TestShutdownReader:
    """``_shutdown_reader`` escalates SIGTERM → SIGKILL when the child lingers."""

    def test_already_exited_process_no_signals(self) -> None:
        session = _make_session()
        reader = mock.MagicMock()
        reader.poll.return_value = 0
        session._shutdown_reader(reader)
        reader.terminate.assert_not_called()
        reader.kill.assert_not_called()

    def test_running_process_gets_sigterm_then_sigkill(self) -> None:
        session = _make_session()
        reader = mock.MagicMock()
        reader.poll.side_effect = [None, None, None]
        reader.wait.side_effect = subprocess.TimeoutExpired(cmd="", timeout=2)
        session._shutdown_reader(reader)
        reader.terminate.assert_called_once()
        reader.kill.assert_called_once()

    def test_terminated_after_wait_no_sigkill(self) -> None:
        session = _make_session()
        reader = mock.MagicMock()
        reader.poll.side_effect = [None, 0]
        session._shutdown_reader(reader)
        reader.terminate.assert_called_once()
        reader.kill.assert_not_called()


# ── Signal handling ──────────────────────────────────────────────────


class TestSignalHandling:
    """Stop handler sets the flag; install wires SIGINT + SIGTERM to it."""

    def test_on_stop_signal_sets_flag(self) -> None:
        session = _make_session()
        assert session._stop_requested is False
        session._on_stop_signal(2, None)
        assert session._stop_requested is True

    def test_install_signal_handlers_registers_both(self) -> None:
        session = _make_session()
        installed: list[int] = []
        with mock.patch.object(
            simple_clearance.signal, "signal", side_effect=lambda sig, _h: installed.append(sig)
        ):
            session._install_signal_handlers()
        assert simple_clearance.signal.SIGINT in installed
        assert simple_clearance.signal.SIGTERM in installed


# ── Read-into-buffer + nonblocking ───────────────────────────────────


class TestReadIntoBuffer:
    """``_read_into_buffer`` is the one place we touch raw fds."""

    def test_eof_returns_original_buffer_and_eof_true(self) -> None:
        with mock.patch.object(simple_clearance.os, "read", return_value=b""):
            buf, eof = simple_clearance._read_into_buffer(fd=3, buf="head")
        assert (buf, eof) == ("head", True)

    def test_chunk_is_appended(self) -> None:
        with mock.patch.object(simple_clearance.os, "read", return_value=b"x\n"):
            buf, eof = simple_clearance._read_into_buffer(fd=3, buf="head")
        assert (buf, eof) == ("headx\n", False)

    def test_oserror_returns_buf_unchanged(self) -> None:
        with mock.patch.object(simple_clearance.os, "read", side_effect=OSError):
            buf, eof = simple_clearance._read_into_buffer(fd=3, buf="head")
        assert (buf, eof) == ("head", False)
