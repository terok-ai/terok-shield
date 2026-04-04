# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the D-Bus event bridge (lib/dbus_bridge.py)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest import mock

import pytest

dbus_fast = pytest.importorskip("dbus_fast", reason="dbus-fast not installed")
pytest.importorskip("terok_dbus", reason="terok-dbus not installed")

from terok_shield.core.state import container_id_path
from terok_shield.lib.dbus_bridge import (
    BUS_NAME_PREFIX,
    ShieldBridge,
    _ShieldInterface,
    bus_name_for_container,
)

from ..testnet import TEST_DOMAIN, TEST_IP1

# ── Helpers ────────────────────────────────────────────────


def _bridge(tmp_path: Path, container: str = "myapp") -> ShieldBridge:
    """Create a ShieldBridge with a stubbed container ID and mock bus."""
    container_id_path(tmp_path).write_text("aabbccddee12\n")
    return ShieldBridge(state_dir=tmp_path, container=container, bus=mock.MagicMock())


def _mock_process(
    *,
    stdout_lines: list[bytes] | None = None,
    returncode: int | None = None,
) -> mock.MagicMock:
    """Build a mock asyncio.subprocess.Process with controllable stdout."""
    proc = mock.MagicMock()
    proc.returncode = returncode
    proc.pid = 42
    proc.terminate = mock.MagicMock()
    proc.kill = mock.MagicMock()
    proc.wait = mock.AsyncMock(return_value=0)

    proc.stdin = mock.MagicMock()
    proc.stdin.write = mock.MagicMock()
    proc.stdin.drain = mock.AsyncMock()

    if stdout_lines is not None:

        async def _iter():
            for line in stdout_lines:
                yield line

        proc.stdout = _iter()
    else:
        proc.stdout = mock.MagicMock()
    return proc


# ── Bus name construction ──────────────────────────────────


def test_bus_name_prefix_is_well_formed() -> None:
    """Bus name prefix follows MPRIS-style convention."""
    assert BUS_NAME_PREFIX == "org.terok.Shield1.Container_"


@pytest.mark.parametrize(
    ("short_id", "expected"),
    [
        pytest.param("abc123def456", "org.terok.Shield1.Container_abc123def456", id="hex-id"),
        pytest.param("0deadbeef12", "org.terok.Shield1.Container_0deadbeef12", id="starts-digit"),
    ],
)
def test_bus_name_for_container(short_id: str, expected: str) -> None:
    """bus_name_for_container() prefixes the short ID with Container_."""
    assert bus_name_for_container(short_id) == expected


# ── Container ID reading ───────────────────────────────────


def test_container_id_read_from_state_dir(tmp_path: Path) -> None:
    """ShieldBridge.container_id reads from state_dir/container.id."""
    container_id_path(tmp_path).write_text("abc123def456\n")
    bus = mock.MagicMock()
    bridge = ShieldBridge(state_dir=tmp_path, container="test-ctr", bus=bus)
    assert bridge.container_id == "abc123def456"


def test_container_id_cached_after_first_read(tmp_path: Path) -> None:
    """container_id is cached — the file is only read once."""
    container_id_path(tmp_path).write_text("abc123def456\n")
    bridge = _bridge(tmp_path)
    _ = bridge.container_id
    container_id_path(tmp_path).write_text("changed\n")
    assert bridge.container_id == "aabbccddee12"  # still cached from _bridge helper


def test_container_id_missing_raises(tmp_path: Path) -> None:
    """ShieldBridge.container_id raises FileNotFoundError if not persisted."""
    bus = mock.MagicMock()
    bridge = ShieldBridge(state_dir=tmp_path, container="test-ctr", bus=bus)
    with pytest.raises(FileNotFoundError, match="Container ID not found"):
        _ = bridge.container_id


def test_bus_name_property(tmp_path: Path) -> None:
    """ShieldBridge.bus_name derives from the persisted container ID."""
    container_id_path(tmp_path).write_text("0deadbeef12\n")
    bus = mock.MagicMock()
    bridge = ShieldBridge(state_dir=tmp_path, container="test-ctr", bus=bus)
    assert bridge.bus_name == "org.terok.Shield1.Container_0deadbeef12"


# ── submit_verdict ─────────────────────────────────────────


def test_submit_verdict_writes_stdin(tmp_path: Path) -> None:
    """submit_verdict() writes JSON to subprocess stdin."""
    bridge = _bridge(tmp_path)
    bridge._process = _mock_process()

    ok = asyncio.run(bridge.submit_verdict("myapp:42", "accept"))

    assert ok is True
    written = bridge._process.stdin.write.call_args[0][0]
    parsed = json.loads(written.decode())
    assert parsed == {"type": "verdict", "id": 42, "action": "accept"}


def test_submit_verdict_invalid_request_id_no_colon(tmp_path: Path) -> None:
    """submit_verdict() returns False when request_id has no colon."""
    bridge = _bridge(tmp_path)
    bridge._process = _mock_process()
    assert asyncio.run(bridge.submit_verdict("no-colon", "accept")) is False


def test_submit_verdict_invalid_request_id_non_integer(tmp_path: Path) -> None:
    """submit_verdict() returns False when packet ID is not an integer."""
    bridge = _bridge(tmp_path)
    bridge._process = _mock_process()
    assert asyncio.run(bridge.submit_verdict("myapp:notanumber", "deny")) is False


def test_submit_verdict_no_process(tmp_path: Path) -> None:
    """submit_verdict() returns False when subprocess is not running."""
    bridge = _bridge(tmp_path)
    assert asyncio.run(bridge.submit_verdict("myapp:1", "accept")) is False


def test_submit_verdict_wrong_container(tmp_path: Path) -> None:
    """submit_verdict() returns False when request_id targets a different container."""
    bridge = _bridge(tmp_path)
    bridge._process = _mock_process()
    assert asyncio.run(bridge.submit_verdict("other:1", "accept")) is False


def test_submit_verdict_invalid_action(tmp_path: Path) -> None:
    """submit_verdict() returns False for actions other than accept/deny."""
    bridge = _bridge(tmp_path)
    bridge._process = _mock_process()
    assert asyncio.run(bridge.submit_verdict("myapp:1", "maybe")) is False


def test_submit_verdict_empty_container_prefix(tmp_path: Path) -> None:
    """submit_verdict() returns False when request_id starts with a colon."""
    bridge = _bridge(tmp_path)
    bridge._process = _mock_process()
    assert asyncio.run(bridge.submit_verdict(":1", "accept")) is False


def test_submit_verdict_broken_pipe(tmp_path: Path) -> None:
    """submit_verdict() returns False on BrokenPipeError."""
    bridge = _bridge(tmp_path)
    proc = _mock_process()
    proc.stdin.write.side_effect = BrokenPipeError
    bridge._process = proc

    assert asyncio.run(bridge.submit_verdict("myapp:1", "accept")) is False


def test_submit_verdict_connection_reset(tmp_path: Path) -> None:
    """submit_verdict() returns False on ConnectionResetError."""
    bridge = _bridge(tmp_path)
    proc = _mock_process()
    proc.stdin.drain = mock.AsyncMock(side_effect=ConnectionResetError)
    bridge._process = proc

    assert asyncio.run(bridge.submit_verdict("myapp:1", "deny")) is False


# ── Event dispatch ─────────────────────────────────────────


def test_dispatch_pending_event(tmp_path: Path) -> None:
    """_dispatch_event() emits connection_blocked signal for 'pending' events."""
    bridge = _bridge(tmp_path)

    with mock.patch.object(bridge._interface, "connection_blocked") as sig:
        bridge._dispatch_event(
            {
                "type": "pending",
                "id": 7,
                "dest": TEST_IP1,
                "port": 443,
                "proto": 6,
                "domain": TEST_DOMAIN,
            }
        )
        sig.assert_called_once_with("myapp", TEST_IP1, 443, 6, TEST_DOMAIN, "myapp:7")


def test_dispatch_verdict_applied_event(tmp_path: Path) -> None:
    """_dispatch_event() emits verdict_applied signal for 'verdict_applied' events."""
    bridge = _bridge(tmp_path)

    with mock.patch.object(bridge._interface, "verdict_applied") as sig:
        bridge._dispatch_event(
            {
                "type": "verdict_applied",
                "id": 7,
                "dest": TEST_IP1,
                "action": "accept",
                "ok": True,
            }
        )
        sig.assert_called_once_with("myapp", TEST_IP1, "myapp:7", "accept", True)


def test_dispatch_unknown_event_type(tmp_path: Path) -> None:
    """_dispatch_event() silently ignores unknown event types."""
    bridge = _bridge(tmp_path)
    bridge._dispatch_event({"type": "unknown_thing", "data": 123})


# ── _read_loop ─────────────────────────────────────────────


def test_read_loop_dispatches_json_events(tmp_path: Path) -> None:
    """_read_loop() parses JSON lines and dispatches events."""
    bridge = _bridge(tmp_path)
    pending_line = (
        json.dumps(
            {
                "type": "pending",
                "id": 1,
                "dest": TEST_IP1,
                "port": 443,
                "proto": 6,
                "domain": TEST_DOMAIN,
            }
        ).encode()
        + b"\n"
    )
    bridge._process = _mock_process(stdout_lines=[pending_line])

    with mock.patch.object(bridge._interface, "connection_blocked") as sig:
        asyncio.run(bridge._read_loop())
        sig.assert_called_once()


def test_read_loop_skips_blank_lines(tmp_path: Path) -> None:
    """_read_loop() skips blank lines without dispatching."""
    bridge = _bridge(tmp_path)
    bridge._process = _mock_process(stdout_lines=[b"\n", b"  \n"])

    with mock.patch.object(bridge, "_dispatch_event") as dispatch:
        asyncio.run(bridge._read_loop())
        dispatch.assert_not_called()


def test_read_loop_skips_non_json_lines(tmp_path: Path) -> None:
    """_read_loop() warns on non-JSON lines and continues."""
    bridge = _bridge(tmp_path)
    bridge._process = _mock_process(stdout_lines=[b"not json\n"])

    with mock.patch.object(bridge, "_dispatch_event") as dispatch:
        asyncio.run(bridge._read_loop())
        dispatch.assert_not_called()


def test_read_loop_handles_exception(tmp_path: Path) -> None:
    """_read_loop() logs exceptions from dispatch and exits cleanly."""
    bridge = _bridge(tmp_path)
    line = json.dumps({"type": "pending", "id": 1}).encode() + b"\n"
    bridge._process = _mock_process(stdout_lines=[line])

    with mock.patch.object(bridge, "_dispatch_event", side_effect=RuntimeError("boom")):
        # Should not raise — exception is caught and logged
        asyncio.run(bridge._read_loop())


def test_read_loop_early_exit_no_process(tmp_path: Path) -> None:
    """_read_loop() returns immediately when process is None."""
    bridge = _bridge(tmp_path)
    bridge._process = None
    asyncio.run(bridge._read_loop())


def test_read_loop_early_exit_no_stdout(tmp_path: Path) -> None:
    """_read_loop() returns immediately when stdout is None."""
    bridge = _bridge(tmp_path)
    proc = mock.MagicMock()
    proc.stdout = None
    bridge._process = proc
    asyncio.run(bridge._read_loop())


# ── Interface class ────────────────────────────────────────


def test_shield_interface_name() -> None:
    """_ShieldInterface uses the canonical Shield1 interface name."""
    bridge = mock.MagicMock()
    iface = _ShieldInterface(bridge)
    assert iface.name == "org.terok.Shield1"


def test_shield_interface_stores_bridge_reference() -> None:
    """_ShieldInterface keeps a reference to the bridge for verdict routing."""
    bridge = mock.MagicMock()
    iface = _ShieldInterface(bridge)
    assert iface._bridge is bridge


def test_connection_blocked_signal_body() -> None:
    """connection_blocked() returns the argument list for D-Bus serialisation."""
    bridge = mock.MagicMock()
    iface = _ShieldInterface(bridge)
    result = iface.connection_blocked(TEST_IP1, TEST_IP1, 443, 6, TEST_DOMAIN, "myapp:1")
    assert result == [TEST_IP1, TEST_IP1, 443, 6, TEST_DOMAIN, "myapp:1"]


def test_verdict_applied_signal_body() -> None:
    """verdict_applied() returns the argument list for D-Bus serialisation."""
    bridge = mock.MagicMock()
    iface = _ShieldInterface(bridge)
    result = iface.verdict_applied("myapp", TEST_IP1, "myapp:1", "accept", True)
    assert result == ["myapp", TEST_IP1, "myapp:1", "accept", True]


def test_verdict_method_delegates() -> None:
    """The verdict method body awaits bridge.submit_verdict."""
    bridge_mock = mock.MagicMock()
    bridge_mock.submit_verdict = mock.AsyncMock(return_value=True)
    iface = _ShieldInterface(bridge_mock)
    # Call the original unwrapped coroutine to exercise the body
    # (the @method() decorator intercepts normal calls for D-Bus dispatch).
    orig_fn = _ShieldInterface.verdict.__wrapped__
    result = asyncio.run(orig_fn(iface, "myapp:1", "accept"))
    assert result is True
    bridge_mock.submit_verdict.assert_awaited_once_with("myapp:1", "accept")


# ── Registry handler ──────────────────────────────────────


def test_handle_dbus_bridge_delegates(tmp_path: Path) -> None:
    """_handle_dbus_bridge() delegates to run_dbus_bridge with state_dir and container."""
    from terok_shield.cli.registry import _handle_dbus_bridge

    shield = mock.MagicMock()
    shield.config.state_dir = tmp_path

    with mock.patch("terok_shield.cli.dbus_bridge.run_dbus_bridge") as run_mock:
        _handle_dbus_bridge(shield, "myapp")
        run_mock.assert_called_once_with(tmp_path, "myapp")


# ── start / stop lifecycle ─────────────────────────────────


def test_start_exports_interface_and_spawns_subprocess(tmp_path: Path) -> None:
    """start() exports the D-Bus interface and spawns the interactive subprocess."""
    bridge = _bridge(tmp_path)
    proc = _mock_process(stdout_lines=[])

    async def _test():
        with mock.patch("asyncio.create_subprocess_exec", return_value=proc) as spawn:
            await bridge.start()
            bridge._bus.export.assert_called_once()
            spawn.assert_awaited_once()
            args = spawn.call_args[0]
            assert "terok_shield.cli.interactive" in args
            await bridge.stop()

    asyncio.run(_test())


def test_start_passes_raw_env(tmp_path: Path) -> None:
    """start() sets _TEROK_SHIELD_NFLOG_RAW=1 in the subprocess environment."""
    bridge = _bridge(tmp_path)
    proc = _mock_process(stdout_lines=[])

    async def _test():
        with mock.patch("asyncio.create_subprocess_exec", return_value=proc) as spawn:
            await bridge.start()
            kwargs = spawn.call_args[1]
            assert kwargs["env"]["_TEROK_SHIELD_NFLOG_RAW"] == "1"
            await bridge.stop()

    asyncio.run(_test())


def test_stop_terminates_subprocess(tmp_path: Path) -> None:
    """stop() terminates the subprocess and unexports the interface."""
    bridge = _bridge(tmp_path)
    proc = _mock_process()
    bridge._process = proc
    bridge._read_task = None

    asyncio.run(bridge.stop())

    proc.terminate.assert_called_once()
    bridge._bus.unexport.assert_called_once()


def test_stop_cancels_read_task(tmp_path: Path) -> None:
    """stop() cancels a running read task before terminating the subprocess."""
    bridge = _bridge(tmp_path)
    proc = _mock_process()
    bridge._process = proc

    async def _test():
        # Create a real long-running task that we can cancel
        stall = asyncio.Event()
        task = asyncio.create_task(stall.wait())
        bridge._read_task = task
        await bridge.stop()
        assert task.cancelled()

    asyncio.run(_test())


def test_stop_kills_on_timeout(tmp_path: Path) -> None:
    """stop() escalates to kill() when terminate() does not exit in time."""
    bridge = _bridge(tmp_path)
    proc = _mock_process()
    # wait() raises TimeoutError on the first call (wait_for wrapper), succeeds on second
    proc.wait = mock.AsyncMock(side_effect=[TimeoutError(), 0])
    bridge._process = proc
    bridge._read_task = None

    asyncio.run(bridge.stop())

    proc.terminate.assert_called_once()
    proc.kill.assert_called_once()


def test_stop_logs_unexport_failure(tmp_path: Path) -> None:
    """stop() logs a debug message when unexport raises."""
    bridge = _bridge(tmp_path)
    bridge._bus.unexport.side_effect = RuntimeError("no such object")
    bridge._process = None
    bridge._read_task = None

    # Should not raise
    asyncio.run(bridge.stop())


def test_stop_without_process(tmp_path: Path) -> None:
    """stop() is safe to call when no subprocess has been started."""
    bridge = _bridge(tmp_path)
    asyncio.run(bridge.stop())


def test_stop_already_exited_process(tmp_path: Path) -> None:
    """stop() does not call terminate when the subprocess has already exited."""
    bridge = _bridge(tmp_path)
    proc = _mock_process(returncode=0)
    bridge._process = proc
    bridge._read_task = None

    asyncio.run(bridge.stop())

    proc.terminate.assert_not_called()


def test_stop_handles_process_lookup_error_on_terminate(tmp_path: Path) -> None:
    """stop() handles ProcessLookupError when subprocess exits before terminate."""
    bridge = _bridge(tmp_path)
    proc = _mock_process()
    proc.terminate.side_effect = ProcessLookupError
    bridge._process = proc
    bridge._read_task = None

    asyncio.run(bridge.stop())
    proc.terminate.assert_called_once()
    proc.kill.assert_not_called()


def test_stop_handles_process_lookup_error_on_kill(tmp_path: Path) -> None:
    """stop() handles ProcessLookupError when subprocess exits before kill."""
    bridge = _bridge(tmp_path)
    proc = _mock_process()
    proc.wait = mock.AsyncMock(side_effect=[TimeoutError(), 0])
    proc.kill.side_effect = ProcessLookupError
    bridge._process = proc
    bridge._read_task = None

    asyncio.run(bridge.stop())
    proc.terminate.assert_called_once()
    proc.kill.assert_called_once()


def test_stop_reraises_cancelled_error(tmp_path: Path) -> None:
    """stop() re-raises CancelledError after completing cleanup."""
    bridge = _bridge(tmp_path)
    proc = _mock_process()
    proc.wait = mock.AsyncMock(side_effect=asyncio.CancelledError)
    bridge._process = proc
    bridge._read_task = None

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(bridge.stop())
    bridge._bus.unexport.assert_called_once()


def test_stop_kills_then_cancelled_during_wait(tmp_path: Path) -> None:
    """stop() re-raises CancelledError that arrives during wait after kill."""
    bridge = _bridge(tmp_path)
    proc = _mock_process()
    # First wait: TimeoutError (triggers kill), second wait: CancelledError
    proc.wait = mock.AsyncMock(side_effect=[TimeoutError(), asyncio.CancelledError()])
    bridge._process = proc
    bridge._read_task = None

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(bridge.stop())
    proc.terminate.assert_called_once()
    proc.kill.assert_called_once()
    bridge._bus.unexport.assert_called_once()


def test_stop_is_idempotent(tmp_path: Path) -> None:
    """stop() can be called twice without error."""
    bridge = _bridge(tmp_path)
    proc = _mock_process()
    bridge._process = proc
    bridge._read_task = None

    asyncio.run(bridge.stop())
    proc.returncode = 0
    asyncio.run(bridge.stop())

    proc.terminate.assert_called_once()


def test_start_preloads_bus_name(tmp_path: Path) -> None:
    """start() reads container_id before any side effects."""
    bus = mock.MagicMock()
    # No container.id file — should fail before export
    bridge = ShieldBridge(state_dir=tmp_path, container="myapp", bus=bus)

    with pytest.raises(FileNotFoundError):
        asyncio.run(bridge.start())

    bus.export.assert_not_called()


def test_start_unexports_on_spawn_failure(tmp_path: Path) -> None:
    """start() rolls back the D-Bus export when subprocess creation fails."""
    bridge = _bridge(tmp_path)

    async def _test():
        with mock.patch("asyncio.create_subprocess_exec", side_effect=OSError("no such binary")):
            with pytest.raises(OSError, match="no such binary"):
                await bridge.start()
        # Interface was exported then unexported during rollback
        bridge._bus.export.assert_called_once()
        bridge._bus.unexport.assert_called_once()

    asyncio.run(_test())


def test_start_rollback_tolerates_unexport_failure(tmp_path: Path) -> None:
    """start() rollback does not mask the original error when unexport also fails."""
    bridge = _bridge(tmp_path)
    bridge._bus.unexport.side_effect = RuntimeError("bus gone")

    async def _test():
        with mock.patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError("python")):
            with pytest.raises(FileNotFoundError, match="python"):
                await bridge.start()

    asyncio.run(_test())


# ── CLI entry point ────────────────────────────────────────


def test_run_dbus_bridge_keyboard_interrupt(tmp_path: Path) -> None:
    """run_dbus_bridge() exits cleanly on KeyboardInterrupt."""
    from terok_shield.cli.dbus_bridge import run_dbus_bridge

    container_id_path(tmp_path).write_text("aabbccddee12\n")

    with mock.patch("terok_shield.cli.dbus_bridge._run_bridge", side_effect=KeyboardInterrupt):
        # Should not raise
        run_dbus_bridge(tmp_path, "myapp")


def test_run_bridge_rejects_duplicate_bus_name(tmp_path: Path) -> None:
    """_run_bridge exits with SystemExit(1) when bus name is already taken."""
    from dbus_fast import RequestNameReply

    from terok_shield.cli.dbus_bridge import _run_bridge

    container_id_path(tmp_path).write_text("aabbccddee12\n")

    mock_bus = mock.AsyncMock()
    mock_bus.request_name = mock.AsyncMock(return_value=RequestNameReply.IN_QUEUE)
    mock_bus.disconnect = mock.MagicMock()

    mock_bus_cls = mock.MagicMock()
    mock_bus_cls.return_value.connect = mock.AsyncMock(return_value=mock_bus)

    async def _test():
        with mock.patch("dbus_fast.aio.MessageBus", mock_bus_cls):
            with pytest.raises(SystemExit) as exc_info:
                await _run_bridge(tmp_path, "myapp")
            assert exc_info.value.code == 1
        mock_bus.disconnect.assert_called_once()

    asyncio.run(_test())


def test_run_bridge_starts_and_stops_on_signal(tmp_path: Path) -> None:
    """_run_bridge acquires bus name, starts bridge, stops on SIGTERM."""
    import signal as _signal

    from dbus_fast import RequestNameReply

    from terok_shield.cli.dbus_bridge import _run_bridge

    container_id_path(tmp_path).write_text("aabbccddee12\n")

    mock_bus = mock.AsyncMock()
    mock_bus.request_name = mock.AsyncMock(return_value=RequestNameReply.PRIMARY_OWNER)
    mock_bus.disconnect = mock.MagicMock()
    mock_bus.export = mock.MagicMock()
    mock_bus.unexport = mock.MagicMock()

    mock_bus_cls = mock.MagicMock()
    mock_bus_cls.return_value.connect = mock.AsyncMock(return_value=mock_bus)

    async def _test():
        with mock.patch("dbus_fast.aio.MessageBus", mock_bus_cls):
            task = asyncio.create_task(_run_bridge(tmp_path, "myapp"))
            # Let the bridge start and register signal handlers
            await asyncio.sleep(0.05)
            # Send SIGTERM to trigger the stop event
            _signal.raise_signal(_signal.SIGTERM)
            await asyncio.wait_for(task, timeout=5.0)

        mock_bus.request_name.assert_awaited_once()
        mock_bus.disconnect.assert_called()

    asyncio.run(_test())
