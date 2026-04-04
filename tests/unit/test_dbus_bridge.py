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

    asyncio.run(_test())
    # Cleanup
    if bridge._read_task and not bridge._read_task.done():
        asyncio.run(bridge.stop())


def test_start_passes_raw_env(tmp_path: Path) -> None:
    """start() sets _TEROK_SHIELD_NFLOG_RAW=1 in the subprocess environment."""
    bridge = _bridge(tmp_path)
    proc = _mock_process(stdout_lines=[])

    async def _test():
        with mock.patch("asyncio.create_subprocess_exec", return_value=proc) as spawn:
            await bridge.start()
            kwargs = spawn.call_args[1]
            assert kwargs["env"]["_TEROK_SHIELD_NFLOG_RAW"] == "1"

    asyncio.run(_test())
    if bridge._read_task and not bridge._read_task.done():
        asyncio.run(bridge.stop())


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
