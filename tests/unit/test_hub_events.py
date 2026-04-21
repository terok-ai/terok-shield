# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the stdlib-only hub event emitter."""

from __future__ import annotations

import json
import os
import socket
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from terok_shield._hub_events import HubEventEmitter, hub_socket_path

_CONTAINER = "test-ctr"


class _SocketRecorder:
    """Minimal unix-socket listener for exercising the emitter end-to-end."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.received: list[bytes] = []
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(str(path))
        self._sock.listen(1)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._stop = False

    def start(self) -> None:
        """Begin accepting connections on the listener thread."""
        self._thread.start()

    def stop(self) -> None:
        """Stop the accept loop and close the listener."""
        self._stop = True
        self._sock.close()
        self._thread.join(timeout=1.0)

    def _accept_loop(self) -> None:
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            with conn:
                chunk = conn.recv(4096)
                if chunk:
                    self.received.append(chunk)


@pytest.fixture
def hub_socket(tmp_path: Path) -> Iterator[_SocketRecorder]:
    """Spin up a throwaway AF_UNIX listener the emitter can hit."""
    recorder = _SocketRecorder(tmp_path / "hub.sock")
    recorder.start()
    try:
        yield recorder
    finally:
        recorder.stop()


class TestHubSocketPath:
    """Canonical socket path resolution."""

    def test_uses_xdg_runtime_dir(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """The canonical path sits directly under XDG_RUNTIME_DIR."""
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
        assert hub_socket_path() == tmp_path / "terok-shield-events.sock"

    def test_falls_back_to_run_user_uid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without XDG_RUNTIME_DIR we fall back to ``/run/user/<uid>``."""
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        assert hub_socket_path() == Path(f"/run/user/{os.getuid()}/terok-shield-events.sock")


class TestHubEventEmitter:
    """End-to-end emitter behaviour against a real unix socket."""

    def test_shield_up_writes_single_json_line(self, hub_socket: _SocketRecorder) -> None:
        """``shield_up`` produces one newline-terminated JSON payload."""
        HubEventEmitter(hub_socket.path).shield_up(_CONTAINER)
        line = _received_one_line(hub_socket)
        assert json.loads(line) == {"type": "shield_up", "container": _CONTAINER}

    def test_shield_down_default_is_plain_down(self, hub_socket: _SocketRecorder) -> None:
        """``shield_down`` without ``allow_all`` maps to ``shield_down``."""
        HubEventEmitter(hub_socket.path).shield_down(_CONTAINER)
        assert json.loads(_received_one_line(hub_socket)) == {
            "type": "shield_down",
            "container": _CONTAINER,
        }

    def test_shield_down_allow_all_maps_to_down_all(self, hub_socket: _SocketRecorder) -> None:
        """``allow_all=True`` flips the event type to ``shield_down_all``."""
        HubEventEmitter(hub_socket.path).shield_down(_CONTAINER, allow_all=True)
        assert json.loads(_received_one_line(hub_socket)) == {
            "type": "shield_down_all",
            "container": _CONTAINER,
        }

    def test_missing_socket_is_fail_silent(self, tmp_path: Path) -> None:
        """Emission against a missing hub must not raise."""
        emitter = HubEventEmitter(tmp_path / "does-not-exist.sock")
        emitter.shield_up(_CONTAINER)  # must not raise
        emitter.shield_down(_CONTAINER, allow_all=True)  # must not raise


def _received_one_line(recorder: _SocketRecorder) -> str:
    """Drain the recorder and return the single newline-terminated payload."""
    # The emitter does a blocking sendall before close; by the time we return
    # here the accept loop has already written to ``recorder.received``.
    for _ in range(100):
        if recorder.received:
            break
        import time

        time.sleep(0.01)
    assert recorder.received, "emitter never reached the listener"
    data = b"".join(recorder.received).decode()
    assert data.endswith("\n")
    return data.rstrip("\n")
