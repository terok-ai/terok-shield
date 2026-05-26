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

from terok_shield._hub_events import HubEventEmitter, _per_container_hub_socket

from ..testfs import RUN_USER_PREFIX

_CONTAINER = "test-ctr"
# Shorter than the canonical 64-char podman UUID — the unix-socket
# 108-byte path limit (sun_path) makes long ids unusable under deep
# pytest tmp_path trees.  The routing logic is character-agnostic;
# the path-length test pins the real path shape independently.
_CONTAINER_ID = "deadbeefcafe1234"


class _SocketRecorder:
    """Minimal unix-socket listener for exercising the emitter end-to-end."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.received: list[bytes] = []
        path.parent.mkdir(parents=True, exist_ok=True)
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
                # AF_UNIX SOCK_STREAM may hand us the payload in multiple
                # chunks under scheduler pressure — drain until EOF so the
                # full JSON line is always available to the asserting helper.
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    self.received.append(chunk)


@pytest.fixture
def hub_socket(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[_SocketRecorder]:
    """Spin up a throwaway AF_UNIX listener bound to the per-container path.

    Points ``XDG_RUNTIME_DIR`` at *tmp_path* so the emitter resolves to
    ``tmp_path/terok/events/<container_id>.sock`` — the very path the
    recorder is listening on.
    """
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    path = tmp_path / "terok" / "events" / f"{_CONTAINER_ID[:12]}.sock"
    recorder = _SocketRecorder(path)
    recorder.start()
    try:
        yield recorder
    finally:
        recorder.stop()


class TestPerContainerHubSocket:
    """Per-container socket path resolution."""

    def test_uses_xdg_runtime_dir(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """The per-container path sits under ``$XDG_RUNTIME_DIR/terok/events``."""
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
        assert _per_container_hub_socket(_CONTAINER_ID) == (
            tmp_path / "terok" / "events" / f"{_CONTAINER_ID[:12]}.sock"
        )

    def test_falls_back_to_run_user_uid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without XDG_RUNTIME_DIR we fall back to ``/run/user/<uid>``."""
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        assert _per_container_hub_socket(_CONTAINER_ID) == Path(
            f"{RUN_USER_PREFIX}{os.getuid()}/terok/events/{_CONTAINER_ID[:12]}.sock"
        )

    def test_distinct_container_ids_route_to_distinct_sockets(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Two containers under one operator land on two different sockets."""
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
        a = _per_container_hub_socket("aaaa11112222")
        b = _per_container_hub_socket("bbbb22223333")
        assert a != b
        assert a.parent == b.parent

    def test_valid_hex_id_passes(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """A well-formed hex container id resolves to a path without raising."""
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
        assert _per_container_hub_socket(_CONTAINER_ID).name == f"{_CONTAINER_ID[:12]}.sock"

    @pytest.mark.parametrize(
        "bad_id",
        [
            pytest.param("../../../../etc/passwd", id="path-traversal"),
            pytest.param("dead/beef/cafe", id="slash"),
            pytest.param("/run/user/0/evil", id="leading-slash"),
            pytest.param("", id="empty"),
            pytest.param("deadbeef", id="too-short"),
            pytest.param("g" * 16, id="non-hex"),
            pytest.param("deadbeefcafe\nfoo", id="newline"),
        ],
    )
    def test_malformed_container_id_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, bad_id: str
    ) -> None:
        """A malformed container id can't escape the events dir or redirect the socket."""
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
        with pytest.raises(ValueError):
            _per_container_hub_socket(bad_id)


class TestHubEventEmitter:
    """End-to-end emitter behaviour against a real per-container unix socket."""

    def test_shield_up_writes_single_json_line(self, hub_socket: _SocketRecorder) -> None:
        """``shield_up`` produces one newline-terminated JSON payload."""
        HubEventEmitter().shield_up(_CONTAINER, _CONTAINER_ID)
        line = _received_one_line(hub_socket)
        assert json.loads(line) == {"type": "shield_up", "container": _CONTAINER}

    def test_shield_down_default_is_plain_down(self, hub_socket: _SocketRecorder) -> None:
        """``shield_down`` without ``allow_all`` maps to ``shield_down``."""
        HubEventEmitter().shield_down(_CONTAINER, _CONTAINER_ID)
        assert json.loads(_received_one_line(hub_socket)) == {
            "type": "shield_down",
            "container": _CONTAINER,
        }

    def test_shield_down_allow_all_maps_to_disengaged(self, hub_socket: _SocketRecorder) -> None:
        """``allow_all=True`` flips the event type to ``shield_disengaged``."""
        HubEventEmitter().shield_down(_CONTAINER, _CONTAINER_ID, allow_all=True)
        assert json.loads(_received_one_line(hub_socket)) == {
            "type": "shield_disengaged",
            "container": _CONTAINER,
        }

    def test_missing_socket_is_fail_silent(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Emission against a missing hub must not raise."""
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
        emitter = HubEventEmitter()
        # Valid hex id (passes the path guard) but no listener is bound, so
        # the connect must fail silently rather than propagate the OSError.
        absent_id = "f" * 16
        emitter.shield_up(_CONTAINER, absent_id)  # must not raise
        emitter.shield_down(_CONTAINER, absent_id, allow_all=True)

    def test_dossier_is_attached_when_present(self, hub_socket: _SocketRecorder) -> None:
        """A non-empty dossier rides under the ``dossier`` key on the wire.

        Mirrors the per-emit dossier the reader already attaches to
        ``connection_blocked`` events — keeps every event for one
        container rendering with the same identity bundle.
        """
        HubEventEmitter().shield_up(
            _CONTAINER,
            _CONTAINER_ID,
            dossier={"project": "terok", "task": "abc", "name": "diligent-octopus"},
        )
        assert json.loads(_received_one_line(hub_socket)) == {
            "type": "shield_up",
            "container": _CONTAINER,
            "dossier": {"project": "terok", "task": "abc", "name": "diligent-octopus"},
        }

    def test_empty_dossier_omits_the_key(self, hub_socket: _SocketRecorder) -> None:
        """Empty / missing dossier yields a flat wire payload — no ``dossier`` key.

        Hub ingesters that don't know about ``dossier`` keep round-tripping
        standalone-container events without seeing an unknown key.
        """
        HubEventEmitter().shield_down(_CONTAINER, _CONTAINER_ID, dossier={})
        assert json.loads(_received_one_line(hub_socket)) == {
            "type": "shield_down",
            "container": _CONTAINER,
        }

    def test_attacker_bytes_in_container_name_are_sanitised(
        self, hub_socket: _SocketRecorder
    ) -> None:
        """A crafted container name can't smuggle control chars onto the wire."""
        HubEventEmitter().shield_up("evil\x00\x1bfoo", _CONTAINER_ID)
        parsed = json.loads(_received_one_line(hub_socket))
        assert parsed["container"] == "evil  foo"

    def test_dossier_values_are_sanitised(self, hub_socket: _SocketRecorder) -> None:
        """Producer-side belt-and-braces: dossier strings hit the wire as printable ASCII."""
        HubEventEmitter().shield_up(
            _CONTAINER,
            _CONTAINER_ID,
            dossier={"name": "p1\nProtocol: spoof", "task": "café"},
        )
        parsed = json.loads(_received_one_line(hub_socket))
        assert parsed["dossier"]["name"] == "p1 Protocol: spoof"
        assert parsed["dossier"]["task"] == "caf "

    def test_routes_to_per_container_socket(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """An emit for container A must not reach the listener for container B.

        Two listeners, two container ids: only the matching one sees the
        payload.  Guards the routing key — if the path scheme regresses to
        a single global socket both listeners would receive everything.
        """
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
        cid_a = "a" * 16
        cid_b = "b" * 16
        rec_a = _SocketRecorder(tmp_path / "terok" / "events" / f"{cid_a[:12]}.sock")
        rec_b = _SocketRecorder(tmp_path / "terok" / "events" / f"{cid_b[:12]}.sock")
        rec_a.start()
        rec_b.start()
        try:
            HubEventEmitter().shield_up(_CONTAINER, cid_a)
            assert _received_one_line(rec_a)
            assert not rec_b.received
        finally:
            rec_a.stop()
            rec_b.stop()


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
