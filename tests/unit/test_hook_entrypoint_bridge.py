# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the bridge-hook dispatch in the shared OCI entrypoint.

The same ``hook_entrypoint.py`` serves both hook pairs; an explicit
``--bridge`` token in ``sys.argv`` selects the NFLOG reader path
(``terok-shield-bridge-hook``) over the default nft path
(``terok-shield-hook``).  These tests cover the bridge path end-to-end:
stage dispatch, reader spawn/reap, and the soft-fail behaviour that
keeps container starts alive when D-Bus or the reader resource aren't
available.
"""

from __future__ import annotations

import io
import json
import signal
from pathlib import Path
from unittest import mock

import pytest

from terok_shield.resources import hook_entrypoint

_CONTAINER_ID = "c" * 64
_SHORT_ID = _CONTAINER_ID[:12]


# ── Helpers ───────────────────────────────────────────────────────────


def _oci_json(state_dir: str, container_id: str = _CONTAINER_ID) -> str:
    """Build the minimal OCI state JSON the bridge hook reads from stdin."""
    return json.dumps(
        {
            "id": container_id,
            "pid": 42,
            "annotations": {
                "terok.shield.state_dir": state_dir,
                "terok.shield.version": "5",
            },
        }
    )


def _run_bridge(payload: str, *, stage: str) -> int:
    """Invoke ``hook_entrypoint.main`` as if dispatched through the bridge pair.

    The kernel's shebang loader strips the exec-supplied ``argv[0]`` and
    substitutes the script path, so the mocked ``sys.argv`` here mirrors
    what the hook actually sees at runtime: script-path plus the
    ``--bridge`` dispatch flag plus the stage.
    """
    with (
        mock.patch.object(hook_entrypoint.sys, "stdin", io.StringIO(payload)),
        mock.patch.object(
            hook_entrypoint.sys, "argv", ["/opt/terok-shield-hook", "--bridge", stage]
        ),
    ):
        return hook_entrypoint.main()


# ── Dispatch ──────────────────────────────────────────────────────────


class TestBridgeDispatch:
    """``main`` routes on ``--bridge`` in argv — bridge hook runs bridge logic."""

    def test_createruntime_invokes_spawn_reader(self, tmp_path: Path) -> None:
        oci = _oci_json(str(tmp_path))
        with mock.patch.object(hook_entrypoint, "_spawn_reader") as spawn:
            rc = _run_bridge(oci, stage="createRuntime")
        assert rc == 0
        spawn.assert_called_once_with(tmp_path, _SHORT_ID)

    def test_poststop_invokes_reap_reader(self, tmp_path: Path) -> None:
        oci = _oci_json(str(tmp_path))
        with mock.patch.object(hook_entrypoint, "_reap_reader") as reap:
            rc = _run_bridge(oci, stage="poststop")
        assert rc == 0
        reap.assert_called_once_with(tmp_path)

    def test_unknown_stage_is_no_op(self, tmp_path: Path) -> None:
        """Bridge path silently ignores unknown stages rather than failing the container."""
        oci = _oci_json(str(tmp_path))
        with (
            mock.patch.object(hook_entrypoint, "_spawn_reader") as spawn,
            mock.patch.object(hook_entrypoint, "_reap_reader") as reap,
        ):
            rc = _run_bridge(oci, stage="unknown")
        assert rc == 0
        spawn.assert_not_called()
        reap.assert_not_called()

    def test_missing_container_id_skips_spawn(self, tmp_path: Path) -> None:
        oci = json.dumps(
            {
                "pid": 42,
                "annotations": {
                    "terok.shield.state_dir": str(tmp_path),
                    "terok.shield.version": "5",
                },
            }
        )
        with mock.patch.object(hook_entrypoint, "_spawn_reader") as spawn:
            rc = _run_bridge(oci, stage="createRuntime")
        assert rc == 0
        spawn.assert_not_called()


# ── Session-bus resolution ────────────────────────────────────────────


class TestSessionBusAddress:
    """Resolution order: DBUS_SESSION_BUS_ADDRESS env → /run/user/$UID/bus → None."""

    def test_env_var_is_preferred(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:abstract=deadbeef")
        assert hook_entrypoint._session_bus_address() == "unix:abstract=deadbeef"

    def test_run_user_bus_fallback(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
        fake_bus = tmp_path / "bus"
        fake_bus.touch()
        with (
            mock.patch.object(hook_entrypoint.os, "getuid", return_value=1000),
            mock.patch.object(
                hook_entrypoint.Path,
                "exists",
                lambda self: str(self) == f"/run/user/1000/bus",  # noqa: F541
            ),
        ):
            addr = hook_entrypoint._session_bus_address()
        assert addr == "unix:path=/run/user/1000/bus"

    def test_returns_none_when_unreachable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
        with (
            mock.patch.object(hook_entrypoint.os, "getuid", return_value=1000),
            mock.patch.object(hook_entrypoint.Path, "exists", lambda _self: False),
        ):
            assert hook_entrypoint._session_bus_address() is None


# ── Reader spawn ──────────────────────────────────────────────────────


class TestSpawnReader:
    """``_spawn_reader`` soft-fails on every misconfiguration; writes pid on success."""

    def test_missing_reader_script_is_soft_fail(self, tmp_path: Path) -> None:
        with (
            mock.patch.object(
                hook_entrypoint, "_reader_script_path", return_value=tmp_path / "missing.py"
            ),
            mock.patch.object(hook_entrypoint.subprocess, "Popen") as popen,
        ):
            hook_entrypoint._spawn_reader(tmp_path, _SHORT_ID)
        popen.assert_not_called()
        assert not (tmp_path / "reader.pid").exists()

    def test_no_session_bus_is_soft_fail(self, tmp_path: Path) -> None:
        reader = tmp_path / "reader.py"
        reader.touch()
        with (
            mock.patch.object(hook_entrypoint, "_reader_script_path", return_value=reader),
            mock.patch.object(hook_entrypoint, "_session_bus_address", return_value=None),
            mock.patch.object(hook_entrypoint.subprocess, "Popen") as popen,
        ):
            hook_entrypoint._spawn_reader(tmp_path, _SHORT_ID)
        popen.assert_not_called()
        assert not (tmp_path / "reader.pid").exists()

    def test_happy_path_starts_reader_and_writes_pid(self, tmp_path: Path) -> None:
        reader = tmp_path / "reader.py"
        reader.touch()
        fake_proc = mock.MagicMock(pid=12345)
        with (
            mock.patch.object(hook_entrypoint, "_reader_script_path", return_value=reader),
            mock.patch.object(
                hook_entrypoint, "_session_bus_address", return_value="unix:path=/run/user/1000/bus"
            ),
            mock.patch.object(hook_entrypoint.subprocess, "Popen", return_value=fake_proc) as popen,
        ):
            hook_entrypoint._spawn_reader(tmp_path, _SHORT_ID)
        assert (tmp_path / "reader.pid").read_text().strip() == "12345"
        cmd = popen.call_args[0][0]
        assert cmd[:2] == ["/usr/bin/python3", str(reader)]
        assert str(tmp_path) in cmd
        assert _SHORT_ID in cmd
        assert "--emit=dbus" in cmd
        env = popen.call_args[1]["env"]
        assert env["DBUS_SESSION_BUS_ADDRESS"] == "unix:path=/run/user/1000/bus"
        assert popen.call_args[1]["start_new_session"] is True

    def test_idempotent_when_reader_already_alive(self, tmp_path: Path) -> None:
        reader = tmp_path / "reader.py"
        reader.touch()
        pid_file = tmp_path / "reader.pid"
        pid_file.write_text("99999\n")
        with (
            mock.patch.object(hook_entrypoint, "_reader_script_path", return_value=reader),
            mock.patch.object(
                hook_entrypoint, "_session_bus_address", return_value="unix:path=/run/user/1000/bus"
            ),
            mock.patch.object(hook_entrypoint, "_pid_exists", return_value=True),
            mock.patch.object(hook_entrypoint.subprocess, "Popen") as popen,
        ):
            hook_entrypoint._spawn_reader(tmp_path, _SHORT_ID)
        popen.assert_not_called()
        assert pid_file.read_text().strip() == "99999"

    def test_popen_failure_is_soft_fail(self, tmp_path: Path) -> None:
        reader = tmp_path / "reader.py"
        reader.touch()
        with (
            mock.patch.object(hook_entrypoint, "_reader_script_path", return_value=reader),
            mock.patch.object(
                hook_entrypoint, "_session_bus_address", return_value="unix:path=/run/user/1000/bus"
            ),
            mock.patch.object(hook_entrypoint.subprocess, "Popen", side_effect=OSError("nope")),
        ):
            hook_entrypoint._spawn_reader(tmp_path, _SHORT_ID)
        assert not (tmp_path / "reader.pid").exists()


# ── Reader reap ───────────────────────────────────────────────────────


class TestReapReader:
    """``_reap_reader`` SIGTERMs then escalates to SIGKILL if the reader lingers."""

    def test_no_pid_file_is_noop(self, tmp_path: Path) -> None:
        with mock.patch.object(hook_entrypoint.os, "kill") as kill:
            hook_entrypoint._reap_reader(tmp_path)
        kill.assert_not_called()

    def test_sigterm_sent_and_pid_file_removed(self, tmp_path: Path) -> None:
        pid_file = tmp_path / "reader.pid"
        pid_file.write_text("12345\n")
        # First poll sees the process gone → no SIGKILL.
        with (
            mock.patch.object(hook_entrypoint.os, "kill") as kill,
            mock.patch.object(hook_entrypoint, "_pid_exists", return_value=False),
            mock.patch.object(hook_entrypoint.time, "sleep"),
        ):
            hook_entrypoint._reap_reader(tmp_path)
        kill.assert_called_once_with(12345, signal.SIGTERM)
        assert not pid_file.exists()

    def test_sigkill_escalation_when_process_lingers(self, tmp_path: Path) -> None:
        pid_file = tmp_path / "reader.pid"
        pid_file.write_text("12345\n")
        with (
            mock.patch.object(hook_entrypoint.os, "kill") as kill,
            mock.patch.object(hook_entrypoint, "_pid_exists", return_value=True),
            mock.patch.object(hook_entrypoint.time, "sleep"),
        ):
            hook_entrypoint._reap_reader(tmp_path)
        signals_sent = [call.args[1] for call in kill.call_args_list]
        assert signals_sent == [signal.SIGTERM, signal.SIGKILL]
        assert not pid_file.exists()

    def test_already_gone_process_is_handled(self, tmp_path: Path) -> None:
        pid_file = tmp_path / "reader.pid"
        pid_file.write_text("12345\n")
        with mock.patch.object(hook_entrypoint.os, "kill", side_effect=ProcessLookupError):
            hook_entrypoint._reap_reader(tmp_path)
        assert not pid_file.exists()

    def test_malformed_pid_file_cleans_up(self, tmp_path: Path) -> None:
        pid_file = tmp_path / "reader.pid"
        pid_file.write_text("not-a-pid\n")
        with mock.patch.object(hook_entrypoint.os, "kill") as kill:
            hook_entrypoint._reap_reader(tmp_path)
        kill.assert_not_called()
        assert not pid_file.exists()
