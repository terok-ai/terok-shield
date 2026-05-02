# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for ``reader_hook.py`` — the NFLOG reader spawn/reap OCI hook.

Stage dispatch, reader spawn/reap, and the soft-fail behaviour that
keeps container starts alive when D-Bus or the reader resource aren't
available.  The reader hook self-dispatches on ``argv[1]`` (the OCI
stage); the legacy ``--bridge`` token from the pre-split shared
entrypoint is gone — each role script is its own binary now.
"""

from __future__ import annotations

import io
import json
import signal
import sys
from pathlib import Path
from unittest import mock

import pytest

from terok_shield.resources import _oci_state, reader_hook

from ..testfs import HOOK_ENTRYPOINT_PATH

_CONTAINER_ID = "c" * 64
_SHORT_ID = _CONTAINER_ID[:12]


# ── Helpers ───────────────────────────────────────────────────────────


def _oci_json(
    state_dir: str,
    container_id: str = _CONTAINER_ID,
    *,
    extra_annotations: dict[str, str] | None = None,
) -> str:
    """Build the minimal OCI state JSON the bridge hook reads from stdin.

    *extra_annotations* are merged on top of the required state-dir +
    version pair so callers can exercise the dossier-extraction path
    without rewriting the whole envelope.
    """
    annotations: dict[str, str] = {
        "terok.shield.state_dir": state_dir,
        "terok.shield.version": "12",
    }
    if extra_annotations:
        annotations.update(extra_annotations)
    return json.dumps({"id": container_id, "pid": 42, "annotations": annotations})


def _run_bridge(payload: str, *, stage: str) -> None:
    """Invoke ``reader_hook.main`` with a stage in argv and OCI state on stdin.

    The kernel's shebang loader strips the exec-supplied ``argv[0]`` and
    substitutes the script path, so the mocked ``sys.argv`` here mirrors
    what the hook actually sees at runtime: script-path plus the stage.
    """
    with (
        mock.patch.object(sys, "stdin", io.StringIO(payload)),
        mock.patch.object(sys, "argv", [HOOK_ENTRYPOINT_PATH, stage]),
    ):
        reader_hook.main()


# ── Dispatch ──────────────────────────────────────────────────────────


class TestBridgeDispatch:
    """``main`` routes by ``argv[1]`` stage — createRuntime spawns, poststop reaps."""

    def test_createruntime_invokes_spawn_reader(self, tmp_path: Path) -> None:
        oci = _oci_json(str(tmp_path))
        with mock.patch.object(reader_hook, "_spawn_reader") as spawn:
            _run_bridge(oci, stage="createRuntime")
        spawn.assert_called_once_with(tmp_path, _SHORT_ID, {})

    def test_createruntime_extracts_dossier_annotations(self, tmp_path: Path) -> None:
        """``dossier.*`` annotations are stripped of their prefix and passed through."""
        oci = json.dumps(
            {
                "id": _CONTAINER_ID,
                "pid": 42,
                "annotations": {
                    "terok.shield.state_dir": str(tmp_path),
                    "terok.shield.version": "12",
                    "dossier.container_name": "my-task-7f3",
                    "dossier.task": "abc",
                    "dossier.project": "terok",
                    "dossier.meta_path": "/var/lib/terok/tasks/abc.json",
                    "io.container.manager": "libpod",  # unrelated, must not leak
                },
            }
        )
        with mock.patch.object(reader_hook, "_spawn_reader") as spawn:
            _run_bridge(oci, stage="createRuntime")
        spawn.assert_called_once_with(
            tmp_path,
            _SHORT_ID,
            {
                "container_name": "my-task-7f3",
                "task": "abc",
                "project": "terok",
                "meta_path": "/var/lib/terok/tasks/abc.json",
            },
        )

    def test_poststop_invokes_reap_reader(self, tmp_path: Path) -> None:
        oci = _oci_json(str(tmp_path))
        with mock.patch.object(reader_hook, "_reap_reader") as reap:
            _run_bridge(oci, stage="poststop")
        reap.assert_called_once_with(tmp_path)

    def test_unknown_stage_is_no_op(self, tmp_path: Path) -> None:
        """Bridge path silently ignores unknown stages rather than failing the container."""
        oci = _oci_json(str(tmp_path))
        with (
            mock.patch.object(reader_hook, "_spawn_reader") as spawn,
            mock.patch.object(reader_hook, "_reap_reader") as reap,
        ):
            _run_bridge(oci, stage="unknown")
        spawn.assert_not_called()
        reap.assert_not_called()

    def test_missing_container_id_skips_spawn(self, tmp_path: Path) -> None:
        oci = json.dumps(
            {
                "pid": 42,
                "annotations": {
                    "terok.shield.state_dir": str(tmp_path),
                    "terok.shield.version": "12",
                },
            }
        )
        with mock.patch.object(reader_hook, "_spawn_reader") as spawn:
            _run_bridge(oci, stage="createRuntime")
        spawn.assert_not_called()

    def test_createruntime_persists_meta_path_for_host_side_callers(self, tmp_path: Path) -> None:
        """The orchestrator's ``dossier.meta_path`` annotation is persisted so ``Shield.up()``/``down()`` can resolve dossiers from the same meta JSON the reader uses.

        Single source of truth on the wire dossier — the meta JSON
        itself — pointed to by a tiny on-disk file.  The reader spawn
        path is mocked; what we assert is the durable side effect.
        """
        oci = _oci_json(
            str(tmp_path),
            extra_annotations={"dossier.meta_path": "/var/lib/terok/tasks/abc.json"},
        )
        with mock.patch.object(reader_hook, "_spawn_reader"):
            _run_bridge(oci, stage="createRuntime")
        assert (tmp_path / "meta_path").read_text() == "/var/lib/terok/tasks/abc.json"

    def test_createruntime_skips_meta_path_file_for_standalone_container(
        self, tmp_path: Path
    ) -> None:
        """Standalone containers (no ``dossier.meta_path``) get no pointer file.

        Missing pointer ⇒ host-side resolver returns ``{}`` ⇒ bare
        container name on the wire.  Same shape every existing
        non-orchestrator deployment already produces.
        """
        oci = _oci_json(str(tmp_path))
        with mock.patch.object(reader_hook, "_spawn_reader"):
            _run_bridge(oci, stage="createRuntime")
        assert not (tmp_path / "meta_path").exists()

    def test_createruntime_persists_meta_path_before_spawn(self, tmp_path: Path) -> None:
        """The pointer file lands before the reader Popen so a spawn failure still feeds shield up/down.

        Spawn is the costly step; a Popen-time crash (no D-Bus, no
        reader script) must not deprive ``Shield.up()`` /
        ``Shield.down()`` of the meta-path they need to resolve a
        wire dossier.
        """
        oci = _oci_json(
            str(tmp_path),
            extra_annotations={"dossier.meta_path": "/var/lib/terok/tasks/p/t.json"},
        )

        def explode(*_args: object, **_kwargs: object) -> None:
            raise OSError("Popen exploded")

        with mock.patch.object(reader_hook, "_spawn_reader", side_effect=explode):
            _run_bridge(oci, stage="createRuntime")
        assert (tmp_path / "meta_path").read_text() == "/var/lib/terok/tasks/p/t.json"


class TestMainSoftFailBranches:
    """``main`` must absorb every error and exit 0 — bridge is opt-out.

    The contract: container start can never be blocked by a hook
    failure on this path.  Bad OCI JSON, missing state_dir, raised
    ``_bridge_main`` — all log and return cleanly.
    """

    def test_bad_oci_json_logs_and_returns(self) -> None:
        """Malformed JSON on stdin → ``_oci_state.log`` once, then return."""
        with mock.patch.object(_oci_state, "log") as logger:
            _run_bridge("not-json", stage="createRuntime")
        logger.assert_called_once()
        assert "bad OCI state" in logger.call_args.args[0]

    def test_missing_state_dir_annotation_returns_silently(self) -> None:
        """OCI state with no ``state_dir`` annotation → ``state_dir_from_oci`` logs and returns."""
        oci = json.dumps({"id": _CONTAINER_ID, "pid": 42, "annotations": {}})
        with mock.patch.object(reader_hook, "_bridge_main") as bridge:
            _run_bridge(oci, stage="createRuntime")
        # state_dir resolution failed before _bridge_main got called.
        bridge.assert_not_called()

    def test_bridge_main_exception_is_swallowed(self, tmp_path: Path) -> None:
        """A raised ``_bridge_main`` is logged into ``hook-error.log`` and absorbed."""
        oci = _oci_json(str(tmp_path))
        with (
            mock.patch.object(reader_hook, "_bridge_main", side_effect=RuntimeError("kaboom")),
            mock.patch.object(_oci_state, "log") as logger,
        ):
            _run_bridge(oci, stage="createRuntime")
        # Logged with the state-dir log file as second positional arg.
        logger.assert_called_once()
        assert "kaboom" in logger.call_args.args[0]
        assert logger.call_args.args[1] == tmp_path / "hook-error.log"


# ── Session-bus resolution ────────────────────────────────────────────


class TestSessionBusAddress:
    """Resolution order: DBUS_SESSION_BUS_ADDRESS env → /run/user/$UID/bus → None."""

    def test_env_var_is_preferred(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:abstract=deadbeef")
        assert reader_hook._session_bus_address() == "unix:abstract=deadbeef"

    def test_run_user_bus_fallback(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
        fake_bus = tmp_path / "bus"
        fake_bus.touch()
        with (
            mock.patch.object(_oci_state, "outer_host_uid", return_value=1000),
            mock.patch.object(
                _oci_state.Path,
                "exists",
                lambda self: str(self) == f"/run/user/1000/bus",  # noqa: F541
            ),
        ):
            addr = reader_hook._session_bus_address()
        assert addr == "unix:path=/run/user/1000/bus"

    def test_returns_none_when_unreachable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
        with (
            mock.patch.object(_oci_state, "outer_host_uid", return_value=1000),
            mock.patch.object(_oci_state.Path, "exists", lambda _self: False),
        ):
            assert reader_hook._session_bus_address() is None


# ── Reader spawn ──────────────────────────────────────────────────────


class TestSpawnReader:
    """``_spawn_reader`` soft-fails on every misconfiguration; writes pid on success."""

    def test_missing_reader_script_is_soft_fail(self, tmp_path: Path) -> None:
        with (
            mock.patch.object(
                reader_hook, "_reader_script_path", return_value=tmp_path / "missing.py"
            ),
            mock.patch.object(_oci_state.subprocess, "Popen") as popen,
        ):
            reader_hook._spawn_reader(tmp_path, _SHORT_ID)
        popen.assert_not_called()
        assert not (tmp_path / "reader.pid").exists()

    def test_no_session_bus_is_soft_fail(self, tmp_path: Path) -> None:
        reader = tmp_path / "reader.py"
        reader.touch()
        with (
            mock.patch.object(reader_hook, "_reader_script_path", return_value=reader),
            mock.patch.object(reader_hook, "_session_bus_address", return_value=None),
            mock.patch.object(_oci_state.subprocess, "Popen") as popen,
        ):
            reader_hook._spawn_reader(tmp_path, _SHORT_ID)
        popen.assert_not_called()
        assert not (tmp_path / "reader.pid").exists()

    def test_happy_path_starts_reader_and_writes_pid(self, tmp_path: Path) -> None:
        reader = tmp_path / "reader.py"
        reader.touch()
        fake_proc = mock.MagicMock(pid=12345)
        with (
            mock.patch.object(reader_hook, "_reader_script_path", return_value=reader),
            mock.patch.object(
                reader_hook, "_session_bus_address", return_value="unix:path=/run/user/1000/bus"
            ),
            mock.patch.object(_oci_state.subprocess, "Popen", return_value=fake_proc) as popen,
        ):
            reader_hook._spawn_reader(tmp_path, _SHORT_ID)
        assert (tmp_path / "reader.pid").read_text().strip() == "12345"
        cmd = popen.call_args[0][0]
        assert cmd[:2] == ["/usr/bin/python3", str(reader)]
        assert str(tmp_path) in cmd
        assert _SHORT_ID in cmd
        assert "--emit=socket" in cmd
        # Default-empty dossier is still serialised so the reader's argparse always sees the flag.
        assert "--annotations={}" in cmd
        env = popen.call_args[1]["env"]
        assert env["DBUS_SESSION_BUS_ADDRESS"] == "unix:path=/run/user/1000/bus"
        assert popen.call_args[1]["start_new_session"] is True

    def test_dossier_is_forwarded_as_annotations_argv(self, tmp_path: Path) -> None:
        """A non-empty dossier lands as a JSON-encoded ``--annotations=...`` argv element."""
        reader = tmp_path / "reader.py"
        reader.touch()
        fake_proc = mock.MagicMock(pid=12345)
        dossier = {"task": "abc", "project": "terok", "container_name": "n1"}
        with (
            mock.patch.object(reader_hook, "_reader_script_path", return_value=reader),
            mock.patch.object(
                reader_hook, "_session_bus_address", return_value="unix:path=/run/user/1000/bus"
            ),
            mock.patch.object(_oci_state.subprocess, "Popen", return_value=fake_proc) as popen,
        ):
            reader_hook._spawn_reader(tmp_path, _SHORT_ID, dossier)
        cmd = popen.call_args[0][0]
        ann_arg = next(a for a in cmd if a.startswith("--annotations="))
        assert json.loads(ann_arg.removeprefix("--annotations=")) == dossier

    def test_idempotent_when_reader_already_alive(self, tmp_path: Path) -> None:
        reader = tmp_path / "reader.py"
        reader.touch()
        pid_file = tmp_path / "reader.pid"
        pid_file.write_text("99999\n")
        with (
            mock.patch.object(reader_hook, "_reader_script_path", return_value=reader),
            mock.patch.object(
                reader_hook, "_session_bus_address", return_value="unix:path=/run/user/1000/bus"
            ),
            # Both arms of the liveness check need to agree — the PID exists
            # AND its cmdline identifies it as our reader.  Historical tests
            # only mocked _pid_exists, which no longer suffices now that
            # _reader_alive cross-checks with _is_our_reader.
            mock.patch.object(_oci_state, "pid_exists", return_value=True),
            mock.patch.object(reader_hook, "_is_our_reader", return_value=True),
            mock.patch.object(_oci_state.subprocess, "Popen") as popen,
        ):
            reader_hook._spawn_reader(tmp_path, _SHORT_ID)
        popen.assert_not_called()
        assert pid_file.read_text().strip() == "99999"

    def test_stale_pid_file_does_not_block_respawn(self, tmp_path: Path) -> None:
        """A reader.pid left behind by a crashed reader must not skip spawning.

        The fix for the PID-recycle case: if _pid_exists returns True but
        _is_our_reader says no (the PID belongs to an unrelated process),
        treat it as no-reader and spawn fresh.
        """
        reader = tmp_path / "reader.py"
        reader.touch()
        (tmp_path / "reader.pid").write_text("99999\n")
        fake_proc = mock.MagicMock(pid=4321)
        with (
            mock.patch.object(reader_hook, "_reader_script_path", return_value=reader),
            mock.patch.object(
                reader_hook, "_session_bus_address", return_value="unix:path=/run/user/1000/bus"
            ),
            mock.patch.object(_oci_state, "pid_exists", return_value=True),
            mock.patch.object(reader_hook, "_is_our_reader", return_value=False),
            mock.patch.object(_oci_state.subprocess, "Popen", return_value=fake_proc) as popen,
        ):
            reader_hook._spawn_reader(tmp_path, _SHORT_ID)
        popen.assert_called_once()
        assert (tmp_path / "reader.pid").read_text().strip() == "4321"

    def test_popen_failure_is_soft_fail(self, tmp_path: Path) -> None:
        reader = tmp_path / "reader.py"
        reader.touch()
        with (
            mock.patch.object(reader_hook, "_reader_script_path", return_value=reader),
            mock.patch.object(
                reader_hook, "_session_bus_address", return_value="unix:path=/run/user/1000/bus"
            ),
            mock.patch.object(_oci_state.subprocess, "Popen", side_effect=OSError("nope")),
        ):
            reader_hook._spawn_reader(tmp_path, _SHORT_ID)
        assert not (tmp_path / "reader.pid").exists()


# ── Reader reap ───────────────────────────────────────────────────────


class TestReapReader:
    """``_reap_reader`` SIGTERMs then escalates to SIGKILL if the reader lingers."""

    def test_no_pid_file_is_noop(self, tmp_path: Path) -> None:
        with mock.patch.object(_oci_state.os, "kill") as kill:
            reader_hook._reap_reader(tmp_path)
        kill.assert_not_called()

    def test_sigterm_sent_and_pid_file_removed(self, tmp_path: Path) -> None:
        pid_file = tmp_path / "reader.pid"
        pid_file.write_text("12345\n")
        # First poll sees the process gone → no SIGKILL.
        with (
            mock.patch.object(_oci_state.os, "kill") as kill,
            mock.patch.object(reader_hook, "_is_our_reader", return_value=True),
            mock.patch.object(_oci_state, "pid_exists", return_value=False),
            mock.patch.object(reader_hook.time, "sleep"),
        ):
            reader_hook._reap_reader(tmp_path)
        kill.assert_called_once_with(12345, signal.SIGTERM)
        assert not pid_file.exists()

    def test_sigkill_escalation_when_process_lingers(self, tmp_path: Path) -> None:
        pid_file = tmp_path / "reader.pid"
        pid_file.write_text("12345\n")
        with (
            mock.patch.object(_oci_state.os, "kill") as kill,
            mock.patch.object(reader_hook, "_is_our_reader", return_value=True),
            mock.patch.object(_oci_state, "pid_exists", return_value=True),
            mock.patch.object(reader_hook.time, "sleep"),
        ):
            reader_hook._reap_reader(tmp_path)
        signals_sent = [call.args[1] for call in kill.call_args_list]
        assert signals_sent == [signal.SIGTERM, signal.SIGKILL]
        assert not pid_file.exists()

    def test_already_gone_process_is_handled(self, tmp_path: Path) -> None:
        pid_file = tmp_path / "reader.pid"
        pid_file.write_text("12345\n")
        with (
            mock.patch.object(reader_hook, "_is_our_reader", return_value=True),
            mock.patch.object(_oci_state.os, "kill", side_effect=ProcessLookupError),
        ):
            reader_hook._reap_reader(tmp_path)
        assert not pid_file.exists()

    def test_malformed_pid_file_cleans_up(self, tmp_path: Path) -> None:
        pid_file = tmp_path / "reader.pid"
        pid_file.write_text("not-a-pid\n")
        with mock.patch.object(_oci_state.os, "kill") as kill:
            reader_hook._reap_reader(tmp_path)
        kill.assert_not_called()
        assert not pid_file.exists()

    def test_stale_pid_belonging_to_other_process_is_skipped(self, tmp_path: Path) -> None:
        """If reader.pid names a process that isn't ours, don't signal it."""
        pid_file = tmp_path / "reader.pid"
        pid_file.write_text("12345\n")
        with (
            mock.patch.object(reader_hook, "_is_our_reader", return_value=False),
            mock.patch.object(_oci_state.os, "kill") as kill,
        ):
            reader_hook._reap_reader(tmp_path)
        kill.assert_not_called()
        assert not pid_file.exists()


class TestIsOurReader:
    """``_is_our_reader`` matches the spawn argv we actually produce."""

    def test_matching_cmdline_returns_true(self, tmp_path: Path) -> None:
        reader = tmp_path / "share" / "nflog-reader.py"
        cmdline = (
            b"/usr/bin/python3\x00"
            + str(reader).encode()
            + b"\x00"
            + str(tmp_path).encode()
            + b"\x00cccccccccccc\x00--emit=socket\x00--annotations={}\x00"
        )
        with (
            mock.patch.object(reader_hook, "_reader_script_path", return_value=reader),
            mock.patch.object(_oci_state.Path, "read_bytes", return_value=cmdline),
        ):
            assert reader_hook._is_our_reader(4321, tmp_path) is True

    def test_wrong_script_returns_false(self, tmp_path: Path) -> None:
        reader = tmp_path / "expected.py"
        cmdline = (
            b"/usr/bin/python3\x00/other/script.py\x00" + str(tmp_path).encode() + b"\x00x\x00"
        )
        with (
            mock.patch.object(reader_hook, "_reader_script_path", return_value=reader),
            mock.patch.object(_oci_state.Path, "read_bytes", return_value=cmdline),
        ):
            assert reader_hook._is_our_reader(4321, tmp_path) is False

    def test_wrong_state_dir_returns_false(self, tmp_path: Path) -> None:
        reader = tmp_path / "reader.py"
        cmdline = b"/usr/bin/python3\x00" + str(reader).encode() + b"\x00/other/state\x00x\x00y\x00"
        with (
            mock.patch.object(reader_hook, "_reader_script_path", return_value=reader),
            mock.patch.object(_oci_state.Path, "read_bytes", return_value=cmdline),
        ):
            assert reader_hook._is_our_reader(4321, tmp_path) is False

    def test_missing_cmdline_returns_false(self, tmp_path: Path) -> None:
        with mock.patch.object(_oci_state.Path, "read_bytes", side_effect=OSError("no such file")):
            assert reader_hook._is_our_reader(4321, tmp_path) is False


class TestSpawnReaderFailureBranches:
    """Soft-fail contract: rare I/O errors don't escape _spawn_reader."""

    def test_reader_log_open_failure_soft_fails(self, tmp_path: Path) -> None:
        """If ``<sd>/reader.log`` can't be opened (EACCES etc.), we log and return."""
        reader = tmp_path / "reader.py"
        reader.touch()
        with (
            mock.patch.object(reader_hook, "_reader_script_path", return_value=reader),
            mock.patch.object(
                reader_hook, "_session_bus_address", return_value="unix:path=/run/user/1000/bus"
            ),
            mock.patch.object(_oci_state.Path, "open", side_effect=OSError("EACCES")),
            mock.patch.object(_oci_state.subprocess, "Popen") as popen,
        ):
            reader_hook._spawn_reader(tmp_path, _SHORT_ID)
        popen.assert_not_called()
        assert not (tmp_path / "reader.pid").exists()

    def test_pid_file_write_failure_sigterms_orphan(self, tmp_path: Path) -> None:
        """If the child started but we can't write its pid, SIGTERM the orphan."""
        reader = tmp_path / "reader.py"
        reader.touch()
        fake_proc = mock.MagicMock(pid=12345)
        fake_sigterm = mock.MagicMock()
        # write_text raises, we expect a SIGTERM back at the running child.
        original_write_text = _oci_state.Path.write_text
        with (
            mock.patch.object(reader_hook, "_reader_script_path", return_value=reader),
            mock.patch.object(
                reader_hook, "_session_bus_address", return_value="unix:path=/run/user/1000/bus"
            ),
            mock.patch.object(_oci_state.subprocess, "Popen", return_value=fake_proc),
            mock.patch.object(
                _oci_state.Path,
                "write_text",
                side_effect=lambda self, *a, **kw: (
                    (_ for _ in ()).throw(OSError("ENOSPC"))
                    if self.name == "reader.pid"
                    else original_write_text(self, *a, **kw)
                ),
                autospec=True,
            ),
            mock.patch.object(_oci_state.os, "kill", fake_sigterm),
        ):
            reader_hook._spawn_reader(tmp_path, _SHORT_ID)
        fake_sigterm.assert_called_once_with(12345, signal.SIGTERM)


class TestReapReaderSIGTERMFailureBranches:
    """Hardening: SIGTERM branches that log and still unlink the pid file."""

    def test_sigterm_oserror_unlinks_pid_and_returns(self, tmp_path: Path) -> None:
        """A non-ESRCH OSError on SIGTERM still cleans up the pid file."""
        pid_file = tmp_path / "reader.pid"
        pid_file.write_text("12345\n")
        with (
            mock.patch.object(reader_hook, "_is_our_reader", return_value=True),
            mock.patch.object(_oci_state.os, "kill", side_effect=OSError("EPERM")),
        ):
            reader_hook._reap_reader(tmp_path)
        assert not pid_file.exists()


class TestReaderAliveEdgeCases:
    """_reader_alive interprets pid-file state conservatively."""

    def test_malformed_pid_file_returns_false(self, tmp_path: Path) -> None:
        pid_file = tmp_path / "reader.pid"
        pid_file.write_text("not-an-int\n")
        assert reader_hook._reader_alive(pid_file) is False

    def test_dead_pid_returns_false(self, tmp_path: Path) -> None:
        pid_file = tmp_path / "reader.pid"
        pid_file.write_text("12345\n")
        with mock.patch.object(_oci_state, "pid_exists", return_value=False):
            assert reader_hook._reader_alive(pid_file) is False


class TestOuterHostUid:
    """``_outer_host_uid`` projects the current uid through /proc/self/uid_map."""

    def test_identity_mapping_returns_same_uid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Init userns has an identity map; projection is a no-op."""
        monkeypatch.setattr(_oci_state.os, "getuid", lambda: 1000)
        with mock.patch.object(
            _oci_state.Path,
            "read_text",
            return_value="         0          0 4294967295\n",
        ):
            assert _oci_state.outer_host_uid() == 1000

    def test_rootless_zero_to_host_uid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """NS_ROOTLESS: in-ns uid 0 maps to outer host uid (typically 1000)."""
        monkeypatch.setattr(_oci_state.os, "getuid", lambda: 0)
        with mock.patch.object(
            _oci_state.Path,
            "read_text",
            return_value="         0       1000          1\n         1     100000      65536\n",
        ):
            assert _oci_state.outer_host_uid() == 1000

    def test_uid_outside_range_falls_through(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """uid not covered by any mapping line falls back to os.getuid()."""
        monkeypatch.setattr(_oci_state.os, "getuid", lambda: 500)
        with mock.patch.object(
            _oci_state.Path, "read_text", return_value="         0       1000          1\n"
        ):
            assert _oci_state.outer_host_uid() == 500

    def test_unreadable_uid_map_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_oci_state.os, "getuid", lambda: 777)
        with mock.patch.object(_oci_state.Path, "read_text", side_effect=OSError("no such file")):
            assert _oci_state.outer_host_uid() == 777

    def test_malformed_uid_map_line_is_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Lines with the wrong shape or non-integer tokens are skipped, not fatal."""
        monkeypatch.setattr(_oci_state.os, "getuid", lambda: 1000)
        with mock.patch.object(
            _oci_state.Path,
            "read_text",
            # Line 1: only 2 parts → len(parts) != 3 continue
            # Line 2: 3 parts but non-integer → ValueError continue
            # Line 3: valid identity map that covers uid 1000
            return_value="two tokens\nbogus value here\n         0          0 4294967295\n",
        ):
            assert _oci_state.outer_host_uid() == 1000


class TestIsOurReaderShortCmdline:
    """Short ``/proc/{pid}/cmdline`` payload must be treated as a mismatch."""

    def test_short_cmdline_returns_false(self, tmp_path: Path) -> None:
        """Cmdline with fewer than four argv entries can't be our reader."""
        with mock.patch.object(_oci_state.Path, "read_bytes", return_value=b"/usr/bin/python3\x00"):
            assert reader_hook._is_our_reader(4321, tmp_path) is False


class TestPidExists:
    """``_pid_exists`` wraps ``os.kill(pid, 0)`` with the kernel's own semantics."""

    def test_alive_process_returns_true(self) -> None:
        with mock.patch.object(_oci_state.os, "kill"):
            assert _oci_state.pid_exists(4321) is True

    def test_dead_process_returns_false(self) -> None:
        with mock.patch.object(_oci_state.os, "kill", side_effect=ProcessLookupError):
            assert _oci_state.pid_exists(4321) is False

    def test_permission_denied_counts_as_alive(self) -> None:
        """EPERM means the PID is valid but owned by someone else — still alive."""
        with mock.patch.object(_oci_state.os, "kill", side_effect=PermissionError("EPERM")):
            assert _oci_state.pid_exists(4321) is True


class TestReaderScriptPath:
    """``_reader_script_path`` honours XDG, falls back under HOME."""

    def test_xdg_data_home_wins(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        assert reader_hook._reader_script_path() == (tmp_path / "terok-shield" / "nflog-reader.py")

    def test_falls_back_to_home_local_share(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))
        assert reader_hook._reader_script_path() == (
            tmp_path / ".local" / "share" / "terok-shield" / "nflog-reader.py"
        )


class TestPersistMetaPath:
    """``_oci_state.persist_meta_path`` records the orchestrator's task-meta JSON path under state_dir."""

    def test_round_trip(self, tmp_path: Path) -> None:
        """Write then read recovers the identical path string."""
        _oci_state.persist_meta_path(tmp_path, "/var/lib/terok/tasks/abc.json")
        assert _oci_state.read_meta_path(tmp_path) == "/var/lib/terok/tasks/abc.json"

    def test_empty_meta_path_is_a_no_op(self, tmp_path: Path) -> None:
        """No annotation ⇒ no file ⇒ host-side resolver returns ``{}``."""
        _oci_state.persist_meta_path(tmp_path, "")
        assert not (tmp_path / "meta_path").exists()

    def test_overwrite_replaces_previous_path(self, tmp_path: Path) -> None:
        """A second persist (e.g. container recreate) rewrites the pointer."""
        _oci_state.persist_meta_path(tmp_path, "/old/abc.json")
        _oci_state.persist_meta_path(tmp_path, "/new/xyz.json")
        assert _oci_state.read_meta_path(tmp_path) == "/new/xyz.json"

    def test_missing_state_dir_soft_fails(self, tmp_path: Path) -> None:
        """A vanished state_dir → log + return, no exception."""
        gone = tmp_path / "vanished"
        with mock.patch.object(_oci_state, "log") as logger:
            _oci_state.persist_meta_path(gone, "/var/lib/terok/x.json")
        logger.assert_called_once()
        assert "meta_path persist failed" in logger.call_args.args[0]


class TestReadMetaPath:
    """``_oci_state.read_meta_path`` soft-fails into ``""`` when the pointer is absent."""

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        """No pointer ⇒ empty string ⇒ resolver returns ``{}``."""
        assert _oci_state.read_meta_path(tmp_path) == ""


class TestResolveDossierFromMeta:
    """``_oci_state.resolve_dossier_from_meta`` reads the orchestrator's wire-dossier JSON file as-is."""

    def test_reads_dossier_file_verbatim(self, tmp_path: Path) -> None:
        """The file is wire-shape JSON — no projection, no key translation."""
        meta = tmp_path / "dossier.json"
        meta.write_text(json.dumps({"project": "terok", "task": "abc", "name": "diligent-octopus"}))
        assert _oci_state.resolve_dossier_from_meta(meta) == {
            "project": "terok",
            "task": "abc",
            "name": "diligent-octopus",
        }

    def test_falsy_values_drop_out(self, tmp_path: Path) -> None:
        """Empty / null fields don't bloat the wire — same as omitting them."""
        meta = tmp_path / "dossier.json"
        meta.write_text(json.dumps({"project": "", "task": "abc", "name": None}))
        assert _oci_state.resolve_dossier_from_meta(meta) == {"task": "abc"}

    def test_empty_meta_path_returns_empty(self, _: Path | None = None) -> None:
        """Standalone-container path: no orchestrator annotation, empty result."""
        assert _oci_state.resolve_dossier_from_meta("") == {}

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        """A pointer to a deleted task → ``{}``, no exception."""
        assert _oci_state.resolve_dossier_from_meta(tmp_path / "absent.json") == {}

    def test_malformed_json_returns_empty(self, tmp_path: Path) -> None:
        """Torn / mid-write file soft-fails (next emit picks up the fixed file)."""
        meta = tmp_path / "dossier.json"
        meta.write_text("{not json")
        assert _oci_state.resolve_dossier_from_meta(meta) == {}

    def test_non_object_payload_returns_empty(self, tmp_path: Path) -> None:
        """Top-level list / scalar isn't a dossier dict — drop quietly."""
        meta = tmp_path / "dossier.json"
        meta.write_text("[1, 2, 3]")
        assert _oci_state.resolve_dossier_from_meta(meta) == {}

    def test_forward_compat_keys_pass_through(self, tmp_path: Path) -> None:
        """A future dossier field the renderer doesn't yet know rides through.

        The renderer tolerates unknown dossier keys (it reads only what
        it cares about), so the resolver doesn't need to whitelist —
        forward compat for free.
        """
        meta = tmp_path / "dossier.json"
        meta.write_text(json.dumps({"project": "terok", "task": "abc", "future": "value"}))
        assert _oci_state.resolve_dossier_from_meta(meta) == {
            "project": "terok",
            "task": "abc",
            "future": "value",
        }

    def test_non_string_values_are_coerced(self, tmp_path: Path) -> None:
        """Forward-compat values landing as int/bool still become wire strings."""
        meta = tmp_path / "dossier.json"
        meta.write_text(json.dumps({"task": 42, "name": True}))
        assert _oci_state.resolve_dossier_from_meta(meta) == {"task": "42", "name": "True"}
