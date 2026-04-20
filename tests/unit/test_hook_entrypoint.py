# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the stdlib-only OCI hook entrypoint script.

The script lives at ``src/terok_shield/resources/hook_entrypoint.py`` and is
importable as a regular Python module (``from terok_shield.resources import
hook_entrypoint``) even though it is installed verbatim as a hook binary.
"""

import io
import json
import os
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from terok_shield.resources import hook_entrypoint


def _oci_json(
    pid: int = 42,
    state_dir: str = "/tmp/sd",
    version: int = 9,
    container_id: str = "abc123def456789abcdef0123456789abcdef0123456789abcdef0123456789a",
) -> str:
    """Return a minimal OCI state JSON for hook_entrypoint.main()."""
    return json.dumps(
        {
            "id": container_id,
            "pid": pid,
            "annotations": {
                "terok.shield.state_dir": state_dir,
                "terok.shield.version": str(version),
            },
        }
    )


# ── _bootstrap_env ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("env_without", "expected_key", "expected_value"),
    [
        pytest.param("HOME", "HOME", "/home/testuser", id="home-from-pwd"),
        pytest.param("XDG_RUNTIME_DIR", "XDG_RUNTIME_DIR", "/run/user/1000", id="xdg-runtime-dir"),
        pytest.param("PATH", "PATH", "/usr/bin", id="path-fallback"),
    ],
)
def test_bootstrap_env_sets_missing_var(
    env_without: str, expected_key: str, expected_value: str
) -> None:
    """_bootstrap_env() sets each missing environment variable to a sensible default."""
    import pwd as _pwd

    full_env = {
        "HOME": "/home/testuser",
        "XDG_RUNTIME_DIR": "/run/user/1000",
        "PATH": "/usr/local/bin:/usr/bin",
    }
    env = {k: v for k, v in full_env.items() if k != env_without}
    fake_entry = _pwd.struct_passwd(
        ("testuser", "x", 1000, 1000, "", "/home/testuser", "/bin/bash")
    )
    with (
        mock.patch.dict("os.environ", env, clear=True),
        mock.patch("terok_shield.resources.hook_entrypoint.pwd.getpwuid", return_value=fake_entry),
        mock.patch("terok_shield.resources.hook_entrypoint._outer_host_uid", return_value=1000),
    ):
        hook_entrypoint._bootstrap_env()
        if expected_key == "PATH":
            assert expected_value in os.environ[expected_key]
        else:
            assert os.environ[expected_key] == expected_value


def test_bootstrap_env_does_not_override_existing_vars() -> None:
    """_bootstrap_env() leaves already-set environment variables unchanged."""
    env = {
        "HOME": "/custom/home",
        "XDG_RUNTIME_DIR": "/custom/xdg",
        "PATH": "/custom/bin",
    }
    with mock.patch.dict("os.environ", env, clear=True):
        hook_entrypoint._bootstrap_env()
        assert os.environ["HOME"] == "/custom/home"
        assert os.environ["XDG_RUNTIME_DIR"] == "/custom/xdg"
        assert os.environ["PATH"] == "/custom/bin"


def test_bootstrap_env_falls_back_when_getpwuid_raises() -> None:
    """_bootstrap_env() falls back to /home/<uid> when getpwuid raises KeyError."""
    env = {"XDG_RUNTIME_DIR": "/run/user/1234", "PATH": "/usr/bin"}
    with mock.patch.dict("os.environ", env, clear=True):
        with mock.patch(
            "terok_shield.resources.hook_entrypoint.pwd.getpwuid",
            side_effect=KeyError("uid not found"),
        ):
            with mock.patch(
                "terok_shield.resources.hook_entrypoint._outer_host_uid", return_value=1234
            ):
                hook_entrypoint._bootstrap_env()
        assert os.environ["HOME"] == "/home/1234"


# ── _find_* helpers ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("finder", "which_result", "expected"),
    [
        pytest.param(
            hook_entrypoint._find_nsenter, "/bin/nsenter", "/bin/nsenter", id="nsenter-which"
        ),
        pytest.param(
            hook_entrypoint._find_nsenter, None, "/usr/bin/nsenter", id="nsenter-fallback"
        ),
        pytest.param(hook_entrypoint._find_nft, "/usr/bin/nft", "/usr/bin/nft", id="nft-which"),
        pytest.param(hook_entrypoint._find_nft, None, "/usr/sbin/nft", id="nft-fallback"),
        pytest.param(
            hook_entrypoint._find_dnsmasq,
            "/usr/bin/dnsmasq",
            "/usr/bin/dnsmasq",
            id="dnsmasq-which",
        ),
        pytest.param(
            hook_entrypoint._find_dnsmasq, None, "/usr/sbin/dnsmasq", id="dnsmasq-fallback"
        ),
    ],
)
def test_find_binary_uses_which_or_falls_back(
    finder: object, which_result: str | None, expected: str
) -> None:
    """Each _find_*() helper returns the which result when found, or a hard-coded fallback."""
    with mock.patch(
        "terok_shield.resources.hook_entrypoint.shutil.which", return_value=which_result
    ):
        assert finder() == expected  # type: ignore[operator]


# ── _nsenter ─────────────────────────────────────────────────────────────────


def test_nsenter_uses_nsenter_directly_when_uid_is_zero() -> None:
    """_nsenter() calls nsenter directly when uid==0 (already in NS_ROOTLESS / crun context).

    crun runs inside NS_ROOTLESS where CAP_NET_ADMIN is already available.
    Calling podman unshare from NS_ROOTLESS would try to re-enter the same
    namespace and fail.
    """
    mock_result = mock.MagicMock()
    mock_result.returncode = 0
    with mock.patch(
        "terok_shield.resources.hook_entrypoint.subprocess.run", return_value=mock_result
    ) as mock_run:
        with mock.patch("terok_shield.resources.hook_entrypoint.os.getuid", return_value=0):
            with mock.patch(
                "terok_shield.resources.hook_entrypoint._find_nsenter",
                return_value="/usr/bin/nsenter",
            ):
                hook_entrypoint._nsenter("99", "nft", "-f", "/tmp/r.nft")

    mock_run.assert_called_once_with(
        ["/usr/bin/nsenter", "-n", "-t", "99", "--", "nft", "-f", "/tmp/r.nft"],
        input=None,
        text=True,
        capture_output=True,
        timeout=30,
    )


def test_nsenter_uses_podman_unshare_when_uid_is_nonzero() -> None:
    """_nsenter() uses 'podman unshare nsenter -n -t' when uid != 0 (NS_INIT / shell context).

    From the initial user namespace the hook has no elevated capabilities.
    podman unshare enters NS_ROOTLESS to gain CAP_NET_ADMIN first.
    """
    mock_result = mock.MagicMock()
    mock_result.returncode = 0
    with mock.patch(
        "terok_shield.resources.hook_entrypoint.subprocess.run", return_value=mock_result
    ) as mock_run:
        with mock.patch("terok_shield.resources.hook_entrypoint.os.getuid", return_value=1000):
            with mock.patch(
                "terok_shield.resources.hook_entrypoint._find_podman",
                return_value="/usr/bin/podman",
            ):
                with mock.patch(
                    "terok_shield.resources.hook_entrypoint._find_nsenter",
                    return_value="/usr/bin/nsenter",
                ):
                    hook_entrypoint._nsenter("99", "nft", "-f", "/tmp/r.nft")

    mock_run.assert_called_once_with(
        [
            "/usr/bin/podman",
            "unshare",
            "/usr/bin/nsenter",
            "-n",
            "-t",
            "99",
            "--",
            "nft",
            "-f",
            "/tmp/r.nft",
        ],
        input=None,
        text=True,
        capture_output=True,
        timeout=30,
    )


def test_nsenter_passes_stdin_as_text() -> None:
    """_nsenter() passes stdin string and text=True when stdin is provided."""
    mock_result = mock.MagicMock()
    mock_result.returncode = 0
    with mock.patch(
        "terok_shield.resources.hook_entrypoint.subprocess.run", return_value=mock_result
    ) as mock_run:
        with mock.patch(
            "terok_shield.resources.hook_entrypoint._find_nsenter",
            return_value="/usr/bin/nsenter",
        ):
            hook_entrypoint._nsenter("99", "nft", "-f", "-", stdin="table inet x {}")

    _, kwargs = mock_run.call_args
    assert kwargs["input"] == "table inet x {}"
    assert kwargs["text"] is True


@pytest.mark.parametrize(
    ("stderr", "stdout", "expected_match"),
    [
        pytest.param("Error: syntax error", "", "syntax error", id="stderr-only"),
        pytest.param("", "stdout error text", "stdout error text", id="stdout-fallback"),
        pytest.param("", "", r"\(no output\)", id="no-output"),
    ],
)
def test_nsenter_raises_on_failure_with_correct_message(
    stderr: str, stdout: str, expected_match: str
) -> None:
    """_nsenter() raises RuntimeError; error combines stderr+stdout (fallback to stdout, then '(no output)')."""
    mock_result = mock.MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = stderr
    mock_result.stdout = stdout
    with (
        mock.patch(
            "terok_shield.resources.hook_entrypoint.subprocess.run", return_value=mock_result
        ),
        mock.patch(
            "terok_shield.resources.hook_entrypoint._find_nsenter", return_value="/usr/bin/nsenter"
        ),
    ):
        with pytest.raises(RuntimeError, match=expected_match):
            hook_entrypoint._nsenter("99", "nft", "-f", "/tmp/r.nft")


def test_nsenter_raises_on_timeout() -> None:
    """_nsenter() raises RuntimeError when subprocess.run exceeds the 30-second timeout."""
    with (
        mock.patch(
            "terok_shield.resources.hook_entrypoint.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["nft"], timeout=30),
        ),
        mock.patch(
            "terok_shield.resources.hook_entrypoint._find_nsenter", return_value="/usr/bin/nsenter"
        ),
    ):
        with pytest.raises(RuntimeError, match="timed out"):
            hook_entrypoint._nsenter("99", "nft", "-f", "-")


# ── _createruntime ────────────────────────────────────────────────────────────


def test_createruntime_raises_when_namespace_files_missing(tmp_path: Path) -> None:
    """_createruntime() raises RuntimeError when /proc/<pid>/ns/net is absent."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "ruleset.nft").write_text("table inet terok_shield {}")
    with pytest.raises(RuntimeError, match="network namespace file missing"):
        hook_entrypoint._createruntime("99999999", sd)


def test_createruntime_treats_permission_error_as_ns_exists(tmp_path: Path) -> None:
    """_createruntime() continues when stat(/proc/pid/ns/net) raises PermissionError.

    Non-root callers on CI cannot stat /proc/1/ns/net but the namespace does exist;
    PermissionError must not be treated as 'namespace missing'.
    """
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "ruleset.nft").write_text("table inet terok_shield {}")

    real_stat = Path.stat

    def _selective_permission_error(self: Path, *args, **kwargs):
        if "ns/net" in str(self):
            raise PermissionError("no access")
        return real_stat(self, *args, **kwargs)

    with (
        mock.patch(
            "terok_shield.resources.hook_entrypoint.Path.stat",
            _selective_permission_error,
        ),
        mock.patch("terok_shield.resources.hook_entrypoint._nsenter"),
    ):
        # Must not raise — PermissionError is treated as "namespace exists but inaccessible"
        hook_entrypoint._createruntime("1", sd)


def test_createruntime_raises_when_ruleset_missing(tmp_path: Path) -> None:
    """_createruntime() raises RuntimeError when ruleset.nft is absent."""
    sd = tmp_path / "sd"
    sd.mkdir()
    # PID 1: stat() raises PermissionError (non-root) → treated as accessible;
    # ruleset.nft is absent, so the ruleset-missing check fires next.
    with pytest.raises(RuntimeError, match="ruleset.nft not found"):
        hook_entrypoint._createruntime("1", sd)


def test_createruntime_applies_ruleset_via_nsenter(tmp_path: Path) -> None:
    """_createruntime() applies the nft ruleset via nsenter stdin."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "ruleset.nft").write_text("table inet terok_shield {}")

    with mock.patch("terok_shield.resources.hook_entrypoint._nsenter") as mock_ns:
        hook_entrypoint._createruntime("1", sd)

    assert mock_ns.call_count == 1
    args = mock_ns.call_args.args
    assert "-" in args  # nft -f - (stdin)
    assert mock_ns.call_args.kwargs.get("stdin") == "table inet terok_shield {}"


def test_createruntime_starts_dnsmasq_when_conf_present(tmp_path: Path) -> None:
    """_createruntime() launches dnsmasq when dnsmasq.conf is present.

    resolv.conf is pre-written by pre_start() and bind-mounted :ro — the hook
    does not write it.  This test verifies nsenter is called for the ruleset
    apply and the dnsmasq launch, and nothing else.
    """
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "ruleset.nft").write_text("table inet terok_shield {}")
    dnsmasq_conf = sd / "dnsmasq.conf"
    dnsmasq_conf.write_text("[dnsmasq config]")

    def _fake_nsenter(*args: object, **kwargs: object) -> None:
        # Simulate dnsmasq writing its PID file on launch.
        if any("conf-file" in str(a) for a in args):
            (sd / "dnsmasq.pid").write_text("42\n")

    with (
        mock.patch(
            "terok_shield.resources.hook_entrypoint._nsenter", side_effect=_fake_nsenter
        ) as mock_ns,
        mock.patch("terok_shield.resources.hook_entrypoint._is_our_dnsmasq", return_value=True),
    ):
        hook_entrypoint._createruntime("1", sd)

    # nsenter called twice: apply ruleset + launch dnsmasq (no resolv.conf write)
    assert mock_ns.call_count == 2
    dnsmasq_call_args = mock_ns.call_args_list[1].args
    assert any("dnsmasq" in str(a) or "conf-file" in str(a) for a in dnsmasq_call_args)


def test_createruntime_raises_when_dnsmasq_pid_file_not_written(tmp_path: Path) -> None:
    """_createruntime() raises when dnsmasq starts but writes no PID file."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "ruleset.nft").write_text("table inet terok_shield {}")
    (sd / "dnsmasq.conf").write_text("[dnsmasq config]")

    with mock.patch("terok_shield.resources.hook_entrypoint._nsenter"):
        with pytest.raises(RuntimeError, match="PID file not written"):
            hook_entrypoint._createruntime("1", sd)


def test_createruntime_raises_when_dnsmasq_identity_check_fails(tmp_path: Path) -> None:
    """_createruntime() raises when PID file exists but process is not our dnsmasq."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "ruleset.nft").write_text("table inet terok_shield {}")
    (sd / "dnsmasq.conf").write_text("[dnsmasq config]")

    def _fake_nsenter(*args: object, **kwargs: object) -> None:
        if any("conf-file" in str(a) for a in args):
            (sd / "dnsmasq.pid").write_text("42\n")

    with (
        mock.patch("terok_shield.resources.hook_entrypoint._nsenter", side_effect=_fake_nsenter),
        mock.patch("terok_shield.resources.hook_entrypoint._is_our_dnsmasq", return_value=False),
    ):
        with pytest.raises(RuntimeError, match="not the expected process"):
            hook_entrypoint._createruntime("1", sd)


def test_createruntime_is_idempotent_when_dnsmasq_already_alive(tmp_path: Path) -> None:
    """_createruntime() skips relaunch when our dnsmasq is already running.

    Second-fire scenarios — a hook replayed by the runtime, a sibling hook
    re-dispatching into the nft branch, a retry after crun restart — must
    never end with dnsmasq colliding on 127.0.0.1:53.
    """
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "ruleset.nft").write_text("table inet terok_shield {}")
    (sd / "dnsmasq.conf").write_text("[dnsmasq config]")
    pid_file = sd / "dnsmasq.pid"
    pid_file.write_text("4242\n")  # prior run left a live process

    def _record_nsenter(*args: object, **kwargs: object) -> None:
        _record_nsenter.calls.append(args)

    _record_nsenter.calls = []
    with (
        mock.patch("terok_shield.resources.hook_entrypoint._nsenter", side_effect=_record_nsenter),
        mock.patch("terok_shield.resources.hook_entrypoint._is_our_dnsmasq", return_value=True),
    ):
        hook_entrypoint._createruntime("1", sd)

    # Ruleset apply still runs (nft is itself idempotent); dnsmasq launch is skipped.
    assert len(_record_nsenter.calls) == 1
    assert "dnsmasq" not in str(_record_nsenter.calls[0])
    assert pid_file.read_text().strip() == "4242"  # untouched


# ── _is_our_dnsmasq ───────────────────────────────────────────────────────────


def test_is_our_dnsmasq_returns_true_when_cmdline_matches(tmp_path: Path) -> None:
    """_is_our_dnsmasq() returns True when argv[0]=='dnsmasq' and --conf-file= matches."""
    conf = tmp_path / "dnsmasq.conf"
    cmdline = b"dnsmasq\x00--conf-file=" + str(conf).encode() + b"\x00"
    with mock.patch.object(hook_entrypoint.Path, "read_bytes", return_value=cmdline):
        assert hook_entrypoint._is_our_dnsmasq(1234, conf) is True


def test_is_our_dnsmasq_returns_false_when_cmdline_missing(tmp_path: Path) -> None:
    """_is_our_dnsmasq() returns False when /proc/{pid}/cmdline is unreadable."""
    conf = tmp_path / "dnsmasq.conf"
    with mock.patch.object(hook_entrypoint.Path, "read_bytes", side_effect=OSError("no such file")):
        assert hook_entrypoint._is_our_dnsmasq(9999, conf) is False


def test_is_our_dnsmasq_returns_false_when_conf_path_substring(tmp_path: Path) -> None:
    """_is_our_dnsmasq() rejects substring match — exact arg required."""
    conf = tmp_path / "dnsmasq.conf"
    longer = tmp_path / "prefixed" / conf.name
    cmdline = b"dnsmasq\x00--conf-file=" + str(longer).encode() + b"\x00"
    with mock.patch.object(hook_entrypoint.Path, "read_bytes", return_value=cmdline):
        assert hook_entrypoint._is_our_dnsmasq(1234, conf) is False


# ── _poststop ─────────────────────────────────────────────────────────────────


def test_poststop_sends_sigterm_to_dnsmasq(tmp_path: Path) -> None:
    """_poststop() sends SIGTERM (signal 15) when identity check passes."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "dnsmasq.pid").write_text("12345\n")

    with (
        mock.patch("terok_shield.resources.hook_entrypoint._is_our_dnsmasq", return_value=True),
        mock.patch("terok_shield.resources.hook_entrypoint.os.kill") as mock_kill,
    ):
        hook_entrypoint._poststop(sd)

    mock_kill.assert_called_once_with(12345, 15)


def test_poststop_skips_stale_pid(tmp_path: Path) -> None:
    """_poststop() skips signalling and removes the stale PID file on identity mismatch."""
    sd = tmp_path / "sd"
    sd.mkdir()
    pid_file = sd / "dnsmasq.pid"
    pid_file.write_text("12345\n")

    with (
        mock.patch("terok_shield.resources.hook_entrypoint._is_our_dnsmasq", return_value=False),
        mock.patch("terok_shield.resources.hook_entrypoint.os.kill") as mock_kill,
    ):
        hook_entrypoint._poststop(sd)

    mock_kill.assert_not_called()
    assert not pid_file.exists(), "stale PID file must be removed when identity check fails"


def test_poststop_ignores_oserror_on_stale_pid_unlink(tmp_path: Path) -> None:
    """_poststop() swallows OSError when removing a stale PID file fails."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "dnsmasq.pid").write_text("12345\n")

    with (
        mock.patch("terok_shield.resources.hook_entrypoint._is_our_dnsmasq", return_value=False),
        mock.patch("terok_shield.resources.hook_entrypoint.Path.unlink", side_effect=OSError),
    ):
        hook_entrypoint._poststop(sd)  # must not raise


def test_poststop_is_noop_when_pid_file_absent(tmp_path: Path) -> None:
    """_poststop() does nothing when dnsmasq.pid does not exist."""
    sd = tmp_path / "sd"
    sd.mkdir()
    # No pid file — should not raise
    hook_entrypoint._poststop(sd)


def test_poststop_ignores_oserror_on_kill(tmp_path: Path) -> None:
    """_poststop() swallows OSError from os.kill (process already gone)."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "dnsmasq.pid").write_text("99999\n")

    with (
        mock.patch("terok_shield.resources.hook_entrypoint._is_our_dnsmasq", return_value=True),
        mock.patch(
            "terok_shield.resources.hook_entrypoint.os.kill",
            side_effect=OSError,
        ),
    ):
        hook_entrypoint._poststop(sd)  # must not raise


def test_poststop_ignores_invalid_pid_content(tmp_path: Path) -> None:
    """_poststop() swallows ValueError from a non-integer PID file."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "dnsmasq.pid").write_text("not-a-pid\n")

    hook_entrypoint._poststop(sd)  # must not raise


# ── main() ────────────────────────────────────────────────────────────────────


def _run_main(json_str: str, *, stage: str = "createRuntime") -> int:
    """Call hook_entrypoint.main() with mocked argv, stdin, and _log.

    _log is suppressed so error paths do not write real files (its fallback
    path is /tmp/terok-hook-error.log which would escape the tmp_path sandbox).
    """
    with (
        mock.patch("terok_shield.resources.hook_entrypoint.sys.argv", ["hook", stage]),
        mock.patch("terok_shield.resources.hook_entrypoint.sys.stdin", io.StringIO(json_str)),
        mock.patch("terok_shield.resources.hook_entrypoint._log"),
    ):
        return hook_entrypoint.main()


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param("not json", id="bad-json"),
        pytest.param("[1, 2, 3]", id="oci-not-dict"),
        pytest.param(
            json.dumps({"pid": 42, "annotations": ["not", "a", "dict"]}),
            id="annotations-not-dict",
        ),
        pytest.param(
            json.dumps({"pid": 42, "annotations": {"terok.shield.version": "9"}}),
            id="state-dir-missing",
        ),
        pytest.param(
            json.dumps(
                {
                    "pid": 42,
                    "annotations": {
                        "terok.shield.state_dir": "/tmp/sd",
                        "terok.shield.version": "999",
                    },
                }
            ),
            id="version-mismatch",
        ),
    ],
)
def test_main_returns_1_for_invalid_input(payload: str) -> None:
    """main() returns 1 for any malformed or missing OCI state field."""
    assert _run_main(payload) == 1


def test_main_returns_1_when_pid_missing_for_createruntime(tmp_path: Path) -> None:
    """main() returns 1 when pid is 0/missing for the createRuntime stage."""
    oci = json.dumps(
        {
            "pid": 0,
            "annotations": {
                "terok.shield.state_dir": str(tmp_path),
                "terok.shield.version": "9",
            },
        }
    )
    assert _run_main(oci) == 1


def test_main_dispatches_createruntime_and_returns_0(tmp_path: Path) -> None:
    """main() calls _createruntime() and returns 0 on success."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "ruleset.nft").write_text("table inet terok_shield {}")

    oci = _oci_json(pid=42, state_dir=str(sd))

    with mock.patch("terok_shield.resources.hook_entrypoint._createruntime") as mock_cr:
        rc = _run_main(oci)

    assert rc == 0
    mock_cr.assert_called_once_with("42", sd)


def test_main_persists_container_id(tmp_path: Path) -> None:
    """main() writes the short container ID to state_dir/container.id."""
    sd = tmp_path / "sd"
    sd.mkdir()
    full_id = "abc123def456789abcdef0123456789abcdef0123456789abcdef0123456789a"
    oci = _oci_json(pid=42, state_dir=str(sd), container_id=full_id)

    with mock.patch("terok_shield.resources.hook_entrypoint._createruntime"):
        rc = _run_main(oci)

    assert rc == 0
    id_file = sd / "container.id"
    assert id_file.is_file()
    assert id_file.read_text().strip() == "abc123def456"


def test_main_dispatches_poststop_and_returns_0(tmp_path: Path) -> None:
    """main() calls _poststop() and returns 0 on success."""
    sd = tmp_path / "sd"
    sd.mkdir()

    oci = _oci_json(pid=0, state_dir=str(sd))

    with mock.patch("terok_shield.resources.hook_entrypoint._poststop") as mock_ps:
        rc = _run_main(oci, stage="poststop")

    assert rc == 0
    mock_ps.assert_called_once_with(sd)


def test_main_dispatches_poststop_on_version_mismatch(tmp_path: Path) -> None:
    """main() calls _poststop() even when bundle version has drifted.

    poststop cleanup must not be gated on bundle version — a container started
    before a terok-shield upgrade still needs its dnsmasq reaped on stop.
    """
    sd = tmp_path / "sd"
    sd.mkdir()
    oci = _oci_json(pid=0, state_dir=str(sd), version=999)

    with mock.patch("terok_shield.resources.hook_entrypoint._poststop") as mock_ps:
        rc = _run_main(oci, stage="poststop")

    assert rc == 0
    mock_ps.assert_called_once_with(sd)


def test_main_returns_1_on_createruntime_exception(tmp_path: Path) -> None:
    """main() returns 1 when _createruntime() raises any exception."""
    sd = tmp_path / "sd"
    sd.mkdir()
    oci = _oci_json(pid=42, state_dir=str(sd))

    with mock.patch(
        "terok_shield.resources.hook_entrypoint._createruntime",
        side_effect=RuntimeError("nft failed"),
    ):
        assert _run_main(oci) == 1


def test_main_returns_1_when_version_annotation_absent(tmp_path: Path) -> None:
    """main() returns 1 (fail-closed) when terok.shield.version annotation is absent."""
    sd = tmp_path / "sd"
    sd.mkdir()
    oci = json.dumps(
        {
            "pid": 42,
            "annotations": {"terok.shield.state_dir": str(sd)},
        }
    )
    assert _run_main(oci) == 1


def test_main_returns_1_for_relative_state_dir() -> None:
    """main() returns 1 when state_dir annotation is a relative path."""
    oci = json.dumps(
        {
            "pid": 42,
            "annotations": {
                "terok.shield.state_dir": "relative/path",
                "terok.shield.version": "9",
            },
        }
    )
    assert _run_main(oci) == 1


def test_main_returns_1_for_unknown_stage(tmp_path: Path) -> None:
    """main() returns 1 for an unrecognised stage and never invokes any handler."""
    sd = tmp_path / "sd"
    sd.mkdir()
    oci = _oci_json(pid=42, state_dir=str(sd))
    with (
        mock.patch("terok_shield.resources.hook_entrypoint._createruntime") as mock_cr,
        mock.patch("terok_shield.resources.hook_entrypoint._poststop") as mock_ps,
    ):
        assert _run_main(oci, stage="prestart") == 1
    mock_cr.assert_not_called()
    mock_ps.assert_not_called()


def test_main_returns_1_when_poststop_raises(tmp_path: Path) -> None:
    """main() returns 1 when _poststop() raises an unexpected exception."""
    sd = tmp_path / "sd"
    sd.mkdir()
    oci = _oci_json(pid=0, state_dir=str(sd))

    with mock.patch(
        "terok_shield.resources.hook_entrypoint._poststop",
        side_effect=RuntimeError("disk full"),
    ):
        assert _run_main(oci, stage="poststop") == 1
