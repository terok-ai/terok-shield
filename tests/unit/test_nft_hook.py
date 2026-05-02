# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for ``nft_hook.py`` — the stdlib-only nft + dnsmasq OCI hook.

The script lives at ``src/terok_shield/resources/nft_hook.py`` and is
importable as a regular Python module (``from terok_shield.resources
import nft_hook``) even though it is installed verbatim as a hook
binary.  Shared helpers (env bootstrap, nsenter, binary finders) live
in the sibling ``_oci_state`` ballast module and are tested via the
same module reference.
"""

import io
import json
import os
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from terok_shield.resources import _oci_state, nft_hook


def _oci_json(
    pid: int = 42,
    state_dir: str = "/tmp/sd",
    version: int = 12,
    container_id: str = "abc123def456789abcdef0123456789abcdef0123456789abcdef0123456789a",
) -> str:
    """Return a minimal OCI state JSON for nft_hook.main()."""
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
        mock.patch("terok_shield.resources._oci_state.pwd.getpwuid", return_value=fake_entry),
        mock.patch("terok_shield.resources._oci_state.outer_host_uid", return_value=1000),
    ):
        _oci_state.bootstrap_env()
        if expected_key == "PATH":
            assert expected_value in os.environ[expected_key]
        else:
            assert os.environ[expected_key] == expected_value


def test_bootstrap_env_preserves_inherited_home_and_xdg() -> None:
    """_bootstrap_env() leaves ``HOME`` and ``XDG_RUNTIME_DIR`` alone when inherited.

    ``PATH`` is the exception — it is overridden unconditionally as a
    defence against a poisoned inherited PATH (see
    ``test_bootstrap_env_overrides_inherited_path``).
    """
    env = {
        "HOME": "/custom/home",
        "XDG_RUNTIME_DIR": "/custom/xdg",
        "PATH": "/usr/bin",
    }
    with mock.patch.dict("os.environ", env, clear=True):
        _oci_state.bootstrap_env()
        assert os.environ["HOME"] == "/custom/home"
        assert os.environ["XDG_RUNTIME_DIR"] == "/custom/xdg"


def test_bootstrap_env_overrides_inherited_path() -> None:
    """An attacker-controlled ``PATH`` is replaced with the trusted constant.

    The OCI runtime may pass through whatever ``$PATH`` the operator
    environment held; if that value puts an attacker-writable directory
    ahead of the system locations, ``shutil.which("nft")`` would
    resolve to a planted binary the hook then runs with
    ``CAP_NET_ADMIN``.  ``bootstrap_env`` clamps the search path to the
    trusted system directories and refuses to honour the inherited one.
    """
    poisoned = "/tmp/attacker:/usr/bin"
    with mock.patch.dict("os.environ", {"HOME": "/h", "PATH": poisoned}, clear=True):
        _oci_state.bootstrap_env()
        assert os.environ["PATH"] == _oci_state._TRUSTED_PATH
        assert "/tmp/attacker" not in os.environ["PATH"]


@pytest.mark.parametrize(
    "var",
    ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PYTHONPATH", "PYTHONHOME"],
)
def test_bootstrap_env_wipes_dynamic_linker_vars(var: str) -> None:
    """Dynamic-linker / Python-import injection vectors are stripped.

    Even with PATH clamped, an inherited ``LD_PRELOAD`` would let any
    subprocess we spawn load attacker code at link time.  The set of
    vars wiped here mirrors ``_DANGEROUS_ENV_VARS``.
    """
    with mock.patch.dict(
        "os.environ", {"HOME": "/h", "PATH": "/usr/bin", var: "/evil"}, clear=True
    ):
        _oci_state.bootstrap_env()
        assert var not in os.environ


def test_bootstrap_env_falls_back_when_getpwuid_raises() -> None:
    """_bootstrap_env() falls back to /home/<uid> when getpwuid raises KeyError."""
    env = {"XDG_RUNTIME_DIR": "/run/user/1234", "PATH": "/usr/bin"}
    with mock.patch.dict("os.environ", env, clear=True):
        with mock.patch(
            "terok_shield.resources._oci_state.pwd.getpwuid",
            side_effect=KeyError("uid not found"),
        ):
            with mock.patch("terok_shield.resources._oci_state.outer_host_uid", return_value=1234):
                _oci_state.bootstrap_env()
        assert os.environ["HOME"] == "/home/1234"


# ── _find_* helpers ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("finder", "which_result", "expected"),
    [
        pytest.param(_oci_state.find_nsenter, "/bin/nsenter", "/bin/nsenter", id="nsenter-which"),
        pytest.param(_oci_state.find_nsenter, None, "/usr/bin/nsenter", id="nsenter-fallback"),
        pytest.param(_oci_state.find_nft, "/usr/bin/nft", "/usr/bin/nft", id="nft-which"),
        pytest.param(_oci_state.find_nft, None, "/usr/sbin/nft", id="nft-fallback"),
        pytest.param(
            _oci_state.find_dnsmasq,
            "/usr/bin/dnsmasq",
            "/usr/bin/dnsmasq",
            id="dnsmasq-which",
        ),
        pytest.param(_oci_state.find_dnsmasq, None, "/usr/sbin/dnsmasq", id="dnsmasq-fallback"),
    ],
)
def test_find_binary_uses_which_or_falls_back(
    finder: object, which_result: str | None, expected: str
) -> None:
    """Each _find_*() helper returns the which result when found, or a hard-coded fallback."""
    with mock.patch("terok_shield.resources._oci_state.shutil.which", return_value=which_result):
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
        "terok_shield.resources._oci_state.subprocess.run", return_value=mock_result
    ) as mock_run:
        with mock.patch("terok_shield.resources._oci_state.os.getuid", return_value=0):
            with mock.patch(
                "terok_shield.resources._oci_state.find_nsenter",
                return_value="/usr/bin/nsenter",
            ):
                _oci_state.nsenter("99", "nft", "-f", "/tmp/r.nft")

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
        "terok_shield.resources._oci_state.subprocess.run", return_value=mock_result
    ) as mock_run:
        with mock.patch("terok_shield.resources._oci_state.os.getuid", return_value=1000):
            with mock.patch(
                "terok_shield.resources._oci_state.find_podman",
                return_value="/usr/bin/podman",
            ):
                with mock.patch(
                    "terok_shield.resources._oci_state.find_nsenter",
                    return_value="/usr/bin/nsenter",
                ):
                    _oci_state.nsenter("99", "nft", "-f", "/tmp/r.nft")

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
        "terok_shield.resources._oci_state.subprocess.run", return_value=mock_result
    ) as mock_run:
        with mock.patch(
            "terok_shield.resources._oci_state.find_nsenter",
            return_value="/usr/bin/nsenter",
        ):
            _oci_state.nsenter("99", "nft", "-f", "-", stdin="table inet x {}")

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
        mock.patch("terok_shield.resources._oci_state.subprocess.run", return_value=mock_result),
        mock.patch(
            "terok_shield.resources._oci_state.find_nsenter", return_value="/usr/bin/nsenter"
        ),
    ):
        with pytest.raises(RuntimeError, match=expected_match):
            _oci_state.nsenter("99", "nft", "-f", "/tmp/r.nft")


def test_nsenter_raises_on_timeout() -> None:
    """_nsenter() raises RuntimeError when subprocess.run exceeds the 30-second timeout."""
    with (
        mock.patch(
            "terok_shield.resources._oci_state.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["nft"], timeout=30),
        ),
        mock.patch(
            "terok_shield.resources._oci_state.find_nsenter", return_value="/usr/bin/nsenter"
        ),
    ):
        with pytest.raises(RuntimeError, match="timed out"):
            _oci_state.nsenter("99", "nft", "-f", "-")


# ── _createruntime ────────────────────────────────────────────────────────────


def test_createruntime_raises_when_namespace_files_missing(tmp_path: Path) -> None:
    """_createruntime() raises RuntimeError when /proc/<pid>/ns/net is absent."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "ruleset.nft").write_text("table inet terok_shield {}")
    with pytest.raises(RuntimeError, match="network namespace file missing"):
        nft_hook._createruntime("99999999", sd)


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
            "terok_shield.resources._oci_state.Path.stat",
            _selective_permission_error,
        ),
        mock.patch("terok_shield.resources._oci_state.nsenter"),
    ):
        # Must not raise — PermissionError is treated as "namespace exists but inaccessible"
        nft_hook._createruntime("1", sd)


def test_createruntime_raises_when_ruleset_missing(tmp_path: Path) -> None:
    """_createruntime() raises RuntimeError when ruleset.nft is absent."""
    sd = tmp_path / "sd"
    sd.mkdir()
    # PID 1: stat() raises PermissionError (non-root) → treated as accessible;
    # ruleset.nft is absent, so the ruleset-missing check fires next.
    with pytest.raises(RuntimeError, match="ruleset.nft not found"):
        nft_hook._createruntime("1", sd)


def test_createruntime_applies_ruleset_via_nsenter(tmp_path: Path) -> None:
    """_createruntime() applies the nft ruleset via nsenter stdin."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "ruleset.nft").write_text("table inet terok_shield {}")

    with mock.patch("terok_shield.resources._oci_state.nsenter") as mock_ns:
        nft_hook._createruntime("1", sd)

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
            "terok_shield.resources._oci_state.nsenter", side_effect=_fake_nsenter
        ) as mock_ns,
        mock.patch("terok_shield.resources.nft_hook._is_our_dnsmasq", return_value=True),
    ):
        nft_hook._createruntime("1", sd)

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

    with mock.patch("terok_shield.resources._oci_state.nsenter"):
        with pytest.raises(RuntimeError, match="PID file not written"):
            nft_hook._createruntime("1", sd)


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
        mock.patch("terok_shield.resources._oci_state.nsenter", side_effect=_fake_nsenter),
        mock.patch("terok_shield.resources.nft_hook._is_our_dnsmasq", return_value=False),
    ):
        with pytest.raises(RuntimeError, match="not the expected process"):
            nft_hook._createruntime("1", sd)


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
        mock.patch("terok_shield.resources._oci_state.nsenter", side_effect=_record_nsenter),
        mock.patch("terok_shield.resources.nft_hook._is_our_dnsmasq", return_value=True),
    ):
        nft_hook._createruntime("1", sd)

    # Ruleset apply still runs (nft is itself idempotent); dnsmasq launch is skipped.
    assert len(_record_nsenter.calls) == 1
    assert "dnsmasq" not in str(_record_nsenter.calls[0])
    assert pid_file.read_text().strip() == "4242"  # untouched


# ── _is_our_dnsmasq ───────────────────────────────────────────────────────────


def test_is_our_dnsmasq_returns_true_when_cmdline_matches(tmp_path: Path) -> None:
    """_is_our_dnsmasq() returns True when argv[0]=='dnsmasq' and --conf-file= matches."""
    conf = tmp_path / "dnsmasq.conf"
    cmdline = b"dnsmasq\x00--conf-file=" + str(conf).encode() + b"\x00"
    with mock.patch.object(_oci_state.Path, "read_bytes", return_value=cmdline):
        assert nft_hook._is_our_dnsmasq(1234, conf) is True


def test_is_our_dnsmasq_returns_false_when_cmdline_missing(tmp_path: Path) -> None:
    """_is_our_dnsmasq() returns False when /proc/{pid}/cmdline is unreadable."""
    conf = tmp_path / "dnsmasq.conf"
    with mock.patch.object(_oci_state.Path, "read_bytes", side_effect=OSError("no such file")):
        assert nft_hook._is_our_dnsmasq(9999, conf) is False


def test_is_our_dnsmasq_returns_false_when_conf_path_substring(tmp_path: Path) -> None:
    """_is_our_dnsmasq() rejects substring match — exact arg required."""
    conf = tmp_path / "dnsmasq.conf"
    longer = tmp_path / "prefixed" / conf.name
    cmdline = b"dnsmasq\x00--conf-file=" + str(longer).encode() + b"\x00"
    with mock.patch.object(_oci_state.Path, "read_bytes", return_value=cmdline):
        assert nft_hook._is_our_dnsmasq(1234, conf) is False


def test_is_our_dnsmasq_returns_false_when_cmdline_is_empty(tmp_path: Path) -> None:
    """_is_our_dnsmasq() returns False when /proc/{pid}/cmdline is empty."""
    conf = tmp_path / "dnsmasq.conf"
    with mock.patch.object(_oci_state.Path, "read_bytes", return_value=b""):
        assert nft_hook._is_our_dnsmasq(1234, conf) is False


# ── _poststop ─────────────────────────────────────────────────────────────────


def test_poststop_sends_sigterm_to_dnsmasq(tmp_path: Path) -> None:
    """_poststop() sends SIGTERM (signal 15) when identity check passes."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "dnsmasq.pid").write_text("12345\n")

    with (
        mock.patch("terok_shield.resources.nft_hook._is_our_dnsmasq", return_value=True),
        mock.patch("terok_shield.resources._oci_state.os.kill") as mock_kill,
    ):
        nft_hook._poststop(sd)

    mock_kill.assert_called_once_with(12345, 15)


def test_poststop_skips_stale_pid(tmp_path: Path) -> None:
    """_poststop() skips signalling and removes the stale PID file on identity mismatch."""
    sd = tmp_path / "sd"
    sd.mkdir()
    pid_file = sd / "dnsmasq.pid"
    pid_file.write_text("12345\n")

    with (
        mock.patch("terok_shield.resources.nft_hook._is_our_dnsmasq", return_value=False),
        mock.patch("terok_shield.resources._oci_state.os.kill") as mock_kill,
    ):
        nft_hook._poststop(sd)

    mock_kill.assert_not_called()
    assert not pid_file.exists(), "stale PID file must be removed when identity check fails"


def test_poststop_ignores_oserror_on_stale_pid_unlink(tmp_path: Path) -> None:
    """_poststop() swallows OSError when removing a stale PID file fails."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "dnsmasq.pid").write_text("12345\n")

    with (
        mock.patch("terok_shield.resources.nft_hook._is_our_dnsmasq", return_value=False),
        mock.patch("terok_shield.resources._oci_state.Path.unlink", side_effect=OSError),
    ):
        nft_hook._poststop(sd)  # must not raise


def test_poststop_is_noop_when_pid_file_absent(tmp_path: Path) -> None:
    """_poststop() does nothing when dnsmasq.pid does not exist."""
    sd = tmp_path / "sd"
    sd.mkdir()
    # No pid file — should not raise
    nft_hook._poststop(sd)


def test_poststop_ignores_oserror_on_kill(tmp_path: Path) -> None:
    """_poststop() swallows OSError from os.kill (process already gone)."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "dnsmasq.pid").write_text("99999\n")

    with (
        mock.patch("terok_shield.resources.nft_hook._is_our_dnsmasq", return_value=True),
        mock.patch(
            "terok_shield.resources._oci_state.os.kill",
            side_effect=OSError,
        ),
    ):
        nft_hook._poststop(sd)  # must not raise


def test_poststop_ignores_invalid_pid_content(tmp_path: Path) -> None:
    """_poststop() swallows ValueError from a non-integer PID file."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "dnsmasq.pid").write_text("not-a-pid\n")

    nft_hook._poststop(sd)  # must not raise


# ── main() ────────────────────────────────────────────────────────────────────


def _run_main(json_str: str, *, stage: str = "createRuntime") -> int:
    """Call nft_hook.main() with mocked argv, stdin, and _log.

    _log is suppressed so error paths do not write real files (its fallback
    path is /tmp/terok-hook-error.log which would escape the tmp_path sandbox).
    """
    with (
        mock.patch("terok_shield.resources.nft_hook.sys.argv", ["hook", stage]),
        mock.patch("terok_shield.resources.nft_hook.sys.stdin", io.StringIO(json_str)),
        mock.patch("terok_shield.resources._oci_state.log"),
    ):
        return nft_hook.main()


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
            json.dumps({"pid": 42, "annotations": {"terok.shield.version": "11"}}),
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
                "terok.shield.version": "12",
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

    with mock.patch("terok_shield.resources.nft_hook._createruntime") as mock_cr:
        rc = _run_main(oci)

    assert rc == 0
    mock_cr.assert_called_once_with("42", sd)


def test_main_persists_container_id(tmp_path: Path) -> None:
    """main() writes the short container ID to state_dir/container.id."""
    sd = tmp_path / "sd"
    sd.mkdir()
    full_id = "abc123def456789abcdef0123456789abcdef0123456789abcdef0123456789a"
    oci = _oci_json(pid=42, state_dir=str(sd), container_id=full_id)

    with mock.patch("terok_shield.resources.nft_hook._createruntime"):
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

    with mock.patch("terok_shield.resources.nft_hook._poststop") as mock_ps:
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

    with mock.patch("terok_shield.resources.nft_hook._poststop") as mock_ps:
        rc = _run_main(oci, stage="poststop")

    assert rc == 0
    mock_ps.assert_called_once_with(sd)


def test_main_returns_1_on_createruntime_exception(tmp_path: Path) -> None:
    """main() returns 1 when _createruntime() raises any exception."""
    sd = tmp_path / "sd"
    sd.mkdir()
    oci = _oci_json(pid=42, state_dir=str(sd))

    with mock.patch(
        "terok_shield.resources.nft_hook._createruntime",
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
                "terok.shield.version": "12",
            },
        }
    )
    assert _run_main(oci) == 1


# ── state_dir hardening (CWE-22 defence-in-depth) ────────────────────────────


class TestStateDirHardening:
    """``state_dir_from_oci`` rejects every shape that isn't a real bundle.

    Treats the OCI annotation as adversarial input.  Each test pins one
    rejection branch — together they keep the door shut against an
    annotation pointing at ``/etc/...``, a non-existent path, a leaf
    symlink, a foreign-uid directory, or a world-writable one.
    """

    def test_rejects_path_under_sensitive_prefix(self) -> None:
        oci = {"annotations": {"terok.shield.state_dir": "/etc/terok-shield"}}
        assert _oci_state.state_dir_from_oci(oci) is None

    def test_rejects_path_resolving_under_sensitive_prefix(self, tmp_path: Path) -> None:
        """A symlink that points into ``/etc`` is rejected after resolve()."""
        link = tmp_path / "evil-link"
        link.symlink_to("/etc")
        oci = {"annotations": {"terok.shield.state_dir": str(link)}}
        assert _oci_state.state_dir_from_oci(oci) is None

    def test_rejects_nonexistent_state_dir(self, tmp_path: Path) -> None:
        """The hook never creates state_dir; pre_start is the only writer."""
        missing = tmp_path / "never-existed"
        oci = {"annotations": {"terok.shield.state_dir": str(missing)}}
        assert _oci_state.state_dir_from_oci(oci) is None

    def test_rejects_state_dir_that_is_a_file(self, tmp_path: Path) -> None:
        f = tmp_path / "not-a-dir"
        f.write_text("")
        oci = {"annotations": {"terok.shield.state_dir": str(f)}}
        assert _oci_state.state_dir_from_oci(oci) is None

    def test_rejects_leaf_symlink(self, tmp_path: Path) -> None:
        """Even a symlink to a valid directory is refused — TOCTOU surface."""
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        oci = {"annotations": {"terok.shield.state_dir": str(link)}}
        assert _oci_state.state_dir_from_oci(oci) is None

    def test_rejects_world_writable_dir(self, tmp_path: Path) -> None:
        """A directory with mode 0o777 is refused — peer-writable bundle."""
        sd = tmp_path / "sd"
        sd.mkdir(mode=0o777)
        sd.chmod(0o777)  # mkdir mode is masked by umask; chmod is exact
        oci = {"annotations": {"terok.shield.state_dir": str(sd)}}
        assert _oci_state.state_dir_from_oci(oci) is None

    def test_rejects_dir_owned_by_other_uid(self, tmp_path: Path) -> None:
        """Directory owned by a different uid is refused.

        We can't actually chown(2) without root, so simulate the mismatch
        by patching ``os.geteuid`` to a value the dir isn't owned by.
        """
        sd = tmp_path / "sd"
        sd.mkdir()
        actual_uid = sd.stat().st_uid
        oci = {"annotations": {"terok.shield.state_dir": str(sd)}}
        with mock.patch.object(_oci_state.os, "geteuid", return_value=actual_uid + 1):
            assert _oci_state.state_dir_from_oci(oci) is None

    def test_accepts_well_formed_state_dir(self, tmp_path: Path) -> None:
        """The happy path still works — owned, mode 0o700, non-symlink."""
        sd = tmp_path / "sd"
        sd.mkdir(mode=0o700)
        sd.chmod(0o700)
        oci = {"annotations": {"terok.shield.state_dir": str(sd)}}
        assert _oci_state.state_dir_from_oci(oci) == sd.resolve()

    def test_rejects_non_string_annotation(self) -> None:
        oci = {"annotations": {"terok.shield.state_dir": 12345}}
        # ``Path(12345)`` raises TypeError; the wrapper catches it.
        assert _oci_state.state_dir_from_oci(oci) is None


# ── log() hardening (CWE-377 symlink-attack defence) ─────────────────────────


class TestLogHardening:
    """``log`` writes safely or not at all — no predictable ``/tmp`` fallback."""

    def test_no_log_path_means_stderr_only(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Errors before state_dir resolution log to stderr, never to disk.

        The pre-fix code wrote to ``/tmp/terok-hook-error.log`` whenever
        ``log_path`` was absent — a predictable name in a world-writable
        directory.  An attacker could pre-create the path as a symlink
        to a sensitive file and have the hook follow it.  We now skip
        the file write entirely when no state-dir-local path is known.
        """
        # ``/tmp/terok-hook-error.log`` must not exist (clean slate)
        # and must not be created by the call.
        sentinel = Path("/tmp/terok-hook-error.log")  # nosec B108 — assertion-only
        existed_before = sentinel.exists()
        _oci_state.log("something failed")
        captured = capsys.readouterr()
        assert "something failed" in captured.err
        assert sentinel.exists() == existed_before, "log() must not write to /tmp"

    def test_appends_to_explicit_log_path(self, tmp_path: Path) -> None:
        log_path = tmp_path / "hook-error.log"
        _oci_state.log("first", log_path)
        _oci_state.log("second", log_path)
        body = log_path.read_text()
        assert "first" in body
        assert "second" in body
        # 0o600 — owner read/write only.
        assert log_path.stat().st_mode & 0o777 == 0o600

    def test_refuses_to_write_through_symlink(self, tmp_path: Path) -> None:
        """``O_NOFOLLOW`` blocks the classic symlink-attack write.

        Mimics the historical ``/tmp`` exploit: a peer pre-creates the
        log path as a symlink to ``/etc/passwd``-equivalent target and
        waits for the hook to follow it.
        """
        target = tmp_path / "sensitive"
        target.write_text("untouched\n")
        link = tmp_path / "log-symlink"
        link.symlink_to(target)
        _oci_state.log("attacker tried to write", link)
        # Target unchanged — O_NOFOLLOW failed the open().
        assert target.read_text() == "untouched\n"

    def test_swallows_fdopen_write_error(self, tmp_path: Path) -> None:
        """A failed write after a successful open() must not propagate."""
        log_path = tmp_path / "hook-error.log"
        with mock.patch.object(_oci_state.os, "fdopen", side_effect=OSError("disk full")):
            _oci_state.log("some failure", log_path)  # must not raise


# ── state_dir hardening — rare error-path coverage ────────────────────────────


class TestStateDirRareErrors:
    """``lstat`` raising OSError on a path that ``resolve()`` accepted is logged + absorbed."""

    def test_lstat_failure_returns_none(self, tmp_path: Path) -> None:
        """A TOCTOU race where the directory vanishes between ``resolve`` and ``lstat``.

        Unlikely but possible: the operator could ``rm -rf`` the state
        bundle between pre_start and the hook firing.  The lstat OSError
        path catches it and bails out without crashing the hook.
        """
        sd = tmp_path / "sd"
        sd.mkdir()
        oci = {"annotations": {"terok.shield.state_dir": str(sd)}}
        with mock.patch.object(_oci_state.Path, "lstat", side_effect=OSError("EIO")):
            assert _oci_state.state_dir_from_oci(oci) is None


def test_main_returns_1_for_unknown_stage(tmp_path: Path) -> None:
    """main() returns 1 for an unrecognised stage and never invokes any handler."""
    sd = tmp_path / "sd"
    sd.mkdir()
    oci = _oci_json(pid=42, state_dir=str(sd))
    with (
        mock.patch("terok_shield.resources.nft_hook._createruntime") as mock_cr,
        mock.patch("terok_shield.resources.nft_hook._poststop") as mock_ps,
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
        "terok_shield.resources.nft_hook._poststop",
        side_effect=RuntimeError("disk full"),
    ):
        assert _run_main(oci, stage="poststop") == 1
