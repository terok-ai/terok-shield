# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the stdlib-only OCI hook entrypoint script.

The script lives at ``src/terok_shield/resources/hook_entrypoint.py`` and is
importable as a regular Python module (``from terok_shield.resources import
hook_entrypoint``) even though it is installed verbatim as a hook binary.
"""

import io
import json
import socket
import struct
from pathlib import Path
from unittest import mock

import pytest

from terok_shield.resources import hook_entrypoint

# ── helpers ──────────────────────────────────────────────────────────────────

# Hex-encoded gateway for 10.0.2.2 as it appears in /proc/{pid}/net/route
# (little-endian uint32: bytes 0A 00 02 02 → stored as 0202000A)
_SLIRP_GW_HEX = format(struct.unpack("<I", socket.inet_aton("10.0.2.2"))[0], "08X")

# Route table header + one default route pointing to 10.0.2.2
_ROUTE_WITH_DEFAULT = (
    "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
    f"eth0\t00000000\t{_SLIRP_GW_HEX}\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
)

# Route table with no default route (pasta mode)
_ROUTE_NO_DEFAULT = (
    "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
    "eth0\t0A000000\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
)


def _oci_json(pid: int = 42, state_dir: str = "/tmp/sd", version: int = 3) -> str:
    """Return a minimal OCI state JSON for hook_entrypoint.main()."""
    return json.dumps(
        {
            "pid": pid,
            "annotations": {
                "terok.shield.state_dir": state_dir,
                "terok.shield.version": str(version),
            },
        }
    )


# ── _find_* helpers ──────────────────────────────────────────────────────────


def test_find_nsenter_uses_which_when_available() -> None:
    """_find_nsenter() returns the path from shutil.which when found."""
    with mock.patch(
        "terok_shield.resources.hook_entrypoint.shutil.which", return_value="/bin/nsenter"
    ):
        assert hook_entrypoint._find_nsenter() == "/bin/nsenter"


def test_find_nsenter_falls_back_to_default() -> None:
    """_find_nsenter() falls back to /usr/bin/nsenter when shutil.which returns None."""
    with mock.patch("terok_shield.resources.hook_entrypoint.shutil.which", return_value=None):
        assert hook_entrypoint._find_nsenter() == "/usr/bin/nsenter"


def test_find_nft_uses_which_when_available() -> None:
    """_find_nft() returns the path from shutil.which when found."""
    with mock.patch(
        "terok_shield.resources.hook_entrypoint.shutil.which", return_value="/usr/bin/nft"
    ):
        assert hook_entrypoint._find_nft() == "/usr/bin/nft"


def test_find_nft_falls_back_to_default() -> None:
    """_find_nft() falls back to /usr/sbin/nft when shutil.which returns None."""
    with mock.patch("terok_shield.resources.hook_entrypoint.shutil.which", return_value=None):
        assert hook_entrypoint._find_nft() == "/usr/sbin/nft"


def test_find_dnsmasq_uses_which_when_available() -> None:
    """_find_dnsmasq() returns the path from shutil.which when found."""
    with mock.patch(
        "terok_shield.resources.hook_entrypoint.shutil.which", return_value="/usr/bin/dnsmasq"
    ):
        assert hook_entrypoint._find_dnsmasq() == "/usr/bin/dnsmasq"


def test_find_dnsmasq_falls_back_to_default() -> None:
    """_find_dnsmasq() falls back to /usr/sbin/dnsmasq when shutil.which returns None."""
    with mock.patch("terok_shield.resources.hook_entrypoint.shutil.which", return_value=None):
        assert hook_entrypoint._find_dnsmasq() == "/usr/sbin/dnsmasq"


def test_find_podman_uses_which_when_available() -> None:
    """_find_podman() returns the path from shutil.which when found."""
    with mock.patch(
        "terok_shield.resources.hook_entrypoint.shutil.which", return_value="/usr/bin/podman"
    ):
        assert hook_entrypoint._find_podman() == "/usr/bin/podman"


def test_find_podman_falls_back_to_default() -> None:
    """_find_podman() falls back to /usr/bin/podman when shutil.which returns None."""
    with mock.patch("terok_shield.resources.hook_entrypoint.shutil.which", return_value=None):
        assert hook_entrypoint._find_podman() == "/usr/bin/podman"


# ── _read_gateway ─────────────────────────────────────────────────────────────


def test_read_gateway_returns_ip_for_default_route(tmp_path: Path) -> None:
    """_read_gateway() parses the default gateway from a slirp4netns routing table."""
    route_file = tmp_path / "route"
    route_file.write_text(_ROUTE_WITH_DEFAULT)

    with mock.patch("terok_shield.resources.hook_entrypoint.Path") as mock_path_cls:
        mock_path_cls.return_value.read_text.return_value = _ROUTE_WITH_DEFAULT
        gw = hook_entrypoint._read_gateway("42")

    assert gw == "10.0.2.2"


def test_read_gateway_returns_empty_when_no_default_route() -> None:
    """_read_gateway() returns '' when there is no default (00000000 destination) route."""
    with mock.patch("terok_shield.resources.hook_entrypoint.Path") as mock_path_cls:
        mock_path_cls.return_value.read_text.return_value = _ROUTE_NO_DEFAULT
        gw = hook_entrypoint._read_gateway("42")

    assert gw == ""


def test_read_gateway_returns_empty_on_oserror() -> None:
    """_read_gateway() returns '' when /proc/{pid}/net/route is unreadable."""
    with mock.patch("terok_shield.resources.hook_entrypoint.Path") as mock_path_cls:
        mock_path_cls.return_value.read_text.side_effect = OSError("no file")
        gw = hook_entrypoint._read_gateway("42")

    assert gw == ""


def test_read_gateway_returns_empty_on_malformed_hex() -> None:
    """_read_gateway() returns '' when the gateway hex is malformed."""
    malformed = "Iface\tDestination\tGateway\neth0\t00000000\tZZZZZZZZ\n"
    with mock.patch("terok_shield.resources.hook_entrypoint.Path") as mock_path_cls:
        mock_path_cls.return_value.read_text.return_value = malformed
        gw = hook_entrypoint._read_gateway("42")

    assert gw == ""


# ── _nsenter ─────────────────────────────────────────────────────────────────


def test_nsenter_runs_subprocess_in_netns() -> None:
    """_nsenter() invokes podman unshare + nsenter inside the container's netns."""
    with mock.patch("terok_shield.resources.hook_entrypoint.subprocess.run") as mock_run:
        with (
            mock.patch(
                "terok_shield.resources.hook_entrypoint._find_podman",
                return_value="/usr/bin/podman",
            ),
            mock.patch(
                "terok_shield.resources.hook_entrypoint._find_nsenter",
                return_value="/usr/bin/nsenter",
            ),
        ):
            hook_entrypoint._nsenter("99", "nft", "-f", "/tmp/r.nft")

    mock_run.assert_called_once_with(
        ["/usr/bin/podman", "unshare", "/usr/bin/nsenter", "-t", "99", "-n", "--", "nft", "-f", "/tmp/r.nft"],
        input=None,
        text=False,
        check=True,
    )


def test_nsenter_passes_stdin_as_text() -> None:
    """_nsenter() passes stdin string and text=True when stdin is provided."""
    with mock.patch("terok_shield.resources.hook_entrypoint.subprocess.run") as mock_run:
        with (
            mock.patch(
                "terok_shield.resources.hook_entrypoint._find_podman",
                return_value="/usr/bin/podman",
            ),
            mock.patch(
                "terok_shield.resources.hook_entrypoint._find_nsenter",
                return_value="/usr/bin/nsenter",
            ),
        ):
            hook_entrypoint._nsenter("99", "nft", "-f", "-", stdin="table inet x {}")

    _, kwargs = mock_run.call_args
    assert kwargs["input"] == "table inet x {}"
    assert kwargs["text"] is True


# ── _createruntime ────────────────────────────────────────────────────────────


def test_createruntime_raises_when_ruleset_missing(tmp_path: Path) -> None:
    """_createruntime() raises RuntimeError when ruleset.nft is absent."""
    sd = tmp_path / "sd"
    sd.mkdir()
    with pytest.raises(RuntimeError, match="ruleset.nft not found"):
        hook_entrypoint._createruntime("42", sd)


def test_createruntime_applies_ruleset_without_gateway(tmp_path: Path) -> None:
    """_createruntime() applies the nft ruleset even when no default gateway is found."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "ruleset.nft").write_text("table inet terok_shield {}")

    with mock.patch("terok_shield.resources.hook_entrypoint._nsenter") as mock_ns:
        with mock.patch("terok_shield.resources.hook_entrypoint._read_gateway", return_value=""):
            hook_entrypoint._createruntime("42", sd)

    # Only one nsenter call — apply the ruleset
    assert mock_ns.call_count == 1
    args = mock_ns.call_args.args
    assert str(sd / "ruleset.nft") in args
    # No gateway file written
    assert not (sd / "gateway").exists()


def test_createruntime_populates_gateway_set_when_discovered(tmp_path: Path) -> None:
    """_createruntime() writes gateway file and adds it to the nft set when found."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "ruleset.nft").write_text("table inet terok_shield {}")

    with mock.patch("terok_shield.resources.hook_entrypoint._nsenter") as mock_ns:
        with mock.patch(
            "terok_shield.resources.hook_entrypoint._read_gateway", return_value="10.0.2.2"
        ):
            with mock.patch(
                "terok_shield.resources.hook_entrypoint._find_nft",
                return_value="/usr/sbin/nft",
            ):
                hook_entrypoint._createruntime("42", sd)

    # Two nsenter calls: apply ruleset + add element to gateway_v4
    assert mock_ns.call_count == 2
    add_call_args = mock_ns.call_args.args
    assert "gateway_v4" in add_call_args
    assert "{ 10.0.2.2 }" in add_call_args

    gw_file = sd / "gateway"
    assert gw_file.exists()
    assert gw_file.read_text().strip() == "10.0.2.2"


def test_createruntime_starts_dnsmasq_when_conf_present(tmp_path: Path) -> None:
    """_createruntime() launches dnsmasq and writes resolv.conf when dnsmasq.conf exists."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "ruleset.nft").write_text("table inet terok_shield {}")
    dnsmasq_conf = sd / "dnsmasq.conf"
    dnsmasq_conf.write_text("[dnsmasq config]")

    # Fake resolv.conf path inside "container"
    fake_resolv = tmp_path / "resolv.conf"
    fake_resolv.write_text("nameserver 1.1.1.1\n")

    with mock.patch("terok_shield.resources.hook_entrypoint._nsenter") as mock_ns:
        with mock.patch("terok_shield.resources.hook_entrypoint._read_gateway", return_value=""):
            with mock.patch(
                "terok_shield.resources.hook_entrypoint.Path",
                side_effect=lambda s: fake_resolv if "resolv.conf" in str(s) else Path(s),
            ):
                hook_entrypoint._createruntime("42", sd)

    # nsenter called twice: apply ruleset + launch dnsmasq
    assert mock_ns.call_count == 2
    dnsmasq_call_args = mock_ns.call_args_list[1].args
    assert any("dnsmasq" in str(a) or "conf-file" in str(a) for a in dnsmasq_call_args)
    assert fake_resolv.read_text() == "nameserver 127.0.0.1\nndots:0\n"


def test_createruntime_ignores_oserror_writing_resolv_conf(tmp_path: Path) -> None:
    """_createruntime() swallows OSError when writing resolv.conf (non-fatal)."""
    sd = tmp_path / "sd"
    sd.mkdir()
    (sd / "ruleset.nft").write_text("table inet terok_shield {}")
    (sd / "dnsmasq.conf").write_text("[dnsmasq config]")

    def _path_side_effect(s: str) -> Path:
        p = Path(s)
        if "resolv.conf" in str(s):
            m = mock.MagicMock(spec=Path)
            m.write_text.side_effect = OSError("read-only")
            return m
        return p

    with mock.patch("terok_shield.resources.hook_entrypoint._nsenter"):
        with mock.patch("terok_shield.resources.hook_entrypoint._read_gateway", return_value=""):
            with mock.patch(
                "terok_shield.resources.hook_entrypoint.Path",
                side_effect=_path_side_effect,
            ):
                hook_entrypoint._createruntime("42", sd)  # must not raise


# ── _is_our_dnsmasq ───────────────────────────────────────────────────────────


def test_is_our_dnsmasq_returns_true_when_cmdline_matches(tmp_path: Path) -> None:
    """_is_our_dnsmasq() returns True when argv[0]=='dnsmasq' and --conf-file= matches."""
    conf = tmp_path / "dnsmasq.conf"
    cmdline = b"dnsmasq\x00--conf-file=" + str(conf).encode() + b"\x00"
    with mock.patch.object(hook_entrypoint.Path, "read_bytes", return_value=cmdline):
        assert hook_entrypoint._is_our_dnsmasq(1234, conf) is True


def test_is_our_dnsmasq_returns_true_for_absolute_path_binary(tmp_path: Path) -> None:
    """_is_our_dnsmasq() returns True when argv[0] is an absolute path ending with /dnsmasq."""
    conf = tmp_path / "dnsmasq.conf"
    cmdline = b"/usr/sbin/dnsmasq\x00--conf-file=" + str(conf).encode() + b"\x00"
    with mock.patch.object(hook_entrypoint.Path, "read_bytes", return_value=cmdline):
        assert hook_entrypoint._is_our_dnsmasq(1234, conf) is True


def test_is_our_dnsmasq_returns_false_when_cmdline_missing(tmp_path: Path) -> None:
    """_is_our_dnsmasq() returns False when /proc/{pid}/cmdline is unreadable."""
    conf = tmp_path / "dnsmasq.conf"
    with mock.patch.object(
        hook_entrypoint.Path,
        "read_bytes",
        side_effect=OSError("no such file"),
    ):
        assert hook_entrypoint._is_our_dnsmasq(9999, conf) is False


def test_is_our_dnsmasq_returns_false_when_conf_path_differs(tmp_path: Path) -> None:
    """_is_our_dnsmasq() returns False when --conf-file= points to a different path."""
    conf = tmp_path / "dnsmasq.conf"
    other_conf = tmp_path / "other" / "dnsmasq.conf"
    cmdline = b"dnsmasq\x00--conf-file=" + str(other_conf).encode() + b"\x00"
    with mock.patch.object(hook_entrypoint.Path, "read_bytes", return_value=cmdline):
        assert hook_entrypoint._is_our_dnsmasq(1234, conf) is False


def test_is_our_dnsmasq_returns_false_when_conf_path_substring(tmp_path: Path) -> None:
    """_is_our_dnsmasq() rejects substring match — exact arg required."""
    conf = tmp_path / "dnsmasq.conf"
    # Embed our conf path inside a longer arg (e.g. --conf-file=/path/prefixed/dnsmasq.conf)
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
    """Call hook_entrypoint.main() with mocked argv and stdin."""
    with mock.patch(
        "terok_shield.resources.hook_entrypoint.sys.argv",
        ["hook", stage],
    ):
        with mock.patch(
            "terok_shield.resources.hook_entrypoint.sys.stdin",
            io.StringIO(json_str),
        ):
            return hook_entrypoint.main()


def test_main_returns_1_for_bad_json() -> None:
    """main() returns 1 when stdin contains invalid JSON."""
    assert _run_main("not json") == 1


def test_main_returns_1_when_oci_is_not_a_dict() -> None:
    """main() returns 1 when the OCI payload is a JSON array instead of an object."""
    assert _run_main("[1, 2, 3]") == 1


def test_main_returns_1_when_annotations_is_not_a_dict() -> None:
    """main() returns 1 when the 'annotations' field is a JSON array instead of an object."""
    oci = json.dumps({"pid": 42, "annotations": ["not", "a", "dict"]})
    assert _run_main(oci) == 1


def test_main_returns_1_when_state_dir_missing() -> None:
    """main() returns 1 when the state_dir annotation is absent."""
    oci = json.dumps({"pid": 42, "annotations": {"terok.shield.version": "3"}})
    assert _run_main(oci) == 1


def test_main_returns_1_on_version_mismatch() -> None:
    """main() returns 1 when the bundle version does not match."""
    oci = json.dumps(
        {
            "pid": 42,
            "annotations": {
                "terok.shield.state_dir": "/tmp/sd",
                "terok.shield.version": "999",
            },
        }
    )
    assert _run_main(oci) == 1


def test_main_returns_1_when_pid_missing_for_createruntime(tmp_path: Path) -> None:
    """main() returns 1 when pid is 0/missing for the createRuntime stage."""
    oci = json.dumps(
        {
            "pid": 0,
            "annotations": {
                "terok.shield.state_dir": str(tmp_path),
                "terok.shield.version": "3",
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


def test_main_dispatches_poststop_and_returns_0(tmp_path: Path) -> None:
    """main() calls _poststop() and returns 0 on success."""
    sd = tmp_path / "sd"
    sd.mkdir()

    oci = _oci_json(pid=0, state_dir=str(sd))

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
                "terok.shield.version": "3",
            },
        }
    )
    assert _run_main(oci) == 1
