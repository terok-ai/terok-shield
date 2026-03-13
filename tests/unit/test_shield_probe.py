# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the shield_probe ICMP diagnostic tool."""

import json
import struct
from collections.abc import Callable, Iterator
from unittest.mock import MagicMock, patch

import pytest

from terok_shield.resources.shield_probe import (
    _ICMP_UNREACH_CODES,
    _SO_EE_ORIGIN_ICMP,
    _SOCK_EE_FMT,
    _SOL_IP,
    main,
    probe,
)

from ..testnet import TEST_IP1

ProbeResultFactory = Callable[..., dict[str, object]]


def _run_probe(mock_sock: MagicMock, mock_poller: MagicMock) -> dict[str, object]:
    """Run probe() with patched socket and poll collaborators."""
    with patch("terok_shield.resources.shield_probe.socket.socket", return_value=mock_sock):
        with patch("terok_shield.resources.shield_probe.select.poll", return_value=mock_poller):
            return probe(TEST_IP1, 443, timeout=1.0)


@pytest.fixture
def make_probe_result() -> Iterator[ProbeResultFactory]:
    """Return a helper that runs probe() with mocked socket/poll collaborators."""

    def _make_probe_result(
        poll_returns: list[list[tuple[int, int]]],
        *,
        recvmsg_result: tuple[bytes, list, int, tuple[str, int]] | None = None,
        send_side_effect: object | None = None,
    ) -> dict:
        mock_sock = MagicMock()
        mock_poller = MagicMock()
        mock_poller.poll = MagicMock(side_effect=poll_returns)
        if recvmsg_result is not None:
            mock_sock.recvmsg.return_value = recvmsg_result
        if send_side_effect is not None:
            mock_sock.send.side_effect = send_side_effect

        return _run_probe(mock_sock, mock_poller)

    yield _make_probe_result


def _make_sock_ee(
    ee_errno: int,
    ee_origin: int,
    ee_type: int,
    ee_code: int,
    ee_info: int = 0,
    ee_data: int = 0,
) -> bytes:
    """Build a binary sock_extended_err struct."""
    return struct.pack(_SOCK_EE_FMT, ee_errno, ee_origin, ee_type, ee_code, ee_info, ee_data)


def _make_ancdata(ee_errno: int, ee_origin: int, ee_type: int, ee_code: int) -> list:
    """Build the ancillary data list returned by recvmsg()."""
    from terok_shield.resources.shield_probe import _IP_RECVERR

    return [(_SOL_IP, _IP_RECVERR, _make_sock_ee(ee_errno, ee_origin, ee_type, ee_code))]


@pytest.mark.parametrize(
    ("poll_returns", "recvmsg_result", "send_side_effect", "expected"),
    [
        pytest.param(
            [[(0, 8)]],
            (b"\x00", _make_ancdata(111, _SO_EE_ORIGIN_ICMP, 3, 3), 0, (TEST_IP1, 443)),
            None,
            {"result": "icmp-error", "icmp_code": 3, "icmp_code_name": "port-unreachable"},
            id="port-unreachable",
        ),
        pytest.param(
            [[]],
            None,
            [None, None],
            {"result": "open"},
            id="open-no-error",
        ),
        pytest.param(
            [[], []],
            None,
            [None, OSError("connection refused")],
            {"result": "timeout"},
            id="timeout-no-response",
        ),
        pytest.param(
            [[(0, 8)]],
            (b"\x00", _make_ancdata(113, _SO_EE_ORIGIN_ICMP, 3, 13), 0, (TEST_IP1, 443)),
            None,
            {"result": "icmp-error", "icmp_code": 13, "icmp_code_name": "admin-prohibited"},
            id="admin-prohibited",
        ),
        pytest.param(
            [[(0, 8)]],
            (b"\x00", _make_ancdata(113, _SO_EE_ORIGIN_ICMP, 3, 99), 0, (TEST_IP1, 443)),
            None,
            {"icmp_code_name": "code-99"},
            id="unknown-icmp-code",
        ),
        pytest.param(
            [[(0, 8)]],
            (b"\x00", _make_ancdata(111, _SO_EE_ORIGIN_ICMP, 3, 3), 0, (TEST_IP1, 443)),
            OSError("send failed"),
            {"result": "icmp-error", "icmp_code": 3},
            id="first-send-error-still-detects-icmp",
        ),
    ],
)
def test_probe_mocked_paths(
    make_probe_result: ProbeResultFactory,
    poll_returns: list[list[tuple[int, int]]],
    recvmsg_result: tuple[bytes, list, int, tuple[str, int]] | None,
    send_side_effect: object | None,
    expected: dict[str, object],
) -> None:
    """probe() follows the expected success, ICMP, and timeout paths."""
    result = make_probe_result(
        poll_returns,
        recvmsg_result=recvmsg_result,
        send_side_effect=send_side_effect,
    )
    for key, value in expected.items():
        assert result[key] == value


def test_probe_returns_timeout_when_recvmsg_fails() -> None:
    """recvmsg() errors are treated as timeouts."""
    mock_sock = MagicMock()
    mock_sock.recvmsg.side_effect = OSError("queue empty")
    mock_poller = MagicMock()
    mock_poller.poll.return_value = [(0, 8)]

    assert _run_probe(mock_sock, mock_poller)["result"] == "timeout"


def test_probe_skips_truncated_ancdata(make_probe_result: ProbeResultFactory) -> None:
    """Truncated ancillary data is ignored and falls back to timeout."""
    from terok_shield.resources.shield_probe import _IP_RECVERR

    result = make_probe_result(
        [[(0, 8)]],
        recvmsg_result=(b"\x00", [(_SOL_IP, _IP_RECVERR, b"\x00\x01")], 0, (TEST_IP1, 443)),
    )
    assert result["result"] == "timeout"


def test_probe_skips_non_icmp_origin(make_probe_result: ProbeResultFactory) -> None:
    """Only ICMP-origin error queue entries are interpreted."""
    result = make_probe_result(
        [[(0, 8)]],
        recvmsg_result=(b"\x00", _make_ancdata(113, 1, 3, 13), 0, (TEST_IP1, 443)),
    )
    assert result["result"] == "timeout"


@pytest.mark.parametrize(
    ("argv", "probe_result", "expected_rc", "expected_probe_args", "expected_output"),
    [
        pytest.param(["shield_probe.py"], None, 1, None, "Usage:", id="usage-error"),
        pytest.param(
            ["shield_probe.py", TEST_IP1],
            {"host": TEST_IP1, "port": 443, "result": "open"},
            0,
            (TEST_IP1, 443),
            {"host": TEST_IP1, "port": 443, "result": "open"},
            id="default-port",
        ),
        pytest.param(
            ["shield_probe.py", TEST_IP1, "80"],
            {"host": TEST_IP1, "port": 80, "result": "open"},
            0,
            (TEST_IP1, 80),
            {"host": TEST_IP1, "port": 80, "result": "open"},
            id="custom-port",
        ),
        pytest.param(
            ["shield_probe.py", TEST_IP1, "abc"],
            None,
            1,
            None,
            {"error": "invalid port: 'abc'"},
            id="invalid-port",
        ),
    ],
)
def test_main_outputs_expected_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    probe_result: dict[str, object] | None,
    expected_rc: int,
    expected_probe_args: tuple[str, int] | None,
    expected_output: str | dict[str, object],
) -> None:
    """main() prints usage or JSON output for success and argument errors."""
    monkeypatch.setattr("sys.argv", argv)
    if probe_result is None:
        rc = main()
    else:
        mock_probe = MagicMock(return_value=probe_result)
        monkeypatch.setattr("terok_shield.resources.shield_probe.probe", mock_probe)
        rc = main()
        mock_probe.assert_called_once_with(*expected_probe_args)

    captured = capsys.readouterr()
    assert rc == expected_rc
    if isinstance(expected_output, str):
        assert expected_output in captured.err
    else:
        assert json.loads(captured.out) == expected_output


def test_main_handles_probe_exceptions(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Unexpected probe exceptions are reported as JSON errors."""
    monkeypatch.setattr("sys.argv", ["shield_probe.py", TEST_IP1])
    monkeypatch.setattr(
        "terok_shield.resources.shield_probe.probe",
        MagicMock(side_effect=RuntimeError("boom")),
    )
    assert main() == 1
    assert json.loads(capsys.readouterr().out)["error"] == "boom"


@pytest.mark.parametrize(
    ("code", "label"),
    [
        pytest.param(13, "admin-prohibited", id="admin-prohibited"),
        pytest.param(3, "port-unreachable", id="port-unreachable"),
    ],
)
def test_icmp_code_table(code: int, label: str) -> None:
    """The ICMP unreachable code table contains the expected well-known labels."""
    assert _ICMP_UNREACH_CODES[code] == label
