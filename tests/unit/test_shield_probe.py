# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the shield_probe ICMP diagnostic tool."""

import json
import struct
from unittest.mock import MagicMock, patch

from terok_shield.resources.shield_probe import (
    _ICMP_UNREACH_CODES,
    _SO_EE_ORIGIN_ICMP,
    _SOCK_EE_FMT,
    _SOL_IP,
    main,
    probe,
)

from ..testnet import TEST_IP1


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
    """Build ancillary data list as returned by recvmsg."""
    from terok_shield.resources.shield_probe import _IP_RECVERR

    return [(_SOL_IP, _IP_RECVERR, _make_sock_ee(ee_errno, ee_origin, ee_type, ee_code))]


def _mock_probe(poll_returns, recvmsg_result=None, send_side_effect=None) -> dict:
    """Run probe() with mocked socket and poll.

    Args:
        poll_returns: List of return values for successive poll() calls.
        recvmsg_result: Tuple (data, ancdata, flags, addr) for recvmsg.
        send_side_effect: Side effect for sock.send (e.g. [None, OSError]).
    """
    mock_sock = MagicMock()
    mock_poller = MagicMock()
    mock_poller.poll = MagicMock(side_effect=poll_returns)

    if recvmsg_result is not None:
        mock_sock.recvmsg.return_value = recvmsg_result
    if send_side_effect is not None:
        mock_sock.send.side_effect = send_side_effect

    with patch("terok_shield.resources.shield_probe.socket.socket", return_value=mock_sock):
        with patch("terok_shield.resources.shield_probe.select.poll", return_value=mock_poller):
            return probe(TEST_IP1, 443, timeout=1.0)


# ── Mocked tests for core probe paths ─────────────────────────────────


class TestProbeMockedPaths:
    """Mocked equivalents of the real-socket tests (work on any platform)."""

    def test_port_unreachable(self) -> None:
        """Poll detects error; recvmsg returns ICMP type=3 code=3 (port-unreachable)."""
        ancdata = _make_ancdata(111, _SO_EE_ORIGIN_ICMP, 3, 3)
        result = _mock_probe(
            poll_returns=[[(0, 8)]],
            recvmsg_result=(b"\x00", ancdata, 0, (TEST_IP1, 443)),
        )
        assert result["result"] == "icmp-error"
        assert result["icmp_code"] == 3
        assert result["icmp_code_name"] == "port-unreachable"

    def test_open_no_error(self) -> None:
        """No poll events; second send succeeds → port is open."""
        result = _mock_probe(
            poll_returns=[[]],
            send_side_effect=[None, None],  # first send OK, second send OK
        )
        assert result["result"] == "open"

    def test_timeout_no_response(self) -> None:
        """No poll events; second send raises OSError; second poll empty → timeout."""
        result = _mock_probe(
            poll_returns=[[], []],
            send_side_effect=[None, OSError("connection refused")],
        )
        assert result["result"] == "timeout"


# ── Mocked tests for edge cases ────────────────────────────────────────


class TestProbeEdgeCases:
    """Test probe() branches that cannot be triggered with real sockets."""

    def test_icmp_admin_prohibited(self) -> None:
        """Detect ICMP admin-prohibited (code 13)."""
        ancdata = _make_ancdata(113, _SO_EE_ORIGIN_ICMP, 3, 13)
        result = _mock_probe(
            poll_returns=[[(0, 8)]],
            recvmsg_result=(b"\x00", ancdata, 0, (TEST_IP1, 443)),
        )
        assert result["result"] == "icmp-error"
        assert result["icmp_code"] == 13
        assert result["icmp_code_name"] == "admin-prohibited"

    def test_icmp_unknown_code(self) -> None:
        """Unknown ICMP code falls back to 'code-N' naming."""
        ancdata = _make_ancdata(113, _SO_EE_ORIGIN_ICMP, 3, 99)
        result = _mock_probe(
            poll_returns=[[(0, 8)]],
            recvmsg_result=(b"\x00", ancdata, 0, (TEST_IP1, 443)),
        )
        assert result["icmp_code_name"] == "code-99"

    def test_timeout_recvmsg_fails(self) -> None:
        """OSError on recvmsg returns timeout."""
        mock_sock = MagicMock()
        mock_sock.recvmsg.side_effect = OSError("queue empty")
        mock_poller = MagicMock()
        mock_poller.poll = MagicMock(return_value=[(0, 8)])

        with patch("terok_shield.resources.shield_probe.socket.socket", return_value=mock_sock):
            with patch("terok_shield.resources.shield_probe.select.poll", return_value=mock_poller):
                result = probe(TEST_IP1, 443, timeout=1.0)
        assert result["result"] == "timeout"

    def test_ancdata_too_short(self) -> None:
        """Truncated ancdata is skipped, falls through to timeout."""
        from terok_shield.resources.shield_probe import _IP_RECVERR

        short_ancdata = [(_SOL_IP, _IP_RECVERR, b"\x00\x01")]
        result = _mock_probe(
            poll_returns=[[(0, 8)]],
            recvmsg_result=(b"\x00", short_ancdata, 0, (TEST_IP1, 443)),
        )
        assert result["result"] == "timeout"

    def test_non_icmp_origin(self) -> None:
        """Non-ICMP origin (e.g. LOCAL) is skipped."""
        ancdata = _make_ancdata(113, 1, 3, 13)  # origin=1 (LOCAL), not ICMP
        result = _mock_probe(
            poll_returns=[[(0, 8)]],
            recvmsg_result=(b"\x00", ancdata, 0, (TEST_IP1, 443)),
        )
        assert result["result"] == "timeout"

    def test_first_send_oserror_still_detects_icmp(self) -> None:
        """OSError on first send does not prevent ICMP detection."""
        ancdata = _make_ancdata(111, _SO_EE_ORIGIN_ICMP, 3, 3)
        result = _mock_probe(
            poll_returns=[[(0, 8)]],
            recvmsg_result=(b"\x00", ancdata, 0, (TEST_IP1, 443)),
            send_side_effect=OSError("send failed"),
        )
        assert result["result"] == "icmp-error"
        assert result["icmp_code"] == 3


# ── CLI main() tests ──────────────────────────────────────────────────


class TestMain:
    """Test the main() CLI entry point."""

    def test_usage_error(self) -> None:
        """No arguments prints usage and returns 1."""
        with patch("sys.argv", ["shield_probe.py"]):
            assert main() == 1

    def test_success_default_port(
        self,
    ) -> None:
        """Valid host uses default port 443."""
        with patch("sys.argv", ["shield_probe.py", TEST_IP1]):
            with patch(
                "terok_shield.resources.shield_probe.probe",
                return_value={"host": TEST_IP1, "port": 443, "result": "open"},
            ) as mock_probe:
                assert main() == 0
                mock_probe.assert_called_once_with(TEST_IP1, 443)

    def test_custom_port(self) -> None:
        """Custom port is parsed from argv."""
        with patch("sys.argv", ["shield_probe.py", TEST_IP1, "80"]):
            with patch(
                "terok_shield.resources.shield_probe.probe",
                return_value={"host": TEST_IP1, "port": 80, "result": "open"},
            ) as mock_probe:
                assert main() == 0
                mock_probe.assert_called_once_with(TEST_IP1, 80)

    def test_invalid_port(self) -> None:
        """Non-integer port returns 1 with error JSON."""
        with patch("sys.argv", ["shield_probe.py", TEST_IP1, "abc"]):
            with patch("builtins.print") as mock_print:
                assert main() == 1
                output = json.loads(mock_print.call_args[0][0])
                assert "invalid port" in output["error"]

    def test_probe_exception(self) -> None:
        """Exception in probe returns 1 with error JSON."""
        with patch("sys.argv", ["shield_probe.py", TEST_IP1]):
            with patch(
                "terok_shield.resources.shield_probe.probe",
                side_effect=RuntimeError("boom"),
            ):
                assert main() == 1

    def test_output_is_json(self) -> None:
        """Successful probe outputs valid JSON to stdout."""
        expected = {"host": TEST_IP1, "port": 443, "result": "timeout"}
        with patch("sys.argv", ["shield_probe.py", TEST_IP1]):
            with patch("terok_shield.resources.shield_probe.probe", return_value=expected):
                with patch("builtins.print") as mock_print:
                    main()
                    output = mock_print.call_args[0][0]
                    assert json.loads(output) == expected


# ── Constants sanity checks ───────────────────────────────────────────


class TestConstants:
    """Verify ICMP code table has expected entries."""

    def test_admin_prohibited_in_table(self) -> None:
        """Code 13 maps to admin-prohibited."""
        assert _ICMP_UNREACH_CODES[13] == "admin-prohibited"

    def test_port_unreachable_in_table(self) -> None:
        """Code 3 maps to port-unreachable."""
        assert _ICMP_UNREACH_CODES[3] == "port-unreachable"
