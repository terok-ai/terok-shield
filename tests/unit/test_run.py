# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for subprocess helpers."""

import subprocess
from unittest import mock

import pytest

from terok_shield.run import (
    CommandRunner,
    ExecError,
    SubprocessRunner,
)

from ..testfs import NFT_BINARY
from ..testnet import (
    ALIAS_DOMAIN,
    IPV6_CLOUDFLARE,
    NONEXISTENT_DOMAIN,
    TEST_DOMAIN,
    TEST_IP1,
    TEST_IP2,
)


class TestExecError:
    """Tests for ExecError."""

    def test_attributes(self) -> None:
        """Store command, return code, and stderr."""
        err = ExecError(["nft", "list"], 1, "permission denied")
        assert err.cmd == ["nft", "list"]
        assert err.rc == 1
        assert err.stderr == "permission denied"

    def test_message(self) -> None:
        """Format human-readable error message."""
        err = ExecError(["nft"], 2, "  error  ")
        assert "rc=2" in str(err)
        assert "error" in str(err)


class TestSubprocessRunner:
    """Tests for the SubprocessRunner class."""

    @pytest.fixture(autouse=True)
    def _setup_runner(self) -> None:
        """Create a runner instance for each test."""
        self.runner = SubprocessRunner()

    def test_implements_command_runner(self) -> None:
        """SubprocessRunner satisfies the CommandRunner protocol."""
        assert isinstance(self.runner, CommandRunner)

    # ── run() ────────────────────────────────────────────

    @mock.patch("subprocess.run")
    def test_run_returns_stdout(self, mock_run: mock.Mock) -> None:
        """Return stdout on success."""
        mock_run.return_value = mock.Mock(returncode=0, stdout="output\n", stderr="")
        result = self.runner.run(["echo", "hi"])
        assert result == "output\n"

    @mock.patch("subprocess.run")
    def test_run_raises_on_failure(self, mock_run: mock.Mock) -> None:
        """Raise ExecError on non-zero exit."""
        mock_run.return_value = mock.Mock(returncode=1, stdout="", stderr="fail")
        with pytest.raises(ExecError):
            self.runner.run(["false"])

    @mock.patch("subprocess.run")
    def test_run_no_raise_when_check_false(self, mock_run: mock.Mock) -> None:
        """Return stdout without raising when check=False."""
        mock_run.return_value = mock.Mock(returncode=1, stdout="partial", stderr="err")
        result = self.runner.run(["cmd"], check=False)
        assert result == "partial"

    @mock.patch("subprocess.run", side_effect=FileNotFoundError("No such file"))
    def test_run_missing_binary_raises(self, _mock_run: mock.Mock) -> None:
        """Raise ExecError when binary is not found."""
        with pytest.raises(ExecError) as ctx:
            self.runner.run(["nonexistent"])
        assert ctx.value.rc == 127

    @mock.patch("subprocess.run", side_effect=FileNotFoundError("No such file"))
    def test_run_missing_binary_no_check(self, _mock_run: mock.Mock) -> None:
        """Return empty string for missing binary when check=False."""
        result = self.runner.run(["nonexistent"], check=False)
        assert result == ""

    @mock.patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(["slow-cmd"], 5),
    )
    def test_run_timeout_raises_exec_error(self, _mock_run: mock.Mock) -> None:
        """TimeoutExpired raises ExecError with rc=-1 when check=True."""
        with pytest.raises(ExecError) as ctx:
            self.runner.run(["slow-cmd"], timeout=5)
        assert ctx.value.rc == -1
        assert "timed out" in ctx.value.stderr

    @mock.patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(["slow-cmd"], 5),
    )
    def test_run_timeout_returns_empty_no_check(self, _mock_run: mock.Mock) -> None:
        """TimeoutExpired returns empty string when check=False."""
        result = self.runner.run(["slow-cmd"], check=False, timeout=5)
        assert result == ""

    # ── has() ────────────────────────────────────────────

    @mock.patch("shutil.which", return_value=NFT_BINARY)
    def test_has_found(self, _: mock.Mock) -> None:
        """Return True when executable is found."""
        assert self.runner.has("nft")

    @mock.patch("shutil.which", return_value=None)
    def test_has_not_found(self, _: mock.Mock) -> None:
        """Return False when executable is not found."""
        assert not self.runner.has("nonexistent")

    # ── nft() ────────────────────────────────────────────

    @mock.patch("subprocess.run")
    def test_nft_with_args(self, mock_run: mock.Mock) -> None:
        """Pass arguments directly to nft."""
        mock_run.return_value = mock.Mock(returncode=0, stdout="output", stderr="")
        result = self.runner.nft("list", "ruleset")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd == ["nft", "list", "ruleset"]
        assert result == "output"

    @mock.patch("subprocess.run")
    def test_nft_with_stdin(self, mock_run: mock.Mock) -> None:
        """Pipe rules on stdin, preserving extra args."""
        mock_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        self.runner.nft("-c", stdin="table ip test {}")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd == ["nft", "-c", "-f", "-"]
        assert mock_run.call_args[1]["input"] == "table ip test {}"

    @mock.patch("subprocess.run")
    def test_nft_stdin_no_args(self, mock_run: mock.Mock) -> None:
        """Pipe rules on stdin without extra args."""
        mock_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        self.runner.nft(stdin="table ip test {}")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd == ["nft", "-f", "-"]
        assert mock_run.call_args[1]["input"] == "table ip test {}"

    # ── nft_via_nsenter() ────────────────────────────────

    @mock.patch("subprocess.run")
    def test_nft_via_nsenter_enters_netns(self, mock_run: mock.Mock) -> None:
        """Look up container PID and nsenter into its network namespace."""
        mock_run.side_effect = [
            mock.Mock(returncode=0, stdout="12345\n", stderr=""),
            mock.Mock(returncode=0, stdout="output", stderr=""),
        ]
        result = self.runner.nft_via_nsenter("my-ctr", "list", "ruleset")
        assert mock_run.call_count == 2
        assert "podman" in mock_run.call_args_list[0][0][0]
        nsenter_cmd = mock_run.call_args_list[1][0][0]
        assert "nsenter" in nsenter_cmd
        assert "12345" in nsenter_cmd
        assert result == "output"

    @mock.patch("subprocess.run")
    def test_nft_via_nsenter_explicit_pid(self, mock_run: mock.Mock) -> None:
        """Skip podman inspect when pid is provided directly."""
        mock_run.return_value = mock.Mock(returncode=0, stdout="output", stderr="")
        result = self.runner.nft_via_nsenter("my-ctr", "list", "ruleset", pid="999")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "999" in cmd
        assert result == "output"

    @mock.patch("subprocess.run")
    def test_nft_via_nsenter_stdin(self, mock_run: mock.Mock) -> None:
        """Pass stdin through to nft -f -."""
        mock_run.side_effect = [
            mock.Mock(returncode=0, stdout="12345\n", stderr=""),
            mock.Mock(returncode=0, stdout="", stderr=""),
        ]
        self.runner.nft_via_nsenter("my-ctr", stdin="flush ruleset")
        nsenter_call = mock_run.call_args_list[1]
        assert "-f" in nsenter_call[0][0]
        assert nsenter_call[1]["input"] == "flush ruleset"

    # ── podman_inspect() ─────────────────────────────────

    @mock.patch("subprocess.run")
    def test_podman_inspect(self, mock_run: mock.Mock) -> None:
        """Return stripped inspect output."""
        mock_run.return_value = mock.Mock(returncode=0, stdout="  12345  \n", stderr="")
        result = self.runner.podman_inspect("my-ctr", "{{.State.Pid}}")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd == ["podman", "inspect", "--format", "{{.State.Pid}}", "my-ctr"]
        assert result == "12345"

    # ── dig_all() ────────────────────────────────────────

    @mock.patch("subprocess.run")
    def test_dig_all_returns_v4_and_v6(self, mock_run: mock.Mock) -> None:
        """Extract both IPv4 and IPv6 addresses from combined dig output."""
        mock_run.return_value = mock.Mock(
            returncode=0,
            stdout=f"{TEST_IP1}\n{TEST_IP2}\n{IPV6_CLOUDFLARE}\n",
            stderr="",
        )
        result = self.runner.dig_all(TEST_DOMAIN)
        assert result == [TEST_IP1, TEST_IP2, IPV6_CLOUDFLARE]

    @mock.patch("subprocess.run")
    def test_dig_all_filters_non_ip(self, mock_run: mock.Mock) -> None:
        """Filter out CNAME and other non-IP lines."""
        mock_run.return_value = mock.Mock(
            returncode=0,
            stdout=f"{ALIAS_DOMAIN}\n{TEST_IP1}\n{IPV6_CLOUDFLARE}\n",
            stderr="",
        )
        result = self.runner.dig_all(TEST_DOMAIN)
        assert result == [TEST_IP1, IPV6_CLOUDFLARE]

    @mock.patch("subprocess.run")
    def test_dig_all_empty_on_failure(self, mock_run: mock.Mock) -> None:
        """Return empty list when dig returns empty (check=False)."""
        mock_run.return_value = mock.Mock(returncode=1, stdout="", stderr="")
        result = self.runner.dig_all(NONEXISTENT_DOMAIN)
        assert result == []

    @mock.patch("subprocess.run", side_effect=FileNotFoundError("dig not found"))
    def test_dig_all_empty_on_missing_binary(self, _mock_run: mock.Mock) -> None:
        """Return empty list when dig binary is missing."""
        result = self.runner.dig_all(TEST_DOMAIN)
        assert result == []

    @mock.patch("subprocess.run")
    def test_dig_all_single_query(self, mock_run: mock.Mock) -> None:
        """Uses a single dig subprocess with both A and AAAA queries."""
        mock_run.return_value = mock.Mock(
            returncode=0,
            stdout=f"{TEST_IP1}\n",
            stderr="",
        )
        self.runner.dig_all(TEST_DOMAIN)
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "A" in cmd
        assert "AAAA" in cmd

    @mock.patch("subprocess.run")
    def test_dig_all_skips_blank_lines(self, mock_run: mock.Mock) -> None:
        """Skip blank lines in dig output."""
        mock_run.return_value = mock.Mock(
            returncode=0,
            stdout=f"\n{TEST_IP1}\n\n{TEST_IP2}\n\n",
            stderr="",
        )
        result = self.runner.dig_all(TEST_DOMAIN)
        assert result == [TEST_IP1, TEST_IP2]
