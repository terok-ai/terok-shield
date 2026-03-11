# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for subprocess helpers."""

import subprocess
import unittest
import unittest.mock

from terok_shield.run import (
    ExecError,
    SubprocessRunner,
    dig_all,
    has,
    nft,
    nft_via_nsenter,
    podman_inspect,
    run,
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


class TestExecError(unittest.TestCase):
    """Tests for ExecError."""

    def test_attributes(self) -> None:
        """Store command, return code, and stderr."""
        err = ExecError(["nft", "list"], 1, "permission denied")
        self.assertEqual(err.cmd, ["nft", "list"])
        self.assertEqual(err.rc, 1)
        self.assertEqual(err.stderr, "permission denied")

    def test_message(self) -> None:
        """Format human-readable error message."""
        err = ExecError(["nft"], 2, "  error  ")
        self.assertIn("rc=2", str(err))
        self.assertIn("error", str(err))


class TestRun(unittest.TestCase):
    """Tests for run()."""

    @unittest.mock.patch("subprocess.run")
    def test_returns_stdout(self, mock_run: unittest.mock.Mock) -> None:
        """Return stdout on success."""
        mock_run.return_value = unittest.mock.Mock(returncode=0, stdout="output\n", stderr="")
        result = run(["echo", "hi"])
        self.assertEqual(result, "output\n")

    @unittest.mock.patch("subprocess.run")
    def test_raises_on_failure(self, mock_run: unittest.mock.Mock) -> None:
        """Raise ExecError on non-zero exit."""
        mock_run.return_value = unittest.mock.Mock(returncode=1, stdout="", stderr="fail")
        with self.assertRaises(ExecError):
            run(["false"])

    @unittest.mock.patch("subprocess.run")
    def test_no_raise_when_check_false(self, mock_run: unittest.mock.Mock) -> None:
        """Return stdout without raising when check=False."""
        mock_run.return_value = unittest.mock.Mock(returncode=1, stdout="partial", stderr="err")
        result = run(["cmd"], check=False)
        self.assertEqual(result, "partial")

    @unittest.mock.patch("subprocess.run", side_effect=FileNotFoundError("No such file"))
    def test_missing_binary_raises(self, _mock_run: unittest.mock.Mock) -> None:
        """Raise ExecError when binary is not found."""
        with self.assertRaises(ExecError) as ctx:
            run(["nonexistent"])
        self.assertEqual(ctx.exception.rc, 127)

    @unittest.mock.patch("subprocess.run", side_effect=FileNotFoundError("No such file"))
    def test_missing_binary_no_check(self, _mock_run: unittest.mock.Mock) -> None:
        """Return empty string for missing binary when check=False."""
        result = run(["nonexistent"], check=False)
        self.assertEqual(result, "")


class TestHas(unittest.TestCase):
    """Tests for has()."""

    @unittest.mock.patch("shutil.which", return_value=NFT_BINARY)
    def test_found(self, _: unittest.mock.Mock) -> None:
        """Return True when executable is found."""
        self.assertTrue(has("nft"))

    @unittest.mock.patch("shutil.which", return_value=None)
    def test_not_found(self, _: unittest.mock.Mock) -> None:
        """Return False when executable is not found."""
        self.assertFalse(has("nonexistent"))


class TestNft(unittest.TestCase):
    """Tests for nft wrapper."""

    @unittest.mock.patch("subprocess.run")
    def test_nft_with_args(self, mock_run: unittest.mock.Mock) -> None:
        """Pass arguments directly to nft."""
        mock_run.return_value = unittest.mock.Mock(returncode=0, stdout="output", stderr="")
        result = nft("list", "ruleset")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd, ["nft", "list", "ruleset"])
        self.assertEqual(result, "output")

    @unittest.mock.patch("subprocess.run")
    def test_nft_with_stdin(self, mock_run: unittest.mock.Mock) -> None:
        """Pipe rules on stdin, preserving extra args."""
        mock_run.return_value = unittest.mock.Mock(returncode=0, stdout="", stderr="")
        nft("-c", stdin="table ip test {}")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd, ["nft", "-c", "-f", "-"])
        self.assertEqual(mock_run.call_args[1]["input"], "table ip test {}")

    @unittest.mock.patch("subprocess.run")
    def test_nft_stdin_no_args(self, mock_run: unittest.mock.Mock) -> None:
        """Pipe rules on stdin without extra args."""
        mock_run.return_value = unittest.mock.Mock(returncode=0, stdout="", stderr="")
        nft(stdin="table ip test {}")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd, ["nft", "-f", "-"])
        self.assertEqual(mock_run.call_args[1]["input"], "table ip test {}")


class TestNftViaNsenter(unittest.TestCase):
    """Tests for nft_via_nsenter wrapper."""

    @unittest.mock.patch("subprocess.run")
    def test_enters_container_netns(self, mock_run: unittest.mock.Mock) -> None:
        """Look up container PID and nsenter into its network namespace."""
        mock_run.side_effect = [
            unittest.mock.Mock(returncode=0, stdout="12345\n", stderr=""),
            unittest.mock.Mock(returncode=0, stdout="output", stderr=""),
        ]
        result = nft_via_nsenter("my-ctr", "list", "ruleset")
        self.assertEqual(mock_run.call_count, 2)
        # First call: podman inspect
        self.assertIn("podman", mock_run.call_args_list[0][0][0])
        # Second call: nsenter
        nsenter_cmd = mock_run.call_args_list[1][0][0]
        self.assertIn("nsenter", nsenter_cmd)
        self.assertIn("12345", nsenter_cmd)
        self.assertEqual(result, "output")

    @unittest.mock.patch("subprocess.run")
    def test_explicit_pid_skips_inspect(self, mock_run: unittest.mock.Mock) -> None:
        """Skip podman inspect when pid is provided directly."""
        mock_run.return_value = unittest.mock.Mock(returncode=0, stdout="output", stderr="")
        result = nft_via_nsenter("my-ctr", "list", "ruleset", pid="999")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        self.assertIn("999", cmd)
        self.assertEqual(result, "output")

    @unittest.mock.patch("subprocess.run")
    def test_stdin_support(self, mock_run: unittest.mock.Mock) -> None:
        """Pass stdin through to nft -f -."""
        mock_run.side_effect = [
            unittest.mock.Mock(returncode=0, stdout="12345\n", stderr=""),
            unittest.mock.Mock(returncode=0, stdout="", stderr=""),
        ]
        nft_via_nsenter("my-ctr", stdin="flush ruleset")
        nsenter_call = mock_run.call_args_list[1]
        self.assertIn("-f", nsenter_call[0][0])
        self.assertEqual(nsenter_call[1]["input"], "flush ruleset")


class TestPodmanInspect(unittest.TestCase):
    """Tests for podman_inspect wrapper."""

    @unittest.mock.patch("subprocess.run")
    def test_returns_stripped_output(self, mock_run: unittest.mock.Mock) -> None:
        """Return stripped inspect output."""
        mock_run.return_value = unittest.mock.Mock(returncode=0, stdout="  12345  \n", stderr="")
        result = podman_inspect("my-ctr", "{{.State.Pid}}")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd, ["podman", "inspect", "--format", "{{.State.Pid}}", "my-ctr"])
        self.assertEqual(result, "12345")


class TestDigAll(unittest.TestCase):
    """Tests for dig_all() -- single-query dual-stack DNS resolution."""

    @unittest.mock.patch("subprocess.run")
    def test_returns_v4_and_v6(self, mock_run: unittest.mock.Mock) -> None:
        """Extract both IPv4 and IPv6 addresses from combined dig output."""
        mock_run.return_value = unittest.mock.Mock(
            returncode=0,
            stdout=f"{TEST_IP1}\n{TEST_IP2}\n{IPV6_CLOUDFLARE}\n",
            stderr="",
        )
        result = dig_all(TEST_DOMAIN)
        self.assertEqual(result, [TEST_IP1, TEST_IP2, IPV6_CLOUDFLARE])

    @unittest.mock.patch("subprocess.run")
    def test_filters_non_ip(self, mock_run: unittest.mock.Mock) -> None:
        """Filter out CNAME and other non-IP lines."""
        mock_run.return_value = unittest.mock.Mock(
            returncode=0,
            stdout=f"{ALIAS_DOMAIN}\n{TEST_IP1}\n{IPV6_CLOUDFLARE}\n",
            stderr="",
        )
        result = dig_all(TEST_DOMAIN)
        self.assertEqual(result, [TEST_IP1, IPV6_CLOUDFLARE])

    @unittest.mock.patch("subprocess.run")
    def test_empty_on_failure(self, mock_run: unittest.mock.Mock) -> None:
        """Return empty list when dig returns empty (check=False)."""
        mock_run.return_value = unittest.mock.Mock(returncode=1, stdout="", stderr="")
        result = dig_all(NONEXISTENT_DOMAIN)
        self.assertEqual(result, [])

    @unittest.mock.patch("subprocess.run", side_effect=FileNotFoundError("dig not found"))
    def test_empty_on_missing_binary(self, _mock_run: unittest.mock.Mock) -> None:
        """Return empty list when dig binary is missing."""
        result = dig_all(TEST_DOMAIN)
        self.assertEqual(result, [])

    @unittest.mock.patch("subprocess.run")
    def test_single_query_call(self, mock_run: unittest.mock.Mock) -> None:
        """Uses a single dig subprocess with both A and AAAA queries."""
        mock_run.return_value = unittest.mock.Mock(
            returncode=0,
            stdout=f"{TEST_IP1}\n",
            stderr="",
        )
        dig_all(TEST_DOMAIN)
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        self.assertIn("A", cmd)
        self.assertIn("AAAA", cmd)


class TestTimeoutHandling(unittest.TestCase):
    """Tests for timeout exception handling."""

    @unittest.mock.patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(["slow-cmd"], 5),
    )
    def test_timeout_raises_exec_error(self, _mock_run: unittest.mock.Mock) -> None:
        """TimeoutExpired raises ExecError with rc=-1 when check=True."""
        with self.assertRaises(ExecError) as ctx:
            run(["slow-cmd"], timeout=5)
        self.assertEqual(ctx.exception.rc, -1)
        self.assertIn("timed out", ctx.exception.stderr)

    @unittest.mock.patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(["slow-cmd"], 5),
    )
    def test_timeout_returns_empty_no_check(self, _mock_run: unittest.mock.Mock) -> None:
        """TimeoutExpired returns empty string when check=False."""
        result = run(["slow-cmd"], check=False, timeout=5)
        self.assertEqual(result, "")


class TestDigAllEdgeCases(unittest.TestCase):
    """Additional edge case tests for dig_all."""

    @unittest.mock.patch("subprocess.run")
    def test_skips_blank_lines(self, mock_run: unittest.mock.Mock) -> None:
        """Skip blank lines in dig output."""
        mock_run.return_value = unittest.mock.Mock(
            returncode=0,
            stdout=f"\n{TEST_IP1}\n\n{TEST_IP2}\n\n",
            stderr="",
        )
        result = dig_all(TEST_DOMAIN)
        self.assertEqual(result, [TEST_IP1, TEST_IP2])


class TestSubprocessRunner(unittest.TestCase):
    """Tests for the SubprocessRunner class."""

    def test_implements_command_runner(self) -> None:
        """SubprocessRunner satisfies the CommandRunner protocol."""
        from terok_shield.run import CommandRunner

        runner = SubprocessRunner()
        self.assertIsInstance(runner, CommandRunner)

    @unittest.mock.patch("subprocess.run")
    def test_run_method(self, mock_run: unittest.mock.Mock) -> None:
        """SubprocessRunner.run() returns stdout on success."""
        mock_run.return_value = unittest.mock.Mock(returncode=0, stdout="hello\n", stderr="")
        runner = SubprocessRunner()
        result = runner.run(["echo", "hello"])
        self.assertEqual(result, "hello\n")
