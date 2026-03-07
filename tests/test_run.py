# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for subprocess helpers."""

import unittest
import unittest.mock

from terok_shield.run import (
    ExecError,
    dig,
    has,
    nft,
    nft_via_nsenter,
    nft_via_rootless_netns,
    podman_inspect,
    run,
)

from .testnet import TEST_IP1, TEST_IP2


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

    @unittest.mock.patch("shutil.which", return_value="/usr/bin/nft")
    def test_found(self, _: unittest.mock.Mock) -> None:
        """Return True when executable is found."""
        self.assertTrue(has("nft"))

    @unittest.mock.patch("shutil.which", return_value=None)
    def test_not_found(self, _: unittest.mock.Mock) -> None:
        """Return False when executable is not found."""
        self.assertFalse(has("nonexistent"))


class TestNft(unittest.TestCase):
    """Tests for nft wrapper."""

    @unittest.mock.patch("terok_shield.run.run")
    def test_nft_with_args(self, mock_run: unittest.mock.Mock) -> None:
        """Pass arguments directly to nft."""
        mock_run.return_value = "output"
        result = nft("list", "ruleset")
        mock_run.assert_called_once_with(["nft", "list", "ruleset"], check=True)
        self.assertEqual(result, "output")

    @unittest.mock.patch("terok_shield.run.run")
    def test_nft_with_stdin(self, mock_run: unittest.mock.Mock) -> None:
        """Pipe rules on stdin, preserving extra args."""
        mock_run.return_value = ""
        nft("-c", stdin="table ip test {}")
        mock_run.assert_called_once_with(
            ["nft", "-c", "-f", "-"], stdin="table ip test {}", check=True
        )

    @unittest.mock.patch("terok_shield.run.run")
    def test_nft_stdin_no_args(self, mock_run: unittest.mock.Mock) -> None:
        """Pipe rules on stdin without extra args."""
        mock_run.return_value = ""
        nft(stdin="table ip test {}")
        mock_run.assert_called_once_with(["nft", "-f", "-"], stdin="table ip test {}", check=True)


class TestNftViaRootlessNetns(unittest.TestCase):
    """Tests for nft_via_rootless_netns wrapper."""

    @unittest.mock.patch("terok_shield.run.run")
    def test_with_args(self, mock_run: unittest.mock.Mock) -> None:
        """Pass arguments via podman unshare."""
        mock_run.return_value = "output"
        result = nft_via_rootless_netns("list", "ruleset")
        mock_run.assert_called_once_with(
            ["podman", "unshare", "--rootless-netns", "nft", "list", "ruleset"], check=True
        )
        self.assertEqual(result, "output")

    @unittest.mock.patch("terok_shield.run.run")
    def test_with_stdin(self, mock_run: unittest.mock.Mock) -> None:
        """Pipe rules on stdin via podman unshare, preserving extra args."""
        mock_run.return_value = ""
        nft_via_rootless_netns("-c", stdin="table ip test {}")
        mock_run.assert_called_once_with(
            ["podman", "unshare", "--rootless-netns", "nft", "-c", "-f", "-"],
            stdin="table ip test {}",
            check=True,
        )


class TestNftViaNsenter(unittest.TestCase):
    """Tests for nft_via_nsenter wrapper."""

    @unittest.mock.patch("terok_shield.run.run")
    def test_enters_container_netns(self, mock_run: unittest.mock.Mock) -> None:
        """Look up container PID and nsenter into its network namespace."""
        mock_run.side_effect = ["12345\n", "output"]
        result = nft_via_nsenter("my-ctr", "list", "ruleset")
        self.assertEqual(mock_run.call_count, 2)
        # First call: podman inspect
        self.assertIn("podman", mock_run.call_args_list[0][0][0])
        # Second call: nsenter
        nsenter_cmd = mock_run.call_args_list[1][0][0]
        self.assertIn("nsenter", nsenter_cmd)
        self.assertIn("12345", nsenter_cmd)
        self.assertEqual(result, "output")

    @unittest.mock.patch("terok_shield.run.run")
    def test_explicit_pid_skips_inspect(self, mock_run: unittest.mock.Mock) -> None:
        """Skip podman inspect when pid is provided directly."""
        mock_run.return_value = "output"
        result = nft_via_nsenter("my-ctr", "list", "ruleset", pid="999")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        self.assertIn("999", cmd)
        self.assertEqual(result, "output")

    @unittest.mock.patch("terok_shield.run.run")
    def test_stdin_support(self, mock_run: unittest.mock.Mock) -> None:
        """Pass stdin through to nft -f -."""
        mock_run.side_effect = ["12345\n", ""]
        nft_via_nsenter("my-ctr", stdin="flush ruleset")
        nsenter_call = mock_run.call_args_list[1]
        self.assertIn("-f", nsenter_call[0][0])
        self.assertEqual(nsenter_call[1]["stdin"], "flush ruleset")


class TestPodmanInspect(unittest.TestCase):
    """Tests for podman_inspect wrapper."""

    @unittest.mock.patch("terok_shield.run.run")
    def test_returns_stripped_output(self, mock_run: unittest.mock.Mock) -> None:
        """Return stripped inspect output."""
        mock_run.return_value = "  12345  \n"
        result = podman_inspect("my-ctr", "{{.State.Pid}}")
        mock_run.assert_called_once_with(
            ["podman", "inspect", "--format", "{{.State.Pid}}", "my-ctr"]
        )
        self.assertEqual(result, "12345")


class TestDig(unittest.TestCase):
    """Tests for dig()."""

    @unittest.mock.patch("terok_shield.run.run")
    def test_returns_ips(self, mock_run: unittest.mock.Mock) -> None:
        """Extract IPv4 addresses from dig output."""
        mock_run.return_value = f"{TEST_IP1}\n{TEST_IP2}\n"
        result = dig("example.com")
        self.assertEqual(result, [TEST_IP1, TEST_IP2])

    @unittest.mock.patch("terok_shield.run.run")
    def test_filters_non_ip(self, mock_run: unittest.mock.Mock) -> None:
        """Filter out CNAME and other non-IP lines."""
        mock_run.return_value = f"alias.example.com.\n{TEST_IP1}\n"
        result = dig("example.com")
        self.assertEqual(result, [TEST_IP1])

    @unittest.mock.patch("terok_shield.run.run")
    def test_empty_on_failure(self, mock_run: unittest.mock.Mock) -> None:
        """Return empty list when dig exits non-zero (check=False returns empty)."""
        mock_run.return_value = ""
        result = dig("nonexistent.invalid")
        self.assertEqual(result, [])

    @unittest.mock.patch("subprocess.run", side_effect=FileNotFoundError("dig not found"))
    def test_empty_on_missing_binary(self, _mock_run: unittest.mock.Mock) -> None:
        """Return empty list when dig binary is missing."""
        result = dig("example.com")
        self.assertEqual(result, [])
