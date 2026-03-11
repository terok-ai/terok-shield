# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the CLI entry point."""

import io
import json
import sys
import unittest
from unittest import mock

from terok_shield import ExecError, ShieldState
from terok_shield.cli import _build_parser, main

from ..testnet import TEST_DOMAIN, TEST_IP1


class TestBuildParser(unittest.TestCase):
    """Test argument parser construction."""

    def test_has_subcommands(self) -> None:
        """Parser has all expected subcommands."""
        parser = _build_parser()
        # Parse known subcommands without error
        for cmd in ["setup", "status", "rules", "logs", "down", "up", "preview"]:
            if cmd in ("setup", "status", "logs", "preview"):
                ns = parser.parse_args([cmd])
            else:
                ns = parser.parse_args([cmd, "ctr"])
            self.assertEqual(ns.command, cmd)

    def test_resolve_requires_container(self):
        """Resolve subcommand requires container arg."""
        parser = _build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["resolve"])

    def test_allow_requires_args(self):
        """Allow subcommand requires container and target."""
        parser = _build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["allow"])

    def test_deny_requires_args(self):
        """Deny subcommand requires container and target."""
        parser = _build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["deny"])

    def test_logs_optional_container(self):
        """Logs subcommand has optional --container."""
        parser = _build_parser()
        ns = parser.parse_args(["logs"])
        self.assertIsNone(ns.container)
        ns = parser.parse_args(["logs", "--container", "test"])
        self.assertEqual(ns.container, "test")

    def test_logs_optional_count(self):
        """Logs subcommand has -n with default 50."""
        parser = _build_parser()
        ns = parser.parse_args(["logs"])
        self.assertEqual(ns.n, 50)
        ns = parser.parse_args(["logs", "-n", "10"])
        self.assertEqual(ns.n, 10)

    def test_down_requires_container(self) -> None:
        """Down subcommand requires container arg."""
        parser = _build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["down"])

    def test_down_allow_all_flag(self) -> None:
        """Down subcommand has --all flag defaulting to False."""
        parser = _build_parser()
        ns = parser.parse_args(["down", "ctr"])
        self.assertFalse(ns.allow_all)
        ns = parser.parse_args(["down", "ctr", "--all"])
        self.assertTrue(ns.allow_all)

    def test_up_requires_container(self) -> None:
        """Up subcommand requires container arg."""
        parser = _build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["up"])

    def test_preview_defaults(self) -> None:
        """Preview subcommand has --down defaulting to False."""
        parser = _build_parser()
        ns = parser.parse_args(["preview"])
        self.assertFalse(ns.down)
        self.assertFalse(ns.allow_all)

    def test_preview_down_flag(self) -> None:
        """Preview subcommand has --down flag."""
        parser = _build_parser()
        ns = parser.parse_args(["preview", "--down"])
        self.assertTrue(ns.down)

    def test_preview_down_all_flags(self) -> None:
        """Preview subcommand has --down --all flags."""
        parser = _build_parser()
        ns = parser.parse_args(["preview", "--down", "--all"])
        self.assertTrue(ns.down)
        self.assertTrue(ns.allow_all)


class TestMainNoCommand(unittest.TestCase):
    """Test CLI with no subcommand."""

    def test_no_args_exits_zero(self):
        """CLI with no args exits 0."""
        with self.assertRaises(SystemExit) as ctx:
            main([])
        self.assertEqual(ctx.exception.code, 0)


class TestMainHelp(unittest.TestCase):
    """Test CLI help output."""

    def test_help_exits_zero(self):
        """CLI --help exits 0."""
        with self.assertRaises(SystemExit) as ctx:
            main(["--help"])
        self.assertEqual(ctx.exception.code, 0)


class TestMainDispatch(unittest.TestCase):
    """Test CLI subcommand dispatch."""

    @mock.patch("terok_shield.cli.shield_setup")
    def test_setup_hook(self, mock_setup):
        """CLI setup calls shield_setup with hook config."""
        main(["setup"])
        mock_setup.assert_called_once()
        call_kwargs = mock_setup.call_args[1]
        self.assertEqual(call_kwargs["config"].mode.value, "hook")

    @mock.patch("terok_shield.cli.shield_status")
    def test_status(self, mock_status):
        """CLI status calls shield_status."""
        mock_status.return_value = {
            "mode": "hook",
            "audit_enabled": True,
            "profiles": ["dev-standard"],
            "log_files": [],
        }
        main(["status"])
        mock_status.assert_called_once()

    @mock.patch("terok_shield.cli.shield_resolve")
    def test_resolve(self, mock_resolve):
        """CLI resolve calls shield_resolve."""
        mock_resolve.return_value = [TEST_IP1]
        main(["resolve", "test"])
        mock_resolve.assert_called_once_with("test", force=False)

    @mock.patch("terok_shield.cli.shield_resolve")
    def test_resolve_force(self, mock_resolve):
        """CLI resolve --force passes force=True."""
        mock_resolve.return_value = []
        main(["resolve", "test", "--force"])
        mock_resolve.assert_called_once_with("test", force=True)

    @mock.patch("terok_shield.cli.shield_allow")
    def test_allow(self, mock_allow):
        """CLI allow calls shield_allow."""
        mock_allow.return_value = [TEST_IP1]
        main(["allow", "test", TEST_IP1])
        mock_allow.assert_called_once_with("test", TEST_IP1)

    @mock.patch("terok_shield.cli.shield_deny")
    def test_deny(self, mock_deny):
        """CLI deny calls shield_deny."""
        mock_deny.return_value = [TEST_IP1]
        main(["deny", "test", TEST_IP1])
        mock_deny.assert_called_once_with("test", TEST_IP1)

    @mock.patch("terok_shield.cli.shield_state")
    @mock.patch("terok_shield.cli.shield_rules")
    def test_rules(self, mock_rules, mock_state):
        """CLI rules calls shield_rules."""
        mock_state.return_value = ShieldState.UP
        mock_rules.return_value = "table inet terok_shield {}"
        main(["rules", "test"])
        mock_rules.assert_called_once_with("test")
        mock_state.assert_called_once_with("test")

    @mock.patch("terok_shield.cli.shield_down")
    def test_down(self, mock_down) -> None:
        """CLI down calls shield_down."""
        main(["down", "test"])
        mock_down.assert_called_once_with("test", allow_all=False)

    @mock.patch("terok_shield.cli.shield_down")
    def test_down_all(self, mock_down) -> None:
        """CLI down --all calls shield_down with allow_all=True."""
        main(["down", "test", "--all"])
        mock_down.assert_called_once_with("test", allow_all=True)

    @mock.patch("terok_shield.cli.shield_up")
    def test_up(self, mock_up) -> None:
        """CLI up calls shield_up."""
        main(["up", "test"])
        mock_up.assert_called_once_with("test")

    @mock.patch("terok_shield.cli.shield_preview", return_value="table inet terok_shield {}")
    def test_preview(self, mock_preview) -> None:
        """CLI preview calls shield_preview."""
        main(["preview"])
        mock_preview.assert_called_once_with(down=False, allow_all=False)

    @mock.patch("terok_shield.cli.shield_preview", return_value="bypass")
    def test_preview_down(self, mock_preview) -> None:
        """CLI preview --down calls shield_preview with down=True."""
        main(["preview", "--down"])
        mock_preview.assert_called_once_with(down=True, allow_all=False)

    @mock.patch("terok_shield.cli.shield_preview", return_value="bypass")
    def test_preview_down_all(self, mock_preview) -> None:
        """CLI preview --down --all calls shield_preview with both flags."""
        main(["preview", "--down", "--all"])
        mock_preview.assert_called_once_with(down=True, allow_all=True)

    def test_preview_all_without_down_exits_1(self) -> None:
        """CLI preview --all without --down exits with code 1."""
        with self.assertRaises(SystemExit) as ctx:
            main(["preview", "--all"])
        self.assertEqual(ctx.exception.code, 1)


class TestMainOutputFormatting(unittest.TestCase):
    """Test CLI output formatting for various subcommands."""

    @mock.patch("terok_shield.cli.shield_status")
    def test_status_output_format(self, mock_status) -> None:
        """CLI status prints formatted output."""
        mock_status.return_value = {
            "mode": "hook",
            "audit_enabled": True,
            "profiles": ["dev-standard"],
            "log_files": ["ctr1"],
        }
        captured = io.StringIO()
        sys.stdout = captured
        try:
            main(["status"])
        finally:
            sys.stdout = sys.__stdout__
        output = captured.getvalue()
        self.assertIn("Mode:", output)
        self.assertIn("hook", output)
        self.assertIn("Audit:", output)
        self.assertIn("enabled", output)
        self.assertIn("Logs:", output)

    @mock.patch("terok_shield.cli.shield_status")
    def test_status_no_logs(self, mock_status) -> None:
        """CLI status omits Logs line when no log files."""
        mock_status.return_value = {
            "mode": "hook",
            "audit_enabled": False,
            "profiles": [],
            "log_files": [],
        }
        captured = io.StringIO()
        sys.stdout = captured
        try:
            main(["status"])
        finally:
            sys.stdout = sys.__stdout__
        output = captured.getvalue()
        self.assertNotIn("Logs:", output)
        self.assertIn("disabled", output)
        self.assertIn("(none)", output)

    @mock.patch("terok_shield.cli.shield_allow", return_value=[])
    def test_allow_no_ips_exits_1(self, _allow) -> None:
        """CLI allow exits 1 when no IPs are allowed."""
        with self.assertRaises(SystemExit) as ctx:
            main(["allow", "test", TEST_DOMAIN])
        self.assertEqual(ctx.exception.code, 1)

    @mock.patch("terok_shield.cli.shield_deny", return_value=[])
    def test_deny_no_ips_exits_1(self, _deny) -> None:
        """CLI deny exits 1 when no IPs are denied."""
        with self.assertRaises(SystemExit) as ctx:
            main(["deny", "test", TEST_DOMAIN])
        self.assertEqual(ctx.exception.code, 1)

    @mock.patch("terok_shield.cli.shield_state")
    @mock.patch("terok_shield.cli.shield_rules", return_value="")
    def test_rules_no_rules(self, _rules, mock_state) -> None:
        """CLI rules prints 'No rules found' for empty output."""
        mock_state.return_value = ShieldState.INACTIVE
        captured = io.StringIO()
        sys.stdout = captured
        try:
            main(["rules", "test"])
        finally:
            sys.stdout = sys.__stdout__
        output = captured.getvalue()
        self.assertIn("No rules found", output)

    @mock.patch("terok_shield.cli.tail_log", return_value=iter([]))
    @mock.patch("terok_shield.cli.list_log_files", return_value=[])
    def test_logs_no_files(self, _files, _tail) -> None:
        """CLI logs prints 'No audit logs found' when no files."""
        captured = io.StringIO()
        sys.stdout = captured
        try:
            main(["logs"])
        finally:
            sys.stdout = sys.__stdout__
        output = captured.getvalue()
        self.assertIn("No audit logs found", output)

    @mock.patch("terok_shield.cli.tail_log")
    def test_logs_with_container(self, mock_tail) -> None:
        """CLI logs with --container prints entries as JSON."""
        mock_tail.return_value = iter([{"action": "setup"}])
        captured = io.StringIO()
        sys.stdout = captured
        try:
            main(["logs", "--container", "test"])
        finally:
            sys.stdout = sys.__stdout__
        output = captured.getvalue().strip()
        entry = json.loads(output)
        self.assertEqual(entry["action"], "setup")


class TestMainErrorHandling(unittest.TestCase):
    """Test CLI error handling."""

    @mock.patch("terok_shield.cli.shield_setup", side_effect=RuntimeError("nope"))
    def test_runtime_error_exits_1(self, _setup):
        """RuntimeError in dispatch exits with code 1."""
        with self.assertRaises(SystemExit) as ctx:
            main(["setup"])
        self.assertEqual(ctx.exception.code, 1)

    @mock.patch("terok_shield.cli.shield_rules", side_effect=FileNotFoundError("missing"))
    def test_file_not_found_exits_1(self, _rules):
        """FileNotFoundError in dispatch exits with code 1."""
        with self.assertRaises(SystemExit) as ctx:
            main(["rules", "test"])
        self.assertEqual(ctx.exception.code, 1)

    @mock.patch("terok_shield.cli.shield_allow", side_effect=ValueError("bad ip"))
    def test_value_error_exits_1(self, _allow):
        """ValueError in dispatch exits with code 1."""
        with self.assertRaises(SystemExit) as ctx:
            main(["allow", "test", "bad"])
        self.assertEqual(ctx.exception.code, 1)

    @mock.patch(
        "terok_shield.cli.shield_setup",
        side_effect=ExecError(["nft", "list"], 1, "command failed"),
    )
    def test_exec_error_exits_1(self, _setup):
        """ExecError in dispatch exits with code 1."""
        with self.assertRaises(SystemExit) as ctx:
            main(["setup"])
        self.assertEqual(ctx.exception.code, 1)

    @mock.patch("terok_shield.cli.shield_rules", side_effect=OSError("permission denied"))
    def test_os_error_exits_1(self, _rules):
        """OSError in dispatch exits with code 1."""
        with self.assertRaises(SystemExit) as ctx:
            main(["rules", "test"])
        self.assertEqual(ctx.exception.code, 1)
