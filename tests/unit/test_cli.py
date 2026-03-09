# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the CLI entry point."""

import unittest
from unittest import mock

from terok_shield import ExecError
from terok_shield.cli import _build_parser, main


class TestBuildParser(unittest.TestCase):
    """Test argument parser construction."""

    def test_has_subcommands(self):
        """Parser has all expected subcommands."""
        parser = _build_parser()
        # Parse known subcommands without error
        for cmd in ["setup", "status", "rules", "logs"]:
            ns = parser.parse_args([cmd] if cmd in ("setup", "status", "logs") else [cmd, "ctr"])
            self.assertEqual(ns.command, cmd)

    def test_setup_bridge_flag(self):
        """Setup subcommand accepts --bridge."""
        parser = _build_parser()
        ns = parser.parse_args(["setup", "--bridge"])
        self.assertTrue(ns.bridge)

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

    @mock.patch("terok_shield.cli.shield_setup")
    def test_setup_bridge(self, mock_setup):
        """CLI setup --bridge calls shield_setup with bridge config."""
        main(["setup", "--bridge"])
        mock_setup.assert_called_once()
        call_kwargs = mock_setup.call_args[1]
        self.assertEqual(call_kwargs["config"].mode.value, "bridge")

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
        mock_resolve.return_value = ["192.0.2.1"]
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
        mock_allow.return_value = ["192.0.2.1"]
        main(["allow", "test", "192.0.2.1"])
        mock_allow.assert_called_once_with("test", "192.0.2.1")

    @mock.patch("terok_shield.cli.shield_deny")
    def test_deny(self, mock_deny):
        """CLI deny calls shield_deny."""
        mock_deny.return_value = ["192.0.2.1"]
        main(["deny", "test", "192.0.2.1"])
        mock_deny.assert_called_once_with("test", "192.0.2.1")

    @mock.patch("terok_shield.cli.shield_rules")
    def test_rules(self, mock_rules):
        """CLI rules calls shield_rules."""
        mock_rules.return_value = "table inet terok_shield {}"
        main(["rules", "test"])
        mock_rules.assert_called_once_with("test")


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
