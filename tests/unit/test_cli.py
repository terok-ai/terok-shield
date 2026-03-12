# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the CLI entry point."""

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from terok_shield import ExecError, ShieldState
from terok_shield.cli import (
    _auto_detect_mode,
    _build_config,
    _build_parser,
    _parse_loopback_ports,
    main,
)
from terok_shield.config import ShieldMode

from ..testfs import (
    FAKE_CONFIG_DIR,
    FAKE_STATE_DIR,
    FAKE_STATE_DIR_STR,
    FAKE_XDG_CONFIG_HOME,
    FAKE_XDG_STATE_HOME,
    FORBIDDEN_TRAVERSAL,
    NFT_BINARY,
    NONEXISTENT_DIR,
    STATE_DIR_WITH_SPACES,
    VOLUME_MOUNT_DATA,
    VOLUME_MOUNT_HOST,
)
from ..testnet import TEST_DOMAIN, TEST_IP1


class TestBuildParser(unittest.TestCase):
    """Test argument parser construction."""

    def test_has_subcommands(self) -> None:
        """Parser has all expected subcommands."""
        parser = _build_parser()
        # Parse known subcommands without error
        for cmd in ["status", "rules", "logs", "down", "up", "preview"]:
            if cmd in ("status", "logs", "preview"):
                ns = parser.parse_args([cmd])
            else:
                ns = parser.parse_args([cmd, "ctr"])
            self.assertEqual(ns.command, cmd)

    def test_prepare_requires_container(self) -> None:
        """Prepare subcommand requires container arg."""
        parser = _build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["prepare"])

    def test_prepare_basic(self) -> None:
        """Prepare subcommand parses container arg."""
        parser = _build_parser()
        ns = parser.parse_args(["prepare", "my-ctr"])
        self.assertEqual(ns.command, "prepare")
        self.assertEqual(ns.container, "my-ctr")
        self.assertIsNone(ns.profiles)

    def test_prepare_profiles(self) -> None:
        """Prepare subcommand parses --profiles flag."""
        parser = _build_parser()
        ns = parser.parse_args(["prepare", "my-ctr", "--profiles", "base", "extra"])
        self.assertEqual(ns.profiles, ["base", "extra"])

    def test_run_requires_container(self) -> None:
        """Run subcommand requires container arg."""
        parser = _build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["run"])

    def test_run_basic(self) -> None:
        """Run subcommand parses container arg."""
        parser = _build_parser()
        ns = parser.parse_args(["run", "my-ctr"])
        self.assertEqual(ns.command, "run")
        self.assertEqual(ns.container, "my-ctr")

    def test_run_profiles(self) -> None:
        """Run subcommand parses --profiles flag."""
        parser = _build_parser()
        ns = parser.parse_args(["run", "my-ctr", "--profiles", "base"])
        self.assertEqual(ns.profiles, ["base"])

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

    def test_state_dir_flag(self) -> None:
        """Parser has --state-dir global flag."""
        parser = _build_parser()
        ns = parser.parse_args(["--state-dir", FAKE_STATE_DIR_STR, "status"])
        self.assertEqual(ns.state_dir, FAKE_STATE_DIR)


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

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_status(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI status calls shield.status()."""
        mock_cls.return_value.status.return_value = {
            "mode": "hook",
            "audit_enabled": True,
            "profiles": ["dev-standard"],
        }
        main(["status"])
        mock_cls.return_value.status.assert_called_once()

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_prepare(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI prepare calls shield.pre_start() and prints flags."""
        mock_cls.return_value.pre_start.return_value = ["--annotation", "a=b"]
        captured = io.StringIO()
        sys.stdout = captured
        try:
            main(["prepare", "test"])
        finally:
            sys.stdout = sys.__stdout__
        mock_cls.return_value.pre_start.assert_called_once_with("test", None)
        output = captured.getvalue().strip()
        self.assertIn("--annotation", output)
        self.assertIn("--name", output)
        self.assertIn("test", output)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_prepare_with_profiles(
        self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock
    ) -> None:
        """CLI prepare --profiles passes profiles to pre_start."""
        mock_cls.return_value.pre_start.return_value = ["--annotation", "a=b"]
        captured = io.StringIO()
        sys.stdout = captured
        try:
            main(["prepare", "test", "--profiles", "base", "extra"])
        finally:
            sys.stdout = sys.__stdout__
        mock_cls.return_value.pre_start.assert_called_once_with("test", ["base", "extra"])

    @mock.patch("os.execvp")
    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_run(
        self,
        mock_cfg: mock.MagicMock,
        mock_cls: mock.MagicMock,
        mock_exec: mock.MagicMock,
    ) -> None:
        """CLI run calls pre_start then execs podman."""
        mock_cls.return_value.pre_start.return_value = ["--annotation", "a=b"]
        main(["run", "test", "--", "alpine:latest", "sh"])
        mock_cls.return_value.pre_start.assert_called_once_with("test", None)
        mock_exec.assert_called_once()
        argv = mock_exec.call_args[0][1]
        self.assertEqual(argv[0], "podman")
        self.assertEqual(argv[1], "run")
        self.assertIn("--name", argv)
        self.assertIn("test", argv)
        self.assertIn("alpine:latest", argv)
        self.assertIn("sh", argv)

    @mock.patch("os.execvp")
    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_run_with_profiles(
        self,
        mock_cfg: mock.MagicMock,
        mock_cls: mock.MagicMock,
        mock_exec: mock.MagicMock,
    ) -> None:
        """CLI run --profiles passes profiles to pre_start."""
        mock_cls.return_value.pre_start.return_value = ["--annotation", "a=b"]
        # main() receives the full argv; it splits on '--' internally
        main(["run", "test", "--profiles", "custom", "--", "alpine:latest"])
        mock_cls.return_value.pre_start.assert_called_once_with("test", ["custom"])
        mock_exec.assert_called_once()

    @mock.patch("os.execvp")
    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_run_trailing_args_split(
        self,
        mock_cfg: mock.MagicMock,
        mock_cls: mock.MagicMock,
        mock_exec: mock.MagicMock,
    ) -> None:
        """CLI run splits argv on '--' and passes trailing args to podman."""
        mock_cls.return_value.pre_start.return_value = ["--annotation", "a=b"]
        main(["run", "test", "--", "-v", VOLUME_MOUNT_HOST, "alpine:latest", "sh"])
        argv = mock_exec.call_args[0][1]
        self.assertIn("-v", argv)
        self.assertIn(VOLUME_MOUNT_HOST, argv)
        self.assertIn("alpine:latest", argv)
        self.assertIn("sh", argv)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_run_no_image_exits_1(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI run without image after '--' exits with code 1."""
        with self.assertRaises(SystemExit) as ctx:
            main(["run", "test", "--"])
        self.assertEqual(ctx.exception.code, 1)
        # pre_start must NOT be called when image is missing
        mock_cls.return_value.pre_start.assert_not_called()

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_run_no_separator_exits_1(
        self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock
    ) -> None:
        """CLI run without '--' and no args exits with code 1."""
        with self.assertRaises(SystemExit) as ctx:
            main(["run", "test"])
        self.assertEqual(ctx.exception.code, 1)
        mock_cls.return_value.pre_start.assert_not_called()

    def test_separator_on_non_run_exits_2(self) -> None:
        """CLI rejects '--' separator on non-run subcommands."""
        with self.assertRaises(SystemExit) as ctx:
            main(["resolve", "test", "--", "junk"])
        self.assertEqual(ctx.exception.code, 2)

    def test_bare_separator_no_command_exits_2(self) -> None:
        """CLI rejects bare '--' with no subcommand."""
        with self.assertRaises(SystemExit) as ctx:
            main(["--", "junk"])
        self.assertEqual(ctx.exception.code, 2)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_run_rejects_shield_managed_flags(
        self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock
    ) -> None:
        """CLI run rejects flags that conflict with shield configuration."""
        for flag in (
            "--name",
            "--network",
            "--hooks-dir",
            "--annotation",
            "--cap-add",
            "--cap-drop",
            "--security-opt",
        ):
            with self.assertRaises(SystemExit) as ctx:
                main(["run", "test", "--", flag, "val", "alpine:latest"])
            self.assertEqual(ctx.exception.code, 1, f"{flag} should be rejected")
            mock_cls.return_value.pre_start.assert_not_called()

        # Equals-form (--flag=value) must also be rejected
        for flag_eq in (
            "--network=host",
            "--name=other",
            "--annotation=a=b",
            "--hooks-dir=/tmp",
            "--cap-add=NET_ADMIN",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
        ):
            with self.assertRaises(SystemExit) as ctx:
                main(["run", "test", "--", flag_eq, "alpine:latest"])
            self.assertEqual(ctx.exception.code, 1, f"{flag_eq} should be rejected")
            mock_cls.return_value.pre_start.assert_not_called()

    @mock.patch("os.execvp")
    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_run_allows_non_managed_flags(
        self,
        mock_cfg: mock.MagicMock,
        mock_cls: mock.MagicMock,
        mock_exec: mock.MagicMock,
    ) -> None:
        """CLI run passes through non-managed podman flags."""
        mock_cls.return_value.pre_start.return_value = ["--annotation", "a=b"]
        main(["run", "test", "--", "-d", "-e", "FOO=bar", "alpine:latest"])
        mock_exec.assert_called_once()
        argv = mock_exec.call_args[0][1]
        self.assertIn("-d", argv)
        self.assertIn("-e", argv)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_prepare_json_output(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI prepare --json outputs a JSON array."""
        mock_cls.return_value.pre_start.return_value = ["--annotation", "a=b"]
        captured = io.StringIO()
        sys.stdout = captured
        try:
            main(["prepare", "test", "--json"])
        finally:
            sys.stdout = sys.__stdout__
        result = json.loads(captured.getvalue())
        self.assertIsInstance(result, list)
        self.assertIn("--annotation", result)
        self.assertIn("--name", result)
        self.assertIn("test", result)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_main_none_argv(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI main(None) reads from sys.argv."""
        mock_cls.return_value.status.return_value = {
            "mode": "hook",
            "audit_enabled": True,
            "profiles": ["dev-standard"],
        }
        with mock.patch("sys.argv", ["terok-shield", "status"]):
            main(None)
        mock_cls.return_value.status.assert_called_once()

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_resolve(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI resolve calls shield.resolve()."""
        mock_cls.return_value.resolve.return_value = [TEST_IP1]
        main(["resolve", "test"])
        mock_cls.return_value.resolve.assert_called_once_with(force=False)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_resolve_force(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI resolve --force passes force=True."""
        mock_cls.return_value.resolve.return_value = []
        main(["resolve", "test", "--force"])
        mock_cls.return_value.resolve.assert_called_once_with(force=True)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_allow(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI allow calls shield.allow()."""
        mock_cls.return_value.allow.return_value = [TEST_IP1]
        main(["allow", "test", TEST_IP1])
        mock_cls.return_value.allow.assert_called_once_with("test", TEST_IP1)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_deny(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI deny calls shield.deny()."""
        mock_cls.return_value.deny.return_value = [TEST_IP1]
        main(["deny", "test", TEST_IP1])
        mock_cls.return_value.deny.assert_called_once_with("test", TEST_IP1)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_rules(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI rules calls shield.state() and shield.rules()."""
        mock_cls.return_value.state.return_value = ShieldState.UP
        mock_cls.return_value.rules.return_value = "table inet terok_shield {}"
        main(["rules", "test"])
        mock_cls.return_value.rules.assert_called_once_with("test")
        mock_cls.return_value.state.assert_called_once_with("test")

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_down(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI down calls shield.down()."""
        main(["down", "test"])
        mock_cls.return_value.down.assert_called_once_with("test", allow_all=False)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_down_all(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI down --all calls shield.down(allow_all=True)."""
        main(["down", "test", "--all"])
        mock_cls.return_value.down.assert_called_once_with("test", allow_all=True)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_up(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI up calls shield.up()."""
        main(["up", "test"])
        mock_cls.return_value.up.assert_called_once_with("test")

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_preview(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI preview calls shield.preview()."""
        mock_cls.return_value.preview.return_value = "table inet terok_shield {}"
        main(["preview"])
        mock_cls.return_value.preview.assert_called_once_with(down=False, allow_all=False)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_preview_down(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI preview --down calls shield.preview(down=True)."""
        mock_cls.return_value.preview.return_value = "bypass"
        main(["preview", "--down"])
        mock_cls.return_value.preview.assert_called_once_with(down=True, allow_all=False)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_preview_down_all(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI preview --down --all calls shield.preview with both flags."""
        mock_cls.return_value.preview.return_value = "bypass"
        main(["preview", "--down", "--all"])
        mock_cls.return_value.preview.assert_called_once_with(down=True, allow_all=True)

    def test_preview_all_without_down_exits_1(self) -> None:
        """CLI preview --all without --down exits with code 1."""
        with self.assertRaises(SystemExit) as ctx:
            main(["preview", "--all"])
        self.assertEqual(ctx.exception.code, 1)


class TestMainOutputFormatting(unittest.TestCase):
    """Test CLI output formatting for various subcommands."""

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_prepare_output_shell_safe(
        self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock
    ) -> None:
        """CLI prepare output is shell-safe (values with spaces are quoted)."""
        annotation_val = f"terok.shield.state_dir={STATE_DIR_WITH_SPACES}"
        mock_cls.return_value.pre_start.return_value = [
            "--annotation",
            annotation_val,
        ]
        captured = io.StringIO()
        sys.stdout = captured
        try:
            main(["prepare", "test"])
        finally:
            sys.stdout = sys.__stdout__
        output = captured.getvalue().strip()
        # The path with spaces should be quoted
        self.assertIn(f"'{annotation_val}'", output)

    @mock.patch("os.execvp")
    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_run_passes_user_podman_flags(
        self,
        mock_cfg: mock.MagicMock,
        mock_cls: mock.MagicMock,
        mock_exec: mock.MagicMock,
    ) -> None:
        """CLI run passes user flags (like -v, -p) through to podman."""
        mock_cls.return_value.pre_start.return_value = ["--annotation", "a=b"]
        main(["run", "test", "--", "-v", VOLUME_MOUNT_DATA, "-p", "8080:80", "alpine:latest"])
        argv = mock_exec.call_args[0][1]
        self.assertIn("-v", argv)
        self.assertIn(VOLUME_MOUNT_DATA, argv)
        self.assertIn("-p", argv)
        self.assertIn("8080:80", argv)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_status_output_format(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI status prints formatted output."""
        mock_cls.return_value.status.return_value = {
            "mode": "hook",
            "audit_enabled": True,
            "profiles": ["dev-standard"],
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

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_status_no_logs(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI status handles disabled audit."""
        mock_cls.return_value.status.return_value = {
            "mode": "hook",
            "audit_enabled": False,
            "profiles": [],
        }
        captured = io.StringIO()
        sys.stdout = captured
        try:
            main(["status"])
        finally:
            sys.stdout = sys.__stdout__
        output = captured.getvalue()
        self.assertIn("disabled", output)
        self.assertIn("(none)", output)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_allow_no_ips_exits_1(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI allow exits 1 when no IPs are allowed."""
        mock_cls.return_value.allow.return_value = []
        with self.assertRaises(SystemExit) as ctx:
            main(["allow", "test", TEST_DOMAIN])
        self.assertEqual(ctx.exception.code, 1)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_deny_no_ips_exits_1(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI deny exits 1 when no IPs are denied."""
        mock_cls.return_value.deny.return_value = []
        with self.assertRaises(SystemExit) as ctx:
            main(["deny", "test", TEST_DOMAIN])
        self.assertEqual(ctx.exception.code, 1)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_rules_no_rules(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """CLI rules prints 'No rules found' for empty output."""
        mock_cls.return_value.state.return_value = ShieldState.INACTIVE
        mock_cls.return_value.rules.return_value = ""
        captured = io.StringIO()
        sys.stdout = captured
        try:
            main(["rules", "test"])
        finally:
            sys.stdout = sys.__stdout__
        output = captured.getvalue()
        self.assertIn("No rules found", output)

    def test_logs_no_files(self) -> None:
        """CLI logs prints 'No audit logs found' when no files."""
        with tempfile.TemporaryDirectory() as tmp:
            captured = io.StringIO()
            sys.stdout = captured
            try:
                main(["--state-dir", tmp, "logs"])
            finally:
                sys.stdout = sys.__stdout__
            output = captured.getvalue()
            self.assertIn("No audit logs found", output)

    def test_logs_with_container(self) -> None:
        """CLI logs with --container prints entries from audit file."""
        with tempfile.TemporaryDirectory() as tmp:
            ctr_dir = Path(tmp) / "containers" / "test"
            ctr_dir.mkdir(parents=True)
            audit_file = ctr_dir / "audit.jsonl"
            audit_file.write_text('{"action":"setup","ts":"2026-01-01T00:00:00"}\n')
            captured = io.StringIO()
            sys.stdout = captured
            try:
                main(["--state-dir", tmp, "logs", "--container", "test"])
            finally:
                sys.stdout = sys.__stdout__
            output = captured.getvalue().strip()
            entry = json.loads(output)
            self.assertEqual(entry["action"], "setup")


class TestMainErrorHandling(unittest.TestCase):
    """Test CLI error handling."""

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_runtime_error_exits_1(
        self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock
    ) -> None:
        """RuntimeError in dispatch exits with code 1."""
        mock_cls.return_value.status.side_effect = RuntimeError("nope")
        with self.assertRaises(SystemExit) as ctx:
            main(["status"])
        self.assertEqual(ctx.exception.code, 1)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_value_error_exits_1(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """ValueError in dispatch exits with code 1."""
        mock_cls.return_value.allow.side_effect = ValueError("bad ip")
        with self.assertRaises(SystemExit) as ctx:
            main(["allow", "test", "bad"])
        self.assertEqual(ctx.exception.code, 1)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_exec_error_exits_1(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """ExecError in dispatch exits with code 1."""
        mock_cls.return_value.status.side_effect = ExecError(["nft", "list"], 1, "command failed")
        with self.assertRaises(SystemExit) as ctx:
            main(["status"])
        self.assertEqual(ctx.exception.code, 1)

    @mock.patch("terok_shield.cli.Shield")
    @mock.patch("terok_shield.cli._build_config")
    def test_os_error_exits_1(self, mock_cfg: mock.MagicMock, mock_cls: mock.MagicMock) -> None:
        """OSError in dispatch exits with code 1."""
        mock_cls.return_value.rules.side_effect = OSError("permission denied")
        with self.assertRaises(SystemExit) as ctx:
            main(["rules", "test"])
        self.assertEqual(ctx.exception.code, 1)


class TestResolveStateRoot(unittest.TestCase):
    """Tests for _resolve_state_root (moved from config.py)."""

    def test_default(self) -> None:
        """Default state root is under ~/.local/state/."""
        from terok_shield.cli import _resolve_state_root

        with mock.patch.dict("os.environ", {}, clear=True):
            root = _resolve_state_root()
            self.assertTrue(str(root).endswith("terok-shield"))

    def test_env_override(self) -> None:
        """TEROK_SHIELD_STATE_DIR overrides default."""
        from terok_shield.cli import _resolve_state_root

        with mock.patch.dict("os.environ", {"TEROK_SHIELD_STATE_DIR": str(FAKE_STATE_DIR)}):
            root = _resolve_state_root()
            self.assertEqual(root, FAKE_STATE_DIR)

    def test_xdg(self) -> None:
        """XDG_STATE_HOME is used when TEROK_SHIELD_STATE_DIR is not set."""
        from terok_shield.cli import _resolve_state_root

        with mock.patch.dict(
            "os.environ", {"XDG_STATE_HOME": str(FAKE_XDG_STATE_HOME)}, clear=True
        ):
            root = _resolve_state_root()
            self.assertEqual(root, FAKE_XDG_STATE_HOME / "terok-shield")

    def test_explicit_overrides_xdg(self) -> None:
        """TEROK_SHIELD_STATE_DIR takes priority over XDG_STATE_HOME."""
        from terok_shield.cli import _resolve_state_root

        with mock.patch.dict(
            "os.environ",
            {
                "TEROK_SHIELD_STATE_DIR": str(FAKE_STATE_DIR),
                "XDG_STATE_HOME": str(FAKE_XDG_STATE_HOME),
            },
        ):
            root = _resolve_state_root()
            self.assertEqual(root, FAKE_STATE_DIR)


class TestResolveConfigRoot(unittest.TestCase):
    """Tests for _resolve_config_root (moved from config.py)."""

    def test_default(self) -> None:
        """Default config root is under ~/.config/."""
        from terok_shield.cli import _resolve_config_root

        with mock.patch.dict("os.environ", {}, clear=True):
            root = _resolve_config_root()
            self.assertTrue(str(root).endswith("terok-shield"))

    def test_env_override(self) -> None:
        """TEROK_SHIELD_CONFIG_DIR overrides default."""
        from terok_shield.cli import _resolve_config_root

        with mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": str(FAKE_CONFIG_DIR)}):
            root = _resolve_config_root()
            self.assertEqual(root, FAKE_CONFIG_DIR)

    def test_xdg(self) -> None:
        """XDG_CONFIG_HOME is used when TEROK_SHIELD_CONFIG_DIR is not set."""
        from terok_shield.cli import _resolve_config_root

        with mock.patch.dict(
            "os.environ", {"XDG_CONFIG_HOME": str(FAKE_XDG_CONFIG_HOME)}, clear=True
        ):
            root = _resolve_config_root()
            self.assertEqual(root, FAKE_XDG_CONFIG_HOME / "terok-shield")


class TestParseLoopbackPorts(unittest.TestCase):
    """Tests for _parse_loopback_ports (moved from config.py)."""

    def test_valid_list(self) -> None:
        """Valid port list is accepted."""
        self.assertEqual(_parse_loopback_ports([8080, 9090]), (8080, 9090))

    def test_single_int(self) -> None:
        """A bare integer is accepted as a single-element tuple."""
        self.assertEqual(_parse_loopback_ports(1234), (1234,))

    def test_empty_list(self) -> None:
        """Empty list produces empty tuple."""
        self.assertEqual(_parse_loopback_ports([]), ())

    def test_bool_rejected(self) -> None:
        """Boolean values are silently dropped."""
        self.assertEqual(_parse_loopback_ports([True]), ())

    def test_out_of_range_dropped(self) -> None:
        """Out-of-range ports are silently dropped."""
        self.assertEqual(_parse_loopback_ports([99999]), ())

    def test_mixed_valid_invalid(self) -> None:
        """Valid ports kept, invalid silently dropped."""
        self.assertEqual(_parse_loopback_ports([8080, 0, True, 9090]), (8080, 9090))

    def test_bool_value_returns_empty(self) -> None:
        """Bare boolean value returns empty tuple."""
        self.assertEqual(_parse_loopback_ports(True), ())

    def test_string_value_returns_empty(self) -> None:
        """String value returns empty tuple."""
        self.assertEqual(_parse_loopback_ports("not-a-list"), ())


class TestAutoDetectMode(unittest.TestCase):
    """Tests for _auto_detect_mode (moved from config.py)."""

    @mock.patch("shutil.which", return_value=None)
    def test_no_tools_raises(self, _which: mock.Mock) -> None:
        """Raise RuntimeError when nft is not available."""
        with self.assertRaises(RuntimeError):
            _auto_detect_mode()

    @mock.patch("shutil.which", side_effect=lambda n: NFT_BINARY if n == "nft" else None)
    def test_nft_returns_hook(self, _which: mock.Mock) -> None:
        """Return HOOK when nft is available."""
        self.assertEqual(_auto_detect_mode(), ShieldMode.HOOK)


class TestLoadConfigFile(unittest.TestCase):
    """Tests for _load_config_file edge cases."""

    def test_malformed_yaml_returns_empty(self) -> None:
        """Malformed YAML returns empty dict."""
        from terok_shield.cli import _load_config_file

        with tempfile.TemporaryDirectory() as cfg_dir:
            config_file = Path(cfg_dir) / "config.yml"
            config_file.write_text(": [invalid yaml\n  bad: {unclosed")
            with mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": cfg_dir}):
                result = _load_config_file()
                self.assertEqual(result, {})

    def test_non_dict_yaml_returns_empty(self) -> None:
        """YAML that parses to a non-dict returns empty dict."""
        from terok_shield.cli import _load_config_file

        with tempfile.TemporaryDirectory() as cfg_dir:
            config_file = Path(cfg_dir) / "config.yml"
            config_file.write_text("- just\n- a\n- list\n")
            with mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": cfg_dir}):
                result = _load_config_file()
                self.assertEqual(result, {})


class TestBuildConfig(unittest.TestCase):
    """Tests for _build_config."""

    @mock.patch("terok_shield.cli._auto_detect_mode", return_value=ShieldMode.HOOK)
    def test_missing_config_file_uses_defaults(self, _mock_mode: mock.Mock) -> None:
        """Return defaults when config file does not exist."""
        with (
            mock.patch.dict(
                "os.environ", {"TEROK_SHIELD_CONFIG_DIR": str(NONEXISTENT_DIR / "config")}
            ),
            tempfile.TemporaryDirectory() as tmp,
        ):
            config = _build_config("test-ctr", state_dir_override=Path(tmp))
            self.assertEqual(config.mode, ShieldMode.HOOK)
            self.assertEqual(config.state_dir, Path(tmp) / "containers" / "test-ctr")

    def test_loads_yaml(self) -> None:
        """Load configuration from YAML file."""
        with tempfile.TemporaryDirectory() as cfg_dir:
            config_file = Path(cfg_dir) / "config.yml"
            config_file.write_text(
                "mode: hook\n"
                "default_profiles: [base, dev-python]\n"
                "loopback_ports: [1234, 5678]\n"
                "audit:\n"
                "  enabled: false\n"
            )
            with (
                mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": cfg_dir}),
                tempfile.TemporaryDirectory() as state_dir,
            ):
                config = _build_config("ctr", state_dir_override=Path(state_dir))
                self.assertEqual(config.mode, ShieldMode.HOOK)
                self.assertEqual(config.default_profiles, ("base", "dev-python"))
                self.assertEqual(config.loopback_ports, (1234, 5678))
                self.assertFalse(config.audit_enabled)

    @mock.patch("terok_shield.cli._auto_detect_mode", return_value=ShieldMode.HOOK)
    def test_state_dir_override(self, _mock_mode: mock.Mock) -> None:
        """--state-dir override is used as state root."""
        with tempfile.TemporaryDirectory() as tmp:
            config = _build_config("my-ctr", state_dir_override=Path(tmp))
            self.assertEqual(config.state_dir, Path(tmp) / "containers" / "my-ctr")

    @mock.patch("terok_shield.cli._auto_detect_mode", return_value=ShieldMode.HOOK)
    def test_default_container(self, _mock_mode: mock.Mock) -> None:
        """No container uses _default subdirectory."""
        with tempfile.TemporaryDirectory() as tmp:
            config = _build_config(state_dir_override=Path(tmp))
            self.assertEqual(config.state_dir, Path(tmp) / "containers" / "_default")

    def test_unknown_mode_raises(self) -> None:
        """Unknown mode string raises ValueError."""
        with tempfile.TemporaryDirectory() as cfg_dir:
            config_file = Path(cfg_dir) / "config.yml"
            config_file.write_text("mode: bridge\n")
            with (
                mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": cfg_dir}),
                tempfile.TemporaryDirectory() as state_dir,
            ):
                with self.assertRaises(ValueError, msg="Unknown shield mode"):
                    _build_config("ctr", state_dir_override=Path(state_dir))

    @mock.patch("terok_shield.cli._auto_detect_mode", return_value=ShieldMode.HOOK)
    def test_non_list_profiles_uses_default(self, _mock_mode: mock.Mock) -> None:
        """Non-list default_profiles falls back to dev-standard."""
        with tempfile.TemporaryDirectory() as cfg_dir:
            config_file = Path(cfg_dir) / "config.yml"
            config_file.write_text("default_profiles: not-a-list\n")
            with (
                mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": cfg_dir}),
                tempfile.TemporaryDirectory() as state_dir,
            ):
                config = _build_config("ctr", state_dir_override=Path(state_dir))
                self.assertEqual(config.default_profiles, ("dev-standard",))

    @mock.patch("terok_shield.cli._auto_detect_mode", return_value=ShieldMode.HOOK)
    def test_non_dict_audit_section_uses_default(self, _mock_mode: mock.Mock) -> None:
        """Non-dict audit section falls back to defaults."""
        with tempfile.TemporaryDirectory() as cfg_dir:
            config_file = Path(cfg_dir) / "config.yml"
            config_file.write_text("audit: not-a-dict\n")
            with (
                mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": cfg_dir}),
                tempfile.TemporaryDirectory() as state_dir,
            ):
                config = _build_config("ctr", state_dir_override=Path(state_dir))
                self.assertTrue(config.audit_enabled)

    @mock.patch("terok_shield.cli._auto_detect_mode", return_value=ShieldMode.HOOK)
    def test_non_bool_audit_enabled_uses_default(self, _mock_mode: mock.Mock) -> None:
        """Non-bool audit.enabled falls back to True."""
        with tempfile.TemporaryDirectory() as cfg_dir:
            config_file = Path(cfg_dir) / "config.yml"
            config_file.write_text("audit:\n  enabled: yes-please\n")
            with (
                mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": cfg_dir}),
                tempfile.TemporaryDirectory() as state_dir,
            ):
                config = _build_config("ctr", state_dir_override=Path(state_dir))
                self.assertTrue(config.audit_enabled)

    @mock.patch("terok_shield.cli._auto_detect_mode", return_value=ShieldMode.HOOK)
    def test_traversal_container_name_rejected(self, _mock_mode: mock.Mock) -> None:
        """Container name with path traversal is rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError, msg="Unsafe container name"):
                _build_config(FORBIDDEN_TRAVERSAL, state_dir_override=Path(tmp))

    @mock.patch("terok_shield.cli._auto_detect_mode", return_value=ShieldMode.HOOK)
    def test_non_string_profiles_uses_default(self, _mock_mode: mock.Mock) -> None:
        """Profile list with non-string entries falls back to default."""
        with tempfile.TemporaryDirectory() as cfg_dir:
            config_file = Path(cfg_dir) / "config.yml"
            config_file.write_text("default_profiles: [1, null]\n")
            with (
                mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": cfg_dir}),
                tempfile.TemporaryDirectory() as state_dir,
            ):
                config = _build_config("ctr", state_dir_override=Path(state_dir))
                self.assertEqual(config.default_profiles, ("dev-standard",))

    @mock.patch("terok_shield.cli._auto_detect_mode", return_value=ShieldMode.HOOK)
    def test_no_state_dir_override_uses_resolve(self, _mock_mode: mock.Mock) -> None:
        """Without --state-dir, _resolve_state_root is used."""
        with (
            mock.patch.dict(
                "os.environ",
                {
                    "TEROK_SHIELD_STATE_DIR": str(FAKE_STATE_DIR),
                    "TEROK_SHIELD_CONFIG_DIR": str(NONEXISTENT_DIR / "config"),
                },
            ),
        ):
            config = _build_config("ctr")
            self.assertEqual(config.state_dir, FAKE_STATE_DIR / "containers" / "ctr")


class TestCmdLogsGlobal(unittest.TestCase):
    """Tests for _cmd_logs multi-container merge/sort."""

    def test_global_logs_merges_and_sorts(self) -> None:
        """Global logs merges entries across containers and sorts by timestamp."""
        with tempfile.TemporaryDirectory() as tmp:
            # Create two container audit logs with interleaved timestamps
            for name, entries in [
                (
                    "ctr-a",
                    [
                        '{"action":"a1","ts":"2026-01-01T00:00:02"}',
                        '{"action":"a2","ts":"2026-01-01T00:00:04"}',
                    ],
                ),
                (
                    "ctr-b",
                    [
                        '{"action":"b1","ts":"2026-01-01T00:00:01"}',
                        '{"action":"b2","ts":"2026-01-01T00:00:03"}',
                    ],
                ),
            ]:
                ctr_dir = Path(tmp) / "containers" / name
                ctr_dir.mkdir(parents=True)
                (ctr_dir / "audit.jsonl").write_text("\n".join(entries) + "\n")

            captured = io.StringIO()
            sys.stdout = captured
            try:
                main(["--state-dir", tmp, "logs", "-n", "3"])
            finally:
                sys.stdout = sys.__stdout__

            lines = captured.getvalue().strip().splitlines()
            self.assertEqual(len(lines), 3)
            actions = [json.loads(line)["action"] for line in lines]
            # Last 3 sorted by timestamp: a1 (02), b2 (03), a2 (04)
            self.assertEqual(actions, ["a1", "b2", "a2"])

    def test_global_logs_empty_containers(self) -> None:
        """Global logs prints 'No audit logs found' when containers exist but have no audit files."""
        with tempfile.TemporaryDirectory() as tmp:
            ctr_dir = Path(tmp) / "containers" / "empty-ctr"
            ctr_dir.mkdir(parents=True)

            captured = io.StringIO()
            sys.stdout = captured
            try:
                main(["--state-dir", tmp, "logs"])
            finally:
                sys.stdout = sys.__stdout__
            self.assertIn("No audit logs found", captured.getvalue())

    def test_logs_container_traversal_rejected(self) -> None:
        """Container name with path traversal is rejected in logs command."""
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit) as ctx:
                main(["--state-dir", tmp, "logs", "--container", FORBIDDEN_TRAVERSAL])
            self.assertEqual(ctx.exception.code, 1)
