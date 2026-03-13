# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the command registry module."""

import io
import json
import sys
import unittest
from unittest import mock

from terok_shield.registry import (
    COMMANDS,
    ArgDef,
    _handle_allow,
    _handle_deny,
    _handle_logs,
    _handle_preview,
    _handle_profiles,
    _handle_state,
)


class TestCommandDefs(unittest.TestCase):
    """Test COMMANDS tuple structure and invariants."""

    def test_names_unique(self) -> None:
        """All command names are unique."""
        names = [cmd.name for cmd in COMMANDS]
        self.assertEqual(len(names), len(set(names)))

    def test_handler_present_when_not_standalone_only(self) -> None:
        """Non-standalone commands have a handler."""
        for cmd in COMMANDS:
            if not cmd.standalone_only:
                self.assertIsNotNone(cmd.handler, f"{cmd.name} missing handler")

    def test_standalone_only_have_no_handler(self) -> None:
        """Standalone-only commands have handler=None."""
        for cmd in COMMANDS:
            if cmd.standalone_only:
                self.assertIsNone(cmd.handler, f"{cmd.name} should have handler=None")


class TestArgDef(unittest.TestCase):
    """Test ArgDef dataclass."""

    def test_defaults(self) -> None:
        """ArgDef defaults are sensible."""
        arg = ArgDef(name="--foo")
        self.assertEqual(arg.help, "")
        self.assertIsNone(arg.type)
        self.assertIsNone(arg.default)
        self.assertIsNone(arg.action)
        self.assertIsNone(arg.dest)
        self.assertIsNone(arg.nargs)


class TestHandlers(unittest.TestCase):
    """Test registry handler functions directly."""

    def test_handle_allow_raises_on_failure(self) -> None:
        """_handle_allow raises RuntimeError when no IPs allowed."""
        shield = mock.MagicMock()
        shield.allow.return_value = []
        with self.assertRaises(RuntimeError) as ctx:
            _handle_allow(shield, "ctr", target="bad")
        self.assertIn("No IPs allowed", str(ctx.exception))

    def test_handle_deny_raises_on_failure(self) -> None:
        """_handle_deny raises RuntimeError when no IPs denied."""
        shield = mock.MagicMock()
        shield.deny.return_value = []
        with self.assertRaises(RuntimeError) as ctx:
            _handle_deny(shield, "ctr", target="bad")
        self.assertIn("No IPs denied", str(ctx.exception))

    def test_handle_logs_prints_json(self) -> None:
        """_handle_logs prints JSONL entries from shield.tail_log."""
        shield = mock.MagicMock()
        shield.tail_log.return_value = [{"action": "setup", "ts": "2026-01-01"}]
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            _handle_logs(shield, "ctr", n=10)
        finally:
            sys.stdout = old_stdout
        shield.tail_log.assert_called_once_with(10)
        entry = json.loads(captured.getvalue().strip())
        self.assertEqual(entry["action"], "setup")

    def test_handle_profiles_prints_names(self) -> None:
        """_handle_profiles prints each profile name."""
        shield = mock.MagicMock()
        shield.profiles_list.return_value = ["dev-standard", "dev-python"]
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            _handle_profiles(shield)
        finally:
            sys.stdout = old_stdout
        lines = captured.getvalue().strip().splitlines()
        self.assertEqual(lines, ["dev-standard", "dev-python"])

    def test_handle_state_prints_value(self) -> None:
        """_handle_state prints the ShieldState value."""
        from terok_shield import ShieldState

        shield = mock.MagicMock()
        shield.state.return_value = ShieldState.UP
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            _handle_state(shield, "ctr")
        finally:
            sys.stdout = old_stdout
        self.assertEqual(captured.getvalue().strip(), "up")

    def test_handle_preview_all_without_down_raises(self) -> None:
        """_handle_preview raises ValueError when allow_all without down."""
        shield = mock.MagicMock()
        with self.assertRaises(ValueError) as ctx:
            _handle_preview(shield, allow_all=True)
        self.assertIn("--all requires --down", str(ctx.exception))
