# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the command registry module."""

import json
from collections.abc import Callable
from unittest import mock

import pytest

from terok_shield.registry import (
    COMMANDS,
    ArgDef,
    _handle_allow,
    _handle_deny,
    _handle_logs,
    _handle_preview,
    _handle_profiles,
    _handle_status,
    _handle_watch,
)


class TestCommandDefs:
    """Test COMMANDS tuple structure and invariants."""

    def test_names_unique(self) -> None:
        """All command names are unique."""
        names = [cmd.name for cmd in COMMANDS]
        assert len(names) == len(set(names))

    def test_handler_present_when_not_standalone_only(self) -> None:
        """Non-standalone commands have a handler."""
        for cmd in COMMANDS:
            if not cmd.standalone_only:
                assert cmd.handler is not None, f"{cmd.name} missing handler"

    def test_standalone_only_have_no_handler(self) -> None:
        """Standalone-only commands have handler=None."""
        for cmd in COMMANDS:
            if cmd.standalone_only:
                assert cmd.handler is None, f"{cmd.name} should have handler=None"


class TestArgDef:
    """Test ArgDef dataclass."""

    def test_defaults(self) -> None:
        """ArgDef defaults are sensible."""
        arg = ArgDef(name="--foo")
        assert arg.help == ""
        assert arg.type is None
        assert arg.default is None
        assert arg.action is None
        assert arg.dest is None
        assert arg.nargs is None


class TestHandlers:
    """Test registry handler functions directly."""

    @pytest.mark.parametrize(
        ("handler", "method_name", "message"),
        [
            pytest.param(_handle_allow, "allow", "No IPs allowed", id="allow"),
            pytest.param(_handle_deny, "deny", "No IPs denied", id="deny"),
        ],
    )
    def test_handle_allow_and_deny_raise_on_failure(
        self,
        handler: Callable[..., None],
        method_name: str,
        message: str,
    ) -> None:
        """_handle_allow/_handle_deny raise RuntimeError when no IPs change."""
        shield = mock.MagicMock()
        getattr(shield, method_name).return_value = []
        with pytest.raises(RuntimeError) as ctx:
            handler(shield, "ctr", target="bad")
        assert message in str(ctx.value)

    def test_handle_logs_prints_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        """_handle_logs prints JSONL entries from shield.tail_log."""
        shield = mock.MagicMock()
        shield.tail_log.return_value = [{"action": "setup", "ts": "2026-01-01"}]
        _handle_logs(shield, "ctr", n=10)
        shield.tail_log.assert_called_once_with(10)
        entry = json.loads(capsys.readouterr().out.strip())
        assert entry["action"] == "setup"

    def test_handle_profiles_prints_names(self, capsys: pytest.CaptureFixture[str]) -> None:
        """_handle_profiles prints each profile name."""
        shield = mock.MagicMock()
        shield.profiles_list.return_value = ["dev-standard", "dev-python"]
        _handle_profiles(shield)
        lines = capsys.readouterr().out.strip().splitlines()
        assert lines == ["dev-standard", "dev-python"]

    def test_handle_status_global(self, capsys: pytest.CaptureFixture[str]) -> None:
        """_handle_status without container prints config overview."""
        shield = mock.MagicMock()
        shield.status.return_value = {
            "mode": "hook",
            "audit_enabled": True,
            "profiles": ["dev-standard"],
        }
        _handle_status(shield)
        output = capsys.readouterr().out
        assert "Mode:" in output
        assert "hook" in output

    def test_handle_status_with_container(self, capsys: pytest.CaptureFixture[str]) -> None:
        """_handle_status with container prints the ShieldState value."""
        from terok_shield import ShieldState

        shield = mock.MagicMock()
        shield.state.return_value = ShieldState.UP
        _handle_status(shield, container="ctr")
        assert capsys.readouterr().out.strip() == "up"

    def test_handle_watch_delegates_to_run_watch(self) -> None:
        """_handle_watch calls run_watch with state_dir and container."""
        shield = mock.MagicMock()
        with mock.patch("terok_shield.watch.run_watch") as mock_run:
            _handle_watch(shield, "ctr")
        mock_run.assert_called_once_with(shield.config.state_dir, "ctr")

    def test_handle_preview_all_without_down_raises(self) -> None:
        """_handle_preview raises ValueError when allow_all without down."""
        shield = mock.MagicMock()
        with pytest.raises(ValueError) as ctx:
            _handle_preview(shield, allow_all=True)
        assert "--all requires --down" in str(ctx.value)
