# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the command registry and the per-verb handler modules."""

import json
from collections.abc import Callable
from unittest import mock

import pytest

from terok_shield.commands import COMMANDS, needs_container, standalone_only
from terok_shield.verbs.control import (
    _handle_allow,
    _handle_deny,
    _handle_preview,
    _handle_quarantine,
    _handle_reset,
)
from terok_shield.verbs.observe import _handle_logs, _handle_profiles, _handle_status
from terok_shield.verbs.stream import _handle_simple_clearance, _handle_watch


class TestCommandDefs:
    """Test the COMMANDS registry structure and invariants.

    The roots are lazy references (name + help + ``source``); their full
    shape lives in the verb modules, so each is
    [resolved][terok_util.cli_types.CommandDef.resolve] before its
    handler/extras are inspected.
    """

    def test_roots_are_lazy(self) -> None:
        """Every top-level root defers to a source module."""
        assert COMMANDS.roots, "registry must not be empty"
        for cmd in COMMANDS:
            assert cmd.is_lazy, f"{cmd.name} should be a lazy root"
            assert cmd.help, f"{cmd.name} lazy root must carry help text"

    def test_names_unique(self) -> None:
        """All command names are unique."""
        names = [cmd.name for cmd in COMMANDS]
        assert len(names) == len(set(names))

    def test_sources_resolve(self) -> None:
        """Each lazy root resolves to a full CommandDef with the same name."""
        for cmd in COMMANDS:
            resolved = cmd.resolve()
            assert resolved.name == cmd.name

    def test_handler_present_when_not_standalone_only(self) -> None:
        """Non-standalone commands resolve to a handler."""
        for cmd in COMMANDS:
            resolved = cmd.resolve()
            if not standalone_only(resolved):
                assert resolved.handler is not None, f"{cmd.name} missing handler"

    def test_standalone_only_have_no_handler(self) -> None:
        """Standalone-only commands resolve to handler=None."""
        for cmd in COMMANDS:
            resolved = cmd.resolve()
            if standalone_only(resolved):
                assert resolved.handler is None, f"{cmd.name} should have handler=None"

    def test_needs_container_verbs_carry_container_arg(self) -> None:
        """Every ``needs_container`` verb defines a ``container`` argument."""
        for cmd in COMMANDS:
            resolved = cmd.resolve()
            if needs_container(resolved):
                dests = {
                    arg.dest or arg.name.lstrip("-").replace("-", "_") for arg in resolved.args
                }
                assert "container" in dests, f"{cmd.name} needs_container but has no container arg"


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

    def test_handle_watch_confines_then_delegates(self) -> None:
        """_handle_watch applies the state-reader policy before running watch."""
        shield = mock.MagicMock()
        calls = mock.Mock()
        with (
            mock.patch("terok_shield._confine.confine_to_state", calls.confine),
            mock.patch("terok_shield.watch.run_watch", calls.run),
        ):
            _handle_watch(shield, "ctr")
        assert calls.mock_calls == [
            mock.call.confine(shield.config.state_dir),
            mock.call.run(shield.config.state_dir, "ctr"),
        ]

    def test_handle_simple_clearance_does_not_confine_controller(self) -> None:
        """The Podman/verdict controller does not use the state-reader policy."""
        shield = mock.MagicMock()
        with (
            mock.patch("terok_shield._confine.confine_to_state") as mock_confine,
            mock.patch("terok_shield.simple_clearance.run_simple_clearance") as mock_run,
        ):
            _handle_simple_clearance(shield, "ctr")
        mock_confine.assert_not_called()
        mock_run.assert_called_once_with(shield.config.state_dir, "ctr")

    def test_handle_quarantine_delegates_and_prints(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """_handle_quarantine calls shield.quarantine() and prints confirmation."""
        shield = mock.MagicMock()
        _handle_quarantine(shield, "test-ctr")
        shield.quarantine.assert_called_once_with("test-ctr")
        output = capsys.readouterr().out
        assert "QUARANTINED" in output
        assert "test-ctr" in output

    def test_handle_reset_delegates_and_prints(self, capsys: pytest.CaptureFixture[str]) -> None:
        """_handle_reset calls shield.reset() and prints confirmation."""
        shield = mock.MagicMock()
        _handle_reset(shield, "test-ctr")
        shield.reset.assert_called_once_with("test-ctr")
        output = capsys.readouterr().out
        assert "reset" in output
        assert "test-ctr" in output

    def test_handle_preview_all_without_down_raises(self) -> None:
        """_handle_preview raises ValueError when disengaged without down."""
        shield = mock.MagicMock()
        with pytest.raises(ValueError) as ctx:
            _handle_preview(shield, disengaged=True)
        assert "--disengage requires --down" in str(ctx.value)


class TestPrintEnvHint:
    """``print_env_hint`` prints issues and the setup hint when present."""

    def test_prints_issues_and_hint(self, capsys: pytest.CaptureFixture) -> None:
        from terok_shield import EnvironmentCheck
        from terok_shield.verbs._common import print_env_hint

        env = EnvironmentCheck(
            ok=False,
            hooks="none",
            health="degraded",
            issues=["nft missing"],
            setup_hint="run setup",
        )
        print_env_hint(env)
        out = capsys.readouterr().out
        assert "nft missing" in out
        assert "run setup" in out

    def test_silent_when_clean(self, capsys: pytest.CaptureFixture) -> None:
        from terok_shield import EnvironmentCheck
        from terok_shield.verbs._common import print_env_hint

        print_env_hint(EnvironmentCheck(ok=True, hooks="per-container", health="ok"))
        assert capsys.readouterr().out == ""
