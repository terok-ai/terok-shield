# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the command registry and the per-verb handler modules."""

import json
from collections.abc import Callable
from unittest import mock

import pytest

from terok_shield.commands import COMMANDS, is_container_arg, needs_container, standalone_only
from terok_shield.verbs.control import (
    _handle_allow,
    _handle_bypass,
    _handle_deny,
    _handle_preview,
    _handle_quarantine,
    _handle_reset,
)
from terok_shield.verbs.observe import (
    _handle_harvest,
    _handle_logs,
    _handle_profiles,
    _handle_status,
)
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

    def test_is_container_arg_matches_exactly_the_container_spellings(self) -> None:
        """The predicate's verdict over the whole live registry, arg by arg.

        Asserting the complete mapping (not a sample) makes a false
        positive on any verb — today's or a future one — fail loudly.
        """
        matched = {
            resolved.name: {arg.name for arg in resolved.args if is_container_arg(arg)}
            for cmd in COMMANDS
            if (resolved := cmd.resolve()).args
        }
        assert matched == {
            "status": {"container"},  # the optional (nargs="?") positional
            "prepare": {"container"},
            "run": {"container"},
            "resolve": {"container"},
            "allow": {"container"},
            "deny": {"container"},
            "down": {"container", "--container-id"},
            "up": {"container", "--container-id"},
            "bypass": {"container"},
            "reset": {"container"},
            "quarantine": {"container"},
            "rules": {"container"},
            "harvest": {"container"},
            "watch": {"container"},
            "simple-clearance": {"container"},
            "logs": {"--container"},  # the standalone CLI's optional filter
            "preview": set(),
        }

    def test_is_container_arg_handles_wire_layer_spellings(self) -> None:
        """Slash-form names and explicit dests resolve like the wire layer's dest.

        The registry doesn't use these forms today, but the wire layer
        supports them — and the predicate's whole job is to keep a future
        spelling from slipping past the bridge.
        """
        from terok_util import ArgDef

        assert is_container_arg(ArgDef(name="-c/--container"))
        assert is_container_arg(ArgDef(name="--target", dest="container"))
        assert not is_container_arg(ArgDef(name="--container", dest="container_filter"))


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

    def test_handle_bypass_opens_the_window_for_the_named_duration(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """``--for`` arms the window and says what was granted."""
        shield = mock.MagicMock()
        shield.bypass.return_value = "5m"
        _handle_bypass(shield, "test-ctr", duration="5m")
        shield.bypass.assert_called_once_with("test-ctr", "5m")
        assert "5m" in capsys.readouterr().out

    def test_handle_bypass_off_closes_the_window(self, capsys: pytest.CaptureFixture[str]) -> None:
        """``--off`` closes it without consulting the remaining time."""
        shield = mock.MagicMock()
        _handle_bypass(shield, "test-ctr", off=True)
        shield.bypass_off.assert_called_once_with("test-ctr")
        shield.bypass.assert_not_called()
        assert "closed" in capsys.readouterr().out

    def test_handle_bypass_without_flags_reports_the_countdown(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Bare, the verb reads the kernel's clock and arms nothing."""
        shield = mock.MagicMock()
        shield.bypass_remaining.return_value = "3m42s"
        _handle_bypass(shield, "test-ctr")
        shield.bypass.assert_not_called()
        assert "3m42s" in capsys.readouterr().out

    def test_handle_bypass_without_flags_says_when_none_is_open(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No window is an answer, phrased as one."""
        shield = mock.MagicMock()
        shield.bypass_remaining.return_value = None
        _handle_bypass(shield, "test-ctr")
        assert "No bypass window" in capsys.readouterr().out

    def test_handle_reset_delegates_and_prints(self, capsys: pytest.CaptureFixture[str]) -> None:
        """_handle_reset calls shield.reset() and prints confirmation."""
        shield = mock.MagicMock()
        _handle_reset(shield, "test-ctr")
        shield.reset.assert_called_once_with("test-ctr")
        output = capsys.readouterr().out
        assert "reset" in output
        assert "test-ctr" in output

    def test_handle_harvest_prints_one_row_per_target(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The table names the action, the target and how often it appeared."""
        from terok_shield.harvest import HarvestEntry

        shield = mock.MagicMock()
        shield.harvest.return_value = [
            HarvestEntry(
                action="blocked",
                target="example.test",
                count=7,
                first_seen="2026-09-30T10:00:00+00:00",
                last_seen="2026-09-30T10:30:00+00:00",
                ports=(443,),
                addresses=(),
            )
        ]
        _handle_harvest(shield, "test-ctr")
        output = capsys.readouterr().out
        assert "blocked" in output
        assert "example.test" in output
        assert "x7" in output

    def test_handle_harvest_says_when_there_is_nothing(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """An empty harvest is an answer — a task that needed nothing it could not have."""
        shield = mock.MagicMock()
        shield.harvest.return_value = []
        _handle_harvest(shield, "test-ctr")
        assert "Nothing harvested" in capsys.readouterr().out

    def test_handle_harvest_json_is_machine_readable(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """``--json`` emits the entries verbatim for a caller that renders its own view."""
        from terok_shield.harvest import HarvestEntry

        shield = mock.MagicMock()
        shield.harvest.return_value = [
            HarvestEntry(
                action="bypass",
                target="example.test",
                count=1,
                first_seen="2026-09-30T10:00:00+00:00",
                last_seen="2026-09-30T10:00:00+00:00",
                ports=(80,),
                addresses=("192.0.2.1",),
            )
        ]
        _handle_harvest(shield, "test-ctr", output_json=True)
        payload = json.loads(capsys.readouterr().out)
        assert payload[0]["target"] == "example.test"
        assert payload[0]["ports"] == [80]

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
