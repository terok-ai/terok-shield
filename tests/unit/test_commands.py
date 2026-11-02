# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the command registry and the per-verb handler modules."""

import argparse
import json
from collections.abc import Callable
from datetime import date, timedelta
from pathlib import Path
from unittest import mock

import pytest

from terok_shield import AllowResult, OverrideRevocation, SecurityTierRefusal, Shield
from terok_shield.commands import COMMANDS, is_container_arg, needs_container, standalone_only
from terok_shield.config import DnsTier, ShieldConfig, ShieldReading, ShieldState
from terok_shield.nft.constants import PASTA_DNS, PASTA_HOST_LOOPBACK_MAP
from terok_shield.policy import LOCALHOST
from terok_shield.state import StateBundle
from terok_shield.verbs._common import format_seconds
from terok_shield.verbs.control import (
    _ESTABLISHED_KEEP_RUNNING,
    _expiry_date,
    _handle_allow,
    _handle_bypass,
    _handle_deny,
    _handle_down,
    _handle_override,
    _handle_preview,
    _handle_quarantine,
    _handle_reset,
    _handle_up,
)
from terok_shield.verbs.observe import (
    _handle_harvest,
    _handle_logs,
    _handle_profiles,
    _handle_status,
)
from terok_shield.verbs.stream import _handle_simple_clearance, _handle_watch

from ..testnet import (
    AWS_IMDS_V4,
    CONTAINER_HOSTNAME,
    DOCKER_HOSTNAME,
    TEST_DOMAIN,
    TEST_IP1,
    TEST_IP2,
    TEST_NET1_HOST,
    VAULT_HOST,
)


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
            "override": {"container"},
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
        ("handler", "method_name", "outcome", "message"),
        [
            pytest.param(_handle_allow, "allow", AllowResult("bad"), "No IPs allowed", id="allow"),
            pytest.param(_handle_deny, "deny", [], "No IPs denied", id="deny"),
        ],
    )
    def test_handle_allow_and_deny_raise_on_failure(
        self,
        handler: Callable[..., None],
        method_name: str,
        outcome: object,
        message: str,
    ) -> None:
        """_handle_allow/_handle_deny raise RuntimeError when no IPs change."""
        shield = mock.MagicMock()
        getattr(shield, method_name).return_value = outcome
        with pytest.raises(RuntimeError) as ctx:
            handler(shield, "ctr", target="bad")
        assert message in str(ctx.value)

    def test_handle_allow_prints_the_addresses_a_running_container_took(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A live grant names every address the running ruleset now admits."""
        shield = mock.MagicMock()
        shield.allow.return_value = AllowResult(TEST_DOMAIN, (TEST_IP1, TEST_IP2))
        _handle_allow(shield, "ctr", target=TEST_DOMAIN)
        assert f"Allowed {TEST_DOMAIN} -> {TEST_IP1}, {TEST_IP2} for ctr" in capsys.readouterr().out

    def test_handle_allow_reports_a_stopped_container_as_pending(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No live ruleset is no failure: the grant waits for the next start, and says so."""
        shield = mock.MagicMock()
        shield.allow.return_value = AllowResult(TEST_DOMAIN, live=False)
        _handle_allow(shield, "ctr", target=TEST_DOMAIN)
        out = capsys.readouterr().out
        assert "ctr is not running" in out
        assert "applies at its next start" in out

    @pytest.mark.parametrize(
        ("refusal", "named"),
        [
            pytest.param(
                SecurityTierRefusal(TEST_DOMAIN, entry=TEST_IP1, address=TEST_IP1),
                TEST_IP1,
                id="shared-address",
            ),
            pytest.param(
                SecurityTierRefusal(TEST_DOMAIN, entry=TEST_DOMAIN), TEST_DOMAIN, id="by-name"
            ),
        ],
    )
    def test_handle_allow_turns_a_security_refusal_into_the_break_glass_hint(
        self, refusal: SecurityTierRefusal, named: str
    ) -> None:
        """The refusal fails the verb with its cause and the override as the way through."""
        shield = mock.MagicMock()
        shield.allow.side_effect = refusal
        with pytest.raises(RuntimeError) as ctx:
            _handle_allow(shield, "ctr", target=TEST_DOMAIN)
        message = str(ctx.value)
        assert named in message
        assert "break-glass only: use a shield.override" in message
        assert ctx.value.__cause__ is refusal

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
        from terok_shield import ShieldReading, ShieldState

        shield = mock.MagicMock()
        shield.inspect.return_value = ShieldReading(state=ShieldState.UP)
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

    def test_handle_bypass_never_claims_the_window_accepts_everything(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The window sits below the security tier and the private ranges, and says so."""
        shield = mock.MagicMock()
        shield.bypass.return_value = "5m"
        _handle_bypass(shield, "test-ctr", duration="5m")
        out = capsys.readouterr().out
        assert "everything is accepted" not in out
        assert "security tier and private ranges stay refused" in out

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
        shield.inspect.return_value = ShieldReading(state=ShieldState.UP, bypass_remaining=222)
        _handle_bypass(shield, "test-ctr")
        shield.bypass.assert_not_called()
        assert "3m42s left" in capsys.readouterr().out

    def test_handle_bypass_without_flags_counts_down_the_last_second(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A window in its last second is still open — ``0s left``, not closed."""
        shield = mock.MagicMock()
        shield.inspect.return_value = ShieldReading(state=ShieldState.UP, bypass_remaining=0)
        _handle_bypass(shield, "test-ctr")
        assert "0s left" in capsys.readouterr().out

    def test_handle_bypass_without_flags_says_when_none_is_open(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No window is an answer, phrased as one."""
        shield = mock.MagicMock()
        shield.inspect.return_value = ShieldReading(state=ShieldState.UP)
        _handle_bypass(shield, "test-ctr")
        assert "No bypass window" in capsys.readouterr().out

    def test_handle_bypass_without_flags_refuses_a_ruleset_that_fails_verification(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """An error-state ruleset may hold a window that never expires: "none open" is no answer.

        The verb fails instead, naming how to look and how to close one.
        """
        shield = mock.MagicMock()
        shield.inspect.return_value = ShieldReading(state=ShieldState.ERROR)
        with pytest.raises(RuntimeError, match="fails verification") as raised:
            _handle_bypass(shield, "test-ctr")
        assert "--off" in str(raised.value)
        assert "No bypass window" not in capsys.readouterr().out

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
        """The table names the action, the target, how often it appeared, its tier and remedies."""
        from terok_shield.harvest import HarvestEntry, HarvestReport

        shield = mock.MagicMock()
        shield.harvest.return_value = HarvestReport(
            entries=(
                HarvestEntry(
                    action="blocked",
                    target=TEST_DOMAIN,
                    count=7,
                    first_seen="2026-09-30T10:00:00+00:00",
                    last_seen="2026-09-30T10:30:00+00:00",
                    ports=(443,),
                    addresses=(),
                ),
            )
        )
        _handle_harvest(shield, "test-ctr")
        output = capsys.readouterr().out
        assert "blocked" in output
        assert TEST_DOMAIN in output
        assert "x7" in output
        assert "t40" in output
        assert "task,project,set" in output

    def test_handle_harvest_says_when_nothing_reaches_the_floor(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """An entry no remedy reaches says so in words, not with an empty column."""
        from terok_shield.harvest import TIER_HARD_DENY, HarvestEntry, HarvestReport

        shield = mock.MagicMock()
        shield.harvest.return_value = HarvestReport(
            entries=(
                HarvestEntry(
                    action="private_range",
                    target=AWS_IMDS_V4,
                    count=1,
                    first_seen="2026-09-30T10:00:00+00:00",
                    last_seen="2026-09-30T10:00:00+00:00",
                    ports=(80,),
                    addresses=(),
                    tier=TIER_HARD_DENY,
                    remedies=(),
                ),
            )
        )
        _handle_harvest(shield, "test-ctr")
        output = capsys.readouterr().out
        assert "private_range" in output
        assert "none" in output

    def test_handle_harvest_says_when_there_is_nothing(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """An empty harvest is an answer — a task that needed nothing it could not have."""
        from terok_shield.harvest import HarvestReport

        shield = mock.MagicMock()
        shield.harvest.return_value = HarvestReport()
        _handle_harvest(shield, "test-ctr")
        assert "Nothing harvested" in capsys.readouterr().out

    def test_handle_harvest_says_when_audit_was_disabled(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """With audit off an empty harvest is no answer, and the verb must not pass it off as one."""
        from terok_shield.harvest import HarvestReport

        shield = mock.MagicMock()
        shield.harvest.return_value = HarvestReport(audit_enabled=False)
        _handle_harvest(shield, "test-ctr")
        output = capsys.readouterr().out
        assert "Audit was disabled" in output
        assert "Nothing harvested" not in output

    def test_handle_harvest_json_is_machine_readable(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """``--json`` emits the whole report: the entries verbatim, and whether audit was on."""
        from terok_shield.harvest import HarvestEntry, HarvestReport

        shield = mock.MagicMock()
        shield.harvest.return_value = HarvestReport(
            entries=(
                HarvestEntry(
                    action="bypass",
                    target=TEST_DOMAIN,
                    count=1,
                    first_seen="2026-09-30T10:00:00+00:00",
                    last_seen="2026-09-30T10:00:00+00:00",
                    ports=(80,),
                    addresses=(TEST_IP1,),
                ),
            ),
            audit_enabled=True,
        )
        _handle_harvest(shield, "test-ctr", output_json=True)
        payload = json.loads(capsys.readouterr().out)
        assert payload["audit_enabled"] is True
        (entry,) = payload["entries"]
        assert entry["target"] == TEST_DOMAIN
        assert entry["ports"] == [80]
        assert entry["tier"] == "t40"
        assert entry["remedies"] == ["task", "project", "set"]

    def test_handle_preview_all_without_down_raises(self) -> None:
        """_handle_preview raises ValueError when disengaged without down."""
        shield = mock.MagicMock()
        with pytest.raises(ValueError) as ctx:
            _handle_preview(shield, disengaged=True)
        assert "--disengage requires --down" in str(ctx.value)


# ── override: break glass, and revoke it ──────────────────


_SOON = date.today() + timedelta(days=7)
_REASON = "vendor outage, direct debug #42"


@pytest.fixture
def launched_shield(make_config: Callable[..., ShieldConfig]) -> Shield:
    """A real Shield over a real HookMode, its bundle launched on pasta; nothing reaches a host."""
    config = make_config()
    bundle = StateBundle(config.state_dir)
    bundle.ensure_dirs()
    bundle.dns_tier.write_text(f"{DnsTier.LOOKUP.value}\n")
    bundle.network_mode.write_text("pasta\n")
    bundle.upstream_dns.write_text(f"{PASTA_DNS}\n")
    return Shield(
        config,
        runner=mock.MagicMock(),
        audit=mock.MagicMock(),
        dns=mock.MagicMock(),
        profiles=mock.MagicMock(),
        ruleset=mock.MagicMock(),
        hub_events=mock.MagicMock(),
    )


class TestOverrideVerb:
    """``override`` grants with both flags, revokes with ``--off``, and refuses as the shield does."""

    def test_grant_opens_the_override_and_says_until_when(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The addresses opened, the last day, that the kernel ends it — and what the end spares.

        The ruleset accepts established traffic ahead of every tier, so a
        connection opened through the override outlives its expiry; the verb
        says so rather than let "closes" promise otherwise.
        """
        shield = mock.MagicMock()
        shield.override.return_value = [TEST_IP1, TEST_IP2]

        _handle_override(shield, "ctr", target=TEST_DOMAIN, expires=_SOON, reason=_REASON)

        shield.override.assert_called_once_with("ctr", TEST_DOMAIN, _SOON, reason=_REASON)
        opened, until, established = capsys.readouterr().out.strip().splitlines()
        assert opened == f"Override open for ctr: {TEST_DOMAIN} -> {TEST_IP1}, {TEST_IP2}"
        assert until.startswith(f"Valid through {_SOON.isoformat()}: the kernel closes it")
        assert "end of that day, host local time" in until
        assert established == _ESTABLISHED_KEEP_RUNNING

    @pytest.mark.parametrize(
        ("expires", "reason", "missing"),
        [
            pytest.param(None, _REASON, "needs --expires:", id="no-expires"),
            pytest.param(_SOON, None, "needs --reason:", id="no-reason"),
            pytest.param(None, None, "needs --expires and --reason:", id="neither"),
        ],
    )
    def test_grant_needs_both_an_expiry_and_a_reason(
        self, expires: date | None, reason: str | None, missing: str
    ) -> None:
        """A break-glass says until when and why — the verb names what was left out."""
        shield = mock.MagicMock()
        with pytest.raises(ValueError, match=missing):
            _handle_override(shield, "ctr", target=TEST_DOMAIN, expires=expires, reason=reason)
        shield.override.assert_not_called()

    def test_off_revokes_and_says_what_closed(self, capsys: pytest.CaptureFixture[str]) -> None:
        """``--off`` ends the override now, names the addresses that closed, and what it spares.

        "Closed" covers new connections only — one already open through the
        override keeps its direct route — so the verb says that too.
        """
        shield = mock.MagicMock()
        shield.revoke_override.return_value = OverrideRevocation(
            target=TEST_DOMAIN, closed=(TEST_IP1,)
        )

        _handle_override(shield, "ctr", target=TEST_DOMAIN, off=True)

        shield.revoke_override.assert_called_once_with("ctr", TEST_DOMAIN)
        shield.override.assert_not_called()
        out = capsys.readouterr().out.strip()
        assert out == (
            f"Override of {TEST_DOMAIN} revoked for ctr: closed {TEST_IP1}\n"
            f"{_ESTABLISHED_KEEP_RUNNING}"
        )

    def test_off_names_what_another_override_keeps_open(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A wider override still covering an address is said out loud — the door is not shut."""
        shield = mock.MagicMock()
        shield.revoke_override.return_value = OverrideRevocation(
            target=TEST_DOMAIN, kept=(TEST_NET1_HOST,)
        )

        _handle_override(shield, "ctr", target=TEST_DOMAIN, off=True)

        revoked, established, kept = capsys.readouterr().out.strip().splitlines()
        assert revoked.endswith("no address closed")
        assert established == _ESTABLISHED_KEEP_RUNNING
        assert kept == (
            f"Still open above the security tier through another override: {TEST_NET1_HOST}"
        )

    def test_off_on_a_stopped_container_says_it_applies_at_the_next_start(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No ruleset to drop it from: the revoke is real, and takes effect from the next start."""
        shield = mock.MagicMock()
        shield.revoke_override.return_value = OverrideRevocation(
            target=TEST_DOMAIN, closed=(TEST_IP1,), live=False
        )

        _handle_override(shield, "ctr", target=TEST_DOMAIN, off=True)

        out = capsys.readouterr().out
        assert "ctr is not running" in out
        assert "its next start does not open it" in out
        assert _ESTABLISHED_KEEP_RUNNING not in out  # a stopped container has none open

    @pytest.mark.parametrize(
        "flags",
        [
            pytest.param({"expires": _SOON}, id="expires"),
            pytest.param({"reason": _REASON}, id="reason"),
        ],
    )
    def test_off_takes_no_expiry_or_reason(self, flags: dict[str, object]) -> None:
        """A revoke with grant flags is a muddled command — refused before anything changes."""
        shield = mock.MagicMock()
        with pytest.raises(ValueError, match="takes no --expires or --reason"):
            _handle_override(shield, "ctr", target=TEST_DOMAIN, off=True, **flags)
        shield.revoke_override.assert_not_called()
        shield.override.assert_not_called()

    @pytest.mark.parametrize(
        ("target", "refusal"),
        [
            pytest.param(AWS_IMDS_V4, "inside the hard-deny floor", id="hard-deny"),
            pytest.param(PASTA_HOST_LOOPBACK_MAP, "the host's own loopback", id="host-map"),
            pytest.param(CONTAINER_HOSTNAME, "is the host itself", id="host-alias"),
            pytest.param(DOCKER_HOSTNAME, "is the host itself", id="docker-host-alias"),
            pytest.param(LOCALHOST, "is the host itself", id="localhost"),
        ],
    )
    def test_grant_refuses_the_floor_and_the_host_in_the_shields_own_words(
        self, launched_shield: Shield, target: str, refusal: str
    ) -> None:
        """The verb adds no rule and rewords none: its refusal is the library's, verbatim.

        No override can ever carry these, so the answer never depends on
        whether one could be granted right now.  The posture reads as a
        stopped container's — the one that would refuse every grant on its
        own — and is never read at all: the refusal comes first.
        """
        with mock.patch(
            "terok_shield.hooks.mode.HookMode.shield_state", return_value=ShieldState.OFFLINE
        ) as probe:
            with pytest.raises(ValueError, match=refusal) as library:
                launched_shield.override("ctr", target, _SOON, reason=_REASON)
            with pytest.raises(ValueError) as verb:
                _handle_override(
                    launched_shield, "ctr", target=target, expires=_SOON, reason=_REASON
                )

        assert str(verb.value) == str(library.value)
        probe.assert_not_called()
        assert not StateBundle(launched_shield.config.state_dir).tier_path("override").exists()

    def test_off_with_nothing_to_revoke_fails_in_the_shields_own_words(
        self, launched_shield: Shield
    ) -> None:
        """No override in force is an error the operator sees, never a quiet "revoked"."""
        with pytest.raises(RuntimeError) as library:
            launched_shield.revoke_override("ctr", TEST_DOMAIN)
        with pytest.raises(RuntimeError) as verb:
            _handle_override(launched_shield, "ctr", target=TEST_DOMAIN, off=True)
        assert str(verb.value) == str(library.value)
        assert f"has no override of {TEST_DOMAIN} to revoke" in str(verb.value)


def test_expires_parses_a_calendar_date() -> None:
    """The one spelling an operator writes, surrounding blanks forgiven."""
    assert _expiry_date(f" {_SOON.isoformat()} ") == _SOON


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("2026-02-30", id="no-such-day"),
        pytest.param("2026-13-01", id="no-such-month"),
        pytest.param("tomorrow", id="word"),
        pytest.param("20261130", id="basic-format"),
        pytest.param("2026-11-30T12:00", id="timestamp"),
    ],
)
def test_expires_refuses_anything_but_a_calendar_date(text: str) -> None:
    """argparse turns this into a usage error naming the expected form."""
    with pytest.raises(argparse.ArgumentTypeError, match="expected YYYY-MM-DD"):
        _expiry_date(text)


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


# ── the degraded-tier rotation warning on stderr ──────────


def _pinned_shield(state_dir: Path) -> mock.MagicMock:
    """A shield whose bundle pins one allowlisted and one security-tier name (lookup tier)."""
    bundle = StateBundle(state_dir)
    bundle.ensure_dirs()
    bundle.dns_tier.write_text(f"{DnsTier.LOOKUP.value}\n")
    bundle.write_tier("project_allow", f"+{TEST_DOMAIN}\n")
    bundle.write_tier("security_deny", f"-{VAULT_HOST}\n")
    shield = mock.MagicMock()
    shield.config.state_dir = state_dir
    return shield


class TestRotationWarning:
    """``up`` / ``down`` say what the tier pins — on stderr, worded for the posture."""

    def test_up_names_every_pinned_kind(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Raised: allowlisted names can break, and the deny can leak."""
        _handle_up(_pinned_shield(tmp_path), "ctr", container_id="cid")
        out, err = capsys.readouterr()
        assert out.strip() == "Shield up for ctr"
        allow, deny = err.strip().splitlines()
        assert TEST_DOMAIN in allow
        assert VAULT_HOST in deny

    def test_down_names_the_deny_alone(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Down, a pinned allow is moot — the security tier is what is still meant to hold."""
        _handle_down(_pinned_shield(tmp_path), "ctr", container_id="cid")
        (deny,) = capsys.readouterr().err.strip().splitlines()
        assert "the shield is down" in deny

    def test_disengaged_down_has_nothing_to_warn_about(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """DISENGAGED enforces nothing, so no name it pins can matter."""
        _handle_down(_pinned_shield(tmp_path), "ctr", container_id="cid", disengaged=True)
        assert capsys.readouterr().err == ""

    def test_no_recorded_tier_no_warning(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A container never shielded from this state dir has nothing to say."""
        shield = mock.MagicMock()
        shield.config.state_dir = tmp_path
        _handle_up(shield, "ctr", container_id="cid")
        assert capsys.readouterr().err == ""


@pytest.mark.parametrize(
    ("seconds", "text"),
    [
        pytest.param(0, "0s", id="last-second"),
        pytest.param(59, "59s", id="seconds"),
        pytest.param(299, "4m59s", id="minutes"),
        pytest.param(3600, "1h", id="zero-units-dropped"),
        pytest.param(90061, "1d1h1m1s", id="days"),
        pytest.param(-3, "0s", id="never-negative"),
    ],
)
def test_format_seconds_spells_a_countdown_like_nft(seconds: int, text: str) -> None:
    """Whole seconds, compound units, nothing below a second."""
    assert format_seconds(seconds) == text
