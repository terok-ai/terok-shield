# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Shield facade class (__init__.py)."""

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import pytest
from terok_util import SetupCheck, SetupStatus

from terok_shield import DnsTier, ExecError, Shield, ShieldConfig, ShieldState, state
from terok_shield.run import ShieldNeedsSetup

from ..testfs import NFT_BINARY
from ..testnet import TEST_DOMAIN, TEST_DOMAIN2, TEST_IP1, TEST_IP2

ConfigFactory = Callable[..., ShieldConfig]


@dataclass
class ShieldHarness:
    """A ``Shield`` instance plus its mock collaborators."""

    shield: Shield
    runner: mock.MagicMock
    audit: mock.MagicMock
    dns: mock.MagicMock
    profiles: mock.MagicMock
    ruleset: mock.MagicMock
    mode: mock.MagicMock
    hub_events: mock.MagicMock


ShieldHarnessFactory = Callable[..., ShieldHarness]


@pytest.fixture
def make_shield(make_config: ConfigFactory) -> ShieldHarnessFactory:
    """Create a ``Shield`` with injected mocks while bypassing ``_create_mode``."""

    def _make_shield(
        config: ShieldConfig | None = None,
        *,
        mode: mock.MagicMock | None = None,
        audit: mock.MagicMock | None = None,
        dns: mock.MagicMock | None = None,
        profiles: mock.MagicMock | None = None,
        ruleset: mock.MagicMock | None = None,
        hub_events: mock.MagicMock | None = None,
    ) -> ShieldHarness:
        harness = ShieldHarness(
            shield=Shield.__new__(Shield),
            runner=mock.MagicMock(),
            audit=audit or mock.MagicMock(),
            dns=dns or mock.MagicMock(),
            profiles=profiles or mock.MagicMock(),
            ruleset=ruleset or mock.MagicMock(),
            mode=mode or mock.MagicMock(),
            hub_events=hub_events or mock.MagicMock(),
        )
        harness.shield.config = config or make_config()
        harness.shield.runner = harness.runner
        harness.shield.audit = harness.audit
        harness.shield.dns = harness.dns
        harness.shield.profiles = harness.profiles
        harness.shield.ruleset = harness.ruleset
        harness.shield.hub_events = harness.hub_events
        harness.shield._mode = harness.mode
        return harness

    return _make_shield


@mock.patch("terok_shield.run.find_nft", return_value=NFT_BINARY)
def test_shield_default_collaborators(_find: mock.Mock, tmp_path: Path) -> None:
    """Shield creates default collaborators when none are injected."""
    shield = Shield(ShieldConfig(state_dir=tmp_path))
    assert shield.runner is not None
    assert shield.audit is not None
    assert shield.dns is not None
    assert shield.profiles is not None
    assert shield.ruleset is not None
    assert shield.hub_events is not None


def test_shield_uses_injected_collaborators(tmp_path: Path) -> None:
    """Shield keeps explicitly injected collaborators."""
    runner = mock.MagicMock()
    audit = mock.MagicMock()
    dns = mock.MagicMock()
    profiles = mock.MagicMock()
    ruleset = mock.MagicMock()
    hub_events = mock.MagicMock()

    shield = Shield(
        ShieldConfig(state_dir=tmp_path),
        runner=runner,
        audit=audit,
        dns=dns,
        profiles=profiles,
        ruleset=ruleset,
        hub_events=hub_events,
    )

    assert shield.runner is runner
    assert shield.audit is audit
    assert shield.dns is dns
    assert shield.profiles is profiles
    assert shield.ruleset is ruleset
    assert shield.hub_events is hub_events


def test_create_mode_rejects_unsupported_value(
    tmp_path: Path, make_shield: ShieldHarnessFactory
) -> None:
    """_create_mode raises ValueError for unsupported modes."""
    harness = make_shield(config=ShieldConfig(state_dir=tmp_path))
    fake_mode = mock.MagicMock()
    fake_mode.__eq__ = lambda self, other: False
    with pytest.raises(ValueError):
        harness.shield._create_mode(fake_mode)


def test_status_returns_mode_profiles_and_audit(make_shield: ShieldHarnessFactory) -> None:
    """status() reports the facade configuration and available profiles."""
    harness = make_shield()
    harness.profiles.list_profiles.return_value = ["base", "dev-standard"]
    result = harness.shield.status()
    assert result == {
        "mode": "hook",
        "profiles": ["base", "dev-standard"],
        "audit_enabled": True,
    }


def test_pre_start_dispatches_and_logs(make_shield: ShieldHarnessFactory) -> None:
    """pre_start() delegates to the backend and logs the chosen profiles."""
    harness = make_shield()
    harness.mode.pre_start.return_value = ["--network", "pasta:"]

    result = harness.shield.pre_start("test-ctr", ["dev-standard"])

    harness.mode.pre_start.assert_called_once_with(
        "test-ctr",
        ["dev-standard"],
        security_deny=(),
        provider_allow=(),
        project_allow=(),
        override=(),
    )
    assert result == ["--network", "pasta:"]
    harness.audit.log_event.assert_called_once_with(
        "test-ctr", "setup", detail="profiles=dev-standard"
    )


def test_pre_start_uses_default_profiles(
    make_shield: ShieldHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start() falls back to config.default_profiles when profiles is None."""
    harness = make_shield(config=make_config(default_profiles=("base",)))
    harness.mode.pre_start.return_value = []

    harness.shield.pre_start("test-ctr")
    harness.mode.pre_start.assert_called_once_with(
        "test-ctr", ["base"], security_deny=(), provider_allow=(), project_allow=(), override=()
    )


def test_refresh_dispatches_and_logs(
    make_shield: ShieldHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """refresh() delegates the tier data to the backend and audit-logs the event.

    Same default-profiles fallback as pre_start — the restart path passes
    ``None`` and gets the config's composed profile set.
    """
    harness = make_shield(config=make_config(default_profiles=("base",)))

    harness.shield.refresh("test-ctr", security_deny=(TEST_DOMAIN,), override=(TEST_DOMAIN2,))

    harness.mode.refresh.assert_called_once_with(
        "test-ctr",
        ["base"],
        security_deny=(TEST_DOMAIN,),
        provider_allow=(),
        project_allow=(),
        override=(TEST_DOMAIN2,),
    )
    harness.audit.log_event.assert_called_once_with("test-ctr", "refresh", detail="profiles=base")


@pytest.mark.parametrize(
    ("method", "target", "resolver_method", "backend_method", "expected"),
    [
        pytest.param("allow", TEST_IP1, None, "allow_ip", [TEST_IP1], id="allow-ip"),
        pytest.param("deny", TEST_IP1, None, "deny_ip", [TEST_IP1], id="deny-ip"),
        pytest.param(
            "allow",
            TEST_DOMAIN,
            "resolve_domains",
            "allow_ip",
            [TEST_IP1, TEST_IP2],
            id="allow-domain",
        ),
        pytest.param(
            "deny",
            TEST_DOMAIN,
            "resolve_domains",
            "deny_ip",
            [TEST_IP1, TEST_IP2],
            id="deny-domain",
        ),
    ],
)
def test_allow_and_deny_resolve_targets_and_delegate(
    make_shield: ShieldHarnessFactory,
    method: str,
    target: str,
    resolver_method: str | None,
    backend_method: str,
    expected: list[str],
) -> None:
    """allow()/deny() either use the target directly or resolve domains first."""
    harness = make_shield()
    harness.dns.resolve_domains.return_value = [TEST_IP1, TEST_IP2]

    result = getattr(harness.shield, method)("test-ctr", target)

    if resolver_method is None:
        harness.dns.resolve_domains.assert_not_called()
    else:
        getattr(harness.dns, resolver_method).assert_called_once_with([target])
    assert getattr(harness.mode, backend_method).call_args_list == [
        mock.call("test-ctr", ip) for ip in expected
    ]
    assert result == expected
    assert harness.audit.log_event.call_count == len(expected)


@pytest.mark.parametrize(
    ("method", "backend_method", "target"),
    [
        pytest.param("allow", "allow_ip", TEST_IP1, id="allow"),
        pytest.param("deny", "deny_ip", TEST_IP1, id="deny"),
    ],
)
def test_allow_and_deny_swallow_backend_exceptions(
    make_shield: ShieldHarnessFactory,
    method: str,
    backend_method: str,
    target: str,
) -> None:
    """allow()/deny() are best-effort when backend IP operations fail."""
    harness = make_shield()
    getattr(harness.mode, backend_method).side_effect = ExecError(["nft"], 1, "nft failed")
    assert getattr(harness.shield, method)("test-ctr", target) == []


@pytest.mark.parametrize("method", ["allow", "deny"])
def test_allow_and_deny_refuse_a_wildcard_on_a_static_tier(
    make_shield: ShieldHarnessFactory, method: str, tmp_path: Path
) -> None:
    """A ``*.`` target names no address where names resolve once, so it is refused up front."""
    harness = make_shield(ShieldConfig(state_dir=tmp_path))
    state.StateBundle(tmp_path).dns_tier.write_text(f"{DnsTier.LOOKUP.value}\n")
    verdict = getattr(harness.shield, method)

    with pytest.raises(ShieldNeedsSetup, match=r"lookup tier: \*\."):
        verdict("test-ctr", f"*.{TEST_DOMAIN}")

    harness.dns.resolve_domains.assert_not_called()


def test_rules_delegates_to_mode(make_shield: ShieldHarnessFactory) -> None:
    """rules() returns the backend ruleset text."""
    harness = make_shield()
    harness.mode.list_rules.return_value = "table inet terok_shield {}"
    assert "terok_shield" in harness.shield.rules("test-ctr")
    harness.mode.list_rules.assert_called_once_with("test-ctr")


@pytest.mark.parametrize(
    ("disengaged", "expected_detail"),
    [
        pytest.param(False, None, id="default"),
        pytest.param(True, "disengaged=True", id="disengaged"),
    ],
)
def test_down_delegates_and_logs(
    make_shield: ShieldHarnessFactory,
    disengaged: bool,
    expected_detail: str | None,
) -> None:
    """down() delegates to the backend, logs, and pings the hub."""
    harness = make_shield()
    harness.shield.down("test-ctr", "ctr-uuid-1", disengaged=disengaged)
    harness.mode.shield_down.assert_called_once_with("test-ctr", disengaged=disengaged)
    harness.audit.log_event.assert_called_once_with(
        "test-ctr", "shield_down", detail=expected_detail
    )
    harness.hub_events.shield_down.assert_called_once_with(
        "test-ctr", "ctr-uuid-1", disengaged=disengaged, dossier={}
    )


def test_up_delegates_and_logs(make_shield: ShieldHarnessFactory) -> None:
    """up() delegates to the backend, logs, and pings the hub."""
    harness = make_shield()
    harness.shield.up("test-ctr", "ctr-uuid-1")
    harness.mode.shield_up.assert_called_once_with("test-ctr")
    harness.audit.log_event.assert_called_once_with("test-ctr", "shield_up")
    harness.hub_events.shield_up.assert_called_once_with("test-ctr", "ctr-uuid-1", dossier={})


def test_up_resolves_dossier_via_meta_path(
    make_shield: ShieldHarnessFactory, state_dir: Path, tmp_path: Path
) -> None:
    """``Shield.up()`` resolves its hub-event dossier by following ``state_dir/meta_path`` into the orchestrator's wire-dossier file.

    Single source of truth: the wire-dossier JSON file the orchestrator
    maintains.  Without this the clearance UI rendered shield state
    changes with a bare container slug while block popups carried the
    full ``project/task · name`` triple — the same container, two
    visual identities in one session.
    """
    meta = tmp_path / "abc.json"
    meta.write_text(json.dumps({"project": "terok", "task": "abc", "name": "diligent-octopus"}))
    StateBundle(state_dir).meta_path.write_text(str(meta))
    harness = make_shield()
    harness.shield.up("test-ctr", "ctr-uuid-1")
    harness.hub_events.shield_up.assert_called_once_with(
        "test-ctr",
        "ctr-uuid-1",
        dossier={"project": "terok", "task": "abc", "name": "diligent-octopus"},
    )


def test_down_resolves_dossier_via_meta_path(
    make_shield: ShieldHarnessFactory, state_dir: Path, tmp_path: Path
) -> None:
    """``Shield.down()`` carries the same identity bundle as ``up()`` (resolved live each call)."""
    meta = tmp_path / "xyz.json"
    meta.write_text(json.dumps({"project": "terok", "task": "xyz"}))
    StateBundle(state_dir).meta_path.write_text(str(meta))
    harness = make_shield()
    harness.shield.down("test-ctr", "ctr-uuid-1", disengaged=True)
    harness.hub_events.shield_down.assert_called_once_with(
        "test-ctr",
        "ctr-uuid-1",
        disengaged=True,
        dossier={"project": "terok", "task": "xyz"},
    )


def test_quarantine_delegates_and_logs(make_shield: ShieldHarnessFactory) -> None:
    """quarantine() delegates to the backend and logs the transition."""
    harness = make_shield()
    harness.shield.quarantine("test-ctr")
    harness.mode.shield_quarantine.assert_called_once_with("test-ctr")
    harness.audit.log_event.assert_called_once_with("test-ctr", "shield_quarantine")


def test_state_delegates_to_mode(make_shield: ShieldHarnessFactory) -> None:
    """state() returns the backend shield state."""
    harness = make_shield()
    harness.mode.shield_state.return_value = ShieldState.UP
    assert harness.shield.state("test-ctr") == ShieldState.UP


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        pytest.param({}, "table inet terok_shield { policy drop }", id="default"),
        pytest.param({"down": True, "disengaged": True}, "disengaged", id="down-disengaged"),
    ],
)
def test_preview_delegates_to_mode(
    make_shield: ShieldHarnessFactory,
    kwargs: dict[str, bool],
    expected: str,
) -> None:
    """preview() passes through the requested preview mode."""
    harness = make_shield()
    harness.mode.preview.return_value = expected
    assert harness.shield.preview(**kwargs) == expected
    harness.mode.preview.assert_called_once_with(
        down=kwargs.get("down", False), disengaged=kwargs.get("disengaged", False)
    )


def test_resolve_composes_profiles_and_caches_dns(make_shield: ShieldHarnessFactory) -> None:
    """resolve() composes profile entries and passes them to the DNS cache."""
    harness = make_shield()
    harness.profiles.compose_profiles.return_value = [TEST_DOMAIN]
    harness.dns.resolve_and_cache.return_value = [TEST_IP1]

    result = harness.shield.resolve(["dev-standard"])

    harness.profiles.compose_profiles.assert_called_once_with(["dev-standard"])
    harness.dns.resolve_and_cache.assert_called_once()
    assert result == [TEST_IP1]


def test_resolve_returns_empty_for_empty_profiles(make_shield: ShieldHarnessFactory) -> None:
    """resolve() short-circuits when composed profiles contain no entries."""
    harness = make_shield()
    harness.profiles.compose_profiles.return_value = []
    assert harness.shield.resolve(["empty"]) == []


@pytest.mark.parametrize(
    ("force", "expected_max_age"),
    [
        pytest.param(False, 3600, id="default-cache"),
        pytest.param(True, 0, id="force-refresh"),
    ],
)
def test_resolve_passes_cache_age(
    make_shield: ShieldHarnessFactory,
    force: bool,
    expected_max_age: int,
) -> None:
    """resolve() adjusts cache freshness based on the force flag."""
    harness = make_shield()
    harness.profiles.compose_profiles.return_value = [TEST_DOMAIN]
    harness.dns.resolve_and_cache.return_value = [TEST_IP1]

    harness.shield.resolve(["dev-standard"], force=force)
    assert harness.dns.resolve_and_cache.call_args.kwargs["max_age"] == expected_max_age


def test_resolve_uses_default_profiles(
    make_shield: ShieldHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """resolve() falls back to config.default_profiles when profiles is None."""
    harness = make_shield(config=make_config(default_profiles=("base",)))
    harness.profiles.compose_profiles.return_value = []
    harness.shield.resolve()
    harness.profiles.compose_profiles.assert_called_once_with(["base"])


@pytest.mark.parametrize(
    ("method", "return_value", "args"),
    [
        pytest.param("profiles_list", ["base", "dev"], (), id="profiles-list"),
        pytest.param("compose_profiles", [TEST_DOMAIN], (["dev-standard"],), id="compose-profiles"),
    ],
)
def test_simple_profile_delegations(
    make_shield: ShieldHarnessFactory,
    method: str,
    return_value: list[str],
    args: tuple[list[str], ...],
) -> None:
    """Small profile-related helpers delegate directly to the collaborator."""
    harness = make_shield()
    target = (
        harness.profiles.list_profiles
        if method == "profiles_list"
        else harness.profiles.compose_profiles
    )
    target.return_value = return_value
    assert getattr(harness.shield, method)(*args) == return_value


def test_tail_log_delegates_to_audit(make_shield: ShieldHarnessFactory) -> None:
    """tail_log() delegates to audit.tail_log()."""
    harness = make_shield()
    harness.audit.tail_log.return_value = iter([{"action": "setup"}])
    result = harness.shield.tail_log(10)
    harness.audit.tail_log.assert_called_once_with(10)
    assert isinstance(result, Iterator)


# ── check_environment tests ──────────────────────────────


def _podman_info_json(version: str = "5.8.0", **host_extra: object) -> str:
    """Build a mock podman info JSON string."""
    return json.dumps({"host": {**host_extra}, "version": {"Version": version}})


def _run_side_effect(podman_version: str = "5.8.0"):
    """Return a runner.run side_effect that handles both podman info and dnsmasq version.

    Needed because check_environment() calls runner.run() for both podman info
    and dnsmasq --version (nftset capability probe).
    """

    def _effect(cmd: list[str], **_kw: object) -> str:
        if Path(cmd[0]).name == "dnsmasq":
            return "Dnsmasq version 2.92\nCompile time options: nftset\n"
        return _podman_info_json(podman_version)

    return _effect


@mock.patch(
    "terok_shield.hooks.install.HooksInstaller.check_setup",
    return_value=(SetupCheck("terok-shield", "hooks", SetupStatus.READY),),
)
class TestCheckEnvironment:
    """Environment diagnostics with owned setup checks isolated from the host."""

    def test_no_lookup_tool_reports_issue(
        self,
        check_setup: mock.Mock,
        make_shield: ShieldHarnessFactory,
    ) -> None:
        """No lookup tool and no dnsmasq reports getent degradation in the environment check."""
        harness = make_shield()
        harness.runner.run.return_value = _podman_info_json("5.8.0")
        harness.runner.has.side_effect = lambda cmd: cmd not in ("dig", "drill", "dnsmasq")
        env = harness.shield.check_environment()
        check_setup.assert_called_once_with()
        assert any(DnsTier.GETENT.hint in i for i in env.issues)
        assert env.dns_tier == DnsTier.GETENT.value

    def test_missing_configured_dnsmasq_reports_issue(
        self,
        check_setup: mock.Mock,
        make_shield: ShieldHarnessFactory,
        tmp_path: Path,
    ) -> None:
        """A configured dnsmasq path that is not executable is an issue, and the host's tiers still resolve."""
        missing = tmp_path / "dnsmasq-missing"
        harness = make_shield(ShieldConfig(state_dir=tmp_path, dnsmasq_path=missing))
        harness.runner.run.return_value = _podman_info_json("5.8.0")
        harness.runner.has.side_effect = lambda cmd: cmd == "dig"
        env = harness.shield.check_environment()
        check_setup.assert_called_once_with()
        assert any(str(missing) in i for i in env.issues)
        assert env.dns_tier == DnsTier.LOOKUP.value

    def test_apparmor_confined_dnsmasq_reports_issue(
        self,
        check_setup: mock.Mock,
        make_shield: ShieldHarnessFactory,
        tmp_path: Path,
    ) -> None:
        """dnsmasq present but AppArmor-confined from the state dir → dig + advisory."""
        harness = make_shield(ShieldConfig(state_dir=tmp_path))
        harness.runner.has.side_effect = lambda cmd: cmd in ("dnsmasq", "dig")

        def _run(cmd: list[str], **_kw: object) -> str:
            if cmd[0] == "podman":
                return _podman_info_json("5.8.0")
            if "--version" in cmd:
                return "Dnsmasq version 2.92\nCompile time options: nftset\n"
            if "--test" in cmd:
                raise ExecError(cmd, 3, "dnsmasq: cannot read config: Permission denied\n")
            return ""

        harness.runner.run.side_effect = _run
        env = harness.shield.check_environment()
        check_setup.assert_called_once_with()
        assert env.dns_tier == DnsTier.LOOKUP.value
        assert any("AppArmor" in i for i in env.issues)

    def test_no_global_hooks(
        self,
        check_setup: mock.Mock,
        make_shield: ShieldHarnessFactory,
    ) -> None:
        """No global hooks → setup-needed."""
        missing = SetupCheck("terok-shield", "hooks", SetupStatus.MISSING, "No global hooks")
        check_setup.return_value = (missing,)
        harness = make_shield()
        harness.runner.run.return_value = _podman_info_json("5.8.0")
        env = harness.shield.check_environment()
        check_setup.assert_called_once_with()
        assert not env.ok
        assert missing.diagnostic in env.issues
        assert env.health == "setup-needed"
        assert env.hooks == "not-installed"
        assert env.needs_setup
        assert env.setup_hint


from terok_shield.state import StateBundle


def test_reset_dispatches_and_logs(make_shield: ShieldHarnessFactory) -> None:
    """reset() delegates to the backend and writes a shield_reset audit event."""
    harness = make_shield()

    harness.shield.reset("test-ctr")

    harness.mode.shield_reset.assert_called_once_with("test-ctr")
    harness.audit.log_event.assert_called_once_with("test-ctr", "shield_reset")


@pytest.mark.parametrize(
    "status", [SetupStatus.READY, SetupStatus.STALE, SetupStatus.INVALID, SetupStatus.DOWNGRADE]
)
def test_environment_uses_owner_checks(status, make_shield: ShieldHarnessFactory) -> None:
    """Environment diagnostics use the owner's receipt API, not child file internals."""
    harness = make_shield()
    harness.runner.run.side_effect = _run_side_effect("5.8.0")
    with mock.patch(
        "terok_shield.hooks.install.HooksInstaller.check_setup",
        return_value=(SetupCheck("terok-shield", "hooks", status, "diagnostic"),),
    ):
        env = harness.shield.check_environment()
    assert env.needs_setup == (status != SetupStatus.READY)
    assert env.hooks == ("global" if status == SetupStatus.READY else "not-installed")
