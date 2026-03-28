# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Shield facade class (__init__.py)."""

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import pytest

from terok_shield import ExecError, Shield, ShieldConfig, ShieldState

from ..testfs import NFT_BINARY
from ..testnet import TEST_DOMAIN, TEST_IP1, TEST_IP2

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
    ) -> ShieldHarness:
        harness = ShieldHarness(
            shield=Shield.__new__(Shield),
            runner=mock.MagicMock(),
            audit=audit or mock.MagicMock(),
            dns=dns or mock.MagicMock(),
            profiles=profiles or mock.MagicMock(),
            ruleset=ruleset or mock.MagicMock(),
            mode=mode or mock.MagicMock(),
        )
        harness.shield.config = config or make_config()
        harness.shield.runner = harness.runner
        harness.shield.audit = harness.audit
        harness.shield.dns = harness.dns
        harness.shield.profiles = harness.profiles
        harness.shield.ruleset = harness.ruleset
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


def test_shield_uses_injected_collaborators(tmp_path: Path) -> None:
    """Shield keeps explicitly injected collaborators."""
    runner = mock.MagicMock()
    audit = mock.MagicMock()
    dns = mock.MagicMock()
    profiles = mock.MagicMock()
    ruleset = mock.MagicMock()

    shield = Shield(
        ShieldConfig(state_dir=tmp_path),
        runner=runner,
        audit=audit,
        dns=dns,
        profiles=profiles,
        ruleset=ruleset,
    )

    assert shield.runner is runner
    assert shield.audit is audit
    assert shield.dns is dns
    assert shield.profiles is profiles
    assert shield.ruleset is ruleset


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

    harness.mode.pre_start.assert_called_once_with("test-ctr", ["dev-standard"])
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
    harness.mode.pre_start.assert_called_once_with("test-ctr", ["base"])


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


def test_rules_delegates_to_mode(make_shield: ShieldHarnessFactory) -> None:
    """rules() returns the backend ruleset text."""
    harness = make_shield()
    harness.mode.list_rules.return_value = "table inet terok_shield {}"
    assert "terok_shield" in harness.shield.rules("test-ctr")
    harness.mode.list_rules.assert_called_once_with("test-ctr")


@pytest.mark.parametrize(
    ("allow_all", "expected_detail"),
    [
        pytest.param(False, None, id="default"),
        pytest.param(True, "allow_all=True", id="allow-all"),
    ],
)
def test_down_delegates_and_logs(
    make_shield: ShieldHarnessFactory,
    allow_all: bool,
    expected_detail: str | None,
) -> None:
    """down() delegates to the backend and records the right audit detail."""
    harness = make_shield()
    harness.shield.down("test-ctr", allow_all=allow_all)
    harness.mode.shield_down.assert_called_once_with("test-ctr", allow_all=allow_all)
    harness.audit.log_event.assert_called_once_with(
        "test-ctr", "shield_down", detail=expected_detail
    )


def test_up_delegates_and_logs(make_shield: ShieldHarnessFactory) -> None:
    """up() delegates to the backend and logs the transition."""
    harness = make_shield()
    harness.shield.up("test-ctr")
    harness.mode.shield_up.assert_called_once_with("test-ctr")
    harness.audit.log_event.assert_called_once_with("test-ctr", "shield_up")


def test_state_delegates_to_mode(make_shield: ShieldHarnessFactory) -> None:
    """state() returns the backend shield state."""
    harness = make_shield()
    harness.mode.shield_state.return_value = ShieldState.UP
    assert harness.shield.state("test-ctr") == ShieldState.UP


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        pytest.param({}, "table inet terok_shield { policy drop }", id="default"),
        pytest.param({"down": True, "allow_all": True}, "bypass", id="down-bypass"),
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
        down=kwargs.get("down", False), allow_all=kwargs.get("allow_all", False)
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
        if cmd[0] == "dnsmasq":
            return "Dnsmasq version 2.92\nCompile time options: nftset\n"
        return _podman_info_json(podman_version)

    return _effect


class TestCheckEnvironment:
    """Tests for Shield.check_environment()."""

    @mock.patch("terok_shield.find_hooks_dirs", return_value=[Path("/fake/hooks")])
    @mock.patch("terok_shield.has_global_hooks", return_value=True)
    @mock.patch("terok_shield.system_hooks_dir", return_value=Path("/fake/hooks"))
    def test_dig_missing_reports_issue(
        self,
        _sys_dir: mock.Mock,
        _has_hooks: mock.Mock,
        _find_dirs: mock.Mock,
        make_shield: ShieldHarnessFactory,
    ) -> None:
        """Missing dig (and dnsmasq) reports getent degradation in environment check."""
        harness = make_shield()
        harness.runner.run.return_value = _podman_info_json("5.8.0")
        harness.runner.has.side_effect = lambda cmd: cmd not in ("dig", "dnsmasq")
        env = harness.shield.check_environment()
        assert any("dig" in i for i in env.issues)
        assert env.dns_tier == "getent"

    @mock.patch("terok_shield.find_hooks_dirs", return_value=[])
    @mock.patch("terok_shield.has_global_hooks", return_value=False)
    def test_no_global_hooks(
        self,
        _has_hooks: mock.Mock,
        _find_dirs: mock.Mock,
        make_shield: ShieldHarnessFactory,
    ) -> None:
        """No global hooks → setup-needed."""
        harness = make_shield()
        harness.runner.run.return_value = _podman_info_json("5.8.0")
        env = harness.shield.check_environment()
        assert not env.ok
        assert env.health == "setup-needed"
        assert env.hooks == "not-installed"
        assert env.needs_setup
        assert env.setup_hint

    @mock.patch("terok_shield.find_hooks_dirs", return_value=[Path("/fake/hooks")])
    @mock.patch("terok_shield.has_global_hooks", return_value=True)
    @mock.patch("terok_shield.system_hooks_dir", return_value=Path("/fake/hooks"))
    def test_stale_hooks_on_persistent_podman(
        self,
        _sys_dir: mock.Mock,
        _has_hooks: mock.Mock,
        _find_dirs: mock.Mock,
        make_shield: ShieldHarnessFactory,
    ) -> None:
        """Podman with hooks_dir_persists + global hooks → stale-hooks."""
        harness = make_shield()
        # Use a version >= HOOKS_DIR_PERSIST_VERSION so hooks_dir_persists is True,
        # which triggers the stale-hooks detection path (global hooks installed but
        # per-container hooks-dir already persists natively).
        harness.runner.run.return_value = _podman_info_json("99.0.0")
        env = harness.shield.check_environment()
        assert not env.ok
        assert env.health == "stale-hooks"
        assert any("Stale" in i for i in env.issues)

    @mock.patch("terok_shield.find_hooks_dirs", return_value=[Path("/fake/hooks")])
    @mock.patch("terok_shield.has_global_hooks", return_value=True)
    @mock.patch("terok_shield.system_hooks_dir", return_value=Path("/fake/hooks"))
    def test_global_system_hooks(
        self,
        _sys_dir: mock.Mock,
        _has_hooks: mock.Mock,
        _find_dirs: mock.Mock,
        make_shield: ShieldHarnessFactory,
    ) -> None:
        """System global hooks → ok/global-system."""
        harness = make_shield()
        harness.runner.run.side_effect = _run_side_effect("5.8.0")
        env = harness.shield.check_environment()
        assert env.ok
        assert env.health == "ok"
        assert env.hooks == "global-system"

    @mock.patch("terok_shield.find_hooks_dirs", return_value=[Path("/user/hooks")])
    @mock.patch("terok_shield.system_hooks_dir", return_value=Path("/nonexistent"))
    def test_global_user_hooks(
        self,
        _sys_dir: mock.Mock,
        _find_dirs: mock.Mock,
        make_shield: ShieldHarnessFactory,
    ) -> None:
        """User global hooks (not system) → ok/global-user."""
        harness = make_shield()
        harness.runner.run.side_effect = _run_side_effect("5.8.0")

        # First call (hooks_dirs from find_hooks_dirs) -> True (hooks exist)
        # Second call ([sys_dir]) -> False (not in system dir)
        with mock.patch("terok_shield.has_global_hooks", side_effect=[True, False]):
            env = harness.shield.check_environment()
        assert env.ok
        assert env.health == "ok"
        assert env.hooks == "global-user"
