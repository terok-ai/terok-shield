# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Shield facade class (__init__.py)."""

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import pytest

from terok_shield import ExecError, Shield, ShieldConfig, ShieldState, state

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
    """down() delegates to the backend, logs, and pings the hub."""
    harness = make_shield()
    harness.shield.down("test-ctr", "ctr-uuid-1", allow_all=allow_all)
    harness.mode.shield_down.assert_called_once_with("test-ctr", allow_all=allow_all)
    harness.audit.log_event.assert_called_once_with(
        "test-ctr", "shield_down", detail=expected_detail
    )
    harness.hub_events.shield_down.assert_called_once_with(
        "test-ctr", "ctr-uuid-1", allow_all=allow_all, dossier={}
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
    harness.shield.down("test-ctr", "ctr-uuid-1", allow_all=True)
    harness.hub_events.shield_down.assert_called_once_with(
        "test-ctr",
        "ctr-uuid-1",
        allow_all=True,
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
        if Path(cmd[0]).name == "dnsmasq":
            return "Dnsmasq version 2.92\nCompile time options: nftset\n"
        return _podman_info_json(podman_version)

    return _effect


class TestCheckEnvironment:
    """Tests for Shield.check_environment()."""

    @staticmethod
    def _write_hook_layout(hooks_dir: Path, ballast_body: str) -> None:
        """Write a JSON descriptor + ballast in the layout the version probe expects.

        The probe follows the descriptor's ``hook.path`` to find the
        script, then reads ``_oci_state.py`` next to it.  Single-flavor
        installs put descriptors and scripts in the same dir, so the
        helper just lays both there.
        """
        import json

        from terok_shield.podman_info.hooks_dir import HOOK_JSON_FILENAME

        hooks_dir.mkdir(parents=True, exist_ok=True)
        script_path = hooks_dir / "terok-shield-hook"
        script_path.write_text("#!/usr/bin/env python3\n")
        (hooks_dir / "_oci_state.py").write_text(ballast_body)
        (hooks_dir / HOOK_JSON_FILENAME).write_text(
            json.dumps({"hook": {"path": str(script_path), "args": []}})
        )

    @mock.patch("terok_shield.find_hooks_dirs", return_value=[Path("/fake/hooks")])
    @mock.patch("terok_shield.has_global_hooks", return_value=True)
    def test_dig_missing_reports_issue(
        self,
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

    @mock.patch("terok_shield.find_hooks_dirs", return_value=[Path("/fake/hooks")])
    @mock.patch("terok_shield.has_global_hooks", return_value=True)
    def test_apparmor_confined_dnsmasq_reports_issue(
        self,
        _has_hooks: mock.Mock,
        _find_dirs: mock.Mock,
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
        assert env.dns_tier == "dig"
        assert any("AppArmor" in i for i in env.issues)

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
    def test_stale_hooks_on_persistent_podman(
        self,
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

    @mock.patch("terok_shield._read_installed_hook_version", return_value=state.BUNDLE_VERSION)
    @mock.patch("terok_shield.find_hooks_dirs", return_value=[Path("/fake/hooks")])
    @mock.patch("terok_shield.has_global_hooks", return_value=True)
    def test_global_hooks_installed(
        self,
        _has_hooks: mock.Mock,
        _find_dirs: mock.Mock,
        _hook_ver: mock.Mock,
        make_shield: ShieldHarnessFactory,
    ) -> None:
        """Global hooks present + version match → ok/global."""
        harness = make_shield()
        harness.runner.run.side_effect = _run_side_effect("5.8.0")
        env = harness.shield.check_environment()
        assert env.ok
        assert env.health == "ok"
        assert env.hooks == "global"

    @mock.patch("terok_shield.find_hooks_dirs")
    @mock.patch("terok_shield.has_global_hooks", return_value=True)
    def test_stale_hook_version_detected(
        self,
        _has_hooks: mock.Mock,
        _find_dirs: mock.Mock,
        make_shield: ShieldHarnessFactory,
        tmp_path: Path,
    ) -> None:
        """Mismatched ballast version → stale-hooks health status."""
        hooks_dir = tmp_path / "hooks.d"
        self._write_hook_layout(hooks_dir, "BUNDLE_VERSION = 1\n")
        _find_dirs.return_value = [hooks_dir]

        harness = make_shield()
        harness.runner.run.side_effect = _run_side_effect("5.8.0")
        env = harness.shield.check_environment()
        assert env.health == "stale-hooks"
        assert any("version" in i.lower() for i in env.issues)

    @mock.patch("terok_shield.find_hooks_dirs")
    @mock.patch("terok_shield.has_global_hooks", return_value=True)
    def test_unreadable_hook_version_treated_as_stale(
        self,
        _has_hooks: mock.Mock,
        _find_dirs: mock.Mock,
        make_shield: ShieldHarnessFactory,
        tmp_path: Path,
    ) -> None:
        """Ballast file without ``BUNDLE_VERSION`` line → stale-hooks (not silently ok)."""
        hooks_dir = tmp_path / "hooks.d"
        self._write_hook_layout(hooks_dir, "# no version here\n")
        _find_dirs.return_value = [hooks_dir]

        harness = make_shield()
        harness.runner.run.side_effect = _run_side_effect("5.8.0")
        env = harness.shield.check_environment()
        assert env.health == "stale-hooks"
        assert any("version" in i.lower() for i in env.issues)


# ── _read_installed_hook_version tests ────────────────────


class TestReadInstalledHookVersion:
    """Tests for the _read_installed_hook_version helper.

    User-scope installs split scripts from descriptors: the JSON
    descriptor in ``hooks_dir`` carries the absolute ``path`` of the
    role script, and the ballast lives next to that script.  The fixture
    helpers mirror that layout: ``_write_layout`` writes a descriptor in
    ``hooks_dir`` and a ballast in a sibling ``script_dir``.
    """

    @staticmethod
    def _write_layout(hooks_dir: Path, script_dir: Path, ballast_body: str) -> None:
        import json

        from terok_shield.podman_info.hooks_dir import HOOK_JSON_FILENAME

        hooks_dir.mkdir(parents=True, exist_ok=True)
        script_dir.mkdir(parents=True, exist_ok=True)
        script_path = script_dir / "terok-shield-hook"
        script_path.write_text("#!/usr/bin/env python3\n")
        (script_dir / "_oci_state.py").write_text(ballast_body)
        (hooks_dir / HOOK_JSON_FILENAME).write_text(
            json.dumps({"hook": {"path": str(script_path), "args": []}})
        )

    def test_reads_version_from_hook(self, tmp_path: Path) -> None:
        """Extracts ``BUNDLE_VERSION`` via the descriptor's script-path reference."""
        from terok_shield import _read_installed_hook_version

        self._write_layout(tmp_path / "hooks.d", tmp_path / "scripts", "BUNDLE_VERSION = 42\n")
        assert _read_installed_hook_version([tmp_path / "hooks.d"]) == 42

    def test_returns_none_when_no_descriptor(self, tmp_path: Path) -> None:
        """Returns None when no shield JSON descriptor is found."""
        from terok_shield import _read_installed_hook_version

        assert _read_installed_hook_version([tmp_path]) is None

    def test_returns_none_on_oserror(self, tmp_path: Path) -> None:
        """Returns None when the ballast file cannot be read."""
        from terok_shield import _read_installed_hook_version

        self._write_layout(tmp_path / "hooks.d", tmp_path / "scripts", "BUNDLE_VERSION = 5\n")
        with mock.patch.object(Path, "read_text", side_effect=OSError("boom")):
            assert _read_installed_hook_version([tmp_path / "hooks.d"]) is None

    def test_returns_none_on_no_match(self, tmp_path: Path) -> None:
        """Returns None when the ballast file has no ``BUNDLE_VERSION`` line."""
        from terok_shield import _read_installed_hook_version

        self._write_layout(tmp_path / "hooks.d", tmp_path / "scripts", "# no version here\n")
        assert _read_installed_hook_version([tmp_path / "hooks.d"]) is None

    def test_returns_none_on_non_dict_toplevel(self, tmp_path: Path) -> None:
        """A descriptor whose top-level JSON isn't an object reports ``None``.

        A malformed active descriptor (here a JSON array) must be
        tolerated — reported as unknown (``None``) rather than raising on
        the subsequent ``.get``.
        """
        import json

        from terok_shield import _read_installed_hook_version
        from terok_shield.podman_info.hooks_dir import HOOK_JSON_FILENAME

        hooks_dir = tmp_path / "hooks.d"
        hooks_dir.mkdir()
        (hooks_dir / HOOK_JSON_FILENAME).write_text(json.dumps(["not", "an", "object"]))
        assert _read_installed_hook_version([hooks_dir]) is None

    def test_returns_none_on_non_dict_hook(self, tmp_path: Path) -> None:
        """A descriptor whose ``hook`` value isn't an object reports ``None``.

        The top-level parses to an object but ``hook`` is a string; the
        probe must report ``None`` rather than raise on ``hook.get``.
        """
        import json

        from terok_shield import _read_installed_hook_version
        from terok_shield.podman_info.hooks_dir import HOOK_JSON_FILENAME

        hooks_dir = tmp_path / "hooks.d"
        hooks_dir.mkdir()
        (hooks_dir / HOOK_JSON_FILENAME).write_text(json.dumps({"hook": "not-an-object"}))
        assert _read_installed_hook_version([hooks_dir]) is None

    def test_returns_none_on_non_string_path(self, tmp_path: Path) -> None:
        """A descriptor whose ``hook.path`` isn't a string reports ``None``, not a crash.

        A malformed active descriptor must be tolerated — reported as
        unknown (``None``) rather than raising.
        """
        import json

        from terok_shield import _read_installed_hook_version
        from terok_shield.podman_info.hooks_dir import HOOK_JSON_FILENAME

        hooks_dir = tmp_path / "hooks.d"
        hooks_dir.mkdir()
        (hooks_dir / HOOK_JSON_FILENAME).write_text(
            json.dumps({"hook": {"path": 12345, "args": []}})
        )
        assert _read_installed_hook_version([hooks_dir]) is None

    def test_broken_active_descriptor_does_not_fall_through(self, tmp_path: Path) -> None:
        """A broken highest-precedence install reports ``None``, not a lower version.

        Podman's last-wins ``--hooks-dir`` rule means the highest-precedence
        descriptor is the *active* one.  If it is malformed, the probe must
        report ``None`` rather than fall back to a valid lower-precedence
        install whose (stale) version would mask the broken active one.
        """
        import json

        from terok_shield import _read_installed_hook_version
        from terok_shield.podman_info.hooks_dir import HOOK_JSON_FILENAME

        # Lower precedence (first in the list): a valid v7 install.
        low = tmp_path / "low"
        self._write_layout(low, tmp_path / "low-scripts", "BUNDLE_VERSION = 7\n")
        # Higher precedence (last in the list → reversed-walked first): broken.
        high = tmp_path / "high"
        high.mkdir()
        (high / HOOK_JSON_FILENAME).write_text(json.dumps(["not", "an", "object"]))

        assert _read_installed_hook_version([low, high]) is None


from terok_shield.state import StateBundle
