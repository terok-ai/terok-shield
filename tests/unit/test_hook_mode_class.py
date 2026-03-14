# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the HookMode class."""

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import pytest

from terok_shield import state
from terok_shield.config import (
    ANNOTATION_AUDIT_ENABLED_KEY,
    ANNOTATION_STATE_DIR_KEY,
    ShieldConfig,
    ShieldState,
)
from terok_shield.mode_hook import HookMode, install_hooks
from terok_shield.nft import bypass_ruleset, hook_ruleset
from terok_shield.run import ExecError

from ..testfs import BIN_DIR_NAME, HOOK_ENTRYPOINT_NAME, HOOKS_DIR_NAME
from ..testnet import IPV6_CLOUDFLARE, TEST_DOMAIN, TEST_IP1, TEST_IP2
from .helpers import write_lines

# Modern podman info JSON — hooks-dir persists (>= 5.6.0), pasta default
_MODERN_PODMAN_INFO = json.dumps(
    {"host": {"rootlessNetworkCmd": "pasta"}, "version": {"Version": "5.8.0"}}
)

ConfigFactory = Callable[..., ShieldConfig]


@dataclass
class HookModeHarness:
    """A ``HookMode`` instance plus its config and mock collaborators."""

    mode: HookMode
    config: ShieldConfig
    runner: mock.MagicMock
    audit: mock.MagicMock
    dns: mock.MagicMock
    profiles: mock.MagicMock
    ruleset: mock.MagicMock


HookModeHarnessFactory = Callable[..., HookModeHarness]


@pytest.fixture
def make_hook_mode(make_config: ConfigFactory) -> HookModeHarnessFactory:
    """Create a ``HookMode`` with mock collaborators."""

    def _make_hook_mode(
        config: ShieldConfig | None = None,
        *,
        runner: mock.MagicMock | None = None,
        audit: mock.MagicMock | None = None,
        dns: mock.MagicMock | None = None,
        profiles: mock.MagicMock | None = None,
        ruleset: mock.MagicMock | None = None,
    ) -> HookModeHarness:
        config = config or make_config()
        runner = runner or mock.MagicMock()
        audit = audit or mock.MagicMock()
        dns = dns or mock.MagicMock()
        profiles = profiles or mock.MagicMock()
        ruleset = ruleset or mock.MagicMock()
        return HookModeHarness(
            mode=HookMode(
                config=config,
                runner=runner,
                audit=audit,
                dns=dns,
                profiles=profiles,
                ruleset=ruleset,
            ),
            config=config,
            runner=runner,
            audit=audit,
            dns=dns,
            profiles=profiles,
            ruleset=ruleset,
        )

    return _make_hook_mode


def _annotation_value(args: list[str], key: str) -> str:
    """Extract an annotation value from the podman args returned by pre_start()."""
    prefix = f"{key}="
    for index, arg in enumerate(args[:-1]):
        if arg == "--annotation" and args[index + 1].startswith(prefix):
            return args[index + 1][len(prefix) :]
    raise AssertionError(f"annotation not found: {key}")


def _set_euid(monkeypatch: pytest.MonkeyPatch, value: int) -> None:
    """Patch ``os.geteuid()`` for rootless/rootful pre_start tests."""
    monkeypatch.setattr("os.geteuid", lambda: value)


def test_hook_mode_stores_collaborators(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """Construction keeps the injected collaborators and config."""
    config = make_config()
    runner = mock.MagicMock()
    audit = mock.MagicMock()
    dns = mock.MagicMock()
    profiles = mock.MagicMock()
    ruleset = mock.MagicMock()
    harness = make_hook_mode(
        config=config,
        runner=runner,
        audit=audit,
        dns=dns,
        profiles=profiles,
        ruleset=ruleset,
    )

    # HookMode intentionally has no public collaborator accessors; this
    # white-box test verifies constructor wiring directly.
    assert harness.mode._config is config
    assert harness.mode._runner is runner
    assert harness.mode._audit is audit
    assert harness.mode._dns is dns
    assert harness.mode._profiles is profiles
    assert harness.mode._ruleset is ruleset


def test_pre_start_uses_pasta_for_rootless_mode(
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start() uses pasta and loopback flags in rootless mode."""
    _set_euid(monkeypatch, 1000)
    harness = make_hook_mode(config=make_config(loopback_ports=(8080,)))
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = [TEST_DOMAIN]

    args = harness.mode.pre_start("test", ["dev-standard"])

    network_arg = args[args.index("--network") + 1]
    assert network_arg.startswith("pasta:")
    assert "-T,8080" in network_arg


def test_pre_start_installs_hooks_and_creates_state_dirs(
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start() installs OCI hook files and state directories."""
    _set_euid(monkeypatch, 0)
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []

    harness.mode.pre_start("test", ["dev-standard"])

    assert state.hooks_dir(config.state_dir).is_dir()
    assert state.hook_entrypoint(config.state_dir).is_file()


@pytest.mark.parametrize(
    ("config_kwargs", "annotation_key", "expected_value"),
    [
        pytest.param(
            {}, ANNOTATION_STATE_DIR_KEY, lambda cfg: str(cfg.state_dir.resolve()), id="state-dir"
        ),
        pytest.param(
            {"audit_enabled": False},
            ANNOTATION_AUDIT_ENABLED_KEY,
            lambda _cfg: "false",
            id="audit-enabled",
        ),
    ],
)
def test_pre_start_includes_expected_annotations(
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    config_kwargs: dict[str, object],
    annotation_key: str,
    expected_value: Callable[[ShieldConfig], str],
) -> None:
    """pre_start() includes the expected state and audit annotations."""
    _set_euid(monkeypatch, 0)
    harness = make_hook_mode(config=make_config(**config_kwargs))
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []

    args = harness.mode.pre_start("test", ["dev-standard"])
    assert _annotation_value(args, annotation_key) == expected_value(harness.config)


@pytest.mark.parametrize(
    ("method", "ip", "expected_action", "expected_set"),
    [
        pytest.param("allow_ip", TEST_IP1, "add", "allow_v4", id="allow-ipv4"),
        pytest.param("allow_ip", IPV6_CLOUDFLARE, "add", "allow_v6", id="allow-ipv6"),
        pytest.param("deny_ip", TEST_IP1, "delete", "allow_v4", id="deny-ipv4"),
    ],
)
def test_allow_and_deny_use_expected_nft_set(
    make_hook_mode: HookModeHarnessFactory,
    method: str,
    ip: str,
    expected_action: str,
    expected_set: str,
) -> None:
    """allow_ip()/deny_ip() target the correct nft set for each address family."""
    harness = make_hook_mode()
    harness.ruleset.safe_ip.return_value = ip

    getattr(harness.mode, method)("test-ctr", ip)

    nft_args = harness.runner.nft_via_nsenter.call_args.args
    assert expected_action in nft_args
    assert expected_set in nft_args


def test_allow_persists_and_deduplicates_live_allowed(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """allow_ip() persists to live.allowed without duplicate lines."""
    harness = make_hook_mode(config=make_config())
    harness.ruleset.safe_ip.return_value = TEST_IP1

    harness.mode.allow_ip("test-ctr", TEST_IP1)
    harness.mode.allow_ip("test-ctr", TEST_IP1)

    lines = state.live_allowed_path(harness.config.state_dir).read_text().splitlines()
    assert lines.count(TEST_IP1) == 1


@pytest.mark.parametrize(
    ("profile_lines", "live_lines", "expect_deny_file", "nft_side_effect"),
    [
        pytest.param([TEST_IP1], [], True, None, id="profile-ip-persists-to-deny-list"),
        pytest.param([], [TEST_IP1], False, None, id="live-only-no-deny-list"),
        pytest.param(
            [TEST_IP1],
            [TEST_IP1],
            True,
            ExecError(["nft"], 1, "not in set"),
            id="nft-error-still-persists",
        ),
    ],
)
def test_deny_updates_state_files(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    profile_lines: list[str],
    live_lines: list[str],
    expect_deny_file: bool,
    nft_side_effect: ExecError | None,
) -> None:
    """deny_ip() removes live entries and optionally persists a deny.list record."""
    harness = make_hook_mode(config=make_config())
    if profile_lines:
        write_lines(state.profile_allowed_path(harness.config.state_dir), profile_lines)
    if live_lines:
        write_lines(state.live_allowed_path(harness.config.state_dir), live_lines)
    harness.runner.nft_via_nsenter.side_effect = nft_side_effect
    harness.ruleset.safe_ip.return_value = TEST_IP1

    harness.mode.deny_ip("test-ctr", TEST_IP1)

    live_path = state.live_allowed_path(harness.config.state_dir)
    live_content = live_path.read_text().splitlines() if live_path.exists() else []
    assert TEST_IP1 not in live_content

    deny_file = state.deny_path(harness.config.state_dir)
    assert deny_file.is_file() is expect_deny_file
    if expect_deny_file:
        assert TEST_IP1 in deny_file.read_text()


def test_allow_after_deny_clears_deny_list(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """allow_ip() removes the IP from deny.list when re-allowing it."""
    harness = make_hook_mode(config=make_config())
    write_lines(state.deny_path(harness.config.state_dir), [TEST_IP1, TEST_IP2])
    harness.ruleset.safe_ip.return_value = TEST_IP1

    harness.mode.allow_ip("test-ctr", TEST_IP1)
    denied = state.read_denied_ips(harness.config.state_dir)
    assert TEST_IP1 not in denied
    assert TEST_IP2 in denied


def test_list_rules_returns_runner_output(make_hook_mode: HookModeHarnessFactory) -> None:
    """list_rules() returns the nft ruleset text on success."""
    harness = make_hook_mode()
    harness.runner.nft_via_nsenter.return_value = "table inet terok_shield {}"
    assert "terok_shield" in harness.mode.list_rules("test-ctr")


def test_list_rules_returns_empty_on_exec_error(make_hook_mode: HookModeHarnessFactory) -> None:
    """list_rules() tolerates ExecError and returns an empty string."""
    harness = make_hook_mode()
    harness.runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "error")
    assert harness.mode.list_rules("test-ctr") == ""


@pytest.mark.parametrize(
    ("allow_all", "verify_errors", "expected_message"),
    [
        pytest.param(False, [], None, id="success"),
        pytest.param(
            False, ["error: missing policy"], "verification failed", id="verification-failure"
        ),
    ],
)
def test_shield_down_builds_bypass_ruleset(
    make_hook_mode: HookModeHarnessFactory,
    allow_all: bool,
    verify_errors: list[str],
    expected_message: str | None,
) -> None:
    """shield_down() applies bypass mode and verifies the resulting ruleset."""
    harness = make_hook_mode()
    # Mock DNS reading so _container_ruleset returns the mock ruleset
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.runner.nft_via_nsenter.side_effect = [
        "",
        "bad output" if verify_errors else "valid output",
    ]
    harness.ruleset.build_bypass.return_value = "bypass ruleset"
    harness.ruleset.verify_bypass.return_value = verify_errors

    if expected_message is None:
        harness.mode.shield_down("test-ctr", allow_all=allow_all)
        assert harness.runner.nft_via_nsenter.call_count == 2
    else:
        with pytest.raises(RuntimeError, match=expected_message):
            harness.mode.shield_down("test-ctr", allow_all=allow_all)


@pytest.mark.parametrize(
    ("allowed_ips", "verify_errors", "expected_calls"),
    [
        pytest.param([], [], 2, id="no-cached-ips"),
        pytest.param([TEST_IP1], [], 3, id="readds-cached-ips"),
        pytest.param([], ["error"], 2, id="verification-failure"),
    ],
)
def test_shield_up_reapplies_hook_ruleset(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    allowed_ips: list[str],
    verify_errors: list[str],
    expected_calls: int,
) -> None:
    """shield_up() restores hook mode, optionally re-adding effective IPs."""
    harness = make_hook_mode(config=make_config())
    if allowed_ips:
        write_lines(state.profile_allowed_path(harness.config.state_dir), allowed_ips)
    # Mock DNS reading so _container_ruleset returns the mock ruleset
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.runner.nft_via_nsenter.side_effect = [""] * (expected_calls - 1) + [
        "valid output" if not verify_errors else "bad output"
    ]
    harness.ruleset.build_hook.return_value = "hook ruleset"
    harness.ruleset.verify_hook.return_value = verify_errors
    harness.ruleset.add_elements_dual.return_value = (
        f"add element {TEST_IP1}" if allowed_ips else ""
    )

    if verify_errors:
        with pytest.raises(RuntimeError):
            harness.mode.shield_up("test-ctr")
    else:
        harness.mode.shield_up("test-ctr")
    assert harness.runner.nft_via_nsenter.call_count == expected_calls


@pytest.mark.parametrize(
    ("nft_output", "verify_bypass", "verify_hook", "expected"),
    [
        pytest.param("", None, None, ShieldState.INACTIVE, id="inactive"),
        pytest.param(hook_ruleset(), ["not bypass"], [], ShieldState.UP, id="up"),
        pytest.param(bypass_ruleset(), [], None, ShieldState.DOWN, id="down"),
        pytest.param(
            "random nft stuff", ["not bypass"], ["not hook"], ShieldState.ERROR, id="error"
        ),
    ],
)
def test_shield_state_classifies_rulesets(
    make_hook_mode: HookModeHarnessFactory,
    nft_output: str,
    verify_bypass: list[str] | None,
    verify_hook: list[str] | None,
    expected: ShieldState,
) -> None:
    """shield_state() distinguishes inactive, hook, bypass, and invalid rulesets."""
    harness = make_hook_mode()
    harness.runner.nft_via_nsenter.return_value = nft_output
    if verify_bypass is not None:
        harness.ruleset.verify_bypass.return_value = verify_bypass
    if verify_hook is not None:
        harness.ruleset.verify_hook.return_value = verify_hook
    assert harness.mode.shield_state("test") == expected


@pytest.mark.parametrize(
    ("kwargs", "expected", "method_name"),
    [
        pytest.param({}, "hook ruleset", "build_hook", id="default-hook-preview"),
        pytest.param(
            {"down": True, "allow_all": True}, "bypass ruleset", "build_bypass", id="bypass-preview"
        ),
    ],
)
def test_preview_delegates_to_ruleset_builder(
    make_hook_mode: HookModeHarnessFactory,
    kwargs: dict[str, bool],
    expected: str,
    method_name: str,
) -> None:
    """preview() delegates to the right ruleset builder entry point."""
    harness = make_hook_mode()
    getattr(harness.ruleset, method_name).return_value = expected
    assert harness.mode.preview(**kwargs) == expected


@pytest.mark.parametrize(
    ("runner_output", "expected"),
    [
        pytest.param(
            json.dumps({"host": {"rootlessNetworkCmd": "pasta"}, "version": {"Version": "5.8.0"}}),
            "pasta",
            id="pasta",
        ),
        pytest.param(
            json.dumps(
                {"host": {"rootlessNetworkCmd": "slirp4netns"}, "version": {"Version": "5.8.0"}}
            ),
            "slirp4netns",
            id="slirp4netns",
        ),
        pytest.param(
            json.dumps(
                {
                    "host": {
                        "slirp4netns": {"executable": "/usr/bin/slirp4netns"},
                        "pasta": {"executable": "/usr/bin/pasta"},
                    },
                    "version": {"Version": "4.9.3"},
                }
            ),
            "slirp4netns",
            id="podman4-fallback-to-slirp",
        ),
        pytest.param("", "pasta", id="empty-output-fallback"),
        pytest.param("not json", "pasta", id="invalid-json-fallback"),
    ],
)
def test_detect_rootless_network_mode(
    make_hook_mode: HookModeHarnessFactory,
    runner_output: str,
    expected: str,
) -> None:
    """Network mode detection via PodmanInfo.network_mode."""
    harness = make_hook_mode()
    harness.runner.run.return_value = runner_output
    info = harness.mode._get_podman_info()
    assert info.network_mode == expected


def test_install_hooks_creates_entrypoint_and_hook_jsons(tmp_path: Path) -> None:
    """install_hooks() writes the executable entrypoint plus both hook descriptors."""
    hook_entrypoint = tmp_path / BIN_DIR_NAME / HOOK_ENTRYPOINT_NAME
    hooks_dir = tmp_path / HOOKS_DIR_NAME

    install_hooks(hook_entrypoint=hook_entrypoint, hooks_dir=hooks_dir)

    assert hook_entrypoint.exists()
    assert hook_entrypoint.stat().st_mode & 0o100
    assert hook_entrypoint.read_text().startswith("#!/bin/sh\n")
    assert "terok_shield.oci_hook" in hook_entrypoint.read_text()

    for stage_name in ("createRuntime", "poststop"):
        hook_file = hooks_dir / f"terok-shield-{stage_name}.json"
        assert hook_file.exists()
        data = json.loads(hook_file.read_text())
        assert data["version"] == "1.0.0"
        assert data["hook"]["path"] == str(hook_entrypoint)
        assert stage_name in data["stages"]


def test_setup_global_hooks_non_sudo(tmp_path: Path) -> None:
    """setup_global_hooks() installs hooks without sudo."""
    from terok_shield.mode_hook import setup_global_hooks

    target = tmp_path / "hooks.d"
    setup_global_hooks(target)
    assert (target / "terok-shield-hook").is_file()
    assert (target / "terok-shield-hook").stat().st_mode & 0o100
    assert (target / "terok-shield-createRuntime.json").is_file()
    assert (target / "terok-shield-poststop.json").is_file()
    # Hook JSONs reference entrypoint in the target dir
    data = json.loads((target / "terok-shield-createRuntime.json").read_text())
    assert data["hook"]["path"] == str(target / "terok-shield-hook")


def test_setup_global_hooks_sudo_uses_subprocess(tmp_path: Path) -> None:
    """setup_global_hooks(use_sudo=True) calls sudo subprocess."""
    from unittest import mock

    from terok_shield.mode_hook import setup_global_hooks

    target = tmp_path / "system-hooks"
    with mock.patch("subprocess.run") as mock_run:
        setup_global_hooks(target, use_sudo=True)
        # Should call sudo mkdir, sudo cp, sudo chmod
        assert mock_run.call_count == 3
        cmds = [call.args[0] for call in mock_run.call_args_list]
        assert all(cmd[0] == "sudo" for cmd in cmds)


def test_pre_start_slirp4netns_network_args(
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start() generates correct slirp4netns network args."""
    _set_euid(monkeypatch, 1000)
    harness = make_hook_mode(config=make_config(loopback_ports=(9418,)))
    # Podman 4.x with slirp4netns
    harness.runner.run.return_value = json.dumps(
        {
            "host": {
                "slirp4netns": {"executable": "/usr/bin/slirp4netns"},
            },
            "version": {"Version": "5.8.0"},
        }
    )
    harness.profiles.compose_profiles.return_value = []

    args = harness.mode.pre_start("test", ["dev-standard"])

    assert "--network" in args
    net_arg = args[args.index("--network") + 1]
    assert net_arg == "slirp4netns:allow_host_loopback=true"
    assert "host.containers.internal:10.0.2.2" in args


def test_pre_start_old_podman_with_global_hooks(
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start() on old podman with global hooks skips --hooks-dir."""
    from unittest import mock

    _set_euid(monkeypatch, 0)
    harness = make_hook_mode(config=make_config())
    harness.runner.run.return_value = json.dumps(
        {
            "host": {},
            "version": {"Version": "5.4.2"},
        }
    )
    harness.profiles.compose_profiles.return_value = []

    with mock.patch("terok_shield.mode_hook.has_global_hooks", return_value=True):
        args = harness.mode.pre_start("test", ["dev-standard"])

    assert "--hooks-dir" not in args
    harness.audit.log_event.assert_any_call(
        "test",
        "setup",
        detail=mock.ANY,
    )


def test_pre_start_old_podman_no_global_hooks_raises(
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start() on old podman without global hooks raises ShieldNeedsSetup."""
    from terok_shield.run import ShieldNeedsSetup

    _set_euid(monkeypatch, 0)
    harness = make_hook_mode(config=make_config())
    harness.runner.run.return_value = json.dumps(
        {
            "host": {},
            "version": {"Version": "5.4.2"},
        }
    )
    harness.profiles.compose_profiles.return_value = []

    with pytest.raises(ShieldNeedsSetup, match="terok-shield setup"):
        harness.mode.pre_start("test", ["dev-standard"])


def test_get_podman_info_caches_result(make_hook_mode: HookModeHarnessFactory) -> None:
    """_get_podman_info() caches the result across calls."""
    harness = make_hook_mode()
    harness.runner.run.return_value = _MODERN_PODMAN_INFO

    info1 = harness.mode._get_podman_info()
    info2 = harness.mode._get_podman_info()
    assert info1 is info2
    # run() called only once
    harness.runner.run.assert_called_once()


def test_read_container_dns(make_hook_mode: HookModeHarnessFactory) -> None:
    """_read_container_dns() reads nameserver from container resolv.conf."""
    harness = make_hook_mode()
    harness.runner.podman_inspect.return_value = "12345"
    harness.runner.run.return_value = "nameserver 10.0.2.3\n"

    dns = harness.mode._read_container_dns("test-ctr")
    assert dns == "10.0.2.3"


def test_read_container_dns_raises_on_no_nameserver(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """_read_container_dns() raises when resolv.conf has no nameserver."""
    harness = make_hook_mode()
    harness.runner.podman_inspect.return_value = "12345"
    harness.runner.run.return_value = "# empty resolv.conf\n"

    with pytest.raises(RuntimeError, match="no nameserver"):
        harness.mode._read_container_dns("test-ctr")


def test_container_ruleset_returns_builder_with_dns(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """_container_ruleset() creates RulesetBuilder with resolved DNS."""
    from terok_shield.nft import RulesetBuilder

    harness = make_hook_mode()
    harness.runner.podman_inspect.return_value = "12345"
    harness.runner.run.return_value = "nameserver 10.0.2.3\n"

    ruleset = harness.mode._container_ruleset("test-ctr")
    assert isinstance(ruleset, RulesetBuilder)
