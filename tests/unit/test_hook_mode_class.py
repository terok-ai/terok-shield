# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the HookMode class."""

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import pytest

from terok_shield.common.config import (
    ANNOTATION_AUDIT_ENABLED_KEY,
    ANNOTATION_STATE_DIR_KEY,
    ShieldConfig,
    ShieldState,
)
from terok_shield.core import state
from terok_shield.core.hook_install import install_hooks
from terok_shield.core.mode_hook import HookMode
from terok_shield.core.nft import bypass_ruleset, hook_ruleset
from terok_shield.core.nft_constants import PASTA_HOST_LOOPBACK_MAP
from terok_shield.core.run import ExecError

from ..testfs import BIN_DIR_NAME, HOOK_ENTRYPOINT_NAME, HOOKS_DIR_NAME
from ..testnet import (
    CONTAINER_HOSTNAME,
    IPV6_CLOUDFLARE,
    SLIRP4NETNS_GATEWAY,
    TEST_DOMAIN,
    TEST_IP1,
    TEST_IP2,
)
from .helpers import write_lines

# Modern podman info JSON — hooks-dir persists (>= 5.6.0), pasta default
_MODERN_PODMAN_INFO = json.dumps(
    {"host": {"rootlessNetworkCmd": "pasta"}, "version": {"Version": "5.8.0"}}
)
# dnsmasq --version output with nftset support compiled in
_DNSMASQ_VERSION_NFTSET = (
    "Dnsmasq version 2.92  Copyright (c) 2000-2025 Simon Kelley\n"
    "Compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 "
    "no-Lua TFTP conntrack ipset nftset auth DNSSEC loop-detect inotify dumpfile\n"
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
        if runner is None:
            runner = mock.MagicMock()
            runner.podman_inspect.return_value = "aabbccddee11223344556677"
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


@mock.patch("terok_shield.core.mode_hook.has_global_hooks", return_value=True)
def test_pre_start_uses_pasta_for_rootless_mode(
    _has_hooks: mock.Mock,
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
    assert "--map-host-loopback" in network_arg
    assert PASTA_HOST_LOOPBACK_MAP in network_arg
    assert "-T," not in network_arg

    add_host_arg = args[args.index("--add-host") + 1]
    assert add_host_arg == f"{CONTAINER_HOSTNAME}:{PASTA_HOST_LOOPBACK_MAP}"


@mock.patch("terok_shield.core.mode_hook.has_global_hooks", return_value=True)
def test_pre_start_installs_hooks_and_creates_state_dirs(
    _has_hooks: mock.Mock,
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
@mock.patch("terok_shield.core.mode_hook.has_global_hooks", return_value=True)
def test_pre_start_includes_expected_annotations(
    _has_hooks: mock.Mock,
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

    getattr(harness.mode, method)("test-ctr", ip)

    all_calls = harness.runner.nft_via_nsenter.call_args_list
    assert any(expected_action in c.args and expected_set in c.args for c in all_calls), (
        f"No single call contained both {expected_action!r} and {expected_set!r}: {all_calls}"
    )


def test_allow_persists_and_deduplicates_live_allowed(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """allow_ip() persists to live.allowed without duplicate lines."""
    harness = make_hook_mode(config=make_config())

    harness.mode.allow_ip("test-ctr", TEST_IP1)
    harness.mode.allow_ip("test-ctr", TEST_IP1)

    lines = state.live_allowed_path(harness.config.state_dir).read_text().splitlines()
    assert lines.count(TEST_IP1) == 1


def test_allow_ip_uses_timeout_zero_in_dnsmasq_tier(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """allow_ip() adds 'timeout 0s' when dnsmasq tier is active so the element never expires."""
    harness = make_hook_mode(config=make_config())
    sd = harness.config.state_dir.resolve()
    state.dns_tier_path(sd).write_text("dnsmasq\n")

    harness.mode.allow_ip("test-ctr", TEST_IP1)

    element_arg = harness.runner.nft_via_nsenter.call_args.args[-1]
    assert "timeout 0s" in element_arg


def test_allow_ip_no_timeout_zero_without_dnsmasq_tier(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """allow_ip() omits 'timeout 0s' when dnsmasq tier is not active."""
    harness = make_hook_mode(config=make_config())
    sd = harness.config.state_dir.resolve()
    state.dns_tier_path(sd).write_text("dig\n")

    harness.mode.allow_ip("test-ctr", TEST_IP1)

    element_arg = harness.runner.nft_via_nsenter.call_args.args[-1]
    assert "timeout 0s" not in element_arg


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
    # shield_state() call (list_rules) + apply + verify
    harness.runner.nft_via_nsenter.side_effect = [
        "table inet terok_shield {}",  # shield_state() → list_rules
        "",  # apply bypass ruleset
        "bad output" if verify_errors else "valid output",  # verify
    ]
    harness.ruleset.build_bypass.return_value = "bypass ruleset"
    harness.ruleset.verify_bypass.return_value = verify_errors
    # shield_state() uses verify_bypass/verify_hook to classify
    harness.ruleset.verify_hook.return_value = []

    if expected_message is None:
        harness.mode.shield_down("test-ctr", allow_all=allow_all)
        assert harness.runner.nft_via_nsenter.call_count == 3
    else:
        with pytest.raises(RuntimeError, match=expected_message):
            harness.mode.shield_down("test-ctr", allow_all=allow_all)


@pytest.mark.parametrize(
    ("allowed_ips", "verify_errors", "expected_calls"),
    [
        pytest.param([], [], 3, id="no-cached-ips"),
        pytest.param([TEST_IP1], [], 4, id="readds-cached-ips"),
        pytest.param([], ["error"], 3, id="verification-failure"),
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
    # shield_state() call (list_rules) returns existing table (UP state)
    harness.runner.nft_via_nsenter.side_effect = [
        "table inet terok_shield {}",  # shield_state() → list_rules
        *[""] * (expected_calls - 2),  # apply + optional elements
        "valid output" if not verify_errors else "bad output",  # verify
    ]
    harness.ruleset.build_hook.return_value = "hook ruleset"
    harness.ruleset.verify_hook.return_value = verify_errors
    harness.ruleset.add_elements_dual.return_value = (
        f"add element {TEST_IP1}" if allowed_ips else ""
    )
    # For shield_state() classification — report UP so delete table is prepended
    harness.ruleset.verify_bypass.return_value = ["not bypass"]

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
    content = hook_entrypoint.read_text()
    assert content.splitlines()[0] == "#!/usr/bin/env python3"
    assert "import terok_shield" not in content

    for stage_name in ("createRuntime", "poststop"):
        hook_file = hooks_dir / f"terok-shield-{stage_name}.json"
        assert hook_file.exists()
        data = json.loads(hook_file.read_text())
        assert data["version"] == "1.0.0"
        assert data["hook"]["path"] == str(hook_entrypoint)
        assert stage_name in data["stages"]


def test_generate_entrypoint_is_stdlib_only(tmp_path: Path) -> None:
    """The entrypoint script uses /usr/bin/env python3 and has no terok_shield imports."""
    from terok_shield.core.hook_install import _generate_entrypoint

    content = _generate_entrypoint()
    assert content.splitlines()[0] == "#!/usr/bin/env python3"
    assert "import terok_shield" not in content
    assert "ruleset.nft" in content


@mock.patch("terok_shield.core.mode_hook.has_global_hooks", return_value=True)
def test_pre_start_writes_ruleset_nft(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start() writes ruleset.nft to the state directory before container start."""
    _set_euid(monkeypatch, 0)
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []

    harness.mode.pre_start("test", ["dev-standard"])

    ruleset_file = state.ruleset_path(config.state_dir)
    assert ruleset_file.is_file(), "pre_start() must write ruleset.nft"
    content = ruleset_file.read_text()
    assert "terok_shield" in content
    assert "gateway_v4" in content
    assert "gateway_v6" in content


def test_setup_global_hooks_non_sudo(tmp_path: Path) -> None:
    """setup_global_hooks() installs hooks without sudo."""
    from terok_shield.core.hook_install import setup_global_hooks

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

    from terok_shield.core.hook_install import setup_global_hooks

    target = tmp_path / "system-hooks"
    with mock.patch("subprocess.run") as mock_run:
        setup_global_hooks(target, use_sudo=True)
        # Should call sudo mkdir, sudo cp, sudo chmod
        assert mock_run.call_count == 3
        cmds = [call.args[0] for call in mock_run.call_args_list]
        assert all(cmd[0] == "sudo" for cmd in cmds)


@mock.patch("terok_shield.core.mode_hook.has_global_hooks", return_value=True)
def test_pre_start_slirp4netns_network_args(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start() generates correct slirp4netns network args."""
    _set_euid(monkeypatch, 1000)
    harness = make_hook_mode(config=make_config(loopback_ports=(9418,)))
    # Podman with slirp4netns
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
    assert f"{CONTAINER_HOSTNAME}:{SLIRP4NETNS_GATEWAY}" in args


def test_pre_start_with_global_hooks_skips_hooks_dir(
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start() with global hooks skips --hooks-dir."""
    _set_euid(monkeypatch, 0)
    harness = make_hook_mode(config=make_config())
    harness.runner.run.return_value = json.dumps(
        {
            "host": {},
            "version": {"Version": "5.8.0"},
        }
    )
    harness.profiles.compose_profiles.return_value = []

    with mock.patch("terok_shield.core.mode_hook.has_global_hooks", return_value=True):
        args = harness.mode.pre_start("test", ["dev-standard"])

    assert "--hooks-dir" not in args
    harness.audit.log_event.assert_any_call(
        "test",
        "setup",
        detail=mock.ANY,
    )


def test_pre_start_no_global_hooks_raises(
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start() without global hooks raises ShieldNeedsSetup."""
    from terok_shield.core.run import ShieldNeedsSetup

    _set_euid(monkeypatch, 0)
    harness = make_hook_mode(config=make_config())
    harness.runner.run.return_value = json.dumps(
        {
            "host": {},
            "version": {"Version": "5.8.0"},
        }
    )
    harness.profiles.compose_profiles.return_value = []

    with mock.patch("terok_shield.core.mode_hook.has_global_hooks", return_value=False):
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
    from terok_shield.core.nft import RulesetBuilder

    harness = make_hook_mode()
    harness.runner.podman_inspect.return_value = "12345"
    harness.runner.run.return_value = "nameserver 10.0.2.3\n"

    ruleset = harness.mode._container_ruleset("test-ctr")
    assert isinstance(ruleset, RulesetBuilder)


def test_shield_up_on_inactive_applies_without_delete(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """shield_up() on INACTIVE netns applies ruleset without delete table prefix."""
    harness = make_hook_mode(config=make_config())
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    # shield_state() → list_rules returns empty (INACTIVE)
    harness.runner.nft_via_nsenter.side_effect = [
        "",  # shield_state() → INACTIVE
        "",  # apply ruleset (no delete prefix)
        "valid output",  # verify
    ]
    harness.ruleset.build_hook.return_value = "hook ruleset"
    harness.ruleset.verify_hook.return_value = []
    harness.ruleset.add_elements_dual.return_value = ""

    harness.mode.shield_up("test-ctr")

    # On an empty netns there is nothing to delete — no call should contain "delete table"
    for call in harness.runner.nft_via_nsenter.call_args_list:
        assert "delete" not in call.kwargs.get("stdin", "")


def test_shield_down_on_inactive_applies_without_delete(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """shield_down() on INACTIVE netns applies bypass ruleset without delete table prefix."""
    harness = make_hook_mode()
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    # shield_state() → list_rules returns empty (INACTIVE)
    harness.runner.nft_via_nsenter.side_effect = [
        "",  # shield_state() → INACTIVE
        "",  # apply bypass ruleset (no delete prefix)
        "valid output",  # verify
    ]
    harness.ruleset.build_bypass.return_value = "bypass ruleset"
    harness.ruleset.verify_bypass.return_value = []

    harness.mode.shield_down("test-ctr", allow_all=False)

    # On an empty netns there is nothing to delete — no call should contain "delete table"
    for call in harness.runner.nft_via_nsenter.call_args_list:
        assert "delete" not in call.kwargs.get("stdin", "")


# ── allow_domain / deny_domain ────────────────────────────


class TestDomainOperations:
    """Tests for allow_domain, deny_domain, and dnsmasq reload."""

    def test_allow_domain_persists_and_reloads(
        self, make_hook_mode: HookModeHarnessFactory
    ) -> None:
        """allow_domain() writes domain to live.domains and sends SIGHUP."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        state.ensure_state_dirs(sd)
        # Write upstream.dns so reload works
        state.upstream_dns_path(sd).write_text("169.254.1.1\n")
        # Write a dnsmasq PID file so reload triggers
        state.dnsmasq_pid_path(sd).write_text("12345\n")

        with (
            mock.patch("terok_shield.core.dnsmasq._is_our_dnsmasq", return_value=True),
            mock.patch("terok_shield.core.dnsmasq.os.kill"),
        ):
            harness.mode.allow_domain(TEST_DOMAIN)

        domains = state.live_domains_path(sd).read_text()
        assert TEST_DOMAIN in domains

    def test_allow_domain_skips_duplicate(self, make_hook_mode: HookModeHarnessFactory) -> None:
        """allow_domain() is a no-op for already-present domains."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        state.ensure_state_dirs(sd)
        state.profile_domains_path(sd).write_text(f"{TEST_DOMAIN}\n")

        with mock.patch("terok_shield.core.dnsmasq.reload") as mock_reload:
            harness.mode.allow_domain(TEST_DOMAIN)
        mock_reload.assert_not_called()

    def test_deny_domain_removes_and_reloads(self, make_hook_mode: HookModeHarnessFactory) -> None:
        """deny_domain() adds domain to denied.domains and reloads."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        state.ensure_state_dirs(sd)
        state.profile_domains_path(sd).write_text(f"{TEST_DOMAIN}\n")
        state.upstream_dns_path(sd).write_text("169.254.1.1\n")
        state.dnsmasq_pid_path(sd).write_text("12345\n")

        with (
            mock.patch("terok_shield.core.dnsmasq._is_our_dnsmasq", return_value=True),
            mock.patch("terok_shield.core.dnsmasq.os.kill"),
        ):
            harness.mode.deny_domain(TEST_DOMAIN)

        # Domain is in denied.domains, excluded from merged set
        from terok_shield.core.dnsmasq import read_merged_domains

        denied = state.denied_domains_path(sd).read_text()
        assert TEST_DOMAIN in denied
        assert TEST_DOMAIN not in read_merged_domains(sd)

    def test_reload_raises_without_upstream_dns(
        self, make_hook_mode: HookModeHarnessFactory
    ) -> None:
        """_reload_dnsmasq() raises when upstream DNS is not persisted."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        state.ensure_state_dirs(sd)

        with pytest.raises(RuntimeError, match="upstream DNS not persisted"):
            harness.mode._reload_dnsmasq(sd)

    @pytest.mark.parametrize(
        ("method_name", "tier"),
        [
            pytest.param("allow_domain", "dig", id="allow-dig"),
            pytest.param("allow_domain", "getent", id="allow-getent"),
            pytest.param("deny_domain", "dig", id="deny-dig"),
            pytest.param("deny_domain", "getent", id="deny-getent"),
        ],
    )
    def test_domain_method_is_noop_for_non_dnsmasq_tier(
        self, method_name: str, tier: str, make_hook_mode: HookModeHarnessFactory
    ) -> None:
        """allow_domain() and deny_domain() are silent no-ops when the active tier is not dnsmasq.

        The static IP-level allow/deny already ran via allow_ip()/deny_ip(); the
        domain-tracking step is dnsmasq-specific and simply skipped on dig/getent tiers.
        """
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        state.ensure_state_dirs(sd)
        state.dns_tier_path(sd).write_text(f"{tier}\n")

        # Must not raise
        getattr(harness.mode, method_name)(TEST_DOMAIN)
        # And must not have written any domain state files
        assert not state.live_domains_path(sd).exists()

    def test_allow_domain_passes_when_tier_absent(
        self, make_hook_mode: HookModeHarnessFactory
    ) -> None:
        """allow_domain() proceeds normally when dns_tier file does not exist (pre_start not run)."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        state.ensure_state_dirs(sd)
        state.upstream_dns_path(sd).write_text("169.254.1.1\n")
        state.dnsmasq_pid_path(sd).write_text("12345\n")
        # dns_tier_path NOT written — pre_start has not run

        with (
            mock.patch("terok_shield.core.dnsmasq._is_our_dnsmasq", return_value=True),
            mock.patch("terok_shield.core.dnsmasq.os.kill"),
        ):
            harness.mode.allow_domain(TEST_DOMAIN)

        domains = state.live_domains_path(sd).read_text()
        assert TEST_DOMAIN in domains


class TestPreStartDnsTierBranches:
    """pre_start() DNS tier branching — dnsmasq vs dig/getent code paths."""

    @mock.patch("terok_shield.core.mode_hook.has_global_hooks", return_value=True)
    def test_pre_start_dig_tier_resolves_all_entries(
        self,
        _has_hooks: mock.Mock,
        monkeypatch: pytest.MonkeyPatch,
        make_hook_mode: HookModeHarnessFactory,
    ) -> None:
        """When tier is DIG, pre_start resolves all entries (domains + IPs) to cache."""
        _set_euid(monkeypatch, 0)
        harness = make_hook_mode()
        harness.runner.run.return_value = _MODERN_PODMAN_INFO
        # Mock has() to return False for dnsmasq, True for dig
        harness.runner.has.side_effect = lambda name: name != "dnsmasq"
        harness.profiles.compose_profiles.return_value = [TEST_DOMAIN, TEST_IP1]

        args = harness.mode.pre_start("test", ["dev-standard"])

        # dig tier: resolve_and_cache called with ALL entries (domains + IPs)
        harness.dns.resolve_and_cache.assert_called_once()
        call_entries = harness.dns.resolve_and_cache.call_args[0][0]
        assert TEST_DOMAIN in call_entries
        assert TEST_IP1 in call_entries
        # No --dns flag for dig tier
        assert "--dns" not in args

    @mock.patch("terok_shield.core.mode_hook.has_global_hooks", return_value=True)
    def test_pre_start_dnsmasq_tier_splits_domains_and_ips(
        self,
        _has_hooks: mock.Mock,
        monkeypatch: pytest.MonkeyPatch,
        make_hook_mode: HookModeHarnessFactory,
    ) -> None:
        """When tier is DNSMASQ, pre_start splits entries: domains to file, IPs to cache."""
        _set_euid(monkeypatch, 0)
        harness = make_hook_mode()
        harness.runner.run.side_effect = lambda cmd, **_kw: (
            _DNSMASQ_VERSION_NFTSET if cmd[0] == "dnsmasq" else _MODERN_PODMAN_INFO
        )
        harness.runner.has.return_value = True  # dnsmasq available (nftset probed via run)
        harness.profiles.compose_profiles.return_value = [TEST_DOMAIN, TEST_IP1]

        args = harness.mode.pre_start("test", ["dev-standard"])

        # dnsmasq tier: resolve_and_cache called with raw IPs only
        harness.dns.resolve_and_cache.assert_called_once()
        call_entries = harness.dns.resolve_and_cache.call_args[0][0]
        assert TEST_IP1 in call_entries
        assert TEST_DOMAIN not in call_entries
        # Domains written to profile.domains
        sd = harness.config.state_dir.resolve()
        domains_content = state.profile_domains_path(sd).read_text()
        assert TEST_DOMAIN in domains_content
        # No --dns flag (triggers pasta to bind host port 53, fails rootless).
        # Instead, resolv.conf is pre-written and bind-mounted :ro via --volume.
        assert "--dns" not in args
        assert "--volume" in args
        volume_args = [args[i + 1] for i, a in enumerate(args) if a == "--volume"]
        assert any("/etc/resolv.conf:ro,Z" in v for v in volume_args)
        # The resolv.conf source file exists and points to dnsmasq
        sd = harness.config.state_dir.resolve()
        resolv = state.resolv_conf_path(sd)
        assert resolv.is_file()
        assert "127.0.0.1" in resolv.read_text()

    @mock.patch("terok_shield.core.mode_hook.has_global_hooks", return_value=True)
    def test_pre_start_getent_tier_resolves_all_entries(
        self,
        _has_hooks: mock.Mock,
        monkeypatch: pytest.MonkeyPatch,
        make_hook_mode: HookModeHarnessFactory,
    ) -> None:
        """When tier is GETENT (no dnsmasq, no dig), pre_start still resolves all entries."""
        _set_euid(monkeypatch, 0)
        harness = make_hook_mode()
        harness.runner.run.return_value = _MODERN_PODMAN_INFO
        harness.runner.has.return_value = False  # nothing available
        harness.profiles.compose_profiles.return_value = [TEST_DOMAIN]

        args = harness.mode.pre_start("test", ["dev-standard"])

        harness.dns.resolve_and_cache.assert_called_once()
        assert "--dns" not in args


class TestDenyDomainWithReload:
    """deny_domain() removes domain and triggers dnsmasq reload."""

    def test_deny_domain_triggers_reload(self, make_hook_mode: HookModeHarnessFactory) -> None:
        """deny_domain() removes domain from live.domains and reloads dnsmasq."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        state.ensure_state_dirs(sd)
        state.live_domains_path(sd).write_text(f"{TEST_DOMAIN}\n")
        state.upstream_dns_path(sd).write_text("169.254.1.1\n")
        state.dnsmasq_pid_path(sd).write_text("12345\n")

        with (
            mock.patch("terok_shield.core.dnsmasq._is_our_dnsmasq", return_value=True),
            mock.patch("terok_shield.core.dnsmasq.os.kill"),
        ):
            harness.mode.deny_domain(TEST_DOMAIN)

        denied = state.denied_domains_path(sd).read_text()
        assert TEST_DOMAIN in denied

    def test_deny_domain_noop_when_not_present(
        self, make_hook_mode: HookModeHarnessFactory
    ) -> None:
        """deny_domain() is a no-op when the domain is not in any domain file."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        state.ensure_state_dirs(sd)

        with mock.patch("terok_shield.core.dnsmasq.reload") as mock_reload:
            harness.mode.deny_domain(TEST_DOMAIN)
        mock_reload.assert_not_called()


class TestContainerRulesetDnsTier:
    """_container_ruleset() uses persisted DNS tier for set_timeout."""

    def test_dnsmasq_tier_enables_set_timeout(self, make_hook_mode: HookModeHarnessFactory) -> None:
        """When dns.tier is 'dnsmasq', RulesetBuilder gets set_timeout."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        state.ensure_state_dirs(sd)
        state.upstream_dns_path(sd).write_text("169.254.1.1\n")
        state.dns_tier_path(sd).write_text("dnsmasq\n")

        harness.runner.podman_inspect.return_value = "42"
        harness.runner.run.side_effect = [
            "nameserver 127.0.0.1\n",  # podman unshare cat resolv.conf
            "",  # podman unshare cat /proc/.../route
        ]

        ruleset = harness.mode._container_ruleset("test-ctr")
        assert ruleset._set_timeout == "30m"

    def test_dig_tier_no_set_timeout(self, make_hook_mode: HookModeHarnessFactory) -> None:
        """When dns.tier is 'dig', RulesetBuilder has no timeout."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        state.ensure_state_dirs(sd)
        state.upstream_dns_path(sd).write_text("169.254.1.1\n")
        state.dns_tier_path(sd).write_text("dig\n")

        harness.runner.podman_inspect.return_value = "42"
        harness.runner.run.side_effect = [
            "nameserver 169.254.1.1\n",
            "",
        ]

        ruleset = harness.mode._container_ruleset("test-ctr")
        assert ruleset._set_timeout == ""

    def test_no_tier_file_no_timeout(self, make_hook_mode: HookModeHarnessFactory) -> None:
        """When dns.tier file is absent, no timeout (backward compat)."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        state.ensure_state_dirs(sd)

        harness.runner.podman_inspect.return_value = "42"
        harness.runner.run.side_effect = [
            "nameserver 169.254.1.1\n",
            "",
        ]

        ruleset = harness.mode._container_ruleset("test-ctr")
        assert ruleset._set_timeout == ""


# ── Additional coverage tests ─────────────────────────────


def test_upstream_dns_for_mode_raises_on_unknown_mode() -> None:
    """_upstream_dns_for_mode() raises ValueError for unrecognised network modes."""
    from terok_shield.core.mode_hook import _upstream_dns_for_mode

    with pytest.raises(ValueError, match="Cannot determine upstream DNS"):
        _upstream_dns_for_mode("bridge")


@mock.patch("terok_shield.core.mode_hook.has_global_hooks", return_value=True)
def test_pre_start_includes_hooks_dir_when_persists(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start() adds --hooks-dir when info.hooks_dir_persists is True."""
    _set_euid(monkeypatch, 1000)
    harness = make_hook_mode(config=make_config())
    # Podman version 99.0.0 triggers hooks_dir_persists = True
    harness.runner.run.return_value = json.dumps(
        {"host": {"rootlessNetworkCmd": "pasta"}, "version": {"Version": "99.0.0"}}
    )
    harness.profiles.compose_profiles.return_value = []

    args = harness.mode.pre_start("test", ["dev-standard"])

    assert "--hooks-dir" in args


def test_shield_state_returns_down_all(make_hook_mode: HookModeHarnessFactory) -> None:
    """shield_state() returns DOWN_ALL when allow-all bypass is active but not simple bypass."""
    harness = make_hook_mode()
    harness.runner.nft_via_nsenter.return_value = "some rules"
    # First call (allow_all=False): non-empty errors → not DOWN, continue
    # Second call (allow_all=True): empty list → DOWN_ALL
    harness.ruleset.verify_bypass.side_effect = [["not bypass"], []]

    assert harness.mode.shield_state("test-ctr") == ShieldState.DOWN_ALL


def test_shield_up_repopulates_gateway_v4_from_file(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """shield_up() re-adds the persisted IPv4 gateway to the nft gateway_v4 set."""
    harness = make_hook_mode(config=make_config())
    sd = harness.config.state_dir
    state.gateway_path(sd).write_text("10.0.2.2\n")

    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.runner.nft_via_nsenter.side_effect = [
        "table inet terok_shield {}",  # shield_state() → UP
        "",  # apply ruleset
        "",  # add gateway element
        "valid output",  # verify
    ]
    harness.ruleset.build_hook.return_value = "hook ruleset"
    harness.ruleset.verify_hook.return_value = []
    harness.ruleset.add_elements_dual.return_value = ""
    harness.ruleset.verify_bypass.return_value = ["not bypass"]

    harness.mode.shield_up("test-ctr")

    gateway_calls = [
        call for call in harness.runner.nft_via_nsenter.call_args_list if "gateway_v4" in call.args
    ]
    assert gateway_calls, "Expected nft call to add gateway_v4 element"
    assert any("{ 10.0.2.2 }" in str(c) for c in gateway_calls)


def test_shield_up_repopulates_gateway_v6_from_file(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """shield_up() re-adds the persisted IPv6 gateway to the nft gateway_v6 set."""
    harness = make_hook_mode(config=make_config())
    sd = harness.config.state_dir
    state.gateway_v6_path(sd).write_text("fd00::1\n")

    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.runner.nft_via_nsenter.side_effect = [
        "table inet terok_shield {}",  # shield_state() → UP
        "",  # apply ruleset
        "",  # add gateway element
        "valid output",  # verify
    ]
    harness.ruleset.build_hook.return_value = "hook ruleset"
    harness.ruleset.verify_hook.return_value = []
    harness.ruleset.add_elements_dual.return_value = ""
    harness.ruleset.verify_bypass.return_value = ["not bypass"]

    harness.mode.shield_up("test-ctr")

    gateway_calls = [
        call for call in harness.runner.nft_via_nsenter.call_args_list if "gateway_v6" in call.args
    ]
    assert gateway_calls, "Expected nft call to add gateway_v6 element"


# ── Interactive mode coverage ────────────────────────────


@mock.patch("terok_shield.core.mode_hook.has_global_hooks", return_value=True)
def test_pre_start_interactive_writes_nflog_tier(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start(interactive=True) writes 'nflog' to the interactive marker file."""
    _set_euid(monkeypatch, 0)
    config = make_config(interactive=True)
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []

    harness.mode.pre_start("test", ["dev-standard"])

    marker = state.interactive_path(config.state_dir)
    assert marker.is_file()
    assert marker.read_text().strip() == "nflog"


@mock.patch("terok_shield.core.mode_hook.has_global_hooks", return_value=True)
def test_pre_start_with_denied_ips_includes_deny_elements(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start() includes deny elements in ruleset when deny.list exists."""
    _set_euid(monkeypatch, 0)
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []

    # Write a deny.list before pre_start
    state.deny_path(config.state_dir).write_text(f"{TEST_IP1}\n")

    harness.mode.pre_start("test", ["dev-standard"])

    ruleset = state.ruleset_path(config.state_dir).read_text()
    assert "deny_v4" in ruleset
    assert TEST_IP1 in ruleset


# ── Container ID persistence ─────────────────────────────


@mock.patch("terok_shield.core.mode_hook.has_global_hooks", return_value=True)
def test_pre_start_persists_container_id(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start() persists the short container ID to state_dir/container.id."""
    _set_euid(monkeypatch, 0)
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.runner.podman_inspect.return_value = "abc123def456789abcdef0"
    harness.profiles.compose_profiles.return_value = []

    harness.mode.pre_start("test", ["dev-standard"])

    harness.runner.podman_inspect.assert_any_call("test", "{{.Id}}")
    id_file = state.container_id_path(config.state_dir)
    assert id_file.is_file()
    assert id_file.read_text().strip() == "abc123def456"


def test_shield_up_interactive_uses_interactive_ruleset(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """shield_up() uses interactive=True when the interactive marker is set."""
    config = make_config()
    harness = make_hook_mode(config=config)
    # Bypass DNS reading
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.runner.nft_via_nsenter.return_value = ""
    harness.ruleset.build_hook.return_value = "hook ruleset"
    harness.ruleset.verify_hook.return_value = []
    harness.ruleset.add_elements_dual.return_value = ""
    harness.ruleset.verify_bypass.return_value = ["not bypass"]

    # Write the interactive marker
    state.interactive_path(config.state_dir).write_text("nflog\n")

    harness.mode.shield_up("test-ctr")

    harness.ruleset.build_hook.assert_called_with(interactive=True)


def test_shield_up_repopulates_deny_sets(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """shield_up() repopulates deny sets from deny.list."""
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.runner.nft_via_nsenter.return_value = ""
    harness.ruleset.build_hook.return_value = "hook ruleset"
    harness.ruleset.verify_hook.return_value = []
    harness.ruleset.add_elements_dual.return_value = ""
    harness.ruleset.verify_bypass.return_value = ["not bypass"]

    # Write a deny.list
    state.deny_path(config.state_dir).write_text(f"{TEST_IP1}\n")

    harness.mode.shield_up("test-ctr")

    # Verify deny elements were sent via nsenter
    deny_calls = [c for c in harness.runner.nft_via_nsenter.call_args_list if c.kwargs.get("stdin")]
    assert any(TEST_IP1 in (c.kwargs.get("stdin", "") or "") for c in deny_calls)


def test_shield_state_detects_interactive_up(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """shield_state() returns UP for an interactive hook ruleset."""
    harness = make_hook_mode()
    harness.runner.nft_via_nsenter.return_value = "some ruleset"
    # First verify_bypass fails, first verify_hook (strict) fails,
    # second verify_hook (interactive=True) succeeds.
    harness.ruleset.verify_bypass.return_value = ["not bypass"]
    harness.ruleset.verify_hook.side_effect = [["not strict"], []]

    assert harness.mode.shield_state("test") == ShieldState.UP


def test_preview_interactive_delegates(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """preview() passes interactive=True when config has interactive enabled."""
    config = make_config(interactive=True)
    harness = make_hook_mode(config=config)
    harness.ruleset.build_hook.return_value = "interactive ruleset"

    result = harness.mode.preview()

    harness.ruleset.build_hook.assert_called_with(interactive=True)
    assert result == "interactive ruleset"
