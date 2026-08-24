# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the HookMode class."""

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import pytest

from terok_shield.config import (
    ANNOTATION_AUDIT_ENABLED_KEY,
    ANNOTATION_STATE_DIR_KEY,
    DnsTier,
    ShieldConfig,
    ShieldRuntime,
    ShieldState,
)
from terok_shield.hooks.install import install_hooks
from terok_shield.hooks.mode import HookMode, _covered
from terok_shield.nft.constants import DNSMASQ_BIND_KRUN, PASTA_DNS, PASTA_HOST_LOOPBACK_MAP
from terok_shield.nft.rules import RulesetBuilder
from terok_shield.run import ExecError

from ..testfs import BIN_DIR_NAME, HOOK_ENTRYPOINT_NAME, HOOKS_DIR_NAME
from ..testnet import (
    BROAD_CIDR_8,
    CONTAINER_HOSTNAME,
    IPV6_CLOUDFLARE,
    SLIRP4NETNS_GATEWAY,
    TEST_DOMAIN,
    TEST_DOMAIN2,
    TEST_IP1,
    TEST_IP2,
    TEST_IP3,
    TEST_IP4,
    TEST_NET1,
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


@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
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


@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
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

    assert StateBundle(config.state_dir).hooks_dir.is_dir()
    assert StateBundle(config.state_dir).hook_entrypoint.is_file()


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
@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
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
        pytest.param("allow_ip", TEST_IP1, "add", "t40_project_allow_v4", id="allow-ipv4"),
        pytest.param("allow_ip", IPV6_CLOUDFLARE, "add", "t40_project_allow_v6", id="allow-ipv6"),
        pytest.param("deny_ip", TEST_IP1, "delete", "t40_project_allow_v4", id="deny-ipv4"),
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


def test_allow_persists_and_deduplicates_overlay(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """allow_ip() records ``+ip`` in the overlay without duplicate lines."""
    harness = make_hook_mode(config=make_config())

    harness.mode.allow_ip("test-ctr", TEST_IP1)
    harness.mode.allow_ip("test-ctr", TEST_IP1)

    lines = StateBundle(harness.config.state_dir).policy_live.read_text().splitlines()
    assert lines.count(f"+{TEST_IP1}") == 1


def test_allow_ip_uses_timeout_zero_in_dnsmasq_tier(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """allow_ip() adds 'timeout 0s' when dnsmasq tier is active so the element never expires."""
    harness = make_hook_mode(config=make_config())
    sd = harness.config.state_dir.resolve()
    StateBundle(sd).dns_tier.write_text("dnsmasq\n")

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
    StateBundle(sd).dns_tier.write_text("dig\n")

    harness.mode.allow_ip("test-ctr", TEST_IP1)

    element_arg = harness.runner.nft_via_nsenter.call_args.args[-1]
    assert "timeout 0s" not in element_arg


@pytest.mark.parametrize(
    ("preallow", "nft_side_effect"),
    [
        pytest.param(True, None, id="allowed-ip-flips-to-deny"),
        pytest.param(False, None, id="fresh-deny-persists"),
        pytest.param(True, ExecError(["nft"], 1, "not in set"), id="nft-error-still-persists"),
    ],
)
def test_deny_persists_to_overlay(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    preallow: bool,
    nft_side_effect: ExecError | None,
) -> None:
    """deny_ip() records ``-ip`` in the overlay regardless of source, even on nft error."""
    harness = make_hook_mode(config=make_config())
    bundle = StateBundle(harness.config.state_dir)
    if preallow:
        bundle.overlay_set("+", TEST_IP1)
    harness.runner.nft_via_nsenter.side_effect = nft_side_effect

    harness.mode.deny_ip("test-ctr", TEST_IP1)

    assert TEST_IP1 in bundle.read_denied_ips()
    assert TEST_IP1 not in bundle.read_effective_ips()


def test_allow_after_deny_clears_deny(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """allow_ip() flips a denied IP back to allowed in the overlay."""
    harness = make_hook_mode(config=make_config())
    bundle = StateBundle(harness.config.state_dir)
    bundle.overlay_set("-", TEST_IP1)
    bundle.overlay_set("-", TEST_IP2)

    harness.mode.allow_ip("test-ctr", TEST_IP1)
    denied = bundle.read_denied_ips()
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
    ("disengaged", "verify_errors", "expected_message"),
    [
        pytest.param(False, [], None, id="success"),
        pytest.param(True, [], None, id="disengaged"),
        pytest.param(
            False, ["error: missing policy"], "verification failed", id="verification-failure"
        ),
    ],
)
def test_shield_down_builds_down_ruleset(
    make_hook_mode: HookModeHarnessFactory,
    disengaged: bool,
    verify_errors: list[str],
    expected_message: str | None,
) -> None:
    """shield_down() applies the down posture and verifies the resulting ruleset."""
    harness = make_hook_mode()
    # Mock DNS reading so _container_ruleset returns the mock ruleset
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    # shield_state() call (list_rules) + allow-set snapshot (v4+v6) + apply + verify
    harness.runner.nft_via_nsenter.side_effect = [
        "table inet terok_shield {}",  # shield_state() → list_rules
        "",  # snapshot t40_project_allow_v4 (empty)
        "",  # snapshot t40_project_allow_v6 (empty)
        "",  # apply down ruleset
        "bad output" if verify_errors else "valid output",  # verify
    ]
    harness.ruleset.build_down.return_value = "down ruleset"
    harness.ruleset.verify_down.return_value = verify_errors
    # shield_state() uses verify_down/verify_up to classify
    harness.ruleset.verify_up.return_value = []

    if expected_message is None:
        harness.mode.shield_down("test-ctr", disengaged=disengaged)
        assert harness.runner.nft_via_nsenter.call_count == 5
        harness.ruleset.build_down.assert_called_once_with(disengaged=disengaged)
        assert harness.ruleset.verify_down.call_args == mock.call(
            "valid output", disengaged=disengaged
        )
    else:
        with pytest.raises(RuntimeError, match=expected_message):
            harness.mode.shield_down("test-ctr", disengaged=disengaged)


@pytest.mark.parametrize(
    ("allowed_ips", "verify_errors", "expected_calls"),
    [
        pytest.param([], [], 5, id="no-cached-ips"),
        pytest.param([TEST_IP1], [], 6, id="readds-cached-ips"),
        pytest.param([], ["error"], 5, id="verification-failure"),
    ],
)
def test_shield_up_reapplies_hook_ruleset(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    allowed_ips: list[str],
    verify_errors: list[str],
    expected_calls: int,
) -> None:
    """shield_up() restores hook mode, optionally re-adding effective IPs.

    Call sequence: shield_state list, allow-set snapshot (v4+v6), apply,
    optional element re-add, verify list — the empty snapshot yields no
    restore call.
    """
    harness = make_hook_mode(config=make_config())
    if allowed_ips:
        write_lines(StateBundle(harness.config.state_dir).resolved_cache, allowed_ips)
    # Mock DNS reading so _container_ruleset returns the mock ruleset
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    # shield_state() call (list_rules) returns existing table (UP state)
    harness.runner.nft_via_nsenter.side_effect = [
        "table inet terok_shield {}",  # shield_state() → list_rules
        "",  # snapshot t40_project_allow_v4 (empty)
        "",  # snapshot t40_project_allow_v6 (empty)
        *[""] * (expected_calls - 4),  # apply + optional elements
        "valid output" if not verify_errors else "bad output",  # verify
    ]
    harness.ruleset.build_up.return_value = "up ruleset"
    harness.ruleset.verify_up.return_value = verify_errors
    harness.ruleset.add_elements_dual.return_value = (
        f"add element {TEST_IP1}" if allowed_ips else ""
    )
    # For shield_state() classification — report UP so delete table is prepended
    harness.ruleset.verify_down.return_value = ["not down"]

    if verify_errors:
        with pytest.raises(RuntimeError):
            harness.mode.shield_up("test-ctr")
    else:
        harness.mode.shield_up("test-ctr")
    assert harness.runner.nft_via_nsenter.call_count == expected_calls


def _snapshot_output(elements: str) -> str:
    """Realistic ``nft list set`` output carrying *elements*."""
    return (
        "table inet terok_shield {\n"
        "\tset t40_project_allow_v4 {\n"
        "\t\ttype ipv4_addr\n"
        "\t\tflags interval,timeout\n"
        "\t\ttimeout 30m\n"
        f"\t\telements = {{ {elements} }}\n"
        "\t}\n"
        "}\n"
    )


def _restore_stdins(runner_mock: mock.Mock) -> list[str]:
    """Every non-empty stdin batch passed to nft_via_nsenter."""
    calls = runner_mock.nft_via_nsenter.call_args_list
    return [s for c in calls if (s := c.kwargs.get("stdin"))]


def test_shield_up_restores_learned_elements(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """A down/up round trip must never forget dnsmasq-learned allow-set state.

    The snapshot taken before the table rebuild is replayed after it, minus
    entries the rebuild re-adds itself (effective seeds) and minus denied
    entries (deny_ip() evicted them from the allow set deliberately).
    """
    harness = make_hook_mode(config=make_config())
    bundle = StateBundle(harness.config.state_dir)
    write_lines(bundle.resolved_cache, [TEST_IP1])  # effective seed
    bundle.overlay_set("-", TEST_IP4)  # denied while down
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.runner.nft_via_nsenter.side_effect = [
        "table inet terok_shield {}",  # shield_state()
        _snapshot_output(
            f"{TEST_IP1} timeout 0s, {TEST_IP3} timeout 30m expires 2m, {TEST_IP4} timeout 30m"
        ),  # snapshot v4
        "",  # snapshot v6
        "",  # apply hook ruleset
        "",  # re-add effective IPs
        "",  # repopulate deny sets
        "",  # restore learned elements
        "valid output",  # verify
    ]
    harness.ruleset.build_up.return_value = "up ruleset"
    harness.ruleset.verify_up.return_value = []
    harness.ruleset.verify_down.return_value = ["not down"]
    harness.ruleset.add_elements_dual.return_value = f"add element {TEST_IP1}"

    harness.mode.shield_up("test-ctr")

    restore = next(s for s in _restore_stdins(harness.runner) if "t40_project_allow_v4" in s)
    assert f"{TEST_IP3} timeout 30m" in restore  # learned survives, full timeout re-granted
    assert TEST_IP1 not in restore  # seed re-added by the rebuild, not the restore
    assert TEST_IP4 not in restore  # denied stays evicted


def test_shield_down_carries_allow_sets_into_down_table(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """shield_down() replays the full allow-set snapshot into the down table.

    The down posture does not evaluate the sets, but the later ``shield up``
    snapshots this table — dropping them here would forget every learned IP
    after one down/up round trip.
    """
    harness = make_hook_mode(config=make_config())
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.runner.nft_via_nsenter.side_effect = [
        "table inet terok_shield {}",  # shield_state()
        _snapshot_output(f"{TEST_IP1} timeout 0s, {TEST_IP3} timeout 30m"),  # snapshot v4
        "",  # snapshot v6
        "",  # apply down ruleset
        "",  # restore allow sets
        "valid output",  # verify
    ]
    harness.ruleset.build_down.return_value = "down ruleset"
    harness.ruleset.verify_down.return_value = []
    harness.ruleset.verify_up.return_value = []

    harness.mode.shield_down("test-ctr")

    restore = next(s for s in _restore_stdins(harness.runner) if "t40_project_allow_v4" in s)
    assert f"{TEST_IP1} timeout 0s" in restore
    assert f"{TEST_IP3} timeout 30m" in restore


def test_shield_up_survives_restore_failure(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A failed allow-set restore is logged, never raised.

    Coming up with a cold allow set (the workload re-learns via DNS) beats
    staying down because a restore batch was rejected.
    """
    harness = make_hook_mode(config=make_config())
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.runner.nft_via_nsenter.side_effect = [
        "table inet terok_shield {}",  # shield_state()
        _snapshot_output(f"{TEST_IP3} timeout 30m"),  # snapshot v4
        "",  # snapshot v6
        "",  # apply hook ruleset
        ExecError(["nft"], 1, "conflict"),  # restore fails
        "valid output",  # verify
    ]
    harness.ruleset.build_up.return_value = "up ruleset"
    harness.ruleset.verify_up.return_value = []
    harness.ruleset.verify_down.return_value = ["not down"]
    harness.ruleset.add_elements_dual.return_value = ""

    with caplog.at_level(logging.WARNING):
        harness.mode.shield_up("test-ctr")  # must not raise

    assert any("restore failed" in r.message for r in caplog.records)


def test_shield_down_tolerates_unsnapshottable_sets(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """A failed set listing (older ruleset, missing set) yields an empty snapshot.

    The transition proceeds with nothing to restore — never an error.
    """
    harness = make_hook_mode(config=make_config())
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.runner.nft_via_nsenter.side_effect = [
        "table inet terok_shield {}",  # shield_state()
        ExecError(["nft"], 1, "No such file or directory"),  # snapshot v4 fails
        ExecError(["nft"], 1, "No such file or directory"),  # snapshot v6 fails
        "",  # apply down ruleset
        "valid output",  # verify
    ]
    harness.ruleset.build_down.return_value = "down ruleset"
    harness.ruleset.verify_down.return_value = []
    harness.ruleset.verify_up.return_value = []

    harness.mode.shield_down("test-ctr")

    assert not [s for s in _restore_stdins(harness.runner) if "add element" in s]


def test_covered_matches_overlap_and_ignores_garbage() -> None:
    """_covered(): interval overlap in either direction counts; unparseable
    skip entries and family mismatches are ignored."""
    assert _covered(TEST_IP1, [TEST_IP1])
    assert _covered(TEST_IP1, [TEST_NET1])  # inside a skip CIDR
    assert _covered(TEST_NET1, [TEST_IP1])  # skip IP inside the element
    assert not _covered(TEST_IP1, ["not-an-ip", IPV6_CLOUDFLARE])
    assert not _covered(TEST_IP1, [TEST_IP3])


def test_shield_reset_flushes_and_reseeds_allow_sets(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """shield_reset() drops learned state and re-seeds literals in one transaction."""
    harness = make_hook_mode(config=make_config())
    write_lines(StateBundle(harness.config.state_dir).resolved_cache, [TEST_IP1])
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.ruleset.add_elements_dual.return_value = f"add element {TEST_IP1}\n"

    harness.mode.shield_reset("test-ctr")

    harness.ruleset.add_elements_dual.assert_called_once_with([TEST_IP1])
    (stdin,) = _restore_stdins(harness.runner)
    assert "flush set inet terok_shield t40_project_allow_v4" in stdin
    assert "flush set inet terok_shield t40_project_allow_v6" in stdin
    # Re-seed rides the same transaction — literals never blink out.
    assert stdin.index("flush set") < stdin.index(f"add element {TEST_IP1}")


@pytest.mark.parametrize(
    ("nft_output", "verify_down", "verify_up", "expected"),
    [
        pytest.param("", None, None, ShieldState.OFFLINE, id="offline"),
        pytest.param(RulesetBuilder().build_up(), ["not down"], [], ShieldState.UP, id="up"),
        pytest.param(RulesetBuilder().build_down(), [], None, ShieldState.DOWN, id="down"),
        pytest.param("random nft stuff", ["not down"], ["not up"], ShieldState.ERROR, id="error"),
    ],
)
def test_shield_state_classifies_rulesets(
    make_hook_mode: HookModeHarnessFactory,
    nft_output: str,
    verify_down: list[str] | None,
    verify_up: list[str] | None,
    expected: ShieldState,
) -> None:
    """shield_state() distinguishes offline, up, down, and invalid rulesets."""
    harness = make_hook_mode()
    harness.runner.nft_via_nsenter.return_value = nft_output
    if verify_down is not None:
        harness.ruleset.verify_down.return_value = verify_down
    if verify_up is not None:
        harness.ruleset.verify_up.return_value = verify_up
    assert harness.mode.shield_state("test") == expected


def test_shield_state_detects_quarantine(make_hook_mode: HookModeHarnessFactory) -> None:
    """shield_state() returns QUARANTINE when verify_quarantine passes."""
    harness = make_hook_mode()
    harness.runner.nft_via_nsenter.return_value = "table inet terok_shield { policy drop }"
    harness.ruleset.verify_quarantine.return_value = []  # passes
    harness.ruleset.verify_down.return_value = ["not down"]
    assert harness.mode.shield_state("test") == ShieldState.QUARANTINE


def test_shield_quarantine_applies_block_ruleset(
    make_hook_mode: HookModeHarnessFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """shield_quarantine() applies the quarantine ruleset and verifies it.

    ``build_quarantine`` / ``verify_quarantine`` are static class methods
    on ``RulesetBuilder`` (no config dependency by design — see
    ``HookMode.shield_quarantine``).  Patch at the class to stub them.
    """
    from terok_shield.nft.rules import RulesetBuilder

    harness = make_hook_mode()
    harness.runner.nft_via_nsenter.side_effect = [
        "table inet terok_shield {}",  # shield_state() → list_rules
        "",  # apply quarantine ruleset
        "valid output",  # verify
    ]
    harness.ruleset.verify_down.return_value = ["not down"]
    harness.ruleset.verify_up.return_value = ["not up"]
    build_mock = mock.Mock(return_value="quarantine ruleset")
    verify_mock = mock.Mock(return_value=[])
    monkeypatch.setattr(RulesetBuilder, "build_quarantine", build_mock)
    monkeypatch.setattr(RulesetBuilder, "verify_quarantine", verify_mock)

    harness.mode.shield_quarantine("test-ctr")
    assert harness.runner.nft_via_nsenter.call_count == 3
    build_mock.assert_called_once()


def test_shield_quarantine_raises_on_verification_failure(
    make_hook_mode: HookModeHarnessFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """shield_quarantine() raises RuntimeError when verification fails."""
    from terok_shield.nft.rules import RulesetBuilder

    harness = make_hook_mode()
    harness.runner.nft_via_nsenter.side_effect = [
        "table inet terok_shield {}",  # shield_state()
        "",  # apply
        "bad output",  # verify
    ]
    harness.ruleset.verify_down.return_value = ["not down"]
    harness.ruleset.verify_up.return_value = ["not up"]
    monkeypatch.setattr(
        RulesetBuilder, "build_quarantine", mock.Mock(return_value="quarantine ruleset")
    )
    monkeypatch.setattr(
        RulesetBuilder, "verify_quarantine", mock.Mock(return_value=["policy is not drop"])
    )

    with pytest.raises(RuntimeError, match="Quarantine ruleset verification failed"):
        harness.mode.shield_quarantine("test-ctr")


def test_shield_quarantine_on_offline_applies_without_delete(
    make_hook_mode: HookModeHarnessFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """shield_quarantine() on an offline container applies ruleset without delete prefix."""
    from terok_shield.nft.rules import RulesetBuilder

    harness = make_hook_mode()
    harness.runner.nft_via_nsenter.side_effect = [
        "",  # shield_state() → OFFLINE
        "",  # apply
        "valid output",  # verify
    ]
    monkeypatch.setattr(
        RulesetBuilder, "build_quarantine", mock.Mock(return_value="quarantine ruleset")
    )
    monkeypatch.setattr(RulesetBuilder, "verify_quarantine", mock.Mock(return_value=[]))

    harness.mode.shield_quarantine("test-ctr")

    # Second call (apply) should NOT have "delete table" prefix
    apply_call = harness.runner.nft_via_nsenter.call_args_list[1]
    stdin_arg = apply_call.kwargs.get(
        "stdin", apply_call.args[1] if len(apply_call.args) > 1 else ""
    )
    assert "delete table" not in stdin_arg


@pytest.mark.parametrize(
    ("kwargs", "expected", "method_name"),
    [
        pytest.param({}, "up ruleset", "build_up", id="default-up-preview"),
        pytest.param(
            {"down": True, "disengaged": True}, "down ruleset", "build_down", id="down-preview"
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


def test_role_scripts_are_stdlib_only(tmp_path: Path) -> None:
    """Both role scripts use ``/usr/bin/env python3`` and have no terok_shield imports.

    The shared ballast (``_oci_state.py``) is verified separately by
    ``test_hook_isolation`` — same stdlib-only contract.
    """
    from terok_shield.hooks.install import _RESOURCES

    for name in ("nft_hook.py", "reader_hook.py"):
        content = (_RESOURCES / name).read_text()
        assert content.splitlines()[0] == "#!/usr/bin/env python3", name
        assert "import terok_shield" not in content, name
        assert "from terok_shield" not in content, name
    # nft_hook is the one that actually emits ``ruleset.nft`` references —
    # keep the file-name literal grep here so a rename in state.py
    # tripwires both this test and ``test_nft_hook_path_strings_match_state_functions``.
    assert "ruleset.nft" in (_RESOURCES / "nft_hook.py").read_text()


@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
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

    ruleset_file = StateBundle(config.state_dir).ruleset
    assert ruleset_file.is_file(), "pre_start() must write ruleset.nft"
    content = ruleset_file.read_text()
    assert "terok_shield" in content


def test_hooks_installer_writes_role_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``HooksInstaller.install()`` lays down nft + reader hooks, ballast, and reader resource."""
    from terok_shield.hooks.install import HooksInstaller

    # Reader resource lands at ``$XDG_DATA_HOME/terok/shield/nflog-reader.py``;
    # redirect it under tmp_path so the test stays hermetic.
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
    monkeypatch.setattr(
        "terok_shield.hooks.install._user_containers_conf",
        lambda: tmp_path / "containers.conf",
    )
    target = tmp_path / "hooks"
    HooksInstaller(target_dir=target).install()

    # Shared ballast lands once — both role scripts import from it.
    assert (target / "_oci_state.py").is_file()

    # nft role: script + JSON pair.
    assert (target / "terok-shield-hook").is_file()
    assert (target / "terok-shield-hook").stat().st_mode & 0o100
    assert (target / "terok-shield-createRuntime.json").is_file()
    assert (target / "terok-shield-poststop.json").is_file()
    nft = json.loads((target / "terok-shield-createRuntime.json").read_text())
    assert nft["hook"]["path"] == str(target / "terok-shield-hook")
    assert nft["hook"]["args"] == ["terok-shield-hook", "createRuntime"]

    # Reader role: own script + own JSON pair (no shared ``--bridge`` flag now).
    assert (target / "terok-shield-bridge-hook").is_file()
    assert (target / "terok-shield-bridge-hook").stat().st_mode & 0o100
    assert (target / "terok-shield-bridge-createRuntime.json").is_file()
    assert (target / "terok-shield-bridge-poststop.json").is_file()
    bridge = json.loads((target / "terok-shield-bridge-createRuntime.json").read_text())
    assert bridge["hook"]["path"] == str(target / "terok-shield-bridge-hook")
    assert bridge["hook"]["args"] == ["terok-shield-bridge-hook", "createRuntime"]

    # NFLOG reader resource lands at the canonical XDG path.
    reader = tmp_path / "share" / "terok" / "shield" / "nflog-reader.py"
    assert reader.is_file()
    assert reader.stat().st_mode & 0o100


def test_install_hooks_honors_custom_entrypoint_name(tmp_path: Path) -> None:
    """``install_hooks`` writes the nft entrypoint at the requested filename.

    Per-container installs and tests pin a specific
    ``hook_entrypoint`` path; the JSON descriptors must point at the
    very file the caller asked for, not the canonical default.  The
    reader entrypoint and the shared ballast still use their canonical
    names — only the nft script is renameable.
    """
    from terok_shield.hooks.install import install_hooks

    target = tmp_path / "hooks.d"
    custom_entrypoint = target / "my-custom-name"
    install_hooks(hook_entrypoint=custom_entrypoint, hooks_dir=target)

    # Custom-named nft script lives at the requested path.
    assert custom_entrypoint.is_file()
    assert custom_entrypoint.stat().st_mode & 0o100

    # JSON descriptors reference that exact path, with the
    # corresponding cosmetic argv[0].
    nft_json = json.loads((target / "terok-shield-createRuntime.json").read_text())
    assert nft_json["hook"]["path"] == str(custom_entrypoint)
    assert nft_json["hook"]["args"] == ["my-custom-name", "createRuntime"]

    # Sibling files keep their canonical names — only the nft script
    # is parameterised.
    assert (target / "_oci_state.py").is_file()
    assert (target / "terok-shield-bridge-hook").is_file()
    bridge_json = json.loads((target / "terok-shield-bridge-createRuntime.json").read_text())
    assert bridge_json["hook"]["path"] == str(target / "terok-shield-bridge-hook")


@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
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

    with mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True):
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
    from terok_shield.run import ShieldNeedsSetup

    _set_euid(monkeypatch, 0)
    harness = make_hook_mode(config=make_config())
    harness.runner.run.return_value = json.dumps(
        {
            "host": {},
            "version": {"Version": "5.8.0"},
        }
    )
    harness.profiles.compose_profiles.return_value = []

    with mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=False):
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
    from terok_shield.nft.rules import RulesetBuilder

    harness = make_hook_mode()
    harness.runner.podman_inspect.return_value = "12345"
    harness.runner.run.return_value = "nameserver 10.0.2.3\n"

    ruleset = harness.mode._container_ruleset("test-ctr")
    assert isinstance(ruleset, RulesetBuilder)


def test_shield_up_on_offline_applies_without_delete(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """shield_up() on OFFLINE netns applies ruleset without delete table prefix."""
    harness = make_hook_mode(config=make_config())
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    # shield_state() → list_rules returns empty (OFFLINE)
    harness.runner.nft_via_nsenter.side_effect = [
        "",  # shield_state() → OFFLINE
        "",  # apply ruleset (no delete prefix)
        "valid output",  # verify
    ]
    harness.ruleset.build_up.return_value = "up ruleset"
    harness.ruleset.verify_up.return_value = []
    harness.ruleset.add_elements_dual.return_value = ""

    harness.mode.shield_up("test-ctr")

    # On an empty netns there is nothing to delete — no call should contain "delete table"
    for call in harness.runner.nft_via_nsenter.call_args_list:
        assert "delete" not in call.kwargs.get("stdin", "")


def test_shield_down_on_offline_applies_without_delete(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """shield_down() on OFFLINE netns applies the down ruleset without delete table prefix."""
    harness = make_hook_mode()
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    # shield_state() → list_rules returns empty (OFFLINE)
    harness.runner.nft_via_nsenter.side_effect = [
        "",  # shield_state() → OFFLINE
        "",  # apply down ruleset (no delete prefix)
        "valid output",  # verify
    ]
    harness.ruleset.build_down.return_value = "down ruleset"
    harness.ruleset.verify_down.return_value = []

    harness.mode.shield_down("test-ctr", disengaged=False)

    # On an empty netns there is nothing to delete — no call should contain "delete table"
    for call in harness.runner.nft_via_nsenter.call_args_list:
        assert "delete" not in call.kwargs.get("stdin", "")


# ── allow_domain / deny_domain ────────────────────────────


class TestDomainOperations:
    """Tests for allow_domain, deny_domain, and dnsmasq reload."""

    def test_allow_domain_persists_and_reloads(
        self, make_hook_mode: HookModeHarnessFactory
    ) -> None:
        """allow_domain() records ``+domain`` in the overlay and reloads dnsmasq."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        StateBundle(sd).ensure_dirs()
        StateBundle(sd).upstream_dns.write_text("169.254.1.1\n")
        StateBundle(sd).dnsmasq_pid.write_text("12345\n")

        with mock.patch("terok_shield.dns.dnsmasq.reload"):
            harness.mode.allow_domain("test-ctr", TEST_DOMAIN)

        assert f"+{TEST_DOMAIN}" in StateBundle(sd).policy_live.read_text()

    def test_allow_domain_reloads_dnsmasq(self, make_hook_mode: HookModeHarnessFactory) -> None:
        """allow_domain() records the overlay entry and reloads dnsmasq for the container."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        StateBundle(sd).ensure_dirs()
        StateBundle(sd).dns_tier.write_text("dnsmasq\n")
        StateBundle(sd).upstream_dns.write_text("169.254.1.1\n")

        with mock.patch("terok_shield.dns.dnsmasq.reload") as mock_reload:
            harness.mode.allow_domain("test-ctr", TEST_DOMAIN)
        mock_reload.assert_called_once()
        assert mock_reload.call_args.kwargs["container"] == "test-ctr"

    def test_deny_domain_removes_and_reloads(self, make_hook_mode: HookModeHarnessFactory) -> None:
        """deny_domain() records ``-domain`` in the overlay and excludes it from the dnsmasq set."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        bundle = StateBundle(sd)
        bundle.ensure_dirs()
        bundle.write_tier("project_allow", f"+{TEST_DOMAIN}\n")
        bundle.upstream_dns.write_text("169.254.1.1\n")
        bundle.dnsmasq_pid.write_text("12345\n")

        with mock.patch("terok_shield.dns.dnsmasq.reload"):
            harness.mode.deny_domain("test-ctr", TEST_DOMAIN)

        from terok_shield.dns.dnsmasq import read_merged_domains

        assert f"-{TEST_DOMAIN}" in bundle.policy_live.read_text()
        assert TEST_DOMAIN not in read_merged_domains(sd)

    def test_reload_raises_without_upstream_dns(
        self, make_hook_mode: HookModeHarnessFactory
    ) -> None:
        """_reload_dnsmasq() raises when upstream DNS is not persisted."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        StateBundle(sd).ensure_dirs()

        with pytest.raises(RuntimeError, match="upstream DNS not persisted"):
            harness.mode._reload_dnsmasq("test-ctr", sd)

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
        StateBundle(sd).ensure_dirs()
        StateBundle(sd).dns_tier.write_text(f"{tier}\n")

        # Must not raise
        getattr(harness.mode, method_name)("test-ctr", TEST_DOMAIN)
        # And must not have written the runtime overlay
        assert not StateBundle(sd).policy_live.exists()

    def test_allow_domain_passes_when_tier_absent(
        self, make_hook_mode: HookModeHarnessFactory
    ) -> None:
        """allow_domain() proceeds normally when dns_tier file does not exist (pre_start not run)."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        StateBundle(sd).ensure_dirs()
        StateBundle(sd).upstream_dns.write_text("169.254.1.1\n")
        StateBundle(sd).dnsmasq_pid.write_text("12345\n")
        # dns_tier_path NOT written — pre_start has not run

        with mock.patch("terok_shield.dns.dnsmasq.reload"):
            harness.mode.allow_domain("test-ctr", TEST_DOMAIN)

        assert f"+{TEST_DOMAIN}" in StateBundle(sd).policy_live.read_text()


class TestPreStartDnsTierBranches:
    """pre_start() DNS tier branching — dnsmasq vs dig/getent code paths."""

    @mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
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

    @mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
    def test_pre_start_dig_tier_writes_resolv_conf_at_upstream(
        self,
        _has_hooks: mock.Mock,
        monkeypatch: pytest.MonkeyPatch,
        make_hook_mode: HookModeHarnessFactory,
    ) -> None:
        """The dig and getent fallback still owns the container's resolv.conf.

        This guards against #1246. On the AppArmor fallback tiers, shield used
        to remove resolv.conf. The container then used podman's default, which
        lists the host's own nameservers. On a LAN one of those is a router,
        and the egress filter blocks the router as a private range. Shield now
        writes resolv.conf, points it at the forwarder the firewall allows, and
        bind-mounts it on this tier too.
        """
        _set_euid(monkeypatch, 0)
        harness = make_hook_mode()
        harness.runner.run.return_value = _MODERN_PODMAN_INFO
        harness.runner.has.side_effect = lambda name: name != "dnsmasq"  # dig tier
        harness.profiles.compose_profiles.return_value = [TEST_DOMAIN]

        # Seed a stale query log from a prior dnsmasq-tier launch. The fallback
        # must remove it, or `shield watch` shows historical queries after the
        # downgrade.
        sd = harness.config.state_dir.resolve()
        seed = StateBundle(sd)
        seed.ensure_dirs()
        seed.dnsmasq_log.write_text("stale query\n")

        args = harness.mode.pre_start("test", ["dev-standard"])

        # resolv.conf is bind-mounted :ro on the fallback tier too.
        volume_args = [args[i + 1] for i, a in enumerate(args) if a == "--volume"]
        assert any("/etc/resolv.conf:ro,Z" in v for v in volume_args)
        # ...and points at the upstream forwarder (pasta), not the dnsmasq
        # loopback (no dnsmasq here) and not a leaked host nameserver.
        resolv = StateBundle(sd).resolv_conf.read_text()
        assert f"nameserver {PASTA_DNS}" in resolv
        assert "127.0.0.1" not in resolv
        # No dnsmasq artifacts on the fallback tier, including the stale log.
        assert not StateBundle(sd).dnsmasq_conf.exists()
        assert not StateBundle(sd).dnsmasq_log.exists()

    @mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
    def test_pre_start_dnsmasq_tier_skips_pre_resolution(
        self,
        _has_hooks: mock.Mock,
        monkeypatch: pytest.MonkeyPatch,
        make_hook_mode: HookModeHarnessFactory,
    ) -> None:
        """DNSMASQ tier: no pre-resolution — dnsmasq populates the allow sets per query.

        dnsmasq commits every answered A/AAAA record to the sets before
        forwarding the reply, so the workload cannot race its own answer;
        launch stays O(1) in allowlist size.  A stale ``resolved.ips`` from
        an earlier fallback-tier run is removed so the ruleset seeds from
        literal IPs only.
        """
        _set_euid(monkeypatch, 0)
        harness = make_hook_mode()
        harness.runner.run.side_effect = lambda cmd, **_kw: (
            _DNSMASQ_VERSION_NFTSET if Path(cmd[0]).name == "dnsmasq" else _MODERN_PODMAN_INFO
        )
        harness.runner.has.return_value = True  # dnsmasq available (nftset probed via run)
        harness.profiles.compose_profiles.return_value = [TEST_DOMAIN, TEST_IP1]
        sd = harness.config.state_dir.resolve()
        stale_cache = StateBundle(sd)
        stale_cache.ensure_dirs()
        stale_cache.resolved_cache.write_text(f"{TEST_IP2}\n")

        args = harness.mode.pre_start("test", ["dev-standard"])

        # dnsmasq tier: no static resolution, and the stale cache is gone.
        harness.dns.resolve_and_cache.assert_not_called()
        assert not StateBundle(sd).resolved_cache.exists()
        # The composed profiles are written to the project-allow tier (domains
        # included) so dnsmasq's --nftset can add on-demand as new records arrive.
        project_allow = StateBundle(sd).tier_path("project_allow").read_text()
        assert f"+{TEST_DOMAIN}" in project_allow
        # No --dns flag (triggers pasta to bind host port 53, fails rootless).
        # Instead, resolv.conf is pre-written and bind-mounted :ro via --volume.
        assert "--dns" not in args
        assert "--volume" in args
        volume_args = [args[i + 1] for i, a in enumerate(args) if a == "--volume"]
        assert any("/etc/resolv.conf:ro,Z" in v for v in volume_args)
        # The resolv.conf source file exists and points to dnsmasq
        sd = harness.config.state_dir.resolve()
        resolv = StateBundle(sd).resolv_conf
        assert resolv.is_file()
        assert "127.0.0.1" in resolv.read_text()

    @mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
    def test_pre_start_dnsmasq_tier_krun_runtime_uses_link_local_bind(
        self,
        _has_hooks: mock.Mock,
        monkeypatch: pytest.MonkeyPatch,
        make_hook_mode: HookModeHarnessFactory,
        make_config: ConfigFactory,
    ) -> None:
        """Under the krun runtime, dnsmasq binds to the link-local address.

        The microVM guest can't reach netns ``127.0.0.1`` (its own
        loopback is separate from the netns), so shield writes the
        link-local bind into both the dnsmasq config and the
        bind-mounted resolv.conf.  The OCI hook adds the address to
        ``lo`` at createRuntime time.
        """
        _set_euid(monkeypatch, 0)
        harness = make_hook_mode(config=make_config(runtime=ShieldRuntime.KRUN))
        harness.runner.run.side_effect = lambda cmd, **_kw: (
            _DNSMASQ_VERSION_NFTSET if Path(cmd[0]).name == "dnsmasq" else _MODERN_PODMAN_INFO
        )
        harness.runner.has.return_value = True
        harness.profiles.compose_profiles.return_value = [TEST_DOMAIN]

        harness.mode.pre_start("test", ["dev-standard"])

        sd = harness.config.state_dir.resolve()
        resolv = StateBundle(sd).resolv_conf
        assert resolv.is_file()
        assert DNSMASQ_BIND_KRUN in resolv.read_text()
        assert "127.0.0.1" not in resolv.read_text()
        conf = StateBundle(sd).dnsmasq_conf.read_text()
        assert f"listen-address={DNSMASQ_BIND_KRUN}" in conf

    @mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
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
        """deny_domain() records ``-domain`` in the overlay and reloads dnsmasq."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        bundle = StateBundle(sd)
        bundle.ensure_dirs()
        bundle.dns_tier.write_text("dnsmasq\n")
        bundle.write_tier("project_allow", f"+{TEST_DOMAIN}\n")
        bundle.upstream_dns.write_text("169.254.1.1\n")
        bundle.dnsmasq_pid.write_text("12345\n")

        with mock.patch("terok_shield.dns.dnsmasq.reload"):
            harness.mode.deny_domain("test-ctr", TEST_DOMAIN)

        assert f"-{TEST_DOMAIN}" in bundle.policy_live.read_text()

    def test_deny_domain_reloads_on_dnsmasq_tier(
        self, make_hook_mode: HookModeHarnessFactory
    ) -> None:
        """deny_domain() reloads dnsmasq on the dnsmasq tier (no dedup skip)."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        bundle = StateBundle(sd)
        bundle.ensure_dirs()
        bundle.dns_tier.write_text("dnsmasq\n")
        bundle.upstream_dns.write_text("169.254.1.1\n")

        with mock.patch("terok_shield.dns.dnsmasq.reload") as mock_reload:
            harness.mode.deny_domain("test-ctr", TEST_DOMAIN)
        mock_reload.assert_called_once()


class TestContainerRulesetDnsTier:
    """_container_ruleset() uses persisted DNS tier for set_timeout."""

    def test_dnsmasq_tier_enables_set_timeout(self, make_hook_mode: HookModeHarnessFactory) -> None:
        """When dns.tier is 'dnsmasq', RulesetBuilder gets set_timeout."""
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        StateBundle(sd).ensure_dirs()
        StateBundle(sd).upstream_dns.write_text("169.254.1.1\n")
        StateBundle(sd).dns_tier.write_text("dnsmasq\n")

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
        StateBundle(sd).ensure_dirs()
        StateBundle(sd).upstream_dns.write_text("169.254.1.1\n")
        StateBundle(sd).dns_tier.write_text("dig\n")

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
        StateBundle(sd).ensure_dirs()

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
    from terok_shield.hooks.mode import _upstream_dns_for_mode

    with pytest.raises(ValueError, match="Cannot determine upstream DNS"):
        _upstream_dns_for_mode("bridge")


def test_gateways_for_mode_raises_on_unknown_mode() -> None:
    """_gateways_for_mode() raises ValueError for unrecognised network modes."""
    from terok_shield.hooks.mode import _gateways_for_mode

    with pytest.raises(ValueError, match="Cannot determine gateways"):
        _gateways_for_mode("bridge")


@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
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


def test_shield_state_returns_disengaged(make_hook_mode: HookModeHarnessFactory) -> None:
    """shield_state() returns DISENGAGED when the disengaged ruleset is active but not the down one."""
    harness = make_hook_mode()
    harness.runner.nft_via_nsenter.return_value = "some rules"
    # First call (disengaged=False): non-empty errors → not DOWN, continue
    # Second call (disengaged=True): empty list → DISENGAGED
    harness.ruleset.verify_down.side_effect = [["not down"], []]

    assert harness.mode.shield_state("test-ctr") == ShieldState.DISENGAGED


@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
def test_pre_start_with_denied_ips_includes_deny_elements(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start(security_deny=…) writes the t20 tier and it reaches the ruleset."""
    _set_euid(monkeypatch, 0)
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []

    harness.mode.pre_start("test", ["dev-standard"], security_deny=[TEST_IP1])

    bundle = StateBundle(config.state_dir)
    assert f"-{TEST_IP1}" in bundle.tier_path("security_deny").read_text()
    ruleset = bundle.ruleset.read_text()
    assert "t20_security_deny_v4" in ruleset
    assert TEST_IP1 in ruleset


@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
def test_pre_start_writes_generated_provider_allow_tier(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start(provider_allow=…) writes the t30 tier as ``+host`` lines."""
    _set_euid(monkeypatch, 0)
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []

    harness.mode.pre_start("test", ["dev-standard"], provider_allow=[TEST_DOMAIN])

    tier = StateBundle(config.state_dir).tier_path("provider_allow").read_text()
    assert f"+{TEST_DOMAIN}" in tier


@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
def test_pre_start_clears_generated_tiers_when_absent(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start owns t20/t30 — a launch without a projection clears stale content."""
    _set_euid(monkeypatch, 0)
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []
    bundle = StateBundle(config.state_dir)
    bundle.ensure_dirs()
    bundle.write_tier("provider_allow", f"+{TEST_DOMAIN}\n")  # left by a prior launch

    harness.mode.pre_start("test", ["dev-standard"])

    assert bundle.tier_path("provider_allow").read_text() == ""


@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
def test_pre_start_merges_project_allow_into_t40(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start(project_allow=…) merges authored hosts into the t40 project-allow tier."""
    _set_euid(monkeypatch, 0)
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = [TEST_DOMAIN2]

    harness.mode.pre_start("test", ["dev-standard"], project_allow=[TEST_DOMAIN])

    tier = StateBundle(config.state_dir).tier_path("project_allow").read_text()
    assert f"+{TEST_DOMAIN}" in tier  # authored
    assert f"+{TEST_DOMAIN2}" in tier  # composed profile — both land in t40


@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
def test_pre_start_writes_override_tier_and_seeds_t10(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start(override=…) writes t10 and seeds the override nft set (above the deny)."""
    _set_euid(monkeypatch, 0)
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []

    harness.mode.pre_start("test", ["dev-standard"], override=[TEST_IP1])

    bundle = StateBundle(config.state_dir)
    assert f"+{TEST_IP1}" in bundle.tier_path("override").read_text()
    ruleset = bundle.ruleset.read_text()
    assert "t10_override_v4" in ruleset
    assert TEST_IP1 in ruleset


@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
def test_pre_start_statically_resolves_security_deny(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """t20 domains are statically resolved into the deny cache on every DNS tier.

    The deny must hold by *address*: it is what ``shield down`` repopulates
    the deny set from, and dnsmasq interception can never populate a deny.
    The resolved IPs must reach the pre-generated ruleset's deny elements.
    """
    _set_euid(monkeypatch, 0)
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []
    bundle = StateBundle(config.state_dir)

    def _fake_resolve(targets: list[str], cache_path: Path, **_kw: object) -> None:
        if cache_path == bundle.deny_resolved:
            cache_path.write_text(f"{TEST_IP2}\n")

    harness.dns.resolve_and_cache.side_effect = _fake_resolve

    harness.mode.pre_start("test", ["dev-standard"], security_deny=[TEST_DOMAIN])

    deny_calls = [
        c for c in harness.dns.resolve_and_cache.call_args_list if c.args[1] == bundle.deny_resolved
    ]
    assert len(deny_calls) == 1
    assert TEST_DOMAIN in deny_calls[0].args[0]
    ruleset = bundle.ruleset.read_text()
    assert "t20_security_deny_v4" in ruleset
    assert TEST_IP2 in ruleset


@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
def test_pre_start_clears_stale_deny_cache_when_deny_tier_empties(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """An emptied deny tier removes the stale resolved-deny cache."""
    _set_euid(monkeypatch, 0)
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []
    bundle = StateBundle(config.state_dir)
    bundle.ensure_dirs()
    bundle.deny_resolved.write_text(f"{TEST_IP2}\n")  # left by a prior launch

    harness.mode.pre_start("test", ["dev-standard"])

    assert not bundle.deny_resolved.exists()


@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
def test_pre_start_override_range_is_seeded_and_logged(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """A CIDR in the override tier opens the whole range — loudly: warning + audit event."""
    _set_euid(monkeypatch, 0)
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []

    with caplog.at_level(logging.WARNING):
        harness.mode.pre_start("test", ["dev-standard"], override=[BROAD_CIDR_8])

    assert any(BROAD_CIDR_8 in record.message for record in caplog.records)
    harness.audit.log_event.assert_any_call("test", "override_range", detail=BROAD_CIDR_8)
    assert BROAD_CIDR_8 in StateBundle(config.state_dir).ruleset.read_text()


# ── Container ID persistence ─────────────────────────────


@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
def test_pre_start_does_not_inspect_container(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """pre_start() must not call podman inspect (container doesn't exist yet)."""
    _set_euid(monkeypatch, 0)
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []

    harness.mode.pre_start("test", ["dev-standard"])

    harness.runner.podman_inspect.assert_not_called()
    assert not StateBundle(config.state_dir).container_id.exists()


def test_shield_up_repopulates_deny_sets(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """shield_up() repopulates deny sets from deny.list."""
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.runner.nft_via_nsenter.return_value = ""
    harness.ruleset.build_up.return_value = "up ruleset"
    harness.ruleset.verify_up.return_value = []
    harness.ruleset.add_elements_dual.return_value = ""
    harness.ruleset.verify_down.return_value = ["not down"]

    # Write a deny.list
    _b = StateBundle(config.state_dir)
    _b.ensure_dirs()
    _b.write_tier("security_deny", f"-{TEST_IP1}\n")

    harness.mode.shield_up("test-ctr")

    # Verify deny elements were sent via nsenter
    deny_calls = [c for c in harness.runner.nft_via_nsenter.call_args_list if c.kwargs.get("stdin")]
    assert any(TEST_IP1 in (c.kwargs.get("stdin", "") or "") for c in deny_calls)


def test_shield_down_repopulates_deny_sets(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """shield_down() repopulates deny sets from deny.list so denies survive shield-down."""
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.runner.nft_via_nsenter.return_value = ""
    harness.ruleset.build_down.return_value = "down ruleset"
    harness.ruleset.verify_down.return_value = []

    # Write a deny.list before going down
    _b = StateBundle(config.state_dir)
    _b.ensure_dirs()
    _b.write_tier("security_deny", f"-{TEST_IP1}\n")

    harness.mode.shield_down("test-ctr", disengaged=False)

    # Verify deny elements were sent via nsenter
    deny_calls = [c for c in harness.runner.nft_via_nsenter.call_args_list if c.kwargs.get("stdin")]
    assert any(TEST_IP1 in (c.kwargs.get("stdin", "") or "") for c in deny_calls)


@pytest.mark.parametrize("transition", ["up", "down"])
def test_shield_transitions_reseed_override_set(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    transition: str,
) -> None:
    """shield_up()/shield_down() re-seed the t10 override set from the bundle.

    The table rebuild recreates every set empty; without the re-seed a
    break-glass override would silently die (still t20-denied) after one
    down/up cycle and only recover on container re-creation.
    """
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.runner.nft_via_nsenter.return_value = ""
    harness.ruleset.build_up.return_value = "up ruleset"
    harness.ruleset.verify_up.return_value = []
    harness.ruleset.add_elements_dual.return_value = ""
    harness.ruleset.build_down.return_value = "down ruleset"
    harness.ruleset.verify_down.return_value = [] if transition == "down" else ["not down"]

    _b = StateBundle(config.state_dir)
    _b.ensure_dirs()
    _b.write_tier("override", f"+{TEST_IP1}\n")

    getattr(harness.mode, f"shield_{transition}")("test-ctr")

    stdins = [
        c.kwargs.get("stdin", "") or "" for c in harness.runner.nft_via_nsenter.call_args_list
    ]
    assert any("t10_override_v4" in s and TEST_IP1 in s for s in stdins)


@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
def test_refresh_rewrites_tiers_and_ruleset(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """refresh() re-authors an existing bundle — current tier data replaces the frozen one.

    A plain restart replays ``ruleset.nft`` through the OCI hook, so a
    roster/config change between creation and restart must land in the
    regenerated artifacts, not just the tier files.
    """
    _set_euid(monkeypatch, 0)
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []
    harness.mode.pre_start("test", ["dev-standard"], security_deny=[TEST_IP1])

    harness.mode.refresh("test", ["dev-standard"], security_deny=[TEST_IP2])

    bundle = StateBundle(config.state_dir)
    tier = bundle.tier_path("security_deny").read_text()
    assert f"-{TEST_IP2}" in tier
    assert f"-{TEST_IP1}" not in tier
    ruleset = bundle.ruleset.read_text()
    assert TEST_IP2 in ruleset
    assert TEST_IP1 not in ruleset


@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
def test_refresh_override_range_is_logged(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """refresh() logs a CIDR override the way pre_start() does: a warning and an audit event."""
    _set_euid(monkeypatch, 0)
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []
    harness.mode.pre_start("test", ["dev-standard"])
    harness.audit.log_event.reset_mock()

    with caplog.at_level(logging.WARNING):
        harness.mode.refresh("test", ["dev-standard"], override=[BROAD_CIDR_8])

    assert any(BROAD_CIDR_8 in record.message for record in caplog.records)
    harness.audit.log_event.assert_any_call("test", "override_range", detail=BROAD_CIDR_8)
    assert BROAD_CIDR_8 in StateBundle(config.state_dir).ruleset.read_text()


@mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
def test_refresh_reuses_persisted_network_mode(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """refresh() derives its gateways from the bundle, never from a fresh ``podman info``.

    A restart must rebuild for the network mode the container was launched
    with — re-detecting could disagree with the mounts and annotations, and
    would put a ``podman info`` probe on an interactive path.
    """
    _set_euid(monkeypatch, 0)
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []
    harness.mode.pre_start("test", ["dev-standard"])
    assert StateBundle(config.state_dir).network_mode.read_text().strip() == "pasta"
    harness.runner.run.reset_mock()

    harness.mode.refresh("test", ["dev-standard"])

    assert not [c for c in harness.runner.run.call_args_list if "info" in c.args[0]]


def test_refresh_without_prepared_bundle_raises(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """refresh() refuses a state dir pre_start never prepared (no persisted DNS tier)."""
    harness = make_hook_mode(config=make_config())

    with pytest.raises(RuntimeError, match="persisted DNS tier"):
        harness.mode.refresh("test", ["dev-standard"])


from terok_shield.state import StateBundle


def test_detect_dns_tier_audits_advisory_when_apparmor_blocks(
    make_hook_mode: HookModeHarnessFactory, tmp_path: Path
) -> None:
    """_detect_dns_tier falls back and audits the AppArmor advisory when dnsmasq is confined."""
    harness = make_hook_mode()
    harness.runner.has.side_effect = lambda name: name in ("dnsmasq", "dig")

    def _run(cmd: list[str], **_kw: object) -> str:
        if "--version" in cmd:
            return "Dnsmasq version 2.92\nCompile time options: nftset\n"
        if "--test" in cmd:
            raise ExecError(cmd, 3, "dnsmasq: cannot read config: Permission denied\n")
        return ""

    harness.runner.run.side_effect = _run

    tier = harness.mode._detect_dns_tier("some-task", tmp_path)

    assert tier is DnsTier.DIG
    harness.audit.log_event.assert_called_once()
    detail = harness.audit.log_event.call_args.kwargs["detail"]
    assert "AppArmor" in detail
    assert "dig" in detail
