# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the HookMode class."""

import fcntl
import json
import logging
import os
import re
import sys
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from threading import Event, get_ident
from unittest import mock
from urllib.parse import unquote

import pytest
from terok_util import SetupCheck, SetupRequiredError, SetupStatus

from terok_shield.config import (
    ANNOTATION_AUDIT_ENABLED_KEY,
    ANNOTATION_STATE_DIR_KEY,
    DnsTier,
    OverrideRevocation,
    ShieldConfig,
    ShieldReading,
    ShieldRuntime,
    ShieldState,
)
from terok_shield.dns import dnsmasq
from terok_shield.dns.resolver import DnsResolver
from terok_shield.hooks.mode import OVERRIDE_NEEDS_RULESET, WINDOW_NEEDS_UP, HookMode, _covered
from terok_shield.nft.constants import (
    CONTAINER_HOST_ALIAS,
    DNSMASQ_BIND_KRUN,
    PASTA_DNS,
    PASTA_HOST_LOOPBACK_MAP,
)
from terok_shield.nft.rules import RulesetBuilder
from terok_shield.policy import LOCALHOST, expiry_deadline
from terok_shield.run import ExecError, ShieldNeedsSetup
from terok_shield.state import SecurityTierRefusal, StateBundle, read_name_resolution

from ..testfs import DNSMASQ_SBIN
from ..testnet import (
    ANY_IPV4,
    ANY_IPV6,
    AWS_IMDS_V4,
    BROAD_CIDR_8,
    CONTAINER_HOSTNAME,
    DOCKER_HOSTNAME,
    IPV6_CLOUDFLARE,
    IPV6_VERBOSE,
    IPV6_VERBOSE_CANONICAL,
    KRUN_DNSMASQ_BIND,
    LOCALHOST_GRANT,
    LOCALHOST_GRANT_PORT,
    RFC1918_CIDR_10,
    SLIRP4NETNS_DNS,
    SLIRP4NETNS_GATEWAY,
    SLIRP4NETNS_GATEWAY_V6,
    TEST_CUSTOM_CIDR_192,
    TEST_CUSTOM_GATEWAY_192,
    TEST_DOMAIN,
    TEST_DOMAIN2,
    TEST_IP1,
    TEST_IP2,
    TEST_IP3,
    TEST_IP4,
    TEST_NET1,
    TEST_NET1_HOST,
    VAULT_HOST,
    VAULT_SUBDOMAIN,
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
_DNSMASQ_VERSION_NO_NFTSET = _DNSMASQ_VERSION_NFTSET.replace(" nftset ", " no-nftset ")

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


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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
    assert f"{DOCKER_HOSTNAME}:{PASTA_HOST_LOOPBACK_MAP}" in args


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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

    assert not (config.state_dir / "hooks").exists()
    assert not (config.state_dir / "terok-shield-hook").exists()


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
@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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


@pytest.mark.parametrize("audit_enabled", [True, False], ids=["audit-on", "audit-off"])
@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
def test_pre_start_records_the_audit_flag_in_the_bundle(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    audit_enabled: bool,
) -> None:
    """The NFLOG reader reads no config: the creation-time audit choice reaches it in the bundle.

    The bundle flag and the annotation carry the same value, so the reader
    and anything reading the annotation never disagree.
    """
    _set_euid(monkeypatch, 0)
    harness = make_hook_mode(config=make_config(audit_enabled=audit_enabled))
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []

    args = harness.mode.pre_start("test", ["dev-standard"])

    bundle = StateBundle(harness.config.state_dir)
    assert bundle.read_audit_enabled() is audit_enabled
    assert bundle.audit_flag.read_text().strip() == _annotation_value(
        args, ANNOTATION_AUDIT_ENABLED_KEY
    )


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
    StateBundle(sd).dns_tier.write_text(f"{DnsTier.DNSMASQ_LIVE.value}\n")

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
    StateBundle(sd).dns_tier.write_text(f"{DnsTier.LOOKUP.value}\n")

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


def _deny_set_deletes(runner: mock.MagicMock) -> list[tuple[str, ...]]:
    """Every nft call that deletes an element from a t20 deny set."""
    return [
        c.args
        for c in runner.nft_via_nsenter.call_args_list
        if "delete" in c.args and any("t20_security_deny" in str(a) for a in c.args)
    ]


def _security_tier(state_dir: Path, *, tier: DnsTier = DnsTier.DNSMASQ_LIVE) -> StateBundle:
    """A launched bundle whose security tier denies VAULT_HOST, resolved at launch to TEST_IP1."""
    bundle = _launched(state_dir.resolve(), tier)
    bundle.write_tier("security_deny", f"-{VAULT_HOST}\n-{TEST_IP2}\n")
    bundle.deny_resolved.write_text(f"{VAULT_HOST} {TEST_IP1}\n")
    return bundle


@pytest.mark.parametrize(
    "ip",
    [pytest.param(TEST_IP1, id="resolved-vault-address"), pytest.param(TEST_IP2, id="literal")],
)
def test_allow_ip_refuses_a_security_tier_address_and_lifts_no_deny(
    make_hook_mode: HookModeHarnessFactory, ip: str
) -> None:
    """A vault address is refused at the API itself — never deleted from the live t20 set.

    The hole this closes: the old un-deny dropped *any* denied address from
    the deny set, so a live allow of a vault host punched through t20 until
    the next rebuild, while the persisted policy still denied it.
    """
    harness = make_hook_mode()
    bundle = _security_tier(harness.config.state_dir)

    with pytest.raises(SecurityTierRefusal) as ctx:
        harness.mode.allow_ip("test-ctr", ip)

    assert ctx.value.address == ip
    harness.runner.nft_via_nsenter.assert_not_called()
    assert not bundle.policy_live.exists()
    assert ip in bundle.read_denied_ips()


def test_allow_ip_lifts_the_operators_own_deny_from_the_deny_set(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """A runtime deny is the operator's: allowing it again deletes it from t20 and flips it."""
    harness = make_hook_mode()
    bundle = _security_tier(harness.config.state_dir)
    bundle.overlay_set("-", TEST_IP3)

    harness.mode.allow_ip("test-ctr", TEST_IP3)

    (delete,) = _deny_set_deletes(harness.runner)
    assert "t20_security_deny_v4" in delete
    assert TEST_IP3 in delete
    assert TEST_IP3 not in bundle.read_denied_ips()
    assert f"+{TEST_IP3}" in bundle.policy_live.read_text()


def test_allow_ip_lifts_an_address_the_overlays_denied_name_resolved_to(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """An address a runtime-denied name resolved to is the operator's deny too, and liftable."""
    harness = make_hook_mode()
    bundle = _security_tier(harness.config.state_dir)
    bundle.overlay_set("-", TEST_DOMAIN2)
    bundle.live_deny_resolved.write_text(f"{TEST_IP4}\n")

    harness.mode.allow_ip("test-ctr", TEST_IP4)

    assert len(_deny_set_deletes(harness.runner)) == 1


def test_allow_ip_leaves_the_deny_set_alone_for_an_address_nobody_denied(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """Nothing to lift: the allow only adds to t40."""
    harness = make_hook_mode()
    _security_tier(harness.config.state_dir)

    harness.mode.allow_ip("test-ctr", TEST_IP3)

    assert _deny_set_deletes(harness.runner) == []


@pytest.mark.parametrize(
    ("target", "ips", "entry"),
    [
        pytest.param(VAULT_HOST, [], VAULT_HOST, id="by-name"),
        pytest.param(VAULT_SUBDOMAIN, [TEST_IP3], VAULT_HOST, id="by-suffix"),
        pytest.param(TEST_DOMAIN, [TEST_IP3, TEST_IP1], TEST_IP1, id="by-shared-address"),
    ],
)
def test_check_security_tier_refuses_by_name_suffix_and_address(
    make_hook_mode: HookModeHarnessFactory, target: str, ips: list[str], entry: str
) -> None:
    """The whole target is checked before anything changes, every resolved address included."""
    harness = make_hook_mode()
    _security_tier(harness.config.state_dir)

    with pytest.raises(SecurityTierRefusal) as ctx:
        harness.mode.check_security_tier(target, ips)

    assert ctx.value.entry == entry
    harness.runner.nft_via_nsenter.assert_not_called()


@pytest.mark.parametrize(
    ("tier", "refused"),
    [
        pytest.param(DnsTier.LOOKUP, True, id="lookup-re-resolves"),
        pytest.param(DnsTier.GETENT, True, id="getent-re-resolves"),
        pytest.param(DnsTier.DNSMASQ_LIVE, False, id="dnsmasq-sinkholes-the-name"),
        pytest.param(DnsTier.DNSMASQ_STATIC, False, id="dnsmasq-static-too"),
    ],
)
def test_check_security_tier_catches_a_rotated_vault_address_where_nothing_sinkholes_it(
    make_hook_mode: HookModeHarnessFactory, tier: DnsTier, refused: bool
) -> None:
    """Without dnsmasq the security names are re-resolved, so a rotated address is still refused.

    On those tiers a vault host's new address reaches the operator as a bare,
    unattributed refusal; the launch-time cache alone would wave it through.
    """
    harness = make_hook_mode()
    _security_tier(harness.config.state_dir, tier=tier)
    harness.dns.resolve_domains.return_value = [TEST_IP4]  # the address it rotated to

    if refused:
        with pytest.raises(SecurityTierRefusal, match=TEST_IP4):
            harness.mode.check_security_tier(TEST_IP4, [TEST_IP4])
        harness.dns.resolve_domains.assert_called_once_with([VAULT_HOST], quiet=True)
    else:
        harness.mode.check_security_tier(TEST_IP4, [TEST_IP4])
        harness.dns.resolve_domains.assert_not_called()


def test_check_security_tier_lets_an_unrelated_target_through(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """A target the tier does not refuse passes silently."""
    harness = make_hook_mode()
    _security_tier(harness.config.state_dir, tier=DnsTier.LOOKUP)
    harness.dns.resolve_domains.return_value = [TEST_IP1]

    harness.mode.check_security_tier(TEST_DOMAIN, [TEST_IP3])


def test_allow_offline_records_the_target_for_the_next_start_without_nft(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """A stopped container takes the grant in its overlay; nothing reaches nft."""
    harness = make_hook_mode()
    bundle = _security_tier(harness.config.state_dir)

    harness.mode.allow_offline(TEST_DOMAIN)

    assert f"+{TEST_DOMAIN}" in bundle.policy_live.read_text().splitlines()
    assert TEST_DOMAIN in bundle.read_effective().allow_targets()
    harness.runner.nft_via_nsenter.assert_not_called()


def test_allow_offline_flips_a_prior_deny_of_the_same_address(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """An IP is normalized first, so it flips the deny ``deny_ip`` recorded canonically."""
    harness = make_hook_mode()
    bundle = _security_tier(harness.config.state_dir)
    bundle.overlay_set("-", IPV6_VERBOSE_CANONICAL)

    harness.mode.allow_offline(IPV6_VERBOSE)

    assert bundle.policy_live.read_text().splitlines() == [f"+{IPV6_VERBOSE_CANONICAL}"]


def test_allow_offline_refuses_a_bundle_no_launch_prepared(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """No start would ever read that overlay — a mistyped container must not look like success."""
    harness = make_hook_mode()
    bundle = StateBundle(harness.config.state_dir.resolve())

    with pytest.raises(RuntimeError, match="pre_start never completed"):
        harness.mode.allow_offline(TEST_DOMAIN)

    assert not bundle.policy_live.exists()


def test_allow_offline_refuses_a_security_host(make_hook_mode: HookModeHarnessFactory) -> None:
    """The overlay is no way around the security tier either."""
    harness = make_hook_mode()
    bundle = _security_tier(harness.config.state_dir)

    with pytest.raises(SecurityTierRefusal):
        harness.mode.allow_offline(VAULT_SUBDOMAIN)

    assert not bundle.policy_live.exists()


@pytest.mark.parametrize("fact", ["upstream_dns", "network_mode"])
def test_allow_offline_refuses_a_bundle_missing_a_launch_fact(
    make_hook_mode: HookModeHarnessFactory, fact: str
) -> None:
    """The rewrite reads every launch-time fact from the bundle; without one, nothing is recorded."""
    harness = make_hook_mode()
    bundle = _security_tier(harness.config.state_dir)
    getattr(bundle, fact).unlink()

    with pytest.raises(RuntimeError, match="pre_start never completed"):
        harness.mode.allow_offline(TEST_DOMAIN)

    assert not bundle.policy_live.exists()


def test_allow_offline_rewrites_the_ruleset_the_next_start_replays(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """The OCI hook replays ruleset.nft as it stands, so the grant must be in it before the start.

    On a tier that pins names the domain resolves now and seeds the rewritten
    ruleset: a plain ``podman start`` applies the allow, with nobody
    re-authoring the bundle first.
    """
    harness = make_hook_mode()
    bundle = _security_tier(harness.config.state_dir, tier=DnsTier.LOOKUP)

    def _resolve(targets: list[str], cache: Path, **_kw: object) -> list[str]:
        cache.write_text(f"{TEST_IP3}\n")
        return [TEST_IP3]

    harness.dns.resolve_and_cache.side_effect = _resolve

    harness.mode.allow_offline(TEST_DOMAIN)

    (allow_call,) = harness.dns.resolve_and_cache.call_args_list
    assert TEST_DOMAIN in allow_call.args[0]
    assert TEST_IP3 in bundle.ruleset.read_text()
    harness.runner.nft_via_nsenter.assert_not_called()


def test_allow_offline_rewrites_the_dnsmasq_config_where_it_listens(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """The live tier learns the name per query, so the config needs its nftset line before the start.

    The listen address and query logging come off the config being replaced,
    never off the caller's: the CLI holds a default config, and a krun
    container's dnsmasq listens on a link-local address its guest can reach.
    """
    harness = make_hook_mode()
    bundle = _security_tier(harness.config.state_dir, tier=DnsTier.DNSMASQ_LIVE)
    bundle.dnsmasq_conf.write_text(f"listen-address={KRUN_DNSMASQ_BIND}\nlog-queries\n")

    harness.mode.allow_offline(TEST_DOMAIN)

    conf = bundle.dnsmasq_conf.read_text().splitlines()
    assert f"listen-address={KRUN_DNSMASQ_BIND}" in conf
    assert "log-queries" in conf
    assert any(line.startswith(f"nftset=/{TEST_DOMAIN}/") for line in conf)
    harness.runner.nft_via_nsenter.assert_not_called()


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


@pytest.mark.parametrize("down", [False, True], ids=["up", "down"])
def test_preview_composes_profiles_into_the_live_tier_ruleset(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    down: bool,
) -> None:
    """preview(profiles=…) is the ruleset the hook applies for those profiles — without any state.

    The profiles' ``+localhost:PORT`` grants join the preamble next to the
    config's own ports, their literal IPs seed the t40 set, and their
    domains are absent: the live tier learns those per query, so the
    preview approximates nothing.  Nothing is resolved, inspected or written.
    """
    config = make_config(loopback_ports=(8080,))
    harness = make_hook_mode(config=config, ruleset=RulesetBuilder(loopback_ports=(8080,)))
    harness.profiles.compose_profiles.return_value = [LOCALHOST_GRANT, TEST_IP1, TEST_DOMAIN]

    ruleset = harness.mode.preview(down=down, profiles=["llm"])

    harness.profiles.compose_profiles.assert_called_once_with(["llm"])
    assert f"tcp dport 8080 ip daddr {PASTA_HOST_LOOPBACK_MAP} accept" in ruleset
    assert f"tcp dport {LOCALHOST_GRANT_PORT} ip daddr {PASTA_HOST_LOOPBACK_MAP} accept" in ruleset
    assert f"add element inet terok_shield t40_project_allow_v4 {{ {TEST_IP1} }}" in ruleset
    assert TEST_DOMAIN not in ruleset
    assert ("policy accept" in ruleset) is down
    harness.runner.run.assert_not_called()
    harness.dns.resolve_and_cache.assert_not_called()
    assert not StateBundle(config.state_dir).ruleset.exists()


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


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
def test_pre_start_opens_a_profile_localhost_grant_in_the_preamble(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """A profile's ``+localhost:PORT`` grant lands as a preamble accept on the host-loopback map.

    The grant is authored into t40 like any other entry, but its port is
    served from the preamble — above the link-local hard-deny — exactly as
    the supervisor's own ``ShieldConfig.loopback_ports`` are.
    """
    _set_euid(monkeypatch, 0)
    config = make_config(loopback_ports=(8080,))
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = [LOCALHOST_GRANT]

    harness.mode.pre_start("test", ["llm"])

    bundle = StateBundle(config.state_dir)
    assert f"+{LOCALHOST_GRANT}" in bundle.tier_path("project_allow").read_text()
    ruleset = bundle.ruleset.read_text()
    assert f"tcp dport 8080 ip daddr {PASTA_HOST_LOOPBACK_MAP} accept" in ruleset
    assert f"tcp dport {LOCALHOST_GRANT_PORT} ip daddr {PASTA_HOST_LOOPBACK_MAP} accept" in ruleset


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
    monkeypatch.setattr("terok_shield.hooks.install.find_host_tool", lambda name: name)
    HooksInstaller(target_dir=target).install()

    # Shared ballast lands once — both role scripts import from it.
    assert (target / "_oci_state.py").is_file()

    # nft role: script + JSON pair.
    assert (target / "terok-shield-hook").is_file()
    assert (target / "terok-shield-hook").stat().st_mode & 0o100
    assert (target / "terok-shield-createRuntime.json").is_file()
    assert (target / "terok-shield-poststop.json").is_file()
    nft = json.loads((target / "terok-shield-createRuntime.json").read_text())
    assert nft["hook"]["path"] == sys.executable
    assert nft["hook"]["args"] == [
        sys.executable,
        "-I",
        str(target / "terok-shield-hook"),
        "createRuntime",
    ]

    # Reader role: own script + own JSON pair (no shared ``--bridge`` flag now).
    assert (target / "terok-shield-bridge-hook").is_file()
    assert (target / "terok-shield-bridge-hook").stat().st_mode & 0o100
    assert (target / "terok-shield-bridge-createRuntime.json").is_file()
    assert (target / "terok-shield-bridge-poststop.json").is_file()
    bridge = json.loads((target / "terok-shield-bridge-createRuntime.json").read_text())
    assert bridge["hook"]["path"] == sys.executable
    assert bridge["hook"]["args"] == [
        sys.executable,
        "-I",
        str(target / "terok-shield-bridge-hook"),
        "createRuntime",
    ]

    # NFLOG reader resource lands at the canonical XDG path.
    reader = tmp_path / "share" / "terok" / "shield" / "nflog-reader.py"
    assert reader.is_file()
    assert reader.stat().st_mode & 0o100


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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
    assert f"{DOCKER_HOSTNAME}:{SLIRP4NETNS_GATEWAY}" in args
    # The gateways the container launches with are recorded for every later reader.
    bundle = StateBundle(harness.config.state_dir)
    assert bundle.read_gateways() == (SLIRP4NETNS_GATEWAY, SLIRP4NETNS_GATEWAY_V6)


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

    with mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=()):
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

    _set_euid(monkeypatch, 0)
    harness = make_hook_mode(config=make_config())
    harness.runner.run.return_value = json.dumps(
        {
            "host": {},
            "version": {"Version": "5.8.0"},
        }
    )
    harness.profiles.compose_profiles.return_value = []

    with mock.patch(
        "terok_shield.hooks.mode.HooksInstaller.check_setup",
        return_value=(SetupCheck("terok-shield", "hooks", SetupStatus.MISSING),),
    ):
        with pytest.raises(SetupRequiredError, match="Run setup"):
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


def test_read_container_dns_raises_on_missing_cat(
    make_hook_mode: HookModeHarnessFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing host cat uses the normal DNS-read failure without launching it."""
    harness = make_hook_mode()
    monkeypatch.setattr("terok_shield.hooks.mode.find_host_tool", lambda _name: None)
    with pytest.raises(RuntimeError, match="Cannot determine DNS"):
        harness.mode._read_container_dns("test-ctr")
    harness.runner.run.assert_not_called()


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
        StateBundle(sd).dns_tier.write_text(f"{DnsTier.DNSMASQ_LIVE.value}\n")
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
            pytest.param("allow_domain", DnsTier.LOOKUP, id="allow-lookup"),
            pytest.param("allow_domain", DnsTier.GETENT, id="allow-getent"),
            pytest.param("deny_domain", DnsTier.LOOKUP, id="deny-lookup"),
            pytest.param("deny_domain", DnsTier.GETENT, id="deny-getent"),
        ],
    )
    def test_domain_method_is_noop_for_non_dnsmasq_tier(
        self, method_name: str, tier: DnsTier, make_hook_mode: HookModeHarnessFactory
    ) -> None:
        """allow_domain() and deny_domain() are silent no-ops on a tier without dnsmasq.

        The static IP-level allow/deny already ran via allow_ip()/deny_ip(); there
        is no dnsmasq to reload on the lookup and getent tiers.
        """
        harness = make_hook_mode()
        sd = harness.config.state_dir.resolve()
        StateBundle(sd).ensure_dirs()
        StateBundle(sd).dns_tier.write_text(f"{tier.value}\n")

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

    @mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
    def test_pre_start_dig_tier_resolves_all_entries(
        self,
        _has_hooks: mock.Mock,
        monkeypatch: pytest.MonkeyPatch,
        make_hook_mode: HookModeHarnessFactory,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """When tier is DIG, pre_start resolves all entries (domains + IPs) to cache and says why."""
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
        # The operator learns which tier runs and what restores the live one.
        assert DnsTier.LOOKUP.hint in capsys.readouterr().err

    @mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
    def test_pre_start_refuses_wildcards_on_a_static_tier(
        self,
        _has_hooks: mock.Mock,
        monkeypatch: pytest.MonkeyPatch,
        make_hook_mode: HookModeHarnessFactory,
    ) -> None:
        """A ``*.`` entry stops a static-tier launch before anything resolves, naming the entry."""
        _set_euid(monkeypatch, 0)
        harness = make_hook_mode()
        harness.runner.run.return_value = _MODERN_PODMAN_INFO
        harness.runner.has.side_effect = lambda name: name != "dnsmasq"
        harness.profiles.compose_profiles.return_value = [f"*.{TEST_DOMAIN}"]

        with pytest.raises(ShieldNeedsSetup, match=rf"lookup tier: \*\.{TEST_DOMAIN}"):
            harness.mode.pre_start("test", ["dev-standard"])

        harness.dns.resolve_and_cache.assert_not_called()

    @mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
    def test_pre_start_records_and_probes_the_configured_dnsmasq(
        self,
        _has_hooks: mock.Mock,
        monkeypatch: pytest.MonkeyPatch,
        make_hook_mode: HookModeHarnessFactory,
        make_config: ConfigFactory,
        tmp_path: Path,
    ) -> None:
        """A configured binary is the one every probe runs and the one the bundle records."""
        _set_euid(monkeypatch, 0)
        binary = tmp_path / "dnsmasq-nftset"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        harness = make_hook_mode(config=make_config(dnsmasq_path=binary))
        recorded = str(binary.resolve())
        harness.runner.run.side_effect = lambda cmd, **_kw: (
            _DNSMASQ_VERSION_NFTSET if cmd[0] == recorded else _MODERN_PODMAN_INFO
        )
        harness.profiles.compose_profiles.return_value = [TEST_DOMAIN]

        harness.mode.pre_start("test", ["dev-standard"])

        sd = harness.config.state_dir.resolve()
        assert StateBundle(sd).dnsmasq_command.read_text().strip() == recorded
        assert StateBundle(sd).read_dns_tier() is DnsTier.DNSMASQ_LIVE
        probes = [c.args[0] for c in harness.runner.run.call_args_list if c.args[0][0] != "podman"]
        assert probes
        assert all(cmd[0] == recorded for cmd in probes)
        harness.runner.has.assert_not_called()

    @mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
    def test_pre_start_refuses_a_configured_dnsmasq_that_is_missing(
        self,
        _has_hooks: mock.Mock,
        monkeypatch: pytest.MonkeyPatch,
        make_hook_mode: HookModeHarnessFactory,
        make_config: ConfigFactory,
        tmp_path: Path,
    ) -> None:
        """A configured path that does not exist stops the launch and is named."""
        _set_euid(monkeypatch, 0)
        missing = tmp_path / "dnsmasq-missing"
        harness = make_hook_mode(config=make_config(dnsmasq_path=missing))
        harness.runner.run.return_value = _MODERN_PODMAN_INFO

        with pytest.raises(ShieldNeedsSetup, match=str(missing)):
            harness.mode.pre_start("test", ["dev-standard"])

    @mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
    def test_pre_start_without_nftset_runs_dnsmasq_and_resolves_once(
        self,
        _has_hooks: mock.Mock,
        monkeypatch: pytest.MonkeyPatch,
        make_hook_mode: HookModeHarnessFactory,
    ) -> None:
        """A dnsmasq built without nftset serves the container's DNS while the sets are static."""
        _set_euid(monkeypatch, 0)
        harness = make_hook_mode()
        harness.runner.run.side_effect = lambda cmd, **_kw: (
            _DNSMASQ_VERSION_NO_NFTSET if Path(cmd[0]).name == "dnsmasq" else _MODERN_PODMAN_INFO
        )
        harness.runner.has.return_value = True
        harness.profiles.compose_profiles.return_value = [TEST_DOMAIN]

        harness.mode.pre_start("test", ["dev-standard"])

        sd = harness.config.state_dir.resolve()
        bundle = StateBundle(sd)
        assert bundle.read_dns_tier() is DnsTier.DNSMASQ_STATIC
        harness.dns.resolve_and_cache.assert_called_once()
        assert "nftset=" not in bundle.dnsmasq_conf.read_text()
        assert "127.0.0.1" in bundle.resolv_conf.read_text()

    @mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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

    @mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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

    @mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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

    @mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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
        bundle.dns_tier.write_text(f"{DnsTier.DNSMASQ_LIVE.value}\n")
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
        bundle.dns_tier.write_text(f"{DnsTier.DNSMASQ_LIVE.value}\n")
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
        StateBundle(sd).dns_tier.write_text(f"{DnsTier.DNSMASQ_LIVE.value}\n")

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
        StateBundle(sd).dns_tier.write_text(f"{DnsTier.LOOKUP.value}\n")

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


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
def test_pre_start_never_writes_per_task_hooks(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """Even future Podman versions use setup-installed global hooks."""
    _set_euid(monkeypatch, 1000)
    harness = make_hook_mode(config=make_config())
    # Do not infer hypothetical hook behavior from a version number.
    harness.runner.run.return_value = json.dumps(
        {"host": {"rootlessNetworkCmd": "pasta"}, "version": {"Version": "99.0.0"}}
    )
    harness.profiles.compose_profiles.return_value = []

    args = harness.mode.pre_start("test", ["dev-standard"])

    assert "--hooks-dir" not in args


def test_shield_state_returns_disengaged(make_hook_mode: HookModeHarnessFactory) -> None:
    """shield_state() returns DISENGAGED when the disengaged ruleset is active but not the down one."""
    harness = make_hook_mode()
    harness.runner.nft_via_nsenter.return_value = "some rules"
    # First call (disengaged=False): non-empty errors → not DOWN, continue
    # Second call (disengaged=True): empty list → DISENGAGED
    harness.ruleset.verify_down.side_effect = [["not down"], []]

    assert harness.mode.shield_state("test-ctr") == ShieldState.DISENGAGED


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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

    def _fake_resolve(names: list[str], cache_path: Path, **_kw: object) -> None:
        if cache_path == bundle.deny_resolved:
            cache_path.write_text(f"{TEST_DOMAIN} {TEST_IP2}\n")

    harness.dns.resolve_names_and_cache.side_effect = _fake_resolve

    harness.mode.pre_start("test", ["dev-standard"], security_deny=[TEST_DOMAIN, TEST_IP3])

    deny_calls = [
        c
        for c in harness.dns.resolve_names_and_cache.call_args_list
        if c.args[1] == bundle.deny_resolved
    ]
    assert len(deny_calls) == 1
    # Names only — a literal reaches the set from the tier — and a name that
    # answers nothing at a later refresh keeps the addresses it had.
    assert deny_calls[0].args[0] == [TEST_DOMAIN]
    assert deny_calls[0].kwargs["keep_unanswered"] is True
    ruleset = bundle.ruleset.read_text()
    assert "t20_security_deny_v4" in ruleset
    assert TEST_IP2 in ruleset


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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

    # The table and its deny elements become visible in the same transaction.
    transactions = [stdin for stdin in _stdins(harness) if stdin]
    assert len(transactions) == 1
    assert "down ruleset" in transactions[0]
    assert TEST_IP1 in transactions[0]


@pytest.mark.parametrize("initial", [ShieldState.UP, ShieldState.OFFLINE])
def test_shield_down_installs_both_deny_families_and_override_atomically(
    make_hook_mode: HookModeHarnessFactory, initial: ShieldState
) -> None:
    """Every accepting table publication already contains its mandatory denies."""
    harness = make_hook_mode()
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.runner.nft_via_nsenter.return_value = ""
    harness.ruleset.build_down.return_value = "down ruleset"
    harness.ruleset.verify_down.return_value = []
    bundle = StateBundle(harness.config.state_dir)
    bundle.ensure_dirs()
    bundle.write_tier("security_deny", f"-{TEST_IP1}\n-{IPV6_CLOUDFLARE}\n")
    bundle.write_tier("override", f"+{TEST_IP2}\n")

    with mock.patch.object(HookMode, "shield_state", return_value=initial):
        harness.mode.shield_down("test-ctr")

    (transaction,) = [stdin for stdin in _stdins(harness) if stdin]
    assert ("delete table" in transaction) is (initial != ShieldState.OFFLINE)
    assert "down ruleset" in transaction
    assert f"t20_security_deny_v4 {{ {TEST_IP1}" in transaction
    assert f"t20_security_deny_v6 {{ {IPV6_CLOUDFLARE}" in transaction
    assert f"t10_override_v4 {{ {TEST_IP2}" in transaction


def test_shield_down_cannot_publish_without_reading_deny_seed(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """An unreadable policy prevents the accepting transaction from being sent."""
    harness = make_hook_mode()
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.ruleset.build_down.return_value = "down ruleset"
    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.OFFLINE),
        mock.patch.object(StateBundle, "read_denied_ips", side_effect=OSError("unreadable")),
        pytest.raises(OSError, match="unreadable"),
    ):
        harness.mode.shield_down("test-ctr")
    assert _stdins(harness) == []


def test_shield_down_failed_transaction_does_not_attempt_later_seed(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """An nft failure leaves no later accepting-table or seed transaction to run."""
    harness = make_hook_mode()
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.ruleset.build_down.return_value = "down ruleset"
    harness.runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "rejected")
    bundle = StateBundle(harness.config.state_dir)
    bundle.ensure_dirs()
    bundle.write_tier("security_deny", f"-{TEST_IP1}\n")
    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.OFFLINE),
        pytest.raises(ExecError),
    ):
        harness.mode.shield_down("test-ctr")
    (transaction,) = _stdins(harness)
    assert "down ruleset" in transaction
    assert TEST_IP1 in transaction


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


def test_disengaged_reseeds_the_override_but_no_deny_set(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """DISENGAGED tags break-glass traffic ``ALLOWED``, so it needs t10 — and no t20.

    Without the override set, a host the operator broke glass for would land
    in the ``DOWN`` catch-all's records as if UP would have refused it; the
    deny set, which DISENGAGED does not reference, stays empty for the next
    ``shield up`` to repopulate.
    """
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.runner.nft_via_nsenter.return_value = ""
    harness.ruleset.build_down.return_value = "down ruleset"
    harness.ruleset.verify_down.return_value = []

    bundle = StateBundle(config.state_dir)
    bundle.ensure_dirs()
    bundle.write_tier("override", f"+{TEST_IP1}\n")
    bundle.write_tier("security_deny", f"-{TEST_IP2}\n")

    harness.mode.shield_down("test-ctr", disengaged=True)

    stdins = [
        c.kwargs.get("stdin", "") or "" for c in harness.runner.nft_via_nsenter.call_args_list
    ]
    assert any("t10_override_v4" in s and TEST_IP1 in s for s in stdins)
    assert not any("t20_security_deny" in s for s in stdins)


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
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


@mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
def test_refresh_accepts_a_bundle_written_under_the_retired_tier_name(
    _has_hooks: mock.Mock,
    monkeypatch: pytest.MonkeyPatch,
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """A container launched before the tier rename still restarts.

    Its bundle records ``dig``.  Read as a raw value that has to be a
    ``DnsTier``, that aborts the restart with a ValueError naming an enum;
    read through the bundle, it is the ``lookup`` tier it always was.
    """
    _set_euid(monkeypatch, 0)
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO
    harness.profiles.compose_profiles.return_value = []
    harness.mode.pre_start("test", ["dev-standard"])
    StateBundle(config.state_dir).dns_tier.write_text("dig\n")

    harness.mode.refresh("test", ["dev-standard"])


def test_refresh_without_prepared_bundle_raises(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
) -> None:
    """refresh() refuses a state dir pre_start never prepared (no persisted DNS tier)."""
    harness = make_hook_mode(config=make_config())

    with pytest.raises(RuntimeError, match="persisted DNS tier"):
        harness.mode.refresh("test", ["dev-standard"])


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

    tier = harness.mode._detect_dns_tier("some-task", tmp_path, DNSMASQ_SBIN)

    assert tier is DnsTier.LOOKUP
    harness.audit.log_event.assert_called_once()
    detail = harness.audit.log_event.call_args.kwargs["detail"]
    assert "AppArmor" in detail


# ── resolve() ────────────────────────────────────────────────────────────


def _authored_bundle(state_dir: Path, tier: DnsTier) -> StateBundle:
    """A bundle as a launch leaves it: a DNS tier and one domain in each resolved tier."""
    bundle = StateBundle(state_dir)
    bundle.ensure_dirs()
    bundle.dns_tier.write_text(f"{tier.value}\n")
    bundle.write_tier("project_allow", f"+{TEST_DOMAIN}\n")
    bundle.write_tier("override", f"+{TEST_DOMAIN2}\n")
    bundle.write_tier("security_deny", f"-{CONTAINER_HOSTNAME}\n")
    return bundle


def test_resolve_needs_a_launched_bundle(make_hook_mode: HookModeHarnessFactory) -> None:
    """Without the DNS tier pre_start persists, resolve() has nothing to resolve against."""
    mode = make_hook_mode().mode
    with pytest.raises(RuntimeError, match="no persisted DNS tier"):
        mode.resolve()


@pytest.mark.parametrize("force", [False, True], ids=["fresh-cache", "force"])
def test_resolve_refreshes_every_cache_and_rewrites_no_tier(
    make_hook_mode: HookModeHarnessFactory, force: bool
) -> None:
    """On a static tier, resolve() re-resolves allow, override and deny; the authored tiers stay."""
    harness = make_hook_mode()
    bundle = _authored_bundle(harness.config.state_dir.resolve(), DnsTier.GETENT)
    tiers = ("project_allow", "override", "security_deny")
    authored = {tier: bundle.tier_path(tier).read_text() for tier in tiers}
    harness.dns.resolve_and_cache.return_value = [TEST_IP1]

    assert harness.mode.resolve(force=force) == [TEST_IP1]

    calls = harness.dns.resolve_and_cache.call_args_list
    assert [c.args[1] for c in calls] == [bundle.resolved_cache]
    assert {c.kwargs["force"] for c in calls} == {force}
    # The override and deny names resolve one by one, into caches that keep
    # them apart; both keep a name's addresses when it goes silent.
    named = harness.dns.resolve_names_and_cache.call_args_list
    assert [(c.args[0], c.args[1]) for c in named] == [
        ([TEST_DOMAIN2], bundle.override_resolved),
        ([CONTAINER_HOSTNAME], bundle.deny_resolved),
    ]
    assert {c.kwargs["force"] for c in named} == {force}
    assert {c.kwargs["source_mtime"] for c in named} == {bundle.policy_mtime()}
    assert [c.kwargs.get("keep_unanswered", False) for c in named] == [True, True]
    assert {tier: bundle.tier_path(tier).read_text() for tier in tiers} == authored


def test_resolve_keeps_the_overlays_denied_names_apart_from_the_security_tier(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """Security names and runtime-denied names resolve into separate caches.

    Both still seed t20, but only the security tier's addresses are refused
    to a live allow; the operator's own denies stay theirs to lift.
    """
    harness = make_hook_mode()
    bundle = _authored_bundle(harness.config.state_dir.resolve(), DnsTier.DNSMASQ_LIVE)
    bundle.overlay_set("-", TEST_DOMAIN2)
    bundle.overlay_set("-", TEST_IP3)

    harness.mode.resolve()

    targets = {c.args[1]: c.args[0] for c in harness.dns.resolve_names_and_cache.call_args_list}
    assert targets[bundle.deny_resolved] == [CONTAINER_HOSTNAME]
    assert targets[bundle.live_deny_resolved] == [TEST_DOMAIN2]


def test_resolve_drops_a_stale_overlay_deny_cache(make_hook_mode: HookModeHarnessFactory) -> None:
    """With no denied name left in the overlay, its cache goes — nothing is resolved for it."""
    harness = make_hook_mode()
    bundle = _authored_bundle(harness.config.state_dir.resolve(), DnsTier.DNSMASQ_LIVE)
    bundle.live_deny_resolved.write_text(f"{TEST_IP4}\n")

    harness.mode.resolve()

    assert not bundle.live_deny_resolved.exists()
    assert bundle.live_deny_resolved not in {
        c.args[1] for c in harness.dns.resolve_names_and_cache.call_args_list
    }


def test_resolve_leaves_live_tier_allow_resolution_to_dnsmasq(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """dnsmasq-live resolves allowed domains per query: resolve() drops a stale allow cache."""
    harness = make_hook_mode()
    bundle = _authored_bundle(harness.config.state_dir.resolve(), DnsTier.DNSMASQ_LIVE)
    bundle.resolved_cache.write_text(f"{TEST_IP4}\n")

    assert harness.mode.resolve() == []

    assert not bundle.resolved_cache.exists()
    harness.dns.resolve_and_cache.assert_not_called()
    # Overrides never ride dnsmasq, and dnsmasq never fills a deny: even the
    # live tier resolves both itself.
    named = harness.dns.resolve_names_and_cache.call_args_list
    assert [c.args[1] for c in named] == [bundle.override_resolved, bundle.deny_resolved]


# ── the timed allow-all window ───────────────────────────────────────────


def test_arm_window_adds_the_default_routes_with_the_kernel_timeout(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """arm_window() hands nft the element that expires on its own."""
    harness = make_hook_mode()
    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP):
        harness.mode.arm_window("test-ctr", "5m")

    stdin = harness.runner.nft_via_nsenter.call_args.kwargs["stdin"]
    assert f"bypass_window_v4 {{ {ANY_IPV4} timeout 5m }}" in stdin
    assert f"bypass_window_v6 {{ {ANY_IPV6} timeout 5m }}" in stdin
    # A re-arm replaces the countdown even where a plain add would keep the old one.
    assert stdin.startswith("flush set inet terok_shield bypass_window_v4\n")


@pytest.mark.parametrize(
    "posture",
    [
        pytest.param(ShieldState.DOWN, id="down"),
        pytest.param(ShieldState.DISENGAGED, id="disengaged"),
        pytest.param(ShieldState.QUARANTINE, id="quarantine"),
        pytest.param(ShieldState.OFFLINE, id="offline"),
        pytest.param(ShieldState.ERROR, id="error"),
    ],
)
def test_arm_window_refuses_outside_up_and_arms_nothing(
    make_hook_mode: HookModeHarnessFactory, posture: ShieldState
) -> None:
    """Only the UP chain reads the window set, so arming it anywhere else is refused.

    A silent arm would report an open window that grants nothing — in DOWN the
    shield accepts by default already, and quarantine drops every packet.
    """
    harness = make_hook_mode()
    expected = WINDOW_NEEDS_UP.format(container="test-ctr", posture=posture.value)
    with (
        mock.patch.object(HookMode, "shield_state", return_value=posture),
        pytest.raises(RuntimeError) as ctx,
    ):
        harness.mode.arm_window("test-ctr", "5m")
    assert str(ctx.value) == expected
    harness.runner.nft_via_nsenter.assert_not_called()


def test_arm_window_refuses_a_timeout_nft_would_not_take(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """A duration that is not an nft timeout never reaches the kernel."""
    harness = make_hook_mode()
    with pytest.raises(ValueError, match="Invalid nft timeout"):
        harness.mode.arm_window("test-ctr", "5m; drop")
    harness.runner.nft_via_nsenter.assert_not_called()


def test_disarm_window_flushes_both_families(make_hook_mode: HookModeHarnessFactory) -> None:
    """disarm_window() closes the window before its timeout runs out."""
    harness = make_hook_mode()
    harness.mode.disarm_window("test-ctr")

    stdin = harness.runner.nft_via_nsenter.call_args.kwargs["stdin"]
    assert stdin.count("flush set") == 2


def _numeric_listing(*, learned: str = "", window: str = "") -> str:
    """A ``nft -T list table`` shape: the t40 set (maybe with a learned element) ahead of the window."""
    t40 = f"\t\telements = {{ {learned} }}\n" if learned else ""
    win = f"\t\telements = {{ {window} }}\n" if window else ""
    return (
        "table inet terok_shield {\n"
        "\tset t40_project_allow_v4 {\n\t\ttype ipv4_addr\n\t\tflags interval,timeout\n"
        f"{t40}\t}}\n\n"
        "\tset bypass_window_v4 {\n\t\ttype ipv4_addr\n\t\tflags interval,timeout\n"
        f"{win}\t}}\n"
        "}\n"
    )


def test_inspect_reads_posture_and_window_from_one_numeric_listing(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """One ``nft -T`` listing answers both, and the countdown is the window's own.

    A learned t40 address prints its countdown first; reading the first
    ``expires`` of the listing would report that instead of the window.
    """
    harness = make_hook_mode()
    harness.runner.nft_via_nsenter.return_value = _numeric_listing(
        learned=f"{TEST_IP1} expires 1799s", window=f"{ANY_IPV4} timeout 300s expires 299s"
    )
    with mock.patch.object(HookMode, "_classify", return_value=ShieldState.UP):
        reading = harness.mode.inspect("test-ctr")

    assert reading == ShieldReading(state=ShieldState.UP, bypass_remaining=299)
    harness.runner.nft_via_nsenter.assert_called_once_with(
        "test-ctr", "-T", "list", "table", "inet", "terok_shield", check=False
    )


def test_inspect_reports_no_window_when_none_is_open(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """An empty window set means closed — not unknown."""
    harness = make_hook_mode()
    harness.runner.nft_via_nsenter.return_value = _numeric_listing(learned=f"{TEST_IP1} expires 9s")
    with mock.patch.object(HookMode, "_classify", return_value=ShieldState.UP):
        assert harness.mode.inspect("test-ctr").bypass_remaining is None


@pytest.mark.parametrize("posture", [ShieldState.DOWN, ShieldState.DISENGAGED, ShieldState.ERROR])
def test_inspect_reports_a_window_for_up_alone(
    make_hook_mode: HookModeHarnessFactory, posture: ShieldState
) -> None:
    """Only the UP chain reads the window set: elsewhere an element grants nothing to count down."""
    harness = make_hook_mode()
    harness.runner.nft_via_nsenter.return_value = _numeric_listing(
        window=f"{ANY_IPV4} timeout 300s expires 120s"
    )
    with mock.patch.object(HookMode, "_classify", return_value=posture):
        assert harness.mode.inspect("test-ctr") == ShieldReading(state=posture)


@pytest.mark.parametrize(
    ("window", "expected"),
    [
        pytest.param(
            f"{ANY_IPV4} timeout 300s expires 299s",
            ShieldReading(state=ShieldState.UP, bypass_remaining=299),
            id="timed",
        ),
        pytest.param(ANY_IPV4, ShieldReading(state=ShieldState.ERROR), id="never-expires"),
    ],
)
def test_inspect_never_reads_a_permanent_window_as_the_trusted_up(
    make_hook_mode: HookModeHarnessFactory, window: str, expected: ShieldReading
) -> None:
    """A window element with no timeout has no countdown — and no UP posture holds one.

    The shield never adds such an element, so one found in the kernel was put
    there from outside: the posture reads as an error, never as plain ``up``
    with the window closed.
    """
    builder = RulesetBuilder()
    harness = make_hook_mode(ruleset=builder)
    harness.runner.nft_via_nsenter.return_value = builder.build_up() + _numeric_listing(
        window=window
    )

    assert harness.mode.inspect("test-ctr") == expected


def test_arm_window_refuses_a_window_that_would_never_close(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """``0s`` is nft's *never* — refused before the posture is even read."""
    harness = make_hook_mode()
    with pytest.raises(ValueError, match="never expires"):
        harness.mode.arm_window("test-ctr", "0m")
    harness.runner.nft_via_nsenter.assert_not_called()


def test_inspect_survives_a_container_without_the_table(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """nft failing (no table, container gone) reads as offline with no window, not a crash."""
    harness = make_hook_mode()
    harness.runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "No such file or directory")
    assert harness.mode.inspect("test-ctr") == ShieldReading(state=ShieldState.OFFLINE)


def test_shield_state_is_the_reading_posture(make_hook_mode: HookModeHarnessFactory) -> None:
    """shield_state() answers from the same one listing inspect() reads."""
    harness = make_hook_mode()
    reading = ShieldReading(state=ShieldState.DOWN)
    with mock.patch.object(HookMode, "inspect", return_value=reading) as inspect:
        assert harness.mode.shield_state("test-ctr") is ShieldState.DOWN
    inspect.assert_called_once_with("test-ctr")


def test_rules_listing_keeps_nfts_own_durations(make_hook_mode: HookModeHarnessFactory) -> None:
    """The ``rules`` verb shows people nft's compound form — no ``-T`` there."""
    harness = make_hook_mode()
    harness.mode.list_rules("test-ctr")
    harness.runner.nft_via_nsenter.assert_called_once_with(
        "test-ctr", "list", "table", "inet", "terok_shield", check=False
    )


def test_container_host_alias_is_podmans_name_for_the_host() -> None:
    """The alias shield pins with ``--add-host`` is podman's own name for the host."""
    assert CONTAINER_HOST_ALIAS == CONTAINER_HOSTNAME


# ── t10 override expiry ──────────────────────────────────────────────────

_SOON = date.today() + timedelta(days=7)
_SOON_ISO = _SOON.isoformat()
"""``_SOON`` as a grant's *expires*, spelled once so a ``pytest.raises`` holds the grant alone."""
_PAST = date.today() - timedelta(days=1)
_REASON = "vendor outage, direct debug #42"
"""A reason as an operator types it — spaces, a comma, a ``#`` — which the tier must keep whole."""


def _launched(state_dir: Path, tier: DnsTier) -> StateBundle:
    """A bundle as pre_start leaves it — enough for refresh() and the live verbs."""
    bundle = StateBundle(state_dir)
    bundle.ensure_dirs()
    bundle.dns_tier.write_text(f"{tier.value}\n")
    bundle.network_mode.write_text("pasta\n")
    bundle.upstream_dns.write_text(f"{PASTA_DNS}\n")
    return bundle


def _deadline(day: date) -> int:
    """The epoch second an override expiring on *day* runs out at."""
    return int(expiry_deadline(day.isoformat()).timestamp())


def _stdins(harness: HookModeHarness) -> list[str]:
    """Every nft stdin the harness's runner was handed, in order."""
    return [c.kwargs.get("stdin") or "" for c in harness.runner.nft_via_nsenter.call_args_list]


def _override_cache_answers(harness: HookModeHarness, cache_text: str) -> None:
    """Make every override-name resolution answer *cache_text* — what DNS answered per name.

    A refresh writes it to the cache.  A grant takes the answers in memory
    (``resolve_names``) and caches them itself, once the tier records it.
    """
    answers = {
        name: addresses
        for name, *addresses in (line.split() for line in cache_text.splitlines() if line.strip())
    }

    def _resolve(names: list[str], cache: Path, **_kwargs: object) -> None:
        cache.write_text(cache_text)

    def _answer(names: list[str], _cache: Path, **_kwargs: object) -> dict[str, list[str]]:
        return {name: answers[name] for name in names if name in answers}

    harness.dns.resolve_names_and_cache.side_effect = _resolve
    harness.dns.resolve_names.side_effect = _answer


def test_live_override_dnsmasq_reload_failure_says_the_address_grant_holds(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """A dead dnsmasq cannot open the name — the operator is told, and told what did take."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.DNSMASQ_LIVE)
    _override_cache_answers(harness, f"{VAULT_HOST} {TEST_IP3}\n")

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        mock.patch.object(HookMode, "_reload_dnsmasq", side_effect=RuntimeError("dnsmasq dead")),
        pytest.raises(RuntimeError, match="holds by address.*dnsmasq dead"),
    ):
        harness.mode.override("test-ctr", VAULT_HOST, _SOON_ISO, reason=_REASON)

    assert bundle.read_effective().override_domains() == [VAULT_HOST]
    # The kernel holds the grant, so the trail does too — reload failure or not.
    harness.audit.log_event.assert_any_call(
        "test-ctr", "override", dest=VAULT_HOST, detail=f"expires={_SOON}; reason={_REASON}"
    )


def test_authoring_drops_an_expired_override_and_says_why(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A break-glass that lapsed while the task was stopped is not authored — and the trail says so."""
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.profiles.compose_profiles.return_value = []
    bundle = _launched(config.state_dir, DnsTier.DNSMASQ_LIVE)

    with caplog.at_level(logging.WARNING):
        harness.mode.refresh("test", [], override=[f"{TEST_IP1} %expires={_PAST}", TEST_IP2])

    assert bundle.tier_path("override").read_text() == f"+{TEST_IP2}\n"
    harness.audit.log_event.assert_any_call(
        "test", "override_expired", dest=TEST_IP1, detail=f"expires={_PAST}"
    )
    assert TEST_IP1 not in bundle.ruleset.read_text()
    assert any(TEST_IP1 in record.message for record in caplog.records)


def test_authoring_refuses_an_expiry_that_names_no_date(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """A typo'd expiry fails the launch: it must not quietly keep a door open, nor close one."""
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.profiles.compose_profiles.return_value = []
    _launched(config.state_dir, DnsTier.DNSMASQ_LIVE)

    with pytest.raises(ValueError, match="someday"):
        harness.mode.refresh("test", [], override=[f"{TEST_IP1} %expires=someday"])


def test_an_expiring_override_is_timed_by_the_hook_not_baked_into_the_ruleset(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """ruleset.nft replays verbatim at every start, so only the overrides that never expire live there."""
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.profiles.compose_profiles.return_value = []
    bundle = _launched(config.state_dir, DnsTier.DNSMASQ_LIVE)

    harness.mode.refresh("test", [], override=[f"{TEST_IP1} %expires={_SOON}", TEST_IP2])

    ruleset = bundle.ruleset.read_text()
    assert TEST_IP2 in ruleset
    assert TEST_IP1 not in ruleset
    assert bundle.override_expiry.read_text() == f"{TEST_IP1} {_deadline(_SOON)}\n"


def test_a_rebuild_times_each_override_from_its_deadline(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """``shield up`` re-seeds t10 with the seconds each override has left — none for one that never ends."""
    harness, bundle = _transition_harness(make_hook_mode, make_config, DnsTier.DNSMASQ_LIVE)
    bundle.write_tier("override", f"+{TEST_IP1} %expires={_SOON}\n+{TEST_IP2}\n")
    now = _deadline(_SOON) - 3600

    with mock.patch("terok_shield.hooks.mode.time.time", return_value=float(now)):
        harness.mode.shield_up("test-ctr")

    assert any(
        f"t10_override_v4 {{ {TEST_IP1} timeout 3600s, {TEST_IP2} }}" in stdin
        for stdin in _stdins(harness)
    )


def test_live_override_records_and_times_the_grant_in_one_swap(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """The tier records it with its expiry; t10 is flushed and re-seeded in one transaction."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    now = _deadline(_SOON) - 60

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        mock.patch("terok_shield.hooks.mode.time.time", return_value=float(now)),
    ):
        assert harness.mode.override("test-ctr", TEST_IP1, _SOON.isoformat(), reason=_REASON) == [
            TEST_IP1
        ]

    (entry,) = bundle.read_tier(bundle.tier_path("override"))
    assert (entry.target, entry.meta["expires"]) == (TEST_IP1, _SOON.isoformat())
    assert unquote(entry.meta["reason"]) == _REASON
    (stdin,) = _stdins(harness)
    assert stdin.startswith("flush set inet terok_shield t10_override_v4\n")
    assert f"t10_override_v4 {{ {TEST_IP1} timeout 60s }}" in stdin


def test_live_override_of_a_name_opens_its_sinkhole_on_a_dnsmasq_tier(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """A vault host is sinkholed by name; the override punches through so the workload resolves it."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.DNSMASQ_LIVE)
    _override_cache_answers(harness, f"{VAULT_HOST} {TEST_IP3}\n")

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.DOWN),
        mock.patch.object(HookMode, "_reload_dnsmasq") as reload_dnsmasq,
    ):
        assert harness.mode.override("test-ctr", VAULT_HOST, _SOON.isoformat(), reason=_REASON) == [
            TEST_IP3
        ]

    reload_dnsmasq.assert_called_once()
    assert TEST_IP3 in _stdins(harness)[0]
    assert bundle.read_effective().override_domains() == [VAULT_HOST]


@pytest.mark.parametrize(
    "target",
    [
        pytest.param(LOCALHOST, id="localhost"),
        pytest.param(CONTAINER_HOSTNAME, id="host-alias"),
        pytest.param(DOCKER_HOSTNAME, id="docker-host-alias"),
        pytest.param(f"*.{TEST_DOMAIN}", id="wildcard"),
        pytest.param("not a target", id="garbage"),
        pytest.param(AWS_IMDS_V4, id="hard-deny"),
        pytest.param(PASTA_HOST_LOOPBACK_MAP, id="pasta-host-map"),
    ],
)
def test_live_override_refuses_what_no_override_can_carry(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory, target: str
) -> None:
    """The host itself, a wildcard, the hard-deny floor — refused before anything changes."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        pytest.raises(ValueError),
    ):
        harness.mode.override("test-ctr", target, _SOON_ISO, reason=_REASON)

    assert not bundle.tier_path("override").exists()
    harness.runner.nft_via_nsenter.assert_not_called()


def test_live_override_refuses_a_name_that_resolves_into_the_hard_deny_floor(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """IMDS sits above t10 — a name pointing there gets no override, by any route."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    _override_cache_answers(harness, f"{TEST_DOMAIN} {TEST_IP1} {AWS_IMDS_V4}\n")

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        pytest.raises(ValueError, match="hard-deny floor"),
    ):
        harness.mode.override("test-ctr", TEST_DOMAIN, _SOON_ISO, reason=_REASON)
    assert not bundle.tier_path("override").exists()
    harness.runner.nft_via_nsenter.assert_not_called()


@pytest.mark.parametrize(
    ("expires", "error"),
    [
        pytest.param(_PAST.isoformat(), "already passed", id="past"),
        pytest.param("someday", "Invalid isoformat", id="no-date"),
    ],
)
def test_live_override_needs_an_expiry_still_ahead(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory, expires: str, error: str
) -> None:
    """Valid through today at least — a date that passed opens nothing."""
    config = make_config()
    harness = make_hook_mode(config=config)
    _launched(config.state_dir, DnsTier.LOOKUP)
    with pytest.raises(ValueError, match=error):
        harness.mode.override("test-ctr", TEST_IP1, expires, reason=_REASON)


@pytest.mark.parametrize(
    "posture", [ShieldState.OFFLINE, ShieldState.QUARANTINE, ShieldState.ERROR]
)
def test_live_override_needs_a_ruleset_with_an_override_set(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory, posture: ShieldState
) -> None:
    """Stopped, quarantined or unrecognised: there is no t10 set to add to."""
    config = make_config()
    harness = make_hook_mode(config=config)
    _launched(config.state_dir, DnsTier.LOOKUP)
    message = OVERRIDE_NEEDS_RULESET.format(container="test-ctr", posture=posture.value)
    with (
        mock.patch.object(HookMode, "shield_state", return_value=posture),
        pytest.raises(RuntimeError, match=message),
    ):
        harness.mode.override("test-ctr", TEST_IP1, _SOON_ISO, reason=_REASON)


def test_live_override_of_a_name_with_no_address_opens_nothing(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """A name that resolves to nothing is reported, not recorded."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.write_tier("override", f"+{TEST_IP2}\n")
    _override_cache_answers(harness, "")
    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        pytest.raises(RuntimeError, match="resolves to no address"),
    ):
        harness.mode.override("test-ctr", TEST_DOMAIN, _SOON_ISO, reason=_REASON)
    assert bundle.tier_path("override").read_text() == f"+{TEST_IP2}\n"


def test_a_live_override_nft_refused_leaves_no_record(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """Nothing took, so nothing may linger for a later rebuild to grant."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.write_tier("override", f"+{TEST_IP2}\n")
    harness.runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "interval overlaps")

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        pytest.raises(ExecError),
    ):
        harness.mode.override("test-ctr", TEST_IP1, _SOON_ISO, reason=_REASON)

    assert bundle.tier_path("override").read_text() == f"+{TEST_IP2}\n"


def test_live_override_swaps_in_the_record_plus_the_grant_before_the_tier_records_it(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """The swap is computed in memory: while nft takes it, the tier holds only what it held."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.write_tier("override", f"+{TEST_IP2}\n")
    tier_at_swap: list[str] = []

    def _swap(_container: str, *_args: str, **_kwargs: object) -> str:
        tier_at_swap.append(bundle.tier_path("override").read_text())
        return ""

    harness.runner.nft_via_nsenter.side_effect = _swap
    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP):
        harness.mode.override("test-ctr", TEST_IP1, _SOON_ISO, reason=_REASON)

    assert tier_at_swap == [f"+{TEST_IP2}\n"]
    (stdin,) = _stdins(harness)
    assert TEST_IP1 in stdin
    assert TEST_IP2 in stdin
    recorded = [entry.target for entry in bundle.read_tier(bundle.tier_path("override"))]
    assert recorded == [TEST_IP2, TEST_IP1]


def test_a_grant_interrupted_before_the_swap_records_nothing(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """Interrupted while its name resolves, a grant reached no kernel — and no rebuild may grant it.

    An interrupt is no ``Exception``, so no rollback could be counted on to
    take a record back: nothing is recorded until the kernel holds the grant.
    """
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.write_tier("override", f"+{TEST_IP2}\n")
    harness.dns.resolve_names.side_effect = KeyboardInterrupt

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        pytest.raises(KeyboardInterrupt),
    ):
        harness.mode.override("test-ctr", TEST_DOMAIN, _SOON_ISO, reason=_REASON)

    assert bundle.tier_path("override").read_text() == f"+{TEST_IP2}\n"
    harness.runner.nft_via_nsenter.assert_not_called()
    harness.audit.log_event.assert_not_called()


def test_a_grant_the_tier_cannot_record_says_the_kernel_holds_it_until_the_next_rebuild(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """The kernel took the grant; the caller hears no rebuild re-seeds it.

    The ``override`` event was handed to the trail, yet the message claims
    nothing of it: audit may be off, or its file on the same full disk.
    """
    config = make_config()
    harness = make_hook_mode(config=config)
    _launched(config.state_dir, DnsTier.LOOKUP)

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        mock.patch.object(StateBundle, "upsert_override", side_effect=OSError("disk full")),
        pytest.raises(
            RuntimeError,
            match="holds in test-ctr's running ruleset.*could not record it.*shield up or down "
            "ends it: disk full",
        ) as unrecorded,
    ):
        harness.mode.override("test-ctr", TEST_IP1, _SOON_ISO, reason=_REASON)

    assert "audited" not in str(unrecorded.value)
    assert len(_stdins(harness)) == 1  # the swap went through
    harness.audit.log_event.assert_called_once_with(
        "test-ctr", "override", dest=TEST_IP1, detail=f"expires={_SOON}; reason={_REASON}"
    )


def test_a_regrant_the_tier_cannot_record_says_a_rebuild_restores_the_earlier_record(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """A shortened grant left unrecorded does not end at the next rebuild: the longer one returns.

    The failed write leaves the tier whole, earlier entry and all, and every
    rebuild re-seeds that entry until its own, later expiry.  Saying the
    rebuild ends the grant would err in the unsafe direction.
    """
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    longer = (_SOON + timedelta(days=30)).isoformat()
    bundle.upsert_override(TEST_IP1, longer, reason=_REASON)

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        mock.patch.object(StateBundle, "upsert_override", side_effect=OSError("disk full")),
        pytest.raises(
            RuntimeError,
            match=re.escape(
                "so the next shield up or down restores the earlier record of it in its place "
                f"(expires={longer}): disk full"
            ),
        ),
    ):
        harness.mode.override("test-ctr", TEST_IP1, _SOON_ISO, reason="wind down")

    (stdin,) = _stdins(harness)
    assert f"{TEST_IP1} timeout" in stdin  # the kernel took the shorter grant
    (entry,) = bundle.override_entries(TEST_IP1)
    assert entry.meta["expires"] == longer


def test_a_grant_the_cache_cannot_record_says_a_rebuild_may_leave_it_out(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """Tier recorded, answers not cached: the grant holds, but a rebuild may seed it from the old cache."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    _override_cache_answers(harness, f"{TEST_DOMAIN} {TEST_IP3}\n")

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        mock.patch(
            "terok_shield.hooks.mode.write_name_resolution", side_effect=OSError("disk full")
        ),
        pytest.raises(
            RuntimeError,
            match="the t10 tier records it, but the addresses it was seeded from could not be "
            "cached.*may leave it out: disk full",
        ),
    ):
        harness.mode.override("test-ctr", TEST_DOMAIN, _SOON_ISO, reason=_REASON)

    assert bundle.read_effective().override_domains() == [TEST_DOMAIN]
    assert not bundle.override_resolved.exists()


@pytest.mark.parametrize(
    ("unrecorded", "message"),
    [
        pytest.param(
            mock.patch.object(StateBundle, "upsert_override", side_effect=OSError("disk full")),
            "could not record it.*name stays sinkholed",
            id="tier",
        ),
        pytest.param(
            mock.patch(
                "terok_shield.hooks.mode.write_name_resolution", side_effect=OSError("disk full")
            ),
            "could not be cached",
            id="cache",
        ),
    ],
)
def test_a_grant_left_unrecorded_still_opens_its_name_in_dnsmasq(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    unrecorded: AbstractContextManager[object],
    message: str,
) -> None:
    """The kernel holds the grant whatever its record says, so dnsmasq follows before the error."""
    config = make_config()
    harness = make_hook_mode(config=config)
    _launched(config.state_dir, DnsTier.DNSMASQ_LIVE)
    _override_cache_answers(harness, f"{VAULT_HOST} {TEST_IP3}\n")

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        mock.patch.object(HookMode, "_reload_dnsmasq") as reload_dnsmasq,
        unrecorded,
        pytest.raises(RuntimeError, match=f"{message}.*disk full"),
    ):
        harness.mode.override("test-ctr", VAULT_HOST, _SOON_ISO, reason=_REASON)

    reload_dnsmasq.assert_called_once()
    assert TEST_IP3 in _stdins(harness)[0]


def _resolving(
    make_hook_mode: HookModeHarnessFactory, config: ShieldConfig, answers: dict[str, list[str]]
) -> HookModeHarness:
    """A harness resolving through a real resolver, so the override cache's own rules apply.

    Its lookups answer from *answers* — nothing for a name not in it.
    """
    runner = mock.MagicMock()
    runner.has.return_value = True
    runner.lookup_all.side_effect = lambda name, **_kwargs: list(answers.get(name, []))
    runner.getent_hosts.return_value = []
    resolver = mock.MagicMock(wraps=DnsResolver(runner=runner))
    return make_hook_mode(config=config, runner=runner, dns=resolver)


def _granted_with_a_fresh_cache(state_dir: Path) -> StateBundle:
    """A bundle whose tier grants TEST_DOMAIN, its cache answered after — fresh for that tier."""
    bundle = _launched(state_dir, DnsTier.LOOKUP)
    bundle.upsert_override(TEST_DOMAIN, _SOON_ISO, reason=_REASON)
    bundle.override_resolved.write_text(f"{TEST_DOMAIN} {TEST_IP1}\n")
    return bundle


def test_a_grant_resolves_its_name_past_a_cache_that_predates_it(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """A cache fresh by the hour knows nothing of the name a grant adds: every name resolves anew.

    The tier records the grant only after the swap, so the cache always
    predates the edit the grant makes — the swap seeds the fresh answers.
    """
    config = make_config()
    harness = _resolving(
        make_hook_mode, config, {TEST_DOMAIN: [TEST_IP4], TEST_DOMAIN2: [TEST_IP3]}
    )
    _granted_with_a_fresh_cache(config.state_dir)

    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP):
        opened = harness.mode.override("test-ctr", TEST_DOMAIN2, _SOON_ISO, reason=_REASON)

    assert opened == [TEST_IP3]
    (stdin,) = _stdins(harness)
    assert TEST_IP3 in stdin
    assert TEST_IP4 in stdin
    assert TEST_IP1 not in stdin


def _ready_to_rebuild(harness: HookModeHarness) -> HookModeHarness:
    """Let *harness*'s ``shield up``/``down`` rebuilds succeed, every nft call answering nothing."""
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.runner.nft_via_nsenter.return_value = ""
    harness.ruleset.build_up.return_value = "up ruleset"
    harness.ruleset.build_down.return_value = "down ruleset"
    harness.ruleset.verify_up.return_value = []
    harness.ruleset.verify_down.return_value = []
    harness.ruleset.add_elements_dual.return_value = ""
    return harness


def _reseed_on_shield_up(harness: HookModeHarness) -> str:
    """Raise the shield on *harness*'s container and return the t10 reseed it handed nft."""
    _ready_to_rebuild(harness).runner.nft_via_nsenter.reset_mock()
    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP):
        harness.mode.shield_up("test-ctr")
    (reseed,) = [stdin for stdin in _stdins(harness) if "t10_override" in stdin]
    return reseed


def test_a_grant_takes_no_answer_from_before_it_for_a_name_that_answers_nothing(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """Re-granted in a DNS outage, a name is refused: the cache answered for the tier before it.

    The refusal changes nothing on disk either.  Rewritten empty by the
    outage, and newer than the unchanged tier, the cache would pass for
    fresh, and the next rebuild — DNS back or not — would seed the grant
    already in force with nothing.
    """
    config = make_config()
    answers: dict[str, list[str]] = {}
    harness = _resolving(make_hook_mode, config, answers)
    bundle = _granted_with_a_fresh_cache(config.state_dir)
    cached = bundle.override_resolved.stat().st_mtime_ns
    later = (_SOON + timedelta(days=1)).isoformat()

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        pytest.raises(RuntimeError, match="resolves to no address"),
    ):
        harness.mode.override("test-ctr", TEST_DOMAIN, later, reason=_REASON)

    harness.runner.nft_via_nsenter.assert_not_called()
    (entry,) = bundle.override_entries(TEST_DOMAIN)
    assert entry.meta["expires"] == _SOON_ISO
    assert bundle.override_resolved.read_text() == f"{TEST_DOMAIN} {TEST_IP1}\n"
    assert bundle.override_resolved.stat().st_mtime_ns == cached
    answers[TEST_DOMAIN] = [TEST_IP1]  # DNS is back
    assert TEST_IP1 in _reseed_on_shield_up(harness)


def test_a_refresh_keeps_an_overrides_addresses_when_its_name_alone_times_out(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """A rebuild's re-resolve never ends a break-glass: the silent name keeps what it had.

    The other override answers anew and takes its new address, so only the
    timeout is bridged — an address an answering name stops giving still goes.
    """
    config = make_config()
    harness = _resolving(
        make_hook_mode, config, {TEST_DOMAIN2: [TEST_IP4]}
    )  # TEST_DOMAIN times out
    bundle = _granted_with_a_fresh_cache(config.state_dir)
    bundle.upsert_override(TEST_DOMAIN2, _SOON_ISO, reason=_REASON)
    bundle.override_resolved.write_text(f"{TEST_DOMAIN} {TEST_IP1}\n{TEST_DOMAIN2} {TEST_IP3}\n")

    harness.mode._resolve_override(config.state_dir, force=True)

    assert read_name_resolution(bundle.override_resolved) == {
        TEST_DOMAIN: [TEST_IP1],
        TEST_DOMAIN2: [TEST_IP4],
    }


def test_a_grant_keeps_another_overrides_addresses_when_its_lookup_fails(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """A lookup timing out during someone else's grant does not end a break-glass in force.

    The grant's own target still needs a fresh answer; the other override
    keeps the addresses its cache held, in the swap and in the cache after.
    """
    config = make_config()
    harness = _resolving(
        make_hook_mode, config, {TEST_DOMAIN2: [TEST_IP3]}
    )  # TEST_DOMAIN times out
    bundle = _granted_with_a_fresh_cache(config.state_dir)

    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP):
        opened = harness.mode.override("test-ctr", TEST_DOMAIN2, _SOON_ISO, reason=_REASON)

    assert opened == [TEST_IP3]
    (stdin,) = _stdins(harness)
    assert TEST_IP1 in stdin  # the other override, kept
    assert TEST_IP3 in stdin
    assert read_name_resolution(bundle.override_resolved) == {
        TEST_DOMAIN: [TEST_IP1],
        TEST_DOMAIN2: [TEST_IP3],
    }


def test_a_grant_refused_in_an_outage_leaves_the_granted_names_to_the_next_rebuild(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """A new name refused for want of an answer writes no answer for the names already granted."""
    config = make_config()
    answers: dict[str, list[str]] = {}
    harness = _resolving(make_hook_mode, config, answers)
    bundle = _granted_with_a_fresh_cache(config.state_dir)

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        pytest.raises(RuntimeError, match="resolves to no address"),
    ):
        harness.mode.override("test-ctr", TEST_DOMAIN2, _SOON_ISO, reason=_REASON)

    assert bundle.override_resolved.read_text() == f"{TEST_DOMAIN} {TEST_IP1}\n"
    assert bundle.read_effective().override_domains() == [TEST_DOMAIN]
    answers[TEST_DOMAIN] = [TEST_IP1]  # DNS is back
    assert TEST_IP1 in _reseed_on_shield_up(harness)


def test_a_grant_the_tier_already_holds_leaves_a_fresh_cache_standing(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """The very same grant again edits nothing: the fresh cache answers, and no lookup runs."""
    config = make_config()
    harness = _resolving(make_hook_mode, config, {})
    _granted_with_a_fresh_cache(config.state_dir)

    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP):
        opened = harness.mode.override("test-ctr", TEST_DOMAIN, _SOON_ISO, reason=_REASON)

    assert opened == [TEST_IP1]
    harness.runner.lookup_all.assert_not_called()


def test_a_grant_leaves_a_cache_the_next_rebuild_trusts(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """Cached after the tier records the grant, the answers are fresh: a rebuild looks nothing up.

    A cache older than the tier it answers for is resolved afresh at the next
    ``shield up``, and a granted name that happened not to answer then would
    drop out of t10.
    """
    config = make_config()
    answers = {TEST_DOMAIN: [TEST_IP4], TEST_DOMAIN2: [TEST_IP3]}
    harness = _resolving(make_hook_mode, config, answers)
    _launched(config.state_dir, DnsTier.LOOKUP)
    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP):
        harness.mode.override("test-ctr", TEST_DOMAIN, _SOON_ISO, reason=_REASON)
        harness.mode.override("test-ctr", TEST_DOMAIN2, _SOON_ISO, reason=_REASON)
    del answers[TEST_DOMAIN]  # its next lookup would come back empty
    harness.runner.lookup_all.reset_mock()

    reseed = _reseed_on_shield_up(harness)

    harness.runner.lookup_all.assert_not_called()
    assert TEST_IP4 in reseed
    assert TEST_IP3 in reseed


def _t10_lock_held(bundle: StateBundle) -> bool:
    """Whether a grant or a revoke holds *bundle*'s t10 lock — probed without waiting for it."""
    try:
        fd = os.open(bundle.override_lock, os.O_RDONLY)
    except FileNotFoundError:
        return False  # never taken
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    finally:
        os.close(fd)
    return False


def test_a_revoke_that_lands_while_a_grant_resolves_stays_revoked(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """The grant swaps from the tier as it stands once its names resolved — never a revoked address.

    The revoke closed the address and said so.  A swap computed from the
    tier as the grant first read it would put the address back above the
    security tier, with no record left to say so or to end it.
    """
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.upsert_override(TEST_IP2, _SOON_ISO, reason=_REASON)
    revoked: list[OverrideRevocation] = []

    def _revoke_meanwhile(names: list[str], _cache: Path, **_kwargs: object) -> dict:
        assert not _t10_lock_held(bundle), "a revoke would wait on the grant's resolver"
        revoked.append(harness.mode.revoke_override("test-ctr", TEST_IP2))
        return {name: [TEST_IP3] for name in names}

    harness.dns.resolve_names.side_effect = _revoke_meanwhile
    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP):
        opened = harness.mode.override("test-ctr", TEST_DOMAIN, _SOON_ISO, reason=_REASON)

    assert revoked == [OverrideRevocation(target=TEST_IP2, closed=(TEST_IP2,), live=True)]
    assert opened == [TEST_IP3]
    revoke_swap, grant_swap = _stdins(harness)
    assert TEST_IP2 not in revoke_swap
    assert TEST_IP2 not in grant_swap
    assert TEST_IP3 in grant_swap
    assert [e.target for e in bundle.read_tier(bundle.tier_path("override"))] == [TEST_DOMAIN]


def test_a_grant_that_lands_while_another_resolves_keeps_its_element(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """Two grants at once: the later swap carries the earlier one's element, as the tier records both."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)

    def _grant_meanwhile(names: list[str], _cache: Path, **_kwargs: object) -> dict:
        assert not _t10_lock_held(bundle), "a grant would wait on another's resolver"
        harness.mode.override("test-ctr", TEST_IP1, _SOON_ISO, reason=_REASON)
        return {name: [TEST_IP3] for name in names}

    harness.dns.resolve_names.side_effect = _grant_meanwhile
    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP):
        harness.mode.override("test-ctr", TEST_DOMAIN, _SOON_ISO, reason=_REASON)

    first, last = _stdins(harness)
    assert TEST_IP1 in first
    assert TEST_IP1 in last
    assert TEST_IP3 in last
    recorded = {e.target for e in bundle.read_tier(bundle.tier_path("override"))}
    assert recorded == {TEST_IP1, TEST_DOMAIN}


@pytest.mark.parametrize("verb", ["grant", "revoke"])
def test_a_grant_and_a_revoke_each_swap_holding_the_t10_lock(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory, verb: str
) -> None:
    """From the read of the tier through the swap, no other grant or revoke gets in — then it is free."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.upsert_override(TEST_IP2, _SOON_ISO, reason=_REASON)
    held_at_swap: list[bool] = []

    def _swap(*_args: object, **_kwargs: object) -> str:
        held_at_swap.append(_t10_lock_held(bundle))
        return ""

    harness.runner.nft_via_nsenter.side_effect = _swap
    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP):
        if verb == "grant":
            harness.mode.override("test-ctr", TEST_IP1, _SOON_ISO, reason=_REASON)
        else:
            harness.mode.revoke_override("test-ctr", TEST_IP2)

    assert held_at_swap == [True]
    assert not _t10_lock_held(bundle)


@pytest.mark.parametrize("transition", ["up", "down"])
@pytest.mark.parametrize("mutation", ["revoke", "deny"])
def test_a_policy_change_cannot_finish_inside_a_rebuild_snapshot(
    make_hook_mode: HookModeHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
    transition: str,
    mutation: str,
) -> None:
    """A revoke or deny waits for publication, then changes the rebuilt table rather than the old one."""
    harness = make_hook_mode()
    bundle = _launched(harness.config.state_dir, DnsTier.LOOKUP)
    bundle.upsert_override(TEST_IP2, _SOON_ISO, reason=_REASON)
    harness.mode._container_ruleset = lambda _c: harness.ruleset
    harness.ruleset.build_up.return_value = "up ruleset"
    harness.ruleset.build_down.return_value = "down ruleset"
    harness.ruleset.verify_up.return_value = []
    harness.ruleset.verify_down.return_value = []
    harness.ruleset.add_elements_dual.return_value = ""
    captured, attempting, finished = Event(), Event(), Event()
    rebuilding_thread = get_ident()
    writes: list[str] = []
    read_seeds = StateBundle.read_override_seeds
    take_lock = StateBundle.override_change

    def _pause_after_snapshot(state: StateBundle, *args: object, **kwargs: object) -> list:
        seeds = read_seeds(state, *args, **kwargs)
        if not captured.is_set():
            assert _t10_lock_held(bundle)
            captured.set()
            assert attempting.wait(timeout=5), "policy mutation never reached the shared lock"
            assert not finished.is_set(), "mutation completed before its snapshot was published"
        return seeds

    @contextmanager
    def _observe_lock(state: StateBundle) -> Iterator[None]:
        if get_ident() != rebuilding_thread:
            attempting.set()
        with take_lock(state):
            yield

    def _write(_container: str, *args: str, stdin: str | None = None) -> str:
        if stdin or (args and args[0] in ("add", "delete")):
            writes.append("rebuild" if get_ident() == rebuilding_thread else mutation)
            assert _t10_lock_held(bundle)
        return ""

    def _mutate() -> None:
        assert captured.wait(timeout=5), "rebuild never captured its seed snapshot"
        if mutation == "revoke":
            harness.mode.revoke_override("test-ctr", TEST_IP2)
        else:
            harness.mode.deny_ip("test-ctr", TEST_IP1)
        finished.set()

    monkeypatch.setattr(StateBundle, "read_override_seeds", _pause_after_snapshot)
    monkeypatch.setattr(StateBundle, "override_change", _observe_lock)
    harness.runner.nft_via_nsenter.side_effect = _write
    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        ThreadPoolExecutor(max_workers=1) as workers,
    ):
        changed = workers.submit(_mutate)
        getattr(harness.mode, f"shield_{transition}")("test-ctr")
        changed.result(timeout=5)

    assert writes[0] == "rebuild"
    assert writes[-1] == mutation
    assert writes == sorted(writes, key=lambda action: action != "rebuild")
    assert finished.is_set()
    assert not _t10_lock_held(bundle)
    if mutation == "revoke":
        assert bundle.override_entries(TEST_IP2) == []
    else:
        assert TEST_IP1 in bundle.read_denied_ips()


_AN_HOUR = 3600
"""Seconds a slow resolution is made to take, by a test's clock — far past a one-minute expiry."""


def test_an_expiry_that_runs_out_while_the_names_resolve_grants_nothing(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """An instant passed mid-resolution would seed nothing, yet be audited as granted: refused instead."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.write_tier("override", f"+{TEST_DOMAIN}\n")  # a name, so the grant resolves
    clock = [datetime.now().timestamp()]
    expires = (datetime.now() + timedelta(minutes=1)).isoformat(timespec="seconds")

    def _resolve_for_an_hour(names: list[str], _cache: Path, **_kwargs: object) -> dict:
        clock[0] += _AN_HOUR
        return {name: [TEST_IP3] for name in names}

    harness.dns.resolve_names.side_effect = _resolve_for_an_hour
    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        mock.patch("terok_shield.hooks.mode.time.time", side_effect=lambda: clock[0]),
        pytest.raises(
            ValueError, match=re.escape(f"expires={expires} ran out while the override names")
        ),
    ):
        harness.mode.override("test-ctr", TEST_IP1, expires, reason=_REASON)

    harness.dns.resolve_names.assert_called_once()
    harness.runner.nft_via_nsenter.assert_not_called()
    harness.audit.log_event.assert_not_called()
    assert bundle.tier_path("override").read_text() == f"+{TEST_DOMAIN}\n"


def test_live_override_needs_a_reason(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """A break-glass says why it exists — a blank reason opens nothing and records nothing."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        pytest.raises(ValueError, match="needs a reason"),
    ):
        harness.mode.override("test-ctr", TEST_IP1, _SOON_ISO, reason="  ")

    assert not bundle.tier_path("override").exists()
    harness.runner.nft_via_nsenter.assert_not_called()
    harness.audit.log_event.assert_not_called()


@pytest.mark.parametrize(
    "target",
    [
        pytest.param(SLIRP4NETNS_GATEWAY, id="gateway-v4"),
        pytest.param(SLIRP4NETNS_GATEWAY_V6, id="gateway-v6"),
        pytest.param(RFC1918_CIDR_10, id="range-around-it"),
    ],
)
def test_live_override_refuses_the_slirp4netns_host_gateway(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    """Under slirp4netns the host's loopback is the gateway, inside a private range.

    An override there would open every port the host listens on locally, where
    a ``+localhost:PORT`` grant opens one — so it is refused like pasta's map,
    and so is a range that takes the gateway in.
    """
    monkeypatch.setattr("terok_shield.podman_info.network._SYSTEM_CONF_PATHS", ())
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.network_mode.write_text("slirp4netns\n")
    bundle.record_gateways(SLIRP4NETNS_GATEWAY, SLIRP4NETNS_GATEWAY_V6)

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        pytest.raises(ValueError, match="host's own loopback.*localhost:PORT"),
    ):
        harness.mode.override("test-ctr", target, _SOON_ISO, reason=_REASON)

    assert not bundle.tier_path("override").exists()
    harness.runner.nft_via_nsenter.assert_not_called()


def _launched_on_slirp4netns(state_dir: Path, monkeypatch: pytest.MonkeyPatch) -> StateBundle:
    """A lookup-tier bundle launched under slirp4netns at its default CIDR (containers.conf unread)."""
    monkeypatch.setattr("terok_shield.podman_info.network._SYSTEM_CONF_PATHS", ())
    bundle = _launched(state_dir, DnsTier.LOOKUP)
    bundle.network_mode.write_text("slirp4netns\n")
    bundle.record_gateways(SLIRP4NETNS_GATEWAY, SLIRP4NETNS_GATEWAY_V6)
    bundle.upstream_dns.write_text(f"{SLIRP4NETNS_DNS}\n")
    return bundle


def _floor_notes(harness: HookModeHarness) -> list[str]:
    """The ``note`` lines saying an override's address stayed out of t10."""
    return [note for note in _notes(harness) if "no override opens it" in note]


def test_a_later_grant_never_seeds_a_name_rebound_onto_the_host_gateway(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A grant re-resolves every override name; one rebound onto the gateway stays out of its swap.

    The grant checks its own target's answer, and only that: the earlier
    name's fresh answer meets the bar in the seed, where every path's answer
    does — and the grant says what it left out.
    """
    config = make_config()
    harness = make_hook_mode(config=config)
    _launched_on_slirp4netns(config.state_dir, monkeypatch)
    answers = {TEST_DOMAIN: [TEST_IP3]}

    def _answer(names: list[str], _cache: Path, **_kwargs: object) -> dict[str, list[str]]:
        return {n: answers[n] for n in names if n in answers}

    harness.dns.resolve_names.side_effect = _answer
    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP):
        harness.mode.override("test-ctr", TEST_DOMAIN, _SOON.isoformat(), reason=_REASON)
        answers.update({TEST_DOMAIN: [SLIRP4NETNS_GATEWAY], TEST_DOMAIN2: [TEST_IP4]})
        opened = harness.mode.override("test-ctr", TEST_DOMAIN2, _SOON.isoformat(), reason=_REASON)

    assert opened == [TEST_IP4]
    swap = _stdins(harness)[-1]
    assert TEST_IP4 in swap
    assert SLIRP4NETNS_GATEWAY not in swap
    (note,) = _floor_notes(harness)
    assert f"{TEST_DOMAIN} reaches {SLIRP4NETNS_GATEWAY}, the host's own loopback" in note


def test_a_rebuild_never_reseeds_a_name_rebound_onto_the_host_gateway(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``shield up`` re-resolves a stale cache before it reseeds t10 — and the gateway stays out.

    So does a cache a refused grant left behind: whatever the cache holds,
    the reseed admits only what an override may open, and notes the rest.
    """
    harness, _ = _transition_harness(make_hook_mode, make_config, DnsTier.LOOKUP)
    bundle = _launched_on_slirp4netns(harness.config.state_dir, monkeypatch)
    bundle.upsert_override(TEST_DOMAIN, _SOON.isoformat(), reason=_REASON)
    _override_cache_answers(harness, f"{TEST_DOMAIN} {SLIRP4NETNS_GATEWAY} {TEST_IP3}\n")

    harness.mode.shield_up("test-ctr")

    (reseed,) = [stdin for stdin in _stdins(harness) if "t10_override" in stdin]
    assert TEST_IP3 in reseed
    assert SLIRP4NETNS_GATEWAY not in reseed
    assert len(_floor_notes(harness)) == 1


def test_container_ruleset_takes_the_gateways_from_the_recorded_network_mode(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rebuild guards the gateway the container launched with, whatever podman's default is now."""
    config = make_config()
    harness = make_hook_mode(config=config)
    _launched_on_slirp4netns(config.state_dir, monkeypatch)
    harness.runner.run.return_value = _MODERN_PODMAN_INFO  # podman's default is pasta today

    rebuilt = harness.mode._container_ruleset("test-ctr").build_up()

    assert f"ip daddr {SLIRP4NETNS_GATEWAY} log" in rebuilt
    harness.runner.run.assert_not_called()  # the bundle answered; podman info was never asked


def _cidr_changed_since_launch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point ``containers.conf``'s slirp4netns ``cidr=`` elsewhere, as an operator edit would."""
    conf = tmp_path / "xdg" / "containers" / "containers.conf"
    conf.parent.mkdir(parents=True)
    conf.write_text(f'[engine]\nnetwork_cmd_options = ["cidr={TEST_CUSTOM_CIDR_192}"]\n')
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))


def test_a_rebuild_keeps_the_gateway_the_container_launched_with(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A ``cidr=`` changed since the launch moves no running container's gateway."""
    config = make_config()
    harness = make_hook_mode(config=config)
    _launched_on_slirp4netns(config.state_dir, monkeypatch)
    _cidr_changed_since_launch(tmp_path, monkeypatch)

    rebuilt = harness.mode._container_ruleset("test-ctr").build_up()

    assert f"ip daddr {SLIRP4NETNS_GATEWAY} log" in rebuilt
    assert TEST_CUSTOM_GATEWAY_192 not in rebuilt


def test_an_override_of_the_launch_gateway_is_refused_after_a_cidr_change(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The host's loopback is where the container reaches it: the recorded gateway, not the new one."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched_on_slirp4netns(config.state_dir, monkeypatch)
    _cidr_changed_since_launch(tmp_path, monkeypatch)

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        pytest.raises(ValueError, match="host's own loopback"),
    ):
        harness.mode.override("test-ctr", SLIRP4NETNS_GATEWAY, _SOON_ISO, reason=_REASON)

    assert not bundle.tier_path("override").exists()
    harness.runner.nft_via_nsenter.assert_not_called()


def _expired_override_punched_through(bundle: StateBundle) -> float:
    """Leave *bundle*'s dnsmasq config as a live override of VAULT_HOST did; return a moment after it ran out."""
    bundle.write_tier("security_deny", f"-{VAULT_HOST}\n")
    bundle.write_tier("override", f"+{VAULT_HOST} %expires={_SOON}\n")
    dnsmasq.rewrite_config(
        bundle.state_dir, PASTA_DNS, [], deny_domains=[VAULT_HOST], override_domains=[VAULT_HOST]
    )
    assert f"local=/{VAULT_HOST}/" not in bundle.dnsmasq_conf.read_text()  # punched through
    return float(_deadline(_SOON) + 60)


@pytest.mark.parametrize("posture", ["up", "down"])
def test_a_rebuild_closes_an_expired_overrides_name_in_dnsmasq(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory, posture: str
) -> None:
    """The kernel ends the override on time; the next rebuild ends its punch-through.

    A running dnsmasq keeps the config it loaded, so the name would stay
    resolvable past the expiry — and a rotated vault address with it.
    """
    harness, bundle = _transition_harness(make_hook_mode, make_config, DnsTier.DNSMASQ_LIVE)
    after = _expired_override_punched_through(bundle)

    with (
        mock.patch("terok_shield.hooks.mode.time.time", return_value=after),
        mock.patch.object(HookMode, "_reload_dnsmasq") as reload_dnsmasq,
    ):
        if posture == "up":
            harness.mode.shield_up("test-ctr")
        else:
            harness.mode.shield_down("test-ctr")

    reload_dnsmasq.assert_called_once()
    assert reload_dnsmasq.call_args.args[0] == "test-ctr"


def test_a_rebuild_leaves_a_current_dnsmasq_config_running(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """While the override holds, the config already says what the policy says: no relaunch."""
    harness, bundle = _transition_harness(make_hook_mode, make_config, DnsTier.DNSMASQ_LIVE)
    after = _expired_override_punched_through(bundle)

    with (
        mock.patch("terok_shield.hooks.mode.time.time", return_value=after - 3600),
        mock.patch.object(HookMode, "_reload_dnsmasq") as reload_dnsmasq,
    ):
        harness.mode.shield_up("test-ctr")

    reload_dnsmasq.assert_not_called()


def test_a_dnsmasq_that_cannot_reload_does_not_stop_the_rebuild(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A dnsmasq past reloading leaves no DNS at all, which resolves the lapsed name no better."""
    harness, bundle = _transition_harness(make_hook_mode, make_config, DnsTier.DNSMASQ_LIVE)
    after = _expired_override_punched_through(bundle)

    with (
        caplog.at_level(logging.WARNING),
        mock.patch("terok_shield.hooks.mode.time.time", return_value=after),
        mock.patch.object(HookMode, "_reload_dnsmasq", side_effect=RuntimeError("dnsmasq dead")),
    ):
        harness.mode.shield_up("test-ctr")

    assert any("dnsmasq dead" in record.message for record in caplog.records)


@pytest.mark.parametrize(
    ("target", "message"),
    [
        pytest.param(AWS_IMDS_V4, "inside the hard-deny floor", id="hard-deny"),
        pytest.param(PASTA_HOST_LOOPBACK_MAP, "the host's own loopback", id="host-loopback"),
    ],
)
def test_live_override_judges_an_address_before_it_asks_the_posture(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory, target: str, message: str
) -> None:
    """An address needs no resolving, so the floor and the host refuse it even on a stopped container.

    The refusal is the same in every posture — never "the container is
    offline" for something no override could ever carry.
    """
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.OFFLINE) as posture,
        pytest.raises(ValueError, match=message),
    ):
        harness.mode.override("test-ctr", target, _SOON_ISO, reason=_REASON)

    posture.assert_not_called()
    assert not bundle.tier_path("override").exists()


# ── revoking a t10 override ──────────────────────────────────────────────

_NO_PROCESS = "0"
"""What ``podman inspect --format {{.State.Pid}}`` prints for a container with no process."""


def _stopped(harness: HookModeHarness) -> HookModeHarness:
    """Make podman report the harness's container stopped — no process, so no netns to enter."""
    harness.runner.podman_inspect.return_value = _NO_PROCESS
    return harness


def _vault_host_punched_through(bundle: StateBundle) -> None:
    """Grant VAULT_HOST an override in force, its name punched through dnsmasq's sinkhole."""
    bundle.write_tier("security_deny", f"-{VAULT_HOST}\n")
    bundle.upsert_override(VAULT_HOST, _SOON.isoformat(), reason=_REASON)
    bundle.override_resolved.write_text(f"{VAULT_HOST} {TEST_IP3}\n")
    dnsmasq.rewrite_config(
        bundle.state_dir, PASTA_DNS, [], deny_domains=[VAULT_HOST], override_domains=[VAULT_HOST]
    )
    assert f"local=/{VAULT_HOST}/" not in bundle.dnsmasq_conf.read_text()  # punched through


@pytest.mark.parametrize(
    "posture",
    [ShieldState.UP, ShieldState.DOWN, ShieldState.DISENGAGED, ShieldState.ERROR],
)
def test_revoke_override_swaps_t10_without_the_target(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory, posture: ShieldState
) -> None:
    """One nft transaction: t10 flushed and re-seeded without the target, every other override kept.

    An unrecognised ruleset is tried too — if it holds a t10 set, the
    override must leave it; if it holds none, nft says so and the revoke
    reports it.
    """
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.write_tier("override", f"+{TEST_IP2}\n")
    bundle.upsert_override(TEST_IP1, _SOON.isoformat(), reason=_REASON)

    with mock.patch.object(HookMode, "shield_state", return_value=posture):
        revoked = harness.mode.revoke_override("test-ctr", TEST_IP1)

    assert revoked == OverrideRevocation(target=TEST_IP1, closed=(TEST_IP1,), live=True)
    assert bundle.tier_path("override").read_text() == f"+{TEST_IP2}\n"
    (stdin,) = _stdins(harness)
    assert stdin.startswith("flush set inet terok_shield t10_override_v4\n")
    assert f"t10_override_v4 {{ {TEST_IP2} }}" in stdin
    assert TEST_IP1 not in stdin
    harness.audit.log_event.assert_called_once_with(
        "test-ctr", "override_revoked", dest=TEST_IP1, detail=f"expires={_SOON}; reason={_REASON}"
    )


def test_revoke_override_keeps_every_other_element_timed_to_its_own_deadline(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """The re-seed is no grant: what stays keeps only the seconds its own override has left."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.write_tier("override", f"+{TEST_IP1}\n+{TEST_IP2} %expires={_SOON}\n")
    now = _deadline(_SOON) - 120

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        mock.patch("terok_shield.hooks.mode.time.time", return_value=float(now)),
    ):
        harness.mode.revoke_override("test-ctr", TEST_IP1)

    (stdin,) = _stdins(harness)
    assert f"t10_override_v4 {{ {TEST_IP2} timeout 120s }}" in stdin


def test_revoke_override_closes_a_names_sinkhole_punch_through(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """The name stops resolving again: dnsmasq reloads, since its config still opens the name."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.DNSMASQ_LIVE)
    _vault_host_punched_through(bundle)

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        mock.patch.object(HookMode, "_reload_dnsmasq") as reload_dnsmasq,
    ):
        revoked = harness.mode.revoke_override("test-ctr", VAULT_HOST)

    assert revoked == OverrideRevocation(target=VAULT_HOST, closed=(TEST_IP3,), live=True)
    reload_dnsmasq.assert_called_once()
    assert reload_dnsmasq.call_args.args[0] == "test-ctr"
    assert bundle.read_effective().override_domains() == []


def test_revoke_override_says_when_dnsmasq_cannot_close_the_name(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """The kernel let go, so the trail says revoked — and the caller hears the name may still resolve."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.DNSMASQ_LIVE)
    _vault_host_punched_through(bundle)

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        mock.patch.object(HookMode, "_reload_dnsmasq", side_effect=RuntimeError("dnsmasq dead")),
        pytest.raises(
            RuntimeError, match="revoked by address.*sinkhole the name again.*dnsmasq dead"
        ),
    ):
        harness.mode.revoke_override("test-ctr", VAULT_HOST)

    harness.audit.log_event.assert_called_once_with(
        "test-ctr", "override_revoked", dest=VAULT_HOST, detail=f"expires={_SOON}; reason={_REASON}"
    )
    assert bundle.override_entries(VAULT_HOST) == []


def test_revoke_override_of_an_address_leaves_dnsmasq_alone(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """An address was never punched through any sinkhole, so there is no name to close."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.DNSMASQ_LIVE)
    bundle.upsert_override(TEST_IP1, _SOON.isoformat(), reason=_REASON)

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        mock.patch.object(HookMode, "_sync_dns_plane") as sync,
    ):
        harness.mode.revoke_override("test-ctr", TEST_IP1)

    sync.assert_not_called()


@pytest.mark.parametrize(
    ("tier_text", "message"),
    [
        pytest.param(
            f"+{TEST_IP2}\n",
            f"test-ctr has no override of {TEST_IP1} to revoke (overrides in force: {TEST_IP2})",
            id="never-granted",
        ),
        pytest.param(
            f"+{TEST_IP1} %expires={_PAST}\n",
            f"the override of {TEST_IP1} on test-ctr is no longer in force (expires={_PAST})",
            id="ran-out",
        ),
        pytest.param("", "(overrides in force: none)", id="no-overrides-at-all"),
    ],
)
def test_revoke_override_with_nothing_in_force_is_an_error(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    tier_text: str,
    message: str,
) -> None:
    """Nothing to revoke is said, never passed off as a success — and nothing is touched."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.write_tier("override", tier_text)

    with pytest.raises(RuntimeError, match=re.escape(message)):
        harness.mode.revoke_override("test-ctr", TEST_IP1)

    assert bundle.tier_path("override").read_text() == tier_text
    harness.runner.nft_via_nsenter.assert_not_called()  # not even to read the posture
    harness.audit.log_event.assert_not_called()


def test_revoke_override_refuses_text_that_is_no_target(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """Garbage is a bad argument, not an override that happens to be missing."""
    config = make_config()
    harness = make_hook_mode(config=config)
    _launched(config.state_dir, DnsTier.LOOKUP)
    with pytest.raises(ValueError, match="invalid target"):
        harness.mode.revoke_override("test-ctr", "not a target")


def test_revoke_override_refuses_a_host_service_grant(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """``+localhost:PORT`` opens a preamble port, not a t10 element — no swap could take it back."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.write_tier("override", f"+{LOCALHOST_GRANT}\n")

    with pytest.raises(ValueError, match=r"host service, not an override"):
        harness.mode.revoke_override("test-ctr", LOCALHOST)

    assert bundle.tier_path("override").read_text() == f"+{LOCALHOST_GRANT}\n"
    harness.runner.nft_via_nsenter.assert_not_called()
    harness.audit.log_event.assert_not_called()


def test_revoke_override_that_nft_cannot_drop_stays_out_of_the_bundle_and_is_reported(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """Fail closed: no rebuild or start may re-open it, and no audit line may claim it closed."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.upsert_override(TEST_IP1, _SOON.isoformat(), reason=_REASON)
    harness.runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "netns gone")

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        pytest.raises(
            RuntimeError,
            match="no rebuild re-opens it.*admits it until the next shield up or down.*netns gone",
        ),
    ):
        harness.mode.revoke_override("test-ctr", TEST_IP1)

    assert bundle.override_entries(TEST_IP1) == []
    assert TEST_IP1 not in bundle.override_expiry.read_text()
    harness.audit.log_event.assert_not_called()


def test_revoke_override_whose_replay_cannot_be_rewritten_still_leaves_the_kernel(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """A failed rewrite strands nothing live: the swap, the audit and the reload still run.

    Its error comes last and says a plain start would re-open the override —
    a retry would find no override left to revoke, so the kernel step cannot wait for one.
    """
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.DNSMASQ_LIVE)
    _vault_host_punched_through(bundle)

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        mock.patch.object(HookMode, "_write_ruleset", side_effect=OSError("disk full")),
        mock.patch.object(HookMode, "_reload_dnsmasq") as reload_dnsmasq,
        pytest.raises(RuntimeError, match="plain podman start.*re-opens it.*disk full"),
    ):
        harness.mode.revoke_override("test-ctr", VAULT_HOST)

    (stdin,) = _stdins(harness)
    assert "flush set" in stdin
    assert bundle.override_entries(VAULT_HOST) == []
    harness.audit.log_event.assert_called_once_with(
        "test-ctr", "override_revoked", dest=VAULT_HOST, detail=f"expires={_SOON}; reason={_REASON}"
    )
    reload_dnsmasq.assert_called_once()


def test_revoke_override_that_neither_nft_nor_the_rewrite_can_take_says_both(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """Both failures are named: the running ruleset still admits it, and a plain start would too."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.upsert_override(TEST_IP1, _SOON.isoformat(), reason=_REASON)
    harness.runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "netns gone")

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        mock.patch.object(HookMode, "_write_ruleset", side_effect=OSError("disk full")),
        pytest.raises(RuntimeError, match="netns gone; and .*plain podman start.*disk full"),
    ):
        harness.mode.revoke_override("test-ctr", TEST_IP1)

    assert bundle.override_entries(TEST_IP1) == []
    harness.audit.log_event.assert_not_called()


def test_revoke_override_on_a_stopped_container_rewrites_what_its_next_start_replays(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """A plain podman start replays ruleset.nft and override.expiry — neither may re-open it."""
    config = make_config()
    harness = _stopped(make_hook_mode(config=config))
    harness.profiles.compose_profiles.return_value = []
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    harness.mode.refresh("test-ctr", [], override=[f"{TEST_IP1} %expires={_SOON}", TEST_IP2])
    assert TEST_IP2 in bundle.ruleset.read_text()  # an override that never expires is baked in
    harness.audit.log_event.reset_mock()

    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.OFFLINE):
        revoked = harness.mode.revoke_override("test-ctr", TEST_IP2)

    assert revoked == OverrideRevocation(target=TEST_IP2, closed=(TEST_IP2,), live=False)
    assert TEST_IP2 not in bundle.ruleset.read_text()
    assert bundle.override_expiry.read_text() == f"{TEST_IP1} {_deadline(_SOON)}\n"
    harness.runner.nft_via_nsenter.assert_not_called()
    harness.audit.log_event.assert_called_once_with(
        "test-ctr", "override_revoked", dest=TEST_IP2, detail="at next start"
    )


def test_revoke_override_on_a_stopped_container_closes_the_name_in_its_dnsmasq_config(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """The hook starts dnsmasq from the config on disk, so that is where the sinkhole comes back."""
    config = make_config()
    harness = _stopped(make_hook_mode(config=config))
    bundle = _launched(config.state_dir, DnsTier.DNSMASQ_LIVE)
    _vault_host_punched_through(bundle)

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.OFFLINE),
        mock.patch.object(HookMode, "_reload_dnsmasq") as reload_dnsmasq,
    ):
        harness.mode.revoke_override("test-ctr", VAULT_HOST)

    assert f"local=/{VAULT_HOST}/" in bundle.dnsmasq_conf.read_text()
    reload_dnsmasq.assert_not_called()


def test_revoke_override_in_a_bundle_no_launch_prepared_writes_no_ruleset(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """With no recorded tier there is no ruleset to replay: the record goes, nothing is invented."""
    config = make_config()
    harness = _stopped(make_hook_mode(config=config))
    bundle = StateBundle(config.state_dir)
    bundle.ensure_dirs()
    bundle.write_tier("override", f"+{TEST_IP1}\n")

    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.OFFLINE):
        revoked = harness.mode.revoke_override("test-ctr", TEST_IP1)

    assert revoked == OverrideRevocation(target=TEST_IP1, closed=(TEST_IP1,), live=False)
    assert bundle.override_entries(TEST_IP1) == []
    assert not bundle.ruleset.exists()


def test_revoke_override_in_quarantine_has_no_set_to_touch(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """Quarantine holds no t10 set: the record goes, so the next rebuild leaves the override out."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.upsert_override(TEST_IP1, _SOON.isoformat(), reason=_REASON)

    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.QUARANTINE):
        revoked = harness.mode.revoke_override("test-ctr", TEST_IP1)

    assert revoked.live
    assert bundle.override_entries(TEST_IP1) == []
    harness.runner.nft_via_nsenter.assert_not_called()
    harness.audit.log_event.assert_called_once()


def test_revoke_override_says_which_addresses_another_override_still_opens(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """A name inside a range override stays reachable through the range, and the revoke says so."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.write_tier("override", f"+{TEST_NET1}\n+{TEST_DOMAIN} %expires={_SOON}\n")
    bundle.override_resolved.write_text(f"{TEST_DOMAIN} {TEST_NET1_HOST} {TEST_IP3}\n")

    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP):
        revoked = harness.mode.revoke_override("test-ctr", TEST_DOMAIN)

    assert (revoked.closed, revoked.kept) == ((TEST_IP3,), (TEST_NET1_HOST,))


def test_revoking_a_range_reseeds_the_host_it_covered(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """A host the range covered had no element of its own; with the range gone it takes one."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.write_tier("override", f"+{TEST_NET1}\n+{TEST_DOMAIN} %expires={_SOON}\n")
    bundle.override_resolved.write_text(f"{TEST_DOMAIN} {TEST_NET1_HOST}\n")

    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP):
        revoked = harness.mode.revoke_override("test-ctr", TEST_NET1)

    assert (revoked.closed, revoked.kept) == ((TEST_NET1,), ())
    (stdin,) = _stdins(harness)
    assert f"{TEST_NET1_HOST} timeout" in stdin
    assert TEST_NET1 not in stdin


_RUNNING_PID = "4242"
"""What ``podman inspect --format {{.State.Pid}}`` prints for a running container."""


def _listings_fail(harness: HookModeHarness, error: ExecError) -> None:
    """Make every ruleset listing raise *error* — a podman or nsenter hiccup; other nft calls pass."""

    def _nft(_container: str, *args: str, **_kwargs: object) -> str:
        if "list" in args:
            raise error
        return ""

    harness.runner.nft_via_nsenter.side_effect = _nft


_PODMAN_KNOWS_IT = 0
"""``podman container exists``'s exit status for a container podman has."""

_PODMAN_KNOWS_NO_SUCH_CONTAINER = 1
"""``podman container exists``'s exit status for a container podman has no record of."""

_PODMAN_CANNOT_LOOK = 125
"""``podman container exists``'s exit status when podman itself failed."""

_NO_SUCH_CONTAINER = ExecError(["podman", "inspect"], 125, 'Error: no such object: "test-ctr"')
"""``podman inspect`` on a removed container: the same exit status as any failure to look."""


def _podman_container_exists_exits(harness: HookModeHarness, status: int) -> None:
    """Make ``podman container exists`` exit with *status*; every other command runs as before."""

    def _run(cmd: list[str], **_kwargs: object) -> object:
        if cmd[:3] == ["podman", "container", "exists"] and status:
            raise ExecError(cmd, status, "")
        return mock.DEFAULT

    harness.runner.run.side_effect = _run


def _removed(harness: HookModeHarness) -> HookModeHarness:
    """Make podman report the harness's container gone — inspected, listed or looked up."""
    _listings_fail(harness, _NO_SUCH_CONTAINER)
    harness.runner.podman_inspect.side_effect = _NO_SUCH_CONTAINER
    _podman_container_exists_exits(harness, _PODMAN_KNOWS_NO_SUCH_CONTAINER)
    return harness


@pytest.mark.parametrize(
    ("pid", "expected"),
    [
        pytest.param(_NO_PROCESS, ShieldState.OFFLINE, id="no-process"),
        pytest.param("", ShieldState.OFFLINE, id="no-pid"),
        pytest.param(_RUNNING_PID, ShieldState.ERROR, id="running"),
    ],
)
def test_confirmed_posture_asks_podman_before_calling_an_unreadable_ruleset_offline(
    make_hook_mode: HookModeHarnessFactory, pid: str, expected: ShieldState
) -> None:
    """A failed listing is OFFLINE only when podman says no process runs; otherwise it is ERROR."""
    harness = make_hook_mode()
    _listings_fail(harness, ExecError(["nsenter"], 1, "transient"))
    harness.runner.podman_inspect.return_value = pid

    assert harness.mode.confirmed_posture("test-ctr") is expected
    harness.runner.podman_inspect.assert_called_once_with("test-ctr", "{{.State.Pid}}")


def test_confirmed_posture_takes_a_read_ruleset_at_its_word(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """A posture the listing showed needs no second opinion: podman is never asked."""
    harness = make_hook_mode()

    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.DOWN):
        assert harness.mode.confirmed_posture("test-ctr") is ShieldState.DOWN

    harness.runner.podman_inspect.assert_not_called()


def test_confirmed_posture_reads_a_running_container_with_no_ruleset_as_error(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """An unshielded container runs: a change takes the live path and reports its failure there."""
    harness = make_hook_mode()
    harness.runner.nft_via_nsenter.return_value = ""
    harness.runner.podman_inspect.return_value = _RUNNING_PID

    assert harness.mode.shield_state("test-ctr") is ShieldState.OFFLINE
    assert harness.mode.confirmed_posture("test-ctr") is ShieldState.ERROR


def test_confirmed_posture_reads_a_container_podman_has_no_record_of_as_offline(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """A removed container runs no process: no inspect error is taken for podman failing to look."""
    harness = _removed(make_hook_mode())

    assert harness.mode.confirmed_posture("test-ctr") is ShieldState.OFFLINE
    harness.runner.run.assert_called_once_with(["podman", "container", "exists", "test-ctr"])


@pytest.mark.parametrize(
    "exists_status",
    [
        pytest.param(_PODMAN_KNOWS_IT, id="podman-has-it"),
        pytest.param(_PODMAN_CANNOT_LOOK, id="podman-cannot-look"),
    ],
)
def test_confirmed_posture_refuses_to_guess_when_podman_cannot_say_either(
    make_hook_mode: HookModeHarnessFactory, exists_status: int
) -> None:
    """No listing and no podman answer: the caller is told so before it changes anything."""
    harness = make_hook_mode()
    locked = ExecError(["podman", "inspect"], 125, "database is locked")
    _listings_fail(harness, locked)
    harness.runner.podman_inspect.side_effect = locked
    _podman_container_exists_exits(harness, exists_status)

    with pytest.raises(RuntimeError, match="nothing was changed, so try again") as ctx:
        harness.mode.confirmed_posture("test-ctr")

    assert ctx.value.__cause__ is locked


def test_confirmed_posture_refuses_to_guess_when_podman_cannot_even_be_executed(
    make_hook_mode: HookModeHarnessFactory,
) -> None:
    """With podman not executable, ``container exists`` cannot say the container is gone either."""
    harness = make_hook_mode()
    locked = ExecError(["podman", "inspect"], 125, "database is locked")
    _listings_fail(harness, locked)
    harness.runner.podman_inspect.side_effect = locked
    harness.runner.run.side_effect = PermissionError("podman")

    with pytest.raises(RuntimeError, match="nothing was changed, so try again") as ctx:
        harness.mode.confirmed_posture("test-ctr")

    assert ctx.value.__cause__ is locked
    harness.runner.run.assert_called_once_with(["podman", "container", "exists", "test-ctr"])


def test_revoke_override_on_a_running_container_whose_ruleset_cannot_be_read_still_swaps(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """A failed listing reads as OFFLINE — podman says the container runs, so it is no stopped one.

    Taken for stopped, the revoke would report "at next start" over a kernel
    still holding the override, and rewrite the dnsmasq config on disk where
    the running dnsmasq never reads it — and no later reconcile would find a
    difference left to reload.  It swaps t10 and relaunches dnsmasq instead.
    """
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.runner.podman_inspect.return_value = _RUNNING_PID
    bundle = _launched(config.state_dir, DnsTier.DNSMASQ_LIVE)
    _vault_host_punched_through(bundle)
    _listings_fail(harness, ExecError(["nsenter"], 1, "transient"))

    with mock.patch.object(HookMode, "_reload_dnsmasq", return_value=True) as reload_dnsmasq:
        revoked = harness.mode.revoke_override("test-ctr", VAULT_HOST)

    assert revoked == OverrideRevocation(target=VAULT_HOST, closed=(TEST_IP3,), live=True)
    assert any(
        stdin.startswith("flush set inet terok_shield t10_override_v4")
        for stdin in _stdins(harness)
    )
    harness.audit.log_event.assert_called_once_with(
        "test-ctr", "override_revoked", dest=VAULT_HOST, detail=f"expires={_SOON}; reason={_REASON}"
    )
    reload_dnsmasq.assert_called_once()


def test_revoke_override_changes_nothing_when_nothing_says_whether_the_container_runs(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """No listing and no podman answer: the revoke refuses to guess, so it can simply be retried."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.DNSMASQ_LIVE)
    _vault_host_punched_through(bundle)
    tier, conf = bundle.tier_path("override").read_text(), bundle.dnsmasq_conf.read_text()
    locked = ExecError(["podman", "inspect"], 125, "database is locked")
    _listings_fail(harness, locked)
    harness.runner.podman_inspect.side_effect = locked
    _podman_container_exists_exits(harness, _PODMAN_CANNOT_LOOK)

    with pytest.raises(
        RuntimeError, match="podman cannot say whether it is running.*database is locked"
    ):
        harness.mode.revoke_override("test-ctr", VAULT_HOST)

    assert bundle.tier_path("override").read_text() == tier
    assert bundle.dnsmasq_conf.read_text() == conf
    assert _stdins(harness) == [""]  # the one listing, and no swap
    harness.audit.log_event.assert_not_called()


def test_revoke_override_on_a_removed_container_rewrites_its_bundle_for_a_recreate(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """Podman has no such container: nothing runs, so the bundle a recreate starts from takes the revoke."""
    config = make_config()
    harness = _removed(make_hook_mode(config=config))
    bundle = _launched(config.state_dir, DnsTier.DNSMASQ_LIVE)
    _vault_host_punched_through(bundle)

    with mock.patch.object(HookMode, "_reload_dnsmasq") as reload_dnsmasq:
        revoked = harness.mode.revoke_override("test-ctr", VAULT_HOST)

    assert revoked == OverrideRevocation(target=VAULT_HOST, closed=(TEST_IP3,), live=False)
    assert bundle.override_entries(VAULT_HOST) == []
    assert f"local=/{VAULT_HOST}/" in bundle.dnsmasq_conf.read_text()
    assert _stdins(harness) == [""]  # the one listing, and no swap
    reload_dnsmasq.assert_not_called()
    harness.audit.log_event.assert_called_once_with(
        "test-ctr",
        "override_revoked",
        dest=VAULT_HOST,
        detail=f"expires={_SOON}; reason={_REASON}; at next start",
    )


def test_revoke_override_says_when_no_dnsmasq_runs_to_sinkhole_the_name(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """No PID file: nothing to relaunch — the revoke says so, and the config on disk sinkholes the name.

    A quiet return would report the name closed while the config the next
    start reads still punched it through, and an orphaned dnsmasq that lost
    its PID file would keep serving it.
    """
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.DNSMASQ_LIVE)
    _vault_host_punched_through(bundle)
    assert not bundle.dnsmasq_pid.exists()

    with (
        mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP),
        pytest.raises(RuntimeError, match="sinkhole the name again: no dnsmasq runs for test-ctr"),
    ):
        harness.mode.revoke_override("test-ctr", VAULT_HOST)

    assert f"local=/{VAULT_HOST}/" in bundle.dnsmasq_conf.read_text()
    harness.audit.log_event.assert_called_once_with(  # the kernel let go: that much is revoked
        "test-ctr", "override_revoked", dest=VAULT_HOST, detail=f"expires={_SOON}; reason={_REASON}"
    )


def test_a_rebuild_with_no_dnsmasq_running_still_closes_the_name_on_disk(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A posture change is best-effort: it warns, and leaves a config the next start can trust."""
    harness, bundle = _transition_harness(make_hook_mode, make_config, DnsTier.DNSMASQ_LIVE)
    after = _expired_override_punched_through(bundle)

    with (
        caplog.at_level(logging.WARNING),
        mock.patch("terok_shield.hooks.mode.time.time", return_value=after),
    ):
        harness.mode.shield_up("test-ctr")

    assert f"local=/{VAULT_HOST}/" in bundle.dnsmasq_conf.read_text()
    assert any("no dnsmasq runs for test-ctr" in record.message for record in caplog.records)


def test_revoke_override_finds_the_target_however_its_case_is_typed(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """Names compare case-insensitively, so an operator's capitals end the recorded override."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.upsert_override(TEST_DOMAIN, _SOON.isoformat(), reason=_REASON)
    bundle.override_resolved.write_text(f"{TEST_DOMAIN} {TEST_IP3}\n")

    with mock.patch.object(HookMode, "shield_state", return_value=ShieldState.UP):
        revoked = harness.mode.revoke_override("test-ctr", TEST_DOMAIN.upper())

    assert revoked == OverrideRevocation(target=TEST_DOMAIN, closed=(TEST_IP3,), live=True)
    assert bundle.override_entries(TEST_DOMAIN) == []


def test_revoke_override_takes_no_trailing_dot_as_no_grant_does(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """The target grammar takes no trailing dot — a revoke spells a name the way a grant must."""
    config = make_config()
    harness = make_hook_mode(config=config)
    bundle = _launched(config.state_dir, DnsTier.LOOKUP)
    bundle.upsert_override(TEST_DOMAIN, _SOON.isoformat(), reason=_REASON)

    with pytest.raises(ValueError, match="invalid target"):
        harness.mode.revoke_override("test-ctr", f"{TEST_DOMAIN}.")

    assert [entry.target for entry in bundle.override_entries(TEST_DOMAIN)] == [TEST_DOMAIN]


# ── rotation risk: notes and the stale-cache refresh ─────────────────────


def _transition_harness(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory, tier: DnsTier
) -> tuple[HookModeHarness, StateBundle]:
    """A harness whose up/down rebuilds succeed against a launched bundle on *tier*."""
    config = make_config()
    harness = _ready_to_rebuild(make_hook_mode(config=config))
    return harness, _launched(config.state_dir, tier)


def _notes(harness: HookModeHarness) -> list[str]:
    """The ``note`` details the harness's audit logger received, in order."""
    return [
        c.kwargs["detail"]
        for c in harness.audit.log_event.call_args_list
        if c.args[1:2] == ("note",)
    ]


def _pinned_policy(bundle: StateBundle) -> None:
    """One allowlisted name and one security-tier name — both pinned on the lookup tier."""
    bundle.write_tier("project_allow", f"+{TEST_DOMAIN}\n")
    bundle.write_tier("security_deny", f"-{VAULT_HOST}\n")


def test_authoring_notes_what_the_tier_pins(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """Launch and restart share the note: the allow line and the deny line, launch-worded."""
    config = make_config()
    harness = make_hook_mode(config=config)
    harness.profiles.compose_profiles.return_value = []
    _launched(config.state_dir, DnsTier.LOOKUP)

    harness.mode.refresh("test", [], security_deny=[VAULT_HOST], project_allow=[TEST_DOMAIN])

    allow, deny = _notes(harness)
    assert TEST_DOMAIN in allow
    assert VAULT_HOST in deny
    assert "whenever the shield is down" in deny


def test_shield_up_notes_every_pinned_kind(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """Raised, allowlisted names can break and the deny can leak — both are noted."""
    harness, bundle = _transition_harness(make_hook_mode, make_config, DnsTier.LOOKUP)
    _pinned_policy(bundle)
    harness.mode.shield_up("test-ctr")
    allow, deny = _notes(harness)
    assert TEST_DOMAIN in allow
    assert "a bypass window is open" in deny


def test_shield_down_notes_the_deny_alone_and_disengaged_nothing(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """Down, only the security tier still means to hold; disengaged, nothing does."""
    harness, bundle = _transition_harness(make_hook_mode, make_config, DnsTier.LOOKUP)
    _pinned_policy(bundle)
    harness.mode.shield_down("test-ctr")
    (deny,) = _notes(harness)
    assert "the shield is down" in deny

    harness.audit.log_event.reset_mock()
    harness.mode.shield_down("test-ctr", disengaged=True)
    assert _notes(harness) == []


@pytest.mark.parametrize("transition", ["up", "down"])
def test_a_posture_change_re_resolves_pinned_names_before_it_rebuilds(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory, transition: str
) -> None:
    """A container raised after hours down must not come up seeded with its launch-time addresses."""
    harness, _ = _transition_harness(make_hook_mode, make_config, DnsTier.GETENT)
    order = mock.Mock()

    def _nft(*_args: object, **_kwargs: object) -> str:
        order.nft()
        return ""

    harness.runner.nft_via_nsenter.side_effect = _nft
    with mock.patch.object(HookMode, "_resolve_policy", side_effect=lambda *_a: order.resolve()):
        getattr(harness.mode, f"shield_{transition}")("test-ctr")

    assert order.mock_calls[0] == mock.call.resolve()
    assert mock.call.nft() in order.mock_calls


def test_the_live_tier_follows_dns_and_skips_the_refresh(
    make_hook_mode: HookModeHarnessFactory, make_config: ConfigFactory
) -> None:
    """dnsmasq-live tracks every answer itself — nothing to re-resolve on a posture change."""
    harness, _ = _transition_harness(make_hook_mode, make_config, DnsTier.DNSMASQ_LIVE)
    with mock.patch.object(HookMode, "_resolve_policy") as resolve:
        harness.mode.shield_up("test-ctr")
    resolve.assert_not_called()


def test_a_failed_refresh_never_blocks_the_posture_change(
    make_hook_mode: HookModeHarnessFactory,
    make_config: ConfigFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Best-effort: the caches stand as they were, and the shield still goes up."""
    harness, _ = _transition_harness(make_hook_mode, make_config, DnsTier.LOOKUP)
    with (
        mock.patch.object(HookMode, "_resolve_policy", side_effect=OSError("disk full")),
        caplog.at_level(logging.WARNING),
    ):
        harness.mode.shield_up("test-ctr")
    harness.ruleset.verify_up.assert_called_once()
    assert any("disk full" in record.message for record in caplog.records)
