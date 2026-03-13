# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Assembly tests: real class interactions without external dependencies.

These tests exercise real constructor signatures, collaborator wiring,
and cross-module data flow — catching API contract regressions that
integration tests would find only with podman/nft. No subprocess calls,
no mocks (unless strictly needed for the runner layer).
"""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import pytest

from terok_shield import Shield, ShieldConfig, state
from terok_shield.audit import AuditLogger
from terok_shield.dns import DnsResolver
from terok_shield.mode_hook import HookMode
from terok_shield.nft import RulesetBuilder
from terok_shield.profiles import ProfileLoader

from ..testfs import FAKE_RESOLVED_DIR, NFT_BINARY
from ..testnet import TEST_DOMAIN, TEST_IP1, TEST_IP2
from .helpers import write_lines


@dataclass
class HookModeHarness:
    """A real ``HookMode`` with exposed mock runner/ruleset collaborators."""

    mode: HookMode
    state_dir: Path
    runner: mock.MagicMock
    ruleset: mock.MagicMock


@pytest.fixture
def make_hook_mode(tmp_path: Path) -> Callable[..., HookModeHarness]:
    """Create a HookMode harness with real config and selected mock collaborators."""

    def _make_hook_mode(
        *,
        state_dir: Path | None = None,
        runner: mock.MagicMock | None = None,
        ruleset: mock.MagicMock | None = None,
    ) -> HookModeHarness:
        effective_state_dir = state_dir or tmp_path
        state.ensure_state_dirs(effective_state_dir)
        runner = runner or mock.MagicMock()
        ruleset = ruleset or mock.MagicMock()
        return HookModeHarness(
            mode=HookMode(
                config=ShieldConfig(state_dir=effective_state_dir),
                runner=runner,
                audit=mock.MagicMock(),
                dns=mock.MagicMock(),
                profiles=mock.MagicMock(),
                ruleset=ruleset,
            ),
            state_dir=effective_state_dir,
            runner=runner,
            ruleset=ruleset,
        )

    return _make_hook_mode


def test_shield_config_requires_state_dir() -> None:
    """ShieldConfig() without state_dir raises TypeError."""
    with pytest.raises(TypeError):
        ShieldConfig()  # type: ignore[call-arg]


def test_shield_config_accepts_state_dir(tmp_path: Path) -> None:
    """ShieldConfig(state_dir=...) constructs successfully."""
    assert ShieldConfig(state_dir=tmp_path).state_dir == tmp_path


def test_dns_resolver_stateless_constructor() -> None:
    """DnsResolver takes only runner=, not resolved_dir."""
    runner = mock.MagicMock()
    assert DnsResolver(runner=runner)._runner is runner


def test_dns_resolver_rejects_resolved_dir() -> None:
    """DnsResolver does not accept resolved_dir kwarg."""
    with pytest.raises(TypeError):
        DnsResolver(resolved_dir=FAKE_RESOLVED_DIR, runner=mock.MagicMock())  # type: ignore[call-arg]


def test_audit_logger_accepts_audit_path(tmp_path: Path) -> None:
    """AuditLogger takes audit_path=, not log_dir."""
    assert isinstance(AuditLogger(audit_path=state.audit_path(tmp_path)), AuditLogger)


def test_ruleset_builder_constructor() -> None:
    """RulesetBuilder accepts loopback_ports."""
    assert isinstance(RulesetBuilder(loopback_ports=(8080, 9090)), RulesetBuilder)


def test_profile_loader_constructor(tmp_path: Path) -> None:
    """ProfileLoader accepts user_dir."""
    assert isinstance(ProfileLoader(user_dir=tmp_path), ProfileLoader)


def test_resolve_and_cache_accepts_cache_path(tmp_path: Path) -> None:
    """resolve_and_cache(entries, cache_path) writes to the given path."""
    runner = mock.MagicMock()
    runner.dig_all.return_value = [TEST_IP1]
    resolver = DnsResolver(runner=runner)

    cache_path = state.profile_allowed_path(tmp_path)
    ips = resolver.resolve_and_cache([TEST_DOMAIN], cache_path)
    assert TEST_IP1 in ips
    assert cache_path.is_file()
    assert TEST_IP1 in cache_path.read_text()


def test_resolve_and_cache_reuses_fresh_cache(tmp_path: Path) -> None:
    """A fresh cache suppresses a second DNS lookup."""
    runner = mock.MagicMock()
    runner.dig_all.return_value = [TEST_IP1]
    resolver = DnsResolver(runner=runner)
    cache_path = state.profile_allowed_path(tmp_path)

    resolver.resolve_and_cache([TEST_DOMAIN], cache_path)
    runner.dig_all.reset_mock()
    assert resolver.resolve_and_cache([TEST_DOMAIN], cache_path, max_age=3600) == [TEST_IP1]
    runner.dig_all.assert_not_called()


def test_allow_ip_writes_to_live_allowed(
    make_hook_mode: Callable[..., HookModeHarness], tmp_path: Path
) -> None:
    """allow_ip() persists live allowlist updates to live.allowed."""
    harness = make_hook_mode(state_dir=tmp_path)
    harness.runner.nft_via_nsenter.return_value = ""
    harness.ruleset.safe_ip.return_value = TEST_IP1

    harness.mode.allow_ip("test-ctr", TEST_IP1)
    assert TEST_IP1 in state.live_allowed_path(tmp_path).read_text()


def test_deny_ip_removes_from_live_allowed(
    make_hook_mode: Callable[..., HookModeHarness], tmp_path: Path
) -> None:
    """deny_ip() removes the IP from live.allowed."""
    live_path = write_lines(state.live_allowed_path(tmp_path), [TEST_IP1, TEST_IP2])
    harness = make_hook_mode(state_dir=tmp_path)
    harness.runner.nft_via_nsenter.return_value = ""
    harness.ruleset.safe_ip.return_value = TEST_IP1

    harness.mode.deny_ip("test-ctr", TEST_IP1)
    content = live_path.read_text()
    assert TEST_IP1 not in content
    assert TEST_IP2 in content


@pytest.mark.parametrize(
    ("profile_lines", "live_lines", "expected"),
    [
        pytest.param([TEST_IP1], [TEST_IP2], [TEST_IP1, TEST_IP2], id="merges-both-files"),
        pytest.param([TEST_IP1], [TEST_IP1, TEST_IP2], [TEST_IP1, TEST_IP2], id="deduplicates"),
    ],
)
def test_read_allowed_ips_merges_state_files(
    tmp_path: Path,
    profile_lines: list[str],
    live_lines: list[str],
    expected: list[str],
) -> None:
    """state.read_allowed_ips() merges profile.allowed and live.allowed."""
    state.ensure_state_dirs(tmp_path)
    write_lines(state.profile_allowed_path(tmp_path), profile_lines)
    write_lines(state.live_allowed_path(tmp_path), live_lines)
    assert state.read_allowed_ips(tmp_path) == expected


def test_shield_up_reads_live_allowed(
    make_hook_mode: Callable[..., HookModeHarness], tmp_path: Path
) -> None:
    """shield_up() re-adds persisted live.allowed IPs."""
    write_lines(state.live_allowed_path(tmp_path), [TEST_IP1, TEST_IP2])
    harness = make_hook_mode(state_dir=tmp_path)
    harness.runner.nft_via_nsenter.return_value = ""
    harness.ruleset.build_hook.return_value = "table inet terok_shield {}"
    harness.ruleset.add_elements_dual.return_value = "add element ..."
    harness.ruleset.verify_hook.return_value = []

    harness.mode.shield_up("test-ctr")
    harness.ruleset.add_elements_dual.assert_called_once_with([TEST_IP1, TEST_IP2])


@mock.patch("terok_shield.run.find_nft", return_value=NFT_BINARY)
def test_shield_constructs_real_collaborators(_find: mock.Mock, tmp_path: Path) -> None:
    """Shield(ShieldConfig(...)) wires the default real collaborators."""
    shield = Shield(ShieldConfig(state_dir=tmp_path))
    assert isinstance(shield.audit, AuditLogger)
    assert isinstance(shield.dns, DnsResolver)
    assert isinstance(shield.profiles, ProfileLoader)
    assert isinstance(shield.ruleset, RulesetBuilder)


@mock.patch("terok_shield.run.find_nft", return_value=NFT_BINARY)
def test_shield_audit_path_derived_from_state_dir(_find: mock.Mock, tmp_path: Path) -> None:
    """Shield's AuditLogger writes to state_dir/audit.jsonl."""
    shield = Shield(ShieldConfig(state_dir=tmp_path))
    assert shield.audit._audit_path == state.audit_path(tmp_path)


@mock.patch("terok_shield.run.find_nft", return_value=NFT_BINARY)
def test_shield_resolve_uses_profile_allowed_path(_find: mock.Mock, tmp_path: Path) -> None:
    """Shield.resolve() caches resolved entries in state_dir/profile.allowed."""
    dns = mock.MagicMock()
    dns.resolve_and_cache.return_value = [TEST_IP1]
    profiles = mock.MagicMock()
    profiles.compose_profiles.return_value = [TEST_DOMAIN]

    Shield(ShieldConfig(state_dir=tmp_path), dns=dns, profiles=profiles).resolve(["dev-standard"])

    args = dns.resolve_and_cache.call_args.args
    assert args[0] == [TEST_DOMAIN]
    assert args[1] == state.profile_allowed_path(tmp_path)
