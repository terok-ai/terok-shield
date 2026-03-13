# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Shield facade class (__init__.py)."""

import tempfile
from collections.abc import Iterator
from pathlib import Path
from unittest import mock

import pytest

from terok_shield import Shield, ShieldConfig, ShieldState

from ..testnet import TEST_DOMAIN, TEST_IP1, TEST_IP2


class TestShieldInit:
    """Test Shield construction and collaborator wiring."""

    def test_default_collaborators(self) -> None:
        """Shield creates default collaborators when none are injected."""
        with tempfile.TemporaryDirectory() as tmp:
            shield = Shield(ShieldConfig(state_dir=Path(tmp)))
            assert shield.runner is not None
            assert shield.audit is not None
            assert shield.dns is not None
            assert shield.profiles is not None
            assert shield.ruleset is not None

    def test_injected_collaborators(self) -> None:
        """Shield uses injected collaborators when provided."""
        runner = mock.MagicMock()
        audit = mock.MagicMock()
        dns = mock.MagicMock()
        profiles = mock.MagicMock()
        ruleset = mock.MagicMock()

        with tempfile.TemporaryDirectory() as tmp:
            shield = Shield(
                ShieldConfig(state_dir=Path(tmp)),
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

    def test_unsupported_mode_raises(self) -> None:
        """ValueError for unsupported mode in _create_mode."""
        with tempfile.TemporaryDirectory() as tmp:
            config = ShieldConfig(state_dir=Path(tmp))
            shield = Shield.__new__(Shield)
            shield.config = config
            shield.runner = mock.MagicMock()
            shield.audit = mock.MagicMock()
            shield.dns = mock.MagicMock()
            shield.profiles = mock.MagicMock()
            shield.ruleset = mock.MagicMock()

            fake_mode = mock.MagicMock()
            fake_mode.__eq__ = lambda self, other: False
            with pytest.raises(ValueError):
                shield._create_mode(fake_mode)


class TestShieldStatus:
    """Test Shield.status()."""

    def test_returns_expected_keys(self) -> None:
        """status() returns dict with mode, profiles, audit_enabled."""
        profiles = mock.MagicMock()
        profiles.list_profiles.return_value = ["base", "dev-standard"]
        audit = mock.MagicMock()

        shield = _make_shield(profiles=profiles, audit=audit)
        result = shield.status()

        assert result["mode"] == "hook"
        assert result["profiles"] == ["base", "dev-standard"]
        assert result["audit_enabled"]


class TestShieldPreStart:
    """Test Shield.pre_start()."""

    def test_dispatches_to_mode(self) -> None:
        """pre_start() calls mode backend with container and profiles."""
        mode = mock.MagicMock()
        mode.pre_start.return_value = ["--network", "pasta:"]
        audit = mock.MagicMock()
        shield = _make_shield(mode=mode, audit=audit)

        result = shield.pre_start("test-ctr", ["dev-standard"])
        mode.pre_start.assert_called_once_with("test-ctr", ["dev-standard"])
        assert result == ["--network", "pasta:"]
        audit.log_event.assert_called_once()

    def test_uses_default_profiles(self) -> None:
        """pre_start() uses config.default_profiles when profiles is None."""
        mode = mock.MagicMock()
        mode.pre_start.return_value = []
        audit = mock.MagicMock()
        with tempfile.TemporaryDirectory() as tmp:
            config = ShieldConfig(state_dir=Path(tmp), default_profiles=("base",))
            shield = _make_shield(config=config, mode=mode, audit=audit)

            shield.pre_start("test-ctr")
            mode.pre_start.assert_called_once_with("test-ctr", ["base"])


class TestShieldAllow:
    """Test Shield.allow()."""

    def test_allows_ip_directly(self) -> None:
        """allow() passes an IP directly to mode.allow_ip."""
        mode = mock.MagicMock()
        audit = mock.MagicMock()
        shield = _make_shield(mode=mode, audit=audit)

        result = shield.allow("test-ctr", TEST_IP1)
        mode.allow_ip.assert_called_once_with("test-ctr", TEST_IP1)
        assert result == [TEST_IP1]

    def test_resolves_domain(self) -> None:
        """allow() resolves domains via dns.resolve_domains."""
        mode = mock.MagicMock()
        dns = mock.MagicMock()
        dns.resolve_domains.return_value = [TEST_IP1, TEST_IP2]
        audit = mock.MagicMock()
        shield = _make_shield(mode=mode, dns=dns, audit=audit)

        result = shield.allow("test-ctr", TEST_DOMAIN)
        dns.resolve_domains.assert_called_once_with([TEST_DOMAIN])
        assert mode.allow_ip.call_count == 2
        assert result == [TEST_IP1, TEST_IP2]

    def test_swallows_exceptions(self) -> None:
        """allow() swallows exceptions from individual allow_ip calls."""
        mode = mock.MagicMock()
        mode.allow_ip.side_effect = RuntimeError("nft failed")
        audit = mock.MagicMock()
        shield = _make_shield(mode=mode, audit=audit)

        result = shield.allow("test-ctr", TEST_IP1)
        assert result == []


class TestShieldDeny:
    """Test Shield.deny()."""

    def test_denies_ip_directly(self) -> None:
        """deny() passes an IP directly to mode.deny_ip."""
        mode = mock.MagicMock()
        audit = mock.MagicMock()
        shield = _make_shield(mode=mode, audit=audit)

        result = shield.deny("test-ctr", TEST_IP1)
        mode.deny_ip.assert_called_once_with("test-ctr", TEST_IP1)
        assert result == [TEST_IP1]

    def test_swallows_exceptions(self) -> None:
        """deny() swallows exceptions from deny_ip (best-effort)."""
        mode = mock.MagicMock()
        mode.deny_ip.side_effect = RuntimeError("nft failed")
        audit = mock.MagicMock()
        shield = _make_shield(mode=mode, audit=audit)

        result = shield.deny("test-ctr", TEST_IP1)
        assert result == []


class TestShieldRules:
    """Test Shield.rules()."""

    def test_delegates_to_mode(self) -> None:
        """rules() calls mode.list_rules."""
        mode = mock.MagicMock()
        mode.list_rules.return_value = "table inet terok_shield {}"
        shield = _make_shield(mode=mode)

        result = shield.rules("test-ctr")
        mode.list_rules.assert_called_once_with("test-ctr")
        assert "terok_shield" in result


class TestShieldDown:
    """Test Shield.down()."""

    def test_delegates_to_mode(self) -> None:
        """down() calls mode.shield_down and logs event."""
        mode = mock.MagicMock()
        audit = mock.MagicMock()
        shield = _make_shield(mode=mode, audit=audit)

        shield.down("test-ctr")
        mode.shield_down.assert_called_once_with("test-ctr", allow_all=False)
        audit.log_event.assert_called_once_with("test-ctr", "shield_down", detail=None)

    def test_allow_all_flag(self) -> None:
        """down() passes allow_all flag and logs detail."""
        mode = mock.MagicMock()
        audit = mock.MagicMock()
        shield = _make_shield(mode=mode, audit=audit)

        shield.down("test-ctr", allow_all=True)
        mode.shield_down.assert_called_once_with("test-ctr", allow_all=True)
        audit.log_event.assert_called_once_with("test-ctr", "shield_down", detail="allow_all=True")


class TestShieldUp:
    """Test Shield.up()."""

    def test_delegates_to_mode(self) -> None:
        """up() calls mode.shield_up and logs event."""
        mode = mock.MagicMock()
        audit = mock.MagicMock()
        shield = _make_shield(mode=mode, audit=audit)

        shield.up("test-ctr")
        mode.shield_up.assert_called_once_with("test-ctr")
        audit.log_event.assert_called_once_with("test-ctr", "shield_up")


class TestShieldState:
    """Test Shield.state()."""

    def test_delegates_to_mode(self) -> None:
        """state() calls mode.shield_state."""
        mode = mock.MagicMock()
        mode.shield_state.return_value = ShieldState.UP
        shield = _make_shield(mode=mode)

        result = shield.state("test-ctr")
        assert result == ShieldState.UP


class TestShieldPreview:
    """Test Shield.preview()."""

    def test_default_preview(self) -> None:
        """preview() generates hook ruleset by default."""
        mode = mock.MagicMock()
        mode.preview.return_value = "table inet terok_shield { policy drop }"
        shield = _make_shield(mode=mode)

        result = shield.preview()
        mode.preview.assert_called_once_with(down=False, allow_all=False)
        assert "policy drop" in result

    def test_bypass_preview(self) -> None:
        """preview(down=True) generates bypass ruleset."""
        mode = mock.MagicMock()
        mode.preview.return_value = "bypass"
        shield = _make_shield(mode=mode)

        result = shield.preview(down=True, allow_all=True)
        mode.preview.assert_called_once_with(down=True, allow_all=True)
        assert result == "bypass"


class TestShieldResolve:
    """Test Shield.resolve()."""

    def test_resolves_profiles(self) -> None:
        """resolve() composes profiles and resolves DNS."""
        profiles = mock.MagicMock()
        profiles.compose_profiles.return_value = [TEST_DOMAIN]
        dns = mock.MagicMock()
        dns.resolve_and_cache.return_value = [TEST_IP1]
        shield = _make_shield(profiles=profiles, dns=dns)

        result = shield.resolve(["dev-standard"])
        profiles.compose_profiles.assert_called_once_with(["dev-standard"])
        dns.resolve_and_cache.assert_called_once()
        assert result == [TEST_IP1]

    def test_empty_profiles_returns_empty(self) -> None:
        """resolve() returns empty list for empty profile entries."""
        profiles = mock.MagicMock()
        profiles.compose_profiles.return_value = []
        shield = _make_shield(profiles=profiles)

        result = shield.resolve(["empty"])
        assert result == []

    def test_force_sets_max_age_zero(self) -> None:
        """resolve(force=True) passes max_age=0."""
        profiles = mock.MagicMock()
        profiles.compose_profiles.return_value = [TEST_DOMAIN]
        dns = mock.MagicMock()
        dns.resolve_and_cache.return_value = [TEST_IP1]
        shield = _make_shield(profiles=profiles, dns=dns)

        shield.resolve(["dev-standard"], force=True)
        call_kwargs = dns.resolve_and_cache.call_args[1]
        assert call_kwargs["max_age"] == 0

    def test_default_profiles(self) -> None:
        """resolve() uses config.default_profiles when None."""
        with tempfile.TemporaryDirectory() as tmp:
            config = ShieldConfig(state_dir=Path(tmp), default_profiles=("base",))
            profiles = mock.MagicMock()
            profiles.compose_profiles.return_value = []
            shield = _make_shield(config=config, profiles=profiles)

            shield.resolve()
            profiles.compose_profiles.assert_called_once_with(["base"])


class TestShieldDelegationMethods:
    """Test simple delegation methods on Shield."""

    def test_profiles_list(self) -> None:
        """profiles_list() delegates to profiles.list_profiles."""
        profiles = mock.MagicMock()
        profiles.list_profiles.return_value = ["base", "dev"]
        shield = _make_shield(profiles=profiles)
        assert shield.profiles_list() == ["base", "dev"]

    def test_tail_log(self) -> None:
        """tail_log() delegates to audit.tail_log."""
        audit = mock.MagicMock()
        audit.tail_log.return_value = iter([{"action": "setup"}])
        shield = _make_shield(audit=audit)
        result = shield.tail_log(10)
        audit.tail_log.assert_called_once_with(10)
        assert isinstance(result, Iterator)

    def test_compose_profiles(self) -> None:
        """compose_profiles() delegates to profiles.compose_profiles."""
        profiles = mock.MagicMock()
        profiles.compose_profiles.return_value = ["github.com"]
        shield = _make_shield(profiles=profiles)
        result = shield.compose_profiles(["dev-standard"])
        profiles.compose_profiles.assert_called_once_with(["dev-standard"])
        assert result == ["github.com"]


# ── Helper ──────────────────────────────────────────────


_DISPOSABLE_DIRS: list[tempfile.TemporaryDirectory] = []
"""Managed temp dirs for mock-only tests (cleaned up at process exit)."""


def _make_shield(
    config: ShieldConfig | None = None,
    *,
    mode: mock.MagicMock | None = None,
    audit: mock.MagicMock | None = None,
    dns: mock.MagicMock | None = None,
    profiles: mock.MagicMock | None = None,
    ruleset: mock.MagicMock | None = None,
) -> Shield:
    """Create a Shield with mock collaborators.  Bypasses _create_mode."""
    if config is None:
        td = tempfile.TemporaryDirectory()
        _DISPOSABLE_DIRS.append(td)
        config = ShieldConfig(state_dir=Path(td.name))
    s = Shield.__new__(Shield)
    s.config = config
    s.runner = mock.MagicMock()
    s.audit = audit or mock.MagicMock()
    s.dns = dns or mock.MagicMock()
    s.profiles = profiles or mock.MagicMock()
    s.ruleset = ruleset or mock.MagicMock()
    s._mode = mode or mock.MagicMock()
    return s
