# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the public API (terok_shield.__init__)."""

import unittest
from unittest import mock

from terok_shield import (
    ShieldConfig,
    ShieldMode,
    shield_allow,
    shield_deny,
    shield_pre_start,
    shield_resolve,
    shield_rules,
    shield_setup,
    shield_status,
)

from ..testnet import TEST_IP1


class TestShieldSetup(unittest.TestCase):
    """Test shield_setup dispatch."""

    @mock.patch("terok_shield.mode_hook.setup")
    def test_hook_mode(self, mock_setup):
        """shield_setup dispatches to mode_hook.setup."""
        config = ShieldConfig(mode=ShieldMode.HOOK)
        shield_setup(config=config)
        mock_setup.assert_called_once_with(config)


class TestShieldStatus(unittest.TestCase):
    """Test shield_status."""

    @mock.patch("terok_shield.list_log_files", return_value=[])
    @mock.patch("terok_shield.list_profiles", return_value=["dev-standard"])
    def test_returns_status_dict(self, _profiles, _logs):
        """shield_status returns dict with expected keys."""
        config = ShieldConfig(mode=ShieldMode.HOOK)
        status = shield_status(config=config)
        self.assertEqual(status["mode"], "hook")
        self.assertIn("profiles", status)
        self.assertIn("audit_enabled", status)
        self.assertIn("log_files", status)


class TestShieldPreStart(unittest.TestCase):
    """Test shield_pre_start dispatch."""

    @mock.patch("terok_shield.log_event")
    @mock.patch("terok_shield.mode_hook.pre_start", return_value=["--network", "pasta:"])
    def test_hook_dispatch(self, mock_pre, _log):
        """shield_pre_start dispatches to mode_hook.pre_start."""
        config = ShieldConfig(mode=ShieldMode.HOOK)
        args = shield_pre_start("test", ["dev-standard"], config=config)
        mock_pre.assert_called_once_with(config, "test", ["dev-standard"])
        self.assertIn("--network", args)

    @mock.patch("terok_shield.log_event")
    @mock.patch("terok_shield.mode_hook.pre_start", return_value=[])
    def test_uses_default_profiles(self, mock_pre, _log):
        """shield_pre_start uses config.default_profiles if none given."""
        config = ShieldConfig(mode=ShieldMode.HOOK, default_profiles=("base",))
        shield_pre_start("test", config=config)
        mock_pre.assert_called_once_with(config, "test", ["base"])


class TestShieldAllow(unittest.TestCase):
    """Test shield_allow."""

    @mock.patch("terok_shield.log_event")
    @mock.patch("terok_shield.mode_hook.allow_ip")
    def test_allows_ip_directly(self, mock_allow, _log):
        """shield_allow passes an IP directly to allow_ip."""
        config = ShieldConfig(mode=ShieldMode.HOOK)
        ips = shield_allow("test", TEST_IP1, config=config)
        mock_allow.assert_called_once_with("test", TEST_IP1)
        self.assertEqual(ips, [TEST_IP1])

    @mock.patch("terok_shield.log_event")
    @mock.patch("terok_shield.mode_hook.allow_ip")
    @mock.patch("terok_shield.dig", return_value=[TEST_IP1])
    def test_resolves_domain(self, mock_dig, mock_allow, _log):
        """shield_allow resolves domains via dig."""
        config = ShieldConfig(mode=ShieldMode.HOOK)
        ips = shield_allow("test", "example.com", config=config)
        mock_dig.assert_called_once_with("example.com")
        mock_allow.assert_called_once_with("test", TEST_IP1)
        self.assertEqual(ips, [TEST_IP1])


class TestShieldDeny(unittest.TestCase):
    """Test shield_deny."""

    @mock.patch("terok_shield.log_event")
    @mock.patch("terok_shield.mode_hook.deny_ip")
    def test_denies_ip_directly(self, mock_deny, _log):
        """shield_deny passes an IP directly to deny_ip."""
        config = ShieldConfig(mode=ShieldMode.HOOK)
        ips = shield_deny("test", TEST_IP1, config=config)
        mock_deny.assert_called_once_with("test", TEST_IP1)
        self.assertEqual(ips, [TEST_IP1])

    @mock.patch("terok_shield.log_event")
    @mock.patch("terok_shield.mode_hook.deny_ip", side_effect=RuntimeError("nft error"))
    def test_swallows_errors(self, mock_deny, _log):
        """shield_deny ignores errors from deny_ip (best-effort)."""
        config = ShieldConfig(mode=ShieldMode.HOOK)
        ips = shield_deny("test", TEST_IP1, config=config)
        self.assertEqual(ips, [])


class TestShieldRules(unittest.TestCase):
    """Test shield_rules."""

    @mock.patch(
        "terok_shield.mode_hook.list_rules",
        return_value="table inet terok_shield {}",
    )
    def test_hook_dispatch(self, mock_rules):
        """shield_rules dispatches to mode_hook.list_rules."""
        config = ShieldConfig(mode=ShieldMode.HOOK)
        result = shield_rules("test", config=config)
        self.assertIn("terok_shield", result)


class TestShieldResolve(unittest.TestCase):
    """Test shield_resolve."""

    @mock.patch("terok_shield.resolve_and_cache", return_value=[TEST_IP1])
    @mock.patch("terok_shield.compose_profiles", return_value=["github.com"])
    def test_resolves_profiles(self, _compose, mock_resolve):
        """shield_resolve composes profiles and resolves."""
        config = ShieldConfig(mode=ShieldMode.HOOK)
        ips = shield_resolve("test", ["dev-standard"], config=config)
        self.assertEqual(ips, [TEST_IP1])

    @mock.patch("terok_shield.compose_profiles", return_value=[])
    def test_empty_profiles_returns_empty(self, _compose):
        """shield_resolve returns empty list for empty profiles."""
        config = ShieldConfig(mode=ShieldMode.HOOK)
        ips = shield_resolve("test", ["empty"], config=config)
        self.assertEqual(ips, [])

    @mock.patch("terok_shield.resolve_and_cache", return_value=[TEST_IP1])
    @mock.patch("terok_shield.compose_profiles", return_value=["github.com"])
    def test_force_sets_max_age_zero(self, _compose, mock_resolve):
        """shield_resolve passes max_age=0 when force=True."""
        config = ShieldConfig(mode=ShieldMode.HOOK)
        shield_resolve("test", ["dev-standard"], config=config, force=True)
        call_kwargs = mock_resolve.call_args[1]
        self.assertEqual(call_kwargs["max_age"], 0)
