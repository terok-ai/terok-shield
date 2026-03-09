# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for bridge mode lifecycle."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from terok_shield.config import (
    BRIDGE_GATEWAY,
    BRIDGE_NETWORK,
    DEFAULT_GATE_PORT,
    ShieldConfig,
    ShieldMode,
)
from terok_shield.mode_bridge import (
    _read_resolved_cache,
    _safe_domain,
    _update_dnsmasq_nftsets,
    allow_ip,
    deny_ip,
    list_rules,
    post_start,
    pre_start,
    pre_stop,
    setup,
)
from terok_shield.run import ExecError

from ..testnet import BRIDGE_CONTAINER_IP, TEST_IP1, TEST_IP2


class TestSetup(unittest.TestCase):
    """Test bridge mode setup."""

    @mock.patch("terok_shield.mode_bridge.ensure_shield_dirs")
    @mock.patch("terok_shield.mode_bridge.run_cmd")
    def test_succeeds_when_network_exists(self, mock_run, mock_dirs):
        """Setup succeeds if the bridge network exists."""
        config = ShieldConfig(mode=ShieldMode.BRIDGE)
        setup(config)
        mock_dirs.assert_called_once()
        mock_run.assert_called_once_with(["podman", "network", "exists", BRIDGE_NETWORK])

    @mock.patch("terok_shield.mode_bridge.ensure_shield_dirs")
    @mock.patch(
        "terok_shield.mode_bridge.run_cmd",
        side_effect=ExecError(["podman", "network", "exists"], 1, "not found"),
    )
    def test_raises_if_network_missing(self, mock_run, mock_dirs):
        """Setup raises RuntimeError if bridge network is absent."""
        config = ShieldConfig(mode=ShieldMode.BRIDGE)
        with self.assertRaises(RuntimeError) as ctx:
            setup(config)
        self.assertIn(BRIDGE_NETWORK, str(ctx.exception))


class TestPreStart(unittest.TestCase):
    """Test bridge mode pre_start."""

    def _config(self, gate_port=DEFAULT_GATE_PORT):
        return ShieldConfig(mode=ShieldMode.BRIDGE, gate_port=gate_port)

    @mock.patch("terok_shield.mode_bridge.resolve_and_cache")
    @mock.patch("terok_shield.mode_bridge.compose_profiles", return_value=["github.com"])
    @mock.patch("terok_shield.mode_bridge.nft_via_rootless_netns")
    def test_returns_bridge_args(self, mock_nft, _compose, _resolve):
        """Pre-start returns bridge network args."""
        mock_nft.return_value = f"table inet terok_shield {{ th dport {DEFAULT_GATE_PORT} }}"
        args = pre_start(self._config(), "test", ["dev-hardened"])

        self.assertIn("--network", args)
        net_idx = args.index("--network") + 1
        self.assertEqual(args[net_idx], BRIDGE_NETWORK)

    @mock.patch("terok_shield.mode_bridge.resolve_and_cache")
    @mock.patch("terok_shield.mode_bridge.compose_profiles", return_value=["github.com"])
    @mock.patch("terok_shield.mode_bridge.nft_via_rootless_netns")
    def test_includes_dns_and_security(self, mock_nft, _compose, _resolve):
        """Pre-start includes DNS, cap-drop, and no-new-privileges args."""
        mock_nft.return_value = f"table inet terok_shield {{ th dport {DEFAULT_GATE_PORT} }}"
        args = pre_start(self._config(), "test", ["dev-hardened"])

        self.assertIn("--dns", args)
        dns_idx = args.index("--dns") + 1
        self.assertEqual(args[dns_idx], BRIDGE_GATEWAY)
        self.assertIn("--cap-drop", args)
        self.assertIn("NET_ADMIN", args)
        self.assertIn("--security-opt", args)
        self.assertIn("no-new-privileges", args)

    @mock.patch("terok_shield.mode_bridge.resolve_and_cache")
    @mock.patch("terok_shield.mode_bridge.compose_profiles", return_value=[])
    @mock.patch("terok_shield.mode_bridge.nft_via_rootless_netns")
    def test_resolve_called_with_empty_entries(self, mock_nft, _compose, mock_resolve):
        """Pre-start calls resolve_and_cache even with empty entries (clears stale cache)."""
        mock_nft.return_value = f"table inet terok_shield {{ th dport {DEFAULT_GATE_PORT} }}"
        pre_start(self._config(), "test", [])
        mock_resolve.assert_called_once_with([], "test")

    @mock.patch("terok_shield.mode_bridge.resolve_and_cache")
    @mock.patch("terok_shield.mode_bridge.compose_profiles", return_value=["github.com"])
    @mock.patch("terok_shield.mode_bridge.nft_via_rootless_netns")
    def test_ensure_netns_loads_table(self, mock_nft, _compose, _resolve):
        """Pre-start creates table if not already present."""
        # First: list ruleset -> empty. Second: load. Third: verify.
        mock_nft.side_effect = [
            "",
            "",
            "table inet terok_shield {}",
        ]
        pre_start(self._config(), "test", ["dev-hardened"])
        self.assertEqual(mock_nft.call_count, 3)

    @mock.patch("terok_shield.mode_bridge.resolve_and_cache")
    @mock.patch("terok_shield.mode_bridge.compose_profiles", return_value=["github.com"])
    @mock.patch("terok_shield.mode_bridge.nft_via_rootless_netns")
    def test_ensure_netns_reloads_on_port_change(self, mock_nft, _compose, _resolve):
        """Pre-start reloads table when gate port has changed."""
        # First: list ruleset -> table exists with old port.
        # Second: delete old table. Third: load new. Fourth: verify.
        mock_nft.side_effect = [
            "table inet terok_shield { th dport 9999 }",
            "",
            "",
            "table inet terok_shield {}",
        ]
        pre_start(self._config(gate_port=1234), "test", ["dev-hardened"])
        # 4 nft calls: list, delete, load, verify
        self.assertEqual(mock_nft.call_count, 4)

    @mock.patch("terok_shield.mode_bridge.resolve_and_cache")
    @mock.patch("terok_shield.mode_bridge.compose_profiles", return_value=["github.com"])
    @mock.patch("terok_shield.mode_bridge.nft_via_rootless_netns")
    def test_ensure_netns_raises_on_failure(self, mock_nft, _compose, _resolve):
        """Pre-start raises RuntimeError if nft table cannot be loaded."""
        mock_nft.return_value = ""  # Table never appears
        with self.assertRaises(RuntimeError):
            pre_start(self._config(), "test", ["dev-hardened"])


class TestPostStart(unittest.TestCase):
    """Test bridge mode post_start."""

    def _config(self):
        return ShieldConfig(mode=ShieldMode.BRIDGE)

    @mock.patch("terok_shield.mode_bridge._update_dnsmasq_nftsets")
    @mock.patch("terok_shield.mode_bridge.nft_via_rootless_netns")
    @mock.patch("terok_shield.mode_bridge.podman_inspect", return_value=BRIDGE_CONTAINER_IP)
    @mock.patch("terok_shield.mode_bridge.compose_profiles", return_value=["github.com"])
    @mock.patch("terok_shield.mode_bridge._read_resolved_cache", return_value=[])
    def test_creates_set_and_forward(self, _cache, _compose, mock_inspect, mock_nft, _dnsmasq):
        """Post-start creates per-container set and forward rule."""
        post_start(self._config(), "test", ["dev-hardened"])
        # At least: create_set + forward_rule (2 nft calls)
        self.assertGreaterEqual(mock_nft.call_count, 2)

    @mock.patch("terok_shield.mode_bridge._update_dnsmasq_nftsets")
    @mock.patch("terok_shield.mode_bridge.nft_via_rootless_netns")
    @mock.patch("terok_shield.mode_bridge.podman_inspect", return_value=BRIDGE_CONTAINER_IP)
    @mock.patch("terok_shield.mode_bridge.compose_profiles", return_value=["github.com"])
    @mock.patch(
        "terok_shield.mode_bridge._read_resolved_cache",
        return_value=[TEST_IP1, TEST_IP2],
    )
    def test_loads_resolved_ips(self, _cache, _compose, _inspect, mock_nft, _dnsmasq):
        """Post-start loads resolved IPs into the allow set."""
        post_start(self._config(), "test", ["dev-hardened"])
        # create_set + add_elements + forward_rule (3 nft calls)
        self.assertGreaterEqual(mock_nft.call_count, 3)


class TestPreStop(unittest.TestCase):
    """Test bridge mode pre_stop."""

    @mock.patch("terok_shield.mode_bridge.shield_resolved_dir")
    @mock.patch("terok_shield.mode_bridge.nft_via_rootless_netns")
    def test_removes_rules_and_set(self, mock_nft, mock_dir):
        """Pre-stop deletes forward rules, allow set, and dnsmasq file."""
        with tempfile.TemporaryDirectory() as td:
            mock_dir.return_value = Path(td)
            dnsmasq_file = Path(td) / "test.dnsmasq-nftset"
            dnsmasq_file.write_text("nftset=/example.com/4#inet#terok_shield#test_allow_v4\n")
            mock_nft.return_value = '  meta nftrace set 1 comment "terok_shield:test" # handle 5\n'
            pre_stop("test")
            self.assertFalse(dnsmasq_file.exists())
        # 1 list chain + 1 delete rule + 1 delete set = 3 nft calls
        self.assertGreaterEqual(mock_nft.call_count, 3)

    @mock.patch("terok_shield.mode_bridge.shield_resolved_dir")
    @mock.patch("terok_shield.mode_bridge.nft_via_rootless_netns")
    def test_no_rules_to_remove(self, mock_nft, mock_dir):
        """Pre-stop handles missing rules and missing dnsmasq file gracefully."""
        with tempfile.TemporaryDirectory() as td:
            mock_dir.return_value = Path(td)
            mock_nft.return_value = ""
            pre_stop("test")
        # 1 list chain + 1 delete set = 2 nft calls
        self.assertEqual(mock_nft.call_count, 2)


class TestAllowDenyIp(unittest.TestCase):
    """Test live allow/deny via rootless-netns."""

    @mock.patch("terok_shield.mode_bridge.nft_via_rootless_netns")
    def test_allow_ip(self, mock_nft):
        """allow_ip adds element to per-container allow set."""
        allow_ip("test", TEST_IP1)
        mock_nft.assert_called_once()
        args = mock_nft.call_args[0]
        self.assertIn("add", args)
        self.assertIn("test_allow_v4", args)

    @mock.patch("terok_shield.mode_bridge.nft_via_rootless_netns")
    def test_deny_ip(self, mock_nft):
        """deny_ip removes element from per-container allow set."""
        deny_ip("test", TEST_IP1)
        mock_nft.assert_called_once()
        args = mock_nft.call_args[0]
        self.assertIn("delete", args)

    def test_allow_invalid_ip_raises(self):
        """allow_ip raises ValueError for invalid IPs."""
        with self.assertRaises(ValueError):
            allow_ip("test", "not-an-ip")

    def test_deny_invalid_ip_raises(self):
        """deny_ip raises ValueError for invalid IPs."""
        with self.assertRaises(ValueError):
            deny_ip("test", "not-an-ip")


class TestListRules(unittest.TestCase):
    """Test list_rules."""

    @mock.patch(
        "terok_shield.mode_bridge.nft_via_rootless_netns",
        return_value="table inet terok_shield {}",
    )
    def test_returns_output(self, mock_nft):
        """list_rules returns nft output."""
        result = list_rules("test")
        self.assertIn("terok_shield", result)


class TestReadResolvedCache(unittest.TestCase):
    """Test _read_resolved_cache."""

    @mock.patch("terok_shield.mode_bridge.shield_resolved_dir")
    def test_reads_cached_ips(self, mock_dir):
        """Reads IPs from cache file."""
        with tempfile.TemporaryDirectory() as td:
            mock_dir.return_value = Path(td)
            cache = Path(td) / "test.resolved"
            cache.write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
            result = _read_resolved_cache("test")
        self.assertEqual(result, [TEST_IP1, TEST_IP2])

    @mock.patch("terok_shield.mode_bridge.shield_resolved_dir")
    def test_returns_empty_on_missing_file(self, mock_dir):
        """Returns empty list if cache file does not exist."""
        with tempfile.TemporaryDirectory() as td:
            mock_dir.return_value = Path(td)
            result = _read_resolved_cache("test")
        self.assertEqual(result, [])

    def test_rejects_unsafe_name(self):
        """Returns empty list for container names that fail validation."""
        result = _read_resolved_cache("../escape")
        self.assertEqual(result, [])


class TestSafeDomain(unittest.TestCase):
    """Test _safe_domain validation."""

    def test_valid_domain(self):
        """Accepts valid domain names."""
        self.assertTrue(_safe_domain("github.com"))
        self.assertTrue(_safe_domain("sub.example.co.uk"))
        self.assertTrue(_safe_domain("example.com."))

    def test_rejects_slash(self):
        """Rejects domains containing slashes."""
        self.assertFalse(_safe_domain("evil/domain"))

    def test_rejects_hash(self):
        """Rejects domains containing hash."""
        self.assertFalse(_safe_domain("evil#domain"))

    def test_rejects_whitespace(self):
        """Rejects domains containing whitespace."""
        self.assertFalse(_safe_domain("evil domain"))
        self.assertFalse(_safe_domain("evil\tdomain"))

    def test_rejects_newline(self):
        """Rejects domains containing newlines."""
        self.assertFalse(_safe_domain("evil\ndomain"))

    def test_rejects_empty(self):
        """Rejects empty strings."""
        self.assertFalse(_safe_domain(""))

    def test_rejects_consecutive_dots(self):
        """Rejects domains with consecutive dots."""
        self.assertFalse(_safe_domain("exam..ple.com"))
        self.assertFalse(_safe_domain("a..b"))

    def test_single_label(self):
        """Accepts single-label domains."""
        self.assertTrue(_safe_domain("localhost"))

    def test_rejects_leading_hyphen_in_label(self):
        """Rejects labels starting with a hyphen."""
        self.assertFalse(_safe_domain("-example.com"))

    def test_rejects_trailing_hyphen_in_label(self):
        """Rejects labels ending with a hyphen."""
        self.assertFalse(_safe_domain("example-.com"))


class TestUpdateDnsmasqNftsetsWarning(unittest.TestCase):
    """Test _update_dnsmasq_nftsets logs warnings for invalid domains."""

    @mock.patch("terok_shield.mode_bridge.shield_resolved_dir")
    def test_logs_warning_for_invalid_domains(self, mock_dir):
        """Invalid domains produce a warning log."""
        with tempfile.TemporaryDirectory() as td:
            mock_dir.return_value = Path(td)
            with self.assertLogs("terok_shield.mode_bridge", level="WARNING") as cm:
                _update_dnsmasq_nftsets("test", ["github.com", "evil/domain", "exam ple.com"])
            self.assertEqual(len(cm.output), 2)
            self.assertIn("evil/domain", cm.output[0])
            self.assertIn("exam ple.com", cm.output[1])

    @mock.patch("terok_shield.mode_bridge.shield_resolved_dir")
    def test_no_warning_for_all_valid_domains(self, mock_dir):
        """All-valid domains produce no warnings."""
        with tempfile.TemporaryDirectory() as td:
            mock_dir.return_value = Path(td)
            with self.assertNoLogs("terok_shield.mode_bridge", level="WARNING"):
                _update_dnsmasq_nftsets("test", ["github.com", "example.com"])
