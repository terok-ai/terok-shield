# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for hook mode lifecycle."""

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

from terok_shield.config import ANNOTATION_KEY, ANNOTATION_NAME_KEY, ShieldConfig, ShieldMode
from terok_shield.mode_hook import (
    _detect_rootless_network_mode,
    _generate_entrypoint,
    _generate_hook_json,
    allow_ip,
    deny_ip,
    install_hooks,
    list_rules,
    pre_start,
    setup,
)

from ..testnet import TEST_DOMAIN, TEST_IP1


class TestDetectRootlessNetworkMode(unittest.TestCase):
    """Test rootless network mode detection."""

    @mock.patch("terok_shield.mode_hook.run_cmd")
    def test_pasta_from_podman_info(self, mock_run):
        """Detect pasta mode from podman info output."""
        mock_run.return_value = json.dumps({"host": {"rootlessNetworkCmd": "pasta"}})
        self.assertEqual(_detect_rootless_network_mode(), "pasta")

    @mock.patch("terok_shield.mode_hook.run_cmd")
    def test_slirp4netns_from_podman_info(self, mock_run):
        """Detect slirp4netns mode from podman info output."""
        mock_run.return_value = json.dumps({"host": {"rootlessNetworkCmd": "slirp4netns"}})
        self.assertEqual(_detect_rootless_network_mode(), "slirp4netns")

    @mock.patch("terok_shield.mode_hook.run_cmd")
    def test_fallback_on_empty_output(self, mock_run):
        """Default to pasta when podman info returns nothing."""
        mock_run.return_value = ""
        self.assertEqual(_detect_rootless_network_mode(), "pasta")

    @mock.patch("terok_shield.mode_hook.run_cmd")
    def test_fallback_on_invalid_json(self, mock_run):
        """Default to pasta when podman info returns invalid JSON."""
        mock_run.return_value = "not json"
        self.assertEqual(_detect_rootless_network_mode(), "pasta")

    @mock.patch("terok_shield.mode_hook.run_cmd")
    def test_fallback_on_missing_field(self, mock_run):
        """Default to pasta when rootlessNetworkCmd is absent."""
        mock_run.return_value = json.dumps({"host": {}})
        self.assertEqual(_detect_rootless_network_mode(), "pasta")

    @mock.patch("terok_shield.mode_hook.run_cmd")
    def test_fallback_on_unknown_mode(self, mock_run):
        """Default to pasta for unrecognised network modes."""
        mock_run.return_value = json.dumps({"host": {"rootlessNetworkCmd": "unknown"}})
        self.assertEqual(_detect_rootless_network_mode(), "pasta")


class TestGenerateEntrypoint(unittest.TestCase):
    """Test OCI hook entrypoint generation."""

    def test_contains_python_path(self):
        """Entrypoint uses the current Python interpreter."""
        ep = _generate_entrypoint()
        self.assertIn(sys.executable, ep)

    def test_contains_module_invocation(self):
        """Entrypoint invokes the hook module."""
        ep = _generate_entrypoint()
        self.assertIn("-m terok_shield.oci_hook", ep)

    def test_starts_with_shebang(self):
        """Entrypoint starts with a shebang line."""
        ep = _generate_entrypoint()
        self.assertTrue(ep.startswith("#!/bin/sh\n"))


class TestGenerateHookJson(unittest.TestCase):
    """Test OCI hook JSON generation."""

    def test_valid_json(self):
        """Output is valid JSON."""
        result = json.loads(_generate_hook_json("/path/to/hook", "createRuntime"))
        self.assertEqual(result["version"], "1.0.0")
        self.assertEqual(result["hook"]["path"], "/path/to/hook")

    def test_annotation_filter(self):
        """Hook triggers on the shield profiles annotation."""
        result = json.loads(_generate_hook_json("/hook", "createRuntime"))
        self.assertIn(ANNOTATION_KEY, result["when"]["annotations"])

    def test_create_runtime_stage(self):
        """Hook fires at createRuntime stage."""
        result = json.loads(_generate_hook_json("/hook", "createRuntime"))
        self.assertEqual(result["stages"], ["createRuntime"])

    def test_poststop_stage(self):
        """Hook fires at poststop stage."""
        result = json.loads(_generate_hook_json("/hook", "poststop"))
        self.assertEqual(result["stages"], ["poststop"])

    def test_stage_in_args(self):
        """Stage appears in hook args."""
        result = json.loads(_generate_hook_json("/hook", "poststop"))
        self.assertIn("poststop", result["hook"]["args"])


class TestSetup(unittest.TestCase):
    """Test hook mode setup."""

    def test_creates_hook_files(self):
        """Setup creates entrypoint and both stage hook JSON files."""
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            self._run_setup(Path(td))

    def _run_setup(self, tmp_dir):
        config = ShieldConfig(mode=ShieldMode.HOOK)
        with (
            mock.patch(
                "terok_shield.mode_hook.shield_hook_entrypoint",
                return_value=tmp_dir / "terok-shield-hook",
            ),
            mock.patch(
                "terok_shield.mode_hook.shield_hooks_dir",
                return_value=tmp_dir / "hooks",
            ),
            mock.patch("terok_shield.mode_hook.ensure_shield_dirs"),
        ):
            (tmp_dir / "hooks").mkdir(parents=True, exist_ok=True)
            setup(config)

        ep = tmp_dir / "terok-shield-hook"
        self.assertTrue(ep.exists())
        self.assertIn("-m terok_shield.oci_hook", ep.read_text())

        for stage in ("createRuntime", "poststop"):
            hook_json = tmp_dir / "hooks" / f"terok-shield-{stage}.json"
            self.assertTrue(hook_json.exists(), f"Missing {hook_json.name}")
            data = json.loads(hook_json.read_text())
            self.assertEqual(data["hook"]["path"], str(ep))
            self.assertEqual(data["stages"], [stage])


class TestInstallHooks(unittest.TestCase):
    """Test install_hooks shared function."""

    def test_installs_both_stages(self):
        """install_hooks creates both createRuntime and poststop hook JSON files."""
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            tmp_dir = Path(td)
            with (
                mock.patch(
                    "terok_shield.mode_hook.shield_hook_entrypoint",
                    return_value=tmp_dir / "terok-shield-hook",
                ),
                mock.patch(
                    "terok_shield.mode_hook.shield_hooks_dir",
                    return_value=tmp_dir / "hooks",
                ),
                mock.patch("terok_shield.mode_hook.ensure_shield_dirs"),
            ):
                (tmp_dir / "hooks").mkdir(parents=True, exist_ok=True)
                install_hooks()

            self.assertTrue((tmp_dir / "hooks" / "terok-shield-createRuntime.json").exists())
            self.assertTrue((tmp_dir / "hooks" / "terok-shield-poststop.json").exists())


class TestPreStart(unittest.TestCase):
    """Test hook mode pre_start."""

    def setUp(self):
        """Create a temporary hooks directory with entrypoint for each test."""
        import tempfile

        self._tmpdir_obj = tempfile.TemporaryDirectory()
        self._tmpdir = Path(self._tmpdir_obj.name)
        hooks_dir = self._tmpdir / "hooks"
        hooks_dir.mkdir()
        (hooks_dir / "terok-shield-createRuntime.json").touch()
        ep = self._tmpdir / "terok-shield-hook"
        ep.write_text("#!/bin/sh\n")
        ep.chmod(0o755)
        self._hooks_patch = mock.patch(
            "terok_shield.mode_hook.shield_hooks_dir",
            return_value=hooks_dir,
        )
        self._ep_patch = mock.patch(
            "terok_shield.mode_hook.shield_hook_entrypoint",
            return_value=ep,
        )
        self._hooks_patch.start()
        self._ep_patch.start()

    def tearDown(self):
        """Clean up patches and temp directory."""
        self._ep_patch.stop()
        self._hooks_patch.stop()
        self._tmpdir_obj.cleanup()

    def _config(self, loopback_ports=()):
        return ShieldConfig(mode=ShieldMode.HOOK, loopback_ports=loopback_ports)

    @mock.patch("terok_shield.mode_hook.resolve_and_cache")
    @mock.patch("terok_shield.mode_hook.compose_profiles", return_value=[TEST_DOMAIN])
    @mock.patch("terok_shield.mode_hook._detect_rootless_network_mode", return_value="pasta")
    @mock.patch("os.geteuid", return_value=1000)
    def test_pasta_args(self, _euid, _mode, _compose, _resolve):
        """Pre-start returns pasta network args for rootless mode."""
        args = pre_start(self._config(), "test", ["dev-standard"])
        self.assertIn("--network", args)
        pasta_idx = args.index("--network") + 1
        self.assertIn("pasta:", args[pasta_idx])

    @mock.patch("terok_shield.mode_hook.resolve_and_cache")
    @mock.patch("terok_shield.mode_hook.compose_profiles", return_value=[TEST_DOMAIN])
    @mock.patch("terok_shield.mode_hook._detect_rootless_network_mode", return_value="slirp4netns")
    @mock.patch("os.geteuid", return_value=1000)
    def test_slirp4netns_args(self, _euid, _mode, _compose, _resolve):
        """Pre-start returns slirp4netns args when detected."""
        args = pre_start(self._config(), "test", ["dev-standard"])
        net_idx = args.index("--network") + 1
        self.assertIn("slirp4netns", args[net_idx])

    @mock.patch("terok_shield.mode_hook.resolve_and_cache")
    @mock.patch("terok_shield.mode_hook.compose_profiles", return_value=[])
    @mock.patch("os.geteuid", return_value=0)
    def test_root_no_network_args(self, _euid, _compose, _resolve):
        """Root user gets no special network args."""
        args = pre_start(self._config(), "test", ["dev-standard"])
        # No --network before the annotation args
        before_annotation = args[: args.index("--annotation")]
        self.assertNotIn("--network", before_annotation)

    @mock.patch("terok_shield.mode_hook.resolve_and_cache")
    @mock.patch("terok_shield.mode_hook.compose_profiles", return_value=[TEST_DOMAIN])
    @mock.patch("os.geteuid", return_value=1000)
    @mock.patch("terok_shield.mode_hook._detect_rootless_network_mode", return_value="pasta")
    def test_shield_args(self, _mode, _euid, _compose, _resolve):
        """Pre-start includes cap-drop and no-new-privileges."""
        args = pre_start(self._config(), "test", ["dev-standard"])
        self.assertIn("--cap-drop", args)
        self.assertIn("NET_ADMIN", args)
        self.assertIn("NET_RAW", args)
        self.assertIn("--security-opt", args)
        self.assertIn("no-new-privileges", args)

    @mock.patch("terok_shield.mode_hook.compose_profiles", return_value=[])
    def test_missing_hook_raises(self, _compose):
        """Pre-start raises RuntimeError if hook not installed."""
        self._hooks_patch.stop()
        self._ep_patch.stop()
        with (
            mock.patch(
                "terok_shield.mode_hook.shield_hooks_dir",
                return_value=Path("/nonexistent"),
            ),
            mock.patch(
                "terok_shield.mode_hook.shield_hook_entrypoint",
                return_value=Path("/nonexistent/ep"),
            ),
            self.assertRaises(RuntimeError),
        ):
            pre_start(self._config(), "test", ["dev-standard"])
        self._hooks_patch.start()
        self._ep_patch.start()

    @mock.patch("terok_shield.mode_hook.resolve_and_cache")
    @mock.patch("terok_shield.mode_hook.compose_profiles", return_value=[TEST_DOMAIN])
    @mock.patch("os.geteuid", return_value=1000)
    @mock.patch("terok_shield.mode_hook._detect_rootless_network_mode", return_value="pasta")
    def test_loopback_ports_in_pasta(self, _mode, _euid, _compose, _resolve):
        """Loopback ports from config appear in pasta network args."""
        args = pre_start(self._config(loopback_ports=(1234, 5678)), "test", ["dev-standard"])
        net_idx = args.index("--network") + 1
        self.assertIn("-T,1234", args[net_idx])
        self.assertIn("-T,5678", args[net_idx])

    @mock.patch("terok_shield.mode_hook.resolve_and_cache")
    @mock.patch("terok_shield.mode_hook.compose_profiles", return_value=[TEST_DOMAIN])
    @mock.patch("os.geteuid", return_value=1000)
    @mock.patch("terok_shield.mode_hook._detect_rootless_network_mode", return_value="pasta")
    def test_empty_loopback_ports_pasta(self, _mode, _euid, _compose, _resolve):
        """Empty loopback ports produce plain pasta: network arg."""
        args = pre_start(self._config(), "test", ["dev-standard"])
        net_idx = args.index("--network") + 1
        self.assertEqual(args[net_idx], "pasta:")

    @mock.patch("terok_shield.mode_hook.resolve_and_cache")
    @mock.patch("terok_shield.mode_hook.compose_profiles", return_value=[TEST_DOMAIN])
    @mock.patch("os.geteuid", return_value=1000)
    @mock.patch("terok_shield.mode_hook._detect_rootless_network_mode", return_value="pasta")
    def test_annotation_includes_profiles(self, _mode, _euid, _compose, _resolve):
        """Annotation arg lists the profile names."""
        args = pre_start(self._config(), "test", ["dev-standard", "base"])
        ann_idx = args.index("--annotation") + 1
        self.assertIn(ANNOTATION_KEY, args[ann_idx])
        self.assertIn("dev-standard,base", args[ann_idx])

    @mock.patch("terok_shield.mode_hook.resolve_and_cache")
    @mock.patch("terok_shield.mode_hook.compose_profiles", return_value=[TEST_DOMAIN])
    @mock.patch("os.geteuid", return_value=1000)
    @mock.patch("terok_shield.mode_hook._detect_rootless_network_mode", return_value="pasta")
    def test_annotation_includes_name(self, _mode, _euid, _compose, _resolve):
        """Annotation arg includes container name."""
        args = pre_start(self._config(), "my-container", ["dev-standard"])
        ann_values = [args[i + 1] for i, a in enumerate(args) if a == "--annotation"]
        name_ann = [v for v in ann_values if ANNOTATION_NAME_KEY in v]
        self.assertEqual(len(name_ann), 1)
        self.assertIn("my-container", name_ann[0])


class TestAllowDenyIp(unittest.TestCase):
    """Test live allow/deny via nsenter."""

    @mock.patch("terok_shield.mode_hook.nft_via_nsenter")
    def test_allow_ip(self, mock_nsenter):
        """allow_ip adds element to allow_v4 set."""
        allow_ip("test", TEST_IP1)
        mock_nsenter.assert_called_once()
        call_args = mock_nsenter.call_args[0]
        self.assertEqual(call_args[0], "test")
        self.assertIn("add", call_args)
        self.assertIn("allow_v4", call_args)

    @mock.patch("terok_shield.mode_hook.nft_via_nsenter")
    def test_deny_ip(self, mock_nsenter):
        """deny_ip removes element from allow_v4 set."""
        deny_ip("test", TEST_IP1)
        mock_nsenter.assert_called_once()
        call_args = mock_nsenter.call_args[0]
        self.assertIn("delete", call_args)

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

    @mock.patch("terok_shield.mode_hook.nft_via_nsenter", return_value="table inet terok_shield {}")
    def test_returns_output(self, mock_nsenter):
        """list_rules returns nft output."""
        result = list_rules("test")
        self.assertIn("terok_shield", result)
        mock_nsenter.assert_called_once()
