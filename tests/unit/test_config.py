# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for shield configuration."""

import unittest
import unittest.mock

from terok_shield.config import (
    ShieldConfig,
    ShieldMode,
    ensure_shield_dirs,
    get_shield_gate_port,
    load_shield_config,
    shield_config_root,
    shield_dns_dir,
    shield_hook_entrypoint,
    shield_hooks_dir,
    shield_logs_dir,
    shield_profiles_dir,
    shield_resolved_dir,
    shield_state_root,
)


class TestShieldConfig(unittest.TestCase):
    """Tests for ShieldConfig dataclass."""

    def test_defaults(self) -> None:
        """Default config is hook mode with standard profiles."""
        cfg = ShieldConfig()
        self.assertEqual(cfg.mode, ShieldMode.HOOK)
        self.assertEqual(cfg.default_profiles, ("dev-standard",))
        self.assertEqual(cfg.gate_port, 9418)
        self.assertTrue(cfg.audit_enabled)
        self.assertTrue(cfg.audit_log_allowed)

    def test_default_profiles_immutable(self) -> None:
        """Default profiles tuple cannot be mutated."""
        cfg = ShieldConfig()
        self.assertIsInstance(cfg.default_profiles, tuple)

    def test_frozen(self) -> None:
        """Config is immutable."""
        cfg = ShieldConfig()
        with self.assertRaises(AttributeError):
            cfg.mode = ShieldMode.BRIDGE  # type: ignore[misc]


class TestPathHelpers(unittest.TestCase):
    """Tests for path helper functions."""

    def test_state_root_default(self) -> None:
        """Default state root is under ~/.local/state/."""
        with unittest.mock.patch.dict("os.environ", {}, clear=True):
            root = shield_state_root()
            self.assertTrue(str(root).endswith("terok-shield"))

    def test_state_root_env_override(self) -> None:
        """TEROK_SHIELD_STATE_DIR overrides default."""
        with unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_STATE_DIR": "/tmp/test-state"}):
            root = shield_state_root()
            self.assertEqual(str(root), "/tmp/test-state")

    def test_config_root_default(self) -> None:
        """Default config root is under ~/.config/."""
        with unittest.mock.patch.dict("os.environ", {}, clear=True):
            root = shield_config_root()
            self.assertTrue(str(root).endswith("terok-shield"))

    def test_config_root_env_override(self) -> None:
        """TEROK_SHIELD_CONFIG_DIR overrides default."""
        with unittest.mock.patch.dict(
            "os.environ", {"TEROK_SHIELD_CONFIG_DIR": "/tmp/test-config"}
        ):
            root = shield_config_root()
            self.assertEqual(str(root), "/tmp/test-config")

    def test_state_root_xdg(self) -> None:
        """XDG_STATE_HOME is used when TEROK_SHIELD_STATE_DIR is not set."""
        with unittest.mock.patch.dict(
            "os.environ", {"XDG_STATE_HOME": "/tmp/xdg-state"}, clear=True
        ):
            root = shield_state_root()
            self.assertEqual(str(root), "/tmp/xdg-state/terok-shield")

    def test_config_root_xdg(self) -> None:
        """XDG_CONFIG_HOME is used when TEROK_SHIELD_CONFIG_DIR is not set."""
        with unittest.mock.patch.dict(
            "os.environ", {"XDG_CONFIG_HOME": "/tmp/xdg-config"}, clear=True
        ):
            root = shield_config_root()
            self.assertEqual(str(root), "/tmp/xdg-config/terok-shield")

    def test_state_root_explicit_overrides_xdg(self) -> None:
        """TEROK_SHIELD_STATE_DIR takes priority over XDG_STATE_HOME."""
        with unittest.mock.patch.dict(
            "os.environ",
            {"TEROK_SHIELD_STATE_DIR": "/tmp/explicit", "XDG_STATE_HOME": "/tmp/xdg"},
        ):
            root = shield_state_root()
            self.assertEqual(str(root), "/tmp/explicit")

    def test_logs_dir_derives_from_state(self) -> None:
        """Logs dir is under the state root."""
        with unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_STATE_DIR": "/tmp/s"}):
            self.assertEqual(str(shield_logs_dir()), "/tmp/s/logs")

    def test_hooks_dir(self) -> None:
        """Hooks dir is under the state root."""
        with unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_STATE_DIR": "/tmp/s"}):
            self.assertEqual(str(shield_hooks_dir()), "/tmp/s/hooks")

    def test_hook_entrypoint(self) -> None:
        """Hook entrypoint is under the state root."""
        with unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_STATE_DIR": "/tmp/s"}):
            self.assertEqual(str(shield_hook_entrypoint()), "/tmp/s/terok-shield-hook")

    def test_profiles_dir(self) -> None:
        """Profiles dir is under the config root."""
        with unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": "/tmp/c"}):
            self.assertEqual(str(shield_profiles_dir()), "/tmp/c/profiles")

    def test_dns_dir(self) -> None:
        """DNS dir is under the state root."""
        with unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_STATE_DIR": "/tmp/s"}):
            self.assertEqual(str(shield_dns_dir()), "/tmp/s/dns")

    def test_resolved_dir(self) -> None:
        """Resolved dir is under the state root."""
        with unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_STATE_DIR": "/tmp/s"}):
            self.assertEqual(str(shield_resolved_dir()), "/tmp/s/resolved")

    def test_ensure_shield_dirs(self) -> None:
        """ensure_shield_dirs creates all required directories."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            with unittest.mock.patch.dict(
                "os.environ",
                {"TEROK_SHIELD_STATE_DIR": f"{tmp}/state", "TEROK_SHIELD_CONFIG_DIR": f"{tmp}/cfg"},
            ):
                ensure_shield_dirs()
                self.assertTrue(Path(f"{tmp}/state").is_dir())
                self.assertTrue(Path(f"{tmp}/state/hooks").is_dir())
                self.assertTrue(Path(f"{tmp}/state/logs").is_dir())
                self.assertTrue(Path(f"{tmp}/state/dns").is_dir())
                self.assertTrue(Path(f"{tmp}/state/resolved").is_dir())
                self.assertTrue(Path(f"{tmp}/cfg/profiles").is_dir())


class TestLoadShieldConfig(unittest.TestCase):
    """Tests for load_shield_config."""

    def test_missing_file_returns_defaults(
        self,
    ) -> None:
        """Return defaults when config file does not exist."""
        with unittest.mock.patch.dict(
            "os.environ", {"TEROK_SHIELD_CONFIG_DIR": "/nonexistent-path"}
        ):
            cfg = load_shield_config()
            self.assertEqual(cfg.mode, ShieldMode.HOOK)

    def test_loads_yaml(self, tmp_path=None) -> None:
        """Load configuration from YAML file."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            config_file = Path(tmp) / "config.yml"
            config_file.write_text(
                "mode: hook\n"
                "default_profiles: [base, dev-python]\n"
                "gate_port: 1234\n"
                "audit:\n"
                "  enabled: false\n"
            )
            with unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": tmp}):
                cfg = load_shield_config()
                self.assertEqual(cfg.mode, ShieldMode.HOOK)
                self.assertEqual(cfg.default_profiles, ("base", "dev-python"))
                self.assertEqual(cfg.gate_port, 1234)
                self.assertFalse(cfg.audit_enabled)

    def test_auto_mode_calls_auto_detect(self) -> None:
        """mode: auto triggers _auto_detect_mode."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            config_file = Path(tmp) / "config.yml"
            config_file.write_text("mode: auto\n")
            with (
                unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": tmp}),
                unittest.mock.patch(
                    "terok_shield.config._auto_detect_mode", return_value=ShieldMode.HOOK
                ) as mock_detect,
            ):
                cfg = load_shield_config()
                mock_detect.assert_called_once()
                self.assertEqual(cfg.mode, ShieldMode.HOOK)

    def test_invalid_yaml_returns_defaults(self) -> None:
        """Return defaults for invalid YAML."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            config_file = Path(tmp) / "config.yml"
            config_file.write_text(": : : invalid yaml [[[")
            with unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": tmp}):
                cfg = load_shield_config()
                self.assertEqual(cfg.mode, ShieldMode.HOOK)

    def test_invalid_mode_raises(self) -> None:
        """Raise ValueError for unknown mode string."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            config_file = Path(tmp) / "config.yml"
            config_file.write_text("mode: bogus\n")
            with (
                unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": tmp}),
                self.assertRaises(ValueError),
            ):
                load_shield_config()

    def test_non_dict_yaml_returns_defaults(self) -> None:
        """Return defaults when YAML parses to non-dict (e.g. a list)."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            config_file = Path(tmp) / "config.yml"
            config_file.write_text("- item1\n- item2\n")
            with unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": tmp}):
                cfg = load_shield_config()
                self.assertEqual(cfg.mode, ShieldMode.HOOK)

    def test_non_list_profiles_falls_back(self) -> None:
        """Non-list default_profiles value falls back to default."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            config_file = Path(tmp) / "config.yml"
            config_file.write_text("mode: hook\ndefault_profiles: not-a-list\n")
            with unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": tmp}):
                cfg = load_shield_config()
                self.assertEqual(cfg.default_profiles, ("dev-standard",))

    def test_non_dict_audit_falls_back(self) -> None:
        """Non-dict audit value falls back to defaults."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            config_file = Path(tmp) / "config.yml"
            config_file.write_text("mode: hook\naudit: not-a-dict\n")
            with unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": tmp}):
                cfg = load_shield_config()
                self.assertTrue(cfg.audit_enabled)

    def test_non_bool_audit_flags_fall_back(self) -> None:
        """Non-boolean audit flag values fall back to defaults."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            config_file = Path(tmp) / "config.yml"
            config_file.write_text('mode: hook\naudit:\n  enabled: "yes"\n  log_allowed: 42\n')
            with unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": tmp}):
                cfg = load_shield_config()
                self.assertIs(cfg.audit_enabled, True)
                self.assertIs(cfg.audit_log_allowed, True)


class TestGetShieldGatePort(unittest.TestCase):
    """Tests for get_shield_gate_port."""

    def test_returns_default(self) -> None:
        """Return default gate port from config."""
        with unittest.mock.patch.dict(
            "os.environ", {"TEROK_SHIELD_CONFIG_DIR": "/nonexistent-path"}
        ):
            port = get_shield_gate_port()
            self.assertEqual(port, 9418)


class TestAutoDetectMode(unittest.TestCase):
    """Tests for _auto_detect_mode."""

    @unittest.mock.patch("shutil.which", return_value=None)
    @unittest.mock.patch("subprocess.run", side_effect=FileNotFoundError)
    def test_no_tools_raises(self, _run: unittest.mock.Mock, _which: unittest.mock.Mock) -> None:
        """Raise RuntimeError when neither nft nor podman is available."""
        from terok_shield.config import _auto_detect_mode

        with self.assertRaises(RuntimeError):
            _auto_detect_mode()

    @unittest.mock.patch(
        "shutil.which", side_effect=lambda n: "/usr/sbin/nft" if n == "nft" else None
    )
    @unittest.mock.patch("subprocess.run", side_effect=FileNotFoundError)
    def test_nft_only_returns_hook(
        self, _run: unittest.mock.Mock, _which: unittest.mock.Mock
    ) -> None:
        """Return HOOK when only nft is available."""
        from terok_shield.config import _auto_detect_mode

        self.assertEqual(_auto_detect_mode(), ShieldMode.HOOK)

    @unittest.mock.patch(
        "shutil.which",
        side_effect=lambda n: {
            "nft": "/usr/sbin/nft",
            "dnsmasq": "/usr/sbin/dnsmasq",
        }.get(n),
    )
    @unittest.mock.patch("subprocess.run")
    def test_bridge_when_bridge_and_dnsmasq(
        self, mock_run: unittest.mock.Mock, _which: unittest.mock.Mock
    ) -> None:
        """Return BRIDGE when podman bridge network exists and dnsmasq available."""
        from terok_shield.config import _auto_detect_mode

        mock_run.return_value = unittest.mock.Mock(returncode=0)
        self.assertEqual(_auto_detect_mode(), ShieldMode.BRIDGE)

    @unittest.mock.patch(
        "shutil.which",
        side_effect=lambda n: {
            "dnsmasq": "/usr/sbin/dnsmasq",
        }.get(n),
    )
    @unittest.mock.patch("subprocess.run")
    def test_bridge_without_nft_raises(
        self, mock_run: unittest.mock.Mock, _which: unittest.mock.Mock
    ) -> None:
        """Raise RuntimeError when bridge network + dnsmasq exist but nft is missing."""
        from terok_shield.config import _auto_detect_mode

        mock_run.return_value = unittest.mock.Mock(returncode=0)
        with self.assertRaises(RuntimeError):
            _auto_detect_mode()


class TestGatePortValidation(unittest.TestCase):
    """Tests for gate_port validation in config loading."""

    def test_bool_rejected(self) -> None:
        """Boolean values for gate_port fall back to default."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            config_file = Path(tmp) / "config.yml"
            config_file.write_text("mode: hook\ngate_port: true\n")
            with unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": tmp}):
                cfg = load_shield_config()
                self.assertEqual(cfg.gate_port, 9418)

    def test_out_of_range_rejected(self) -> None:
        """Out-of-range port falls back to default."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            config_file = Path(tmp) / "config.yml"
            config_file.write_text("mode: hook\ngate_port: 99999\n")
            with unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": tmp}):
                cfg = load_shield_config()
                self.assertEqual(cfg.gate_port, 9418)

    def test_zero_rejected(self) -> None:
        """Port 0 falls back to default."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            config_file = Path(tmp) / "config.yml"
            config_file.write_text("mode: hook\ngate_port: 0\n")
            with unittest.mock.patch.dict("os.environ", {"TEROK_SHIELD_CONFIG_DIR": tmp}):
                cfg = load_shield_config()
                self.assertEqual(cfg.gate_port, 9418)
