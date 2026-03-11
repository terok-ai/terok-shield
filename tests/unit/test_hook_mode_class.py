# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the HookMode class (OOP API)."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from terok_shield.config import ShieldConfig, ShieldState
from terok_shield.mode_hook import HookMode
from terok_shield.nft import bypass_ruleset, hook_ruleset
from terok_shield.run import ExecError

from ..testfs import NONEXISTENT_DIR
from ..testnet import IPV6_CLOUDFLARE, TEST_DOMAIN, TEST_IP1


def _make_hook_mode(
    config: ShieldConfig | None = None,
    *,
    runner: mock.MagicMock | None = None,
    audit: mock.MagicMock | None = None,
    dns: mock.MagicMock | None = None,
    profiles: mock.MagicMock | None = None,
    ruleset: mock.MagicMock | None = None,
) -> HookMode:
    """Create a HookMode with mock collaborators."""
    return HookMode(
        config=config or ShieldConfig(),
        runner=runner or mock.MagicMock(),
        audit=audit or mock.MagicMock(),
        dns=dns or mock.MagicMock(),
        profiles=profiles or mock.MagicMock(),
        ruleset=ruleset or mock.MagicMock(),
    )


class TestHookModeInit(unittest.TestCase):
    """Test HookMode construction."""

    def test_stores_collaborators(self) -> None:
        """HookMode stores all injected collaborators."""
        runner = mock.MagicMock()
        audit = mock.MagicMock()
        dns = mock.MagicMock()
        profiles = mock.MagicMock()
        ruleset = mock.MagicMock()
        config = ShieldConfig()
        mode = HookMode(
            config=config,
            runner=runner,
            audit=audit,
            dns=dns,
            profiles=profiles,
            ruleset=ruleset,
        )
        self.assertIs(mode._config, config)
        self.assertIs(mode._runner, runner)
        self.assertIs(mode._audit, audit)
        self.assertIs(mode._dns, dns)
        self.assertIs(mode._profiles, profiles)
        self.assertIs(mode._ruleset, ruleset)


class TestHookModeSetup(unittest.TestCase):
    """Test HookMode.setup()."""

    def test_installs_hooks(self) -> None:
        """setup() calls install_hooks with config paths."""
        config = ShieldConfig()
        mode = _make_hook_mode(config=config)
        with mock.patch("terok_shield.mode_hook.install_hooks") as mock_install:
            mode.setup()
            mock_install.assert_called_once_with(
                hook_entrypoint=config.paths.hook_entrypoint,
                hooks_dir=config.paths.hooks_dir,
            )


class TestHookModePreStart(unittest.TestCase):
    """Test HookMode.pre_start()."""

    def setUp(self):
        """Create temp dir with hooks/entrypoint for each test."""
        self._tmpdir_obj = tempfile.TemporaryDirectory()
        self._tmpdir = Path(self._tmpdir_obj.name)
        hooks_dir = self._tmpdir / "hooks"
        hooks_dir.mkdir()
        (hooks_dir / "terok-shield-createRuntime.json").touch()
        ep = self._tmpdir / "terok-shield-hook"
        ep.write_text("#!/bin/sh\n")
        ep.chmod(0o755)
        self._config = ShieldConfig(
            paths=mock.MagicMock(
                hooks_dir=hooks_dir,
                hook_entrypoint=ep,
                resolved_dir=self._tmpdir / "resolved",
            ),
            loopback_ports=(8080,),
        )

    def tearDown(self):
        self._tmpdir_obj.cleanup()

    @mock.patch("os.geteuid", return_value=1000)
    def test_pasta_args(self, _euid) -> None:
        """Pre-start returns pasta network args for rootless mode."""
        runner = mock.MagicMock()
        runner.run.return_value = json.dumps({"host": {"rootlessNetworkCmd": "pasta"}})
        profiles = mock.MagicMock()
        profiles.compose_profiles.return_value = [TEST_DOMAIN]
        dns = mock.MagicMock()
        mode = _make_hook_mode(
            config=self._config,
            runner=runner,
            profiles=profiles,
            dns=dns,
        )
        args = mode.pre_start("test", ["dev-standard"])
        self.assertIn("--network", args)
        net_idx = args.index("--network") + 1
        self.assertIn("pasta:", args[net_idx])
        self.assertIn("-T,8080", args[net_idx])

    def test_missing_hook_raises(self) -> None:
        """Pre-start raises RuntimeError if hook not installed."""
        config = ShieldConfig(
            paths=mock.MagicMock(
                hooks_dir=NONEXISTENT_DIR,
                hook_entrypoint=NONEXISTENT_DIR / "ep",
            ),
        )
        mode = _make_hook_mode(config=config)
        with self.assertRaises(RuntimeError):
            mode.pre_start("test", ["dev-standard"])


class TestHookModeAllowDeny(unittest.TestCase):
    """Test HookMode.allow_ip() and deny_ip()."""

    def test_allow_ipv4(self) -> None:
        """allow_ip adds element to allow_v4 set."""
        runner = mock.MagicMock()
        ruleset = mock.MagicMock()
        ruleset.safe_ip.return_value = TEST_IP1
        mode = _make_hook_mode(runner=runner, ruleset=ruleset)

        mode.allow_ip("test-ctr", TEST_IP1)
        runner.nft_via_nsenter.assert_called_once()
        call_args = runner.nft_via_nsenter.call_args[0]
        self.assertIn("add", call_args)
        self.assertIn("allow_v4", call_args)

    def test_allow_ipv6(self) -> None:
        """allow_ip adds element to allow_v6 set for IPv6."""
        runner = mock.MagicMock()
        ruleset = mock.MagicMock()
        ruleset.safe_ip.return_value = IPV6_CLOUDFLARE
        mode = _make_hook_mode(runner=runner, ruleset=ruleset)

        mode.allow_ip("test-ctr", IPV6_CLOUDFLARE)
        call_args = runner.nft_via_nsenter.call_args[0]
        self.assertIn("allow_v6", call_args)

    def test_deny_ipv4(self) -> None:
        """deny_ip removes element from allow_v4 set."""
        runner = mock.MagicMock()
        ruleset = mock.MagicMock()
        ruleset.safe_ip.return_value = TEST_IP1
        mode = _make_hook_mode(runner=runner, ruleset=ruleset)

        mode.deny_ip("test-ctr", TEST_IP1)
        call_args = runner.nft_via_nsenter.call_args[0]
        self.assertIn("delete", call_args)
        self.assertIn("allow_v4", call_args)


class TestHookModeListRules(unittest.TestCase):
    """Test HookMode.list_rules()."""

    def test_returns_output(self) -> None:
        """list_rules returns nft output."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.return_value = "table inet terok_shield {}"
        mode = _make_hook_mode(runner=runner)

        result = mode.list_rules("test-ctr")
        self.assertIn("terok_shield", result)

    def test_returns_empty_on_exec_error(self) -> None:
        """list_rules returns empty string on ExecError."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "error")
        mode = _make_hook_mode(runner=runner)

        result = mode.list_rules("test-ctr")
        self.assertEqual(result, "")


class TestHookModeShieldDown(unittest.TestCase):
    """Test HookMode.shield_down()."""

    def test_applies_bypass_ruleset(self) -> None:
        """shield_down applies bypass ruleset and verifies."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.side_effect = ["", "valid output"]
        ruleset = mock.MagicMock()
        ruleset.build_bypass.return_value = "bypass ruleset"
        ruleset.verify_bypass.return_value = []  # no errors
        mode = _make_hook_mode(runner=runner, ruleset=ruleset)

        mode.shield_down("test-ctr")
        self.assertEqual(runner.nft_via_nsenter.call_count, 2)
        ruleset.build_bypass.assert_called_once_with(allow_all=False)

    def test_verification_failure_raises(self) -> None:
        """shield_down raises RuntimeError on verification failure."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.side_effect = ["", "bad output"]
        ruleset = mock.MagicMock()
        ruleset.build_bypass.return_value = "bypass"
        ruleset.verify_bypass.return_value = ["error: missing policy"]
        mode = _make_hook_mode(runner=runner, ruleset=ruleset)

        with self.assertRaises(RuntimeError) as ctx:
            mode.shield_down("test-ctr")
        self.assertIn("verification failed", str(ctx.exception))


class TestHookModeShieldUp(unittest.TestCase):
    """Test HookMode.shield_up()."""

    def test_applies_hook_ruleset(self) -> None:
        """shield_up applies hook ruleset and verifies."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.side_effect = ["", "valid output"]
        runner.podman_inspect.return_value = "test"
        ruleset = mock.MagicMock()
        ruleset.build_hook.return_value = "hook ruleset"
        ruleset.verify_hook.return_value = []
        ruleset.add_elements_dual.return_value = ""

        with tempfile.TemporaryDirectory() as td:
            config = ShieldConfig(
                paths=mock.MagicMock(resolved_dir=Path(td)),
            )
            mode = _make_hook_mode(config=config, runner=runner, ruleset=ruleset)
            mode.shield_up("test-ctr")
            self.assertEqual(runner.nft_via_nsenter.call_count, 2)

    def test_readds_cached_ips(self) -> None:
        """shield_up re-adds cached IPs from resolved file."""
        with tempfile.TemporaryDirectory() as td:
            resolved = Path(td) / "test.resolved"
            resolved.write_text(f"{TEST_IP1}\n")

            runner = mock.MagicMock()
            runner.nft_via_nsenter.side_effect = ["", "", "valid output"]
            runner.podman_inspect.return_value = "test"
            ruleset = mock.MagicMock()
            ruleset.build_hook.return_value = "hook"
            ruleset.verify_hook.return_value = []
            ruleset.add_elements_dual.return_value = f"add element {TEST_IP1}"

            config = ShieldConfig(paths=mock.MagicMock(resolved_dir=Path(td)))
            mode = _make_hook_mode(config=config, runner=runner, ruleset=ruleset)
            mode.shield_up("test-ctr")
            self.assertEqual(runner.nft_via_nsenter.call_count, 3)

    def test_verification_failure_raises(self) -> None:
        """shield_up raises RuntimeError on verification failure."""
        with tempfile.TemporaryDirectory() as td:
            runner = mock.MagicMock()
            runner.nft_via_nsenter.side_effect = ["", "bad output"]
            runner.podman_inspect.return_value = "test"
            ruleset = mock.MagicMock()
            ruleset.build_hook.return_value = "hook"
            ruleset.verify_hook.return_value = ["error"]
            ruleset.add_elements_dual.return_value = ""

            config = ShieldConfig(paths=mock.MagicMock(resolved_dir=Path(td)))
            mode = _make_hook_mode(config=config, runner=runner, ruleset=ruleset)
            with self.assertRaises(RuntimeError):
                mode.shield_up("test-ctr")


class TestHookModeResolveContainerName(unittest.TestCase):
    """Test HookMode._resolve_container_name()."""

    def test_returns_annotation_name(self) -> None:
        """Returns canonical name from annotation."""
        runner = mock.MagicMock()
        runner.podman_inspect.return_value = "my-container"
        mode = _make_hook_mode(runner=runner)
        self.assertEqual(mode._resolve_container_name("abc123"), "my-container")

    def test_falls_back_on_error(self) -> None:
        """Falls back to raw arg when podman inspect fails."""
        runner = mock.MagicMock()
        runner.podman_inspect.side_effect = RuntimeError("not running")
        mode = _make_hook_mode(runner=runner)
        self.assertEqual(mode._resolve_container_name("abc123"), "abc123")

    def test_falls_back_on_no_value(self) -> None:
        """Falls back to raw arg when annotation returns <no value>."""
        runner = mock.MagicMock()
        runner.podman_inspect.return_value = "<no value>"
        mode = _make_hook_mode(runner=runner)
        self.assertEqual(mode._resolve_container_name("abc123"), "abc123")

    def test_falls_back_on_empty(self) -> None:
        """Falls back to raw arg when annotation is empty."""
        runner = mock.MagicMock()
        runner.podman_inspect.return_value = ""
        mode = _make_hook_mode(runner=runner)
        self.assertEqual(mode._resolve_container_name("abc123"), "abc123")


class TestHookModeShieldState(unittest.TestCase):
    """Test HookMode.shield_state()."""

    def test_inactive_on_empty(self) -> None:
        """Empty nft output means INACTIVE."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.return_value = ""
        ruleset = mock.MagicMock()
        mode = _make_hook_mode(runner=runner, ruleset=ruleset)
        self.assertEqual(mode.shield_state("test"), ShieldState.INACTIVE)

    def test_up_detected(self) -> None:
        """Hook ruleset detected as UP."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.return_value = hook_ruleset()
        ruleset = mock.MagicMock()
        ruleset.verify_bypass.return_value = ["not bypass"]
        ruleset.verify_hook.return_value = []  # passes hook verification
        mode = _make_hook_mode(runner=runner, ruleset=ruleset)
        self.assertEqual(mode.shield_state("test"), ShieldState.UP)

    def test_down_detected(self) -> None:
        """Bypass ruleset detected as DOWN."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.return_value = bypass_ruleset()
        ruleset = mock.MagicMock()
        ruleset.verify_bypass.return_value = []  # passes bypass verification
        mode = _make_hook_mode(runner=runner, ruleset=ruleset)
        self.assertEqual(mode.shield_state("test"), ShieldState.DOWN)

    def test_error_detected(self) -> None:
        """Unrecognised ruleset detected as ERROR."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.return_value = "random nft stuff"
        ruleset = mock.MagicMock()
        ruleset.verify_bypass.return_value = ["not bypass"]
        ruleset.verify_hook.return_value = ["not hook"]
        mode = _make_hook_mode(runner=runner, ruleset=ruleset)
        self.assertEqual(mode.shield_state("test"), ShieldState.ERROR)


class TestHookModePreview(unittest.TestCase):
    """Test HookMode.preview()."""

    def test_default_returns_hook(self) -> None:
        """Default preview returns hook ruleset."""
        ruleset = mock.MagicMock()
        ruleset.build_hook.return_value = "hook ruleset"
        mode = _make_hook_mode(ruleset=ruleset)

        result = mode.preview()
        ruleset.build_hook.assert_called_once()
        self.assertEqual(result, "hook ruleset")

    def test_down_returns_bypass(self) -> None:
        """Preview with down=True returns bypass ruleset."""
        ruleset = mock.MagicMock()
        ruleset.build_bypass.return_value = "bypass ruleset"
        mode = _make_hook_mode(ruleset=ruleset)

        result = mode.preview(down=True, allow_all=True)
        ruleset.build_bypass.assert_called_once_with(allow_all=True)
        self.assertEqual(result, "bypass ruleset")


class TestHookModeDetectNetwork(unittest.TestCase):
    """Test HookMode._detect_rootless_network_mode()."""

    def test_pasta_from_podman_info(self) -> None:
        """Detect pasta mode from podman info output."""
        runner = mock.MagicMock()
        runner.run.return_value = json.dumps({"host": {"rootlessNetworkCmd": "pasta"}})
        mode = _make_hook_mode(runner=runner)
        self.assertEqual(mode._detect_rootless_network_mode(), "pasta")

    def test_slirp4netns(self) -> None:
        """Detect slirp4netns from podman info output."""
        runner = mock.MagicMock()
        runner.run.return_value = json.dumps({"host": {"rootlessNetworkCmd": "slirp4netns"}})
        mode = _make_hook_mode(runner=runner)
        self.assertEqual(mode._detect_rootless_network_mode(), "slirp4netns")

    def test_fallback_on_empty(self) -> None:
        """Default to pasta on empty output."""
        runner = mock.MagicMock()
        runner.run.return_value = ""
        mode = _make_hook_mode(runner=runner)
        self.assertEqual(mode._detect_rootless_network_mode(), "pasta")

    def test_fallback_on_invalid_json(self) -> None:
        """Default to pasta on invalid JSON."""
        runner = mock.MagicMock()
        runner.run.return_value = "not json"
        mode = _make_hook_mode(runner=runner)
        self.assertEqual(mode._detect_rootless_network_mode(), "pasta")
