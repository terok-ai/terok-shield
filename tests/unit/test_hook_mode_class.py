# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the HookMode class."""

import json
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from terok_shield import state
from terok_shield.config import ANNOTATION_KEY, ShieldConfig, ShieldState
from terok_shield.mode_hook import HookMode, install_hooks
from terok_shield.nft import bypass_ruleset, hook_ruleset
from terok_shield.run import ExecError

from ..testnet import IPV6_CLOUDFLARE, TEST_DOMAIN, TEST_IP1, TEST_IP2

_DISPOSABLE_DIRS: list[tempfile.TemporaryDirectory] = []
"""Managed temp dirs for mock-only tests (cleaned up at process exit)."""


def _make_hook_mode(
    tmp_path: Path | None = None,
    config: ShieldConfig | None = None,
    *,
    runner: mock.MagicMock | None = None,
    audit: mock.MagicMock | None = None,
    dns: mock.MagicMock | None = None,
    profiles: mock.MagicMock | None = None,
    ruleset: mock.MagicMock | None = None,
) -> HookMode:
    """Create a HookMode with mock collaborators."""
    if config is None:
        if tmp_path is None:
            td = tempfile.TemporaryDirectory()
            _DISPOSABLE_DIRS.append(td)
            tmp_path = Path(td.name)
        config = ShieldConfig(state_dir=tmp_path)
    return HookMode(
        config=config,
        runner=runner or mock.MagicMock(),
        audit=audit or mock.MagicMock(),
        dns=dns or mock.MagicMock(),
        profiles=profiles or mock.MagicMock(),
        ruleset=ruleset or mock.MagicMock(),
    )


class TestHookModeInit:
    """Test HookMode construction."""

    def test_stores_collaborators(self) -> None:
        """HookMode stores all injected collaborators."""
        runner = mock.MagicMock()
        audit = mock.MagicMock()
        dns = mock.MagicMock()
        profiles = mock.MagicMock()
        ruleset = mock.MagicMock()
        with tempfile.TemporaryDirectory() as tmp:
            config = ShieldConfig(state_dir=Path(tmp))
            mode = HookMode(
                config=config,
                runner=runner,
                audit=audit,
                dns=dns,
                profiles=profiles,
                ruleset=ruleset,
            )
            assert mode._config is config
            assert mode._runner is runner
            assert mode._audit is audit
            assert mode._dns is dns
            assert mode._profiles is profiles
            assert mode._ruleset is ruleset


class TestHookModePreStart:
    """Test HookMode.pre_start()."""

    @mock.patch("os.geteuid", return_value=1000)
    def test_pasta_args(self, _euid) -> None:
        """Pre-start returns pasta network args for rootless mode."""
        with tempfile.TemporaryDirectory() as tmp:
            config = ShieldConfig(state_dir=Path(tmp), loopback_ports=(8080,))
            runner = mock.MagicMock()
            runner.run.return_value = json.dumps({"host": {"rootlessNetworkCmd": "pasta"}})
            profiles_mock = mock.MagicMock()
            profiles_mock.compose_profiles.return_value = [TEST_DOMAIN]
            dns = mock.MagicMock()
            mode = _make_hook_mode(
                config=config,
                runner=runner,
                profiles=profiles_mock,
                dns=dns,
            )
            args = mode.pre_start("test", ["dev-standard"])
            assert "--network" in args
            net_idx = args.index("--network") + 1
            assert "pasta:" in args[net_idx]
            assert "-T,8080" in args[net_idx]

    def test_installs_hooks(self) -> None:
        """pre_start installs hooks and creates state dirs."""
        with tempfile.TemporaryDirectory() as tmp:
            config = ShieldConfig(state_dir=Path(tmp))
            profiles_mock = mock.MagicMock()
            profiles_mock.compose_profiles.return_value = []
            dns = mock.MagicMock()
            mode = _make_hook_mode(config=config, profiles=profiles_mock, dns=dns)
            with mock.patch("os.geteuid", return_value=0):
                mode.pre_start("test", ["dev-standard"])
            # Check hooks were installed
            assert state.hooks_dir(Path(tmp)).is_dir()
            assert state.hook_entrypoint(Path(tmp)).is_file()

    def test_annotations_include_state_dir(self) -> None:
        """pre_start includes state_dir annotation."""
        with tempfile.TemporaryDirectory() as tmp:
            config = ShieldConfig(state_dir=Path(tmp), loopback_ports=(1234,))
            profiles_mock = mock.MagicMock()
            profiles_mock.compose_profiles.return_value = []
            dns = mock.MagicMock()
            mode = _make_hook_mode(config=config, profiles=profiles_mock, dns=dns)
            with mock.patch("os.geteuid", return_value=0):
                args = mode.pre_start("test", ["dev-standard"])
            # Find state_dir annotation
            for i, arg in enumerate(args):
                if arg == "--annotation" and "terok.shield.state_dir=" in args[i + 1]:
                    assert str(Path(tmp)) in args[i + 1]
                    break
            else:
                pytest.fail("state_dir annotation not found in args")

    def test_annotations_include_audit_enabled(self) -> None:
        """pre_start includes audit_enabled annotation."""
        with tempfile.TemporaryDirectory() as tmp:
            config = ShieldConfig(state_dir=Path(tmp), audit_enabled=False)
            profiles_mock = mock.MagicMock()
            profiles_mock.compose_profiles.return_value = []
            dns = mock.MagicMock()
            mode = _make_hook_mode(config=config, profiles=profiles_mock, dns=dns)
            with mock.patch("os.geteuid", return_value=0):
                args = mode.pre_start("test", ["dev-standard"])
            # Find audit_enabled annotation
            for i, arg in enumerate(args):
                if arg == "--annotation" and "terok.shield.audit_enabled=" in args[i + 1]:
                    assert "false" in args[i + 1]
                    break
            else:
                pytest.fail("audit_enabled annotation not found in args")


class TestHookModeAllowDeny:
    """Test HookMode.allow_ip() and deny_ip()."""

    def test_allow_ipv4(self) -> None:
        """allow_ip adds element to allow_v4 set."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.MagicMock()
            ruleset = mock.MagicMock()
            ruleset.safe_ip.return_value = TEST_IP1
            mode = _make_hook_mode(tmp_path=Path(tmp), runner=runner, ruleset=ruleset)

            mode.allow_ip("test-ctr", TEST_IP1)
            runner.nft_via_nsenter.assert_called_once()
            call_args = runner.nft_via_nsenter.call_args[0]
            assert "add" in call_args
            assert "allow_v4" in call_args

    def test_allow_persists_to_live_allowed(self) -> None:
        """allow_ip persists IP to live.allowed file."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.MagicMock()
            ruleset = mock.MagicMock()
            ruleset.safe_ip.return_value = TEST_IP1
            mode = _make_hook_mode(tmp_path=Path(tmp), runner=runner, ruleset=ruleset)

            mode.allow_ip("test-ctr", TEST_IP1)
            live_path = state.live_allowed_path(Path(tmp))
            assert live_path.is_file()
            assert TEST_IP1 in live_path.read_text()

    def test_allow_deduplicates_live_allowed(self) -> None:
        """allow_ip does not append duplicate entries to live.allowed."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.MagicMock()
            ruleset = mock.MagicMock()
            ruleset.safe_ip.return_value = TEST_IP1
            mode = _make_hook_mode(tmp_path=Path(tmp), runner=runner, ruleset=ruleset)

            mode.allow_ip("test-ctr", TEST_IP1)
            mode.allow_ip("test-ctr", TEST_IP1)
            live_path = state.live_allowed_path(Path(tmp))
            lines = [line for line in live_path.read_text().splitlines() if line.strip()]
            assert lines.count(TEST_IP1) == 1

    def test_allow_ipv6(self) -> None:
        """allow_ip adds element to allow_v6 set for IPv6."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.MagicMock()
            ruleset = mock.MagicMock()
            ruleset.safe_ip.return_value = IPV6_CLOUDFLARE
            mode = _make_hook_mode(tmp_path=Path(tmp), runner=runner, ruleset=ruleset)

            mode.allow_ip("test-ctr", IPV6_CLOUDFLARE)
            call_args = runner.nft_via_nsenter.call_args[0]
            assert "allow_v6" in call_args

    def test_deny_ipv4(self) -> None:
        """deny_ip removes element from allow_v4 set."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.MagicMock()
            ruleset = mock.MagicMock()
            ruleset.safe_ip.return_value = TEST_IP1
            mode = _make_hook_mode(tmp_path=Path(tmp), runner=runner, ruleset=ruleset)

            mode.deny_ip("test-ctr", TEST_IP1)
            call_args = runner.nft_via_nsenter.call_args[0]
            assert "delete" in call_args
            assert "allow_v4" in call_args

    def test_deny_removes_from_live_allowed(self) -> None:
        """deny_ip removes IP from live.allowed file."""
        with tempfile.TemporaryDirectory() as tmp:
            live_path = state.live_allowed_path(Path(tmp))
            live_path.parent.mkdir(parents=True, exist_ok=True)
            live_path.write_text(f"{TEST_IP1}\n")

            runner = mock.MagicMock()
            ruleset = mock.MagicMock()
            ruleset.safe_ip.return_value = TEST_IP1
            mode = _make_hook_mode(tmp_path=Path(tmp), runner=runner, ruleset=ruleset)

            mode.deny_ip("test-ctr", TEST_IP1)
            assert TEST_IP1 not in live_path.read_text().splitlines()

    def test_deny_profile_ip_writes_deny_list(self) -> None:
        """deny_ip of a profile-sourced IP persists to deny.list."""
        with tempfile.TemporaryDirectory() as tmp:
            state.profile_allowed_path(Path(tmp)).write_text(f"{TEST_IP1}\n")

            runner = mock.MagicMock()
            ruleset = mock.MagicMock()
            ruleset.safe_ip.return_value = TEST_IP1
            mode = _make_hook_mode(tmp_path=Path(tmp), runner=runner, ruleset=ruleset)

            mode.deny_ip("test-ctr", TEST_IP1)
            deny_file = state.deny_path(Path(tmp))
            assert deny_file.is_file()
            assert TEST_IP1 in deny_file.read_text()

    def test_deny_live_only_ip_no_deny_list(self) -> None:
        """deny_ip of a live-only IP does NOT write deny.list."""
        with tempfile.TemporaryDirectory() as tmp:
            state.live_allowed_path(Path(tmp)).write_text(f"{TEST_IP1}\n")

            runner = mock.MagicMock()
            ruleset = mock.MagicMock()
            ruleset.safe_ip.return_value = TEST_IP1
            mode = _make_hook_mode(tmp_path=Path(tmp), runner=runner, ruleset=ruleset)

            mode.deny_ip("test-ctr", TEST_IP1)
            deny_file = state.deny_path(Path(tmp))
            assert not deny_file.is_file()

    def test_deny_nft_error_still_persists(self) -> None:
        """nft delete element ExecError is caught; deny still persists to files."""
        with tempfile.TemporaryDirectory() as tmp:
            state.profile_allowed_path(Path(tmp)).write_text(f"{TEST_IP1}\n")
            state.live_allowed_path(Path(tmp)).write_text(f"{TEST_IP1}\n")

            runner = mock.MagicMock()
            runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "not in set")
            ruleset = mock.MagicMock()
            ruleset.safe_ip.return_value = TEST_IP1
            mode = _make_hook_mode(tmp_path=Path(tmp), runner=runner, ruleset=ruleset)

            mode.deny_ip("test-ctr", TEST_IP1)
            # live.allowed should still have IP removed
            live_content = state.live_allowed_path(Path(tmp)).read_text()
            assert TEST_IP1 not in live_content.splitlines()
            # deny.list should be written
            assert TEST_IP1 in state.deny_path(Path(tmp)).read_text()

    def test_allow_after_deny_clears_deny_list(self) -> None:
        """allow_ip removes IP from deny.list (un-deny)."""
        with tempfile.TemporaryDirectory() as tmp:
            state.deny_path(Path(tmp)).write_text(f"{TEST_IP1}\n{TEST_IP2}\n")

            runner = mock.MagicMock()
            ruleset = mock.MagicMock()
            ruleset.safe_ip.return_value = TEST_IP1
            mode = _make_hook_mode(tmp_path=Path(tmp), runner=runner, ruleset=ruleset)

            mode.allow_ip("test-ctr", TEST_IP1)
            denied = state.read_denied_ips(Path(tmp))
            assert TEST_IP1 not in denied
            assert TEST_IP2 in denied


class TestHookModeListRules:
    """Test HookMode.list_rules()."""

    def test_returns_output(self) -> None:
        """list_rules returns nft output."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.return_value = "table inet terok_shield {}"
        mode = _make_hook_mode(runner=runner)

        result = mode.list_rules("test-ctr")
        assert "terok_shield" in result

    def test_returns_empty_on_exec_error(self) -> None:
        """list_rules returns empty string on ExecError."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "error")
        mode = _make_hook_mode(runner=runner)

        result = mode.list_rules("test-ctr")
        assert result == ""


class TestHookModeShieldDown:
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
        assert runner.nft_via_nsenter.call_count == 2
        ruleset.build_bypass.assert_called_once_with(allow_all=False)

    def test_verification_failure_raises(self) -> None:
        """shield_down raises RuntimeError on verification failure."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.side_effect = ["", "bad output"]
        ruleset = mock.MagicMock()
        ruleset.build_bypass.return_value = "bypass"
        ruleset.verify_bypass.return_value = ["error: missing policy"]
        mode = _make_hook_mode(runner=runner, ruleset=ruleset)

        with pytest.raises(RuntimeError) as ctx:
            mode.shield_down("test-ctr")
        assert "verification failed" in str(ctx.value)


class TestHookModeShieldUp:
    """Test HookMode.shield_up()."""

    def test_applies_hook_ruleset(self) -> None:
        """shield_up applies hook ruleset and verifies."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.MagicMock()
            runner.nft_via_nsenter.side_effect = ["", "valid output"]
            ruleset = mock.MagicMock()
            ruleset.build_hook.return_value = "hook ruleset"
            ruleset.verify_hook.return_value = []
            ruleset.add_elements_dual.return_value = ""
            config = ShieldConfig(state_dir=Path(tmp))
            mode = _make_hook_mode(config=config, runner=runner, ruleset=ruleset)
            mode.shield_up("test-ctr")
            assert runner.nft_via_nsenter.call_count == 2

    def test_readds_cached_ips(self) -> None:
        """shield_up re-adds cached IPs from allowlist files."""
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = state.profile_allowed_path(Path(tmp))
            profile_path.write_text(f"{TEST_IP1}\n")

            runner = mock.MagicMock()
            runner.nft_via_nsenter.side_effect = ["", "", "valid output"]
            ruleset = mock.MagicMock()
            ruleset.build_hook.return_value = "hook"
            ruleset.verify_hook.return_value = []
            ruleset.add_elements_dual.return_value = f"add element {TEST_IP1}"

            config = ShieldConfig(state_dir=Path(tmp))
            mode = _make_hook_mode(config=config, runner=runner, ruleset=ruleset)
            mode.shield_up("test-ctr")
            assert runner.nft_via_nsenter.call_count == 3

    def test_verification_failure_raises(self) -> None:
        """shield_up raises RuntimeError on verification failure."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.MagicMock()
            runner.nft_via_nsenter.side_effect = ["", "bad output"]
            ruleset = mock.MagicMock()
            ruleset.build_hook.return_value = "hook"
            ruleset.verify_hook.return_value = ["error"]
            ruleset.add_elements_dual.return_value = ""

            config = ShieldConfig(state_dir=Path(tmp))
            mode = _make_hook_mode(config=config, runner=runner, ruleset=ruleset)
            with pytest.raises(RuntimeError):
                mode.shield_up("test-ctr")


class TestHookModeShieldState:
    """Test HookMode.shield_state()."""

    def test_inactive_on_empty(self) -> None:
        """Empty nft output means INACTIVE."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.return_value = ""
        ruleset = mock.MagicMock()
        mode = _make_hook_mode(runner=runner, ruleset=ruleset)
        assert mode.shield_state("test") == ShieldState.INACTIVE

    def test_up_detected(self) -> None:
        """Hook ruleset detected as UP."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.return_value = hook_ruleset()
        ruleset = mock.MagicMock()
        ruleset.verify_bypass.return_value = ["not bypass"]
        ruleset.verify_hook.return_value = []  # passes hook verification
        mode = _make_hook_mode(runner=runner, ruleset=ruleset)
        assert mode.shield_state("test") == ShieldState.UP

    def test_down_detected(self) -> None:
        """Bypass ruleset detected as DOWN."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.return_value = bypass_ruleset()
        ruleset = mock.MagicMock()
        ruleset.verify_bypass.return_value = []  # passes bypass verification
        mode = _make_hook_mode(runner=runner, ruleset=ruleset)
        assert mode.shield_state("test") == ShieldState.DOWN

    def test_error_detected(self) -> None:
        """Unrecognised ruleset detected as ERROR."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.return_value = "random nft stuff"
        ruleset = mock.MagicMock()
        ruleset.verify_bypass.return_value = ["not bypass"]
        ruleset.verify_hook.return_value = ["not hook"]
        mode = _make_hook_mode(runner=runner, ruleset=ruleset)
        assert mode.shield_state("test") == ShieldState.ERROR


class TestHookModePreview:
    """Test HookMode.preview()."""

    def test_default_returns_hook(self) -> None:
        """Default preview returns hook ruleset."""
        ruleset = mock.MagicMock()
        ruleset.build_hook.return_value = "hook ruleset"
        mode = _make_hook_mode(ruleset=ruleset)

        result = mode.preview()
        ruleset.build_hook.assert_called_once()
        assert result == "hook ruleset"

    def test_down_returns_bypass(self) -> None:
        """Preview with down=True returns bypass ruleset."""
        ruleset = mock.MagicMock()
        ruleset.build_bypass.return_value = "bypass ruleset"
        mode = _make_hook_mode(ruleset=ruleset)

        result = mode.preview(down=True, allow_all=True)
        ruleset.build_bypass.assert_called_once_with(allow_all=True)
        assert result == "bypass ruleset"


class TestHookModeDetectNetwork:
    """Test HookMode._detect_rootless_network_mode()."""

    def test_pasta_from_podman_info(self) -> None:
        """Detect pasta mode from podman info output."""
        runner = mock.MagicMock()
        runner.run.return_value = json.dumps({"host": {"rootlessNetworkCmd": "pasta"}})
        mode = _make_hook_mode(runner=runner)
        assert mode._detect_rootless_network_mode() == "pasta"

    def test_slirp4netns(self) -> None:
        """Detect slirp4netns from podman info output."""
        runner = mock.MagicMock()
        runner.run.return_value = json.dumps({"host": {"rootlessNetworkCmd": "slirp4netns"}})
        mode = _make_hook_mode(runner=runner)
        assert mode._detect_rootless_network_mode() == "slirp4netns"

    def test_fallback_on_empty(self) -> None:
        """Default to pasta on empty output."""
        runner = mock.MagicMock()
        runner.run.return_value = ""
        mode = _make_hook_mode(runner=runner)
        assert mode._detect_rootless_network_mode() == "pasta"

    def test_fallback_on_invalid_json(self) -> None:
        """Default to pasta on invalid JSON."""
        runner = mock.MagicMock()
        runner.run.return_value = "not json"
        mode = _make_hook_mode(runner=runner)
        assert mode._detect_rootless_network_mode() == "pasta"


class TestInstallHooks:
    """Test install_hooks() writes entrypoint and hook JSON files."""

    def test_creates_entrypoint_and_hook_jsons(self) -> None:
        """install_hooks creates executable entrypoint and both hook JSONs."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ep = base / "bin" / "terok-shield-hook"
            hooks = base / "hooks"

            install_hooks(hook_entrypoint=ep, hooks_dir=hooks)

            # Entrypoint exists and is executable
            assert ep.exists()
            assert ep.stat().st_mode & 0o100  # owner-execute bit
            content = ep.read_text()
            assert content.startswith("#!/bin/sh\n")
            assert "terok_shield.oci_hook" in content

            # Both hook JSON files exist with correct structure
            for stage_name in ("createRuntime", "poststop"):
                hook_file = hooks / f"terok-shield-{stage_name}.json"
                assert hook_file.exists()
                data = json.loads(hook_file.read_text())
                assert data["version"] == "1.0.0"
                assert data["hook"]["path"] == str(ep)
                assert stage_name in data["stages"]
                assert ANNOTATION_KEY in data["when"]["annotations"]
