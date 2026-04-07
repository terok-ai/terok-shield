# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: podman environment detection and setup.

Tests check_environment(), setup command, and the version gate
against the real podman installation on the host.
"""

from pathlib import Path

import pytest

from terok_shield import EnvironmentCheck, Shield, ShieldConfig
from terok_shield.hooks.install import setup_global_hooks
from terok_shield.podman_info import (
    ensure_containers_conf_hooks_dir,
    find_hooks_dirs,
    has_global_hooks,
    parse_podman_info,
)
from terok_shield.run import ShieldNeedsSetup

from ..conftest import hooks_present, nft_missing, podman_missing


@pytest.mark.needs_host_features
@podman_missing
class TestPodmanInfoDetection:
    """Verify podman info parsing against the real host."""

    def test_parse_real_podman_info(self, shield_env: Path) -> None:
        """parse_podman_info() returns a valid version from the real host."""
        import subprocess

        output = subprocess.run(
            ["podman", "info", "-f", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        info = parse_podman_info(output.stdout)
        assert info.version >= (4,), f"Unexpected podman version: {info.version}"
        assert info.network_mode in ("pasta", "slirp4netns")

    def test_check_environment_returns_valid_result(self, shield_env: Path) -> None:
        """check_environment() returns a well-formed EnvironmentCheck."""
        shield = Shield(ShieldConfig(state_dir=shield_env / "containers" / "test"))
        env = shield.check_environment()
        assert isinstance(env, EnvironmentCheck)
        assert env.podman_version >= (4,)
        assert env.hooks in ("global-system", "global-user", "not-installed")
        assert env.health in ("ok", "setup-needed")

    def test_hooks_dir_detection(self) -> None:
        """find_hooks_dirs() returns paths (may be empty on minimal systems)."""
        dirs = find_hooks_dirs()
        assert isinstance(dirs, list)
        for d in dirs:
            assert isinstance(d, Path)


@pytest.mark.needs_podman
@podman_missing
@nft_missing
@hooks_present
class TestHooklessErrorPath:
    """Verify the error path when no OCI hooks are available."""

    def test_pre_start_raises_shield_needs_setup(self, shield_env: Path) -> None:
        """pre_start() raises ShieldNeedsSetup with setup hint when hooks are missing."""
        sd = shield_env / "containers" / "hookless-test"
        shield = Shield(ShieldConfig(state_dir=sd))
        with pytest.raises(ShieldNeedsSetup, match="terok-shield setup"):
            shield.pre_start("hookless-test")


@pytest.mark.needs_host_features
@podman_missing
class TestGlobalHooksSetup:
    """Test global hooks installation with real filesystem."""

    def test_setup_user_hooks(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """setup --user installs hooks and updates containers.conf."""
        hooks_dir = tmp_path / "hooks.d"
        conf_dir = tmp_path / "config" / "containers"
        monkeypatch.setattr(
            "terok_shield.podman_info._user_containers_conf",
            lambda: conf_dir / "containers.conf",
        )

        # Install hooks
        setup_global_hooks(hooks_dir)
        assert (hooks_dir / "terok-shield-createRuntime.json").is_file()
        assert (hooks_dir / "terok-shield-poststop.json").is_file()
        assert (hooks_dir / "terok-shield-hook").is_file()

        # Verify entrypoint is executable
        hook = hooks_dir / "terok-shield-hook"
        assert hook.stat().st_mode & 0o100

        # Update containers.conf
        ensure_containers_conf_hooks_dir(hooks_dir)
        conf = conf_dir / "containers.conf"
        assert conf.is_file()
        text = conf.read_text()
        assert str(hooks_dir) in text
        assert text.count("[engine]") == 1

    def test_has_global_hooks_after_setup(self, tmp_path: Path) -> None:
        """has_global_hooks() returns True after setup_global_hooks()."""
        hooks_dir = tmp_path / "hooks.d"
        assert not has_global_hooks([hooks_dir])
        setup_global_hooks(hooks_dir)
        assert has_global_hooks([hooks_dir])

    def test_setup_idempotent(self, tmp_path: Path) -> None:
        """Running setup twice does not break anything."""
        hooks_dir = tmp_path / "hooks.d"
        setup_global_hooks(hooks_dir)
        first_content = (hooks_dir / "terok-shield-hook").read_text()
        setup_global_hooks(hooks_dir)
        assert (hooks_dir / "terok-shield-hook").read_text() == first_content
