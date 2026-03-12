# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: config path resolution with real environment."""

from pathlib import Path

import pytest

from terok_shield.config import ShieldPaths


@pytest.mark.needs_host_features
class TestPathResolution:
    """Test XDG path resolution with real environment."""

    def test_state_root_with_xdg(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """XDG_STATE_HOME is respected."""
        monkeypatch.delenv("TEROK_SHIELD_STATE_DIR", raising=False)
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))

        paths = ShieldPaths.from_env()
        assert paths.state_root == tmp_path / "state" / "terok-shield"

    def test_config_root_with_xdg(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """XDG_CONFIG_HOME is respected."""
        monkeypatch.delenv("TEROK_SHIELD_CONFIG_DIR", raising=False)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))

        paths = ShieldPaths.from_env()
        assert paths.config_root == tmp_path / "config" / "terok-shield"

    def test_explicit_overrides_xdg(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Explicit env var overrides XDG."""
        monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", str(tmp_path / "explicit"))
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))

        paths = ShieldPaths.from_env()
        assert paths.state_root == tmp_path / "explicit"

    def test_ensure_dirs_creates_tree(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ShieldPaths.ensure_dirs() creates the full directory tree."""
        paths = ShieldPaths(
            state_root=tmp_path / "state",
            config_root=tmp_path / "config",
        )

        paths.ensure_dirs()

        assert (tmp_path / "state" / "hooks").is_dir()
        assert (tmp_path / "state" / "logs").is_dir()
        assert (tmp_path / "state" / "dns").is_dir()
        assert (tmp_path / "state" / "resolved").is_dir()
        assert (tmp_path / "config" / "profiles").is_dir()
