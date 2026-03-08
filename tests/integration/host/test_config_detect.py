# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: config path resolution with real environment."""

from pathlib import Path

import pytest

from terok_shield.config import ensure_shield_dirs, shield_config_root, shield_state_root


@pytest.mark.needs_host_features
class TestPathResolution:
    """Test XDG path resolution with real environment."""

    def test_state_root_with_xdg(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """XDG_STATE_HOME is respected."""
        monkeypatch.delenv("TEROK_SHIELD_STATE_DIR", raising=False)
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))

        result = shield_state_root()
        assert result == tmp_path / "state" / "terok-shield"

    def test_config_root_with_xdg(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """XDG_CONFIG_HOME is respected."""
        monkeypatch.delenv("TEROK_SHIELD_CONFIG_DIR", raising=False)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))

        result = shield_config_root()
        assert result == tmp_path / "config" / "terok-shield"

    def test_explicit_overrides_xdg(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Explicit env var overrides XDG."""
        monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", str(tmp_path / "explicit"))
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))

        result = shield_state_root()
        assert result == tmp_path / "explicit"

    def test_ensure_dirs_creates_tree(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ensure_shield_dirs creates the full directory tree."""
        monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", str(tmp_path / "state"))
        monkeypatch.setenv("TEROK_SHIELD_CONFIG_DIR", str(tmp_path / "config"))

        ensure_shield_dirs()

        assert (tmp_path / "state" / "hooks").is_dir()
        assert (tmp_path / "state" / "logs").is_dir()
        assert (tmp_path / "state" / "dns").is_dir()
        assert (tmp_path / "state" / "resolved").is_dir()
        assert (tmp_path / "config" / "profiles").is_dir()
