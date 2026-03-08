# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: config path resolution and auto-detect with real podman."""

from pathlib import Path

import pytest

from terok_shield.config import (
    ShieldMode,
    _auto_detect_mode,
    ensure_shield_dirs,
    shield_config_root,
    shield_state_root,
)

from .conftest import podman_missing


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


@pytest.mark.integration
@podman_missing
class TestAutoDetect:
    """Test _auto_detect_mode with real podman."""

    def test_returns_valid_mode(self) -> None:
        """Auto-detect must return a valid ShieldMode."""
        mode = _auto_detect_mode()
        assert isinstance(mode, ShieldMode)

    def test_at_least_standard_with_nft(self, nft_in_netns: None) -> None:
        """If nft works in a container netns, auto-detect returns at least STANDARD."""
        mode = _auto_detect_mode()
        assert mode in (ShieldMode.STANDARD, ShieldMode.HARDENED)
