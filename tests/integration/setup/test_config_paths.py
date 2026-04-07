# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: config path resolution with real environment."""

from pathlib import Path

import pytest

from terok_shield import state
from terok_shield.cli.main import _resolve_config_root, _resolve_state_root


@pytest.mark.needs_host_features
class TestPathResolution:
    """Test XDG path resolution with real environment."""

    def test_state_root_with_xdg(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """XDG_STATE_HOME is respected."""
        monkeypatch.delenv("TEROK_SHIELD_STATE_DIR", raising=False)
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))

        root = _resolve_state_root()
        assert root == tmp_path / "state" / "terok" / "shield"

    def test_config_root_with_xdg(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """XDG_CONFIG_HOME is respected."""
        monkeypatch.delenv("TEROK_SHIELD_CONFIG_DIR", raising=False)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))

        root = _resolve_config_root()
        assert root == tmp_path / "config" / "terok" / "shield"

    def test_explicit_overrides_xdg(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Explicit env var overrides XDG."""
        monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", str(tmp_path / "explicit"))
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))

        root = _resolve_state_root()
        assert root == tmp_path / "explicit"

    def test_ensure_state_dirs_creates_tree(self, tmp_path: Path) -> None:
        """state.ensure_state_dirs() creates the bundle directory tree."""
        sd = tmp_path / "containers" / "test-ctr"
        state.ensure_state_dirs(sd)

        assert sd.is_dir()
        assert state.hooks_dir(sd).is_dir()
