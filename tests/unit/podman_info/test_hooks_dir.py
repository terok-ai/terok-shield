# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``terok_shield.podman_info.hooks_dir`` — OCI hook directory discovery."""

from pathlib import Path

import pytest

from terok_shield.podman_info.hooks_dir import (
    HOOK_JSON_FILENAME,
    _parse_hooks_dir_from_conf,
    find_hooks_dirs,
    global_hooks_hint,
    has_global_hooks,
    system_hooks_dir,
)
from tests.testfs import (
    NONEXISTENT_DIR,
    SINGLE_HOOKS_PATH_LITERAL,
    SYSTEM_HOOKS_DIR_LITERAL,
    USER_HOOKS_DIR_LITERAL,
)

# ── find_hooks_dirs tests ────────────────────────────────


class TestFindHooksDirs:
    """Tests for hooks directory detection."""

    def test_user_conf_takes_precedence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """User-level containers.conf hooks_dir overrides system config."""
        user_conf = tmp_path / "user" / "containers" / "containers.conf"
        user_conf.parent.mkdir(parents=True)
        user_conf.write_text(f'[engine]\nhooks_dir = ["{USER_HOOKS_DIR_LITERAL}"]\n')
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "user"))

        # Patch system paths to avoid real filesystem interference
        monkeypatch.setattr(
            "terok_shield.podman_info.hooks_dir._SYSTEM_CONF_PATHS",
            (tmp_path / "nonexistent",),
        )
        monkeypatch.setattr("terok_shield.podman_info.hooks_dir._SYSTEM_HOOKS_DIRS", ())

        dirs = find_hooks_dirs()
        assert dirs == [Path(USER_HOOKS_DIR_LITERAL)]

    def test_falls_back_to_system_dirs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Falls back to existing system dirs when no config."""
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "no-config"))
        monkeypatch.setattr(
            "terok_shield.podman_info.hooks_dir._SYSTEM_CONF_PATHS",
            (tmp_path / "nonexistent",),
        )
        system_dir = tmp_path / "system-hooks"
        system_dir.mkdir()
        monkeypatch.setattr("terok_shield.podman_info.hooks_dir._SYSTEM_HOOKS_DIRS", (system_dir,))

        dirs = find_hooks_dirs()
        assert dirs == [system_dir]

    def test_system_conf_used_when_no_user_conf(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """System containers.conf is used when user config absent."""
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "no-user"))
        sys_conf = tmp_path / "system.conf"
        sys_conf.write_text(f'[engine]\nhooks_dir = ["{SYSTEM_HOOKS_DIR_LITERAL}"]\n')
        monkeypatch.setattr("terok_shield.podman_info.hooks_dir._SYSTEM_CONF_PATHS", (sys_conf,))
        monkeypatch.setattr("terok_shield.podman_info.hooks_dir._SYSTEM_HOOKS_DIRS", ())
        dirs = find_hooks_dirs()
        assert dirs == [Path(SYSTEM_HOOKS_DIR_LITERAL)]


# ── has_global_hooks tests ───────────────────────────────


class TestHasGlobalHooks:
    """Tests for global hooks detection."""

    def test_hook_found(self, tmp_path: Path) -> None:
        """Returns True when hook JSON exists in a hooks dir."""
        hooks_dir = tmp_path / "hooks"
        hooks_dir.mkdir()
        (hooks_dir / HOOK_JSON_FILENAME).write_text("{}")
        assert has_global_hooks([hooks_dir])

    def test_hook_not_found(self, tmp_path: Path) -> None:
        """Returns False when hooks dir is empty."""
        hooks_dir = tmp_path / "hooks"
        hooks_dir.mkdir()
        assert not has_global_hooks([hooks_dir])

    def test_empty_dirs_list(self) -> None:
        """Returns False with no dirs to check."""
        assert not has_global_hooks([])

    def test_default_dirs_auto_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``hooks_dirs=None`` reaches for :func:`find_hooks_dirs` (default branch)."""
        sentinel: list[Path] = []
        monkeypatch.setattr(
            "terok_shield.podman_info.hooks_dir.find_hooks_dirs",
            lambda: sentinel,
        )
        assert not has_global_hooks()


# ── _parse_hooks_dir_from_conf edge cases ────────────────


class TestParseHooksDirFromConf:
    """Tests for containers.conf hooks_dir parsing."""

    def test_hooks_dir_as_string(self, tmp_path: Path) -> None:
        """hooks_dir as a bare string (not list)."""
        conf = tmp_path / "containers.conf"
        conf.write_text(f'[engine]\nhooks_dir = "{SINGLE_HOOKS_PATH_LITERAL}"\n')
        assert _parse_hooks_dir_from_conf(conf) == [SINGLE_HOOKS_PATH_LITERAL]

    def test_hooks_dir_missing(self, tmp_path: Path) -> None:
        """No hooks_dir key returns empty."""
        conf = tmp_path / "containers.conf"
        conf.write_text('[engine]\nfoo = "bar"\n')
        assert _parse_hooks_dir_from_conf(conf) == []

    def test_nonexistent_file(self, tmp_path: Path) -> None:
        """Nonexistent file returns empty."""
        assert _parse_hooks_dir_from_conf(tmp_path / "nope.conf") == []

    def test_invalid_toml(self, tmp_path: Path) -> None:
        """Invalid TOML returns empty."""
        conf = tmp_path / "containers.conf"
        conf.write_text("not valid toml {{{\n")
        assert _parse_hooks_dir_from_conf(conf) == []

    def test_hooks_dir_empty_list(self, tmp_path: Path) -> None:
        """Empty hooks_dir list returns empty."""
        conf = tmp_path / "containers.conf"
        conf.write_text("[engine]\nhooks_dir = []\n")
        assert _parse_hooks_dir_from_conf(conf) == []

    def test_engine_as_scalar_returns_empty(self, tmp_path: Path) -> None:
        """Non-table ``engine = "value"`` is rejected — no AttributeError."""
        conf = tmp_path / "containers.conf"
        conf.write_text('engine = "scalar-not-table"\n')
        assert _parse_hooks_dir_from_conf(conf) == []

    def test_hooks_dir_wrong_type_returns_empty(self, tmp_path: Path) -> None:
        """``hooks_dir`` set to a non-list/non-string falls through to ``return []``."""
        conf = tmp_path / "containers.conf"
        conf.write_text("[engine]\nhooks_dir = 42\n")
        assert _parse_hooks_dir_from_conf(conf) == []


# ── system_hooks_dir tests ───────────────────────────────


class TestSystemHooksDir:
    """Tests for system hooks directory detection."""

    def test_returns_existing_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returns an existing system dir when available."""
        d = tmp_path / "hooks.d"
        d.mkdir()
        monkeypatch.setattr("terok_shield.podman_info.hooks_dir._SYSTEM_HOOKS_DIRS", (d,))
        assert system_hooks_dir() == d

    def test_fallback_when_none_exist(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Falls back to last entry when no system dir exists."""
        monkeypatch.setattr(
            "terok_shield.podman_info.hooks_dir._SYSTEM_HOOKS_DIRS",
            (NONEXISTENT_DIR / "a", NONEXISTENT_DIR / "b"),
        )
        assert system_hooks_dir() == NONEXISTENT_DIR / "b"


# ── global_hooks_hint tests ──────────────────────────────


class TestGlobalHooksHint:
    """Tests for the setup hint message."""

    def test_contains_setup_command(self) -> None:
        """Hint mentions terok-shield setup."""
        assert "terok-shield setup" in global_hooks_hint()

    def test_contains_reference(self) -> None:
        """Hint includes the podman issue reference."""
        assert "17935" in global_hooks_hint()
