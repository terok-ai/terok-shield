# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for HooksInstaller and the containers.conf patcher.

Covers the single-layout install/uninstall lifecycle and the line-based
containers.conf editing that install triggers.  The per-container
[`install_hooks`][terok_shield.hooks.install.install_hooks] path and the
role-file generators are exercised by ``test_hook_mode_class``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from terok_shield.hooks.install import (
    _DESCRIPTOR_FILES,
    _SCRIPT_FILES,
    HooksInstaller,
    _default_target_dir,
    ensure_user_hooks_dir_configured,
)

from ..testfs import PLACEHOLDER_ALT_HOOKS_DIR, PLACEHOLDER_HOOKS_DIR

# ── Install / uninstall lifecycle ────────────────────────


class TestInstallLifecycle:
    """End-to-end install + uninstall against a tmp directory."""

    def test_install_writes_every_hook_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A fresh install lays down every name in ``_SCRIPT_FILES`` + ``_DESCRIPTOR_FILES``."""
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: tmp_path / "containers.conf",
        )
        installer = HooksInstaller(target_dir=tmp_path / "hooks")
        installer.install()
        for name in (*_SCRIPT_FILES, *_DESCRIPTOR_FILES):
            assert (installer.target_dir / name).is_file(), f"missing {name}"

    def test_install_marks_entrypoints_executable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The two role scripts get the executable bit; the ballast does not."""
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: tmp_path / "containers.conf",
        )
        installer = HooksInstaller(target_dir=tmp_path / "hooks")
        installer.install()
        assert (installer.target_dir / "terok-shield-hook").stat().st_mode & 0o100
        assert (installer.target_dir / "terok-shield-bridge-hook").stat().st_mode & 0o100

    def test_install_is_idempotent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A second install overwrites without raising; file contents stay stable."""
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: tmp_path / "containers.conf",
        )
        installer = HooksInstaller(target_dir=tmp_path / "hooks")
        installer.install()
        first = (installer.target_dir / "terok-shield-hook").read_text()
        installer.install()
        assert (installer.target_dir / "terok-shield-hook").read_text() == first

    def test_uninstall_removes_every_hook_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``uninstall`` clears what ``install`` wrote — symmetric cleanup."""
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: tmp_path / "containers.conf",
        )
        installer = HooksInstaller(target_dir=tmp_path / "hooks")
        installer.install()
        installer.uninstall()
        for name in (*_SCRIPT_FILES, *_DESCRIPTOR_FILES):
            assert not (installer.target_dir / name).exists()

    def test_uninstall_tolerates_missing_files(self, tmp_path: Path) -> None:
        """Uninstall against a never-installed target raises nothing — idempotent."""
        HooksInstaller(target_dir=tmp_path / "never-installed").uninstall()

    def test_is_installed_reflects_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The presence probe flips True after install, False after uninstall."""
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: tmp_path / "containers.conf",
        )
        installer = HooksInstaller(target_dir=tmp_path / "hooks")
        assert not installer.is_installed()
        installer.install()
        assert installer.is_installed()
        installer.uninstall()
        assert not installer.is_installed()


# ── containers.conf registration ─────────────────────────


class TestRegisterHooksDir:
    """Editing the user's containers.conf to list our hooks_dir."""

    def test_creates_new_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Creates containers.conf when absent, parent dirs and all."""
        conf_dir = tmp_path / "containers"
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: conf_dir / "containers.conf",
        )
        ensure_user_hooks_dir_configured(Path(PLACEHOLDER_HOOKS_DIR))
        text = (conf_dir / "containers.conf").read_text()
        assert f'hooks_dir = ["{PLACEHOLDER_HOOKS_DIR}"]' in text
        assert text.count("[engine]") == 1

    def test_inserts_into_existing_engine_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Inserts hooks_dir into existing [engine] without duplicating the section."""
        conf = tmp_path / "containers.conf"
        conf.write_text('[engine]\nimage_copy_tmp_dir = "/data/tmp"\n')
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: conf,
        )
        ensure_user_hooks_dir_configured(Path(PLACEHOLDER_HOOKS_DIR))
        text = conf.read_text()
        assert text.count("[engine]") == 1
        assert f'hooks_dir = ["{PLACEHOLDER_HOOKS_DIR}"]' in text
        assert 'image_copy_tmp_dir = "/data/tmp"' in text

    def test_preserves_comments(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Existing comments around [engine] are preserved verbatim."""
        conf = tmp_path / "containers.conf"
        conf.write_text("# preamble\n[engine]\n# inner comment\n")
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: conf,
        )
        ensure_user_hooks_dir_configured(Path(PLACEHOLDER_HOOKS_DIR))
        text = conf.read_text()
        assert "# preamble" in text
        assert "# inner comment" in text

    def test_idempotent_on_same_value(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A second call with the same value is a no-op."""
        conf = tmp_path / "containers.conf"
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: conf,
        )
        ensure_user_hooks_dir_configured(Path(PLACEHOLDER_HOOKS_DIR))
        first = conf.read_text()
        ensure_user_hooks_dir_configured(Path(PLACEHOLDER_HOOKS_DIR))
        assert conf.read_text() == first

    def test_appends_to_existing_other_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When containers.conf lists a different hooks_dir, ours is appended to the list."""
        conf = tmp_path / "containers.conf"
        conf.write_text(f'[engine]\nhooks_dir = ["{PLACEHOLDER_ALT_HOOKS_DIR}"]\n')
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: conf,
        )
        ensure_user_hooks_dir_configured(Path(PLACEHOLDER_HOOKS_DIR))
        text = conf.read_text()
        assert PLACEHOLDER_ALT_HOOKS_DIR in text
        assert PLACEHOLDER_HOOKS_DIR in text

    def test_appends_to_list_with_inline_comment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A hooks_dir line carrying a trailing ``#`` comment still gets ours appended."""
        conf = tmp_path / "containers.conf"
        conf.write_text(f'[engine]\nhooks_dir = ["{PLACEHOLDER_ALT_HOOKS_DIR}"]  # keep me\n')
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: conf,
        )
        ensure_user_hooks_dir_configured(Path(PLACEHOLDER_HOOKS_DIR))
        text = conf.read_text()
        assert PLACEHOLDER_ALT_HOOKS_DIR in text
        assert PLACEHOLDER_HOOKS_DIR in text
        assert "# keep me" in text

    def test_promotes_scalar_hooks_dir_to_list(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A scalar ``hooks_dir = "/path"`` is promoted to a two-element list.

        Exercises the scalar-form regex branch in ``_append_to_hooks_dir``:
        podman accepts ``hooks_dir`` as a bare string, so an operator who
        pinned one that way must still get ours appended — as a list.
        """
        conf = tmp_path / "containers.conf"
        conf.write_text(f'[engine]\nhooks_dir = "{PLACEHOLDER_ALT_HOOKS_DIR}"\n')
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: conf,
        )
        ensure_user_hooks_dir_configured(Path(PLACEHOLDER_HOOKS_DIR))
        text = conf.read_text()
        assert f'hooks_dir = ["{PLACEHOLDER_ALT_HOOKS_DIR}", "{PLACEHOLDER_HOOKS_DIR}"]' in text

    def test_promotes_scalar_hooks_dir_preserving_inline_comment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Scalar promotion keeps a trailing ``#`` comment verbatim."""
        conf = tmp_path / "containers.conf"
        conf.write_text(f'[engine]\nhooks_dir = "{PLACEHOLDER_ALT_HOOKS_DIR}"  # pinned\n')
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: conf,
        )
        ensure_user_hooks_dir_configured(Path(PLACEHOLDER_HOOKS_DIR))
        text = conf.read_text()
        assert f'["{PLACEHOLDER_ALT_HOOKS_DIR}", "{PLACEHOLDER_HOOKS_DIR}"]' in text
        assert "# pinned" in text

    def test_defaults_to_namespace_hooks_dir_when_arg_omitted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Calling with no *hooks_dir* falls back to ``_default_target_dir()``.

        The sibling-installer entry point (terok-sandbox) calls this with
        no argument to register shield's canonical hooks dir; the default
        branch resolves it under ``paths.root`` via ``TEROK_ROOT``.
        """
        conf = tmp_path / "containers.conf"
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: conf,
        )
        monkeypatch.setenv("TEROK_ROOT", str(tmp_path / "root"))
        ensure_user_hooks_dir_configured()
        text = conf.read_text()
        assert f'hooks_dir = ["{_default_target_dir()}"]' in text


# ── Install also patches containers.conf ─────────────────


def test_install_patches_containers_conf(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``HooksInstaller.install()`` adds its target_dir to containers.conf."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
    conf = tmp_path / "containers.conf"
    monkeypatch.setattr(
        "terok_shield.hooks.install._user_containers_conf",
        lambda: conf,
    )
    installer = HooksInstaller(target_dir=tmp_path / "hooks")
    installer.install()
    assert str(installer.target_dir) in conf.read_text()
