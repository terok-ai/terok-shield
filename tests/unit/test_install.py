# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for HooksInstaller and the containers.conf patcher.

Covers the system/user factory pair, the symmetric install/uninstall
lifecycle, and the line-based containers.conf editing that user-scope
installs trigger.  The per-container [`install_hooks`][terok_shield.hooks.install.install_hooks]
path and the role-file generators are exercised by ``test_hook_mode_class``.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from terok_shield.hooks.install import (
    _INSTALLED_FILES,
    HooksInstaller,
    _register_hooks_dir_in_containers_conf,
)

from ..testfs import PLACEHOLDER_ALT_HOOKS_DIR, PLACEHOLDER_HOOKS_DIR

# ── Factory constructors ─────────────────────────────────


class TestFactories:
    """The ``system`` / ``user`` classmethods bind the right scope defaults."""

    def test_system_uses_sudo(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``system()`` escalates writes and skips containers.conf registration."""
        monkeypatch.setattr(
            "terok_shield.hooks.install.system_hooks_dir",
            lambda: Path("/fake/system"),
        )
        installer = HooksInstaller.system()
        assert installer.target_dir == Path("/fake/system")
        assert installer.use_sudo is True
        assert installer.register_in_containers_conf is False

    def test_user_does_not_use_sudo(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``user()`` writes directly and registers in containers.conf."""
        monkeypatch.setattr(
            "terok_shield.hooks.install.USER_HOOKS_DIR",
            Path("/fake/user"),
        )
        installer = HooksInstaller.user()
        assert installer.target_dir == Path("/fake/user")
        assert installer.use_sudo is False
        assert installer.register_in_containers_conf is True


# ── Install / uninstall lifecycle ────────────────────────


class TestInstallLifecycle:
    """End-to-end install + uninstall against a tmp directory."""

    def test_install_writes_every_hook_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A fresh non-sudo install lays down every name in ``_INSTALLED_FILES``."""
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
        installer = HooksInstaller(target_dir=tmp_path / "hooks.d")
        installer.install()
        for name in _INSTALLED_FILES:
            assert (installer.target_dir / name).is_file(), f"missing {name}"

    def test_install_marks_entrypoints_executable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The two role scripts get the executable bit; the ballast does not."""
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
        installer = HooksInstaller(target_dir=tmp_path / "hooks.d")
        installer.install()
        assert (installer.target_dir / "terok-shield-hook").stat().st_mode & 0o100
        assert (installer.target_dir / "terok-shield-bridge-hook").stat().st_mode & 0o100

    def test_install_is_idempotent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A second install overwrites without raising; file contents stay stable."""
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
        installer = HooksInstaller(target_dir=tmp_path / "hooks.d")
        installer.install()
        first = (installer.target_dir / "terok-shield-hook").read_text()
        installer.install()
        assert (installer.target_dir / "terok-shield-hook").read_text() == first

    def test_uninstall_removes_every_hook_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``uninstall`` clears what ``install`` wrote — symmetric cleanup."""
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
        installer = HooksInstaller(target_dir=tmp_path / "hooks.d")
        installer.install()
        installer.uninstall()
        for name in _INSTALLED_FILES:
            assert not (installer.target_dir / name).exists()

    def test_uninstall_tolerates_missing_files(self, tmp_path: Path) -> None:
        """Uninstall against a never-installed target raises nothing — idempotent."""
        HooksInstaller(target_dir=tmp_path / "never-installed").uninstall()

    def test_is_installed_reflects_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The presence probe flips True after install, False after uninstall."""
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
        installer = HooksInstaller(target_dir=tmp_path / "hooks.d")
        assert not installer.is_installed()
        installer.install()
        assert installer.is_installed()
        installer.uninstall()
        assert not installer.is_installed()


# ── Sudo escalation path ─────────────────────────────────


class TestSudoEscalation:
    """``use_sudo=True`` routes writes and removals through ``sudo``."""

    def test_install_runs_sudo_subprocess_chain(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """sudo mkdir + sudo cp + sudo chmod fire in that order."""
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
        target = tmp_path / "system-hooks"
        installer = HooksInstaller(target_dir=target, use_sudo=True)
        with mock.patch("terok_shield.hooks.install.subprocess.run") as run:
            installer.install()
        argv0s = [call.args[0][0] for call in run.call_args_list]
        assert argv0s == ["sudo", "sudo", "sudo"]
        verbs = [call.args[0][1] for call in run.call_args_list]
        assert verbs == ["mkdir", "cp", "chmod"]

    def test_uninstall_runs_sudo_rm(self, tmp_path: Path) -> None:
        """Sudo uninstall fires a single ``sudo rm -f`` listing every hook file."""
        target = tmp_path / "system-hooks"
        installer = HooksInstaller(target_dir=target, use_sudo=True)
        with mock.patch("terok_shield.hooks.install.subprocess.run") as run:
            installer.uninstall()
        [(call,)] = [(c,) for c in run.call_args_list]
        argv = call.args[0]
        assert argv[:3] == ["sudo", "rm", "-f"]
        assert {Path(p).name for p in argv[3:]} == set(_INSTALLED_FILES)

    def test_remove_via_sudo_empty_list_short_circuits(self) -> None:
        """Empty paths list returns without shelling out — defensive guard."""
        from terok_shield.hooks.install import _remove_via_sudo

        with mock.patch("terok_shield.hooks.install.subprocess.run") as run:
            _remove_via_sudo([])
        run.assert_not_called()


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
        _register_hooks_dir_in_containers_conf(Path(PLACEHOLDER_HOOKS_DIR))
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
        _register_hooks_dir_in_containers_conf(Path(PLACEHOLDER_HOOKS_DIR))
        text = conf.read_text()
        assert text.count("[engine]") == 1
        assert f'hooks_dir = ["{PLACEHOLDER_HOOKS_DIR}"]' in text
        assert 'image_copy_tmp_dir = "/data/tmp"' in text

    def test_preserves_comments(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Comments in the file are preserved across the insert."""
        conf = tmp_path / "containers.conf"
        conf.write_text('# My config\n[engine]\n# temp dir\nimage_copy_tmp_dir = "/data"\n')
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: conf,
        )
        _register_hooks_dir_in_containers_conf(Path(PLACEHOLDER_HOOKS_DIR))
        text = conf.read_text()
        assert "# My config" in text
        assert "# temp dir" in text

    def test_ignores_engine_in_comment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A literal ``[engine]`` inside a comment doesn't trigger the insert."""
        conf = tmp_path / "containers.conf"
        conf.write_text('# see [engine] docs\n[engine]\nfoo = "bar"\n')
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: conf,
        )
        _register_hooks_dir_in_containers_conf(Path(PLACEHOLDER_HOOKS_DIR))
        text = conf.read_text()
        assert text.count("[engine]") == 2  # one in comment, one real
        assert text.count("hooks_dir") == 1

    def test_skips_if_already_configured(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No-op when hooks_dir already points to the right path."""
        conf = tmp_path / "containers.conf"
        conf.write_text(f'[engine]\nhooks_dir = ["{PLACEHOLDER_HOOKS_DIR}"]\n')
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: conf,
        )
        _register_hooks_dir_in_containers_conf(Path(PLACEHOLDER_HOOKS_DIR))
        assert conf.read_text().count("hooks_dir") == 1

    def test_appends_engine_when_no_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Appends [engine] when the file has other sections but no [engine]."""
        conf = tmp_path / "containers.conf"
        conf.write_text("[containers]\nlabel = false\n")
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: conf,
        )
        _register_hooks_dir_in_containers_conf(Path(PLACEHOLDER_HOOKS_DIR))
        text = conf.read_text()
        assert "[containers]" in text
        assert "[engine]" in text
        assert f'hooks_dir = ["{PLACEHOLDER_HOOKS_DIR}"]' in text

    def test_warns_when_different_hooks_dir_configured(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Warns (does not modify) when hooks_dir is already set differently."""
        conf = tmp_path / "containers.conf"
        conf.write_text(f'[engine]\nhooks_dir = ["{PLACEHOLDER_ALT_HOOKS_DIR}"]\n')
        monkeypatch.setattr(
            "terok_shield.hooks.install._user_containers_conf",
            lambda: conf,
        )
        _register_hooks_dir_in_containers_conf(Path(PLACEHOLDER_HOOKS_DIR))
        assert "Warning" in capsys.readouterr().out
        assert conf.read_text().count("hooks_dir") == 1  # unchanged


# ── User-scope install registers in containers.conf ──────


def test_user_install_registers_in_containers_conf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``register_in_containers_conf=True`` patches containers.conf as part of install."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
    conf = tmp_path / "containers.conf"
    monkeypatch.setattr(
        "terok_shield.hooks.install._user_containers_conf",
        lambda: conf,
    )
    installer = HooksInstaller(target_dir=tmp_path / "hooks.d", register_in_containers_conf=True)
    installer.install()
    assert str(installer.target_dir) in conf.read_text()


def test_non_user_install_skips_containers_conf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``register_in_containers_conf=False`` leaves containers.conf untouched."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
    conf = tmp_path / "containers.conf"
    monkeypatch.setattr(
        "terok_shield.hooks.install._user_containers_conf",
        lambda: conf,
    )
    HooksInstaller(target_dir=tmp_path / "hooks.d").install()
    assert not conf.exists()
