# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the bridge-hook pair and the NFLOG reader installer."""

from __future__ import annotations

import json
from pathlib import Path

from terok_shield.hooks.install import (
    install_bridge_hooks,
    install_hooks,
    uninstall_bridge_hooks,
)
from terok_shield.hooks.reader_install import install_reader_resource

from ..testfs import BIN_DIR_NAME, HOOK_ENTRYPOINT_NAME, HOOKS_DIR_NAME

# ── Bridge-hook JSON pair ─────────────────────────────────────────────


class TestInstallBridgeHooks:
    """``install_bridge_hooks`` adds a second hook pair alongside the nft one."""

    def test_both_stages_get_json_files(self, tmp_path: Path) -> None:
        hook_entrypoint = tmp_path / BIN_DIR_NAME / HOOK_ENTRYPOINT_NAME
        hooks_dir = tmp_path / HOOKS_DIR_NAME
        install_hooks(hook_entrypoint=hook_entrypoint, hooks_dir=hooks_dir)

        install_bridge_hooks(hook_entrypoint=hook_entrypoint, hooks_dir=hooks_dir)

        for stage in ("createRuntime", "poststop"):
            assert (hooks_dir / f"terok-shield-bridge-{stage}.json").exists()

    def test_bridge_json_args_carry_the_dispatch_flag(self, tmp_path: Path) -> None:
        """Bridge hooks pass ``--bridge`` between the cosmetic argv[0] and stage.

        The kernel's shebang loader discards the exec-supplied argv[0] and
        substitutes the script path, so dispatch has to ride on a real
        positional argument.
        """
        hook_entrypoint = tmp_path / BIN_DIR_NAME / HOOK_ENTRYPOINT_NAME
        hooks_dir = tmp_path / HOOKS_DIR_NAME
        install_hooks(hook_entrypoint=hook_entrypoint, hooks_dir=hooks_dir)

        install_bridge_hooks(hook_entrypoint=hook_entrypoint, hooks_dir=hooks_dir)

        json_file = hooks_dir / "terok-shield-bridge-createRuntime.json"
        descriptor = json.loads(json_file.read_text())
        assert descriptor["hook"]["args"] == [
            "terok-shield-bridge-hook",
            "--bridge",
            "createRuntime",
        ]
        assert descriptor["hook"]["path"] == str(hook_entrypoint)

    def test_nft_json_args_have_no_bridge_flag(self, tmp_path: Path) -> None:
        """The nft hook JSON must NOT carry ``--bridge`` or it would misroute."""
        hook_entrypoint = tmp_path / BIN_DIR_NAME / HOOK_ENTRYPOINT_NAME
        hooks_dir = tmp_path / HOOKS_DIR_NAME
        install_hooks(hook_entrypoint=hook_entrypoint, hooks_dir=hooks_dir)

        descriptor = json.loads((hooks_dir / "terok-shield-createRuntime.json").read_text())
        assert "--bridge" not in descriptor["hook"]["args"]
        assert descriptor["hook"]["args"] == ["terok-shield-hook", "createRuntime"]

    def test_nft_pair_is_untouched(self, tmp_path: Path) -> None:
        """Bridge install doesn't clobber the nft hook JSON files."""
        hook_entrypoint = tmp_path / BIN_DIR_NAME / HOOK_ENTRYPOINT_NAME
        hooks_dir = tmp_path / HOOKS_DIR_NAME
        install_hooks(hook_entrypoint=hook_entrypoint, hooks_dir=hooks_dir)
        nft_before = (hooks_dir / "terok-shield-createRuntime.json").read_text()

        install_bridge_hooks(hook_entrypoint=hook_entrypoint, hooks_dir=hooks_dir)

        nft_after = (hooks_dir / "terok-shield-createRuntime.json").read_text()
        assert nft_before == nft_after

    def test_install_is_idempotent(self, tmp_path: Path) -> None:
        """Running install twice leaves exactly the same file set."""
        hook_entrypoint = tmp_path / BIN_DIR_NAME / HOOK_ENTRYPOINT_NAME
        hooks_dir = tmp_path / HOOKS_DIR_NAME
        install_hooks(hook_entrypoint=hook_entrypoint, hooks_dir=hooks_dir)

        install_bridge_hooks(hook_entrypoint=hook_entrypoint, hooks_dir=hooks_dir)
        first = sorted(p.name for p in hooks_dir.iterdir())
        install_bridge_hooks(hook_entrypoint=hook_entrypoint, hooks_dir=hooks_dir)
        second = sorted(p.name for p in hooks_dir.iterdir())
        assert first == second


class TestUninstallBridgeHooks:
    """``uninstall_bridge_hooks`` reverts to the nft-only hook set."""

    def test_removes_only_bridge_pair(self, tmp_path: Path) -> None:
        hook_entrypoint = tmp_path / BIN_DIR_NAME / HOOK_ENTRYPOINT_NAME
        hooks_dir = tmp_path / HOOKS_DIR_NAME
        install_hooks(hook_entrypoint=hook_entrypoint, hooks_dir=hooks_dir)
        install_bridge_hooks(hook_entrypoint=hook_entrypoint, hooks_dir=hooks_dir)

        uninstall_bridge_hooks(hooks_dir=hooks_dir)

        remaining = sorted(p.name for p in hooks_dir.iterdir())
        assert remaining == ["terok-shield-createRuntime.json", "terok-shield-poststop.json"]

    def test_uninstall_tolerates_missing_files(self, tmp_path: Path) -> None:
        """Calling uninstall on a directory without bridge hooks is a no-op."""
        hooks_dir = tmp_path / HOOKS_DIR_NAME
        hooks_dir.mkdir()
        uninstall_bridge_hooks(hooks_dir=hooks_dir)  # must not raise


# ── Reader resource installer ─────────────────────────────────────────


class TestInstallReaderResource:
    """``install_reader_resource`` copies the script verbatim to the given path."""

    def test_writes_executable_script_with_shebang(self, tmp_path: Path) -> None:
        dest = tmp_path / "share" / "terok-shield" / "nflog-reader.py"
        install_reader_resource(dest)

        assert dest.exists()
        assert dest.stat().st_mode & 0o100
        first_line = dest.read_text().splitlines()[0]
        assert first_line.startswith("#!")
        assert "python3" in first_line

    def test_overwrites_existing_file(self, tmp_path: Path) -> None:
        dest = tmp_path / "nflog-reader.py"
        dest.write_text("stale")
        install_reader_resource(dest)
        assert dest.read_text().startswith("#!")

    def test_has_no_terok_shield_imports(self, tmp_path: Path) -> None:
        """The installed script must stay stdlib-only — /usr/bin/python3 will run it."""
        dest = tmp_path / "nflog-reader.py"
        install_reader_resource(dest)
        content = dest.read_text()
        assert "import terok_shield" not in content
        assert "from terok_shield" not in content
