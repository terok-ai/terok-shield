# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the standalone NFLOG reader resource installer.

The reader script lives at
``src/terok_shield/resources/nflog_reader.py`` and is shipped verbatim
to a per-user XDG path so the OCI bridge hook can spawn it via
``/usr/bin/python3`` outside any virtualenv.  ``install_reader_resource``
is the one place that does that copy.

Bridge-hook JSON generation is no longer a separate API surface — the
two role scripts (nft + reader) are written together by
``setup_global_hooks``; integration coverage for that lives in
``test_hook_mode_class.py``.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

from terok_shield.hooks.reader_install import install_reader_resource
from terok_shield.paths import reader_script_path

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

    def test_default_dest_uses_reader_script_path(self, tmp_path: Path) -> None:
        """``install_reader_resource()`` with no args picks the canonical XDG path."""
        env = {"XDG_DATA_HOME": str(tmp_path), "HOME": str(tmp_path)}
        with mock.patch.dict("os.environ", env, clear=False):
            installed = install_reader_resource()
        assert installed == tmp_path / "terok-shield" / "nflog-reader.py"
        assert installed.is_file()


# ── reader_script_path ────────────────────────────────────────────────


class TestReaderScriptPath:
    """``reader_script_path`` resolves the canonical on-disk reader location."""

    def test_respects_xdg_data_home(self, tmp_path: Path) -> None:
        with mock.patch.dict("os.environ", {"XDG_DATA_HOME": str(tmp_path)}, clear=False):
            assert reader_script_path() == tmp_path / "terok-shield" / "nflog-reader.py"

    def test_falls_back_to_home_local_share(self, tmp_path: Path) -> None:
        env = {"HOME": str(tmp_path)}
        with mock.patch.dict("os.environ", env, clear=False):
            import os as _os

            _os.environ.pop("XDG_DATA_HOME", None)
            expected = tmp_path / ".local" / "share" / "terok-shield" / "nflog-reader.py"
            assert reader_script_path() == expected
