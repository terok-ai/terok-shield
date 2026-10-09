# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the optional logrotate integration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from terok_shield.logrotate import (
    CONFIG_FILENAME,
    audit_log_pattern,
    find_logrotate,
    generate_config,
    install_config,
    setup_logrotate,
)


class TestFindLogrotate:
    """logrotate binary detection."""

    def test_found(self) -> None:
        """Returns the binary path when logrotate is on PATH."""
        with patch("shutil.which", return_value="/usr/sbin/logrotate"):
            assert find_logrotate() == "/usr/sbin/logrotate"

    def test_not_found(self) -> None:
        """Returns None when logrotate is not installed."""
        with patch("shutil.which", return_value=None):
            assert find_logrotate() is None


class TestAuditLogPattern:
    """The wildcard path covers every per-container audit log."""

    def test_pattern_ends_with_audit_jsonl(self) -> None:
        pattern = audit_log_pattern()
        assert pattern.endswith("/tasks/*/*/shield/audit.jsonl")

    def test_pattern_under_sandbox_live_root(self) -> None:
        from terok_sandbox.paths import sandbox_live_root

        pattern = audit_log_pattern()
        root = str(sandbox_live_root())
        assert pattern.startswith(root)


class TestGenerateConfig:
    """Config generation."""

    def test_includes_pattern(self) -> None:
        config = generate_config("/custom/path/audit.jsonl")
        assert "/custom/path/audit.jsonl {" in config

    def test_uses_copytruncate(self) -> None:
        """copytruncate keeps the NFLOG reader's file handle valid."""
        config = generate_config()
        assert "copytruncate" in config

    def test_includes_rotation_policy(self) -> None:
        config = generate_config()
        assert "daily" in config
        assert "rotate 7" in config
        assert "compress" in config
        assert "missingok" in config
        assert "notifempty" in config

    def test_default_pattern(self) -> None:
        config = generate_config()
        assert audit_log_pattern() in config


class TestInstallConfig:
    """Config installation."""

    def test_install_to_tmp_dir(self, tmp_path: Path) -> None:
        config = generate_config("/test/audit.jsonl")
        target = install_config(config, target_dir=tmp_path)
        assert target is not None
        assert target.name == CONFIG_FILENAME
        assert target.read_text() == config
        # Mode should be world-readable (logrotate configs are 0644)
        assert target.stat().st_mode & 0o777 == 0o644

    def test_install_failure_returns_none(self, tmp_path: Path) -> None:
        """Returns None when the target dir is not writable."""
        config = generate_config()
        # Use a path that can't be created (under a file)
        bad_dir = tmp_path / "file" / "subdir"
        (tmp_path / "file").write_text("not a dir")
        target = install_config(config, target_dir=bad_dir)
        assert target is None


class TestSetupLogrotate:
    """End-to-end setup_logrotate behavior."""

    def test_no_logrotate_prints_config(self, capsys) -> None:
        """When logrotate is missing, prints the config for manual install."""
        with patch("terok_shield.logrotate.find_logrotate", return_value=None):
            result = setup_logrotate(verbose=True)
        assert result is None
        out = capsys.readouterr().out
        assert "logrotate not found" in out
        assert "audit.jsonl" in out  # config is printed

    def test_logrotate_installs_config(self, tmp_path: Path, capsys) -> None:
        """When logrotate is present and /etc is writable, installs config."""
        with (
            patch("terok_shield.logrotate.find_logrotate", return_value="/usr/sbin/logrotate"),
            patch("terok_shield.logrotate.SYSTEM_LOGROTATE_DIR", tmp_path),
        ):
            result = setup_logrotate(verbose=True)
        assert result is not None
        assert result.name == CONFIG_FILENAME
        out = capsys.readouterr().out
        assert "installed" in out

    def test_install_failure_prints_config(self, capsys) -> None:
        """When install fails (permissions), prints config for manual install."""
        with (
            patch("terok_shield.logrotate.find_logrotate", return_value="/usr/sbin/logrotate"),
            patch("terok_shield.logrotate.install_config", return_value=None),
        ):
            result = setup_logrotate(verbose=True)
        assert result is None
        out = capsys.readouterr().out
        assert "Cannot write" in out
        assert "audit.jsonl" in out  # config is printed

    def test_quiet_mode(self, capsys) -> None:
        """verbose=False suppresses output."""
        with patch("terok_shield.logrotate.find_logrotate", return_value=None):
            result = setup_logrotate(verbose=False)
        assert result is None
        assert capsys.readouterr().out == ""
