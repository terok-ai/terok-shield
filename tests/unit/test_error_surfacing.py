# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for warning/logging on silent failures (PR #154).

Verifies that previously-silent error paths now surface diagnostics
to operators via stderr warnings or Python logger warnings.
"""

from __future__ import annotations

import logging
from pathlib import Path
from unittest import mock

import pytest

from terok_shield.audit import AuditLogger
from terok_shield.cli import _load_config_file
from terok_shield.config import ShieldFileConfig
from terok_shield.dnsmasq import generate_config, read_domains
from terok_shield.nft_constants import PASTA_DNS
from terok_shield.run import ExecError

from ..testnet import TEST_DOMAIN, TEST_DOMAIN2

# ── cli._load_config_file warnings ─────────────────────


class TestLoadConfigFileWarnings:
    """Verify _load_config_file() prints warnings to stderr on bad input."""

    def test_corrupt_yaml_warns(
        self,
        monkeypatch: pytest.MonkeyPatch,
        config_root: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Corrupt YAML produces a warning on stderr and returns {}."""
        (config_root / "config.yml").write_text(": [invalid yaml\n  bad: {unclosed")
        monkeypatch.setenv("TEROK_SHIELD_CONFIG_DIR", str(config_root))

        result = _load_config_file()

        assert result == ShieldFileConfig()
        captured = capsys.readouterr()
        assert "Warning [shield]:" in captured.err
        assert "failed to parse" in captured.err

    def test_non_dict_yaml_warns(
        self,
        monkeypatch: pytest.MonkeyPatch,
        config_root: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Non-dict YAML (e.g. a bare string) produces a warning and returns {}."""
        (config_root / "config.yml").write_text('"just a string"\n')
        monkeypatch.setenv("TEROK_SHIELD_CONFIG_DIR", str(config_root))

        result = _load_config_file()

        assert result == ShieldFileConfig()
        captured = capsys.readouterr()
        assert "Warning [shield]:" in captured.err
        assert "expected mapping" in captured.err
        assert "str" in captured.err

    def test_list_yaml_warns(
        self,
        monkeypatch: pytest.MonkeyPatch,
        config_root: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A YAML list warns about non-dict type and returns {}."""
        (config_root / "config.yml").write_text("- item1\n- item2\n")
        monkeypatch.setenv("TEROK_SHIELD_CONFIG_DIR", str(config_root))

        result = _load_config_file()

        assert result == ShieldFileConfig()
        captured = capsys.readouterr()
        assert "Warning [shield]:" in captured.err
        assert "expected mapping" in captured.err
        assert "list" in captured.err

    def test_missing_file_no_warning(
        self,
        monkeypatch: pytest.MonkeyPatch,
        config_root: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A missing config file returns {} without any warning."""
        monkeypatch.setenv("TEROK_SHIELD_CONFIG_DIR", str(config_root))
        # config.yml does not exist

        result = _load_config_file()

        assert result == ShieldFileConfig()
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_unreadable_file_warns(
        self,
        monkeypatch: pytest.MonkeyPatch,
        config_root: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """An unreadable config file produces an OSError warning and returns {}."""
        cfg = config_root / "config.yml"
        cfg.write_text("mode: hook\n")
        cfg.chmod(0o000)
        monkeypatch.setenv("TEROK_SHIELD_CONFIG_DIR", str(config_root))

        result = _load_config_file()

        cfg.chmod(0o644)  # restore for cleanup
        assert result == ShieldFileConfig()
        captured = capsys.readouterr()
        assert "Warning [shield]:" in captured.err
        assert "failed to read" in captured.err

    def test_valid_config_no_warning(
        self,
        monkeypatch: pytest.MonkeyPatch,
        config_root: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A valid YAML dict returns the content without any warning."""
        (config_root / "config.yml").write_text("mode: hook\n")
        monkeypatch.setenv("TEROK_SHIELD_CONFIG_DIR", str(config_root))

        result = _load_config_file()

        assert result == ShieldFileConfig(mode="hook")
        captured = capsys.readouterr()
        assert captured.err == ""


# ── dnsmasq.read_domains logging ────────────────────────


class TestReadDomainsWarnings:
    """Verify read_domains() logs warnings for invalid entries."""

    def test_invalid_entry_logs_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Invalid domain entries are skipped with a logger warning."""
        domains_path = tmp_path / "profile.domains"
        domains_path.write_text(f"{TEST_DOMAIN}\n; injection\n{TEST_DOMAIN2}\n")

        with caplog.at_level(logging.WARNING, logger="terok_shield.dnsmasq"):
            result = read_domains(domains_path)

        assert result == [TEST_DOMAIN, TEST_DOMAIN2]
        assert len(caplog.records) == 1
        assert "skipping invalid entry" in caplog.records[0].message
        # Must NOT log the raw entry value (security: avoid log injection)
        assert "; injection" not in caplog.records[0].message

    def test_multiple_invalid_entries_log_per_entry(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Each invalid entry generates its own warning."""
        domains_path = tmp_path / "profile.domains"
        domains_path.write_text(f"{TEST_DOMAIN}\n; bad1\n; bad2\n{TEST_DOMAIN2}\n")

        with caplog.at_level(logging.WARNING, logger="terok_shield.dnsmasq"):
            result = read_domains(domains_path)

        assert result == [TEST_DOMAIN, TEST_DOMAIN2]
        assert len(caplog.records) == 2

    def test_all_valid_no_warning(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """All-valid entries produce no warnings."""
        domains_path = tmp_path / "profile.domains"
        domains_path.write_text(f"{TEST_DOMAIN}\n{TEST_DOMAIN2}\n")

        with caplog.at_level(logging.WARNING, logger="terok_shield.dnsmasq"):
            result = read_domains(domains_path)

        assert result == [TEST_DOMAIN, TEST_DOMAIN2]
        assert len(caplog.records) == 0

    def test_warning_includes_file_path(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The warning message includes the file path for debugging."""
        domains_path = tmp_path / "profile.domains"
        domains_path.write_text("not-a-valid-entry\n")

        with caplog.at_level(logging.WARNING, logger="terok_shield.dnsmasq"):
            read_domains(domains_path)

        assert str(domains_path) in caplog.records[0].message


# ── dnsmasq.generate_config logging ─────────────────────


class TestGenerateConfigWarnings:
    """Verify generate_config() logs warnings for invalid domains."""

    def test_invalid_domain_logs_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Invalid domains are skipped with a logger warning."""
        pid_path = tmp_path / "dnsmasq.pid"

        with caplog.at_level(logging.WARNING, logger="terok_shield.dnsmasq"):
            config = generate_config(PASTA_DNS, [TEST_DOMAIN, "; rm -rf /", TEST_DOMAIN2], pid_path)

        # Valid domains are present, invalid one is not
        assert f"nftset=/{TEST_DOMAIN}/" in config
        assert f"nftset=/{TEST_DOMAIN2}/" in config
        assert "rm -rf" not in config

        # Warning was logged
        assert len(caplog.records) == 1
        assert "skipping invalid domain" in caplog.records[0].message

    def test_all_valid_domains_no_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """All-valid domain list produces no warnings."""
        pid_path = tmp_path / "dnsmasq.pid"

        with caplog.at_level(logging.WARNING, logger="terok_shield.dnsmasq"):
            config = generate_config(PASTA_DNS, [TEST_DOMAIN, TEST_DOMAIN2], pid_path)

        assert f"nftset=/{TEST_DOMAIN}/" in config
        assert len(caplog.records) == 0


# ── audit.AuditLogger.log_event logging ─────────────────


class TestAuditLogEventWarnings:
    """Verify AuditLogger.log_event() logs via Python logger on write failure."""

    def test_write_failure_logs_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """OSError during audit write is surfaced as a logger warning."""
        audit_path = tmp_path / "readonly" / "audit.jsonl"
        # Create parent as a *file* so mkdir fails (simulating a read-only path)
        (tmp_path / "readonly").write_text("")

        audit = AuditLogger(audit_path=audit_path, enabled=True)

        with caplog.at_level(logging.WARNING, logger="terok_shield.audit"):
            audit.log_event("test-ctr", "setup", detail="test")

        assert len(caplog.records) == 1
        assert "Failed to write audit log" in caplog.records[0].message
        assert str(audit_path) in caplog.records[0].message

    def test_write_failure_does_not_raise(self, tmp_path: Path) -> None:
        """Write failures are swallowed (do not crash the protected workload)."""
        audit_path = tmp_path / "readonly" / "audit.jsonl"
        (tmp_path / "readonly").write_text("")

        audit = AuditLogger(audit_path=audit_path, enabled=True)
        # Must not raise
        audit.log_event("test-ctr", "setup", detail="test")

    def test_disabled_logger_no_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Disabled loggers skip the write entirely (no warning possible)."""
        audit_path = tmp_path / "readonly" / "audit.jsonl"
        (tmp_path / "readonly").write_text("")

        audit = AuditLogger(audit_path=audit_path, enabled=False)

        with caplog.at_level(logging.WARNING, logger="terok_shield.audit"):
            audit.log_event("test-ctr", "setup", detail="test")

        assert len(caplog.records) == 0


# ── mode_hook.HookMode.deny_ip logging ──────────────────


class TestDenyIpWarnings:
    """Verify deny_ip() suppresses expected nft errors and warns on unexpected ones."""

    @pytest.fixture
    def hook_mode(self, tmp_path: Path) -> tuple[mock.MagicMock, object]:
        """Create a minimal HookMode with a mock runner for deny_ip tests."""
        from terok_shield import state
        from terok_shield.config import ShieldConfig, ShieldMode
        from terok_shield.mode_hook import HookMode
        from terok_shield.nft import RulesetBuilder

        state.ensure_state_dirs(tmp_path)
        config = ShieldConfig(state_dir=tmp_path, mode=ShieldMode.HOOK)
        runner = mock.MagicMock()
        audit = mock.MagicMock()
        dns = mock.MagicMock()
        profiles = mock.MagicMock()
        ruleset = RulesetBuilder(dns=PASTA_DNS)
        mode = HookMode(
            config=config,
            runner=runner,
            audit=audit,
            dns=dns,
            profiles=profiles,
            ruleset=ruleset,
        )
        return runner, mode

    def test_suppresses_not_in_set_without_warning(
        self,
        hook_mode: tuple[mock.MagicMock, object],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """'not in set' ExecError is silently suppressed (no warning)."""
        runner, mode = hook_mode
        runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "Error: element is not in set")

        with caplog.at_level(logging.WARNING, logger="terok_shield.mode_hook"):
            mode.deny_ip("test-ctr", "192.0.2.1")  # type: ignore[union-attr]

        assert len(caplog.records) == 0

    def test_suppresses_element_does_not_exist_without_warning(
        self,
        hook_mode: tuple[mock.MagicMock, object],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """'element does not exist' ExecError is silently suppressed."""
        runner, mode = hook_mode
        runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "Error: element does not exist")

        with caplog.at_level(logging.WARNING, logger="terok_shield.mode_hook"):
            mode.deny_ip("test-ctr", "192.0.2.1")  # type: ignore[union-attr]

        assert len(caplog.records) == 0

    def test_suppresses_no_such_file_without_warning(
        self,
        hook_mode: tuple[mock.MagicMock, object],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """'no such file' ExecError is silently suppressed."""
        runner, mode = hook_mode
        runner.nft_via_nsenter.side_effect = ExecError(
            ["nft"], 1, "Error: no such file or directory"
        )

        with caplog.at_level(logging.WARNING, logger="terok_shield.mode_hook"):
            mode.deny_ip("test-ctr", "192.0.2.1")  # type: ignore[union-attr]

        assert len(caplog.records) == 0

    def test_unexpected_exec_error_logs_warning(
        self,
        hook_mode: tuple[mock.MagicMock, object],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Unexpected ExecError messages generate a warning."""
        runner, mode = hook_mode
        runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "Error: permission denied")

        with caplog.at_level(logging.WARNING, logger="terok_shield.mode_hook"):
            mode.deny_ip("test-ctr", "192.0.2.1")  # type: ignore[union-attr]

        assert len(caplog.records) == 1
        assert "nft delete element failed" in caplog.records[0].message
        assert "192.0.2.1" in caplog.records[0].message
