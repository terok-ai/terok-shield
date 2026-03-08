# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: audit logging with real filesystem paths."""

import json
from pathlib import Path

import pytest

from terok_shield.audit import list_log_files, log_event, tail_log
from tests.testnet import TEST_IP1, TEST_IP2


@pytest.mark.needs_host_features
class TestAuditLive:
    """Audit logging with real temp directories."""

    def test_log_and_tail(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Write audit events and read them back."""
        monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", str(tmp_path))

        log_event("test-ctr", "setup", detail="integration test")
        log_event("test-ctr", "allowed", dest=TEST_IP1)
        log_event("test-ctr", "denied", dest=TEST_IP2)

        events = list(tail_log("test-ctr", n=10))
        assert len(events) == 3
        assert events[0]["action"] == "setup"
        assert events[1]["dest"] == TEST_IP1
        assert events[2]["action"] == "denied"

    def test_jsonl_format(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Each line must be valid compact JSON."""
        monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", str(tmp_path))

        log_event("fmt-test", "setup")
        log_event("fmt-test", "teardown")

        log_file = tmp_path / "logs" / "fmt-test.jsonl"
        assert log_file.is_file()

        for line in log_file.read_text().splitlines():
            entry = json.loads(line)
            assert "ts" in entry
            assert "container" in entry
            assert "action" in entry
            # Compact format: no spaces after separators
            assert ", " not in line
            assert ": " not in line

    def test_list_log_files(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """list_log_files returns container names with logs."""
        monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", str(tmp_path))

        log_event("alpha", "setup")
        log_event("bravo", "setup")

        names = list_log_files()
        assert "alpha" in names
        assert "bravo" in names

    def test_tail_empty_container(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Tailing a non-existent container returns no events."""
        monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", str(tmp_path))

        events = list(tail_log("nonexistent", n=10))
        assert events == []
