# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: audit logging (filesystem)."""

import json
from pathlib import Path

import pytest

from terok_shield import state
from terok_shield.audit import AuditLogger
from tests.testnet import TEST_IP1, TEST_IP2

# -- Filesystem audit (no container needed) -------------------


@pytest.mark.needs_host_features
class TestAuditLive:
    """Audit logging with real temp directories."""

    def test_log_and_tail(self, tmp_path: Path) -> None:
        """Write audit events and read them back."""
        audit = AuditLogger(audit_path=state.audit_path(tmp_path))

        audit.log_event("test-ctr", "setup", detail="integration test")
        audit.log_event("test-ctr", "allowed", dest=TEST_IP1)
        audit.log_event("test-ctr", "denied", dest=TEST_IP2)

        events = list(audit.tail_log(n=10))
        assert len(events) == 3
        assert events[0]["action"] == "setup"
        assert events[1]["dest"] == TEST_IP1
        assert events[2]["action"] == "denied"

    def test_jsonl_format(self, tmp_path: Path) -> None:
        """Each line must be valid compact JSON."""
        audit_path = state.audit_path(tmp_path)
        audit = AuditLogger(audit_path=audit_path)

        audit.log_event("fmt-test", "setup")
        audit.log_event("fmt-test", "teardown")

        assert audit_path.is_file()

        for line in audit_path.read_text().splitlines():
            entry = json.loads(line)
            assert "ts" in entry
            assert "container" in entry
            assert "action" in entry
            # Compact format: no spaces after separators
            assert ", " not in line
            assert ": " not in line

    def test_tail_empty_returns_no_events(self, tmp_path: Path) -> None:
        """Tailing when no log file exists returns no events."""
        audit = AuditLogger(audit_path=state.audit_path(tmp_path))

        events = list(audit.tail_log(n=10))
        assert events == []
