# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the AuditLogger class."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from terok_shield.audit import AuditLogger

from ..testfs import NONEXISTENT_DIR
from ..testnet import TEST_IP1


class TestAuditLoggerInit(unittest.TestCase):
    """Test AuditLogger construction."""

    def test_direct_init(self) -> None:
        """Construct with explicit audit_path and enabled flag."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            logger = AuditLogger(audit_path=path, enabled=False)
            self.assertFalse(logger.enabled)

    def test_default_enabled(self) -> None:
        """Default enabled is True."""
        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditLogger(audit_path=Path(tmp) / "audit.jsonl")
            self.assertTrue(logger.enabled)


class TestAuditLoggerEnabledToggle(unittest.TestCase):
    """Test enabled property and setter."""

    def test_toggle_enabled(self) -> None:
        """Can toggle enabled on and off."""
        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditLogger(audit_path=Path(tmp) / "audit.jsonl", enabled=True)
            self.assertTrue(logger.enabled)
            logger.enabled = False
            self.assertFalse(logger.enabled)
            logger.enabled = True
            self.assertTrue(logger.enabled)


class TestAuditLoggerLogEvent(unittest.TestCase):
    """Test AuditLogger.log_event()."""

    def test_writes_jsonl(self) -> None:
        """Write a JSON-lines audit event."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            logger = AuditLogger(audit_path=path)
            logger.log_event("test-ctr", "setup", detail="test")

            self.assertTrue(path.exists())
            entry = json.loads(path.read_text().strip())
            self.assertEqual(entry["container"], "test-ctr")
            self.assertEqual(entry["action"], "setup")
            self.assertEqual(entry["detail"], "test")
            self.assertIn("ts", entry)

    def test_optional_fields(self) -> None:
        """Only include optional fields when provided."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            logger = AuditLogger(audit_path=path)
            logger.log_event("test-ctr", "denied", dest=TEST_IP1)

            entry = json.loads(path.read_text().strip())
            self.assertEqual(entry["dest"], TEST_IP1)
            self.assertNotIn("detail", entry)

    def test_skips_when_disabled(self) -> None:
        """No file written when disabled."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            logger = AuditLogger(audit_path=path, enabled=False)
            logger.log_event("test-ctr", "setup", detail="test")
            self.assertFalse(path.exists())

    @mock.patch("pathlib.Path.open", side_effect=OSError("disk full"))
    def test_silently_ignores_write_error(self, _open: mock.Mock) -> None:
        """OSError during write is silently ignored."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            logger = AuditLogger(audit_path=path)
            # Should not raise
            logger.log_event("test-ctr", "setup")

    def test_multiple_events_appended(self) -> None:
        """Multiple events append to the same file."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            logger = AuditLogger(audit_path=path)
            logger.log_event("test-ctr", "setup")
            logger.log_event("test-ctr", "allowed", dest=TEST_IP1)

            lines = path.read_text().strip().split("\n")
            self.assertEqual(len(lines), 2)

    def test_creates_parent_dirs(self) -> None:
        """log_event creates parent directories if needed."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "subdir" / "audit.jsonl"
            logger = AuditLogger(audit_path=path)
            logger.log_event("test-ctr", "setup")
            self.assertTrue(path.exists())


class TestAuditLoggerTailLog(unittest.TestCase):
    """Test AuditLogger.tail_log()."""

    def test_returns_last_n_entries(self) -> None:
        """Return the last N audit events."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            entries = [json.dumps({"action": f"event-{i}"}) for i in range(5)]
            path.write_text("\n".join(entries) + "\n")
            logger = AuditLogger(audit_path=path)

            result = list(logger.tail_log(n=3))
            self.assertEqual(len(result), 3)
            self.assertEqual(result[0]["action"], "event-2")

    def test_skips_corrupt_lines(self) -> None:
        """Skip corrupt JSON lines and yield valid ones."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            path.write_text('{"action":"good"}\nnot-json\n{"action":"also-good"}\n')
            logger = AuditLogger(audit_path=path)

            result = list(logger.tail_log())
            self.assertEqual(len(result), 2)

    def test_missing_file(self) -> None:
        """Return empty for missing log files."""
        logger = AuditLogger(audit_path=NONEXISTENT_DIR / "audit.jsonl")
        result = list(logger.tail_log())
        self.assertEqual(result, [])

    def test_n_zero_returns_nothing(self) -> None:
        """n=0 yields no events."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            path.write_text('{"action":"a"}\n')
            logger = AuditLogger(audit_path=path)
            result = list(logger.tail_log(n=0))
            self.assertEqual(result, [])
