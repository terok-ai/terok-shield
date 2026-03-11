# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the AuditLogger class (OOP API)."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from terok_shield.audit import AuditLogger
from terok_shield.config import ShieldConfig

from ..testfs import FAKE_LOGS_DIR, FORBIDDEN_TRAVERSAL, NONEXISTENT_DIR
from ..testnet import TEST_IP1


class TestAuditLoggerInit(unittest.TestCase):
    """Test AuditLogger construction."""

    def test_direct_init(self) -> None:
        """Construct with explicit logs_dir and enabled flag."""
        logger = AuditLogger(logs_dir=FAKE_LOGS_DIR, enabled=False)
        self.assertFalse(logger.enabled)

    def test_from_config(self) -> None:
        """Construct from ShieldConfig."""
        config = ShieldConfig(audit_enabled=False)
        logger = AuditLogger.from_config(config)
        self.assertFalse(logger.enabled)
        self.assertEqual(logger._logs_dir, config.paths.logs_dir)

    def test_default_enabled(self) -> None:
        """Default enabled is True."""
        logger = AuditLogger(logs_dir=FAKE_LOGS_DIR)
        self.assertTrue(logger.enabled)


class TestAuditLoggerEnabledToggle(unittest.TestCase):
    """Test enabled property and setter."""

    def test_toggle_enabled(self) -> None:
        """Can toggle enabled on and off."""
        logger = AuditLogger(logs_dir=FAKE_LOGS_DIR, enabled=True)
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
            logger = AuditLogger(logs_dir=Path(tmp))
            logger.log_event("test-ctr", "setup", detail="test")

            log_file = Path(tmp) / "test-ctr.jsonl"
            self.assertTrue(log_file.exists())
            entry = json.loads(log_file.read_text().strip())
            self.assertEqual(entry["container"], "test-ctr")
            self.assertEqual(entry["action"], "setup")
            self.assertEqual(entry["detail"], "test")
            self.assertIn("ts", entry)

    def test_optional_fields(self) -> None:
        """Only include optional fields when provided."""
        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditLogger(logs_dir=Path(tmp))
            logger.log_event("test-ctr", "denied", dest=TEST_IP1)

            entry = json.loads((Path(tmp) / "test-ctr.jsonl").read_text().strip())
            self.assertEqual(entry["dest"], TEST_IP1)
            self.assertNotIn("detail", entry)

    def test_skips_when_disabled(self) -> None:
        """No file written when disabled."""
        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditLogger(logs_dir=Path(tmp), enabled=False)
            logger.log_event("test-ctr", "setup", detail="test")
            self.assertFalse((Path(tmp) / "test-ctr.jsonl").exists())

    def test_rejects_path_traversal(self) -> None:
        """Reject container names with path traversal."""
        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditLogger(logs_dir=Path(tmp))
            with self.assertRaises(ValueError):
                logger.log_event(FORBIDDEN_TRAVERSAL, "setup")

    @mock.patch("pathlib.Path.open", side_effect=OSError("disk full"))
    def test_silently_ignores_write_error(self, _open: mock.Mock) -> None:
        """OSError during write is silently ignored."""
        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditLogger(logs_dir=Path(tmp))
            # Should not raise
            logger.log_event("test-ctr", "setup")

    def test_multiple_events_appended(self) -> None:
        """Multiple events append to the same file."""
        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditLogger(logs_dir=Path(tmp))
            logger.log_event("test-ctr", "setup")
            logger.log_event("test-ctr", "allowed", dest=TEST_IP1)

            lines = (Path(tmp) / "test-ctr.jsonl").read_text().strip().split("\n")
            self.assertEqual(len(lines), 2)


class TestAuditLoggerTailLog(unittest.TestCase):
    """Test AuditLogger.tail_log()."""

    def test_returns_last_n_entries(self) -> None:
        """Return the last N audit events."""
        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditLogger(logs_dir=Path(tmp))
            log_file = Path(tmp) / "test-ctr.jsonl"
            entries = [json.dumps({"action": f"event-{i}"}) for i in range(5)]
            log_file.write_text("\n".join(entries) + "\n")

            result = list(logger.tail_log("test-ctr", n=3))
            self.assertEqual(len(result), 3)
            self.assertEqual(result[0]["action"], "event-2")

    def test_skips_corrupt_lines(self) -> None:
        """Skip corrupt JSON lines and yield valid ones."""
        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditLogger(logs_dir=Path(tmp))
            log_file = Path(tmp) / "test-ctr.jsonl"
            log_file.write_text('{"action":"good"}\nnot-json\n{"action":"also-good"}\n')

            result = list(logger.tail_log("test-ctr"))
            self.assertEqual(len(result), 2)

    def test_missing_file(self) -> None:
        """Return empty for missing log files."""
        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditLogger(logs_dir=Path(tmp))
            result = list(logger.tail_log("nonexistent"))
            self.assertEqual(result, [])

    def test_n_zero_returns_nothing(self) -> None:
        """n=0 yields no events."""
        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditLogger(logs_dir=Path(tmp))
            (Path(tmp) / "test-ctr.jsonl").write_text('{"action":"a"}\n')
            result = list(logger.tail_log("test-ctr", n=0))
            self.assertEqual(result, [])


class TestAuditLoggerListLogFiles(unittest.TestCase):
    """Test AuditLogger.list_log_files()."""

    def test_lists_containers(self) -> None:
        """List container names with audit logs."""
        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditLogger(logs_dir=Path(tmp))
            (Path(tmp) / "ctr-a.jsonl").write_text("")
            (Path(tmp) / "ctr-b.jsonl").write_text("")
            result = logger.list_log_files()
            self.assertEqual(result, ["ctr-a", "ctr-b"])

    def test_empty_when_dir_missing(self) -> None:
        """Return empty list when logs directory does not exist."""
        logger = AuditLogger(logs_dir=NONEXISTENT_DIR / "logs")
        self.assertEqual(logger.list_log_files(), [])
