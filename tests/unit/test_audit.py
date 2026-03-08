# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for audit logging."""

import json
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from terok_shield.audit import list_log_files, log_event, tail_log

from ..testnet import TEST_IP1


class TestLogEvent(unittest.TestCase):
    """Tests for log_event."""

    @unittest.mock.patch("terok_shield.audit.shield_logs_dir")
    def test_writes_jsonl(self, mock_dir: unittest.mock.Mock) -> None:
        """Write a JSON-lines audit event."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            log_event("test-ctr", "setup", detail="test")
            log_file = Path(tmp) / "test-ctr.jsonl"
            self.assertTrue(log_file.exists())
            lines = log_file.read_text().strip().split("\n")
            self.assertEqual(len(lines), 1)
            entry = json.loads(lines[0])
            self.assertEqual(entry["container"], "test-ctr")
            self.assertEqual(entry["action"], "setup")
            self.assertEqual(entry["detail"], "test")
            self.assertIn("ts", entry)

    @unittest.mock.patch("terok_shield.audit.shield_logs_dir")
    def test_optional_fields(self, mock_dir: unittest.mock.Mock) -> None:
        """Only include optional fields when provided."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            log_event("test-ctr", "denied", dest=TEST_IP1)
            entry = json.loads((Path(tmp) / "test-ctr.jsonl").read_text().strip())
            self.assertEqual(entry["dest"], TEST_IP1)
            self.assertNotIn("detail", entry)


class TestLogPathTraversal(unittest.TestCase):
    """Tests for path traversal prevention."""

    @unittest.mock.patch("terok_shield.audit.shield_logs_dir")
    def test_rejects_path_traversal(self, mock_dir: unittest.mock.Mock) -> None:
        """Reject container names with path traversal."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            with self.assertRaises(ValueError):
                log_event("../etc/passwd", "setup")

    @unittest.mock.patch("terok_shield.audit.shield_logs_dir")
    def test_rejects_slash(self, mock_dir: unittest.mock.Mock) -> None:
        """Reject container names with slashes."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            with self.assertRaises(ValueError):
                log_event("foo/bar", "setup")

    @unittest.mock.patch("terok_shield.audit.shield_logs_dir")
    def test_rejects_absolute_path(self, mock_dir: unittest.mock.Mock) -> None:
        """Reject absolute path as container name."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            with self.assertRaises(ValueError):
                log_event("/etc/passwd", "setup")


class TestLogEventErrorHandling(unittest.TestCase):
    """Tests for best-effort error handling in log_event."""

    @unittest.mock.patch("terok_shield.audit.shield_logs_dir")
    def test_silently_ignores_write_error(self, mock_dir: unittest.mock.Mock) -> None:
        """OSError during write is silently ignored (best-effort logging)."""
        mock_dir.return_value = Path("/nonexistent/readonly/path")
        # Should not raise
        log_event("test-ctr", "setup")


class TestTailLog(unittest.TestCase):
    """Tests for tail_log."""

    @unittest.mock.patch("terok_shield.audit.shield_logs_dir")
    def test_tail_skips_corrupt_lines(self, mock_dir: unittest.mock.Mock) -> None:
        """Skip corrupt JSON lines and yield valid ones."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            log_file = Path(tmp) / "test-ctr.jsonl"
            log_file.write_text('{"action":"good"}\nnot-json\n{"action":"also-good"}\n')
            result = list(tail_log("test-ctr"))
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["action"], "good")
            self.assertEqual(result[1]["action"], "also-good")

    @unittest.mock.patch("terok_shield.audit.shield_logs_dir")
    def test_tail_returns_entries(self, mock_dir: unittest.mock.Mock) -> None:
        """Return the last N audit events."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            log_file = Path(tmp) / "test-ctr.jsonl"
            entries = [
                json.dumps(
                    {
                        "ts": "2026-01-01T00:00:00+00:00",
                        "container": "test-ctr",
                        "action": f"event-{i}",
                    }
                )
                for i in range(5)
            ]
            log_file.write_text("\n".join(entries) + "\n")
            result = list(tail_log("test-ctr", n=3))
            self.assertEqual(len(result), 3)
            self.assertEqual(result[0]["action"], "event-2")

    @unittest.mock.patch("terok_shield.audit.shield_logs_dir")
    def test_tail_n_zero_returns_nothing(self, mock_dir: unittest.mock.Mock) -> None:
        """n=0 yields no events (not all events)."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            log_file = Path(tmp) / "test-ctr.jsonl"
            log_file.write_text('{"action":"a"}\n{"action":"b"}\n')
            result = list(tail_log("test-ctr", n=0))
            self.assertEqual(result, [])

    @unittest.mock.patch("terok_shield.audit.shield_logs_dir")
    def test_tail_missing_file(self, mock_dir: unittest.mock.Mock) -> None:
        """Return empty for missing log files."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            result = list(tail_log("nonexistent"))
            self.assertEqual(result, [])


class TestListLogFiles(unittest.TestCase):
    """Tests for list_log_files."""

    @unittest.mock.patch("terok_shield.audit.shield_logs_dir")
    def test_lists_containers(self, mock_dir: unittest.mock.Mock) -> None:
        """List container names with audit logs."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            (Path(tmp) / "ctr-a.jsonl").write_text("")
            (Path(tmp) / "ctr-b.jsonl").write_text("")
            result = list_log_files()
            self.assertEqual(result, ["ctr-a", "ctr-b"])

    @unittest.mock.patch("terok_shield.audit.shield_logs_dir")
    def test_empty_when_dir_missing(self, mock_dir: unittest.mock.Mock) -> None:
        """Return empty list when logs directory does not exist."""
        mock_dir.return_value = Path("/nonexistent/logs")
        result = list_log_files()
        self.assertEqual(result, [])
