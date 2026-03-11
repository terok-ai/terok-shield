# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the HookExecutor class (OOP API)."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from terok_shield.oci_hook import HookExecutor
from terok_shield.run import ExecError

from ..testfs import FAKE_RESOLVED_DIR, FORBIDDEN_TRAVERSAL
from ..testnet import RFC1918_HOST, TEST_IP1, TEST_IP2


class TestHookExecutorInit(unittest.TestCase):
    """Test HookExecutor construction."""

    def test_stores_collaborators(self) -> None:
        """HookExecutor stores all injected collaborators."""
        runner = mock.MagicMock()
        audit = mock.MagicMock()
        ruleset = mock.MagicMock()
        resolved_dir = FAKE_RESOLVED_DIR

        executor = HookExecutor(
            runner=runner,
            audit=audit,
            ruleset=ruleset,
            resolved_dir=resolved_dir,
        )
        self.assertIs(executor._runner, runner)
        self.assertIs(executor._audit, audit)
        self.assertIs(executor._ruleset, ruleset)
        self.assertEqual(executor._resolved_dir, resolved_dir)


class TestHookExecutorApply(unittest.TestCase):
    """Test HookExecutor.apply()."""

    def test_success_no_ips(self) -> None:
        """Apply with no pre-resolved IPs."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.MagicMock()
            runner.nft_via_nsenter.side_effect = ["", "valid list output"]
            audit = mock.MagicMock()
            ruleset = mock.MagicMock()
            ruleset.build_hook.return_value = "hook ruleset"
            ruleset.verify_hook.return_value = []
            ruleset.add_elements_dual.return_value = ""

            executor = HookExecutor(
                runner=runner,
                audit=audit,
                ruleset=ruleset,
                resolved_dir=Path(tmp),
            )
            executor.apply("test-ctr", "42")

            # verify calls: apply + list for verify
            self.assertEqual(runner.nft_via_nsenter.call_count, 2)
            # audit trail
            details = [c.kwargs.get("detail", "") for c in audit.log_event.call_args_list]
            self.assertIn("ruleset applied", details)
            self.assertIn("verification passed", details)

    def test_success_with_ips(self) -> None:
        """Apply with pre-resolved IPs."""
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "test-ctr.resolved").write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
            runner = mock.MagicMock()
            runner.nft_via_nsenter.side_effect = ["", "", "valid list output"]
            audit = mock.MagicMock()
            ruleset = mock.MagicMock()
            ruleset.build_hook.return_value = "hook"
            ruleset.verify_hook.return_value = []
            ruleset.add_elements_dual.return_value = f"add element allow_v4 {{ {TEST_IP1} }}"

            executor = HookExecutor(
                runner=runner,
                audit=audit,
                ruleset=ruleset,
                resolved_dir=Path(tmp),
            )
            executor.apply("test-ctr", "42")
            self.assertEqual(runner.nft_via_nsenter.call_count, 3)

    def test_fail_closed_on_apply_error(self) -> None:
        """Raise RuntimeError and short-circuit if ruleset application fails."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.MagicMock()
            runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "permission denied")
            audit = mock.MagicMock()
            ruleset = mock.MagicMock()
            ruleset.build_hook.return_value = "hook"

            executor = HookExecutor(
                runner=runner,
                audit=audit,
                ruleset=ruleset,
                resolved_dir=Path(tmp),
            )
            with self.assertRaises(RuntimeError):
                executor.apply("test-ctr", "42")

            # Verify short-circuit: nft called once (apply), verify never reached
            runner.nft_via_nsenter.assert_called_once()
            ruleset.verify_hook.assert_not_called()

    def test_fail_closed_on_verify_error(self) -> None:
        """Raise RuntimeError if verification fails."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.MagicMock()
            runner.nft_via_nsenter.side_effect = ["", "bad output"]
            audit = mock.MagicMock()
            ruleset = mock.MagicMock()
            ruleset.build_hook.return_value = "hook"
            ruleset.verify_hook.return_value = ["policy is not drop"]

            executor = HookExecutor(
                runner=runner,
                audit=audit,
                ruleset=ruleset,
                resolved_dir=Path(tmp),
            )
            with self.assertRaises(RuntimeError) as ctx:
                executor.apply("test-ctr", "42")
            self.assertIn("verification failed", str(ctx.exception))


class TestHookExecutorReadResolvedIps(unittest.TestCase):
    """Test HookExecutor._read_resolved_ips()."""

    def test_reads_file(self) -> None:
        """Read IPs from resolved file."""
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "test-ctr.resolved").write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
            executor = _make_executor(resolved_dir=Path(tmp))
            result = executor._read_resolved_ips("test-ctr")
            self.assertEqual(result, [TEST_IP1, TEST_IP2])

    def test_missing_file(self) -> None:
        """Return empty list for missing resolved file."""
        with tempfile.TemporaryDirectory() as tmp:
            executor = _make_executor(resolved_dir=Path(tmp))
            result = executor._read_resolved_ips("nonexistent")
            self.assertEqual(result, [])

    def test_rejects_path_traversal(self) -> None:
        """Return empty list for names with path traversal."""
        executor = _make_executor()
        self.assertEqual(executor._read_resolved_ips(FORBIDDEN_TRAVERSAL), [])

    def test_skips_blank_lines(self) -> None:
        """Skip blank lines in resolved file."""
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "test-ctr.resolved").write_text(f"\n{TEST_IP1}\n\n")
            executor = _make_executor(resolved_dir=Path(tmp))
            result = executor._read_resolved_ips("test-ctr")
            self.assertEqual(result, [TEST_IP1])


class TestHookExecutorNftExec(unittest.TestCase):
    """Test HookExecutor._nft_exec()."""

    def test_success(self) -> None:
        """nft_exec returns output on success."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.return_value = "output"
        executor = _make_executor(runner=runner)

        result = executor._nft_exec("test-ctr", "42", "list", "ruleset")
        self.assertEqual(result, "output")

    def test_exec_error_raises_runtime(self) -> None:
        """nft_exec converts ExecError to RuntimeError."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "fail")
        audit = mock.MagicMock()
        executor = _make_executor(runner=runner, audit=audit)

        with self.assertRaises(RuntimeError) as ctx:
            executor._nft_exec("test-ctr", "42", "list", "ruleset")
        self.assertIn("list failed", str(ctx.exception))
        audit.log_event.assert_called()

    def test_custom_action_label(self) -> None:
        """nft_exec uses custom action label in error messages."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "fail")
        audit = mock.MagicMock()
        executor = _make_executor(runner=runner, audit=audit)

        with self.assertRaises(RuntimeError) as ctx:
            executor._nft_exec("test-ctr", "42", stdin="rules", action="add-elements")
        self.assertIn("add-elements failed", str(ctx.exception))


class TestHookExecutorParseOciState(unittest.TestCase):
    """Test HookExecutor.parse_oci_state() static method."""

    def test_valid_state(self) -> None:
        """Parse valid OCI state via the class method."""
        cid, pid, _ = HookExecutor.parse_oci_state(json.dumps({"id": "abc123", "pid": 42}))
        self.assertEqual(cid, "abc123")
        self.assertEqual(pid, "42")

    def test_invalid_json_raises(self) -> None:
        """Raise ValueError for invalid JSON."""
        with self.assertRaises(ValueError):
            HookExecutor.parse_oci_state("not json")


class TestHookExecutorClassifyLogging(unittest.TestCase):
    """Test private-range and broad CIDR classification logging in HookExecutor."""

    def test_rfc1918_logged_as_note(self) -> None:
        """RFC1918 IPs produce a 'note' log entry."""
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "test-ctr.resolved").write_text(f"{RFC1918_HOST}\n")
            runner = mock.MagicMock()
            runner.nft_via_nsenter.side_effect = ["", "", "valid"]
            audit = mock.MagicMock()
            ruleset = mock.MagicMock()
            ruleset.build_hook.return_value = "hook"
            ruleset.verify_hook.return_value = []
            ruleset.add_elements_dual.return_value = "add element"

            executor = HookExecutor(
                runner=runner,
                audit=audit,
                ruleset=ruleset,
                resolved_dir=Path(tmp),
            )
            executor.apply("test-ctr", "42")

            note_calls = [
                c for c in audit.log_event.call_args_list if len(c[0]) >= 2 and c[0][1] == "note"
            ]
            self.assertTrue(
                any("private range" in c.kwargs.get("detail", "") for c in note_calls),
            )


class TestHookExecutorCacheReadError(unittest.TestCase):
    """Test fail-closed on cache read error."""

    def test_oserror_raises_runtime(self) -> None:
        """OSError reading resolved cache raises RuntimeError."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.return_value = ""
        audit = mock.MagicMock()
        ruleset = mock.MagicMock()
        ruleset.build_hook.return_value = "hook"

        executor = HookExecutor(
            runner=runner,
            audit=audit,
            ruleset=ruleset,
            resolved_dir=FAKE_RESOLVED_DIR,
        )
        with mock.patch.object(executor, "_read_resolved_ips", side_effect=OSError("disk fail")):
            with self.assertRaises(RuntimeError):
                executor.apply("test-ctr", "42")

    def test_unicodeerror_raises_runtime(self) -> None:
        """UnicodeError reading resolved cache raises RuntimeError."""
        runner = mock.MagicMock()
        runner.nft_via_nsenter.return_value = ""
        audit = mock.MagicMock()
        ruleset = mock.MagicMock()
        ruleset.build_hook.return_value = "hook"

        executor = HookExecutor(
            runner=runner,
            audit=audit,
            ruleset=ruleset,
            resolved_dir=FAKE_RESOLVED_DIR,
        )
        with mock.patch.object(
            executor, "_read_resolved_ips", side_effect=UnicodeError("bad encoding")
        ):
            with self.assertRaises(RuntimeError):
                executor.apply("test-ctr", "42")


# ── Helper ──────────────────────────────────────────────


def _make_executor(
    *,
    runner: mock.MagicMock | None = None,
    audit: mock.MagicMock | None = None,
    ruleset: mock.MagicMock | None = None,
    resolved_dir: Path | None = None,
) -> HookExecutor:
    """Create a HookExecutor with mock collaborators."""
    return HookExecutor(
        runner=runner or mock.MagicMock(),
        audit=audit or mock.MagicMock(),
        ruleset=ruleset or mock.MagicMock(),
        resolved_dir=resolved_dir or FAKE_RESOLVED_DIR,
    )
