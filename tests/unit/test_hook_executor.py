# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the HookExecutor class."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from terok_shield import state
from terok_shield.oci_hook import HookExecutor
from terok_shield.run import ExecError

from ..testnet import RFC1918_HOST, TEST_IP1, TEST_IP2


class TestHookExecutorInit(unittest.TestCase):
    """Test HookExecutor construction."""

    def test_stores_collaborators(self) -> None:
        """HookExecutor stores all injected collaborators."""
        runner = mock.MagicMock()
        audit = mock.MagicMock()
        ruleset = mock.MagicMock()

        with tempfile.TemporaryDirectory() as tmp:
            executor = HookExecutor(
                runner=runner,
                audit=audit,
                ruleset=ruleset,
                state_dir=Path(tmp),
            )
            self.assertIs(executor._runner, runner)
            self.assertIs(executor._audit, audit)
            self.assertIs(executor._ruleset, ruleset)
            self.assertEqual(executor._state_dir, Path(tmp))


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
                state_dir=Path(tmp),
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
            state.profile_allowed_path(Path(tmp)).write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
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
                state_dir=Path(tmp),
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
                state_dir=Path(tmp),
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
                state_dir=Path(tmp),
            )
            with self.assertRaises(RuntimeError) as ctx:
                executor.apply("test-ctr", "42")
            self.assertIn("verification failed", str(ctx.exception))


class TestHookExecutorReadAllowedIps(unittest.TestCase):
    """Test HookExecutor._read_allowed_ips()."""

    def test_reads_profile_allowed(self) -> None:
        """Read IPs from profile.allowed file."""
        with tempfile.TemporaryDirectory() as tmp:
            state.profile_allowed_path(Path(tmp)).write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
            executor = _make_executor(state_dir=Path(tmp))
            result = executor._read_allowed_ips()
            self.assertEqual(result, [TEST_IP1, TEST_IP2])

    def test_reads_both_files(self) -> None:
        """Read and merge IPs from both profile.allowed and live.allowed."""
        with tempfile.TemporaryDirectory() as tmp:
            state.profile_allowed_path(Path(tmp)).write_text(f"{TEST_IP1}\n")
            state.live_allowed_path(Path(tmp)).write_text(f"{TEST_IP2}\n")
            executor = _make_executor(state_dir=Path(tmp))
            result = executor._read_allowed_ips()
            self.assertEqual(result, [TEST_IP1, TEST_IP2])

    def test_deduplicates(self) -> None:
        """Duplicate IPs across files are deduplicated."""
        with tempfile.TemporaryDirectory() as tmp:
            state.profile_allowed_path(Path(tmp)).write_text(f"{TEST_IP1}\n")
            state.live_allowed_path(Path(tmp)).write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
            executor = _make_executor(state_dir=Path(tmp))
            result = executor._read_allowed_ips()
            self.assertEqual(result, [TEST_IP1, TEST_IP2])

    def test_missing_files(self) -> None:
        """Return empty list when no allowlist files exist."""
        with tempfile.TemporaryDirectory() as tmp:
            executor = _make_executor(state_dir=Path(tmp))
            result = executor._read_allowed_ips()
            self.assertEqual(result, [])

    def test_skips_blank_lines(self) -> None:
        """Skip blank lines in allowlist files."""
        with tempfile.TemporaryDirectory() as tmp:
            state.profile_allowed_path(Path(tmp)).write_text(f"\n{TEST_IP1}\n\n")
            executor = _make_executor(state_dir=Path(tmp))
            result = executor._read_allowed_ips()
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
            state.profile_allowed_path(Path(tmp)).write_text(f"{RFC1918_HOST}\n")
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
                state_dir=Path(tmp),
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
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.MagicMock()
            runner.nft_via_nsenter.return_value = ""
            audit = mock.MagicMock()
            ruleset = mock.MagicMock()
            ruleset.build_hook.return_value = "hook"

            executor = HookExecutor(
                runner=runner,
                audit=audit,
                ruleset=ruleset,
                state_dir=Path(tmp),
            )
            with mock.patch.object(executor, "_read_allowed_ips", side_effect=OSError("disk fail")):
                with self.assertRaises(RuntimeError):
                    executor.apply("test-ctr", "42")

    def test_unicodeerror_raises_runtime(self) -> None:
        """UnicodeError reading resolved cache raises RuntimeError."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.MagicMock()
            runner.nft_via_nsenter.return_value = ""
            audit = mock.MagicMock()
            ruleset = mock.MagicMock()
            ruleset.build_hook.return_value = "hook"

            executor = HookExecutor(
                runner=runner,
                audit=audit,
                ruleset=ruleset,
                state_dir=Path(tmp),
            )
            with mock.patch.object(
                executor, "_read_allowed_ips", side_effect=UnicodeError("bad encoding")
            ):
                with self.assertRaises(RuntimeError):
                    executor.apply("test-ctr", "42")


# ── Helper ──────────────────────────────────────────────


def _make_executor(
    *,
    runner: mock.MagicMock | None = None,
    audit: mock.MagicMock | None = None,
    ruleset: mock.MagicMock | None = None,
    state_dir: Path | None = None,
) -> HookExecutor:
    """Create a HookExecutor with mock collaborators."""
    return HookExecutor(
        runner=runner or mock.MagicMock(),
        audit=audit or mock.MagicMock(),
        ruleset=ruleset or mock.MagicMock(),
        state_dir=state_dir or Path(tempfile.mkdtemp()),
    )
