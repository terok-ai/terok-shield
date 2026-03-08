# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for OCI hook entry point."""

import json
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from terok_shield.hook import _parse_oci_state, _read_resolved_ips, apply_hook, hook_main
from terok_shield.nft_constants import RFC1918
from terok_shield.run import ExecError

from ..testnet import TEST_IP1, TEST_IP2

# Mock output that passes verify_ruleset (must have chain structure
# and RFC1918 reject rules in proper context for regex matching)
_VALID_LIST_OUTPUT = (
    "chain output { type filter hook output priority filter; policy drop;\n"
    "meta nfproto ipv6 drop\n"
    "TEROK_SHIELD_DENIED @allow_v4\n"
    + "\n".join(f"ip daddr {net} reject with icmp type admin-prohibited" for net in RFC1918)
    + "\n}\n"
    + "chain input { type filter hook input priority filter; policy drop;\n"
    + "meta nfproto ipv6 drop\n"
    + "drop }"
)


def _oci_state(cid: str = "abc123", pid: int = 42) -> str:
    """Return a minimal OCI state JSON string."""
    return json.dumps({"id": cid, "pid": pid})


class TestParseOciState(unittest.TestCase):
    """Tests for _parse_oci_state."""

    def test_valid_state(self) -> None:
        """Parse valid OCI state."""
        cid, pid = _parse_oci_state(_oci_state("mycontainer", 1234))
        self.assertEqual(cid, "mycontainer")
        self.assertEqual(pid, "1234")

    def test_missing_id(self) -> None:
        """Raise ValueError for missing id."""
        with self.assertRaises(ValueError):
            _parse_oci_state(json.dumps({"pid": 42}))

    def test_missing_pid(self) -> None:
        """Raise ValueError for missing pid."""
        with self.assertRaises(ValueError):
            _parse_oci_state(json.dumps({"id": "abc"}))

    def test_invalid_json(self) -> None:
        """Raise ValueError for invalid JSON."""
        with self.assertRaises(ValueError):
            _parse_oci_state("not json")

    def test_empty_id(self) -> None:
        """Raise ValueError for empty id."""
        with self.assertRaises(ValueError):
            _parse_oci_state(json.dumps({"id": "", "pid": 42}))

    def test_non_object_json(self) -> None:
        """Raise ValueError for valid JSON that is not an object."""
        for value in ["[]", '"string"', "123", "true"]:
            with self.assertRaises(ValueError, msg=f"Should reject: {value}"):
                _parse_oci_state(value)


class TestReadResolvedIps(unittest.TestCase):
    """Tests for _read_resolved_ips."""

    @unittest.mock.patch("terok_shield.hook.shield_resolved_dir")
    def test_reads_file(self, mock_dir: unittest.mock.Mock) -> None:
        """Read IPs from resolved file."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            (Path(tmp) / "test-ctr.resolved").write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
            result = _read_resolved_ips("test-ctr")
            self.assertEqual(result, [TEST_IP1, TEST_IP2])

    @unittest.mock.patch("terok_shield.hook.shield_resolved_dir")
    def test_missing_file(self, mock_dir: unittest.mock.Mock) -> None:
        """Return empty list for missing resolved file."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            result = _read_resolved_ips("nonexistent")
            self.assertEqual(result, [])

    @unittest.mock.patch("terok_shield.hook.shield_resolved_dir")
    def test_skips_blank_lines(self, mock_dir: unittest.mock.Mock) -> None:
        """Skip blank lines in resolved file."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            (Path(tmp) / "test-ctr.resolved").write_text(f"\n{TEST_IP1}\n\n{TEST_IP2}\n\n")
            result = _read_resolved_ips("test-ctr")
            self.assertEqual(result, [TEST_IP1, TEST_IP2])

    def test_rejects_path_traversal(self) -> None:
        """Return empty list for names with path traversal."""
        self.assertEqual(_read_resolved_ips("../etc/passwd"), [])

    def test_rejects_slash(self) -> None:
        """Return empty list for names with slashes."""
        self.assertEqual(_read_resolved_ips("foo/bar"), [])


class TestApplyHook(unittest.TestCase):
    """Tests for apply_hook."""

    @unittest.mock.patch("terok_shield.hook.log_event")
    @unittest.mock.patch("terok_shield.hook.nft_via_nsenter")
    @unittest.mock.patch("terok_shield.hook.shield_resolved_dir")
    def test_success_no_ips(
        self,
        mock_dir: unittest.mock.Mock,
        mock_nft: unittest.mock.Mock,
        mock_log: unittest.mock.Mock,
    ) -> None:
        """Apply hook with no pre-resolved IPs."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            mock_nft.side_effect = [
                "",  # apply ruleset
                _VALID_LIST_OUTPUT,  # list ruleset
            ]
            apply_hook("test-ctr", "42")
            self.assertEqual(mock_nft.call_count, 2)
            # First call: apply ruleset via stdin
            apply_call = mock_nft.call_args_list[0]
            self.assertIn("stdin", apply_call.kwargs)
            self.assertEqual(apply_call.kwargs["pid"], "42")
            # Second call: list ruleset
            list_call = mock_nft.call_args_list[1]
            self.assertIn("list", list_call.args)
            self.assertEqual(list_call.kwargs["pid"], "42")
            # Audit trail: per-step setup logs + final summary
            details = [c.kwargs.get("detail", "") for c in mock_log.call_args_list]
            self.assertIn("ruleset applied", details)
            self.assertIn("read 0 cached IPs", details)
            self.assertIn("verification passed", details)
            self.assertIn("applied with 0 allowed IPs", details)

    @unittest.mock.patch("terok_shield.hook.log_event")
    @unittest.mock.patch("terok_shield.hook.nft_via_nsenter")
    @unittest.mock.patch("terok_shield.hook.shield_resolved_dir")
    def test_success_with_ips(
        self,
        mock_dir: unittest.mock.Mock,
        mock_nft: unittest.mock.Mock,
        mock_log: unittest.mock.Mock,
    ) -> None:
        """Apply hook with pre-resolved IPs."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            (Path(tmp) / "test-ctr.resolved").write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
            mock_nft.side_effect = [
                "",  # apply ruleset
                "",  # add elements
                _VALID_LIST_OUTPUT,  # list
            ]
            apply_hook("test-ctr", "42")
            self.assertEqual(mock_nft.call_count, 3)
            # First call: apply ruleset via stdin
            apply_call = mock_nft.call_args_list[0]
            self.assertIn("stdin", apply_call.kwargs)
            self.assertEqual(apply_call.kwargs["pid"], "42")
            # Second call: add elements — must carry the resolved IPs
            add_call = mock_nft.call_args_list[1]
            add_stdin = add_call.kwargs.get("stdin", "")
            self.assertIn(TEST_IP1, add_stdin)
            self.assertIn(TEST_IP2, add_stdin)
            self.assertEqual(add_call.kwargs["pid"], "42")
            # Third call: list ruleset for verification
            list_call = mock_nft.call_args_list[2]
            self.assertIn("list", list_call.args)
            self.assertEqual(list_call.kwargs["pid"], "42")
            # Audit trail: per-step setup logs including IP details
            details = [c.kwargs.get("detail", "") for c in mock_log.call_args_list]
            self.assertIn("ruleset applied", details)
            self.assertIn("read 2 cached IPs", details)
            self.assertTrue(any(f"[ips] cached: {TEST_IP1}" in d for d in details))
            self.assertTrue(any(f"[ips] added to allow_v4: {TEST_IP1}" in d for d in details))
            self.assertIn("verification passed", details)
            self.assertIn("applied with 2 allowed IPs", details)

    @unittest.mock.patch("terok_shield.hook.log_event")
    @unittest.mock.patch("terok_shield.hook.nft_via_nsenter")
    @unittest.mock.patch("terok_shield.hook.shield_resolved_dir")
    def test_fail_closed_on_apply_error(
        self,
        mock_dir: unittest.mock.Mock,
        mock_nft: unittest.mock.Mock,
        mock_log: unittest.mock.Mock,
    ) -> None:
        """Raise RuntimeError if ruleset application fails."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            mock_nft.side_effect = ExecError(["nft"], 1, "permission denied")
            with self.assertRaises(RuntimeError):
                apply_hook("test-ctr", "42")
            # Last log call must be the error
            self.assertEqual(mock_log.call_args[0], ("test-ctr", "error"))
            self.assertIn("apply failed", mock_log.call_args[1]["detail"])

    @unittest.mock.patch("terok_shield.hook.log_event")
    @unittest.mock.patch("terok_shield.hook.nft_via_nsenter")
    @unittest.mock.patch("terok_shield.hook.shield_resolved_dir")
    def test_fail_closed_on_add_elements_error(
        self,
        mock_dir: unittest.mock.Mock,
        mock_nft: unittest.mock.Mock,
        mock_log: unittest.mock.Mock,
    ) -> None:
        """Raise RuntimeError if adding allow elements fails."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            (Path(tmp) / "test-ctr.resolved").write_text(f"{TEST_IP1}\n")
            mock_nft.side_effect = [
                "",  # apply ruleset succeeds
                ExecError(["nft"], 1, "add failed"),  # add elements fails
            ]
            with self.assertRaises(RuntimeError):
                apply_hook("test-ctr", "42")
            # Last log call must be the error (earlier setup logs are expected)
            self.assertEqual(mock_log.call_args[0], ("test-ctr", "error"))
            self.assertIn("add-elements failed", mock_log.call_args[1]["detail"])

    @unittest.mock.patch("terok_shield.hook.log_event")
    @unittest.mock.patch("terok_shield.hook.nft_via_nsenter")
    @unittest.mock.patch("terok_shield.hook.shield_resolved_dir")
    def test_fail_closed_on_list_error(
        self,
        mock_dir: unittest.mock.Mock,
        mock_nft: unittest.mock.Mock,
        mock_log: unittest.mock.Mock,
    ) -> None:
        """Raise RuntimeError if listing ruleset for verification fails."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            mock_nft.side_effect = [
                "",  # apply ruleset succeeds
                ExecError(["nft"], 1, "list failed"),  # list ruleset fails
            ]
            with self.assertRaises(RuntimeError):
                apply_hook("test-ctr", "42")
            # Last log call must be the error (earlier setup logs are expected)
            self.assertEqual(mock_log.call_args[0], ("test-ctr", "error"))
            self.assertIn("list failed", mock_log.call_args[1]["detail"])

    @unittest.mock.patch("terok_shield.hook.log_event")
    @unittest.mock.patch("terok_shield.hook.nft_via_nsenter")
    @unittest.mock.patch("terok_shield.hook.shield_resolved_dir")
    def test_fail_closed_on_verify_error(
        self,
        mock_dir: unittest.mock.Mock,
        mock_nft: unittest.mock.Mock,
        mock_log: unittest.mock.Mock,
    ) -> None:
        """Raise RuntimeError if verification fails."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            mock_nft.side_effect = [
                "",  # apply
                "some garbage without policy drop",  # list — fails verify
            ]
            with self.assertRaises(RuntimeError):
                apply_hook("test-ctr", "42")
            # Last log call must be the error (earlier setup logs are expected)
            self.assertEqual(mock_log.call_args[0], ("test-ctr", "error"))
            self.assertIn("verification failed", mock_log.call_args[1]["detail"])

    @unittest.mock.patch("terok_shield.hook.log_event")
    @unittest.mock.patch("terok_shield.hook.nft_via_nsenter")
    @unittest.mock.patch("terok_shield.hook._read_resolved_ips")
    def test_fail_closed_on_cache_read_error(
        self,
        mock_read: unittest.mock.Mock,
        mock_nft: unittest.mock.Mock,
        mock_log: unittest.mock.Mock,
    ) -> None:
        """Raise RuntimeError if reading resolved cache fails."""
        mock_nft.return_value = ""
        mock_read.side_effect = OSError("disk error")
        with self.assertRaises(RuntimeError):
            apply_hook("test-ctr", "42")
        mock_log.assert_called_with(
            "test-ctr", "error", detail="resolved cache read failed: disk error"
        )


class TestIpClassification(unittest.TestCase):
    """Tests for RFC1918 and broad CIDR classification logging."""

    @unittest.mock.patch("terok_shield.hook.log_event")
    @unittest.mock.patch("terok_shield.hook.nft_via_nsenter")
    @unittest.mock.patch("terok_shield.hook.shield_resolved_dir")
    def test_rfc1918_logged_as_note(
        self,
        mock_dir: unittest.mock.Mock,
        mock_nft: unittest.mock.Mock,
        mock_log: unittest.mock.Mock,
    ) -> None:
        """RFC1918 IPs in resolved cache produce a 'note' log entry."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            (Path(tmp) / "test-ctr.resolved").write_text("10.0.0.5\n")
            mock_nft.side_effect = ["", "", _VALID_LIST_OUTPUT]
            apply_hook("test-ctr", "42")
            note_calls = [c for c in mock_log.call_args_list if c[0][1] == "note"]
            self.assertTrue(
                any(
                    "rfc1918 whitelisted: 10.0.0.5" in c.kwargs.get("detail", "")
                    for c in note_calls
                )
            )

    @unittest.mock.patch("terok_shield.hook.log_event")
    @unittest.mock.patch("terok_shield.hook.nft_via_nsenter")
    @unittest.mock.patch("terok_shield.hook.shield_resolved_dir")
    def test_broad_cidr_logged_as_note(
        self,
        mock_dir: unittest.mock.Mock,
        mock_nft: unittest.mock.Mock,
        mock_log: unittest.mock.Mock,
    ) -> None:
        """Broad CIDRs (prefix <= 16) produce a 'note' log entry."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            (Path(tmp) / "test-ctr.resolved").write_text(f"203.0.0.0/8\n{TEST_IP1}\n")
            mock_nft.side_effect = ["", "", _VALID_LIST_OUTPUT]
            apply_hook("test-ctr", "42")
            note_calls = [c for c in mock_log.call_args_list if c[0][1] == "note"]
            self.assertTrue(
                any(
                    "broad range whitelisted: 203.0.0.0/8" in c.kwargs.get("detail", "")
                    for c in note_calls
                )
            )

    @unittest.mock.patch("terok_shield.hook.log_event")
    @unittest.mock.patch("terok_shield.hook.nft_via_nsenter")
    @unittest.mock.patch("terok_shield.hook.shield_resolved_dir")
    def test_no_note_for_public_ips(
        self,
        mock_dir: unittest.mock.Mock,
        mock_nft: unittest.mock.Mock,
        mock_log: unittest.mock.Mock,
    ) -> None:
        """Normal public IPs produce no 'note' log entries."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            (Path(tmp) / "test-ctr.resolved").write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
            mock_nft.side_effect = ["", "", _VALID_LIST_OUTPUT]
            apply_hook("test-ctr", "42")
            note_calls = [c for c in mock_log.call_args_list if c[0][1] == "note"]
            self.assertEqual(note_calls, [])


class TestHookMain(unittest.TestCase):
    """Tests for hook_main entry point."""

    @unittest.mock.patch("terok_shield.hook.apply_hook")
    def test_success(self, mock_apply: unittest.mock.Mock) -> None:
        """Return 0 on success."""
        rc = hook_main(_oci_state("test-ctr", 42))
        self.assertEqual(rc, 0)
        mock_apply.assert_called_once_with("test-ctr", "42")

    @unittest.mock.patch("terok_shield.hook.apply_hook")
    def test_invalid_json(self, mock_apply: unittest.mock.Mock) -> None:
        """Return 1 on invalid OCI state."""
        rc = hook_main("not json")
        self.assertEqual(rc, 1)
        mock_apply.assert_not_called()

    @unittest.mock.patch("terok_shield.hook.apply_hook", side_effect=RuntimeError("boom"))
    def test_runtime_error(self, mock_apply: unittest.mock.Mock) -> None:
        """Return 1 on RuntimeError from apply_hook."""
        rc = hook_main(_oci_state())
        self.assertEqual(rc, 1)
