# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for per-container state bundle layout (state.py)."""

import tempfile
import unittest
from pathlib import Path

from terok_shield.state import (
    BUNDLE_VERSION,
    audit_path,
    deny_path,
    ensure_state_dirs,
    hook_entrypoint,
    hook_json_path,
    hooks_dir,
    live_allowed_path,
    profile_allowed_path,
    read_denied_ips,
    read_effective_ips,
)

from ..testfs import FAKE_STATE_DIR
from ..testnet import TEST_IP1, TEST_IP2, TEST_IP3


class TestBundleVersion(unittest.TestCase):
    """Test BUNDLE_VERSION constant."""

    def test_is_positive_int(self) -> None:
        """Bundle version is a positive integer."""
        self.assertIsInstance(BUNDLE_VERSION, int)
        self.assertGreater(BUNDLE_VERSION, 0)


class TestPathDerivation(unittest.TestCase):
    """Test pure path derivation functions."""

    def setUp(self) -> None:
        """Set up a base state directory for tests."""
        self._sd = FAKE_STATE_DIR

    def test_hooks_dir(self) -> None:
        """hooks_dir returns state_dir / hooks."""
        self.assertEqual(hooks_dir(self._sd), self._sd / "hooks")

    def test_hook_entrypoint(self) -> None:
        """hook_entrypoint returns state_dir / terok-shield-hook."""
        self.assertEqual(hook_entrypoint(self._sd), self._sd / "terok-shield-hook")

    def test_hook_json_path_create_runtime(self) -> None:
        """hook_json_path returns correct path for createRuntime."""
        expected = self._sd / "hooks" / "terok-shield-createRuntime.json"
        self.assertEqual(hook_json_path(self._sd, "createRuntime"), expected)

    def test_hook_json_path_poststop(self) -> None:
        """hook_json_path returns correct path for poststop."""
        expected = self._sd / "hooks" / "terok-shield-poststop.json"
        self.assertEqual(hook_json_path(self._sd, "poststop"), expected)

    def test_profile_allowed_path(self) -> None:
        """profile_allowed_path returns state_dir / profile.allowed."""
        self.assertEqual(profile_allowed_path(self._sd), self._sd / "profile.allowed")

    def test_live_allowed_path(self) -> None:
        """live_allowed_path returns state_dir / live.allowed."""
        self.assertEqual(live_allowed_path(self._sd), self._sd / "live.allowed")

    def test_deny_path(self) -> None:
        """deny_path returns state_dir / deny.list."""
        self.assertEqual(deny_path(self._sd), self._sd / "deny.list")

    def test_audit_path(self) -> None:
        """audit_path returns state_dir / audit.jsonl."""
        self.assertEqual(audit_path(self._sd), self._sd / "audit.jsonl")


class TestEnsureStateDirs(unittest.TestCase):
    """Test ensure_state_dirs directory creation."""

    def test_creates_dirs(self) -> None:
        """ensure_state_dirs creates state_dir and hooks subdirectory."""
        with tempfile.TemporaryDirectory() as tmp:
            sd = Path(tmp) / "container-1"
            ensure_state_dirs(sd)
            self.assertTrue(sd.is_dir())
            self.assertTrue(hooks_dir(sd).is_dir())

    def test_idempotent(self) -> None:
        """ensure_state_dirs is safe to call repeatedly."""
        with tempfile.TemporaryDirectory() as tmp:
            sd = Path(tmp) / "container-1"
            ensure_state_dirs(sd)
            ensure_state_dirs(sd)  # should not raise
            self.assertTrue(sd.is_dir())

    def test_nested_path(self) -> None:
        """ensure_state_dirs creates deeply nested paths."""
        with tempfile.TemporaryDirectory() as tmp:
            sd = Path(tmp) / "deep" / "nested" / "state"
            ensure_state_dirs(sd)
            self.assertTrue(sd.is_dir())
            self.assertTrue(hooks_dir(sd).is_dir())


class TestReadDeniedIps(unittest.TestCase):
    """Test read_denied_ips()."""

    def test_empty_when_no_file(self) -> None:
        """Return empty set when deny.list does not exist."""
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(read_denied_ips(Path(tmp)), set())

    def test_reads_populated_file(self) -> None:
        """Read IPs from deny.list."""
        with tempfile.TemporaryDirectory() as tmp:
            sd = Path(tmp)
            deny_path(sd).write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
            result = read_denied_ips(sd)
            self.assertEqual(result, {TEST_IP1, TEST_IP2})

    def test_skips_blank_lines(self) -> None:
        """Skip blank lines in deny.list."""
        with tempfile.TemporaryDirectory() as tmp:
            sd = Path(tmp)
            deny_path(sd).write_text(f"\n{TEST_IP1}\n\n")
            self.assertEqual(read_denied_ips(sd), {TEST_IP1})


class TestReadEffectiveIps(unittest.TestCase):
    """Test read_effective_ips()."""

    def test_subtracts_denied(self) -> None:
        """Denied IPs are removed from the effective list."""
        with tempfile.TemporaryDirectory() as tmp:
            sd = Path(tmp)
            profile_allowed_path(sd).write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
            deny_path(sd).write_text(f"{TEST_IP1}\n")
            result = read_effective_ips(sd)
            self.assertEqual(result, [TEST_IP2])

    def test_no_deny_file_same_as_read_allowed(self) -> None:
        """Without deny.list, effective IPs equal allowed IPs."""
        with tempfile.TemporaryDirectory() as tmp:
            sd = Path(tmp)
            profile_allowed_path(sd).write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
            live_allowed_path(sd).write_text(f"{TEST_IP3}\n")
            result = read_effective_ips(sd)
            self.assertEqual(result, [TEST_IP1, TEST_IP2, TEST_IP3])

    def test_deny_only_affects_matching_ips(self) -> None:
        """Deny list entries that are not in allowed have no effect."""
        with tempfile.TemporaryDirectory() as tmp:
            sd = Path(tmp)
            profile_allowed_path(sd).write_text(f"{TEST_IP1}\n")
            deny_path(sd).write_text(f"{TEST_IP3}\n")
            result = read_effective_ips(sd)
            self.assertEqual(result, [TEST_IP1])
