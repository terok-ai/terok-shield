# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for per-container state bundle layout (state.py)."""

import tempfile
import unittest
from pathlib import Path

from terok_shield.state import (
    BUNDLE_VERSION,
    audit_path,
    ensure_state_dirs,
    hook_entrypoint,
    hook_json_path,
    hooks_dir,
    live_allowed_path,
    profile_allowed_path,
)


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
        self._sd = Path("/tmp/terok-test-state")

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
