# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""API surface snapshot tests.

Asserts the exact public API shape so accidental breakage is caught
immediately when terok starts depending on terok-shield.
"""

import dataclasses
import tempfile
import unittest
from pathlib import Path

import terok_shield
from terok_shield import ExecError, ShieldConfig, ShieldMode, ShieldState

EXPECTED_ALL = [
    "AuditLogger",
    "CommandRunner",
    "DnsResolver",
    "ExecError",
    "ProfileLoader",
    "RulesetBuilder",
    "Shield",
    "ShieldConfig",
    "ShieldMode",
    "ShieldState",
    "SubprocessRunner",
]


class TestAPISurface(unittest.TestCase):
    """Snapshot tests for the terok-shield public API."""

    # ── __all__ ──────────────────────────────────────────

    def test_all_exports(self):
        """__all__ contains exactly the expected public names."""
        self.assertEqual(sorted(terok_shield.__all__), EXPECTED_ALL)

    # ── ShieldMode ───────────────────────────────────────

    def test_shield_mode_members(self):
        """ShieldMode has exactly HOOK."""
        members = {m.name: m.value for m in ShieldMode}
        self.assertEqual(members, {"HOOK": "hook"})

    def test_shield_state_members(self):
        """ShieldState has UP, DOWN, DOWN_ALL, INACTIVE, ERROR."""
        members = {m.name: m.value for m in ShieldState}
        self.assertEqual(
            members,
            {
                "UP": "up",
                "DOWN": "down",
                "DOWN_ALL": "down_all",
                "INACTIVE": "inactive",
                "ERROR": "error",
            },
        )

    # ── ShieldConfig ─────────────────────────────────────

    def test_shield_config_fields(self):
        """ShieldConfig has the expected fields with correct defaults."""
        names = [f.name for f in dataclasses.fields(ShieldConfig)]
        self.assertEqual(
            names,
            [
                "state_dir",
                "mode",
                "default_profiles",
                "loopback_ports",
                "audit_enabled",
                "profiles_dir",
            ],
        )

        with tempfile.TemporaryDirectory() as tmp:
            cfg = ShieldConfig(state_dir=Path(tmp))
            self.assertEqual(cfg.mode, ShieldMode.HOOK)
            self.assertEqual(cfg.default_profiles, ("dev-standard",))
            self.assertEqual(cfg.loopback_ports, ())
            self.assertIs(cfg.audit_enabled, True)
            self.assertIsNone(cfg.profiles_dir)

    def test_shield_config_frozen(self):
        """ShieldConfig is frozen — assignment raises FrozenInstanceError."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = ShieldConfig(state_dir=Path(tmp))
            with self.assertRaises(dataclasses.FrozenInstanceError):
                cfg.mode = ShieldMode.HOOK  # type: ignore[misc]

    # ── ExecError ────────────────────────────────────────

    def test_exec_error_attributes(self):
        """ExecError stores cmd, rc, stderr and is an Exception."""
        err = ExecError(["nft"], 1, "err")
        self.assertEqual(err.cmd, ["nft"])
        self.assertEqual(err.rc, 1)
        self.assertEqual(err.stderr, "err")
        self.assertIsInstance(err, Exception)

    # ── py.typed marker ──────────────────────────────────

    def test_py_typed_marker(self):
        """PEP 561 py.typed marker exists in the package directory."""
        pkg_dir = Path(terok_shield.__file__).parent
        self.assertTrue((pkg_dir / "py.typed").exists())
