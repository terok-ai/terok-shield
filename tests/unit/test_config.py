# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for shield configuration."""

import dataclasses
import tempfile
import unittest
from pathlib import Path

from terok_shield.config import (
    ANNOTATION_KEY,
    ANNOTATION_LOOPBACK_PORTS_KEY,
    ANNOTATION_NAME_KEY,
    ANNOTATION_STATE_DIR_KEY,
    ANNOTATION_VERSION_KEY,
    ShieldConfig,
    ShieldMode,
    ShieldState,
)


class TestShieldConfig(unittest.TestCase):
    """Tests for ShieldConfig dataclass."""

    def test_requires_state_dir(self) -> None:
        """ShieldConfig requires state_dir argument."""
        with self.assertRaises(TypeError):
            ShieldConfig()  # type: ignore[call-arg]

    def test_minimal_construction(self) -> None:
        """Construct with only state_dir."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = ShieldConfig(state_dir=Path(tmp))
            self.assertEqual(cfg.state_dir, Path(tmp))
            self.assertEqual(cfg.mode, ShieldMode.HOOK)
            self.assertEqual(cfg.default_profiles, ("dev-standard",))
            self.assertEqual(cfg.loopback_ports, ())
            self.assertTrue(cfg.audit_enabled)
            self.assertIsNone(cfg.profiles_dir)

    def test_full_construction(self) -> None:
        """Construct with all fields specified."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = ShieldConfig(
                state_dir=Path(tmp),
                mode=ShieldMode.HOOK,
                default_profiles=("base",),
                loopback_ports=(8080,),
                audit_enabled=False,
                profiles_dir=Path(tmp) / "profiles",
            )
            self.assertEqual(cfg.loopback_ports, (8080,))
            self.assertFalse(cfg.audit_enabled)
            self.assertEqual(cfg.profiles_dir, Path(tmp) / "profiles")

    def test_default_profiles_immutable(self) -> None:
        """Default profiles tuple cannot be mutated."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = ShieldConfig(state_dir=Path(tmp))
            self.assertIsInstance(cfg.default_profiles, tuple)

    def test_frozen(self) -> None:
        """Config is immutable."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = ShieldConfig(state_dir=Path(tmp))
            with self.assertRaises(dataclasses.FrozenInstanceError):
                cfg.mode = ShieldMode.HOOK  # type: ignore[misc]

    def test_state_dir_is_first_field(self) -> None:
        """state_dir is the first field (required, positional)."""
        fields = [f.name for f in dataclasses.fields(ShieldConfig)]
        self.assertEqual(fields[0], "state_dir")


class TestShieldMode(unittest.TestCase):
    """Tests for ShieldMode enum."""

    def test_hook_member(self) -> None:
        """ShieldMode has HOOK member."""
        self.assertEqual(ShieldMode.HOOK.value, "hook")


class TestShieldState(unittest.TestCase):
    """Tests for ShieldState enum."""

    def test_members(self) -> None:
        """ShieldState has all expected members."""
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


class TestAnnotationConstants(unittest.TestCase):
    """Tests for annotation key constants."""

    def test_annotation_keys_exist(self) -> None:
        """All annotation key constants are defined."""
        self.assertEqual(ANNOTATION_KEY, "terok.shield.profiles")
        self.assertEqual(ANNOTATION_NAME_KEY, "terok.shield.name")
        self.assertEqual(ANNOTATION_STATE_DIR_KEY, "terok.shield.state_dir")
        self.assertEqual(ANNOTATION_LOOPBACK_PORTS_KEY, "terok.shield.loopback_ports")
        self.assertEqual(ANNOTATION_VERSION_KEY, "terok.shield.version")
