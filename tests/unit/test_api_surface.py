# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""API surface snapshot tests.

Asserts the exact public API shape so accidental breakage is caught
immediately when terok starts depending on terok-shield.
"""

import dataclasses
import inspect
import unittest
from collections.abc import Iterator
from pathlib import Path

import terok_shield
from terok_shield import ExecError, ShieldConfig, ShieldMode

EXPECTED_ALL = [
    "ExecError",
    "ShieldConfig",
    "ShieldMode",
    "list_log_files",
    "list_profiles",
    "load_shield_config",
    "log_event",
    "shield_allow",
    "shield_deny",
    "shield_pre_start",
    "shield_resolve",
    "shield_rules",
    "shield_setup",
    "shield_status",
    "tail_log",
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

    # ── ShieldConfig ─────────────────────────────────────

    def test_shield_config_fields(self):
        """ShieldConfig has the expected fields with correct defaults."""
        names = {f.name for f in dataclasses.fields(ShieldConfig)}
        self.assertEqual(
            names,
            {"mode", "default_profiles", "loopback_ports", "audit_enabled", "audit_log_allowed"},
        )

        cfg = ShieldConfig()
        self.assertEqual(cfg.mode, ShieldMode.HOOK)
        self.assertEqual(cfg.default_profiles, ("dev-standard",))
        self.assertEqual(cfg.loopback_ports, ())
        self.assertIs(cfg.audit_enabled, True)
        self.assertIs(cfg.audit_log_allowed, True)

    def test_shield_config_frozen(self):
        """ShieldConfig is frozen — assignment raises FrozenInstanceError."""
        cfg = ShieldConfig()
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

    # ── Function signatures ──────────────────────────────

    def _assert_sig(self, fn, expected_params, expected_return):
        """Assert a function's parameter names/kinds/defaults/annotations and return annotation.

        Args:
            fn: The callable to inspect.
            expected_params: List of (name, kind, default, annotation) tuples.
                Use inspect.Parameter.empty for no default or annotation.
            expected_return: Expected return annotation.
        """
        sig = inspect.signature(fn)
        params = list(sig.parameters.values())
        self.assertEqual(len(params), len(expected_params), f"{fn.__name__}: param count mismatch")
        for param, (exp_name, exp_kind, exp_default, exp_ann) in zip(
            params, expected_params, strict=True
        ):
            self.assertEqual(param.name, exp_name, f"{fn.__name__}.{exp_name}: name")
            self.assertEqual(param.kind, exp_kind, f"{fn.__name__}.{exp_name}: kind")
            self.assertEqual(param.default, exp_default, f"{fn.__name__}.{exp_name}: default")
            self.assertEqual(param.annotation, exp_ann, f"{fn.__name__}.{exp_name}: annotation")
        self.assertEqual(sig.return_annotation, expected_return, f"{fn.__name__}: return")

    def test_function_signatures(self):
        """Public function signatures match the expected API contract."""
        POS = inspect.Parameter.POSITIONAL_OR_KEYWORD
        KW = inspect.Parameter.KEYWORD_ONLY
        empty = inspect.Parameter.empty

        cfg_or_none = ShieldConfig | None
        str_list_or_none = list[str] | None
        str_or_none = str | None

        cases = [
            (
                terok_shield.shield_setup,
                [("config", KW, None, cfg_or_none)],
                None,
            ),
            (
                terok_shield.shield_status,
                [("config", KW, None, cfg_or_none)],
                dict,
            ),
            (
                terok_shield.shield_pre_start,
                [
                    ("container", POS, empty, str),
                    ("profiles", POS, None, str_list_or_none),
                    ("config", KW, None, cfg_or_none),
                ],
                list[str],
            ),
            (
                terok_shield.shield_allow,
                [
                    ("container", POS, empty, str),
                    ("target", POS, empty, str),
                    ("config", KW, None, cfg_or_none),
                ],
                list[str],
            ),
            (
                terok_shield.shield_deny,
                [
                    ("container", POS, empty, str),
                    ("target", POS, empty, str),
                    ("config", KW, None, cfg_or_none),
                ],
                list[str],
            ),
            (
                terok_shield.shield_rules,
                [
                    ("container", POS, empty, str),
                    ("config", KW, None, cfg_or_none),
                ],
                str,
            ),
            (
                terok_shield.shield_resolve,
                [
                    ("container", POS, empty, str),
                    ("profiles", POS, None, str_list_or_none),
                    ("config", KW, None, cfg_or_none),
                    ("force", KW, False, bool),
                ],
                list[str],
            ),
            (
                terok_shield.list_log_files,
                [],
                list[str],
            ),
            (
                terok_shield.list_profiles,
                [],
                list[str],
            ),
            (
                terok_shield.load_shield_config,
                [],
                ShieldConfig,
            ),
            (
                terok_shield.log_event,
                [
                    ("container", POS, empty, str),
                    ("action", POS, empty, str),
                    ("dest", KW, None, str_or_none),
                    ("detail", KW, None, str_or_none),
                ],
                None,
            ),
            (
                terok_shield.tail_log,
                [
                    ("container", POS, empty, str),
                    ("n", POS, 50, int),
                ],
                Iterator[dict],
            ),
        ]

        for fn, expected_params, expected_return in cases:
            with self.subTest(fn=fn.__name__):
                self._assert_sig(fn, expected_params, expected_return)

    # ── py.typed marker ──────────────────────────────────

    def test_py_typed_marker(self):
        """PEP 561 py.typed marker exists in the package directory."""
        pkg_dir = Path(terok_shield.__file__).parent
        self.assertTrue((pkg_dir / "py.typed").exists())
