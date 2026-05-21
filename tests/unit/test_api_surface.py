# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""API surface snapshot tests.

Asserts the exact public API shape so accidental breakage is caught
immediately when terok starts depending on terok-shield.
"""

import dataclasses
from pathlib import Path

import pytest

import terok_shield
from terok_shield import (
    DigNotFoundError,
    ExecError,
    NftNotFoundError,
    ShieldConfig,
    ShieldMode,
    ShieldRuntime,
    ShieldState,
)

EXPECTED_ALL = [
    "ArgDef",
    "AuditFileConfig",
    "AuditLogger",
    "BinaryCheck",
    "COMMANDS",
    "CommandDef",
    "CommandRunner",
    "DigNotFoundError",
    "DnsResolver",
    "DnsTier",
    "EnvironmentCheck",
    "ExecError",
    "HOOK_ENTRYPOINT_NAME",
    "NftNotFoundError",
    "ProfileLoader",
    "RulesetBuilder",
    "Shield",
    "ShieldConfig",
    "ShieldFileConfig",
    "ShieldMode",
    "ShieldNeedsSetup",
    "ShieldRuntime",
    "ShieldState",
    "SubprocessRunner",
    "USER_HOOKS_DIR",
    "check_firewall_binaries",
    "check_krun_binaries",
    "ensure_containers_conf_hooks_dir",
    "reader_script_path",
    "setup_global_hooks",
    "system_hooks_dir",
]


class TestAPISurface:
    """Snapshot tests for the terok-shield public API."""

    # ── __all__ ──────────────────────────────────────────

    def test_all_exports(self):
        """__all__ contains exactly the expected public names."""
        assert sorted(terok_shield.__all__) == EXPECTED_ALL

    # ── ShieldMode ───────────────────────────────────────

    def test_shield_mode_members(self):
        """ShieldMode has exactly HOOK."""
        members = {m.name: m.value for m in ShieldMode}
        assert members == {"HOOK": "hook"}

    def test_shield_state_members(self):
        """ShieldState has QUARANTINE, UP, DOWN, DISENGAGED, OFFLINE, ERROR."""
        members = {m.name: m.value for m in ShieldState}
        assert members == {
            "QUARANTINE": "quarantine",
            "UP": "up",
            "DOWN": "down",
            "DISENGAGED": "disengaged",
            "OFFLINE": "offline",
            "ERROR": "error",
        }

    # ── ShieldRuntime ─────────────────────────────────────

    def test_shield_runtime_members(self):
        """ShieldRuntime has DEFAULT and KRUN."""
        members = {m.name: m.value for m in ShieldRuntime}
        assert members == {"DEFAULT": "default", "KRUN": "krun"}

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            pytest.param("krun", ShieldRuntime.KRUN, id="krun"),
            pytest.param("crun", ShieldRuntime.DEFAULT, id="crun"),
            pytest.param(None, ShieldRuntime.DEFAULT, id="none"),
            pytest.param("", ShieldRuntime.DEFAULT, id="empty"),
            pytest.param("unknown-runtime", ShieldRuntime.DEFAULT, id="unknown"),
        ],
    )
    def test_shield_runtime_from_name(self, name, expected):
        """`from_runtime_name` recognises ``krun`` and otherwise returns DEFAULT.

        Default is the safe assumption — every runtime shield has been tested
        against besides krun shares the netns loopback with the container.
        """
        assert ShieldRuntime.from_runtime_name(name) is expected

    # ── ShieldConfig ─────────────────────────────────────

    def test_shield_config_fields(self, make_config):
        """ShieldConfig has the expected fields with correct defaults."""
        names = [f.name for f in dataclasses.fields(ShieldConfig)]
        assert names == [
            "state_dir",
            "mode",
            "default_profiles",
            "loopback_ports",
            "audit_enabled",
            "profiles_dir",
            "runtime",
        ]

        cfg = make_config()
        assert cfg.mode == ShieldMode.HOOK
        assert cfg.default_profiles == ("dev-standard",)
        assert cfg.loopback_ports == ()
        assert cfg.audit_enabled is True
        assert cfg.profiles_dir is None
        assert cfg.runtime == ShieldRuntime.DEFAULT

    def test_shield_config_frozen(self, make_config):
        """ShieldConfig is frozen — assignment raises FrozenInstanceError."""
        cfg = make_config()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.mode = ShieldMode.HOOK  # type: ignore[misc]

    # ── NftNotFoundError ──────────────────────────────────

    def test_nft_not_found_error_is_runtime_error(self):
        """NftNotFoundError is a RuntimeError subclass for backwards compat."""
        err = NftNotFoundError("nft missing")
        assert isinstance(err, RuntimeError)

    # ── DigNotFoundError ─────────────────────────────────

    def test_dig_not_found_error_is_runtime_error(self):
        """DigNotFoundError is a RuntimeError subclass."""
        err = DigNotFoundError("dig missing")
        assert isinstance(err, RuntimeError)

    # ── ExecError ────────────────────────────────────────

    def test_exec_error_attributes(self):
        """ExecError stores cmd, rc, stderr and is an Exception."""
        err = ExecError(["nft"], 1, "err")
        assert err.cmd == ["nft"]
        assert err.rc == 1
        assert err.stderr == "err"
        assert isinstance(err, Exception)

    # ── py.typed marker ──────────────────────────────────

    def test_py_typed_marker(self):
        """PEP 561 py.typed marker exists in the package directory."""
        pkg_dir = Path(terok_shield.__file__).parent
        assert (pkg_dir / "py.typed").exists()
