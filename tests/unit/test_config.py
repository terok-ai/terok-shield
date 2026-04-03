# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for shield configuration."""

import dataclasses
from pathlib import Path

import pytest
from pydantic import ValidationError

from terok_shield.config import (
    ANNOTATION_KEY,
    ANNOTATION_LOOPBACK_PORTS_KEY,
    ANNOTATION_NAME_KEY,
    ANNOTATION_STATE_DIR_KEY,
    ANNOTATION_VERSION_KEY,
    AuditFileConfig,
    ShieldConfig,
    ShieldFileConfig,
    ShieldMode,
    ShieldState,
)


class TestShieldConfig:
    """Tests for ShieldConfig dataclass."""

    def test_requires_state_dir(self) -> None:
        """ShieldConfig requires state_dir argument."""
        with pytest.raises(TypeError):
            ShieldConfig()  # type: ignore[call-arg]

    def test_minimal_construction(self, make_config, state_dir: Path) -> None:
        """Construct with only state_dir."""
        cfg = make_config()
        assert cfg.state_dir == state_dir
        assert cfg.mode == ShieldMode.HOOK
        assert cfg.default_profiles == ("dev-standard",)
        assert cfg.loopback_ports == ()
        assert cfg.audit_enabled
        assert cfg.profiles_dir is None

    def test_full_construction(self, make_config, state_dir: Path) -> None:
        """Construct with all fields specified."""
        cfg = make_config(
            mode=ShieldMode.HOOK,
            default_profiles=("base",),
            loopback_ports=(8080,),
            audit_enabled=False,
            profiles_dir=state_dir / "profiles",
        )
        assert cfg.loopback_ports == (8080,)
        assert not cfg.audit_enabled
        assert cfg.profiles_dir == state_dir / "profiles"

    def test_default_profiles_immutable(self, make_config) -> None:
        """Default profiles tuple cannot be mutated."""
        assert isinstance(make_config().default_profiles, tuple)

    def test_frozen(self, make_config) -> None:
        """Config is immutable."""
        cfg = make_config()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.mode = ShieldMode.HOOK  # type: ignore[misc]

    def test_state_dir_is_first_field(self) -> None:
        """state_dir is the first field (required, positional)."""
        fields = [f.name for f in dataclasses.fields(ShieldConfig)]
        assert fields[0] == "state_dir"


class TestShieldMode:
    """Tests for ShieldMode enum."""

    def test_hook_member(self) -> None:
        """ShieldMode has HOOK member."""
        assert ShieldMode.HOOK.value == "hook"


class TestShieldState:
    """Tests for ShieldState enum."""

    def test_members(self) -> None:
        """ShieldState has all expected members."""
        members = {m.name: m.value for m in ShieldState}
        assert members == {
            "UP": "up",
            "DOWN": "down",
            "DOWN_ALL": "down_all",
            "INACTIVE": "inactive",
            "ERROR": "error",
        }


class TestAnnotationConstants:
    """Tests for annotation key constants."""

    def test_annotation_keys_exist(self) -> None:
        """All annotation key constants are defined."""
        assert ANNOTATION_KEY == "terok.shield.profiles"
        assert ANNOTATION_NAME_KEY == "terok.shield.name"
        assert ANNOTATION_STATE_DIR_KEY == "terok.shield.state_dir"
        assert ANNOTATION_LOOPBACK_PORTS_KEY == "terok.shield.loopback_ports"
        assert ANNOTATION_VERSION_KEY == "terok.shield.version"


# ── ShieldFileConfig (Pydantic) ─────────────────────────


class TestShieldFileConfigDefaults:
    """Default values when no fields are provided."""

    def test_all_defaults(self) -> None:
        """Empty config produces sane defaults."""
        cfg = ShieldFileConfig()
        assert cfg.mode == "auto"
        assert cfg.default_profiles == ["dev-standard"]
        assert cfg.loopback_ports == []
        assert cfg.audit.enabled is True

    def test_audit_defaults(self) -> None:
        """AuditFileConfig defaults to enabled."""
        assert AuditFileConfig().enabled is True


class TestShieldFileConfigValid:
    """Valid configurations are accepted."""

    def test_full_config(self) -> None:
        """All fields set explicitly."""
        cfg = ShieldFileConfig(
            mode="hook",
            default_profiles=["base", "dev-python"],
            loopback_ports=[8080, 9090],
            audit=AuditFileConfig(enabled=False),
        )
        assert cfg.mode == "hook"
        assert cfg.default_profiles == ["base", "dev-python"]
        assert cfg.loopback_ports == [8080, 9090]
        assert cfg.audit.enabled is False

    def test_single_port_int_coerced_to_list(self) -> None:
        """A bare integer is accepted and wrapped in a list."""
        cfg = ShieldFileConfig(loopback_ports=1234)
        assert cfg.loopback_ports == [1234]

    def test_boundary_ports(self) -> None:
        """Port 1 and 65535 are both valid."""
        cfg = ShieldFileConfig(loopback_ports=[1, 65535])
        assert cfg.loopback_ports == [1, 65535]


class TestShieldFileConfigUnknownKeys:
    """extra='forbid' catches typos."""

    def test_typo_in_top_level_key(self) -> None:
        """Unknown top-level key is rejected."""
        with pytest.raises(ValidationError, match="mod"):
            ShieldFileConfig(mod="hook")  # type: ignore[call-arg]

    def test_typo_in_audit_key(self) -> None:
        """Unknown key in audit section is rejected."""
        with pytest.raises(ValidationError, match="enbled"):
            ShieldFileConfig(audit={"enbled": True})  # type: ignore[arg-type]


class TestShieldFileConfigPortValidation:
    """Port range and type enforcement."""

    def test_port_zero_rejected(self) -> None:
        """Port 0 is out of range."""
        with pytest.raises(ValidationError, match="out of range"):
            ShieldFileConfig(loopback_ports=[0])

    def test_port_too_high_rejected(self) -> None:
        """Port above 65535 is rejected."""
        with pytest.raises(ValidationError, match="out of range"):
            ShieldFileConfig(loopback_ports=[99999])

    def test_bool_in_ports_rejected(self) -> None:
        """Booleans in port list are rejected (not silently coerced to 0/1)."""
        with pytest.raises(ValidationError, match="bool"):
            ShieldFileConfig(loopback_ports=[True])

    def test_bare_bool_rejected(self) -> None:
        """A bare boolean instead of a list is rejected."""
        with pytest.raises(ValidationError, match="bool"):
            ShieldFileConfig(loopback_ports=True)

    def test_string_rejected(self) -> None:
        """A string instead of a port list is rejected."""
        with pytest.raises(ValidationError, match="expected list"):
            ShieldFileConfig(loopback_ports="not-a-list")


class TestShieldFileConfigProfileValidation:
    """Profile list enforcement."""

    def test_empty_profile_name_rejected(self) -> None:
        """Empty strings in profile list are rejected."""
        with pytest.raises(ValidationError, match="non-empty"):
            ShieldFileConfig(default_profiles=["valid", ""])

    def test_empty_list_rejected(self) -> None:
        """An empty profile list is rejected."""
        with pytest.raises(ValidationError, match="non-empty"):
            ShieldFileConfig(default_profiles=[])


class TestShieldFileConfigModeValidation:
    """Mode literal enforcement."""

    def test_invalid_mode_rejected(self) -> None:
        """Modes outside the literal union are rejected."""
        with pytest.raises(ValidationError, match="bridge"):
            ShieldFileConfig(mode="bridge")  # type: ignore[arg-type]


class TestShieldFileConfigAuditValidation:
    """Nested audit section validation."""

    def test_non_bool_enabled_rejected(self) -> None:
        """audit.enabled must be a boolean."""
        with pytest.raises(ValidationError):
            ShieldFileConfig(audit={"enabled": "yes-please"})  # type: ignore[arg-type]
