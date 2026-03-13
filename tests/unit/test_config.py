# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for shield configuration."""

import dataclasses
from pathlib import Path

import pytest

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
