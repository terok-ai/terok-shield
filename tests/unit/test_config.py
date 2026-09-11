# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for shield configuration."""

import dataclasses
from pathlib import Path

import pytest
from pydantic import ValidationError

from terok_shield.config import (
    ANNOTATION_KEY,
    ANNOTATION_NAME_KEY,
    ANNOTATION_STATE_DIR_KEY,
    ANNOTATION_VERSION_KEY,
    DnsTier,
    ShieldConfig,
    ShieldMode,
    ShieldState,
    detect_dns_tier,
)
from terok_shield.config_file import AuditFileConfig, ShieldFileConfig


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
        assert cfg.default_profiles == ()
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
            "QUARANTINE": "quarantine",
            "UP": "up",
            "DOWN": "down",
            "DISENGAGED": "disengaged",
            "OFFLINE": "offline",
            "ERROR": "error",
        }


class TestAnnotationConstants:
    """Tests for annotation key constants."""

    def test_annotation_keys_exist(self) -> None:
        """All annotation key constants are defined."""
        assert ANNOTATION_KEY == "terok.shield.profiles"
        assert ANNOTATION_NAME_KEY == "terok.shield.name"
        assert ANNOTATION_STATE_DIR_KEY == "terok.shield.state_dir"
        assert ANNOTATION_VERSION_KEY == "terok.shield.version"


# ── ShieldFileConfig (Pydantic) ─────────────────────────


class TestShieldFileConfigDefaults:
    """Default values when no fields are provided."""

    def test_all_defaults(self) -> None:
        """Empty config produces sane defaults."""
        cfg = ShieldFileConfig()
        assert cfg.mode == "auto"
        assert cfg.default_profiles == []
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
            audit=AuditFileConfig(enabled=False),
        )
        assert cfg.mode == "hook"
        assert cfg.default_profiles == ["base", "dev-python"]
        assert cfg.audit.enabled is False


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

    def test_loopback_ports_rejected(self) -> None:
        """``loopback_ports`` is per-container state (state bundle), not config — reject if seen."""
        with pytest.raises(ValidationError, match="loopback_ports"):
            ShieldFileConfig(loopback_ports=[8080])  # type: ignore[call-arg]


class TestShieldFileConfigProfileValidation:
    """Profile list enforcement."""

    def test_empty_profile_name_rejected(self) -> None:
        """Empty strings in profile list are rejected."""
        with pytest.raises(ValidationError, match="non-empty"):
            ShieldFileConfig(default_profiles=["valid", ""])

    def test_empty_list_accepted(self) -> None:
        """An empty profile list names no profile."""
        assert ShieldFileConfig(default_profiles=[]).default_profiles == []

    @pytest.mark.parametrize(
        "profiles",
        [
            pytest.param([1], id="int"),
            pytest.param([None], id="none"),
        ],
    )
    def test_invalid_profile_name_rejected(self, profiles: list[object]) -> None:
        """A profile name that is not a string is rejected."""
        with pytest.raises(ValidationError):
            ShieldFileConfig(default_profiles=profiles)  # type: ignore[arg-type]


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


class TestDnsTierDetection:
    """The tier ladder: dnsmasq with nftset, dnsmasq without it, a lookup tool, getent."""

    def test_dnsmasq_with_nftset_is_the_live_tier(self) -> None:
        tier = detect_dns_tier(lambda _name: True, dnsmasq_usable=True, nftset=True)
        assert tier is DnsTier.DNSMASQ_LIVE

    def test_dnsmasq_without_nftset_still_runs_but_resolves_once(self) -> None:
        tier = detect_dns_tier(lambda _name: True, dnsmasq_usable=True, nftset=False)
        assert tier is DnsTier.DNSMASQ_STATIC
        assert tier.runs_dnsmasq
        assert not tier.live

    def test_drill_alone_selects_the_lookup_tier(self) -> None:
        assert detect_dns_tier(lambda name: name == "drill") is DnsTier.LOOKUP

    def test_no_tool_falls_through_to_getent(self) -> None:
        assert detect_dns_tier(lambda name: False) is DnsTier.GETENT


class TestDnsTierNames:
    """A recorded name reads back as a tier, retired names included."""

    @pytest.mark.parametrize(
        ("recorded", "tier"),
        [("dig", DnsTier.LOOKUP), ("dnsmasq", DnsTier.DNSMASQ_LIVE)],
    )
    def test_a_retired_name_reads_as_the_tier_it_named(self, recorded: str, tier: DnsTier) -> None:
        assert DnsTier.parse(recorded) is tier

    def test_a_name_that_is_not_a_tier_reads_as_none(self) -> None:
        assert DnsTier.parse("bogus") is None
