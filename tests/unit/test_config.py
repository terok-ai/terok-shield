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
    ShieldConfig,
    ShieldMode,
    ShieldState,
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
        assert cfg.default_profiles == ["dev-standard"]
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


class TestLookupTierDetection:
    """The lookup tier accepts either one-shot resolver."""

    def test_drill_alone_selects_the_lookup_tier(self) -> None:
        """With the proxy off, the one-shot tools are what is left."""
        from terok_shield.config import DnsTier, detect_dns_tier

        tier = detect_dns_tier(lambda name: name == "drill", proxy_enabled=False)
        assert tier is DnsTier.LOOKUP

    def test_no_tool_falls_through_to_getent(self) -> None:
        from terok_shield.config import DnsTier, detect_dns_tier

        assert detect_dns_tier(lambda name: False, proxy_enabled=False) is DnsTier.GETENT


class TestProxyTierDetection:
    """The proxy is ours, so it is a decision rather than a probe."""

    def test_a_host_without_dnsmasq_gets_the_proxy(self) -> None:
        """Default on: a rotation breaking a task mid-run is the worse default."""
        from terok_shield.config import DnsTier, detect_dns_tier

        assert detect_dns_tier(lambda name: name == "dig") is DnsTier.PROXY

    def test_dnsmasq_still_outranks_it(self) -> None:
        from terok_shield.config import DnsTier, detect_dns_tier

        assert detect_dns_tier(lambda _name: True) is DnsTier.DNSMASQ

    def test_a_named_tier_is_a_requirement(self) -> None:
        """An operator who names a tier gets it or gets an error, never less."""
        import pytest

        from terok_shield.config import DnsTierUnavailableError, detect_dns_tier

        with pytest.raises(DnsTierUnavailableError, match="dnsmasq"):
            detect_dns_tier(lambda _name: False, requested="dnsmasq")

    def test_a_named_tier_the_host_has_is_honoured(self) -> None:
        """Naming a weaker tier than the host could run is the operator's call."""
        from terok_shield.config import DnsTier, detect_dns_tier

        assert detect_dns_tier(lambda _name: True, requested="getent") is DnsTier.GETENT

    def test_an_unknown_tier_name_is_refused(self) -> None:
        import pytest

        from terok_shield.config import DnsTierUnavailableError, detect_dns_tier

        with pytest.raises(DnsTierUnavailableError, match="unknown"):
            detect_dns_tier(lambda _name: True, requested="nonesuch")

    def test_the_detail_names_what_the_proxy_resolves_with(self) -> None:
        """``proxy + dig`` and ``proxy + getent`` are not the same tier in practice."""
        from terok_shield.config import DnsTier, dns_tier_detail

        assert dns_tier_detail(DnsTier.PROXY, lambda name: name == "dig") == "proxy + dig"
        assert dns_tier_detail(DnsTier.PROXY, lambda _name: False) == "proxy + getent"
        assert dns_tier_detail(DnsTier.DNSMASQ, lambda _name: True) == "dnsmasq"

    def test_every_tier_can_be_read_back_from_a_bundle(self, tmp_path) -> None:
        """The state layer mirrors this enum by hand, and a drift is unrecoverable.

        A tier the reader does not know reads as "never launched", and
        the container recorded under it can never restart — it can only
        be re-created.
        """
        from terok_shield.config import DnsTier
        from terok_shield.state import StateBundle

        bundle = StateBundle(tmp_path)
        for tier in DnsTier:
            bundle.dns_tier.write_text(f"{tier.value}\n")
            assert bundle.read_dns_tier() == tier.value

    def test_only_the_answering_tiers_are_dynamic(self) -> None:
        """What follows from it: no static pre-resolution, and set entries expire."""
        from terok_shield.config import DnsTier

        assert DnsTier.DNSMASQ.is_dynamic and DnsTier.PROXY.is_dynamic
        assert not DnsTier.LOOKUP.is_dynamic and not DnsTier.GETENT.is_dynamic
