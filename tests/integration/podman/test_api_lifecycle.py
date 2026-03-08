# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the terok-shield public API.

These tests exercise the public API surface (``shield_setup``,
``shield_pre_start``, ``shield_allow``, ``shield_deny``,
``shield_rules``, ``shield_resolve``, ``shield_status``) as users
and terok integrations will use them.

Run via: ``make test-podman``
"""

from pathlib import Path

import pytest

from terok_shield import (
    ShieldConfig,
    shield_allow,
    shield_deny,
    shield_pre_start,
    shield_rules,
    shield_setup,
)
from tests.testnet import (
    ALLOWED_TARGET_HTTP,
    ALLOWED_TARGET_IPS,
    BLOCKED_TARGET_HTTP,
)

from .conftest import nft_missing, podman_missing
from .helpers import assert_blocked, assert_reachable, assert_ruleset_applied

# ── shield_setup ─────────────────────────────────────────


@pytest.mark.needs_podman
@podman_missing
@nft_missing
class TestShieldSetup:
    """Verify ``shield_setup()`` installs OCI hook files."""

    def test_setup_creates_hook_files(self, shield_env: Path) -> None:
        """Hook JSON and entrypoint script exist after ``shield_setup()``."""
        cfg = ShieldConfig()
        shield_setup(config=cfg)

        hooks_dir = shield_env / "hooks"
        assert (hooks_dir / "terok-shield-hook.json").is_file()
        entrypoint = shield_env / "terok-shield-hook"
        assert entrypoint.is_file()
        assert entrypoint.stat().st_mode & 0o100, "Entrypoint must be executable"

    def test_setup_idempotent(self, shield_env: Path) -> None:
        """Calling ``shield_setup()`` twice does not break anything."""
        cfg = ShieldConfig()
        shield_setup(config=cfg)
        shield_setup(config=cfg)

        hooks_dir = shield_env / "hooks"
        assert (hooks_dir / "terok-shield-hook.json").is_file()


# ── shield_pre_start ─────────────────────────────────────


@pytest.mark.needs_podman
@podman_missing
@nft_missing
class TestShieldPreStart:
    """Verify ``shield_pre_start()`` returns correct podman args."""

    def test_pre_start_returns_podman_args(self, shield_env: Path) -> None:
        """Returned args contain ``--hooks-dir``, ``--annotation``, ``--cap-drop``."""
        cfg = ShieldConfig()
        shield_setup(config=cfg)
        args = shield_pre_start("test-container", config=cfg)

        assert "--hooks-dir" in args
        assert "--annotation" in args
        assert "--cap-drop" in args
        assert "--security-opt" in args

    def test_pre_start_without_setup_raises(self, shield_env: Path) -> None:
        """Calling ``shield_pre_start()`` before setup raises ``RuntimeError``."""
        cfg = ShieldConfig()
        with pytest.raises(RuntimeError, match="hook not installed"):
            shield_pre_start("test-container", config=cfg)

    @pytest.mark.needs_internet
    def test_pre_start_resolves_dns(self, shield_env: Path) -> None:
        """The resolved cache file is created after ``shield_pre_start()``."""
        cfg = ShieldConfig()
        shield_setup(config=cfg)
        shield_pre_start("dns-test-ctr", config=cfg)

        resolved_dir = shield_env / "resolved"
        assert resolved_dir.is_dir()
        cache_files = list(resolved_dir.iterdir())
        assert len(cache_files) > 0, "At least one resolved cache file should be created"


# ── shield lifecycle (with real container) ───────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestShieldLifecycle:
    """End-to-end tests using the public API with a real container."""

    def test_firewall_applied_via_hook(self, shielded_container: str) -> None:
        """A container started via the public API has firewall rules applied."""
        assert_ruleset_applied(shielded_container)

    def test_traffic_blocked_by_default(self, shielded_container: str) -> None:
        """Outbound traffic is blocked after the public API lifecycle."""
        assert_blocked(shielded_container, BLOCKED_TARGET_HTTP)

    def test_shield_allow_ip(self, shielded_container: str) -> None:
        """``shield_allow()`` with an IP makes it reachable."""
        allowed = shield_allow(shielded_container, ALLOWED_TARGET_IPS[0])
        assert ALLOWED_TARGET_IPS[0] in allowed

        # Allow both Cloudflare IPs (anycast pair)
        shield_allow(shielded_container, ALLOWED_TARGET_IPS[1])
        assert_reachable(shielded_container, ALLOWED_TARGET_HTTP)

    def test_shield_allow_deny_cycle(self, shielded_container: str) -> None:
        """``shield_allow()`` then ``shield_deny()`` blocks IP again."""
        for ip in ALLOWED_TARGET_IPS:
            shield_allow(shielded_container, ip)
        assert_reachable(shielded_container, ALLOWED_TARGET_HTTP)

        for ip in ALLOWED_TARGET_IPS:
            shield_deny(shielded_container, ip)
        assert_blocked(shielded_container, ALLOWED_TARGET_HTTP)

    def test_shield_rules_returns_ruleset(self, shielded_container: str) -> None:
        """``shield_rules()`` returns text containing ``terok_shield``."""
        rules = shield_rules(shielded_container)
        assert "terok_shield" in rules
        assert "allow_v4" in rules
