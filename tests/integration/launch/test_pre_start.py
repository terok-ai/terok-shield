# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: Shield.pre_start and firewall application."""

from pathlib import Path

import pytest

from terok_shield import Shield, ShieldConfig, state

from ..conftest import nft_missing, podman_missing
from ..helpers import assert_ruleset_applied

# -- Shield.pre_start -----------------------------------------


@pytest.mark.needs_podman
@podman_missing
@nft_missing
class TestShieldPreStart:
    """Verify ``Shield.pre_start()`` returns correct podman args."""

    def test_pre_start_returns_podman_args(self, shield_env: Path) -> None:
        """Returned args contain ``--hooks-dir``, ``--annotation``, ``--cap-drop``."""
        sd = shield_env / "containers" / "test-container"
        shield = Shield(ShieldConfig(state_dir=sd))
        args = shield.pre_start("test-container")

        assert "--hooks-dir" in args
        assert "--annotation" in args
        assert "--cap-drop" in args
        assert "--security-opt" in args

    @pytest.mark.needs_internet
    def test_pre_start_resolves_dns(self, shield_env: Path) -> None:
        """The profile.allowed file is created after ``Shield.pre_start()``."""
        sd = shield_env / "containers" / "dns-test-ctr"
        shield = Shield(ShieldConfig(state_dir=sd))
        shield.pre_start("dns-test-ctr")

        allowed = state.profile_allowed_path(sd)
        assert allowed.is_file(), "profile.allowed should be created"
        assert allowed.stat().st_size > 0, "profile.allowed should have content"


# -- Firewall applied via public API lifecycle ----------------


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestFirewallApplied:
    """Verify firewall rules are applied after the public API lifecycle."""

    def test_firewall_applied_via_hook(self, shielded_container: str) -> None:
        """A container started via the public API has firewall rules applied."""
        assert_ruleset_applied(shielded_container)
