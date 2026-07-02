# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: shield state detection with real containers.

Verifies ``Shield.state()`` correctly classifies live nft rulesets
as UP, DOWN, DISENGAGED, or OFFLINE by querying actual container
network namespaces.
"""

import uuid

import pytest

from terok_shield import ShieldState

from ..conftest import nft_missing, podman_missing
from ..helpers import disposable_shield as _shield


@pytest.mark.needs_podman
@pytest.mark.needs_hooks
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestShieldState:
    """Verify Shield.state() returns correct states for live containers."""

    def test_state_up_after_setup(self, shielded_container: str) -> None:
        """A freshly shielded container reports state UP."""
        assert _shield().state(shielded_container) == ShieldState.UP

    def test_state_down_after_shield_down(self, shielded_container: str) -> None:
        """State is DOWN after shield.down() (RFC1918 protection kept)."""
        shield = _shield()
        shield.down(shielded_container, shielded_container.id)
        assert shield.state(shielded_container) == ShieldState.DOWN

    def test_state_disengaged_after_shield_disengaged(self, shielded_container: str) -> None:
        """State is DISENGAGED after shield.down(allow_all=True)."""
        shield = _shield()
        shield.down(shielded_container, shielded_container.id, allow_all=True)
        assert shield.state(shielded_container) == ShieldState.DISENGAGED

    def test_state_up_after_shield_up(self, shielded_container: str) -> None:
        """State returns to UP after shield.down() then shield.up()."""
        shield = _shield()
        shield.down(shielded_container, shielded_container.id)
        assert shield.state(shielded_container) == ShieldState.DOWN

        shield.up(shielded_container, shielded_container.id)
        assert shield.state(shielded_container) == ShieldState.UP


@pytest.mark.needs_podman
@podman_missing
@nft_missing
class TestShieldStateInactive:
    """Verify OFFLINE state for containers without rulesets."""

    def test_state_offline_for_stopped_container(self) -> None:
        """A nonexistent/stopped container reports OFFLINE."""
        bogus = f"nonexistent-{uuid.uuid4().hex[:12]}"
        assert _shield().state(bogus) == ShieldState.OFFLINE

    def test_state_offline_for_bare_container(self, container: str) -> None:
        """A running container with no shield ruleset reports OFFLINE."""
        assert _shield().state(container) == ShieldState.OFFLINE
