# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: full bypass lifecycle and edge cases.

Exercises every combination of state transitions a user might attempt,
verifying that the shield behaves predictably and safely at all times.
Each test checks both actual network behavior and state correctness.
"""

import os
import subprocess
from pathlib import Path

import pytest

from terok_shield import Shield, ShieldConfig, ShieldState
from tests.testnet import (
    ALLOWED_TARGET_HTTP,
    ALLOWED_TARGET_IPS,
    BLOCKED_TARGET_DNS_PORT,
    BLOCKED_TARGET_HTTP,
    BLOCKED_TARGET_IP,
)

from ..conftest import CTR_PREFIX, IMAGE, nft_missing, podman_missing
from ..helpers import assert_blocked, assert_connectable, assert_reachable, start_shielded_container


def _shield() -> Shield:
    return Shield(ShieldConfig())


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestBypassBasicLifecycle:
    """Basic down/up cycle with traffic verification."""

    def test_up_down_up_cycle(self, shielded_container: str) -> None:
        """Full cycle: UP -> DOWN -> UP with traffic checks at each step."""
        shield = _shield()
        # Initial state: UP, traffic blocked
        assert shield.state(shielded_container) == ShieldState.UP
        assert_blocked(shielded_container, BLOCKED_TARGET_HTTP)

        # Shield down: traffic allowed
        shield.down(shielded_container)
        assert shield.state(shielded_container) == ShieldState.DOWN
        assert_connectable(shielded_container, BLOCKED_TARGET_IP, BLOCKED_TARGET_DNS_PORT)

        # Shield up: traffic blocked again
        shield.up(shielded_container)
        assert shield.state(shielded_container) == ShieldState.UP
        assert_blocked(shielded_container, BLOCKED_TARGET_HTTP)

    def test_up_down_all_up_cycle(self, shielded_container: str) -> None:
        """Full cycle with allow_all: UP -> DOWN_ALL -> UP."""
        shield = _shield()
        shield.down(shielded_container, allow_all=True)
        assert shield.state(shielded_container) == ShieldState.DOWN_ALL

        rules = shield.rules(shielded_container)
        assert "policy accept" in rules
        assert_connectable(shielded_container, BLOCKED_TARGET_IP, BLOCKED_TARGET_DNS_PORT)

        shield.up(shielded_container)
        assert shield.state(shielded_container) == ShieldState.UP
        assert_blocked(shielded_container, BLOCKED_TARGET_HTTP)


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestBypassIdempotency:
    """Verify repeated operations are safe and idempotent."""

    def test_down_twice_stays_down(self, shielded_container: str) -> None:
        """Calling shield.down() twice does not break anything."""
        shield = _shield()
        shield.down(shielded_container)
        assert shield.state(shielded_container) == ShieldState.DOWN

        shield.down(shielded_container)
        assert shield.state(shielded_container) == ShieldState.DOWN
        assert_connectable(shielded_container, BLOCKED_TARGET_IP, BLOCKED_TARGET_DNS_PORT)

    def test_up_twice_stays_up(self, shielded_container: str) -> None:
        """Calling shield.up() on an already-UP container is safe."""
        shield = _shield()
        assert shield.state(shielded_container) == ShieldState.UP

        shield.up(shielded_container)
        assert shield.state(shielded_container) == ShieldState.UP
        assert_blocked(shielded_container, BLOCKED_TARGET_HTTP)

    def test_up_without_prior_down(self, shielded_container: str) -> None:
        """shield.up() on a freshly shielded container is a no-op."""
        shield = _shield()
        shield.up(shielded_container)
        assert shield.state(shielded_container) == ShieldState.UP
        assert_blocked(shielded_container, BLOCKED_TARGET_HTTP)


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestBypassModeSwitch:
    """Verify switching between bypass modes (DOWN <-> DOWN_ALL)."""

    def test_down_to_down_all(self, shielded_container: str) -> None:
        """Switch from protected bypass to full bypass."""
        shield = _shield()
        shield.down(shielded_container)
        assert shield.state(shielded_container) == ShieldState.DOWN

        shield.down(shielded_container, allow_all=True)
        assert shield.state(shielded_container) == ShieldState.DOWN_ALL

        # Private-range rules should be gone
        rules = shield.rules(shielded_container)
        assert "TEROK_SHIELD_PRIVATE" not in rules

    def test_down_all_to_down(self, shielded_container: str) -> None:
        """Switch from full bypass back to protected bypass."""
        shield = _shield()
        shield.down(shielded_container, allow_all=True)
        assert shield.state(shielded_container) == ShieldState.DOWN_ALL

        shield.down(shielded_container)
        assert shield.state(shielded_container) == ShieldState.DOWN

        # Private-range rules should be restored
        rules = shield.rules(shielded_container)
        assert "TEROK_SHIELD_PRIVATE" in rules


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestBypassWithAllowDeny:
    """Verify allow/deny interactions during bypass."""

    def test_allow_during_bypass_does_not_persist(self, shielded_container: str) -> None:
        """IPs added via allow during bypass are lost on shield.up().

        shield.up() atomically replaces the ruleset, so any runtime
        allow() calls during bypass do not survive the transition.
        Only cached IPs from the .resolved file are re-added.
        """
        shield = _shield()
        shield.down(shielded_container)

        # Add IP to allow set during bypass
        shield.allow(shielded_container, BLOCKED_TARGET_IP)

        # Restore shield — the runtime add is lost
        shield.up(shielded_container)

        # Verify the IP is not allowed
        assert_blocked(shielded_container, BLOCKED_TARGET_HTTP)

    def test_deny_during_bypass_has_no_traffic_effect(self, shielded_container: str) -> None:
        """Denying during bypass doesn't block traffic (policy is accept).

        In bypass mode the output chain policy is accept, so removing
        an IP from the allow set has no effect on traffic flow.
        """
        shield = _shield()
        shield.down(shielded_container)

        # Deny shouldn't affect traffic in bypass mode
        shield.deny(shielded_container, BLOCKED_TARGET_IP)
        assert_connectable(shielded_container, BLOCKED_TARGET_IP, BLOCKED_TARGET_DNS_PORT)


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestBypassIPRestoration:
    """Verify cached IPs are restored when going back up."""

    def test_cached_ips_restored_on_shield_up(self, shield_env: Path, _pull_image: None) -> None:
        """Pre-resolved IPs from .resolved cache are re-added on shield.up().

        Full lifecycle: setup -> pre_start (populates cache) -> run ->
        allow -> verify reachable -> down -> up -> verify still reachable.
        """
        shield = Shield(ShieldConfig())
        shield.setup()

        name = f"{CTR_PREFIX}-bypass-cache-{os.getpid()}-{os.urandom(4).hex()}"
        subprocess.run(["podman", "rm", "-f", name], capture_output=True)

        try:
            extra_args = shield.pre_start(name)
            start_shielded_container(name, extra_args, IMAGE)

            # Allow Cloudflare IPs and verify reachability
            for ip in ALLOWED_TARGET_IPS:
                shield.allow(name, ip)
            assert_reachable(name, ALLOWED_TARGET_HTTP)

            # Write these IPs to the resolved cache (simulating DNS resolution)
            resolved_dir = shield_env / "resolved"
            resolved_dir.mkdir(parents=True, exist_ok=True)
            (resolved_dir / f"{name}.resolved").write_text("\n".join(ALLOWED_TARGET_IPS) + "\n")

            # Go down (all traffic allowed regardless)
            shield.down(name)
            assert_reachable(name, ALLOWED_TARGET_HTTP)

            # Come back up — cached IPs should be restored
            shield.up(name)
            assert shield.state(name) == ShieldState.UP
            assert_reachable(name, ALLOWED_TARGET_HTTP)

        finally:
            subprocess.run(["podman", "rm", "-f", name], capture_output=True, timeout=30)


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestBypassAuditTrail:
    """Verify audit log events for bypass operations."""

    def test_down_up_audit_events(self, shielded_container: str) -> None:
        """shield.down and shield.up produce audit log entries."""
        shield = _shield()
        shield.down(shielded_container)
        shield.up(shielded_container)

        events = list(shield.tail_log(shielded_container))
        actions = [e["action"] for e in events]
        assert "shield_down" in actions
        assert "shield_up" in actions

        # shield_down must precede shield_up
        down_idx = actions.index("shield_down")
        up_idx = actions.index("shield_up")
        assert down_idx < up_idx

    def test_down_all_logs_detail(self, shielded_container: str) -> None:
        """shield.down(allow_all=True) logs the allow_all detail."""
        shield = _shield()
        shield.down(shielded_container, allow_all=True)

        events = list(shield.tail_log(shielded_container))
        down_events = [e for e in events if e["action"] == "shield_down"]
        assert any(e.get("detail") == "allow_all=True" for e in down_events)


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestBypassFullE2E:
    """End-to-end test exercising the full user journey.

    Simulates a realistic workflow: user starts a shielded container,
    discovers they need to find which domains to allowlist, toggles
    bypass to discover traffic, then re-enables the shield.
    """

    def test_discovery_workflow(self, shield_env: Path, _pull_image: None) -> None:
        """Complete traffic-discovery workflow as the user would execute it.

        1. Setup and start shielded container
        2. Allow known-good IPs, verify traffic works
        3. Down for discovery — all traffic flows
        4. Up — original IPs still work (from cache)
        5. Verify blocked target is blocked again
        6. Audit trail has the complete story
        """
        shield = Shield(ShieldConfig())
        shield.setup()

        name = f"{CTR_PREFIX}-bypass-e2e-{os.getpid()}-{os.urandom(4).hex()}"
        subprocess.run(["podman", "rm", "-f", name], capture_output=True)

        try:
            extra_args = shield.pre_start(name)
            start_shielded_container(name, extra_args, IMAGE)

            # Step 1: Default deny is in effect
            assert shield.state(name) == ShieldState.UP
            assert_blocked(name, BLOCKED_TARGET_HTTP)
            assert_blocked(name, ALLOWED_TARGET_HTTP)

            # Step 2: Allow Cloudflare, write cache
            for ip in ALLOWED_TARGET_IPS:
                shield.allow(name, ip)
            assert_reachable(name, ALLOWED_TARGET_HTTP)
            assert_blocked(name, BLOCKED_TARGET_HTTP)

            # Persist to cache for restoration
            resolved_dir = shield_env / "resolved"
            resolved_dir.mkdir(parents=True, exist_ok=True)
            (resolved_dir / f"{name}.resolved").write_text("\n".join(ALLOWED_TARGET_IPS) + "\n")

            # Step 3: Down for discovery
            shield.down(name)
            assert shield.state(name) == ShieldState.DOWN
            assert_reachable(name, ALLOWED_TARGET_HTTP)
            assert_connectable(name, BLOCKED_TARGET_IP, BLOCKED_TARGET_DNS_PORT)

            # Step 4: Switch to full bypass to also check RFC1918 destinations
            shield.down(name, allow_all=True)
            assert shield.state(name) == ShieldState.DOWN_ALL
            assert_connectable(name, BLOCKED_TARGET_IP, BLOCKED_TARGET_DNS_PORT)

            # Step 5: Back to protected bypass
            shield.down(name)
            assert shield.state(name) == ShieldState.DOWN
            assert_connectable(name, BLOCKED_TARGET_IP, BLOCKED_TARGET_DNS_PORT)

            # Step 6: Restore the shield
            shield.up(name)
            assert shield.state(name) == ShieldState.UP

            # Cached IPs should be restored
            assert_reachable(name, ALLOWED_TARGET_HTTP)
            # Blocked target should be blocked again
            assert_blocked(name, BLOCKED_TARGET_HTTP)

            # Step 7: Verify audit trail tells the whole story
            events = list(shield.tail_log(name))
            actions = [e["action"] for e in events]
            assert "setup" in actions
            assert "allowed" in actions
            assert "shield_down" in actions
            assert "shield_up" in actions

            # shield_down events come after allow, shield_up is last
            first_allowed = actions.index("allowed")
            first_down = actions.index("shield_down")
            last_up = len(actions) - 1 - actions[::-1].index("shield_up")
            assert first_allowed < first_down < last_up

        finally:
            subprocess.run(["podman", "rm", "-f", name], capture_output=True, timeout=30)

    def test_rapid_toggle(self, shielded_container: str) -> None:
        """Rapidly toggling down/up doesn't break the container.

        Users might accidentally run down twice, or script rapid toggles.
        The shield must remain consistent throughout.
        """
        shield = _shield()
        # Rapid toggles
        shield.down(shielded_container)
        shield.up(shielded_container)
        shield.down(shielded_container)
        shield.down(shielded_container, allow_all=True)
        shield.up(shielded_container)
        shield.up(shielded_container)

        # Final state must be UP and enforcing
        assert shield.state(shielded_container) == ShieldState.UP
        assert_blocked(shielded_container, BLOCKED_TARGET_HTTP)

        # Ruleset must be valid
        rules = shield.rules(shielded_container)
        assert "policy drop" in rules
        assert "terok_shield" in rules

    def test_allow_before_and_after_bypass(self, shielded_container: str) -> None:
        """IPs allowed before bypass, lost during bypass, can be re-allowed after.

        Demonstrates that the state is clean after a bypass cycle:
        the user can re-allow IPs just like on a fresh container.
        """
        shield = _shield()
        # Allow before bypass
        for ip in ALLOWED_TARGET_IPS:
            shield.allow(shielded_container, ip)
        assert_reachable(shielded_container, ALLOWED_TARGET_HTTP)

        # Bypass cycle
        shield.down(shielded_container)
        shield.up(shielded_container)

        # Without cache, the allowed IPs are gone (ruleset was replaced)
        assert_blocked(shielded_container, ALLOWED_TARGET_HTTP)

        # But we can re-allow them
        for ip in ALLOWED_TARGET_IPS:
            shield.allow(shielded_container, ip)
        assert_reachable(shielded_container, ALLOWED_TARGET_HTTP)
