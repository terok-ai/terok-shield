# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: allow/deny traffic behavior."""

import tempfile
from pathlib import Path

import pytest

from terok_shield import Shield, ShieldConfig
from terok_shield.nft import add_elements, hook_ruleset
from tests.testnet import (
    ALLOWED_TARGET_HTTP,
    ALLOWED_TARGET_HTTPS,
    ALLOWED_TARGET_IPS,
    BLOCKED_TARGET_HTTP,
    RFC1918_HOST,
)

from ..conftest import nft_missing, nsenter_nft, podman_missing
from ..helpers import assert_blocked, assert_reachable, is_reachable, wget as _wget

# -- Low-level nft allow behavior -----------------------------


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestFirewallAllowing:
    """Verify that IPs added to the allow set can be reached."""

    def test_allowed_ip_reachable_http(self, container: str, container_pid: str) -> None:
        """HTTP traffic to an allowed IP is permitted."""
        r = nsenter_nft(container_pid, stdin=hook_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"
        r = nsenter_nft(container_pid, stdin=add_elements("allow_v4", ALLOWED_TARGET_IPS))
        assert r.returncode == 0, f"Add elements failed: {r.stderr}"

        post = _wget(container, ALLOWED_TARGET_HTTP, timeout=10)
        assert is_reachable(post), f"Allowed IP should be reachable via HTTP: {post.stderr}"

    def test_allowed_ip_reachable_https(self, container: str, container_pid: str) -> None:
        """HTTPS traffic to an allowed IP is permitted."""
        r = nsenter_nft(container_pid, stdin=hook_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"
        r = nsenter_nft(container_pid, stdin=add_elements("allow_v4", ALLOWED_TARGET_IPS))
        assert r.returncode == 0, f"Add elements failed: {r.stderr}"

        post = _wget(container, ALLOWED_TARGET_HTTPS, timeout=10)
        assert is_reachable(post), f"Allowed IP should be reachable via HTTPS: {post.stderr}"

    def test_non_allowed_ip_still_blocked(self, container: str, container_pid: str) -> None:
        """IPs not in the allow set remain blocked after adding others."""
        r = nsenter_nft(container_pid, stdin=hook_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"
        r = nsenter_nft(container_pid, stdin=add_elements("allow_v4", ALLOWED_TARGET_IPS))
        assert r.returncode == 0, f"Add elements failed: {r.stderr}"

        blocked = _wget(container, BLOCKED_TARGET_HTTP, timeout=10)
        assert blocked.returncode != 0, "Non-allowed IP should be blocked"

    def test_allow_then_block_different_targets(self, container: str, container_pid: str) -> None:
        """One IP allowed, another blocked — in the same container."""
        r = nsenter_nft(container_pid, stdin=hook_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"
        r = nsenter_nft(container_pid, stdin=add_elements("allow_v4", ALLOWED_TARGET_IPS))
        assert r.returncode == 0, f"Add elements failed: {r.stderr}"

        allowed = _wget(container, ALLOWED_TARGET_HTTP, timeout=10)
        blocked = _wget(container, BLOCKED_TARGET_HTTP, timeout=10)
        assert is_reachable(allowed), "Allowed IP should pass"
        assert blocked.returncode != 0, "Non-allowed IP should be rejected"


# -- RFC1918 whitelist behavior -------------------------------


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestRFC1918Allow:
    """Verify RFC1918 addresses can be whitelisted via the allow set."""

    def test_rfc1918_allowed_when_whitelisted(self, container: str, container_pid: str) -> None:
        """RFC1918 addresses in the allow set bypass the RFC1918 reject rules."""
        from terok_shield.nft_constants import RFC1918

        nsenter_nft(container_pid, stdin=hook_ruleset())
        nsenter_nft(container_pid, stdin=add_elements("allow_v4", [RFC1918_HOST]))

        # Structural: allow set evaluates before RFC1918 reject
        listed = nsenter_nft(container_pid, "list", "ruleset")
        assert listed.returncode == 0, listed.stderr
        output = listed.stdout
        allow_pos = output.find("@allow_v4")
        rfc_pos = output.find(RFC1918[0])
        assert allow_pos != -1, "allow_v4 set must be present"
        assert rfc_pos != -1, "RFC1918 reject rules must be present"
        assert allow_pos < rfc_pos, "Allow set must precede RFC1918 reject rules"


# -- Public API allow/deny ------------------------------------


@pytest.mark.needs_podman
@pytest.mark.needs_hooks
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestAllowDenyAPI:
    """Verify Shield.allow/Shield.deny via the public API."""

    def test_shield_allow_ip(self, shielded_container: str) -> None:
        """``Shield.allow()`` with an IP makes it reachable."""
        with tempfile.TemporaryDirectory() as tmp:
            shield = Shield(ShieldConfig(state_dir=Path(tmp)))
            allowed = shield.allow(shielded_container, ALLOWED_TARGET_IPS[0])
            assert ALLOWED_TARGET_IPS[0] in allowed

            # Allow both Cloudflare IPs (anycast pair)
            shield.allow(shielded_container, ALLOWED_TARGET_IPS[1])
            assert_reachable(shielded_container, ALLOWED_TARGET_HTTP)

    def test_shield_allow_deny_cycle(self, shielded_container: str) -> None:
        """``Shield.allow()`` then ``Shield.deny()`` blocks IP again."""
        with tempfile.TemporaryDirectory() as tmp:
            shield = Shield(ShieldConfig(state_dir=Path(tmp)))
            for ip in ALLOWED_TARGET_IPS:
                shield.allow(shielded_container, ip)
            assert_reachable(shielded_container, ALLOWED_TARGET_HTTP)

            for ip in ALLOWED_TARGET_IPS:
                shield.deny(shielded_container, ip)
            assert_blocked(shielded_container, ALLOWED_TARGET_HTTP)
