# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: default-deny firewall behavior."""

import pytest

from terok_shield.nft import hook_ruleset
from terok_shield.nft_constants import RFC1918
from tests.testnet import (
    ALLOWED_TARGET_HTTP,
    ALLOWED_TARGET_HTTPS,
    BLOCKED_TARGET_HTTP,
    IPV6_CLOUDFLARE,
    IPV6_GOOGLE,
    IPV6_HTTP_URL,
)

from ..conftest import nft_missing, nsenter_nft, podman_missing
from ..helpers import assert_blocked, exec_in_container as _exec, wget as _wget


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestFirewallBlocking:
    """Verify the default-deny ruleset blocks outbound traffic."""

    def test_http_blocked_after_ruleset(self, container: str, container_pid: str) -> None:
        """Outbound HTTP to an external IP is rejected after applying the ruleset."""
        r = nsenter_nft(container_pid, stdin=hook_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"

        post = _wget(container, ALLOWED_TARGET_HTTP, timeout=10)
        assert post.returncode != 0, "HTTP traffic should be blocked"

    def test_https_blocked_after_ruleset(self, container: str, container_pid: str) -> None:
        """Outbound HTTPS is rejected after applying the ruleset."""
        r = nsenter_nft(container_pid, stdin=hook_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"

        post = _wget(container, ALLOWED_TARGET_HTTPS, timeout=10)
        assert post.returncode != 0, "HTTPS traffic should be blocked"

    def test_ipv6_blocked_after_ruleset(self, container: str, container_pid: str) -> None:
        """IPv6 traffic is unconditionally dropped after applying the ruleset."""
        # Pre-firewall IPv6 probe — if IPv6 doesn't work before the firewall,
        # functional checks would pass trivially (false positive)
        pre_ping = _exec(container, "ping", "-6", "-c1", "-W2", IPV6_CLOUDFLARE, timeout=5)
        ipv6_available = pre_ping.returncode == 0

        nsenter_nft(container_pid, stdin=hook_ruleset())

        # Structural check: IPv6 drop is present and before first accept rule
        listed = nsenter_nft(container_pid, "list", "ruleset")
        assert listed.returncode == 0, listed.stderr
        output = listed.stdout
        assert "nfproto ipv6 drop" in output, "IPv6 drop rule must be in applied ruleset"
        ipv6_pos = output.find("nfproto ipv6 drop")
        ct_pos = output.find("ct state established,related accept")
        assert ipv6_pos < ct_pos, "IPv6 drop must precede established accept"

        if not ipv6_available:
            pytest.skip(
                "IPv6 not available pre-firewall — functional checks would be false positives"
            )

        # Functional: ICMP6 ping to Cloudflare DNS
        ping_cf = _exec(container, "ping", "-6", "-c1", "-W2", IPV6_CLOUDFLARE, timeout=5)
        assert ping_cf.returncode != 0, "IPv6 ping to Cloudflare should be blocked"

        # Functional: ICMP6 ping to Google DNS
        ping_g = _exec(container, "ping", "-6", "-c1", "-W2", IPV6_GOOGLE, timeout=5)
        assert ping_g.returncode != 0, "IPv6 ping to Google should be blocked"

        # Functional: HTTP over IPv6 literal (must not force IPv4)
        http6 = _wget(container, IPV6_HTTP_URL, timeout=5)
        assert http6.returncode != 0, "HTTP over IPv6 should be blocked"

    def test_reject_is_fast_not_timeout(self, container: str, container_pid: str) -> None:
        """Blocked traffic fails fast (reject), not via silent timeout (drop).

        A ``reject`` rule sends an ICMP error back immediately, so the
        connection fails in well under the timeout.  A ``drop`` rule
        would silently discard packets, causing the client to hang until
        the full timeout expires.  We verify reject behavior by measuring
        elapsed time rather than parsing tool-specific error messages.
        """
        import time

        r = nsenter_nft(container_pid, stdin=hook_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"

        wget_timeout = 10
        t0 = time.monotonic()
        post = _wget(container, BLOCKED_TARGET_HTTP, timeout=wget_timeout)
        elapsed = time.monotonic() - t0

        assert post.returncode != 0, "Blocked target should be rejected"
        assert elapsed < wget_timeout / 2, (
            f"Connection took {elapsed:.1f}s (timeout={wget_timeout}s) — "
            f"looks like drop (silent timeout), not reject (ICMP error)"
        )

    def test_rfc1918_still_blocked_when_not_whitelisted(
        self, container: str, container_pid: str
    ) -> None:
        """RFC1918 addresses are rejected when not in the allow set."""
        nsenter_nft(container_pid, stdin=hook_ruleset())

        # Structural: all RFC1918 reject rules present
        listed = nsenter_nft(container_pid, "list", "ruleset")
        assert listed.returncode == 0, listed.stderr
        for net in RFC1918:
            assert net in listed.stdout, f"Missing RFC1918 block for {net}"


# ── Default-deny via public API ──────────────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestDefaultDenyAPI:
    """Verify default-deny through the public API lifecycle."""

    def test_traffic_blocked_by_default(self, shielded_container: str) -> None:
        """Outbound traffic is blocked after the public API lifecycle."""
        assert_blocked(shielded_container, BLOCKED_TARGET_HTTP)
