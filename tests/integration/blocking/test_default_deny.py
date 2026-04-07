# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: default-deny firewall behavior.

Each blocking test includes a pre-firewall reachability check to prevent
false positives: if the target is unreachable *before* our rules are applied,
the "blocked" assertion would pass trivially (the block comes from the
network environment, not from terok-shield).

IPv4 targets are mandatory — pre-firewall failure is a hard error (fix the
host environment).  IPv6 is optional — tests skip gracefully when the host
lacks IPv6 connectivity.
"""

import time

import pytest

from terok_shield.nft.constants import IPV6_PRIVATE, RFC1918
from terok_shield.nft.rules import hook_ruleset
from tests.testnet import (
    ALLOWED_TARGET_HTTP,
    ALLOWED_TARGET_HTTPS,
    BLOCKED_TARGET_DNS_PORT,
    BLOCKED_TARGET_HTTP,
    BLOCKED_TARGET_IP,
    IPV6_CLOUDFLARE,
    IPV6_GOOGLE,
    IPV6_HTTP_URL,
)

from ..conftest import nft_missing, nsenter_nft, podman_missing
from ..helpers import assert_blocked, exec_in_container as _exec, wget as _wget

# ── Pre-flight helpers ──────────────────────────────────────────────

_PREFLIGHT_MSG = (
    "Pre-firewall: {target} unreachable without firewall rules.\n"
    "Fix host connectivity or wait for remote service to recover before running "
    "firewall tests (false positives occur when an upstream firewall blocks traffic)."
)


def _preflight_wget(container: str, url: str, timeout: int = 10) -> None:
    """Fail hard if HTTP(S) target is unreachable before applying firewall rules."""
    r = _wget(container, url, timeout=timeout)
    assert r.returncode == 0, _PREFLIGHT_MSG.format(target=url) + f"\nstderr: {r.stderr}"


def _preflight_tcp(container: str, ip: str, port: int, timeout: int = 5) -> None:
    """Fail hard if TCP target is unreachable before applying firewall rules."""
    r = _exec(container, "nc", "-z", "-w", str(timeout), ip, str(port), timeout=timeout + 5)
    assert r.returncode == 0, _PREFLIGHT_MSG.format(target=f"{ip}:{port}") + f"\nstderr: {r.stderr}"


def _skip_unless_ipv6(container: str) -> None:
    """Skip test if IPv6 connectivity is not available pre-firewall."""
    r = _exec(container, "ping", "-6", "-c1", "-W2", IPV6_CLOUDFLARE, timeout=5)
    if r.returncode != 0:
        pytest.skip("IPv6 not available pre-firewall — skipping to avoid false positives")


# ── IPv4 default-deny ───────────────────────────────────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestFirewallBlocking:
    """Verify the default-deny ruleset blocks outbound IPv4 traffic."""

    def test_http_blocked_after_ruleset(self, container: str, container_pid: str) -> None:
        """Outbound HTTP to an external IP is rejected after applying the ruleset."""
        _preflight_wget(container, ALLOWED_TARGET_HTTP)

        r = nsenter_nft(container_pid, stdin=hook_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"

        post = _wget(container, ALLOWED_TARGET_HTTP, timeout=10)
        assert post.returncode != 0, "HTTP traffic should be blocked"

    def test_https_blocked_after_ruleset(self, container: str, container_pid: str) -> None:
        """Outbound HTTPS is rejected after applying the ruleset."""
        _preflight_wget(container, ALLOWED_TARGET_HTTPS)

        r = nsenter_nft(container_pid, stdin=hook_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"

        post = _wget(container, ALLOWED_TARGET_HTTPS, timeout=10)
        assert post.returncode != 0, "HTTPS traffic should be blocked"

    def test_reject_is_fast_not_timeout(self, container: str, container_pid: str) -> None:
        """Blocked traffic fails fast (reject), not via silent timeout (drop).

        A ``reject`` rule sends an ICMP error back immediately, so the
        connection fails in well under the timeout.  A ``drop`` rule
        would silently discard packets, causing the client to hang until
        the full timeout expires.  We verify reject behavior by measuring
        elapsed time rather than parsing tool-specific error messages.
        """
        _preflight_tcp(container, BLOCKED_TARGET_IP, BLOCKED_TARGET_DNS_PORT)

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


# ── IPv6 default-deny ───────────────────────────────────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestFirewallBlockingIPv6:
    """Verify the default-deny ruleset blocks outbound IPv6 traffic.

    IPv6 tests skip gracefully when the host lacks IPv6 connectivity,
    since that would cause false positives (traffic blocked by network,
    not by firewall).
    """

    def test_ipv6_ruleset_has_dual_stack_sets(self, container: str, container_pid: str) -> None:
        """Applied ruleset contains allow_v6 set and IPv6 private reject rules."""
        nsenter_nft(container_pid, stdin=hook_ruleset())
        listed = nsenter_nft(container_pid, "list", "ruleset")
        assert listed.returncode == 0, listed.stderr
        output = listed.stdout
        assert "allow_v6" in output, "allow_v6 set must be in applied ruleset"
        for net in IPV6_PRIVATE:
            assert net in output, f"IPv6 private reject rule for {net} missing"

    def test_ipv6_icmp_blocked(self, container: str, container_pid: str) -> None:
        """ICMPv6 ping to non-allowed IPv6 addresses is blocked."""
        _skip_unless_ipv6(container)

        nsenter_nft(container_pid, stdin=hook_ruleset())

        for ip, label in [(IPV6_CLOUDFLARE, "Cloudflare"), (IPV6_GOOGLE, "Google")]:
            r = _exec(container, "ping", "-6", "-c1", "-W2", ip, timeout=5)
            assert r.returncode != 0, f"IPv6 ICMP ping to {label} ({ip}) should be blocked"

    def test_ipv6_dns_blocked(self, container: str, container_pid: str) -> None:
        """TCP to port 53 (DNS) on a non-allowed IPv6 address is blocked."""
        _skip_unless_ipv6(container)

        pre = _exec(container, "nc", "-z", "-w", "3", IPV6_CLOUDFLARE, "53", timeout=8)
        if pre.returncode != 0:
            pytest.skip("IPv6 DNS (port 53) not reachable pre-firewall")

        nsenter_nft(container_pid, stdin=hook_ruleset())

        post = _exec(container, "nc", "-z", "-w", "3", IPV6_CLOUDFLARE, "53", timeout=8)
        assert post.returncode != 0, "IPv6 DNS (port 53) should be blocked"

    def test_ipv6_http_blocked(self, container: str, container_pid: str) -> None:
        """HTTP over IPv6 literal address is blocked."""
        _skip_unless_ipv6(container)

        pre = _wget(container, IPV6_HTTP_URL, timeout=5)
        if pre.returncode != 0:
            pytest.skip("IPv6 HTTP not reachable pre-firewall")

        nsenter_nft(container_pid, stdin=hook_ruleset())

        post = _wget(container, IPV6_HTTP_URL, timeout=5)
        assert post.returncode != 0, "HTTP over IPv6 should be blocked"

    def test_ipv6_https_blocked(self, container: str, container_pid: str) -> None:
        """TCP to port 443 (HTTPS) on a non-allowed IPv6 address is blocked."""
        _skip_unless_ipv6(container)

        pre = _exec(container, "nc", "-z", "-w", "3", IPV6_CLOUDFLARE, "443", timeout=8)
        if pre.returncode != 0:
            pytest.skip("IPv6 HTTPS (port 443) not reachable pre-firewall")

        nsenter_nft(container_pid, stdin=hook_ruleset())

        post = _exec(container, "nc", "-z", "-w", "3", IPV6_CLOUDFLARE, "443", timeout=8)
        assert post.returncode != 0, "IPv6 HTTPS (port 443) should be blocked"


# ── Default-deny via public API ─────────────────────────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_hooks
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestDefaultDenyAPI:
    """Verify default-deny through the public API lifecycle."""

    def test_traffic_blocked_by_default(self, shielded_container: str) -> None:
        """Outbound traffic is blocked after the public API lifecycle."""
        assert_blocked(shielded_container, BLOCKED_TARGET_HTTP)
