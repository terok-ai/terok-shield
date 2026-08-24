# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: network behavior in the down posture.

Verifies actual traffic flows correctly when the shield is down:
all outbound traffic accepted (with logging), RFC1918 still rejected
by default, and IPv6 private ranges still rejected.

Traffic tests are split by protocol/port so that future rule changes
(e.g. different treatment for DNS vs HTTP) are caught individually.
"""

import pytest

from terok_shield.nft.constants import (
    BYPASS_LOG_PREFIX,
    DENIED_LOG_PREFIX,
    HARD_DENY_RANGES,
    PRIVATE_RANGES,
)
from tests.testnet import (
    ALLOWED_TARGET_HTTP,
    BLOCKED_TARGET_DNS_PORT,
    BLOCKED_TARGET_IP,
    CONNCHECK_HTTP,
    CONNCHECK_HTTPS,
)

from ..conftest import nft_missing, podman_missing
from ..helpers import (
    assert_blocked,
    assert_connectable,
    assert_not_connectable,
    assert_reachable,
    disposable_shield as _shield,
)


@pytest.mark.needs_podman
@pytest.mark.needs_hooks
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestDownTrafficDNS:
    """Verify DNS (port 53) connectivity while the shield is down."""

    def test_dns_connectable_when_down(self, shielded_container: str) -> None:
        """DNS port (53) on a non-allowed target is connectable while down."""
        _shield().down(shielded_container, shielded_container.id)
        assert_connectable(shielded_container, BLOCKED_TARGET_IP, BLOCKED_TARGET_DNS_PORT)

    def test_dns_blocked_again_after_up(self, shielded_container: str) -> None:
        """DNS connectivity is blocked again after restoring the shield."""
        shield = _shield()
        shield.down(shielded_container, shielded_container.id)
        assert_connectable(shielded_container, BLOCKED_TARGET_IP, BLOCKED_TARGET_DNS_PORT)

        shield.up(shielded_container, shielded_container.id)
        assert_not_connectable(shielded_container, BLOCKED_TARGET_IP, BLOCKED_TARGET_DNS_PORT)


@pytest.mark.needs_podman
@pytest.mark.needs_hooks
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestDownTrafficHTTP:
    """Verify HTTP (port 80) connectivity while the shield is down."""

    def test_http_reachable_when_down(self, shielded_container: str) -> None:
        """HTTP (port 80) to a non-allowed target is reachable while down."""
        _shield().down(shielded_container, shielded_container.id)
        assert_reachable(shielded_container, CONNCHECK_HTTP)

    def test_http_blocked_again_after_up(self, shielded_container: str) -> None:
        """HTTP traffic to non-allowed target is blocked after restoring shield."""
        shield = _shield()
        shield.down(shielded_container, shielded_container.id)
        assert_reachable(shielded_container, CONNCHECK_HTTP)

        shield.up(shielded_container, shielded_container.id)
        assert_blocked(shielded_container, CONNCHECK_HTTP)


@pytest.mark.needs_podman
@pytest.mark.needs_hooks
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestDownTrafficHTTPS:
    """Verify HTTPS (port 443) connectivity while the shield is down."""

    def test_https_reachable_when_down(self, shielded_container: str) -> None:
        """HTTPS (port 443) to a non-allowed target is reachable while down."""
        _shield().down(shielded_container, shielded_container.id)
        assert_reachable(shielded_container, CONNCHECK_HTTPS)

    def test_https_blocked_again_after_up(self, shielded_container: str) -> None:
        """HTTPS traffic to non-allowed target is blocked after restoring shield."""
        shield = _shield()
        shield.down(shielded_container, shielded_container.id)
        assert_reachable(shielded_container, CONNCHECK_HTTPS)

        shield.up(shielded_container, shielded_container.id)
        assert_blocked(shielded_container, CONNCHECK_HTTPS)


@pytest.mark.needs_podman
@pytest.mark.needs_hooks
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestDownTrafficAllowed:
    """Verify allowed targets remain reachable while the shield is down."""

    def test_allowed_target_reachable_when_down(self, shielded_container: str) -> None:
        """Already-allowed HTTP target stays reachable while down."""
        _shield().down(shielded_container, shielded_container.id)
        assert_reachable(shielded_container, ALLOWED_TARGET_HTTP)


@pytest.mark.needs_podman
@pytest.mark.needs_hooks
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestDownRuleset:
    """Verify structural properties of the down ruleset."""

    def test_down_ruleset_has_log_prefix(self, shielded_container: str) -> None:
        """The down ruleset contains the TEROK_SHIELD_BYPASS log prefix."""
        shield = _shield()
        shield.down(shielded_container, shielded_container.id)
        rules = shield.rules(shielded_container)
        assert BYPASS_LOG_PREFIX in rules

    def test_down_ruleset_has_accept_policy(self, shielded_container: str) -> None:
        """The down ruleset output chain has policy accept."""
        shield = _shield()
        shield.down(shielded_container, shielded_container.id)
        rules = shield.rules(shielded_container)
        assert "policy accept" in rules

    def test_disengaged_ruleset_drops_the_deny_set_reject(self, shielded_container: str) -> None:
        """DISENGAGED enforces nothing — the deny-set reject is gone, not just the range floors."""
        shield = _shield()
        shield.down(shielded_container, shielded_container.id, disengaged=True)
        rules = shield.rules(shielded_container)
        assert DENIED_LOG_PREFIX not in rules
        assert BYPASS_LOG_PREFIX in rules


@pytest.mark.needs_podman
@pytest.mark.needs_hooks
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestDownRFC1918:
    """Verify RFC1918 protection in the down posture."""

    def test_rfc1918_rules_present_in_default_down(self, shielded_container: str) -> None:
        """Default down (no --disengage) keeps RFC1918 reject rules."""
        shield = _shield()
        shield.down(shielded_container, shielded_container.id)
        rules = shield.rules(shielded_container)
        for net in (n for n in HARD_DENY_RANGES + PRIVATE_RANGES if "." in n):
            assert net in rules, f"RFC1918 reject rule for {net} missing in down ruleset"

    def test_rfc1918_rules_absent_when_disengaged(self, shielded_container: str) -> None:
        """Down with disengaged=True removes RFC1918 reject rules."""
        shield = _shield()
        shield.down(shielded_container, shielded_container.id, disengaged=True)
        rules = shield.rules(shielded_container)
        for net in (n for n in HARD_DENY_RANGES + PRIVATE_RANGES if "." in n):
            assert (
                f"ip daddr {net}" not in rules or "reject" not in rules.split(net)[1].split("\n")[0]
            ), f"RFC1918 reject rule for {net} should not be in disengaged ruleset"

    def test_rfc1918_reject_is_fast_when_down(self, shielded_container: str) -> None:
        """RFC1918 reject in the down posture is immediate, not a silent drop.

        Since we can't route to real RFC1918 addresses from a rootless
        container, we verify structurally that reject rules are present
        (which guarantees ICMP admin-prohibited responses).
        """
        shield = _shield()
        shield.down(shielded_container, shielded_container.id)
        rules = shield.rules(shielded_container)
        assert "admin-prohibited" in rules


@pytest.mark.needs_podman
@pytest.mark.needs_hooks
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestDownIPv6Private:
    """Verify IPv6 private ranges are still rejected in the down posture."""

    def test_ipv6_private_rules_present_in_default_down(self, shielded_container: str) -> None:
        """Default down keeps IPv6 private reject rules."""
        shield = _shield()
        shield.down(shielded_container, shielded_container.id)
        rules = shield.rules(shielded_container)
        for net in (n for n in HARD_DENY_RANGES + PRIVATE_RANGES if ":" in n):
            assert net in rules, f"IPv6 private reject rule for {net} missing in down ruleset"

    def test_ipv6_private_rules_absent_when_disengaged(self, shielded_container: str) -> None:
        """Down with disengaged=True removes IPv6 private reject rules."""
        shield = _shield()
        shield.down(shielded_container, shielded_container.id, disengaged=True)
        rules = shield.rules(shielded_container)
        for net in (n for n in HARD_DENY_RANGES + PRIVATE_RANGES if ":" in n):
            assert (
                f"ip6 daddr {net}" not in rules
                or "reject" not in rules.split(net)[1].split("\n")[0]
            ), f"IPv6 private reject rule for {net} should not be in disengaged ruleset"
