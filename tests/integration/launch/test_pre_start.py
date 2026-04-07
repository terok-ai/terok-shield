# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: Shield.pre_start and firewall application."""

from pathlib import Path
from unittest import mock

import pytest

from terok_shield import Shield, ShieldConfig, state

from ..conftest import hooks_unavailable, nft_missing, podman_missing
from ..helpers import assert_ruleset_applied

# -- Shield.pre_start -----------------------------------------


@pytest.mark.needs_podman
@podman_missing
@nft_missing
class TestShieldPreStart:
    """Verify ``Shield.pre_start()`` returns correct podman args."""

    @mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
    def test_pre_start_returns_podman_args(self, _hgh: mock.Mock, shield_env: Path) -> None:
        """Returned args contain ``--annotation`` and ``--cap-drop``."""
        sd = shield_env / "containers" / "test-container"
        shield = Shield(ShieldConfig(state_dir=sd))
        args = shield.pre_start("test-container")

        assert "--annotation" in args
        assert "--cap-drop" in args
        # --hooks-dir only present on podman >= 5.6.0;
        # on older podman, global hooks are used instead

    @pytest.mark.needs_internet
    @mock.patch("terok_shield.hooks.mode.has_global_hooks", return_value=True)
    def test_pre_start_resolves_dns(self, _hgh: mock.Mock, shield_env: Path) -> None:
        """DNS preparation files are written after ``Shield.pre_start()``.

        On the dnsmasq tier, domains go to ``profile.domains`` (not
        ``profile.allowed``).  On the dig/getent tier, resolved IPs go to
        ``profile.allowed``.  At least one of the two must have content.
        """
        sd = shield_env / "containers" / "dns-test-ctr"
        shield = Shield(ShieldConfig(state_dir=sd))
        shield.pre_start("dns-test-ctr")

        allowed = state.profile_allowed_path(sd)
        domains = state.profile_domains_path(sd)
        dns_prepared = (allowed.is_file() and allowed.stat().st_size > 0) or (
            domains.is_file() and domains.stat().st_size > 0
        )
        assert dns_prepared, (
            "DNS preparation should write IPs to profile.allowed (dig/getent tier) "
            "or domains to profile.domains (dnsmasq tier)"
        )


# -- Firewall applied via public API lifecycle ----------------


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@hooks_unavailable
@pytest.mark.needs_hooks
@pytest.mark.usefixtures("nft_in_netns")
class TestFirewallApplied:
    """Verify firewall rules are applied after the public API lifecycle."""

    def test_firewall_applied_via_hook(self, shielded_container: str) -> None:
        """A container started via the public API has firewall rules applied."""
        assert_ruleset_applied(shielded_container)
