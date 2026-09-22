# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: Shield.pre_start and firewall application."""

from pathlib import Path
from unittest import mock

import pytest

from terok_shield import Shield, ShieldConfig

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
        """DNS preparation is written after ``Shield.pre_start()``.

        pre_start composes the profiles into the ``policy/40-project-allow``
        tier and resolves them into the ``resolved.ips`` cache; at least one
        of the two must have content.
        """
        sd = shield_env / "containers" / "dns-test-ctr"
        shield = Shield(ShieldConfig(state_dir=sd))
        shield.pre_start("dns-test-ctr", ["dev-standard"])

        bundle = StateBundle(sd)
        project_allow = bundle.tier_path("project_allow")
        cache = bundle.resolved_cache
        dns_prepared = (project_allow.is_file() and project_allow.stat().st_size > 0) or (
            cache.is_file() and cache.stat().st_size > 0
        )
        assert dns_prepared, (
            "DNS preparation should write the composed policy to the project-allow "
            "tier or resolved IPs to the resolved.ips cache"
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


from terok_shield.state import StateBundle
