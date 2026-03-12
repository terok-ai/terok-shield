# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Full API lifecycle integration test.

Exercises the complete pre_start → allow → deny → audit cycle as terok
would use it, driving each step manually rather than via fixtures.
"""

import os
import subprocess

import pytest

from terok_shield import Shield, ShieldConfig

from ...testnet import ALLOWED_TARGET_HTTP, ALLOWED_TARGET_IPS
from ..conftest import CTR_PREFIX, IMAGE, nft_missing, podman_missing
from ..helpers import assert_blocked, assert_reachable, start_shielded_container


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestAPILifecycle:
    """End-to-end lifecycle test using the public API."""

    def test_full_lifecycle(self, shield_env, _pull_image) -> None:
        """Drive pre_start → allow → deny → audit via public API."""
        name = f"{CTR_PREFIX}-lifecycle-{os.getpid()}-{os.urandom(4).hex()}"
        sd = shield_env / "containers" / name
        cfg = ShieldConfig(state_dir=sd)
        shield = Shield(cfg)

        try:
            # 1. Pre-start → returns podman args (also installs hooks)
            extra_args = shield.pre_start(name)
            assert isinstance(extra_args, list)
            assert len(extra_args) > 0

            # 2. Start container with shield args
            subprocess.run(["podman", "rm", "-f", name], capture_output=True, timeout=30)
            start_shielded_container(name, extra_args, IMAGE)

            # 3. Verify ruleset applied
            rules = shield.rules(name)
            assert "terok_shield" in rules
            assert "allow_v4" in rules

            # 4. Allow target IPs (Cloudflare anycast may respond from either)
            allowed: list[str] = []
            for ip in ALLOWED_TARGET_IPS:
                allowed.extend(shield.allow(name, ip))
            assert all(ip in allowed for ip in ALLOWED_TARGET_IPS)

            # 5. Verify traffic flows
            assert_reachable(name, ALLOWED_TARGET_HTTP)

            # 6. Deny all allowed IPs
            for ip in allowed:
                shield.deny(name, ip)

            # 7. Verify blocked
            assert_blocked(name, ALLOWED_TARGET_HTTP)

            # 8. Check status
            status = shield.status()
            assert status["mode"] == cfg.mode.value
            assert status["audit_enabled"] is True

            # 9. Verify audit trail
            events = list(shield.tail_log())
            actions = [e["action"] for e in events]
            assert "setup" in actions
            assert "allowed" in actions
            assert "denied" in actions

        finally:
            subprocess.run(["podman", "rm", "-f", name], capture_output=True, timeout=30)
