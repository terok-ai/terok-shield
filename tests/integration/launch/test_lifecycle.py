# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Full API lifecycle integration test.

Exercises the complete setup → allow → deny → audit cycle as terok
would use it, driving each step manually rather than via fixtures.
"""

import os
import subprocess

import pytest

from terok_shield import (
    ShieldConfig,
    shield_allow,
    shield_deny,
    shield_pre_start,
    shield_rules,
    shield_setup,
    shield_status,
    tail_log,
)

from ...testnet import ALLOWED_TARGET_HTTP, ALLOWED_TARGET_IPS
from ..conftest import CTR_PREFIX, IMAGE, nft_missing, podman_missing
from ..helpers import assert_blocked, assert_reachable


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestAPILifecycle:
    """End-to-end lifecycle test using the public API."""

    def test_full_lifecycle(self, shield_env, _pull_image) -> None:
        """Drive setup → pre_start → allow → deny → audit via public API."""
        cfg = ShieldConfig()
        name = f"{CTR_PREFIX}-lifecycle-{os.getpid()}-{os.urandom(4).hex()}"

        try:
            # 1. Setup
            shield_setup(config=cfg)

            # 2. Pre-start → returns podman args
            extra_args = shield_pre_start(name, config=cfg)
            assert isinstance(extra_args, list)
            assert len(extra_args) > 0

            # 3. Start container with shield args
            subprocess.run(["podman", "rm", "-f", name], capture_output=True, timeout=30)
            subprocess.run(
                ["podman", "run", "-d", "--name", name, *extra_args, IMAGE, "sleep", "120"],
                check=True,
                capture_output=True,
                timeout=30,
            )

            # 4. Verify ruleset applied
            rules = shield_rules(name, config=cfg)
            assert "terok_shield" in rules
            assert "allow_v4" in rules

            # 5. Allow target IPs (Cloudflare anycast may respond from either)
            allowed: list[str] = []
            for ip in ALLOWED_TARGET_IPS:
                allowed.extend(shield_allow(name, ip, config=cfg))
            assert all(ip in allowed for ip in ALLOWED_TARGET_IPS)

            # 6. Verify traffic flows
            assert_reachable(name, ALLOWED_TARGET_HTTP)

            # 7. Deny all allowed IPs
            for ip in allowed:
                shield_deny(name, ip, config=cfg)

            # 8. Verify blocked
            assert_blocked(name, ALLOWED_TARGET_HTTP)

            # 9. Check status
            status = shield_status(config=cfg)
            assert status["mode"] == cfg.mode.value
            assert status["audit_enabled"] is True

            # 10. Verify audit trail
            events = list(tail_log(name))
            actions = [e["action"] for e in events]
            setup_i = actions.index("setup")
            allowed_i = actions.index("allowed")
            denied_i = actions.index("denied")
            assert setup_i < allowed_i < denied_i

        finally:
            subprocess.run(["podman", "rm", "-f", name], capture_output=True, timeout=30)
