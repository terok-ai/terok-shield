# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration test: shield persistence across container stop/start.

Verifies that the OCI hook fires on both ``podman run`` and
``podman start`` (restart), keeping the shield active across the
full container lifecycle.  Requires global hooks installed via
``terok-shield setup`` (per-container ``--hooks-dir`` does not
persist across stop/start — see #121, #122).
"""

import os
import subprocess
from pathlib import Path

import pytest

from terok_shield import Shield, ShieldConfig, ShieldState

from ..conftest import CTR_PREFIX, IMAGE, _podman_rm, hooks_unavailable, nft_missing, podman_missing
from ..helpers import start_shielded_container


def _container_running(name: str) -> bool:
    """Return True if a container is running."""
    r = subprocess.run(
        ["podman", "inspect", "--format", "{{.State.Running}}", name],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return r.returncode == 0 and r.stdout.strip() == "true"


@pytest.mark.needs_podman
@pytest.mark.needs_hooks
@podman_missing
@nft_missing
@hooks_unavailable
@pytest.mark.usefixtures("nft_in_netns")
class TestRestartPersistence:
    """Shield must survive a container stop + start cycle.

    The OCI ``createRuntime`` hook must fire on every container start,
    including ``podman start`` of a previously-stopped container.
    This requires global hooks — per-container ``--hooks-dir`` is lost
    on restart (#121, #122).
    """

    def test_shield_lifecycle_with_restart(self, shield_env: Path, _pull_image: None) -> None:
        """Start → verify shield → stop → restart → verify shield again."""
        name = f"{CTR_PREFIX}-restart-{os.getpid()}-{os.urandom(4).hex()}"
        sd = shield_env / "containers" / name
        cfg = ShieldConfig(state_dir=sd)
        shield = Shield(cfg)

        _podman_rm(name)

        try:
            # ── Phase 1: initial start ─────────────────────────
            extra_args = shield.pre_start(name)
            start_shielded_container(name, extra_args, IMAGE)

            assert _container_running(name), "Container should be running after initial start"

            assert shield.state(name) == ShieldState.UP, "Shield should be UP after initial start"

            rules = shield.rules(name)
            assert "terok_shield" in rules, "Expected terok_shield table in ruleset"
            assert "policy drop" in rules, "Expected deny-all policy in output chain"
            assert "allow_v4" in rules, "Expected allow_v4 set in ruleset"

            # ── Phase 2: stop ──────────────────────────────────
            subprocess.run(
                ["podman", "stop", "-t", "3", name],
                check=True,
                capture_output=True,
                timeout=30,
            )

            assert not _container_running(name), "Container should be stopped"

            # ── Phase 3: restart ───────────────────────────────
            subprocess.run(
                ["podman", "start", name],
                check=True,
                capture_output=True,
                timeout=30,
            )

            assert _container_running(name), "Container should be running after restart"

            # Shield must still be active — the global hook fired on restart
            assert shield.state(name) == ShieldState.UP, (
                "Shield should be UP after restart (fail-close guarantee). "
                "If INACTIVE, the OCI hook did not fire on podman start — "
                "the container is running without firewall protection."
            )

            rules_after = shield.rules(name)
            assert "terok_shield" in rules_after, (
                "Expected terok_shield table in ruleset after restart"
            )
            assert "policy drop" in rules_after, "Expected deny-all policy after restart"

        finally:
            _podman_rm(name)
