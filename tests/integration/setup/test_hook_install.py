# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: hook installation via pre_start."""

from pathlib import Path
from unittest import mock

import pytest

from terok_shield import Shield, ShieldConfig, state

from ..conftest import nft_missing, podman_missing

# -- Hook installation via pre_start --------------------------


@pytest.mark.needs_podman
@podman_missing
@nft_missing
class TestHookInstall:
    """Verify ``Shield.pre_start()`` installs OCI hook files."""

    @mock.patch("terok_shield.mode_hook.has_global_hooks", return_value=True)
    def test_pre_start_creates_hook_files(self, _hgh: mock.Mock, shield_env: Path) -> None:
        """Hook JSON and entrypoint script exist after ``Shield.pre_start()``."""
        sd = shield_env / "containers" / "test-ctr"
        shield = Shield(ShieldConfig(state_dir=sd))
        shield.pre_start("test-ctr")

        hooks = state.hooks_dir(sd)
        assert (hooks / "terok-shield-createRuntime.json").is_file()
        assert (hooks / "terok-shield-poststop.json").is_file()
        entrypoint = state.hook_entrypoint(sd)
        assert entrypoint.is_file()
        assert entrypoint.stat().st_mode & 0o100, "Entrypoint must be executable"

    @mock.patch("terok_shield.mode_hook.has_global_hooks", return_value=True)
    def test_pre_start_idempotent(self, _hgh: mock.Mock, shield_env: Path) -> None:
        """Calling ``Shield.pre_start()`` twice does not break anything."""
        sd = shield_env / "containers" / "test-ctr"
        shield = Shield(ShieldConfig(state_dir=sd))
        shield.pre_start("test-ctr")
        shield.pre_start("test-ctr")

        hooks = state.hooks_dir(sd)
        assert (hooks / "terok-shield-createRuntime.json").is_file()
        assert (hooks / "terok-shield-poststop.json").is_file()
        entrypoint = state.hook_entrypoint(sd)
        assert entrypoint.is_file()
        assert entrypoint.stat().st_mode & 0o100, "Entrypoint must be executable after re-run"
