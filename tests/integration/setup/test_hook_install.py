# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: setup-owned hooks remain untouched by pre_start."""

from pathlib import Path
from unittest import mock

import pytest

from terok_shield import Shield, ShieldConfig

from ..conftest import nft_missing, podman_missing

# -- Hook installation via pre_start --------------------------


@pytest.mark.needs_podman
@podman_missing
@nft_missing
class TestHookInstall:
    """Verify ``Shield.pre_start()`` does not modify global OCI hook files."""

    @mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
    def test_pre_start_does_not_install_hooks(self, _hgh: mock.Mock, shield_env: Path) -> None:
        """Preparing a task never installs or updates hooks."""
        sd = shield_env / "containers" / "test-ctr"
        shield = Shield(ShieldConfig(state_dir=sd))
        shield.pre_start("test-ctr")

        assert not (sd / "hooks").exists()
        assert not (sd / "terok-shield-hook").exists()

    @mock.patch("terok_shield.hooks.mode.HooksInstaller.check_setup", return_value=())
    def test_pre_start_idempotent(self, _hgh: mock.Mock, shield_env: Path) -> None:
        """Calling ``Shield.pre_start()`` twice does not break anything."""
        sd = shield_env / "containers" / "test-ctr"
        shield = Shield(ShieldConfig(state_dir=sd))
        shield.pre_start("test-ctr")
        shield.pre_start("test-ctr")

        assert not (sd / "hooks").exists()
        assert not (sd / "terok-shield-hook").exists()
