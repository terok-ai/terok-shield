# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: hook installation via public API and CLI."""

from pathlib import Path

import pytest

from terok_shield import ShieldConfig, shield_setup
from terok_shield.cli import main

from ..conftest import nft_missing, podman_missing

# ── API-based setup ──────────────────────────────────────


@pytest.mark.needs_podman
@podman_missing
@nft_missing
class TestShieldSetup:
    """Verify ``shield_setup()`` installs OCI hook files."""

    def test_setup_creates_hook_files(self, shield_env: Path) -> None:
        """Hook JSON and entrypoint script exist after ``shield_setup()``."""
        cfg = ShieldConfig()
        shield_setup(config=cfg)

        hooks_dir = shield_env / "hooks"
        assert (hooks_dir / "terok-shield-hook.json").is_file()
        entrypoint = shield_env / "terok-shield-hook"
        assert entrypoint.is_file()
        assert entrypoint.stat().st_mode & 0o100, "Entrypoint must be executable"

    def test_setup_idempotent(self, shield_env: Path) -> None:
        """Calling ``shield_setup()`` twice does not break anything."""
        cfg = ShieldConfig()
        shield_setup(config=cfg)
        shield_setup(config=cfg)

        hooks_dir = shield_env / "hooks"
        assert (hooks_dir / "terok-shield-hook.json").is_file()
        entrypoint = shield_env / "terok-shield-hook"
        assert entrypoint.is_file()
        assert entrypoint.stat().st_mode & 0o100, "Entrypoint must be executable after re-setup"


# ── CLI-based setup ──────────────────────────────────────


@pytest.mark.needs_podman
@podman_missing
@nft_missing
class TestCLISetup:
    """Verify ``terok-shield setup`` via CLI."""

    def test_cli_setup(self, shield_env: Path) -> None:
        """``main(["setup"])`` exits normally and creates hook files."""
        main(["setup"])

        hooks_dir = shield_env / "hooks"
        assert (hooks_dir / "terok-shield-hook.json").is_file()
        assert (shield_env / "terok-shield-hook").is_file()

    def test_cli_setup_idempotent(self, shield_env: Path) -> None:
        """Calling setup twice via CLI succeeds."""
        main(["setup"])
        main(["setup"])

        hooks_dir = shield_env / "hooks"
        assert (hooks_dir / "terok-shield-hook.json").is_file()
        entrypoint = shield_env / "terok-shield-hook"
        assert entrypoint.is_file()
        assert entrypoint.stat().st_mode & 0o100, "Entrypoint must be executable after re-setup"
