# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: shield status (API + CLI)."""

from pathlib import Path

import pytest

from terok_shield import Shield, ShieldConfig
from terok_shield.cli import main

# -- Public API status ----------------------------------------


@pytest.mark.needs_host_features
class TestShieldStatus:
    """Verify ``Shield.status()`` returns expected structure."""

    def test_status_returns_dict(self, shield_env: Path) -> None:
        """Status dict contains expected keys."""
        sd = shield_env / "containers" / "_default"
        status = Shield(ShieldConfig(state_dir=sd)).status()
        assert isinstance(status, dict)
        assert "mode" in status
        assert "profiles" in status
        assert "audit_enabled" in status
        assert isinstance(status["profiles"], list)


# -- CLI status -----------------------------------------------


@pytest.mark.needs_host_features
class TestCLIStatus:
    """Verify ``terok-shield status`` via CLI."""

    def test_cli_status(self, shield_env: Path, capsys: pytest.CaptureFixture) -> None:
        """``main(["status"])`` prints mode info."""
        main(["status"])
        captured = capsys.readouterr()
        assert "Mode:" in captured.out
        assert "Audit:" in captured.out
