# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for ``shield_status()`` — no podman or internet needed."""

from pathlib import Path

import pytest

from terok_shield import shield_status


@pytest.mark.needs_host_features
class TestShieldStatus:
    """Verify ``shield_status()`` returns expected structure."""

    def test_status_returns_dict(self, shield_env: Path) -> None:
        """Status dict contains expected keys."""
        status = shield_status()
        assert isinstance(status, dict)
        assert "mode" in status
        assert "profiles" in status
        assert "audit_enabled" in status
        assert "log_files" in status
        assert isinstance(status["profiles"], list)
