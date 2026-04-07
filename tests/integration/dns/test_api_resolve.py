# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: Shield.resolve() and CLI resolve."""

from pathlib import Path

import pytest

from terok_shield import Shield, ShieldConfig, state
from terok_shield.cli.main import main
from tests.testnet import TEST_IP4

# -- Public API resolve ---------------------------------------


@pytest.mark.needs_internet
class TestShieldResolve:
    """Verify ``Shield.resolve()`` resolves DNS profiles."""

    def test_resolve_returns_ips(self, shield_env: Path) -> None:
        """``Shield.resolve()`` returns a list of IPs."""
        sd = shield_env / "containers" / "resolve-test-ctr"
        ips = Shield(ShieldConfig(state_dir=sd)).resolve()
        assert len(ips) > 0, "Resolve should return at least one IP"
        for ip in ips:
            assert isinstance(ip, str)

    def test_resolve_creates_cache(self, shield_env: Path) -> None:
        """A profile.allowed file exists after ``Shield.resolve()``."""
        sd = shield_env / "containers" / "cache-test-ctr"
        Shield(ShieldConfig(state_dir=sd)).resolve()

        allowed = state.profile_allowed_path(sd)
        assert allowed.is_file(), "profile.allowed should be created"

    def test_resolve_force_bypasses_cache(self, shield_env: Path) -> None:
        """``force=True`` re-resolves even if cache is fresh."""
        sd = shield_env / "containers" / "force-test-ctr"
        sd.mkdir(parents=True, exist_ok=True)
        cache_file = state.profile_allowed_path(sd)
        cache_file.write_text(f"{TEST_IP4}\n")

        ips = Shield(ShieldConfig(state_dir=sd)).resolve(force=True)

        assert ips, "Force-resolve should return at least one IP"
        assert TEST_IP4 not in ips, "Sentinel IP should be replaced by real resolution"
        assert TEST_IP4 not in cache_file.read_text(), "Cache should be overwritten"


# -- CLI resolve ----------------------------------------------


@pytest.mark.needs_internet
class TestCLIResolve:
    """Verify ``terok-shield resolve`` via CLI."""

    def test_cli_resolve(self, shield_env: Path, capsys: pytest.CaptureFixture) -> None:
        """``main(["resolve", container])`` prints resolved IP count."""
        main(["resolve", "cli-resolve-test"])
        captured = capsys.readouterr()
        assert "Resolved" in captured.out
        assert "cli-resolve-test" in captured.out
