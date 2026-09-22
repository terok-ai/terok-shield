# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: Shield.resolve() and CLI resolve."""

from pathlib import Path

import pytest

from terok_shield import DnsTier, Shield, ShieldConfig
from terok_shield.cli.main import main
from tests.testnet import TEST_IP4


def _author_static_tier_bundle(state_dir: Path) -> None:
    """Leave *state_dir* the way a launch on a static DNS tier would: dev-standard's hosts in t40."""
    bundle = StateBundle(state_dir)
    bundle.ensure_dirs()
    bundle.dns_tier.write_text(f"{DnsTier.GETENT.value}\n")
    hosts = Shield(ShieldConfig(state_dir=state_dir)).compose_profiles(["dev-standard"])
    bundle.write_tier("project_allow", "".join(f"+{host}\n" for host in hosts))


# -- Public API resolve ---------------------------------------


@pytest.mark.needs_internet
class TestShieldResolve:
    """Verify ``Shield.resolve()`` re-resolves an authored policy."""

    def test_resolve_returns_ips(self, shield_env: Path) -> None:
        """``Shield.resolve()`` returns a list of IPs."""
        sd = shield_env / "containers" / "resolve-test-ctr"
        _author_static_tier_bundle(sd)
        ips = Shield(ShieldConfig(state_dir=sd)).resolve()
        assert len(ips) > 0, "Resolve should return at least one IP"
        for ip in ips:
            assert isinstance(ip, str)

    def test_resolve_creates_cache(self, shield_env: Path) -> None:
        """A resolved.ips cache file exists after ``Shield.resolve()``."""
        sd = shield_env / "containers" / "cache-test-ctr"
        _author_static_tier_bundle(sd)
        Shield(ShieldConfig(state_dir=sd)).resolve()

        allowed = StateBundle(sd).resolved_cache
        assert allowed.is_file(), "resolved.ips should be created"

    def test_resolve_force_ignores_fresh_cache(self, shield_env: Path) -> None:
        """``force=True`` re-resolves even if cache is fresh."""
        sd = shield_env / "containers" / "force-test-ctr"
        _author_static_tier_bundle(sd)
        cache_file = StateBundle(sd).resolved_cache
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
        _author_static_tier_bundle(shield_env / "containers" / "cli-resolve-test")
        main(["--state-dir", str(shield_env), "resolve", "cli-resolve-test"])
        captured = capsys.readouterr()
        assert "Resolved" in captured.out
        assert "cli-resolve-test" in captured.out


from terok_shield.state import StateBundle
