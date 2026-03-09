# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: shield_resolve() and CLI resolve."""

from pathlib import Path

import pytest

from terok_shield import shield_resolve
from terok_shield.cli import main
from tests.testnet import TEST_IP4

# ── Public API resolve ───────────────────────────────────


@pytest.mark.needs_internet
class TestShieldResolve:
    """Verify ``shield_resolve()`` resolves DNS profiles."""

    def test_resolve_returns_ips(self, shield_env: Path) -> None:
        """``shield_resolve()`` returns a list of IPs."""
        ips = shield_resolve("resolve-test-ctr")
        assert len(ips) > 0, "Resolve should return at least one IP"
        for ip in ips:
            assert isinstance(ip, str)

    def test_resolve_creates_cache(self, shield_env: Path) -> None:
        """A cache file exists after ``shield_resolve()``."""
        shield_resolve("cache-test-ctr")

        resolved_dir = shield_env / "resolved"
        assert resolved_dir.is_dir()
        cache_files = list(resolved_dir.iterdir())
        assert any("cache-test-ctr" in f.name for f in cache_files)

    def test_resolve_force_bypasses_cache(self, shield_env: Path) -> None:
        """``force=True`` re-resolves even if cache is fresh."""
        # Seed the cache with a sentinel IP that real DNS will never return
        resolved_dir = shield_env / "resolved"
        resolved_dir.mkdir(exist_ok=True)
        cache_file = resolved_dir / "force-test-ctr.resolved"
        cache_file.write_text(f"{TEST_IP4}\n")

        ips = shield_resolve("force-test-ctr", force=True)

        assert ips, "Force-resolve should return at least one IP"
        assert TEST_IP4 not in ips, "Sentinel IP should be replaced by real resolution"
        assert TEST_IP4 not in cache_file.read_text(), "Cache should be overwritten"


# ── CLI resolve ──────────────────────────────────────────


@pytest.mark.needs_internet
class TestCLIResolve:
    """Verify ``terok-shield resolve`` via CLI."""

    def test_cli_resolve(self, shield_env: Path, capsys: pytest.CaptureFixture) -> None:
        """``main(["resolve", container])`` prints resolved IP count."""
        main(["resolve", "cli-resolve-test"])
        captured = capsys.readouterr()
        assert "Resolved" in captured.out
        assert "cli-resolve-test" in captured.out
