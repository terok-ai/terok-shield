# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: profile loading → DNS resolution → cache pipeline."""

import tempfile
from pathlib import Path

import pytest

from terok_shield.dns import DnsResolver
from terok_shield.profiles import ProfileLoader
from terok_shield.run import SubprocessRunner
from tests.testnet import CLOUDFLARE_DOMAIN, TEST_IP99

from ..conftest import dig_missing


@pytest.mark.needs_internet
@dig_missing
class TestProfileResolvePipeline:
    """Full pipeline: load profile → resolve domains → cache."""

    def test_base_profile_resolves(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Entries from base profile resolve to at least some IPs."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            loader = ProfileLoader(user_dir=Path(tmp) / "profiles")
            runner = SubprocessRunner()
            resolver = DnsResolver(resolved_dir=Path(tmp) / "resolved", runner=runner)
            entries = loader.load_profile("base")
            ips = resolver.resolve_and_cache(entries, "profile-itest")
            assert len(ips) > 0, "Base profile should resolve to at least one IP"
            cache = Path(tmp) / "resolved" / "profile-itest.resolved"
            assert cache.is_file(), "Cache file should be written"

    def test_dev_standard_resolves_github(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """dev-standard profile resolves github.com."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            loader = ProfileLoader(user_dir=Path(tmp) / "profiles")
            runner = SubprocessRunner()
            resolver = DnsResolver(resolved_dir=Path(tmp) / "resolved", runner=runner)
            entries = loader.load_profile("dev-standard")
            ips = resolver.resolve_and_cache(entries, "devstd-itest")
            # github.com should resolve to at least one IP
            assert len(ips) > 0

    def test_user_profile_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """User profile with custom entries overrides bundled."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            monkeypatch.setenv("TEROK_SHIELD_CONFIG_DIR", tmp)
            profiles_dir = Path(tmp) / "profiles"
            profiles_dir.mkdir()
            (profiles_dir / "custom.txt").write_text(f"{CLOUDFLARE_DOMAIN}\n{TEST_IP99}\n")

            loader = ProfileLoader(user_dir=profiles_dir)
            runner = SubprocessRunner()
            resolver = DnsResolver(resolved_dir=Path(tmp) / "resolved", runner=runner)
            entries = loader.load_profile("custom")
            assert entries == [CLOUDFLARE_DOMAIN, TEST_IP99]

            ips = resolver.resolve_and_cache(entries, "custom-itest")
            assert TEST_IP99 in ips  # raw IP passes through
            assert len(ips) >= 2  # resolved + raw
