# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: profile loading → DNS resolution → cache pipeline."""

import tempfile
from pathlib import Path

import pytest

from terok_shield import state
from terok_shield.dns.resolver import DnsResolver
from terok_shield.profiles import ProfileLoader
from terok_shield.run import SubprocessRunner
from tests.testnet import CLOUDFLARE_DOMAIN, TEST_IP99

from ..conftest import dig_missing


@pytest.mark.needs_internet
@dig_missing
class TestProfileResolvePipeline:
    """Full pipeline: load profile → resolve domains → cache."""

    def test_base_profile_resolves(self) -> None:
        """Entries from base profile resolve to at least some IPs."""
        with tempfile.TemporaryDirectory() as tmp:
            loader = ProfileLoader(user_dir=Path(tmp) / "profiles")
            runner = SubprocessRunner()
            resolver = DnsResolver(runner=runner)
            entries = loader.load_profile("base")
            cache_path = state.profile_allowed_path(Path(tmp))
            ips = resolver.resolve_and_cache(entries, cache_path)
            assert len(ips) > 0, "Base profile should resolve to at least one IP"
            assert cache_path.is_file(), "Cache file should be written"

    def test_dev_standard_resolves_github(self) -> None:
        """dev-standard profile resolves github.com."""
        with tempfile.TemporaryDirectory() as tmp:
            loader = ProfileLoader(user_dir=Path(tmp) / "profiles")
            runner = SubprocessRunner()
            resolver = DnsResolver(runner=runner)
            entries = loader.load_profile("dev-standard")
            cache_path = state.profile_allowed_path(Path(tmp))
            ips = resolver.resolve_and_cache(entries, cache_path)
            # github.com should resolve to at least one IP
            assert len(ips) > 0

    def test_user_profile_override(self) -> None:
        """User profile with custom entries overrides bundled."""
        with tempfile.TemporaryDirectory() as tmp:
            profiles_dir = Path(tmp) / "profiles"
            profiles_dir.mkdir()
            (profiles_dir / "custom.txt").write_text(f"{CLOUDFLARE_DOMAIN}\n{TEST_IP99}\n")

            loader = ProfileLoader(user_dir=profiles_dir)
            runner = SubprocessRunner()
            resolver = DnsResolver(runner=runner)
            entries = loader.load_profile("custom")
            assert entries == [CLOUDFLARE_DOMAIN, TEST_IP99]

            cache_path = state.profile_allowed_path(Path(tmp))
            ips = resolver.resolve_and_cache(entries, cache_path)
            assert TEST_IP99 in ips  # raw IP passes through
            assert len(ips) >= 2  # resolved + raw
