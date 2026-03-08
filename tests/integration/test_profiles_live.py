# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: profile loading → DNS resolution → cache pipeline."""


import shutil
import tempfile
from pathlib import Path

import pytest

from terok_shield.dns import resolve_and_cache
from terok_shield.profiles import compose_profiles, list_profiles, load_profile

from ..testnet import CLOUDFLARE_DOMAIN, TEST_IP99

dig_missing = pytest.mark.skipif(not shutil.which("dig"), reason="dig not installed")


@pytest.mark.integration
class TestProfilesLive:
    """Verify bundled profiles load correctly and contain expected entries."""

    def test_all_bundled_profiles_load(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Every listed profile loads without error."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_CONFIG_DIR", tmp)
            for name in list_profiles():
                entries = load_profile(name)
                assert len(entries) > 0, f"Profile {name!r} is empty"

    def test_base_profile_entries(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Base profile has NTP and DNS infrastructure."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_CONFIG_DIR", tmp)
            entries = load_profile("base")
            # Should have pool.ntp.org for NTP
            assert any("ntp" in e for e in entries)
            # Should have OCSP/CRL for TLS validation
            assert any("ocsp" in e or "crl" in e for e in entries)

    def test_compose_deduplicates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Composing all profiles yields no duplicates."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_CONFIG_DIR", tmp)
            all_names = list_profiles()
            entries = compose_profiles(all_names)
            assert len(entries) == len(set(entries)), "Duplicates found in composed profiles"


@pytest.mark.integration
@dig_missing
class TestProfileResolvePipeline:
    """Full pipeline: load profile → resolve domains → cache."""

    def test_base_profile_resolves(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Entries from base profile resolve to at least some IPs."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            entries = load_profile("base")
            ips = resolve_and_cache(entries, "profile-itest")
            assert len(ips) > 0, "Base profile should resolve to at least one IP"
            cache = Path(tmp) / "resolved" / "profile-itest.resolved"
            assert cache.is_file(), "Cache file should be written"

    def test_dev_standard_resolves_github(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """dev-standard profile resolves github.com."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            entries = load_profile("dev-standard")
            ips = resolve_and_cache(entries, "devstd-itest")
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

            entries = load_profile("custom")
            assert entries == [CLOUDFLARE_DOMAIN, TEST_IP99]

            ips = resolve_and_cache(entries, "custom-itest")
            assert TEST_IP99 in ips  # raw IP passes through
            assert len(ips) >= 2  # resolved + raw
