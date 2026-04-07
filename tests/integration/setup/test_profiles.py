# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: bundled profile loading (no network required)."""

import tempfile
from pathlib import Path

import pytest

from terok_shield.profiles import ProfileLoader


@pytest.mark.needs_host_features
class TestProfilesLive:
    """Verify bundled profiles load correctly and contain expected entries."""

    def test_all_bundled_profiles_load(self) -> None:
        """Every listed profile loads without error."""
        with tempfile.TemporaryDirectory() as tmp:
            loader = ProfileLoader(user_dir=Path(tmp) / "profiles")
            for name in loader.list_profiles():
                entries = loader.load_profile(name)
                assert len(entries) > 0, f"Profile {name!r} is empty"

    def test_base_profile_entries(self) -> None:
        """Base profile has NTP and DNS infrastructure."""
        with tempfile.TemporaryDirectory() as tmp:
            loader = ProfileLoader(user_dir=Path(tmp) / "profiles")
            entries = loader.load_profile("base")
            # Should have pool.ntp.org for NTP
            assert any("ntp" in e for e in entries)
            # Should have OCSP/CRL for TLS validation
            assert any("ocsp" in e or "crl" in e for e in entries)

    def test_compose_deduplicates(self) -> None:
        """Composing all profiles yields no duplicates."""
        with tempfile.TemporaryDirectory() as tmp:
            loader = ProfileLoader(user_dir=Path(tmp) / "profiles")
            all_names = loader.list_profiles()
            entries = loader.compose_profiles(all_names)
            assert len(entries) == len(set(entries)), "Duplicates found in composed profiles"
