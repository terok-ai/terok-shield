# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: bundled profile loading (no network required)."""

import tempfile

import pytest

from terok_shield.profiles import compose_profiles, list_profiles, load_profile


@pytest.mark.needs_host_features
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
