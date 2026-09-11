# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the ProfileLoader class."""

from pathlib import Path

import pytest

from terok_shield.profiles import ProfileLoader, UnknownProfileError

from ..testfs import FAKE_PROFILES_DIR, FORBIDDEN_TRAVERSAL, NONEXISTENT_DIR
from ..testnet import CUSTOM_DOMAIN, DEV_PYPI_DOMAIN, TEST_DOMAIN, TEST_IP1
from .helpers import write_lines


def test_profile_loader_stores_user_dir() -> None:
    """Construction keeps the requested user profile directory."""
    loader = ProfileLoader(user_dir=FAKE_PROFILES_DIR)
    assert loader._user_dir == FAKE_PROFILES_DIR
    assert loader._bundled_dir is not None


@pytest.mark.parametrize(
    ("name", "expected_stem"),
    [
        pytest.param("base", "base", id="bundled-profile"),
        pytest.param("nonexistent-profile-xyz", None, id="missing-profile"),
    ],
)
def test_find_profile_uses_bundled_profiles(name: str, expected_stem: str | None) -> None:
    """_find_profile() returns bundled profiles and None for missing ones."""
    path = ProfileLoader(user_dir=NONEXISTENT_DIR)._find_profile(name)
    assert path.stem == expected_stem if path is not None else expected_stem is None


def test_find_profile_prefers_user_overrides(tmp_path: Path) -> None:
    """User-provided profiles override bundled profiles of the same name."""
    user_file = write_lines(tmp_path / "base.txt", [CUSTOM_DOMAIN])
    assert ProfileLoader(user_dir=tmp_path)._find_profile("base") == user_file


@pytest.mark.parametrize(
    "name",
    [
        pytest.param(FORBIDDEN_TRAVERSAL, id="path-traversal"),
        pytest.param("_hidden", id="leading-underscore"),
        pytest.param(".hidden", id="leading-dot"),
        pytest.param("-flag", id="leading-dash"),
        pytest.param("", id="empty"),
    ],
)
def test_find_profile_names_no_profile_for_unsafe_names(name: str) -> None:
    """An unsafe name names no profile: the lookup never builds a path from it."""
    assert ProfileLoader(user_dir=FAKE_PROFILES_DIR)._find_profile(name) is None


def test_load_profile_reads_bundled_profile() -> None:
    """load_profile() reads bundled profile contents."""
    assert len(ProfileLoader(user_dir=NONEXISTENT_DIR).load_profile("base")) > 0


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("nonexistent-xyz", id="missing"),
        pytest.param(FORBIDDEN_TRAVERSAL, id="path-traversal"),
    ],
)
def test_load_profile_names_the_available_profiles_for_an_unknown_name(name: str) -> None:
    """load_profile() refuses a name that carries no profile and lists the profiles that exist."""
    with pytest.raises(UnknownProfileError, match="available profiles: .*dev-standard"):
        ProfileLoader(user_dir=NONEXISTENT_DIR).load_profile(name)


def test_load_profile_uses_user_override(tmp_path: Path) -> None:
    """load_profile() prefers user profiles over bundled ones."""
    write_lines(tmp_path / "base.txt", [f"+{CUSTOM_DOMAIN}", f"+{TEST_IP1}"])
    assert ProfileLoader(user_dir=tmp_path).load_profile("base") == [CUSTOM_DOMAIN, TEST_IP1]


def test_compose_profiles_merges_and_deduplicates() -> None:
    """compose_profiles() merges multiple profiles while deduplicating entries."""
    entries = ProfileLoader(user_dir=NONEXISTENT_DIR).compose_profiles(["base", "dev-standard"])
    assert any("ntp" in entry for entry in entries)
    assert TEST_DOMAIN in entries
    assert len(entries) == len(set(entries))


def test_compose_profiles_returns_empty_for_empty_input() -> None:
    """compose_profiles() short-circuits when no profile names are given."""
    assert ProfileLoader(user_dir=NONEXISTENT_DIR).compose_profiles([]) == []


def test_list_profiles_includes_bundled_profiles() -> None:
    """list_profiles() includes bundled profile names."""
    profiles = ProfileLoader(user_dir=NONEXISTENT_DIR).list_profiles()
    assert "base" in profiles
    assert "dev-standard" in profiles
    assert "krun_guest" in profiles


def test_krun_guest_profile_minimal() -> None:
    """krun_guest profile is intentionally tight — NTP + distro updates only."""
    entries = ProfileLoader(user_dir=NONEXISTENT_DIR).load_profile("krun_guest")
    assert any("ntp" in entry for entry in entries)
    # Sanity: it must not have grown to include developer-grade egress.
    # If this fails, ask whether the addition really belongs on krun guests.
    assert TEST_DOMAIN not in entries
    assert DEV_PYPI_DOMAIN not in entries


def test_list_profiles_includes_user_profiles(tmp_path: Path) -> None:
    """list_profiles() merges user and bundled profile names."""
    write_lines(tmp_path / "custom.txt", [CUSTOM_DOMAIN])
    profiles = ProfileLoader(user_dir=tmp_path).list_profiles()
    assert "custom" in profiles
    assert "base" in profiles


def test_list_profiles_is_sorted() -> None:
    """list_profiles() returns profile names in sorted order."""
    profiles = ProfileLoader(user_dir=NONEXISTENT_DIR).list_profiles()
    assert profiles == sorted(profiles)
