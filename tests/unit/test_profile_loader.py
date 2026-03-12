# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the ProfileLoader class."""

import tempfile
import unittest
from pathlib import Path

from terok_shield.profiles import ProfileLoader

from ..testfs import FAKE_PROFILES_DIR, FORBIDDEN_TRAVERSAL, NONEXISTENT_DIR
from ..testnet import CUSTOM_DOMAIN, TEST_DOMAIN, TEST_IP1


class TestProfileLoaderInit(unittest.TestCase):
    """Test ProfileLoader construction."""

    def test_direct_init(self) -> None:
        """Construct with explicit dirs."""
        loader = ProfileLoader(user_dir=FAKE_PROFILES_DIR)
        self.assertEqual(loader._user_dir, FAKE_PROFILES_DIR)
        self.assertIsNotNone(loader._bundled_dir)


class TestProfileLoaderFindProfile(unittest.TestCase):
    """Test ProfileLoader._find_profile()."""

    def test_finds_bundled(self) -> None:
        """Find a bundled profile by name."""
        loader = ProfileLoader(user_dir=NONEXISTENT_DIR)
        path = loader._find_profile("base")
        self.assertIsNotNone(path)
        self.assertEqual(path.stem, "base")

    def test_user_overrides_bundled(self) -> None:
        """User profile overrides bundled when both exist."""
        with tempfile.TemporaryDirectory() as tmp:
            user_file = Path(tmp) / "base.txt"
            user_file.write_text(f"{CUSTOM_DOMAIN}\n")
            loader = ProfileLoader(user_dir=Path(tmp))
            path = loader._find_profile("base")
            self.assertEqual(path, user_file)

    def test_returns_none_for_missing(self) -> None:
        """Return None for nonexistent profile."""
        loader = ProfileLoader(user_dir=NONEXISTENT_DIR)
        self.assertIsNone(loader._find_profile("nonexistent-profile-xyz"))

    def test_rejects_path_traversal(self) -> None:
        """Raise ValueError for path traversal names."""
        loader = ProfileLoader(user_dir=FAKE_PROFILES_DIR)
        with self.assertRaises(ValueError):
            loader._find_profile(FORBIDDEN_TRAVERSAL)


class TestProfileLoaderLoadProfile(unittest.TestCase):
    """Test ProfileLoader.load_profile()."""

    def test_loads_bundled(self) -> None:
        """Load a bundled profile."""
        loader = ProfileLoader(user_dir=NONEXISTENT_DIR)
        entries = loader.load_profile("base")
        self.assertGreater(len(entries), 0)

    def test_not_found_raises(self) -> None:
        """Raise FileNotFoundError for missing profile."""
        loader = ProfileLoader(user_dir=NONEXISTENT_DIR)
        with self.assertRaises(FileNotFoundError):
            loader.load_profile("nonexistent-xyz")

    def test_user_override(self) -> None:
        """User profile with same name overrides bundled."""
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "base.txt").write_text(f"{CUSTOM_DOMAIN}\n{TEST_IP1}\n")
            loader = ProfileLoader(user_dir=Path(tmp))
            entries = loader.load_profile("base")
            self.assertEqual(entries, [CUSTOM_DOMAIN, TEST_IP1])


class TestProfileLoaderComposeProfiles(unittest.TestCase):
    """Test ProfileLoader.compose_profiles()."""

    def test_merges_and_deduplicates(self) -> None:
        """Merge multiple profiles and deduplicate."""
        loader = ProfileLoader(user_dir=NONEXISTENT_DIR)
        entries = loader.compose_profiles(["base", "dev-standard"])
        self.assertTrue(any("ntp" in e for e in entries))
        self.assertIn(TEST_DOMAIN, entries)
        self.assertEqual(len(entries), len(set(entries)))

    def test_empty_list(self) -> None:
        """Empty profile list returns empty entries."""
        loader = ProfileLoader(user_dir=NONEXISTENT_DIR)
        self.assertEqual(loader.compose_profiles([]), [])


class TestProfileLoaderListProfiles(unittest.TestCase):
    """Test ProfileLoader.list_profiles()."""

    def test_includes_bundled(self) -> None:
        """List includes bundled profiles."""
        loader = ProfileLoader(user_dir=NONEXISTENT_DIR)
        profiles = loader.list_profiles()
        self.assertIn("base", profiles)
        self.assertIn("dev-standard", profiles)

    def test_includes_user_profiles(self) -> None:
        """List includes user profiles alongside bundled."""
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "custom.txt").write_text(f"{CUSTOM_DOMAIN}\n")
            loader = ProfileLoader(user_dir=Path(tmp))
            profiles = loader.list_profiles()
            self.assertIn("custom", profiles)
            self.assertIn("base", profiles)

    def test_sorted(self) -> None:
        """Profile list is sorted."""
        loader = ProfileLoader(user_dir=NONEXISTENT_DIR)
        profiles = loader.list_profiles()
        self.assertEqual(profiles, sorted(profiles))
