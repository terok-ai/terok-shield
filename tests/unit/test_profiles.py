# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for profile loading and composition."""

import tempfile
import unittest
import unittest.mock
from pathlib import Path

from terok_shield.profiles import (
    _parse_entries,
    compose_profiles,
    list_profiles,
    load_profile,
)

from ..testnet import TEST_IP1


class TestParseEntries(unittest.TestCase):
    """Tests for _parse_entries."""

    def test_basic(self) -> None:
        """Parse domains and IPs from text."""
        text = f"example.com\n{TEST_IP1}\ntest.org\n"
        self.assertEqual(_parse_entries(text), ["example.com", TEST_IP1, "test.org"])

    def test_comments_stripped(self) -> None:
        """Skip comment lines."""
        text = "# comment\nexample.com\n# another\ntest.org\n"
        self.assertEqual(_parse_entries(text), ["example.com", "test.org"])

    def test_blank_lines_stripped(self) -> None:
        """Skip blank lines."""
        text = "\nexample.com\n\n\ntest.org\n\n"
        self.assertEqual(_parse_entries(text), ["example.com", "test.org"])

    def test_whitespace_stripped(self) -> None:
        """Strip leading/trailing whitespace from entries."""
        text = "  example.com  \n  test.org  \n"
        self.assertEqual(_parse_entries(text), ["example.com", "test.org"])

    def test_empty(self) -> None:
        """Empty text returns empty list."""
        self.assertEqual(_parse_entries(""), [])


class TestLoadProfile(unittest.TestCase):
    """Tests for load_profile."""

    def test_loads_bundled(self) -> None:
        """Load a bundled profile by name."""
        entries = load_profile("base")
        self.assertGreater(len(entries), 0)
        # base.txt should have known domains
        self.assertTrue(any("ntp" in e for e in entries))

    def test_loads_dev_standard(self) -> None:
        """Load the dev-standard bundled profile."""
        entries = load_profile("dev-standard")
        self.assertIn("github.com", entries)
        self.assertIn("pypi.org", entries)

    def test_not_found(self) -> None:
        """Raise FileNotFoundError for missing profiles."""
        with self.assertRaises(FileNotFoundError):
            load_profile("nonexistent-profile-xyz")

    def test_rejects_path_traversal(self) -> None:
        """Raise FileNotFoundError for path traversal names."""
        with self.assertRaises(FileNotFoundError):
            load_profile("../etc/passwd")

    def test_rejects_slash(self) -> None:
        """Raise FileNotFoundError for names with slashes."""
        with self.assertRaises(FileNotFoundError):
            load_profile("foo/bar")

    @unittest.mock.patch("terok_shield.profiles.shield_profiles_dir")
    def test_user_overrides_bundled(self, mock_dir: unittest.mock.Mock) -> None:
        """User profile with same name overrides bundled."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            user_file = Path(tmp) / "base.txt"
            user_file.write_text(f"custom.example.com\n{TEST_IP1}\n")
            entries = load_profile("base")
            self.assertEqual(entries, ["custom.example.com", TEST_IP1])


class TestComposeProfiles(unittest.TestCase):
    """Tests for compose_profiles."""

    def test_merges_and_deduplicates(self) -> None:
        """Merge multiple profiles and deduplicate entries."""
        entries = compose_profiles(["base", "dev-standard"])
        # Should contain entries from both
        self.assertTrue(any("ntp" in e for e in entries))
        self.assertIn("github.com", entries)
        # No duplicates
        self.assertEqual(len(entries), len(set(entries)))

    def test_preserves_order(self) -> None:
        """First occurrence wins for ordering."""
        entries = compose_profiles(["dev-standard", "dev-python"])
        # pypi.org appears in both; should stay ahead of dev-python-only entries
        self.assertLess(entries.index("pypi.org"), entries.index("conda.anaconda.org"))
        self.assertEqual(entries.count("pypi.org"), 1)

    def test_missing_profile_raises(self) -> None:
        """Raise FileNotFoundError if any profile is missing."""
        with self.assertRaises(FileNotFoundError):
            compose_profiles(["base", "nonexistent-xyz"])

    def test_empty_list(self) -> None:
        """Empty profile list returns empty entries."""
        self.assertEqual(compose_profiles([]), [])


class TestListProfiles(unittest.TestCase):
    """Tests for list_profiles."""

    def test_includes_bundled(self) -> None:
        """List includes all bundled profiles."""
        profiles = list_profiles()
        self.assertIn("base", profiles)
        self.assertIn("dev-standard", profiles)
        self.assertIn("dev-python", profiles)
        self.assertIn("dev-node", profiles)
        self.assertIn("nvidia-hpc", profiles)

    def test_sorted(self) -> None:
        """Profile list is sorted alphabetically."""
        profiles = list_profiles()
        self.assertEqual(profiles, sorted(profiles))

    @unittest.mock.patch("terok_shield.profiles.shield_profiles_dir")
    def test_includes_user_profiles(self, mock_dir: unittest.mock.Mock) -> None:
        """List includes user profiles alongside bundled."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_dir.return_value = Path(tmp)
            (Path(tmp) / "custom.txt").write_text("custom.example.com\n")
            profiles = list_profiles()
            self.assertIn("custom", profiles)
            self.assertIn("base", profiles)
