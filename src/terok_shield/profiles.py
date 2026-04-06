# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Allowlist profile loading and composition.

Finds, reads, and merges ``.txt`` allowlist profiles from user and
bundled directories.  User profiles override bundled ones with the
same name, so site-specific customisation works without forking.
"""
# WAYPOINT: Shield (__init__), HookMode (mode_hook)

from importlib import resources as importlib_resources
from pathlib import Path

from .validation import parse_entries as _parse_entries, validate_safe_name

_BUNDLED_PACKAGE = "terok_shield.resources.dns"


class ProfileLoader:
    """Loads and composes .txt allowlist profiles.

    Searches user profiles first (overriding bundled), then falls
    back to the bundled profiles shipped with the package.
    """

    def __init__(
        self,
        *,
        user_dir: Path,
        bundled_dir: Path | None = None,
    ) -> None:
        """Create a profile loader.

        Args:
            user_dir: User profiles directory (overrides bundled).
            bundled_dir: Bundled profiles directory (auto-detected if None).
        """
        self._user_dir = user_dir
        self._bundled_dir = bundled_dir or _bundled_dir()

    def load_profile(self, name: str) -> list[str]:
        """Load a profile by name and return its entries.

        User profiles take precedence over bundled profiles.

        Raises:
            ValueError: If the name contains path separators or traversal.
            FileNotFoundError: If the profile does not exist.
        """
        path = self._find_profile(name)
        if path is None:
            raise FileNotFoundError(f"Profile not found: {name!r}")
        return _parse_entries(path.read_text())

    def compose_profiles(self, names: list[str]) -> list[str]:
        """Load and merge multiple profiles, deduplicating entries.

        Preserves insertion order (first occurrence wins).

        Raises:
            ValueError: If any name contains path separators or traversal.
            FileNotFoundError: If any named profile does not exist.
        """
        seen: set[str] = set()
        result: list[str] = []
        for name in names:
            for entry in self.load_profile(name):
                if entry not in seen:
                    seen.add(entry)
                    result.append(entry)
        return result

    def list_profiles(self) -> list[str]:
        """List available profile names (bundled + user, deduplicated)."""
        names: set[str] = set()
        for directory in (self._bundled_dir, self._user_dir):
            if directory.is_dir():
                names.update(f.stem for f in directory.glob("*.txt"))
        return sorted(names)

    def _find_profile(self, name: str) -> Path | None:
        """Find a profile file by name.  User profiles override bundled."""
        validate_safe_name(name)
        user_path = self._user_dir / f"{name}.txt"
        if user_path.is_file():
            return user_path
        bundled_path = self._bundled_dir / f"{name}.txt"
        if bundled_path.is_file():
            return bundled_path
        return None


def _bundled_dir() -> Path:
    """Return the path to the bundled DNS allowlists directory."""
    return Path(str(importlib_resources.files(_BUNDLED_PACKAGE)))
