# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Profile loading and composition from .txt allowlists."""

import re
from importlib import resources as importlib_resources
from pathlib import Path

from .config import shield_profiles_dir

_BUNDLED_PACKAGE = "terok_shield.resources.dns"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _bundled_dir() -> Path:
    """Return the path to the bundled DNS allowlists directory."""
    return Path(str(importlib_resources.files(_BUNDLED_PACKAGE)))


def _parse_entries(text: str) -> list[str]:
    """Parse a profile .txt file into a list of entries.

    Strips comments (lines starting with ``#``) and blank lines.
    """
    return [
        line.strip()
        for line in text.splitlines()
        if (stripped := line.strip()) and not stripped.startswith("#")
    ]


def _find_profile(name: str) -> Path | None:
    """Find a profile file by name.  User profiles override bundled ones.

    Returns None for names containing path separators or traversal sequences.
    """
    if not _SAFE_NAME.fullmatch(name):
        return None
    user_path = shield_profiles_dir() / f"{name}.txt"
    if user_path.is_file():
        return user_path
    bundled_path = _bundled_dir() / f"{name}.txt"
    if bundled_path.is_file():
        return bundled_path
    return None


def load_profile(name: str) -> list[str]:
    """Load a profile by name and return its entries.

    User profiles in ``shield_profiles_dir()`` take precedence over
    bundled profiles in ``resources/dns/``.

    Raises:
        FileNotFoundError: If the profile does not exist.
    """
    path = _find_profile(name)
    if path is None:
        raise FileNotFoundError(f"Profile not found: {name!r}")
    return _parse_entries(path.read_text())


def compose_profiles(names: list[str]) -> list[str]:
    """Load and merge multiple profiles, deduplicating entries.

    Preserves insertion order (first occurrence wins).

    Raises:
        FileNotFoundError: If any named profile does not exist.
    """
    seen: set[str] = set()
    result: list[str] = []
    for name in names:
        for entry in load_profile(name):
            if entry not in seen:
                seen.add(entry)
                result.append(entry)
    return result


def list_profiles() -> list[str]:
    """List available profile names (bundled + user, deduplicated)."""
    names: set[str] = set()
    for directory in (_bundled_dir(), shield_profiles_dir()):
        if directory.is_dir():
            names.update(f.stem for f in directory.glob("*.txt"))
    return sorted(names)
