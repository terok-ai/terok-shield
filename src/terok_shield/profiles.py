# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Allowlist profile loading and composition.

Finds, reads, and merges ``.txt`` allowlist profiles from user and
bundled directories.  User profiles override bundled ones with the
same name, so site-specific customisation works without forking.

Profiles are unified ``+``/``-`` policy files; a loaded profile yields
its admitted (``+``) targets.  The bundled profiles ship under
``resources/examples`` as samples a caller names explicitly; the curated
egress sets belong to terok, and the OS-package and provider hosts to
terok-executor.
"""
# WAYPOINT: Shield (__init__), HookMode (hooks.mode)

from importlib import resources as importlib_resources
from pathlib import Path

from .policy import parse_policy
from .validation import SAFE_NAME

_BUNDLED_PACKAGE = "terok_shield.resources.examples"


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
        """Load a profile by name and return its admitted (``+``) targets.

        User profiles take precedence over bundled profiles.

        Raises:
            UnknownProfileError: If no profile carries *name*; the message
                names the available profiles.
        """
        path = self._find_profile(name)
        if path is None:
            available = ", ".join(self.list_profiles()) or "none"
            raise UnknownProfileError(f"Unknown profile {name!r}; available profiles: {available}")
        return [e.target for e in parse_policy(path.read_text()) if e.action == "+"]

    def compose_profiles(self, names: list[str]) -> list[str]:
        """Load and merge multiple profiles, deduplicating entries.

        Preserves insertion order (first occurrence wins).

        Raises:
            UnknownProfileError: If any name carries no profile.
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
        """Find a profile file by name.  User profiles override bundled.

        A name outside [`SAFE_NAME`][terok_shield.validation.SAFE_NAME] — a
        path separator, a traversal — names no profile, so the lookup never
        builds a path from it.
        """
        if not SAFE_NAME.fullmatch(name):
            return None
        user_path = self._user_dir / f"{name}.txt"
        if user_path.is_file():
            return user_path
        bundled_path = self._bundled_dir / f"{name}.txt"
        if bundled_path.is_file():
            return bundled_path
        return None


class UnknownProfileError(ValueError):
    """A requested name matches no profile, user or bundled."""


def _bundled_dir() -> Path:
    """Return the path to the bundled example profiles directory."""
    return Path(str(importlib_resources.files(_BUNDLED_PACKAGE)))
