# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Allowlist profile loading and composition.

Finds, reads, and merges ``.txt`` allowlist profiles from user and
bundled directories.  User profiles override bundled ones with the
same name, so site-specific customisation works without forking.

Profiles are unified ``+``/``-`` policy files; a loaded profile yields
its admitted (``+``) targets, port and all, so a ``+localhost:PORT``
host-service grant survives into the authored tier.  The bundled profiles ship under
``resources/examples`` as samples a caller names explicitly; the curated
egress sets belong to terok, and the OS-package and provider hosts to
terok-executor.
"""
# WAYPOINT: Shield (__init__), HookMode (hooks.mode)

from importlib import resources as importlib_resources
from pathlib import Path

from .policy import parse_policy, render_target

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
        """Load a profile by name and return its admitted (``+``) ``target[:port]`` entries.

        User profiles take precedence over bundled profiles.

        Raises:
            UnknownProfileError: If no profile carries *name*; the message
                names the available profiles.
        """
        profiles = self._profile_paths()
        path = profiles.get(name)
        if path is None:
            available = ", ".join(sorted(profiles)) or "none"
            raise UnknownProfileError(f"Unknown profile {name!r}; available profiles: {available}")
        return [render_target(e) for e in parse_policy(path.read_text()) if e.action == "+"]

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
        return sorted(self._profile_paths())

    def _find_profile(self, name: str) -> Path | None:
        """Find a profile file by name.  User profiles override bundled."""
        return self._profile_paths().get(name)

    def _profile_paths(self) -> dict[str, Path]:
        """Map each available profile name to its file, user overriding bundled.

        Every name comes from the directory listing, never from a caller, so a
        requested name is matched against what exists rather than spliced into a
        path: a separator or a traversal simply names no profile.
        """
        return {
            path.stem: path
            for directory in (self._bundled_dir, self._user_dir)
            for path in directory.glob("*.txt")
        }


class UnknownProfileError(ValueError):
    """A requested name matches no profile, user or bundled."""


def _bundled_dir() -> Path:
    """Return the path to the bundled example profiles directory."""
    return Path(str(importlib_resources.files(_BUNDLED_PACKAGE)))
