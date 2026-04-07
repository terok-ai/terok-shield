# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Input validators for container names, profile names, and allowlist files.

Pure functions with no internal dependencies — safe to import from any module.
"""

import re

SAFE_CONTAINER = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
"""Container name pattern — allows leading underscore (podman convention)."""

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
"""Strict name pattern for profiles, cache keys, etc."""


def validate_container_name(name: str) -> str:
    """Validate a container name against path-traversal and injection.

    Raises:
        ValueError: If the name contains path separators or other unsafe chars.
    """
    if not SAFE_CONTAINER.fullmatch(name):
        raise ValueError(f"Unsafe container name: {name!r}")
    return name


def validate_safe_name(name: str) -> str:
    """Validate a generic safe name (profiles, cache keys).

    Stricter than container names — no leading underscore.

    Raises:
        ValueError: If the name contains path separators or other unsafe chars.
    """
    if not SAFE_NAME.fullmatch(name):
        raise ValueError(f"Unsafe name: {name!r}")
    return name


def parse_entries(text: str) -> list[str]:
    """Parse an allowlist text file into non-blank, non-comment lines."""
    return [
        line.strip()
        for line in text.splitlines()
        if (stripped := line.strip()) and not stripped.startswith("#")
    ]
