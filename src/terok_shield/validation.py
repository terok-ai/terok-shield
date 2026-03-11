# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared input validators for container and profile names.

Pure functions with no internal dependencies -- safe to import from any module.
Eliminates ``_SAFE_NAME`` / ``_SAFE_CONTAINER`` regex duplication across
audit.py, dns.py, profiles.py, and oci_hook.py.
"""

import re

SAFE_CONTAINER = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
"""Container name pattern -- allows leading underscore (podman convention)."""

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

    Stricter than container names -- no leading underscore.

    Raises:
        ValueError: If the name contains path separators or other unsafe chars.
    """
    if not SAFE_NAME.fullmatch(name):
        raise ValueError(f"Unsafe name: {name!r}")
    return name


def parse_entries(text: str) -> list[str]:
    """Parse a text file into a list of non-blank, non-comment lines.

    Strips leading/trailing whitespace from each line.
    Lines starting with ``#`` (after stripping) are treated as comments.
    """
    return [
        line.strip()
        for line in text.splitlines()
        if (stripped := line.strip()) and not stripped.startswith("#")
    ]
