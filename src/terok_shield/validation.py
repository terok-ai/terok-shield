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

SAFE_CONTAINER_ID = re.compile(r"^[0-9a-fA-F]{12,64}$")
"""Podman container id — hex only, 12 (short) to 64 (full UUID) chars.

Pure hex by construction: no path separators, no ``.``/``..``, no leading
slash — so a value matching this can be spliced into a filesystem path
without traversal risk.
"""


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


def validate_container_id(container_id: str) -> str:
    """Validate a podman container id against path-traversal and redirection.

    A container id is interpolated into the per-container hub socket path,
    so it must be a pure hex identifier — anything containing ``/``, ``..``,
    a leading slash, or other non-hex characters could escape the events
    directory or redirect the connection.

    Raises:
        ValueError: If the id is not a 12-to-64-char hex string.
    """
    if not SAFE_CONTAINER_ID.fullmatch(container_id):
        raise ValueError(f"Unsafe container id: {container_id!r}")
    return container_id


def parse_entries(text: str) -> list[str]:
    """Parse an allowlist text file into non-blank, non-comment lines."""
    return [
        line.strip()
        for line in text.splitlines()
        if (stripped := line.strip()) and not stripped.startswith("#")
    ]
