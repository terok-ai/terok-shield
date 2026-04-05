# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tail ``audit.jsonl`` and emit events for shield lifecycle changes.

Watches for new JSON-lines entries written by
:class:`~terok_shield.lib.audit.AuditLogger` and surfaces them as
:class:`WatchEvent` instances with ``source="audit"``.
"""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from ._event import WatchEvent


class AuditLogWatcher:
    """Tail ``audit.jsonl`` and yield events for shield lifecycle changes."""

    def __init__(self, audit_path: Path, container: str) -> None:
        """Open *audit_path* and seek to end.

        Args:
            audit_path: Path to the per-container ``audit.jsonl`` file.
            container: Container name (for event metadata).
        """
        self._audit_path = audit_path
        self._container = container
        audit_path.touch(exist_ok=True)
        self._fh = open(audit_path)  # noqa: SIM115 — needs fileno() for select
        self._fh.seek(0, os.SEEK_END)

    def fileno(self) -> int:
        """Return the file descriptor for ``select.select()`` multiplexing."""
        return self._fh.fileno()

    def close(self) -> None:
        """Close the underlying file handle."""
        self._fh.close()

    def poll(self) -> list[WatchEvent]:
        """Read new audit lines and return watch events."""
        events: list[WatchEvent] = []
        while line := self._fh.readline():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue
            events.append(
                WatchEvent(
                    ts=entry.get("ts", datetime.now(UTC).isoformat()),
                    source="audit",
                    action=entry.get("action", "unknown"),
                    container=entry.get("container", self._container),
                    dest=entry.get("dest", ""),
                    detail=entry.get("detail", ""),
                )
            )
        return events
