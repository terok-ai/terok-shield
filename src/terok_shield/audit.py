# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Structured audit logging for shield (JSON-lines format).

Provides ``AuditLogger`` -- owns an audit file path and an enabled
flag, writes JSON-lines entries to a single per-container file.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path


class AuditLogger:
    """JSON-lines audit logger for a single container.

    Writes to a single file (``audit_path``).  When disabled, all
    write operations are no-ops.
    """

    def __init__(self, *, audit_path: Path, enabled: bool = True) -> None:
        """Create an audit logger.

        Args:
            audit_path: Path to the ``.jsonl`` audit log file.
            enabled: Whether logging is active (can be toggled later).
        """
        self._audit_path = audit_path
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        """Whether audit logging is active."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        """Toggle audit logging on or off."""
        self._enabled = value

    def log_event(
        self,
        container: str,
        action: str,
        *,
        dest: str | None = None,
        detail: str | None = None,
    ) -> None:
        """Write a single audit event to the log file.

        No-op when audit is disabled.

        Args:
            container: Container name.
            action: Event type (setup, teardown, allowed, denied).
            dest: Destination IP/domain (optional).
            detail: Additional detail string (optional).
        """
        if not self._enabled:
            return
        entry: dict = {
            "ts": datetime.now(UTC).isoformat(timespec="seconds"),
            "container": container,
            "action": action,
        }
        if dest is not None:
            entry["dest"] = dest
        if detail is not None:
            entry["detail"] = detail

        try:
            self._audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self._audit_path.open("a") as f:
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        except OSError:
            pass  # audit logging is best-effort

    def tail_log(self, n: int = 50) -> Iterator[dict]:
        """Yield the last *n* audit events.

        Args:
            n: Number of recent events to yield.
        """
        if not self._audit_path.is_file():
            return

        lines = self._audit_path.read_text().splitlines()
        for line in lines[-n:] if n > 0 else []:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
