# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Structured audit logging for shield (JSON-lines format).

Provides ``AuditLogger`` (Service pattern) -- owns a logs directory and
an enabled flag, writes JSON-lines per container.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Self

from .config import ShieldConfig
from .validation import validate_container_name


class AuditLogger:
    """Service: JSON-lines audit logger scoped to a logs directory.

    Each container gets its own ``<container>.jsonl`` file.
    When disabled, all write operations are no-ops.
    """

    def __init__(self, *, logs_dir: Path, enabled: bool = True) -> None:
        """Create an audit logger.

        Args:
            logs_dir: Directory for per-container ``.jsonl`` files.
            enabled: Whether logging is active (can be toggled later).
        """
        self._logs_dir = logs_dir
        self._enabled = enabled

    @classmethod
    def from_config(cls, config: ShieldConfig) -> Self:
        """Construct from a ``ShieldConfig``, reading paths and audit flag."""
        return cls(logs_dir=config.paths.logs_dir, enabled=config.audit_enabled)

    @property
    def enabled(self) -> bool:
        """Whether audit logging is active."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        """Toggle audit logging on or off."""
        self._enabled = value

    def _log_path(self, container: str) -> Path:
        """Return the audit log path for a container.

        Raises ValueError if the container name is unsafe.
        """
        validate_container_name(container)
        self._logs_dir.mkdir(parents=True, exist_ok=True)
        return self._logs_dir / f"{container}.jsonl"

    def log_event(
        self,
        container: str,
        action: str,
        *,
        dest: str | None = None,
        detail: str | None = None,
    ) -> None:
        """Write a single audit event to the container's log file.

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
            with self._log_path(container).open("a") as f:
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        except OSError:
            pass  # audit logging is best-effort

    def tail_log(self, container: str, n: int = 50) -> Iterator[dict]:
        """Yield the last *n* audit events for a container.

        Args:
            container: Container name.
            n: Number of recent events to yield.
        """
        path = self._log_path(container)
        if not path.is_file():
            return

        lines = path.read_text().splitlines()
        for line in lines[-n:] if n > 0 else []:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

    def list_log_files(self) -> list[str]:
        """Return container names that have audit logs."""
        if not self._logs_dir.is_dir():
            return []
        return sorted(f.stem for f in self._logs_dir.glob("*.jsonl"))
