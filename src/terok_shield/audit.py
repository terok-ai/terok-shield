# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Structured audit logging for shield (JSON-lines format).

Provides ``AuditLogger`` (Service pattern) -- owns a logs directory and
an enabled flag, writes JSON-lines per container.  Replaces the former
module-level ``_audit_enabled`` global + free functions.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Self

from .config import ShieldConfig, shield_logs_dir
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


# ── Module-level backwards compatibility ─────────────────
# These free functions and the global toggle are kept so existing
# callers (tests, oci_hook.py, __init__.py) continue to work
# during migration.  New code should use AuditLogger directly.

_audit_enabled: bool = True


def configure_audit(*, enabled: bool) -> None:
    """Set the module-level audit toggle.

    Called once per config load -- either from the public API layer
    (which receives config from the caller) or from ``hook_main``
    (which reads config from disk).  All subsequent ``log_event``
    calls respect the setting until it is changed.
    """
    global _audit_enabled  # noqa: PLW0603
    _audit_enabled = enabled


def _log_path(container: str) -> Path:
    """Return the audit log path for a container.

    Raises ValueError if the container name contains path-separator
    characters or other unsafe sequences (prevents path traversal).
    """
    validate_container_name(container)
    logs_dir = shield_logs_dir()
    logs_dir.mkdir(parents=True, exist_ok=True)
    return logs_dir / f"{container}.jsonl"


def log_event(
    container: str,
    action: str,
    *,
    dest: str | None = None,
    detail: str | None = None,
) -> None:
    """Write a single audit event to the container's log file.

    Respects the module-level toggle set by :func:`configure_audit`.
    When audit is disabled the call is a no-op.

    Args:
        container: Container name.
        action: Event type (setup, teardown, allowed, denied).
        dest: Destination IP/domain (optional).
        detail: Additional detail string (optional).
    """
    if not _audit_enabled:
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
        with _log_path(container).open("a") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except OSError:
        pass  # audit logging is best-effort


def tail_log(container: str, n: int = 50) -> Iterator[dict]:
    """Yield the last *n* audit events for a container.

    Args:
        container: Container name.
        n: Number of recent events to yield.
    """
    path = _log_path(container)
    if not path.is_file():
        return

    lines = path.read_text().splitlines()
    for line in lines[-n:] if n > 0 else []:
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def list_log_files() -> list[str]:
    """Return container names that have audit logs."""
    logs_dir = shield_logs_dir()
    if not logs_dir.is_dir():
        return []
    return sorted(f.stem for f in logs_dir.glob("*.jsonl"))
