# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Optional logrotate integration for the per-container shield audit log.

The NFLOG reader appends one JSON line per blocked connection to
``<state_dir>/audit.jsonl`` — an unbounded append-only file that grows
~58 MB/day under sustained blocked-connection traffic.  Rather than
implementing our own rotation, this module detects ``logrotate`` on the
host and installs a drop-in config that covers every per-container
audit log under the sandbox-live tree.

Design:

- **Optional** — when ``logrotate`` is not on PATH, setup prints the
  generated config to stdout so the operator can install it manually
  or wire it into their own rotation.  Nothing fails.
- **copytruncate** — the NFLOG reader keeps the audit file open in
  append mode for its lifetime.  ``copytruncate`` copies the file and
  truncates the original in place, so the reader's file handle stays
  valid and no log lines are lost to a renamed file.
- **Wildcard path** — the config covers
  ``<sandbox-live-root>/tasks/*/*/shield/audit.jsonl`` so every
  container's audit log is rotated without per-container config.
- **System or user** — installs to ``/etc/logrotate.d/terok-shield``
  when running as root, otherwise prints to stdout for the operator
  to place in their own logrotate config.
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path

_log = logging.getLogger(__name__)

#: Drop-in filename under ``/etc/logrotate.d/``.
CONFIG_FILENAME = "terok-shield"

#: System logrotate drop-in directory (root installs only).
SYSTEM_LOGROTATE_DIR = Path("/etc/logrotate.d")


def find_logrotate() -> str | None:
    """Return the ``logrotate`` binary path, or ``None`` when not installed."""
    return shutil.which("logrotate")


def audit_log_pattern() -> str:
    """Return the wildcard path covering every per-container audit log.

    The pattern is ``<sandbox-live-root>/tasks/*/*/shield/audit.jsonl``
    — one wildcard per path component that varies per container.
    """
    from terok_sandbox.paths import sandbox_live_root

    root = sandbox_live_root()
    return str(root / "tasks" / "*" / "*" / "shield" / "audit.jsonl")


def generate_config(pattern: str | None = None) -> str:
    """Generate a logrotate drop-in config for the shield audit logs.

    Args:
        pattern: Wildcard path to the audit logs.  Defaults to
            [`audit_log_pattern`][terok_shield.logrotate.audit_log_pattern].

    Returns:
        A logrotate config snippet using ``copytruncate`` so the NFLOG
        reader's open file handle stays valid across rotations.
    """
    if pattern is None:
        pattern = audit_log_pattern()
    return f"""\
# terok-shield per-container audit log rotation.
# Installed by `terok-shield setup` — safe to remove and reinstall.
# copytruncate: the NFLOG reader keeps the file open in append mode;
# without it, rotation would rename the file and the reader would keep
# writing to the renamed (now-orphaned) inode.
{pattern} {{
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}}
"""


def install_config(config: str, *, target_dir: Path | None = None) -> Path | None:
    """Install the logrotate config, or return ``None`` if not possible.

    When running as root (or with write access to ``/etc/logrotate.d``),
    writes the config to ``/etc/logrotate.d/terok-shield`` and returns
    the path.  Otherwise returns ``None`` so the caller can print the
    config for manual installation.

    Args:
        config: The logrotate config text (from
            [`generate_config`][terok_shield.logrotate.generate_config]).
        target_dir: Override the install directory.  Defaults to
            ``/etc/logrotate.d``.
    """
    if target_dir is None:
        target_dir = SYSTEM_LOGROTATE_DIR
    target = target_dir / CONFIG_FILENAME
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        target.write_text(config)
        os.chmod(target, 0o644)
    except OSError as exc:
        _log.debug("cannot install logrotate config to %s: %s", target, exc)
        return None
    return target


def setup_logrotate(*, verbose: bool = True) -> Path | None:
    """Detect logrotate and install the audit-log rotation config.

    Returns the installed config path, or ``None`` when logrotate is not
    available or the config could not be written (in which case the
    config is printed to stdout when *verbose*).

    This is a best-effort convenience — failure never blocks
    ``terok-shield setup``.
    """
    binary = find_logrotate()
    if binary is None:
        if verbose:
            print(
                "logrotate not found on PATH — skipping audit log rotation setup.\n"
                "To enable rotation, install logrotate and re-run 'terok-shield setup',\n"
                "or install this config manually:\n\n" + generate_config()
            )
        return None

    config = generate_config()
    target = install_config(config)
    if target is not None:
        if verbose:
            print(f"logrotate config installed: {target}")
            print(f"  (binary: {binary})")
            print(f"  (pattern: {audit_log_pattern()})")
        return target

    if verbose:
        print(
            f"Cannot write to {SYSTEM_LOGROTATE_DIR} — install this config manually:\n\n" + config
        )
    return None
