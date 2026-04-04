# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""``shield watch`` entry point — signal handling and select loop.

This module contains the CLI/tool portion of the watch subsystem:
signal handlers, tier validation, and the blocking ``run_watch()``
event loop.  The library-level watcher classes live in
:mod:`terok_shield.watch`.
"""

from __future__ import annotations

import select
import signal
import sys
from pathlib import Path

from ..config import DnsTier
from ..core import state
from ..watch import AuditLogWatcher, DnsLogWatcher, NflogWatcher

# ── Entry point ─────────────────────────────────────────

_running = True


def _handle_signal(_signum: int, _frame: object) -> None:
    """Set the stop flag on SIGINT/SIGTERM."""
    global _running  # noqa: PLW0603
    _running = False


def _ensure_log_file(log_path: Path) -> None:
    """Create the dnsmasq log file if it does not exist yet.

    ``pre_start()`` configures ``log-facility=<path>`` in the dnsmasq
    config, but dnsmasq may not have written any queries yet when
    ``shield watch`` starts.  Creating the file ensures the watcher
    can open it immediately.
    """
    log_path.touch(exist_ok=True)


def _validate_dnsmasq_tier(state_dir: Path) -> None:
    """Verify the dnsmasq DNS tier is active, or exit with an error.

    Raises:
        SystemExit: If the DNS tier file is missing or not dnsmasq.
    """
    tier_path = state.dns_tier_path(state_dir)
    if tier_path.is_file():
        tier_value = tier_path.read_text().strip()
        if tier_value != DnsTier.DNSMASQ.value:
            print(
                f"Error: shield watch requires dnsmasq tier, got {tier_value!r}.",
                file=sys.stderr,
            )
            raise SystemExit(1)
    else:
        print(
            "Error: DNS tier not set — container may not be shielded.",
            file=sys.stderr,
        )
        raise SystemExit(1)


def run_watch(state_dir: Path, container: str) -> None:
    """Stream blocked-access events as JSON lines to stdout.

    Validates that the dnsmasq tier is active, then enters a
    ``select.select()`` loop tailing the query log, audit log,
    and (optionally) the NFLOG netlink socket.  Clean exit
    on SIGINT or SIGTERM.

    Args:
        state_dir: Per-container state directory.
        container: Container name (for event metadata).

    Raises:
        SystemExit: If the DNS tier is not dnsmasq.
    """
    _validate_dnsmasq_tier(state_dir)

    log_path = state.dnsmasq_log_path(state_dir)
    _ensure_log_file(log_path)

    global _running  # noqa: PLW0603
    _running = True
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    dns_watcher = DnsLogWatcher(log_path, state_dir, container)
    audit_watcher = AuditLogWatcher(state.audit_path(state_dir), container)
    nflog_watcher = NflogWatcher.create(container)

    try:
        while _running:
            # Only use select() for the netlink socket (real fd);
            # regular files always appear readable in select() so we
            # poll them unconditionally each iteration.
            if nflog_watcher:
                readable, _, _ = select.select([nflog_watcher], [], [], 1.0)
                if readable:
                    for event in nflog_watcher.poll():
                        print(event.to_json(), flush=True)
            else:
                # No netlink socket — just sleep to avoid busy-looping
                select.select([], [], [], 1.0)

            for event in dns_watcher.poll():
                print(event.to_json(), flush=True)
            for event in audit_watcher.poll():
                print(event.to_json(), flush=True)
    finally:
        dns_watcher.close()
        audit_watcher.close()
        if nflog_watcher:
            nflog_watcher.close()
