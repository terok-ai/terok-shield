# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""``shield watch`` entry point — signal handling and select loop.

This module contains the CLI/tool portion of the watch subsystem:
signal handlers, tier validation, and the blocking ``run_watch()``
event loop.  The library-level watcher classes live in
:mod:`terok_shield.lib.watchers`.
"""

from __future__ import annotations

import select
import signal
import sys
from pathlib import Path

from ..common.config import DnsTier
from ..core import state
from ..lib.watchers import AuditLogWatcher, DnsLogWatcher, DomainCache, NflogWatcher, WatchEvent

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


def _emit_events(events: list[WatchEvent]) -> None:
    """Print each event as a JSON line to stdout."""
    for event in events:
        print(event.to_json(), flush=True)


def _enrich_nflog(events: list[WatchEvent], cache: DomainCache) -> list[WatchEvent]:
    """Attach cached domain names to NFLOG events that have a dest IP.

    Refreshes the cache at most once per batch to avoid reparsing the
    entire dnsmasq log for every cache miss.
    """
    enriched: list[WatchEvent] = []
    refreshed = False
    for ev in events:
        if ev.dest and not ev.domain:
            domain = cache.lookup(ev.dest)
            if not domain and not refreshed:
                cache.refresh()
                refreshed = True
                domain = cache.lookup(ev.dest)
            if domain:
                from dataclasses import replace

                ev = replace(ev, domain=domain)
        enriched.append(ev)
    return enriched


def _poll_nflog_or_sleep(nflog_watcher: NflogWatcher | None, domain_cache: DomainCache) -> None:
    """Wait on the NFLOG socket (or sleep) and emit any packets."""
    if nflog_watcher:
        readable, _, _ = select.select([nflog_watcher], [], [], 1.0)
        if readable:
            _emit_events(_enrich_nflog(nflog_watcher.poll(), domain_cache))
    else:
        select.select([], [], [], 1.0)


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
    domain_cache = DomainCache(state_dir)

    try:
        while _running:
            _poll_nflog_or_sleep(nflog_watcher, domain_cache)
            _emit_events(dns_watcher.poll())
            _emit_events(audit_watcher.poll())
    finally:
        dns_watcher.close()
        audit_watcher.close()
        if nflog_watcher:
            nflog_watcher.close()
