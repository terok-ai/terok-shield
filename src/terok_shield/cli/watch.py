# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""``shield watch`` — stream blocked-access events as JSON lines.

Tails the dnsmasq query log, per-container audit log, and (optionally)
the NFLOG netlink socket.  Only works when the dnsmasq DNS tier is
active.  Clean exit on SIGINT or SIGTERM.
"""

import select
import signal
import sys
from pathlib import Path

from ..common.config import DnsTier
from ..core import state
from ..lib.watchers import AuditLogWatcher, DnsLogWatcher, DomainCache, NflogWatcher, WatchEvent

_running = True


# ── Entry point ─────────────────────────────────────────


def run_watch(state_dir: Path, container: str) -> None:
    """Stream blocked-access events as JSON lines to stdout.

    Only meaningful under the dnsmasq tier — the query log and nftset
    integration that feed the watchers do not exist in the dig/getent
    tiers.  Uses ``select`` so a single thread can multiplex the DNS
    log, audit log, and NFLOG socket without blocking on any one source.

    Args:
        state_dir: Per-container state directory.
        container: Container name (for event metadata).

    Raises:
        SystemExit: If the DNS tier is not dnsmasq.
    """
    _validate_dnsmasq_tier(state_dir)

    log_path = state.dnsmasq_log_path(state_dir)
    _ensure_log_file(log_path)

    _install_signal_handlers()

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


# ── Validation ──────────────────────────────────────────


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


def _ensure_log_file(log_path: Path) -> None:
    """Create the dnsmasq log file if it does not exist yet.

    ``pre_start()`` configures ``log-facility=<path>``, but dnsmasq
    may not have written any queries yet when ``shield watch`` starts.
    """
    log_path.touch(exist_ok=True)


# ── Event loop mechanics ────────────────────────────────


def _install_signal_handlers() -> None:
    """Reset the stop flag and register SIGINT/SIGTERM for clean shutdown."""
    global _running  # noqa: PLW0603
    _running = True
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)


def _handle_signal(_signum: int, _frame: object) -> None:
    """Set the stop flag on SIGINT/SIGTERM."""
    global _running  # noqa: PLW0603
    _running = False


def _poll_nflog_or_sleep(nflog_watcher: NflogWatcher | None, domain_cache: DomainCache) -> None:
    """Wait on the NFLOG socket (or sleep 1s) and emit any packets."""
    if nflog_watcher:
        readable, _, _ = select.select([nflog_watcher], [], [], 1.0)
        if readable:
            _emit_events(_enrich_nflog(nflog_watcher.poll(), domain_cache))
    else:
        select.select([], [], [], 1.0)


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
