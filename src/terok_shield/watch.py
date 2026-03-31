# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Live blocked-access event stream for ``shield watch``.

Tails the per-container dnsmasq query log and emits JSON events for
domains that are not in the current allowlist.  Requires the dnsmasq
DNS tier — ``dig`` / ``getent`` tiers do not produce a query log.
"""

from __future__ import annotations

import json
import os
import re
import select
import signal
import sys
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from . import dnsmasq, state
from .config import DnsTier

# ── Constants ───────────────────────────────────────────

# Matches dnsmasq log-queries lines like:
#   Mar 31 12:00:00 dnsmasq[123]: query[A] evil.example.com from 127.0.0.1
#   Mar 31 12:00:00 dnsmasq[123]: query[AAAA] evil.example.com from 127.0.0.1
_QUERY_RE = re.compile(r"query\[(A{1,4})\]\s+(\S+)\s+from\s+")

# How often (seconds) to refresh the allowed domain list.
_DOMAIN_REFRESH_INTERVAL = 30.0


# ── Data types ──────────────────────────────────────────


@dataclass(frozen=True)
class WatchEvent:
    """A single watch event emitted to the output stream."""

    ts: str
    source: str
    action: str
    domain: str
    query_type: str
    container: str

    def to_json(self) -> str:
        """Serialize to a compact JSON line."""
        return json.dumps(asdict(self), separators=(",", ":"))


# ── DNS log watcher ─────────────────────────────────────


class DnsLogWatcher:
    """Tail the dnsmasq query log and yield events for blocked domains.

    Opens the log file, seeks to the end, and watches for new query
    lines.  Domains are classified by suffix-matching against the
    merged allowed domain set (profile + live - denied).
    """

    def __init__(self, log_path: Path, state_dir: Path, container: str) -> None:
        """Open *log_path*, seek to end, and load the initial allowed domain set."""
        self._log_path = log_path
        self._state_dir = state_dir
        self._container = container
        self._fh = open(log_path)  # noqa: SIM115 — needs fileno() for select
        try:
            self._fh.seek(0, os.SEEK_END)
            self._allowed_domains: set[str] = set()
            self._last_refresh = 0.0
            self._refresh_domains()
        except Exception:
            self._fh.close()
            raise

    def fileno(self) -> int:
        """Return the file descriptor for ``select.select()`` multiplexing."""
        return self._fh.fileno()

    def close(self) -> None:
        """Close the underlying file handle."""
        self._fh.close()

    def _refresh_domains(self) -> None:
        """Reload the merged domain set from state files."""
        self._allowed_domains = set(dnsmasq.read_merged_domains(self._state_dir))
        self._last_refresh = _monotonic()

    def _is_allowed(self, domain: str) -> bool:
        """Return True if *domain* (or a parent) is in the allowed set.

        dnsmasq ``--nftset`` matches subdomains, so ``x.y.z`` is allowed
        if ``y.z`` is in the set.
        """
        d = domain.lower().rstrip(".")
        while d:
            if d in self._allowed_domains:
                return True
            dot = d.find(".")
            if dot < 0:
                break
            d = d[dot + 1 :]
        return False

    def poll(self) -> list[WatchEvent]:
        """Read new lines and return events for blocked queries."""
        if _monotonic() - self._last_refresh > _DOMAIN_REFRESH_INTERVAL:
            self._refresh_domains()

        events: list[WatchEvent] = []
        while line := self._fh.readline():
            m = _QUERY_RE.search(line)
            if not m:
                continue
            query_type, domain = m.group(1), m.group(2).lower().rstrip(".")
            if self._is_allowed(domain):
                continue
            events.append(
                WatchEvent(
                    ts=datetime.now(UTC).isoformat(),
                    source="dns",
                    action="blocked_query",
                    domain=domain,
                    query_type=query_type,
                    container=self._container,
                )
            )
        return events


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


def run_watch(state_dir: Path, container: str) -> None:
    """Stream blocked-access events as JSON lines to stdout.

    Validates that the dnsmasq tier is active, then enters a
    ``select.select()`` loop tailing the query log.  Clean exit
    on SIGINT or SIGTERM.

    Args:
        state_dir: Per-container state directory.
        container: Container name (for event metadata).

    Raises:
        SystemExit: If the DNS tier is not dnsmasq.
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

    log_path = state.dnsmasq_log_path(state_dir)
    _ensure_log_file(log_path)

    global _running  # noqa: PLW0603
    _running = True
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    watcher = DnsLogWatcher(log_path, state_dir, container)
    try:
        while _running:
            select.select([watcher], [], [], 1.0)
            for event in watcher.poll():
                print(event.to_json(), flush=True)
    finally:
        watcher.close()


def _monotonic() -> float:
    """Return monotonic time (seconds).  Extracted for testability."""
    return time.monotonic()
