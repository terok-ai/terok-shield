# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tail the dnsmasq query log and emit events for blocked domain lookups.

Watches for new ``query[A]`` / ``query[AAAA]`` lines and classifies
each domain by suffix-matching against the merged allowed domain set
(profile + live - denied).  Requires the dnsmasq DNS tier.
"""

import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path

from ..dns import dnsmasq
from ._event import WatchEvent

# Matches dnsmasq log-queries lines like:
#   Mar 31 12:00:00 dnsmasq[123]: query[A] evil.example.com from 127.0.0.1
_QUERY_RE = re.compile(r"query\[(A{1,4})\]\s+(\S+)\s+from\s+")

# How often (seconds) to refresh the allowed domain list.
_DOMAIN_REFRESH_INTERVAL = 30.0


class DnsLogWatcher:
    """Tail the dnsmasq query log and yield events for blocked domains.

    Opens the log file, seeks to the end, and watches for new query lines.
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


def _monotonic() -> float:
    """Return monotonic time (seconds).  Extracted for testability."""
    return time.monotonic()
