# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""DNS domain resolution with timestamp-based caching.

Provides ``DnsResolver`` -- stateless resolver that takes an explicit
cache path per call.  All ``dig`` calls go through a ``CommandRunner``.
"""

import logging
import time
from pathlib import Path

from .run import CommandRunner
from .util import is_ip as _is_ip

logger = logging.getLogger(__name__)


# ── Pure helpers ─────────────────────────────────────────


def _split_entries(entries: list[str]) -> tuple[list[str], list[str]]:
    """Split entries into (domains, raw_ips)."""
    domains, ips = [], []
    for entry in entries:
        (_ips := ips if _is_ip(entry) else domains).append(entry)
    return domains, ips


def _cache_fresh(path: Path, max_age: int) -> bool:
    """Return True if the cache file exists and is younger than max_age seconds."""
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return False
    return (time.time() - mtime) < max_age


# ── DnsResolver ──────────────────────────────────────────


class DnsResolver:
    """Stateless DNS resolver with file-based caching.

    Resolves domain names to IP addresses (A + AAAA) via ``dig``.
    Cache path is provided per call -- no internal state beyond
    the ``CommandRunner``.
    """

    def __init__(self, *, runner: CommandRunner) -> None:
        """Create a resolver.

        Args:
            runner: Command runner for ``dig`` subprocess calls.
        """
        self._runner = runner

    def resolve_domains(self, domains: list[str]) -> list[str]:
        """Resolve a list of domains to IPv4 and IPv6 addresses.

        Queries both A and AAAA records for each domain.
        Skips domains that fail to resolve (best-effort).
        Returns deduplicated IPs.
        """
        seen: set[str] = set()
        result: list[str] = []
        for domain in domains:
            ips = self._runner.dig_all(domain)
            if not ips:
                logger.warning("Domain %r resolved to no IPs (typo or DNS failure?)", domain)
            for ip in ips:
                if ip not in seen:
                    seen.add(ip)
                    result.append(ip)
        return result

    def resolve_and_cache(
        self,
        entries: list[str],
        cache_path: Path,
        *,
        max_age: int = 3600,
    ) -> list[str]:
        """Resolve domains and cache results.  Return cached IPs if fresh.

        Entries can be a mix of domain names and raw IP/CIDR addresses.
        Raw IPs are passed through without resolution.

        Args:
            entries: Domain names and/or raw IPs from composed profiles.
            cache_path: Path to the cache file for this container.
            max_age: Cache freshness threshold in seconds (default: 1 hour).

        Returns:
            List of resolved IPv4/IPv6 addresses + raw IPs/CIDRs.
        """
        if _cache_fresh(cache_path, max_age):
            return self._read_cache(cache_path)

        domains, raw_ips = _split_entries(entries)
        resolved = self.resolve_domains(domains)
        all_ips = raw_ips + resolved

        self._write_cache(cache_path, all_ips)
        return all_ips

    @staticmethod
    def _read_cache(path: Path) -> list[str]:
        """Read cached IPs from a resolved file."""
        if not path.is_file():
            return []
        return [line.strip() for line in path.read_text().splitlines() if line.strip()]

    @staticmethod
    def _write_cache(path: Path, ips: list[str]) -> None:
        """Write resolved IPs to a cache file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(ips) + "\n" if ips else "")
