# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""DNS resolution with timestamp-based caching.

Resolves domain names from allowlist profiles via ``dig`` and caches
the results so containers do not block on DNS at every start.  Profiles
prefer domain names over raw IPs because CDN addresses rotate.

Falls back to ``getent hosts`` when ``dig`` is not installed — fewer
IPs are captured (no parallel A + AAAA query), but resolution still
works.  When the dnsmasq tier is active, domain resolution happens at
runtime via ``--nftset``; this module then only handles raw IPs.
"""
# WAYPOINT: Shield (__init__), HookMode (mode_hook)

import logging
import time
from pathlib import Path

from ..run import CommandRunner, DigNotFoundError
from ..util import is_ip as _is_ip

logger = logging.getLogger(__name__)


class DnsResolver:
    """Stateless DNS resolver — all persistence lives in the cache file.

    The only dependency is a :class:`CommandRunner` for ``dig`` / ``getent``
    subprocess calls.
    """

    def __init__(self, *, runner: CommandRunner) -> None:
        """Inject the command runner used for all DNS subprocess calls."""
        self._runner = runner

    # ── Public API ──────────────────────────────────────────

    def resolve_and_cache(
        self,
        entries: list[str],
        cache_path: Path,
        *,
        max_age: int = 3600,
    ) -> list[str]:
        """Resolve profile entries and cache the result.

        Profiles mix domain names with literal IPs/CIDRs — domains go
        through DNS resolution, literals pass through unchanged.

        Args:
            entries: Domain names and/or raw IPs from composed profiles.
            cache_path: File to store resolved IPs in, per-container scoped.
            max_age: Cache freshness threshold in seconds (default: 1 hour).

        Returns:
            Resolved IPv4/IPv6 addresses combined with raw IPs/CIDRs.
        """
        if self._cache_fresh(cache_path, max_age):
            return self._read_cache(cache_path)

        domains, raw_ips = self._split_entries(entries)
        resolved = self.resolve_domains(domains)
        all_ips = raw_ips + resolved

        self._write_cache(cache_path, all_ips)
        return all_ips

    def resolve_domains(self, domains: list[str]) -> list[str]:
        """Resolve domain names to IP addresses (A + AAAA), best-effort.

        Unresolvable domains are skipped with a warning.  Results are
        deduplicated in first-seen order.
        """
        seen: set[str] = set()
        result: list[str] = []
        use_getent = False
        for domain in domains:
            try:
                ips = self._resolve_one(domain, use_getent=use_getent)
            except DigNotFoundError:
                # dig missing — degrade gracefully for the rest of this batch
                logger.warning("dig not found — falling back to getent for DNS resolution")
                use_getent = True
                ips = self._resolve_one(domain, use_getent=True)
            if not ips:
                logger.warning("Domain %r resolved to no IPs (typo or DNS failure?)", domain)
            for ip in ips:
                if ip not in seen:
                    seen.add(ip)
                    result.append(ip)
        return result

    # ── Resolution detail ───────────────────────────────────

    def _resolve_one(self, domain: str, *, use_getent: bool = False) -> list[str]:
        """Resolve a single domain using dig or getent."""
        if use_getent:
            return self._runner.getent_hosts(domain)
        return self._runner.dig_all(domain)

    # ── Cache mechanics ─────────────────────────────────────

    @staticmethod
    def _split_entries(entries: list[str]) -> tuple[list[str], list[str]]:
        """Separate entries into (domains, raw_ips)."""
        domains, ips = [], []
        for entry in entries:
            (_ips := ips if _is_ip(entry) else domains).append(entry)
        return domains, ips

    @staticmethod
    def _cache_fresh(path: Path, max_age: int) -> bool:
        """Check whether the cache file exists and is younger than *max_age* seconds."""
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return False
        return (time.time() - mtime) < max_age

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
