# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""DNS resolution with timestamp-based caching.

Resolves allowlist domains via ``dig`` (``getent`` fallback) and caches
the IPs so containers do not block on DNS at every start.

Two cache layers:

- **per-container file** (``cache_path``): the view the nft ruleset reads.
  Scoped to one container, so a fresh container never reuses another's.
- **host cache** (``host_cache_dir``): shared across containers, keyed by
  the allowlist's content hash. The first task resolves; the rest read.

Domains resolve concurrently with a per-lookup timeout, so a batch costs
about one lookup and one dead domain cannot stall startup.  A batch that
does run says so on stderr, before and after: the launcher is waiting on
it, and a silent wait reads as a hang.

Every tier but ``dnsmasq-live`` uses this module at launch.  On that tier
domains resolve on-demand at runtime via ``--nftset``; this module then
handles raw IPs only.
"""
# WAYPOINT: Shield (__init__), HookMode (hooks.mode)

import contextlib
import hashlib
import logging
import os
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..paths import dns_cache_dir
from ..run import CommandRunner
from ..state import STATE_DIR_MODE
from ..util import is_ip as _is_ip

logger = logging.getLogger(__name__)

RESOLVE_TIMEOUT = 2
"""Per-subprocess DNS budget in seconds.

Best-effort: an answer slower than this counts as no answer. The old 10s
budget let one dead domain (times the getent retry) stall a start by ~20s.
"""

MAX_RESOLVE_WORKERS = 16
"""Upper bound on concurrent resolver subprocesses per batch."""

_HOST_CACHE_KEY_LEN = 16
"""Hex digits of the entry-list hash used as the host-cache filename."""


_CACHE_MAX_AGE = 3600
"""Seconds a resolution cache stays fresh, per container and on the host alike."""


class DnsResolver:
    """Stateless DNS resolver — all persistence lives in the cache files.

    Depends on a [`CommandRunner`][terok_shield.dns.resolver.CommandRunner]
    for lookup-tool (``dig``/``drill``) and ``getent`` subprocess calls
    and a host-level cache directory shared across containers.
    """

    def __init__(self, *, runner: CommandRunner, host_cache_dir: Path | None = None) -> None:
        """Inject the command runner and the shared cache location.

        Args:
            runner: Command runner used for all DNS subprocess calls.
            host_cache_dir: Cross-container cache directory; ``None`` selects
                [`dns_cache_dir`][terok_shield.paths.dns_cache_dir].
        """
        self._runner = runner
        self._host_cache_dir = host_cache_dir or dns_cache_dir()

    # ── Public API ──────────────────────────────────────────

    def resolve_and_cache(
        self,
        entries: list[str],
        cache_path: Path,
        *,
        force: bool = False,
        source_mtime: float = 0.0,
    ) -> list[str]:
        """Resolve profile entries and cache the result.

        Reads the per-container file first, then the shared host cache
        (materializing a hit into the per-container file), and only resolves
        when both miss.

        Args:
            entries: Domain names and/or raw IPs from composed profiles.
            cache_path: Per-container file the nft ruleset reads.
            force: Re-resolve even when a cache is younger than the one-hour
                freshness window.
            source_mtime: mtime of the authored policy; a per-container cache
                older than it is re-resolved even within the freshness window,
                so an edited allowlist takes effect on the next task start. The
                host cache ignores this — its content-hash key already makes it
                edit-aware.

        Returns:
            Resolved IPv4/IPv6 addresses combined with raw IPs/CIDRs.
        """
        max_age = 0 if force else _CACHE_MAX_AGE
        if self._cache_fresh(cache_path, max_age, source_mtime):
            return self._read_cache(cache_path)

        host_path = self._host_cache_path(entries)
        if self._cache_fresh(host_path, max_age):
            ips = self._read_cache(host_path)
            self._write_cache(cache_path, ips)
            return ips

        domains, raw_ips = self._split_entries(entries)
        resolved = self._resolve_announced(domains)
        all_ips = raw_ips + resolved

        self._write_cache(cache_path, all_ips)
        # An all-domains-failed resolve (DNS outage, broken resolver) is fine
        # for one container but must not poison every task on the host for
        # max_age: share only when at least one domain resolved (or there were
        # none to resolve).
        if resolved or not domains:
            self._write_cache(host_path, all_ips)
        return all_ips

    def _resolve_announced(self, domains: list[str]) -> list[str]:
        """Resolve *domains* and tell the operator what the wait is for.

        The bound is the worst case of the thread pool: every lookup timing
        out, each followed by its ``getent`` retry.
        """
        if not domains:
            return []
        rounds = -(-len(domains) // MAX_RESOLVE_WORKERS)
        bound = rounds * RESOLVE_TIMEOUT * 2
        print(f"Resolving {len(domains)} allowlist names, up to {bound} s.", file=sys.stderr)
        started = time.monotonic()
        ips = self.resolve_domains(domains)
        elapsed = time.monotonic() - started
        print(f"Resolved to {len(ips)} addresses in {elapsed:.1f} s.", file=sys.stderr)
        return ips

    def resolve_domains(self, domains: list[str]) -> list[str]:
        """Resolve domain names to IPs (A + AAAA), best-effort and concurrent.

        Probes for a lookup tool once, then resolves every domain on a small thread
        pool — a batch costs about its slowest single lookup. Unresolvable
        domains are skipped with a warning; results are deduplicated in
        first-seen (input) order.
        """
        if not domains:
            return []
        if self._runner.has("dig") or self._runner.has("drill"):
            resolve = self._resolve_via_lookup
        else:
            logger.warning("neither dig nor drill found — using getent for DNS resolution")
            resolve = self._resolve_via_getent
        with ThreadPoolExecutor(max_workers=min(len(domains), MAX_RESOLVE_WORKERS)) as pool:
            per_domain = pool.map(resolve, domains)
        return list(dict.fromkeys(ip for ips in per_domain for ip in ips))

    # ── Resolution detail ───────────────────────────────────

    def _resolve_via_lookup(self, domain: str) -> list[str]:
        """Resolve via the lookup tool, retrying through NSS on an empty answer.

        An empty answer is usually not a dead domain: some environments
        break the tool specifically (an EDNS-hostile forwarder, a hardened
        path) while glibc resolution still works, so we retry that one
        domain through ``getent`` before giving up (terok#1119).
        """
        ips = self._runner.lookup_all(domain, timeout=RESOLVE_TIMEOUT)
        if not ips:
            ips = self._runner.getent_hosts(domain, timeout=RESOLVE_TIMEOUT)
            if ips:
                logger.warning(
                    "lookup returned nothing for %r but NSS resolved it — the tool is broken here",
                    domain,
                )
        return self._warn_if_empty(domain, ips)

    def _resolve_via_getent(self, domain: str) -> list[str]:
        """Resolve via NSS (``getent``) — the path taken when ``dig`` is absent."""
        ips = self._runner.getent_hosts(domain, timeout=RESOLVE_TIMEOUT)
        return self._warn_if_empty(domain, ips)

    @staticmethod
    def _warn_if_empty(domain: str, ips: list[str]) -> list[str]:
        """Say so on an empty resolution (typo or DNS failure); pass the IPs through."""
        if not ips:
            message = f"No address for {domain}."
            logger.warning(message)
            print(message, file=sys.stderr)
        return ips

    # ── Cache mechanics ─────────────────────────────────────

    def _host_cache_path(self, entries: list[str]) -> Path:
        """Shared cache file for this exact entry list.

        Keyed by the content hash of the entry list: any allowlist edit lands
        on a fresh key and re-resolves. Creates the directory ``0700`` on first
        use.
        """
        self._host_cache_dir.mkdir(parents=True, exist_ok=True)
        self._host_cache_dir.chmod(STATE_DIR_MODE)
        digest = hashlib.sha256("\n".join(entries).encode()).hexdigest()
        return self._host_cache_dir / f"{digest[:_HOST_CACHE_KEY_LEN]}.resolved"

    @staticmethod
    def _split_entries(entries: list[str]) -> tuple[list[str], list[str]]:
        """Separate entries into (domains, raw_ips)."""
        domains: list[str] = []
        ips: list[str] = []
        for entry in entries:
            (ips if _is_ip(entry) else domains).append(entry)
        return domains, ips

    @staticmethod
    def _cache_fresh(path: Path, max_age: int, source_mtime: float = 0.0) -> bool:
        """True when *path* exists, is younger than *max_age*, and post-dates *source_mtime*.

        A cache older than *source_mtime* (the authored policy's mtime) is
        stale even within *max_age* — the allowlist changed since we resolved.
        """
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return False
        # future: jitter max_age per-container so many tasks don't re-resolve
        # in a synchronized wave at the hour boundary.
        if mtime < source_mtime:
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
        """Write resolved IPs atomically (unique temp file + rename).

        The host-level file is shared across concurrently starting tasks — a
        torn read would seed a container with a truncated allowlist — and two
        threads of one process can write the same (content-hash-keyed) file at
        once, so each write goes to its own ``mkstemp`` temp before the rename.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(ips) + "\n" if ips else "")
            os.replace(tmp, path)
        except OSError:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
