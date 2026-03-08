# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""DNS domain resolution with timestamp-based caching."""


import ipaddress
import re
import time
from pathlib import Path

from .config import shield_resolved_dir
from .run import dig

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _is_ip(entry: str) -> bool:
    """Return True if `entry` is an IPv4 address or CIDR, False if it's a domain."""
    try:
        if "/" in entry:
            ipaddress.IPv4Network(entry, strict=False)
        else:
            ipaddress.IPv4Address(entry)
        return True
    except ValueError:
        return False


def _split_entries(entries: list[str]) -> tuple[list[str], list[str]]:
    """Split entries into (domains, raw_ips)."""
    domains, ips = [], []
    for entry in entries:
        (_ips := ips if _is_ip(entry) else domains).append(entry)
    return domains, ips


def resolve_domains(domains: list[str]) -> list[str]:
    """Resolve a list of domains to IPv4 addresses.

    Skips domains that fail to resolve (best-effort).
    Returns deduplicated IPs.
    """
    seen: set[str] = set()
    result: list[str] = []
    for domain in domains:
        for ip in dig(domain):
            if ip not in seen:
                seen.add(ip)
                result.append(ip)
    return result


def _cache_path(container: str) -> Path:
    """Return the resolved IP cache path for a container.

    Raises:
        ValueError: If the container name contains path separators or traversal.
    """
    if not _SAFE_NAME.fullmatch(container):
        raise ValueError(f"Unsafe container name for cache key: {container!r}")
    return shield_resolved_dir() / f"{container}.resolved"


def _read_cache(path: Path) -> list[str]:
    """Read cached IPs from a resolved file."""
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def _write_cache(path: Path, ips: list[str]) -> None:
    """Write resolved IPs to a cache file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(ips) + "\n" if ips else "")


def _cache_fresh(path: Path, max_age: int) -> bool:
    """Return True if the cache file exists and is younger than max_age seconds."""
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return False
    return (time.time() - mtime) < max_age


def resolve_and_cache(
    entries: list[str],
    container: str,
    *,
    max_age: int = 3600,
) -> list[str]:
    """Resolve domains and cache results.  Return cached IPs if fresh.

    Entries can be a mix of domain names and raw IP/CIDR addresses.
    Raw IPs are passed through without resolution.

    Args:
        entries: Domain names and/or raw IPs from composed profiles.
        container: Container name (used as a cache key).
        max_age: Cache freshness threshold in seconds (default: 1 hour).

    Returns:
        List of resolved IPv4 addresses + raw IPs/CIDRs.
    """
    path = _cache_path(container)
    if _cache_fresh(path, max_age):
        return _read_cache(path)

    domains, raw_ips = _split_entries(entries)
    resolved = resolve_domains(domains)
    all_ips = raw_ips + resolved

    _write_cache(path, all_ips)
    return all_ips
