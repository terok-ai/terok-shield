# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Per-container dnsmasq config generation, reload, and domain management.

dnsmasq runs inside the container's network namespace (via ``nsenter``)
on a runtime-dependent listen address — ``127.0.0.1:53`` for ordinary
runtimes that share the netns loopback, a link-local address under
krun whose guest can't reach netns 127.0.0.1.  ``--nftset``
auto-populates nft allow sets on every DNS resolution to handle IP
rotation that static pre-start resolution cannot.

This module is the single package-side owner of dnsmasq config format
and CLI args; the per-container start/stop dance is owned by the OCI
hook resource (``resources/nft_hook.py``), which has its own stdlib-
only copy because hook scripts run outside the package venv.
"""
# WAYPOINT: HookMode (hooks.mode)

import ipaddress
import logging
import os
import re
import signal
from pathlib import Path

from .. import state
from ..nft.constants import DNSMASQ_BIND_DEFAULT, NFT_TABLE_NAME
from ..run import CommandRunner

logger = logging.getLogger(__name__)

# Strict domain label validation (RFC 1035 + wildcards).
_DOMAIN_RE = re.compile(r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


# ── Lifecycle ──────────────────────────────────────────


def reload(state_dir: Path, upstream_dns: str, domains: list[str]) -> None:
    """Regenerate dnsmasq config and signal the daemon to reload.

    Sends SIGHUP to the running dnsmasq, which re-reads its config file.
    No-op if dnsmasq is not running (PID file absent).

    Args:
        state_dir: Per-container state directory.
        upstream_dns: Upstream DNS forwarder address.
        domains: Updated domain names for nftset auto-population.

    Raises:
        RuntimeError: If dnsmasq PID exists but the process is gone
            (stale PID).  The caller should log this — it means the
            container's DNS is broken.
    """
    pid_int = _read_pid(state_dir)
    if pid_int is None:
        return

    if not _is_our_dnsmasq(pid_int, state_dir):
        _clear_pid_file(state_dir)
        raise RuntimeError(
            f"PID {pid_int} is not dnsmasq (stale PID file) — container DNS is broken. "
            "Restart the container to recover."
        )

    # Regenerate config, then signal dnsmasq to re-read it.  Preserve
    # log-queries / log-facility and the listen address so a live
    # reload never rebinds dnsmasq onto a different interface.
    pid_path = state.dnsmasq_pid_path(state_dir)
    conf_path = state.dnsmasq_conf_path(state_dir)
    old_conf = conf_path.read_text() if conf_path.is_file() else ""
    log_path = state.dnsmasq_log_path(state_dir) if "log-queries" in old_conf else None
    listen_address = _extract_listen_address(old_conf) or DNSMASQ_BIND_DEFAULT
    conf_path.write_text(
        generate_config(
            upstream_dns,
            domains,
            pid_path,
            listen_address=listen_address,
            log_path=log_path,
        )
    )
    try:
        os.kill(pid_int, signal.SIGHUP)
    except ProcessLookupError as e:
        raise RuntimeError(
            f"dnsmasq (pid {pid_int}) is dead — container DNS is broken. "
            "Restart the container to recover."
        ) from e


# ── Domain file operations ─────────────────────────────


def add_domain(state_dir: Path, domain: str) -> bool:
    """Append a domain to the live.domains file.

    Writes to ``live.domains`` (not ``profile.domains``) so that
    runtime additions survive container restarts without overwriting
    the profile-derived domain list.

    Returns True if the domain was added, False if already present
    in the merged domain set (profile + live - denied).
    """
    domain = _validate_domain(domain)
    existing = read_merged_domains(state_dir)
    if domain in existing:
        return False

    # Remove from denied.domains if present (un-deny)
    denied_path = state.denied_domains_path(state_dir)
    if denied_path.is_file():
        denied = read_domains(denied_path)
        if domain in denied:
            denied.remove(domain)
            denied_path.write_text("\n".join(denied) + "\n" if denied else "")

    live_path = state.live_domains_path(state_dir)
    with live_path.open("a") as f:
        f.write(f"{domain}\n")
    return True


def remove_domain(state_dir: Path, domain: str) -> bool:
    """Remove a domain by adding it to the denied.domains file.

    Writes to ``denied.domains`` so the denial persists across
    dnsmasq reloads.  Also removes from ``live.domains`` if present.

    Returns True if the domain was removed, False if not found
    in the merged domain set.
    """
    domain = _validate_domain(domain)
    existing = read_merged_domains(state_dir)
    if domain not in existing:
        return False

    # Remove from live.domains if present
    live_path = state.live_domains_path(state_dir)
    if live_path.is_file():
        live = read_domains(live_path)
        if domain in live:
            live.remove(domain)
            live_path.write_text("\n".join(live) + "\n" if live else "")

    # Add to denied.domains
    denied_path = state.denied_domains_path(state_dir)
    denied = read_domains(denied_path)
    if domain not in denied:
        with denied_path.open("a") as f:
            f.write(f"{domain}\n")

    return True


def read_domains(domains_path: Path) -> list[str]:
    """Read and normalize domain names from a domains file.

    Validates and lowercases each entry so comparisons with
    ``add_domain()``/``remove_domain()`` are consistent.
    Invalid entries are silently skipped.
    """
    if not domains_path.is_file():
        return []
    domains: list[str] = []
    for line in domains_path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            domains.append(_validate_domain(line))
        except ValueError:
            logger.warning("read_domains: skipping invalid entry in %s", domains_path)
            continue
    return list(dict.fromkeys(domains))


def read_merged_domains(state_dir: Path) -> list[str]:
    """Compute effective domains: (profile + live) - denied.

    Returns a deduplicated, stable-order list.
    """
    profile = read_domains(state.profile_domains_path(state_dir))
    live = read_domains(state.live_domains_path(state_dir))
    denied = set(read_domains(state.denied_domains_path(state_dir)))

    merged: list[str] = []
    seen: set[str] = set()
    for d in profile + live:
        if d not in seen and d not in denied:
            seen.add(d)
            merged.append(d)
    return merged


# ── Container DNS setup ────────────────────────────────


# ── Config generation ──────────────────────────────────


def generate_config(
    upstream_dns: str,
    domains: list[str],
    pid_path: Path,
    *,
    listen_address: str,
    log_path: Path | None = None,
) -> str:
    """Generate a complete dnsmasq configuration.

    Args:
        upstream_dns: Upstream DNS forwarder (pasta or slirp4netns address).
        domains: Domain names for ``--nftset`` auto-population.
        pid_path: Path for the dnsmasq PID file.
        listen_address: Address dnsmasq binds to inside the netns.  See
            [`DNSMASQ_BIND_DEFAULT`][terok_shield.nft.constants.DNSMASQ_BIND_DEFAULT]
            /
            [`DNSMASQ_BIND_KRUN`][terok_shield.nft.constants.DNSMASQ_BIND_KRUN].
        log_path: If set, enable query logging to this file (for ``shield watch``).

    Raises:
        ValueError: If *upstream_dns* or *listen_address* is not a valid IP address.
    """
    ipaddress.ip_address(upstream_dns)
    ipaddress.ip_address(listen_address)
    lines = [
        f"# Generated by terok-shield (pid {os.getpid()})",
        f"listen-address={listen_address}",
        "port=53",
        "bind-interfaces",
        "no-resolv",
        "no-hosts",
        f"server={upstream_dns}",
        f"pid-file={pid_path}",
    ]
    if log_path is not None:
        lines += ["log-queries", f"log-facility={log_path}"]
    for domain in domains:
        try:
            lines.append(nftset_entry(domain))
        except ValueError:
            logger.warning("generate_config: skipping invalid domain entry")
            continue
    return "\n".join(lines) + "\n"


def _extract_listen_address(conf_text: str) -> str | None:
    """Return the ``listen-address=…`` value from a dnsmasq config, if any.

    Used by [`reload`][terok_shield.dns.dnsmasq.reload] to preserve the
    bind address across config regeneration — the hook ballast has its
    own copy of this logic (stdlib-only contract on the ballast side).
    """
    for line in conf_text.splitlines():
        if line.startswith("listen-address="):
            return line.split("=", 1)[1].strip()
    return None


def nftset_entry(domain: str) -> str:
    """Generate a dnsmasq ``nftset`` config line for a domain.

    Maps A records to the IPv4 allow set and AAAA records to the IPv6
    allow set.  dnsmasq automatically matches the domain and all its
    subdomains.

    Example::

        nftset=/github.com/4#inet#terok_shield#allow_v4,6#inet#terok_shield#allow_v6
    """
    domain = _validate_domain(domain)
    # Strip leading wildcard — dnsmasq nftset inherently matches subdomains.
    if domain.startswith("*."):
        domain = domain[2:]
    return f"nftset=/{domain}/4#inet#{NFT_TABLE_NAME}#allow_v4,6#inet#{NFT_TABLE_NAME}#allow_v6"


# ── Capability probing ─────────────────────────────────


def has_nftset_support(runner: CommandRunner) -> bool:
    """Return True if the installed dnsmasq supports ``--nftset``.

    Parses ``dnsmasq --version`` compile-time options for the ``nftset``
    feature flag.  Returns False if dnsmasq is not installed or its
    output contains ``no-nftset`` (explicitly disabled).
    """
    out = runner.run(["dnsmasq", "--version"], check=False)
    return bool(re.search(r"\bnftset\b", out)) and not bool(re.search(r"\bno-nftset\b", out))


# ── Private helpers ────────────────────────────────────


def _validate_domain(domain: str) -> str:
    """Validate a domain name against injection.

    Raises ValueError on invalid input.
    """
    d = domain.strip().lower()
    if not d:
        raise ValueError("Empty domain name")
    if not _DOMAIN_RE.fullmatch(d):
        raise ValueError(f"Invalid domain name: {d!r}")
    return d


def _read_pid(state_dir: Path) -> int | None:
    """Read the dnsmasq PID from state, or None if missing/invalid."""
    pid_path = state.dnsmasq_pid_path(state_dir)
    try:
        return int(pid_path.read_text().strip())
    except (OSError, ValueError):
        return None


def _is_our_dnsmasq(pid_int: int, state_dir: Path) -> bool:
    """Return True if the PID belongs to *this container's* dnsmasq.

    Parses ``/proc/{pid}/cmdline`` as a NUL-separated argv vector and
    checks that argv[0] is the ``dnsmasq`` binary (exact name or absolute
    path) and that ``--conf-file=<our-conf>`` is present as a separate
    argument.  Substring matching is not used, preventing false positives
    from monitoring tools that embed these strings in their own arguments.
    """
    conf_arg = b"--conf-file=" + str(state.dnsmasq_conf_path(state_dir)).encode()
    try:
        raw = Path(f"/proc/{pid_int}/cmdline").read_bytes()
    except OSError:
        return False
    args = raw.rstrip(b"\x00").split(b"\x00")
    if not args:
        return False
    exe = args[0]
    return (exe == b"dnsmasq" or exe.endswith(b"/dnsmasq")) and conf_arg in args


def _clear_pid_file(state_dir: Path) -> None:
    """Remove the dnsmasq PID file (best-effort)."""
    try:
        state.dnsmasq_pid_path(state_dir).unlink()
    except OSError:
        pass
