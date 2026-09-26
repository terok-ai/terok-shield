# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Per-container dnsmasq config generation, reload, and domain management.

dnsmasq runs inside the container's network namespace (via ``nsenter``)
on a runtime-dependent listen address — ``127.0.0.1:53`` for ordinary
runtimes that share the netns loopback, a link-local address under
krun whose guest can't reach netns 127.0.0.1.  A build with nftset
support populates the nft allow sets on every DNS resolution, which
follows IP rotation that static pre-start resolution cannot; a build
without it still serves the query log and the deny sinkholes.

This module is the single package-side owner of dnsmasq config format
and CLI args; the per-container start/stop dance is owned by the OCI
hook resource (``resources/nft_hook.py``).  Both sides locate and
match the dnsmasq process through ``resources/_oci_state``.
"""
# WAYPOINT: HookMode (hooks.mode)

import contextlib
import ipaddress
import logging
import os
import re
import signal
import time
from collections.abc import Sequence
from pathlib import Path

from terok_util import require_host_tool

from ..nft.constants import DNSMASQ_BIND_DEFAULT, NFT_TABLE_NAME, TIER_PROJECT_ALLOW
from ..resources._oci_state import is_our_dnsmasq
from ..run import CommandRunner, ShieldNeedsSetup
from ..state import StateBundle

logger = logging.getLogger(__name__)

# Strict domain label validation (RFC 1035 + wildcards).
_DOMAIN_RE = re.compile(r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


# ── Locating the binary ────────────────────────────────


def locate(explicit: Path | None, runner: CommandRunner) -> str:
    """The dnsmasq binary shield runs: *explicit* when set, else the host's own.

    Returns an empty string when the host has none.  An explicit path is the
    operator's word, so a path that is not an executable file is refused,
    never silently replaced by a PATH lookup.

    Raises:
        ShieldNeedsSetup: When *explicit* is not an executable file.
    """
    if explicit is None:
        return "dnsmasq" if runner.has("dnsmasq") else ""
    if not (explicit.is_file() and os.access(explicit, os.X_OK)):
        raise ShieldNeedsSetup(f"dnsmasq_path {explicit} is not an executable file.")
    return str(explicit.absolute())


# ── Lifecycle ──────────────────────────────────────────


def reload(
    state_dir: Path,
    upstream_dns: str,
    domains: list[str],
    *,
    deny_domains: Sequence[str] = (),
    override_domains: Sequence[str] = (),
    container: str,
    runner: CommandRunner,
) -> None:
    """Regenerate the dnsmasq config and restart dnsmasq so it takes effect.

    dnsmasq does NOT re-read its main config file on SIGHUP (only hosts /
    ``--addn-hosts`` / ``--hostsdir`` and its cache), so a config change —
    the ``nftset=`` line for a newly allowed domain, or the ``local=``
    NXDOMAIN sinkhole for a denied one — only lands on a fresh start.  So we
    restart in-netns: regenerate the conf, stop the old process, and relaunch
    it reading the new conf.  No-op if dnsmasq was never started (PID file
    absent — a tier without dnsmasq).

    There is a sub-second window with no in-container DNS between stop and
    relaunch.  Runtime domain allow/deny is operator-initiated and rare, so
    that is preferred over the previous SIGHUP, which loaded nothing.

    Args:
        state_dir: Per-container state directory.
        upstream_dns: Upstream DNS forwarder address.
        domains: Updated domain names for nftset auto-population.
        deny_domains: Denied domain names for DNS-plane NXDOMAIN sinkholes.
        override_domains: t10 override domains — sinkhole punch-throughs
            (see [`generate_config`][terok_shield.dns.dnsmasq.generate_config]).
        container: Container name — used to enter its netns for the relaunch.
        runner: Command runner that performs the in-netns relaunch.

    Raises:
        RuntimeError: On a stale/foreign PID file, or if dnsmasq does not
            come back after the restart — the container's DNS is broken and
            the task should be re-created.
    """
    pid_int = _read_pid(state_dir)
    if pid_int is None:
        return

    if not is_our_dnsmasq(pid_int, state_dir):
        _clear_pid_file(state_dir)
        raise RuntimeError(
            f"PID {pid_int} is not dnsmasq (stale PID file) — container DNS is broken. "
            "Restart the container to recover."
        )

    # Regenerate the config, preserving log-queries / log-facility and the
    # listen address so the relaunch never rebinds onto a different interface.
    bundle = StateBundle(state_dir)
    conf_path = bundle.dnsmasq_conf
    old_conf = conf_path.read_text() if conf_path.is_file() else ""
    log_path = bundle.dnsmasq_log if "log-queries" in old_conf else None
    listen_address = _extract_listen_address(old_conf) or DNSMASQ_BIND_DEFAULT
    tier = bundle.read_dns_tier()
    conf_path.write_text(
        generate_config(
            upstream_dns,
            domains,
            bundle.dnsmasq_pid,
            listen_address=listen_address,
            log_path=log_path,
            deny_domains=deny_domains,
            override_domains=override_domains,
            populate=tier is not None and tier.live,
        )
    )

    # Stop the old dnsmasq, then relaunch it reading the fresh conf.  The
    # netns already carries the listen address on ``lo`` (added at
    # createRuntime and persistent for the container's lifetime), so no
    # ``ip addr add`` is needed here.
    binary = require_host_tool(bundle.dnsmasq_command.read_text().strip())
    _terminate(pid_int, state_dir)
    _clear_pid_file(state_dir)
    bundle.dnsmasq_bin.write_text(binary + "\n")
    runner.dnsmasq_via_nsenter(container, str(conf_path), binary=binary)
    _await_restart(state_dir)


def _terminate(pid_int: int, state_dir: Path, timeout_s: float = 2.0) -> None:
    """SIGTERM *pid_int*, wait for it to exit, then SIGKILL as a last resort."""
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid_int, signal.SIGTERM)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if not is_our_dnsmasq(pid_int, state_dir):
            return
        time.sleep(0.05)
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid_int, signal.SIGKILL)


def _await_restart(state_dir: Path, timeout_s: float = 2.0) -> None:
    """Confirm a fresh dnsmasq wrote its PID file and owns the conf."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        pid = _read_pid(state_dir)
        if pid is not None and is_our_dnsmasq(pid, state_dir):
            return
        time.sleep(0.05)
    raise RuntimeError(
        "dnsmasq did not restart after a config reload — container DNS is broken. "
        "Re-create the task to recover."
    )


# ── Domain file operations ─────────────────────────────


def read_merged_domains(state_dir: Path) -> list[str]:
    """Effective dnsmasq nftset domains: admitted (``+``) minus denied (``-``).

    Composed from the tiered ``policy/`` bundle (project/provider/live), so
    runtime ``shield allow``/``deny`` of a domain takes effect on the next
    dnsmasq reload.  Returns a deduplicated, stable-order list.
    """
    return StateBundle(state_dir).read_effective().dnsmasq_domains()


def read_denied_domains(state_dir: Path) -> list[str]:
    """Denied (``-``) domains from the composed policy bundle.

    Fed to [`generate_config`][terok_shield.dns.dnsmasq.generate_config] as
    DNS-plane sinkholes, so a denied name stops resolving at all instead of
    resolving and then timing out against the packet filter.
    """
    return StateBundle(state_dir).read_effective().deny_domains()


def read_override_domains(state_dir: Path) -> list[str]:
    """Break-glass (t10) override domains from the composed policy bundle.

    Fed to [`generate_config`][terok_shield.dns.dnsmasq.generate_config] as
    sinkhole punch-throughs: an override host is usually *also* denied by
    t20, and without the punch-through it would NXDOMAIN before its
    statically seeded t10 set ever saw a packet.
    """
    return StateBundle(state_dir).read_effective().override_domains()


# ── Container DNS setup ────────────────────────────────


# ── Config generation ──────────────────────────────────


def generate_config(
    upstream_dns: str,
    domains: list[str],
    pid_path: Path,
    *,
    listen_address: str,
    log_path: Path | None = None,
    deny_domains: Sequence[str] = (),
    override_domains: Sequence[str] = (),
    populate: bool = True,
) -> str:
    """Generate a complete dnsmasq configuration.

    ``cache-size=0`` is deliberate: dnsmasq only performs the ``--nftset``
    add while processing an *upstream* reply, so a cached answer would hand
    the workload an IP without re-arming its (timeout-carrying) allow-set
    element.  With caching off, every query re-arms the element right before
    the connection that needs it; the upstream forwarder sits one hop away
    and caches on the host side.

    Args:
        upstream_dns: Upstream DNS forwarder (pasta or slirp4netns address).
        domains: Domain names for ``--nftset`` auto-population.
        pid_path: Path for the dnsmasq PID file.
        listen_address: Address dnsmasq binds to inside the netns.  See
            [`DNSMASQ_BIND_DEFAULT`][terok_shield.nft.constants.DNSMASQ_BIND_DEFAULT]
            /
            [`DNSMASQ_BIND_KRUN`][terok_shield.nft.constants.DNSMASQ_BIND_KRUN].
        log_path: If set, enable query logging to this file (for ``shield watch``).
        deny_domains: Denied domains, sinkholed in the DNS plane (NXDOMAIN)
            so they fail fast and observably instead of resolving and then
            timing out against the packet filter.
        override_domains: t10 break-glass override domains — treated as
            allowed by the sinkhole generator (exact-name denies emit no
            sinkhole, subdomain-of-denied-ancestor gets a punch-through)
            without joining the ``--nftset`` population: the override's
            addresses are statically seeded into the t10 set, the DNS plane
            only has to keep the name resolvable.
        populate: Emit the ``nftset=`` lines.  False for a dnsmasq built
            without nftset support, which then serves the query log and the
            sinkholes while the allow sets are seeded statically.

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
        "cache-size=0",
        f"server={upstream_dns}",
        f"pid-file={pid_path}",
    ]
    if log_path is not None:
        lines += ["log-queries", f"log-facility={log_path}"]
    for domain in domains if populate else ():
        try:
            lines.append(nftset_entry(domain))
        except ValueError:
            logger.warning("generate_config: skipping invalid domain entry")
            continue
    lines += deny_config_lines([*domains, *override_domains], deny_domains, upstream_dns)
    return "\n".join(lines) + "\n"


def deny_config_lines(
    allow_domains: Sequence[str], deny_domains: Sequence[str], upstream_dns: str
) -> list[str]:
    """DNS-plane deny: NXDOMAIN sinkholes for denied domains, with punch-throughs.

    Emits ``local=/dom/`` (never forwarded, answered NXDOMAIN) for each
    denied domain.  dnsmasq matches domain directives by longest suffix, so
    an *allowed* strict subdomain of a denied ancestor gets an explicit
    ``server=/sub/upstream`` punch-through — mirroring the policy engine,
    where the more specific allow entry survives the ancestor deny.

    Two deliberate asymmetries with the packet filter:

    - A deny at exactly an allowed domain's own name emits **no** sinkhole
      (a same-specificity directive conflict has no defined winner in
      dnsmasq); the IP tiers still govern actual connectivity.
    - The sinkhole stops the *name*, not the address — an IP learned via a
      legitimately allowed co-hosted domain remains reachable.  That gap is
      intrinsic to L3/L4 enforcement; the DNS plane just fails the common
      case fast and visibly.

    Invalid entries are skipped with a warning, matching the nftset path.
    """
    allows = set()
    for domain in allow_domains:
        try:
            allows.add(_strip_wildcard(_validate_domain(domain)))
        except ValueError:
            continue  # the nftset loop already warned about it
    lines: list[str] = []
    for domain in deny_domains:
        try:
            base = _strip_wildcard(_validate_domain(domain))
        except ValueError:
            logger.warning("deny_config_lines: skipping invalid deny entry")
            continue
        if base in allows:
            continue  # same-specificity conflict — leave it to the IP tiers
        lines.append(f"local=/{base}/")
        lines += (
            f"server=/{allowed}/{upstream_dns}"
            for allowed in sorted(allows)
            if allowed.endswith(f".{base}")
        )
    return list(dict.fromkeys(lines))


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

    Maps A records to the IPv4 project-allow set and AAAA records to the
    IPv6 project-allow set (tier 40).  dnsmasq automatically matches the
    domain and all its subdomains.

    Example::

        nftset=/github.com/4#inet#terok_shield#t40_project_allow_v4,6#inet#terok_shield#t40_project_allow_v6
    """
    domain = _strip_wildcard(_validate_domain(domain))
    return (
        f"nftset=/{domain}"
        f"/4#inet#{NFT_TABLE_NAME}#{TIER_PROJECT_ALLOW}_v4"
        f",6#inet#{NFT_TABLE_NAME}#{TIER_PROJECT_ALLOW}_v6"
    )


# ── Capability probing ─────────────────────────────────


def has_nftset_support(runner: CommandRunner, binary: str) -> bool:
    """Return True if the dnsmasq at *binary* supports ``--nftset``.

    Parses ``dnsmasq --version`` compile-time options for the ``nftset``
    feature flag.  A build without it prints ``no-nftset``.
    """
    out = runner.run([binary, "--version"], check=False)
    return bool(re.search(r"\bnftset\b", out)) and not bool(re.search(r"\bno-nftset\b", out))


# ── Private helpers ────────────────────────────────────


def _strip_wildcard(domain: str) -> str:
    """Drop a leading ``*.`` — dnsmasq domain directives inherently match subdomains."""
    return domain.removeprefix("*.")


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
    pid_path = StateBundle(state_dir).dnsmasq_pid
    try:
        return int(pid_path.read_text().strip())
    except (OSError, ValueError):
        return None


def _clear_pid_file(state_dir: Path) -> None:
    """Remove the dnsmasq PID file (best-effort)."""
    try:
        StateBundle(state_dir).dnsmasq_pid.unlink()
    except OSError:
        pass
