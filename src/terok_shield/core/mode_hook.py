# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Hook mode: OCI hooks + per-container netns.

Uses OCI hooks to apply per-container nftables rules inside each
container's network namespace.  No root required — only podman and nft.
The stdlib-only ``hook_entrypoint.py`` applies the pre-generated ruleset
at container creation; this module handles DNS pre-resolution, live
allow/deny, and shield lifecycle (up/down/state).
"""

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

from ..common.config import (
    ANNOTATION_AUDIT_ENABLED_KEY,
    ANNOTATION_DNS_TIER_KEY,
    ANNOTATION_INTERACTIVE_KEY,
    ANNOTATION_KEY,
    ANNOTATION_LOOPBACK_PORTS_KEY,
    ANNOTATION_NAME_KEY,
    ANNOTATION_STATE_DIR_KEY,
    ANNOTATION_UPSTREAM_DNS_KEY,
    ANNOTATION_VERSION_KEY,
    DnsTier,
    ShieldConfig,
    ShieldState,
    detect_dns_tier,
)
from ..common.podman_info import (
    PodmanInfo,
    global_hooks_hint,
    has_global_hooks,
    parse_podman_info,
    parse_resolv_conf,
)
from ..common.util import is_ip as _is_ip, is_ipv4
from . import dnsmasq, state
from .hook_install import install_hooks
from .nft import (
    NFT_TABLE,
    RulesetBuilder,
    add_deny_elements_dual,
    delete_deny_elements_dual,
    safe_ip,
)
from .nft_constants import (
    NFT_SET_TIMEOUT_DNSMASQ,
    PASTA_DNS,
    PASTA_HOST_LOOPBACK_MAP,
    SLIRP4NETNS_DNS,
)
from .run import ExecError, ShieldNeedsSetup

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from ..lib.audit import AuditLogger
    from ..lib.profiles import ProfileLoader
    from .dns import DnsResolver
    from .run import CommandRunner


class HookMode:
    """Hook-mode shield backend (Strategy, implements ``ShieldModeBackend``).

    Manages the full lifecycle of OCI-hook-based container firewalling:
    pre-start DNS resolution and hook installation, live allow/deny,
    bypass (down/up), and ruleset preview.
    """

    def __init__(
        self,
        *,
        config: ShieldConfig,
        runner: "CommandRunner",
        audit: "AuditLogger",
        dns: "DnsResolver",
        profiles: "ProfileLoader",
        ruleset: RulesetBuilder,
    ) -> None:
        """Create a hook mode backend with all collaborators.

        Args:
            config: Shield configuration (provides state_dir).
            runner: Command runner for subprocess calls.
            audit: Audit logger for event logging.
            dns: DNS resolver for domain resolution and caching.
            profiles: Profile loader for allowlist profiles.
            ruleset: Ruleset builder for nft generation and verification.
        """
        self._config = config
        self._runner = runner
        self._audit = audit
        self._dns = dns
        self._profiles = profiles
        self._ruleset = ruleset
        self._podman_info: PodmanInfo | None = None

    # ── Setup (pre_start) ───────────────────────────────

    def pre_start(self, container: str, profiles: list[str]) -> list[str]:
        """Prepare for container start in hook mode.

        Installs hooks, composes profiles, resolves DNS, writes
        allowlist, detects DNS tier, sets annotations, and returns
        the podman CLI arguments needed for shield protection.

        Raises:
            ShieldNeedsSetup: When global hooks are not installed
                (see ``WORKAROUND(hooks-dir-persist)``).
        """
        sd = self._config.state_dir.resolve()
        info = self._get_podman_info()
        interactive = self._config.interactive

        # Ensure state dirs and install hooks (idempotent)
        state.ensure_state_dirs(sd)
        install_hooks(
            hook_entrypoint=state.hook_entrypoint(sd),
            hooks_dir=state.hooks_dir(sd),
        )

        # Detect DNS tier and upstream DNS
        tier = self._detect_dns_tier()
        mode = info.network_mode or "pasta"
        upstream_dns = _upstream_dns_for_mode(mode)

        # Resolve DNS, write allowlists, generate ruleset + dnsmasq config
        entries = self._profiles.compose_profiles(profiles)
        self._resolve_and_write_allowlists(sd, tier, entries)
        state.upstream_dns_path(sd).write_text(f"{upstream_dns}\n")
        state.dns_tier_path(sd).write_text(f"{tier.value}\n")
        self._write_ruleset(sd, tier, upstream_dns)
        self._write_dnsmasq_config_or_scrub(sd, tier, upstream_dns)

        # Build podman args
        args = self._build_network_args(mode)

        # Redirect container DNS through per-container dnsmasq via volume mount.
        # See commit history for detailed rationale on why --dns cannot be used.
        if tier == DnsTier.DNSMASQ:
            args += ["--volume", f"{state.resolv_conf_path(sd)}:/etc/resolv.conf:ro,Z"]

        # Annotations: profiles, name, state_dir, loopback_ports, version, dns
        ports_str = ",".join(str(p) for p in self._config.loopback_ports)
        args += [
            "--annotation",
            f"{ANNOTATION_KEY}={','.join(profiles)}",
            "--annotation",
            f"{ANNOTATION_NAME_KEY}={container}",
            "--annotation",
            f"{ANNOTATION_STATE_DIR_KEY}={sd}",
            "--annotation",
            f"{ANNOTATION_LOOPBACK_PORTS_KEY}={ports_str}",
            "--annotation",
            f"{ANNOTATION_VERSION_KEY}={state.BUNDLE_VERSION}",
            "--annotation",
            f"{ANNOTATION_AUDIT_ENABLED_KEY}={str(self._config.audit_enabled).lower()}",
            "--annotation",
            f"{ANNOTATION_UPSTREAM_DNS_KEY}={upstream_dns}",
            "--annotation",
            f"{ANNOTATION_DNS_TIER_KEY}={tier.value}",
            "--annotation",
            f"{ANNOTATION_INTERACTIVE_KEY}={str(interactive).lower()}",
        ]

        # WORKAROUND(hooks-dir-persist): currently always takes the global path
        if info.hooks_dir_persists:
            args += ["--hooks-dir", str(state.hooks_dir(sd))]
        elif has_global_hooks():
            self._audit.log_event(
                container,
                "setup",
                detail=(
                    f"podman {'.'.join(str(v) for v in info.version)}: "
                    "using global hooks dir (--hooks-dir does not persist on restart)"
                ),
            )
        else:
            raise ShieldNeedsSetup(
                f"Podman {'.'.join(str(v) for v in info.version)} detected.\n\n"
                + global_hooks_hint()
            )

        args += [
            "--cap-drop",
            "NET_ADMIN",
            "--cap-drop",
            "NET_RAW",
        ]
        return args

    def _resolve_and_write_allowlists(self, sd: Path, tier: DnsTier, entries: list[str]) -> None:
        """Resolve profile entries and write allowlist files for the detected tier."""
        if tier == DnsTier.DNSMASQ:
            # dnsmasq handles domain→IP resolution at runtime via --nftset.
            # Split entries: write domains for dnsmasq config, resolve only raw IPs.
            domains, raw_ips = _split_domains_ips(entries)
            state.profile_domains_path(sd).write_text("\n".join(domains) + "\n" if domains else "")
            self._dns.resolve_and_cache(raw_ips, state.profile_allowed_path(sd))
        else:
            # dig/getent tier: resolve everything to IPs at pre-start time.
            self._dns.resolve_and_cache(entries, state.profile_allowed_path(sd))

    def _write_ruleset(self, sd: Path, tier: DnsTier, upstream_dns: str) -> None:
        """Pre-generate the complete nft ruleset into the state bundle."""
        set_timeout = NFT_SET_TIMEOUT_DNSMASQ if tier == DnsTier.DNSMASQ else ""
        interactive = self._config.interactive
        ruleset_builder = RulesetBuilder(
            dns=upstream_dns,
            loopback_ports=self._config.loopback_ports,
            set_timeout=set_timeout,
        )
        ips = state.read_effective_ips(sd)
        denied_ips = list(state.read_denied_ips(sd))
        ruleset = ruleset_builder.build_hook(interactive=interactive)
        ruleset += ruleset_builder.add_elements_dual(ips)
        if denied_ips:
            ruleset += add_deny_elements_dual(denied_ips)
        state.ruleset_path(sd).write_text(ruleset)

        # Persist interactive mode flag for shield_up() and the verdict handler
        if interactive:
            state.interactive_path(sd).write_text("nflog\n")
        else:
            state.interactive_path(sd).unlink(missing_ok=True)

    def _write_dnsmasq_config_or_scrub(self, sd: Path, tier: DnsTier, upstream_dns: str) -> None:
        """Pre-generate dnsmasq config for dnsmasq tier, or scrub stale artifacts."""
        if tier == DnsTier.DNSMASQ:
            domains = dnsmasq.read_merged_domains(sd)
            conf = dnsmasq.generate_config(
                upstream_dns,
                domains,
                state.dnsmasq_pid_path(sd),
                log_path=state.dnsmasq_log_path(sd),
            )
            state.dnsmasq_conf_path(sd).write_text(conf)
            state.resolv_conf_path(sd).write_text("nameserver 127.0.0.1\noptions ndots:0\n")
        else:
            for stale in (
                state.dnsmasq_conf_path(sd),
                state.dnsmasq_pid_path(sd),
                state.resolv_conf_path(sd),
            ):
                stale.unlink(missing_ok=True)

    def _build_network_args(self, mode: str) -> list[str]:
        """Build rootless network arguments (pasta or slirp4netns)."""
        if os.geteuid() == 0:
            return []
        if mode == "slirp4netns":
            return [
                "--network",
                "slirp4netns:allow_host_loopback=true",
                "--add-host",
                "host.containers.internal:10.0.2.2",
            ]
        # Use pasta --map-host-loopback unconditionally so that
        # host.containers.internal always resolves to an address
        # pasta actually forwards to the host's 127.0.0.1.
        return [
            "--network",
            f"pasta:--map-host-loopback,{PASTA_HOST_LOOPBACK_MAP}",
            "--add-host",
            f"host.containers.internal:{PASTA_HOST_LOOPBACK_MAP}",
        ]

    def _detect_dns_tier(self) -> DnsTier:
        """Detect the best available DNS resolution tier."""
        return detect_dns_tier(self._runner.has, lambda: dnsmasq.has_nftset_support(self._runner))

    def _get_podman_info(self) -> PodmanInfo:
        """Get podman info, caching the result for the lifetime of this instance."""
        if self._podman_info is None:
            output = self._runner.run(["podman", "info", "-f", "json"], check=False)
            self._podman_info = parse_podman_info(output)
        return self._podman_info

    # ── Live operations (domain) ───────────────────────

    def allow_domain(self, domain: str) -> None:
        """Add a domain to the dnsmasq config and signal reload.

        Delegates to ``dnsmasq.add_domain()``, which persists the domain to
        ``live.domains`` (not ``profile.domains``) and removes any matching
        entry from ``denied.domains``.  When dnsmasq is running, a SIGHUP is
        sent so the change takes effect immediately without a container restart.
        These entries are runtime additions: they survive dnsmasq reloads but
        are separate from the pre-start ``profile.domains`` list.

        The IP-level allow (nft set update) is handled separately by
        ``allow_ip()`` — this method is the domain-tracking counterpart
        that ensures future IP rotations are also captured.

        No-op when the container is not using the dnsmasq DNS tier (the
        static IP-level allow already happened via ``allow_ip()``).
        """
        sd = self._config.state_dir.resolve()
        if not _is_dnsmasq_tier(sd):
            return
        if not dnsmasq.add_domain(sd, domain):
            return  # already present
        self._reload_dnsmasq(sd)

    def deny_domain(self, domain: str) -> None:
        """Remove a domain from the dnsmasq config and signal reload.

        Counterpart of ``allow_domain()``.  Removes the domain so dnsmasq
        stops auto-populating nft sets for it on future DNS queries.

        No-op when the container is not using the dnsmasq DNS tier.
        """
        sd = self._config.state_dir.resolve()
        if not _is_dnsmasq_tier(sd):
            return
        if not dnsmasq.remove_domain(sd, domain):
            return  # not present
        self._reload_dnsmasq(sd)

    def _reload_dnsmasq(self, state_dir: Path) -> None:
        """Regenerate dnsmasq config and send SIGHUP.

        No-op if dnsmasq is not running (PID file absent).
        Raises RuntimeError if dnsmasq is dead (stale PID).
        """
        upstream = self._read_upstream_dns()
        if not upstream:
            raise RuntimeError("Cannot reload dnsmasq: upstream DNS not persisted in state")

        domains = dnsmasq.read_merged_domains(state_dir)
        dnsmasq.reload(state_dir, upstream, domains)

    # ── Live operations (IP) ────────────────────────────

    def allow_ip(self, container: str, ip: str) -> None:
        """Live-allow an IP for a running container via nsenter."""
        ip = safe_ip(ip)

        # Un-deny: remove from deny.list and nft deny set if present
        sd = self._config.state_dir.resolve()
        dp = state.deny_path(sd)
        if dp.is_file():
            denied = state.read_denied_ips(sd)
            if ip in denied:
                denied.discard(ip)
                dp.write_text("".join(f"{d}\n" for d in sorted(denied)))
                nft_cmd = delete_deny_elements_dual([ip])
                if nft_cmd:
                    self._nft_apply_best_effort(container, nft_cmd)

        # When the dnsmasq set has a default timeout (30 m), permanent IPs must use
        # 'timeout 0s' so they are never evicted by the set's per-element expiry clock.
        tier_path = state.dns_tier_path(sd)
        if tier_path.is_file() and tier_path.read_text().strip() == DnsTier.DNSMASQ.value:
            element = f"{{ {ip} timeout 0s }}"
        else:
            element = f"{{ {ip} }}"

        self._runner.nft_via_nsenter(
            container,
            "add",
            "element",
            "inet",
            "terok_shield",
            self._set_for_ip(ip),
            element,
        )
        # Persist to live.allowed (skip if already present)
        live_path = self._live_path()
        live_path.parent.mkdir(parents=True, exist_ok=True)
        existing = set(live_path.read_text().splitlines()) if live_path.is_file() else set()
        if ip not in existing:
            with live_path.open("a") as f:
                f.write(f"{ip}\n")

    def deny_ip(self, container: str, ip: str) -> None:
        """Live-deny an IP for a running container via nsenter.

        Removes from the nft allow set (best-effort) and from live.allowed.
        Adds to the nft deny set.  Persists to deny.list when the IP would
        otherwise be re-allowed (profile IP or interactive mode).
        """
        ip = safe_ip(ip)
        sd = self._config.state_dir.resolve()

        # Best-effort nft delete (IP may not be in the set)
        try:
            self._runner.nft_via_nsenter(
                container,
                "delete",
                "element",
                "inet",
                "terok_shield",
                self._set_for_ip(ip),
                f"{{ {ip} }}",
            )
        except ExecError as e:
            stderr = str(e).lower()
            if not any(
                pat in stderr for pat in ("no such file", "element does not exist", "not in set")
            ):
                logger.warning("nft delete element failed for %s: %s", ip, e)

        # Remove from live.allowed
        live_path = self._live_path()
        if live_path.is_file():
            lines = live_path.read_text().splitlines()
            lines = [line for line in lines if line.strip() != ip]
            live_path.write_text("\n".join(lines) + "\n" if lines else "")

        # Add to nft deny set (prevents dnsmasq from re-allowing)
        nft_cmd = add_deny_elements_dual([ip])
        if nft_cmd:
            self._nft_apply_best_effort(container, nft_cmd)

        # Persist to deny.list so deny sets survive shield_up / restart.
        # In interactive mode: always persist (operator rejects must stick).
        # In strict mode: only persist when the IP came from a profile.
        should_persist = state.interactive_path(sd).is_file()
        if not should_persist:
            profile_path = state.profile_allowed_path(sd)
            should_persist = profile_path.is_file() and ip in {
                ln.strip() for ln in profile_path.read_text().splitlines() if ln.strip()
            }
        if should_persist:
            dp = state.deny_path(sd)
            if ip not in state.read_denied_ips(sd):
                with dp.open("a") as f:
                    f.write(f"{ip}\n")

    def _set_for_ip(self, ip: str) -> str:
        """Return the nft set name for an IP address."""
        return "allow_v4" if is_ipv4(ip) else "allow_v6"

    def _live_path(self) -> Path:
        """Return the resolved path to live.allowed (prevents path traversal)."""
        return state.live_allowed_path(self._config.state_dir).resolve()

    def _nft_apply_best_effort(self, container: str, nft_cmd: str) -> None:
        """Run multi-line nft commands via nsenter, swallowing errors."""
        for line in nft_cmd.strip().splitlines():
            parts = line.strip().split()
            if parts:
                try:
                    self._runner.nft_via_nsenter(container, *parts)
                except ExecError:
                    pass

    # ── State transitions ───────────────────────────────

    def shield_down(self, container: str, *, allow_all: bool = False) -> None:
        """Switch a running container to bypass mode."""
        ruleset = self._container_ruleset(container)
        rs = ruleset.build_bypass(allow_all=allow_all)
        current = self.shield_state(container)
        if current == ShieldState.INACTIVE:
            stdin = rs
        else:
            stdin = f"delete table {NFT_TABLE}\n{rs}"
        self._runner.nft_via_nsenter(container, stdin=stdin)
        output = self._runner.nft_via_nsenter(container, "list", "ruleset")
        errors = ruleset.verify_bypass(output, allow_all=allow_all)
        if errors:
            raise RuntimeError(f"Bypass ruleset verification failed: {'; '.join(errors)}")

    def shield_up(self, container: str) -> None:
        """Restore normal deny-all mode for a running container."""
        sd = self._config.state_dir.resolve()
        interactive = state.interactive_path(sd).is_file()

        ruleset = self._container_ruleset(container)
        rs = ruleset.build_hook(interactive=interactive)
        current = self.shield_state(container)
        if current == ShieldState.INACTIVE:
            stdin = rs
        else:
            stdin = f"delete table {NFT_TABLE}\n{rs}"
        self._runner.nft_via_nsenter(container, stdin=stdin)

        # Re-add effective IPs (allowed minus denied)
        unique_ips = state.read_effective_ips(sd)
        if unique_ips:
            elements_cmd = ruleset.add_elements_dual(unique_ips)
            if elements_cmd:
                self._runner.nft_via_nsenter(container, stdin=elements_cmd)

        # Repopulate deny sets from deny.list
        denied_ips = list(state.read_denied_ips(sd))
        if denied_ips:
            deny_cmd = add_deny_elements_dual(denied_ips)
            if deny_cmd:
                self._runner.nft_via_nsenter(container, stdin=deny_cmd)

        # Repopulate gateway sets from persisted discovery (hook wrote them at container start)
        for gw_path, set_name in (
            (state.gateway_path(sd), "gateway_v4"),
            (state.gateway_v6_path(sd), "gateway_v6"),
        ):
            if gw_path.is_file():
                gw = gw_path.read_text().strip()
                if gw:
                    self._runner.nft_via_nsenter(
                        container,
                        "add",
                        "element",
                        "inet",
                        "terok_shield",
                        set_name,
                        f"{{ {gw} }}",
                    )

        output = self._runner.nft_via_nsenter(container, "list", "ruleset")
        errors = ruleset.verify_hook(output, interactive=interactive)
        if errors:
            raise RuntimeError(f"Ruleset verification failed: {'; '.join(errors)}")

    def _container_ruleset(self, container: str) -> RulesetBuilder:
        """Build a RulesetBuilder with the container's actual DNS settings.

        Prefers persisted upstream DNS (from pre_start) over resolv.conf,
        because dnsmasq mode rewrites resolv.conf to ``127.0.0.1``.
        """
        upstream = self._read_upstream_dns()
        dns = upstream if upstream else self._read_container_dns(container)

        # Read persisted DNS tier to determine if set timeouts are needed
        sd = self._config.state_dir.resolve()
        tier_path = state.dns_tier_path(sd)
        set_timeout = ""
        if tier_path.is_file():
            tier_str = tier_path.read_text().strip()
            if tier_str == DnsTier.DNSMASQ.value:
                set_timeout = NFT_SET_TIMEOUT_DNSMASQ

        return RulesetBuilder(
            dns=dns,
            loopback_ports=self._config.loopback_ports,
            set_timeout=set_timeout,
        )

    def _read_upstream_dns(self) -> str | None:
        """Read persisted upstream DNS from state (written by pre_start).

        Returns None if the file is absent (pre-dnsmasq container or
        container started before this feature).
        """
        sd = self._config.state_dir.resolve()
        path = state.upstream_dns_path(sd)
        if not path.is_file():
            return None
        value = path.read_text().strip()
        return value or None

    def _read_container_dns(self, container: str) -> str:
        """Read DNS nameserver from a running container's resolv.conf.

        Uses ``/proc/{pid}/root/etc/resolv.conf`` via ``podman unshare``
        to access the container's rootfs without entering its mount
        namespace (avoids requiring ``cat`` inside the container).
        """
        pid = self._runner.podman_inspect(container, "{{.State.Pid}}")
        output = self._runner.run(
            ["podman", "unshare", "cat", f"/proc/{pid}/root/etc/resolv.conf"],
            check=False,
        )
        dns = parse_resolv_conf(output)
        if not dns:
            raise RuntimeError(
                f"Cannot determine DNS for container {container}: no nameserver in resolv.conf"
            )
        return dns

    # ── Queries ─────────────────────────────────────────

    def shield_state(self, container: str) -> ShieldState:
        """Query the live nft ruleset to determine the container's shield state."""
        output = self.list_rules(container)
        if not output.strip():
            return ShieldState.INACTIVE

        # verify_* returns a list of errors; empty list = ruleset is valid
        if not self._ruleset.verify_bypass(output, allow_all=False):
            return ShieldState.DOWN
        if not self._ruleset.verify_bypass(output, allow_all=True):
            return ShieldState.DOWN_ALL

        # Check both strict and interactive hook rulesets
        if not self._ruleset.verify_hook(output):
            return ShieldState.UP
        if not self._ruleset.verify_hook(output, interactive=True):
            return ShieldState.UP

        return ShieldState.ERROR

    def list_rules(self, container: str) -> str:
        """List current nft rules for a running container."""
        try:
            return self._runner.nft_via_nsenter(
                container,
                "list",
                "table",
                "inet",
                "terok_shield",
                check=False,
            )
        except ExecError:
            return ""

    def preview(self, *, down: bool = False, allow_all: bool = False) -> str:
        """Generate the ruleset that would be applied to a container."""
        if down:
            return self._ruleset.build_bypass(allow_all=allow_all)
        return self._ruleset.build_hook(interactive=self._config.interactive)


# ── Module-level helpers ────────────────────────────────


def _upstream_dns_for_mode(network_mode: str) -> str:
    """Return the upstream DNS forwarder address for a network mode.

    Raises ValueError for unrecognised modes so new modes (e.g. bridge)
    get an explicit implementation rather than a silent wrong default.
    """
    if network_mode == "slirp4netns":
        return SLIRP4NETNS_DNS
    if network_mode == "pasta":
        return PASTA_DNS
    raise ValueError(
        f"Cannot determine upstream DNS for network mode {network_mode!r}. "
        "Add support for this mode in _upstream_dns_for_mode()."
    )


def _split_domains_ips(entries: list[str]) -> tuple[list[str], list[str]]:
    """Split profile entries into (domains, raw_ips).

    Domains are forwarded to dnsmasq for runtime resolution via ``--nftset``.
    Raw IPs are resolved/cached as before and loaded into nft sets at hook time.
    """
    domains: list[str] = []
    raw_ips: list[str] = []
    for entry in entries:
        if _is_ip(entry):
            raw_ips.append(entry)
        else:
            domains.append(entry)
    return domains, raw_ips


def _is_dnsmasq_tier(state_dir: Path) -> bool:
    """Return True when the container's DNS tier is dnsmasq (or unknown).

    ``allow_domain`` / ``deny_domain`` are dnsmasq-specific enhancements
    (future IP rotation tracking via ``--nftset``).  On dig/getent tiers
    the static IP-level allow/deny in ``allow_ip``/``deny_ip`` already ran;
    the domain-tracking step is simply not available and callers skip it.

    Returns True when ``dns_tier_path`` is absent (pre_start not yet run —
    pass-through so the caller can still attempt the dnsmasq operation).
    """
    tier_path = state.dns_tier_path(state_dir)
    if not tier_path.is_file():
        return True
    return tier_path.read_text().strip() == DnsTier.DNSMASQ.value
