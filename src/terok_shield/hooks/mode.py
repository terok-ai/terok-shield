# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Hook mode: OCI hooks + per-container netns.

Uses OCI hooks to apply per-container nftables rules inside each
container's network namespace.  No root required — only podman and nft.

Orchestrates collaborators per lifecycle phase:

- **RulesetBuilder** (``nft.rules``) — generates and verifies nft rulesets
- **DnsResolver** (``dns.resolver``) — pre-start domain resolution
- **ProfileLoader** (``profiles``) — allowlist profile composition
- **AuditLogger** (``audit``) — event logging
- **CommandRunner** (``run``) — subprocess execution (nft, nsenter)
- **dnsmasq** (``dns.dnsmasq``) — runtime DNS with nftset auto-population
- **hook_install** (``hooks.install``) — OCI hook file generation
- **state** (``state``) — per-container state bundle I/O
"""
# WAYPOINT: Shield (__init__)

import ipaddress
import logging
import os
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from .. import state
from ..config import (
    ANNOTATION_AUDIT_ENABLED_KEY,
    ANNOTATION_DNS_TIER_KEY,
    ANNOTATION_KEY,
    ANNOTATION_LIST_SEP,
    ANNOTATION_NAME_KEY,
    ANNOTATION_STATE_DIR_KEY,
    ANNOTATION_UPSTREAM_DNS_KEY,
    ANNOTATION_VERSION_KEY,
    DnsTier,
    ShieldConfig,
    ShieldRuntime,
    ShieldState,
    dns_tier_detail,
)
from ..dns import apparmor, dnsmasq
from ..nft.constants import (
    DNSMASQ_BIND_DEFAULT,
    DNSMASQ_BIND_KRUN,
    NFT_SET_TIMEOUT_DNSMASQ,
    NFT_TABLE,
    NFT_TABLE_NAME,
    PASTA_DNS,
    PASTA_HOST_LOOPBACK_MAP,
    SLIRP4NETNS_DNS,
    SLIRP4NETNS_GATEWAY_V6,
    TIER_PROJECT_ALLOW,
)
from ..nft.rules import (
    RulesetBuilder,
    add_deny_elements_dual,
    add_override_elements_dual,
    delete_deny_elements_dual,
    parse_set_elements,
    restore_elements,
    safe_ip,
)
from ..podman_info.hooks_dir import global_hooks_hint, has_global_hooks
from ..podman_info.info import PodmanInfo, parse_podman_info
from ..podman_info.network import parse_resolv_conf, slirp4netns_gateway
from ..run import ExecError, ShieldNeedsSetup
from ..state import StateBundle
from ..util import is_ipv4
from .install import install_hooks

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from ..audit import AuditLogger
    from ..dns.resolver import DnsResolver
    from ..profiles import ProfileLoader
    from ..run import CommandRunner


class HookMode:
    """Hook-mode shield backend (Strategy, implements ``ShieldModeBackend``).

    Coordinates the full lifecycle of OCI-hook-based container firewalling.
    Delegates to ``RulesetBuilder`` for nft generation, ``DnsResolver`` for
    name resolution, ``ProfileLoader`` for allowlists, ``dnsmasq`` for
    runtime DNS, and ``state`` for per-container persistence.
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
        self._gateways: tuple[str, str] | None = None

    # ── Setup (pre_start) ───────────────────────────────

    def pre_start(
        self,
        container: str,
        profiles: list[str],
        *,
        security_deny: Sequence[str] = (),
        provider_allow: Sequence[str] = (),
        project_allow: Sequence[str] = (),
        override: Sequence[str] = (),
    ) -> list[str]:
        """Prepare for container start in hook mode.

        Installs hooks, composes profiles, resolves DNS, writes
        allowlist, detects DNS tier, sets annotations, and returns
        the podman CLI arguments needed for shield protection.

        Args:
            security_deny: Hosts/IPs an upstream layer (executor's roster
                projection, carried by sandbox) generates for the t20
                security-deny tier — vault hosts denied direct egress.
            provider_allow: Hosts/IPs generated for the t30 provider-allow
                tier — agent/provider egress endpoints.
            project_allow: Hosts/IPs authored by the orchestrator for the t40
                project-allow tier (git remote, custom domains) — merged with
                the composed profiles.
            override: Hosts/IPs/CIDRs authored for the t10 break-glass override
                tier, which sits *above* the security-deny; statically resolved
                and seeded into a separate nft set.  A CIDR opens a whole
                subnet above the deny — accepted, but logged as a warning and
                an ``override_range`` audit event.  Shield owns writing every
                tier, so callers pass data, never touch the bundle.

        Raises:
            ShieldNeedsSetup: When global hooks are not installed
                (see ``WORKAROUND(hooks-dir-persist)``).
        """
        sd = self._config.state_dir.resolve()
        info = self._get_podman_info()

        # Ensure state dirs and install hooks (idempotent)
        StateBundle(sd).ensure_dirs()
        install_hooks(
            hook_entrypoint=StateBundle(sd).hook_entrypoint,
            hooks_dir=StateBundle(sd).hooks_dir,
        )

        # Detect DNS tier, upstream DNS, and gateway addresses
        tier = self._detect_dns_tier(container, sd)
        mode = info.network_mode or "pasta"
        upstream_dns = _upstream_dns_for_mode(mode)
        gw_v4, gw_v6 = self._gateways = _gateways_for_mode(mode)

        # Persist the launch-detected facts first: they are what ``refresh``
        # reuses instead of re-detecting, and ``_write_ruleset`` reads the
        # ports back out of the bundle (SSOT) rather than off the config, so
        # later up/down rebuilds share one source.
        bundle = StateBundle(sd)
        bundle.upstream_dns.write_text(f"{upstream_dns}\n")
        bundle.dns_tier.write_text(f"{tier.value}\n")
        bundle.network_mode.write_text(f"{mode}\n")
        bundle.loopback_ports.write_text("".join(f"{p}\n" for p in self._config.loopback_ports))
        self._author_policy(
            container,
            sd,
            profiles,
            tier,
            upstream_dns,
            (gw_v4, gw_v6),
            security_deny=security_deny,
            provider_allow=provider_allow,
            project_allow=project_allow,
            override=override,
        )

        # Build podman args
        args = self._build_network_args(mode)

        # WORKAROUND(pasta-dns-bind): bind-mount shield's own resolv.conf over
        # the container's on every tier instead of using podman --dns. --dns
        # makes pasta bind host port 53, which fails for a rootless container.
        # Podman's default resolv.conf lists the host's own nameservers; on an
        # AppArmor host one of those is a blocked LAN router, so the container
        # resolves nothing (#1246). Drop this when rootless podman/pasta can
        # set the container's resolvers without binding host port 53.
        args += ["--volume", f"{StateBundle(sd).resolv_conf}:/etc/resolv.conf:ro,Z"]

        # Annotations: profiles, name, state_dir, version, dns.  loopback_ports
        # lives in the state bundle (per-container, written above), not as an
        # annotation — annotations are write-only on shield's side.
        args += [
            "--annotation",
            f"{ANNOTATION_KEY}={ANNOTATION_LIST_SEP.join(profiles)}",
            "--annotation",
            f"{ANNOTATION_NAME_KEY}={container}",
            "--annotation",
            f"{ANNOTATION_STATE_DIR_KEY}={sd}",
            "--annotation",
            f"{ANNOTATION_VERSION_KEY}={state.BUNDLE_VERSION}",
            "--annotation",
            f"{ANNOTATION_AUDIT_ENABLED_KEY}={str(self._config.audit_enabled).lower()}",
            "--annotation",
            f"{ANNOTATION_UPSTREAM_DNS_KEY}={upstream_dns}",
            "--annotation",
            f"{ANNOTATION_DNS_TIER_KEY}={tier.value}",
        ]

        # WORKAROUND(hooks-dir-persist): currently always takes the global path
        if info.hooks_dir_persists:
            args += ["--hooks-dir", str(StateBundle(sd).hooks_dir)]
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

    def refresh(
        self,
        container: str,
        profiles: list[str],
        *,
        security_deny: Sequence[str] = (),
        provider_allow: Sequence[str] = (),
        project_allow: Sequence[str] = (),
        override: Sequence[str] = (),
    ) -> None:
        """Recompute an existing container's policy bundle before a plain restart.

        The policy-authoring half of
        [`pre_start`][terok_shield.hooks.mode.HookMode.pre_start] without the
        launch half: rewrites every tier from the caller's current data,
        refreshes the static-resolution caches, and regenerates
        ``ruleset.nft`` + the dnsmasq config — so the OCI hook applies
        *current* policy at the next ``podman start`` instead of replaying
        the bundle frozen at creation.  Reuses every launch-detected fact the
        bundle persisted — DNS tier, upstream DNS, network mode, loopback
        ports — rather than re-detecting: the container's mounts and
        annotations were built for those, a fresh detection could disagree
        with them, and a restart stays free of ``podman info``.

        Raises:
            RuntimeError: When the bundle carries no persisted DNS tier /
                upstream DNS / network mode (``pre_start`` never ran for this
                state dir).
        """
        sd = self._config.state_dir.resolve()
        bundle = StateBundle(sd)
        # Through ``read_dns_tier``, not the raw file: it is the one place that
        # knows which recorded names are still tiers, so a container written
        # under a retired name restarts here instead of raising out of
        # ``DnsTier``.
        tier_str = bundle.read_dns_tier()
        mode = bundle.network_mode.read_text().strip() if bundle.network_mode.is_file() else ""
        upstream_dns = self._read_upstream_dns()
        if not tier_str or not upstream_dns or not mode:
            raise RuntimeError(
                "shield bundle has no persisted DNS tier / upstream DNS / network mode — "
                "pre_start never completed for this container; re-create the task"
            )
        self._gateways = _gateways_for_mode(mode)
        self._author_policy(
            container,
            sd,
            profiles,
            DnsTier(tier_str),
            upstream_dns,
            self._gateways,
            security_deny=security_deny,
            provider_allow=provider_allow,
            project_allow=project_allow,
            override=override,
        )

    def _author_policy(
        self,
        container: str,
        sd: Path,
        profiles: list[str],
        tier: DnsTier,
        upstream_dns: str,
        gateways: tuple[str, str],
        *,
        security_deny: Sequence[str],
        provider_allow: Sequence[str],
        project_allow: Sequence[str],
        override: Sequence[str],
    ) -> None:
        """Write every tier, refresh the seed caches, regenerate the artifacts.

        The half of [`pre_start`][terok_shield.hooks.mode.HookMode.pre_start]
        that [`refresh`][terok_shield.hooks.mode.HookMode.refresh] repeats.  A
        launch and a plain restart must derive the *same* bundle from the same
        tier data, so a new tier or a new resolution step belongs here — where
        neither path can miss it.
        """
        entries = self._profiles.compose_profiles(profiles) + list(project_allow)
        self._write_generated_tiers(container, sd, security_deny, provider_allow, override)
        self._write_policy_and_resolve(sd, entries, tier)
        self._resolve_override(sd)
        self._resolve_security_deny(sd)
        self._write_ruleset(sd, tier, upstream_dns, *gateways)
        self._write_dns_artifacts(sd, tier, upstream_dns)

    def _write_generated_tiers(
        self,
        container: str,
        sd: Path,
        security_deny: Sequence[str],
        provider_allow: Sequence[str],
        override: Sequence[str],
    ) -> None:
        """Persist the caller-generated t20/t30/t10 tiers into the policy bundle.

        These are the orchestrator-owned tiers Phase 1 left empty: t20 vault-host
        denies, t30 provider-allow endpoints, and t10 break-glass overrides.
        Shield owns the on-disk layout, so it renders the ``-``/``+`` policy lines
        and writes them here rather than exposing the bundle;
        [`EffectivePolicy`][terok_shield.state.EffectivePolicy] already composes
        every tier into resolution, dnsmasq domains, and the ruleset.
        Content-stable (empty input clears the tier).
        """
        bundle = StateBundle(sd)
        bundle.write_tier("security_deny", "".join(f"-{h}\n" for h in security_deny))
        bundle.write_tier("provider_allow", "".join(f"+{h}\n" for h in provider_allow))
        self._log_override_ranges(container, override)
        bundle.write_tier("override", "".join(f"+{h}\n" for h in override))

    def _log_override_ranges(self, container: str, override: Sequence[str]) -> None:
        """Warn about every CIDR in the t10 override tier — a subnet opened above the deny.

        A break-glass override sits above the security-deny, so a range widens
        a whole subnet straight through the firewall.  Opening the agent to
        several local services is a legitimate way to run, so the launch goes
        ahead — but each range lands in the log and the audit trail, so the
        widening never passes unnoticed.
        """
        for net in (h for h in override if "/" in h):
            logger.warning("t10 override opens a whole range above the security-deny: %s", net)
            self._audit.log_event(container, "override_range", detail=net)

    def _resolve_override(self, sd: Path) -> None:
        """Statically resolve the t10 break-glass targets into the override seed cache.

        The override tier is a *separate* above-deny nft set, resolved
        independently of the allow tiers and statically on every DNS tier —
        break-glass entries are rare and specific, and dnsmasq interception
        would populate t40 (below the deny), defeating the override.
        """
        bundle = StateBundle(sd)
        self._resolve_tier(
            bundle, bundle.read_effective().override_targets(), bundle.override_resolved
        )

    def _resolve_security_deny(self, sd: Path) -> None:
        """Statically resolve the t20 security-deny targets into the deny seed cache.

        Denied domains must deny by *address*: the deny set is enforced even
        in the shield-down posture (the down transition repopulates it from
        [`read_denied_ips`][terok_shield.state.StateBundle.read_denied_ips]),
        and an address-level deny also catches direct-IP access that never
        consults the DNS plane.  Resolved statically on every DNS tier —
        dnsmasq interception only ever *adds* to allow sets, so it can play
        no part in populating a deny.
        """
        bundle = StateBundle(sd)
        self._resolve_tier(bundle, bundle.read_effective().deny_targets(), bundle.deny_resolved)

    def _resolve_tier(self, bundle: StateBundle, targets: list[str], cache: Path) -> None:
        """Refresh one tier's static-resolution cache; an empty tier clears it."""
        if not targets:
            cache.unlink(missing_ok=True)
            return
        self._dns.resolve_and_cache(targets, cache, source_mtime=bundle.policy_mtime())

    def _write_policy_and_resolve(self, sd: Path, entries: list[str], tier: DnsTier) -> None:
        """Write the composed profiles as the project-allow tier; statically resolve only where needed.

        The authored ``policy/40-project-allow`` is the source of truth
        (domains + literal IPs).  On the dnsmasq tier there is **no**
        pre-resolution: dnsmasq commits every answered A/AAAA record to the
        allow sets *before* forwarding the reply (``forward.c`` calls the
        nftset add synchronously while processing the upstream response), so
        a workload can never race its own answer.  The kernel set is
        populated on demand, per query — launch cost stays O(1) in allowlist
        size, and CDN rotation is tracked for free.  Any stale
        ``resolved.ips`` is removed so the ruleset seeds from literal IPs
        only.

        The lookup/getent fallback tiers have no DNS interception point, so
        statically resolving every admitted target into ``resolved.ips``
        (refreshed when stale or older than the authored policy) remains
        their only domain-enforcement mechanism.
        """
        bundle = StateBundle(sd)
        bundle.write_tier("project_allow", "".join(f"+{e}\n" for e in entries))
        if tier == DnsTier.DNSMASQ:
            bundle.resolved_cache.unlink(missing_ok=True)
            return
        self._dns.resolve_and_cache(
            bundle.read_effective().allow_targets(),
            bundle.resolved_cache,
            source_mtime=bundle.policy_mtime(),
        )

    def _write_ruleset(
        self, sd: Path, tier: DnsTier, upstream_dns: str, gw_v4: str = "", gw_v6: str = ""
    ) -> None:
        """Pre-generate the complete nft ruleset into the state bundle."""
        set_timeout = NFT_SET_TIMEOUT_DNSMASQ if tier == DnsTier.DNSMASQ else ""
        ruleset_builder = RulesetBuilder(
            dns=upstream_dns,
            loopback_ports=StateBundle(sd).read_loopback_ports(),
            gateway_v4=gw_v4,
            gateway_v6=gw_v6,
            set_timeout=set_timeout,
        )
        ips = StateBundle(sd).read_effective_ips()
        override_ips = list(StateBundle(sd).read_override_ips())
        denied_ips = list(StateBundle(sd).read_denied_ips())
        ruleset = ruleset_builder.build_up()
        ruleset += ruleset_builder.add_elements_dual(ips)
        if override_ips:
            ruleset += add_override_elements_dual(override_ips)
        if denied_ips:
            ruleset += add_deny_elements_dual(denied_ips)
        StateBundle(sd).ruleset.write_text(ruleset)

    def _write_dns_artifacts(self, sd: Path, tier: DnsTier, upstream_dns: str) -> None:
        """Write the container's ``resolv.conf`` on every tier, and its
        ``dnsmasq.conf`` on the dnsmasq tier.

        Shield owns the container's ``resolv.conf`` on every tier. The
        alternative is podman's default ``resolv.conf``. That default lists
        the host's own nameservers. On an AppArmor host such as Manjaro, one
        of those is a LAN router. The egress filter rejects the router as a
        private range, so the container resolves nothing (#1246).  The file is
        bind-mounted read-only over the container's ``/etc/resolv.conf`` — see
        ``WORKAROUND(pasta-dns-bind)`` in ``pre_start``.

        - **dnsmasq tier**: point ``resolv.conf`` at the per-container dnsmasq
          bind address. dnsmasq forwards to *upstream_dns* and adds each
          resolved address to the allow sets.
        - **lookup / getent tiers**: no per-container dnsmasq runs, so point
          ``resolv.conf`` straight at *upstream_dns*, the forwarder the
          firewall allows. Name resolution then uses the forwarder. The nft
          sets still gate egress, so this widens resolution only, never
          reachability. This also removes the dnsmasq artifacts.
        """
        bundle = StateBundle(sd)
        if tier == DnsTier.DNSMASQ:
            bind = _dnsmasq_bind(self._config.runtime)
            domains = dnsmasq.read_merged_domains(sd)
            conf = dnsmasq.generate_config(
                upstream_dns,
                domains,
                bundle.dnsmasq_pid,
                listen_address=bind,
                log_path=bundle.dnsmasq_log,
                deny_domains=dnsmasq.read_denied_domains(sd),
                override_domains=dnsmasq.read_override_domains(sd),
            )
            bundle.dnsmasq_conf.write_text(conf)
            bundle.resolv_conf.write_text(f"nameserver {bind}\noptions ndots:0\n")
            return
        bundle.dnsmasq_conf.unlink(missing_ok=True)
        bundle.dnsmasq_pid.unlink(missing_ok=True)
        bundle.dnsmasq_log.unlink(missing_ok=True)
        bundle.resolv_conf.write_text(f"nameserver {upstream_dns}\noptions ndots:0\n")

    def _build_network_args(self, mode: str) -> list[str]:
        """Build rootless network arguments (pasta or slirp4netns)."""
        if os.geteuid() == 0:
            return []
        if mode == "slirp4netns":
            gw = slirp4netns_gateway()
            return [
                "--network",
                "slirp4netns:allow_host_loopback=true",
                "--add-host",
                f"host.containers.internal:{gw}",
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

    def _detect_dns_tier(self, container: str, state_dir: Path) -> DnsTier:
        """Pick the DNS tier. Warn on the console when AppArmor blocks dnsmasq.

        AppArmor confinement is not a silent downgrade. This warns the operator
        on the console (``logger.warning``) and in the audit log. The message
        names the lost dnsmasq tier and the way to restore it. The operator
        then sees the drop to static resolution at once, instead of tracing a
        later egress failure back to it.
        """
        tier, apparmor_blocked = apparmor.detect_dns_tier_under_apparmor(
            self._runner, state_dir, requested=self._config.dns_tier
        )
        if apparmor_blocked:
            rotation = (
                "Domain allowlists still follow a rotation — the built-in responder "
                "answers the container's own queries — but it answers A and AAAA only."
                if tier.is_dynamic
                else "Domain allowlists now resolve once at launch, not on each reply, so a "
                "domain whose address rotates can fail."
            )
            detail = (
                f"DNS tier fell back to "
                f"'{dns_tier_detail(tier, self._runner.has)}'. AppArmor confines dnsmasq from "
                f"{state_dir}, so the per-container dnsmasq tier is not available. "
                f"{rotation} To restore the dnsmasq tier, "
                "install the terok-shield AppArmor profile addendum. See docs/apparmor.md. "
                "The terok orchestrator installs it with 'terok setup'."
            )
            logger.warning("%s", detail)
            self._audit.log_event(container, "setup", detail=detail)
        return tier

    def _get_podman_info(self) -> PodmanInfo:
        """Get podman info, caching the result for the lifetime of this instance."""
        if self._podman_info is None:
            output = self._runner.run(["podman", "info", "-f", "json"], check=False)
            self._podman_info = parse_podman_info(output)
        return self._podman_info

    # ── Live operations (domain) ───────────────────────

    def allow_domain(self, container: str, domain: str) -> None:
        """Record ``+domain`` in the runtime overlay and reload dnsmasq.

        The overlay (``policy/live``) flips any prior deny of *domain* and
        survives reloads; the dnsmasq restart picks up the new ``nftset=``
        line so future IP rotations of *domain* are auto-populated.  The
        IP-level allow (nft set update) is handled separately by ``allow_ip()``.

        No-op when the container is not using the dnsmasq DNS tier (the static
        IP-level allow already happened via ``allow_ip()``).
        """
        sd = self._config.state_dir.resolve()
        if not _is_dnsmasq_tier(sd):
            return
        StateBundle(sd).overlay_set("+", domain)
        self._reload_dnsmasq(container, sd)

    def deny_domain(self, container: str, domain: str) -> None:
        """Record ``-domain`` in the runtime overlay and reload dnsmasq.

        Counterpart of ``allow_domain()``: the dnsmasq restart picks up the
        ``local=`` sinkhole, so *domain* stops resolving (NXDOMAIN) and the
        deny fails fast in the DNS plane instead of timing out against the
        filter.

        No-op when the container is not using the dnsmasq DNS tier.
        """
        sd = self._config.state_dir.resolve()
        if not _is_dnsmasq_tier(sd):
            return
        StateBundle(sd).overlay_set("-", domain)
        self._reload_dnsmasq(container, sd)

    def _reload_dnsmasq(self, container: str, state_dir: Path) -> None:
        """Regenerate the dnsmasq config and restart dnsmasq to load it.

        No-op if dnsmasq is not running (PID file absent).
        Raises RuntimeError if dnsmasq is dead (stale PID) or fails to restart.
        """
        upstream = self._read_upstream_dns()
        if not upstream:
            raise RuntimeError("Cannot reload dnsmasq: upstream DNS not persisted in state")

        domains = dnsmasq.read_merged_domains(state_dir)
        dnsmasq.reload(
            state_dir,
            upstream,
            domains,
            deny_domains=dnsmasq.read_denied_domains(state_dir),
            override_domains=dnsmasq.read_override_domains(state_dir),
            container=container,
            runner=self._runner,
        )

    # ── Live operations (IP) ────────────────────────────

    def allow_ip(self, container: str, ip: str) -> None:
        """Live-allow an IP for a running container via nsenter."""
        ip = safe_ip(ip)
        sd = self._config.state_dir.resolve()
        bundle = StateBundle(sd)

        # Un-deny: drop from the nft deny set if it is currently denied.
        if ip in bundle.read_denied_ips():
            nft_cmd = delete_deny_elements_dual([ip])
            if nft_cmd:
                self._nft_apply_best_effort(container, nft_cmd)

        # When the dnsmasq set has a default timeout (30 m), permanent IPs must use
        # 'timeout 0s' so they are never evicted by the set's per-element expiry clock.
        tier_path = bundle.dns_tier
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
        # Persist to the runtime overlay (flips any prior deny of this IP).
        bundle.overlay_set("+", ip)

    def deny_ip(self, container: str, ip: str) -> None:
        """Live-deny an IP for a running container via nsenter.

        Removes from the nft allow set (best-effort), adds to the nft deny set,
        and records ``-ip`` in ``policy/live`` so the deny sticks across
        ``shield up`` / restart and flips any prior allow.
        """
        ip = safe_ip(ip)
        sd = self._config.state_dir.resolve()
        bundle = StateBundle(sd)

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

        # Add to nft deny set (prevents dnsmasq from re-allowing)
        nft_cmd = add_deny_elements_dual([ip])
        if nft_cmd:
            self._nft_apply_best_effort(container, nft_cmd)

        # Persist to the runtime overlay (flips any prior allow; sticks across restart).
        bundle.overlay_set("-", ip)

    def _set_for_ip(self, ip: str) -> str:
        """Return the tier-40 project-allow nft set for an IP address (by family)."""
        return f"{TIER_PROJECT_ALLOW}_v4" if is_ipv4(ip) else f"{TIER_PROJECT_ALLOW}_v6"

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

    def shield_down(self, container: str, *, disengaged: bool = False) -> None:
        """Switch a running container to the DOWN posture (DISENGAGED when *disengaged*).

        Plain DOWN accepts by default but keeps the deny set and both range
        floors; DISENGAGED enforces nothing, so its deny sets are left empty —
        the next ``shield up`` repopulates them from the composed policy.
        """
        sd = self._config.state_dir.resolve()
        ruleset = self._container_ruleset(container)
        rs = ruleset.build_down(disengaged=disengaged)
        current = self.shield_state(container)
        if current == ShieldState.OFFLINE:
            stdin = rs
        else:
            stdin = f"delete table {NFT_TABLE}\n{rs}"
        snapshot = [] if current == ShieldState.OFFLINE else self._snapshot_allow_sets(container)
        self._runner.nft_via_nsenter(container, stdin=stdin)

        # Carry the allow-set contents (seeds + dnsmasq-learned IPs) across
        # the rebuild — the down posture does not evaluate them, but the later
        # ``shield up`` snapshots this table, so dropping them here would
        # forget every learned IP after one down/up round trip.
        self._restore_allow_sets(container, snapshot, skip=())

        # Repopulate deny sets so the deny policy is enforced even when shield
        # is down, and the t10 override set so break-glass hosts stay above it.
        # DISENGAGED references neither set, so there is nothing to reseed.
        if not disengaged:
            self._reseed_deny_and_override(container, sd)

        output = self._runner.nft_via_nsenter(
            container,
            "list",
            "table",
            "inet",
            NFT_TABLE_NAME,
        )
        errors = ruleset.verify_down(output, disengaged=disengaged)
        if errors:
            raise RuntimeError(f"Shield-down ruleset verification failed: {'; '.join(errors)}")

    def shield_quarantine(self, container: str) -> None:
        """Total network blackout — drop all traffic, log dropped traffic.

        Reads no settings — no DNS, no allowlists, no loopback ports,
        no gateway probe, no profile lookup.  ``build_quarantine`` /
        ``verify_quarantine`` are static; the only inputs are the
        container name and the live ruleset state (table-or-no-table).
        Any config-conditional branch added here is a bug.
        """
        rs = RulesetBuilder.build_quarantine()
        current = self.shield_state(container)
        stdin = rs if current == ShieldState.OFFLINE else f"delete table {NFT_TABLE}\n{rs}"
        self._runner.nft_via_nsenter(container, stdin=stdin)
        output = self._runner.nft_via_nsenter(
            container,
            "list",
            "table",
            "inet",
            NFT_TABLE_NAME,
        )
        errors = RulesetBuilder.verify_quarantine(output)
        if errors:
            raise RuntimeError(f"Quarantine ruleset verification failed: {'; '.join(errors)}")

    def shield_up(self, container: str) -> None:
        """Restore normal deny-all mode for a running container.

        The rebuild is ``delete table`` + re-apply, which would forget every
        dnsmasq-learned allow-set element — a container coming out of the down
        posture would suddenly lose IPs its workload already resolved (clients
        cache answers, so they do not necessarily re-query).  The allow sets
        are therefore snapshotted before the rebuild and restored after it.
        """
        sd = self._config.state_dir.resolve()

        ruleset = self._container_ruleset(container)
        rs = ruleset.build_up()
        current = self.shield_state(container)
        if current == ShieldState.OFFLINE:
            stdin = rs
        else:
            stdin = f"delete table {NFT_TABLE}\n{rs}"
        snapshot = [] if current == ShieldState.OFFLINE else self._snapshot_allow_sets(container)
        self._runner.nft_via_nsenter(container, stdin=stdin)

        # Re-add effective IPs (allowed minus denied)
        unique_ips = StateBundle(sd).read_effective_ips()
        if unique_ips:
            elements_cmd = ruleset.add_elements_dual(unique_ips)
            if elements_cmd:
                self._runner.nft_via_nsenter(container, stdin=elements_cmd)

        # Repopulate the deny sets and the t10 override set from the bundle
        denied_ips = self._reseed_deny_and_override(container, sd)

        # Restore the snapshot, minus everything the rebuild already re-added
        # (a duplicate/overlapping element would abort the nft transaction)
        # and minus denied entries (deny_ip() removed them from the allow set
        # deliberately — a down/up round trip must not resurrect them).
        self._restore_allow_sets(container, snapshot, skip=[*unique_ips, *denied_ips])

        # Gateway addresses are baked into the ruleset — no repopulation needed.

        output = self._runner.nft_via_nsenter(
            container,
            "list",
            "table",
            "inet",
            NFT_TABLE_NAME,
        )
        errors = ruleset.verify_up(output)
        if errors:
            raise RuntimeError(f"Ruleset verification failed: {'; '.join(errors)}")

    def shield_reset(self, container: str) -> None:
        """Forget learned allow-set state — back to the just-launched contents.

        Flushes both tier-40 project-allow sets and re-seeds them from the
        effective policy in a single nft transaction, so authored literals
        never blink out.  dnsmasq-learned IPs vanish until the workload
        resolves the corresponding names again; the operator overlay
        (``policy/live``) and the deny tier are untouched.
        """
        sd = self._config.state_dir.resolve()
        ruleset = self._container_ruleset(container)
        stdin = (
            f"flush set {NFT_TABLE} {TIER_PROJECT_ALLOW}_v4\n"
            f"flush set {NFT_TABLE} {TIER_PROJECT_ALLOW}_v6\n"
        )
        stdin += ruleset.add_elements_dual(StateBundle(sd).read_effective_ips())
        self._runner.nft_via_nsenter(container, stdin=stdin)

    def _reseed_deny_and_override(self, container: str, sd: Path) -> list[str]:
        """Repopulate the t20 deny and t10 override sets after a table rebuild.

        Both sets seed purely from the bundle (literals + static-resolution
        caches), so unlike the dnsmasq-learned t40 they need no snapshot —
        every ``shield down``/``up`` rebuild re-derives them.  The override
        is re-seeded in *both* postures: it sits above the deny, and the
        deny is enforced even when the shield is down.  Returns the denied
        IPs so ``shield_up`` can exclude them from the snapshot restore.
        """
        denied_ips = list(StateBundle(sd).read_denied_ips())
        if denied_ips and (deny_cmd := add_deny_elements_dual(denied_ips)):
            self._runner.nft_via_nsenter(container, stdin=deny_cmd)
        override_ips = list(StateBundle(sd).read_override_ips())
        if override_ips and (override_cmd := add_override_elements_dual(override_ips)):
            self._runner.nft_via_nsenter(container, stdin=override_cmd)
        return denied_ips

    # ── Allow-set snapshot/restore (down/up round trips) ─

    def _snapshot_allow_sets(self, container: str) -> list[tuple[str, str, str]]:
        """Dump the tier-40 allow sets as ``(set_name, ip, timeout)`` rows.

        Captures seeds and dnsmasq-learned elements right before a table
        rebuild.  A missing table or set yields no rows — there was nothing
        to keep.  (Tiers 10/20 are re-seeded from the bundle by
        ``_reseed_deny_and_override`` instead — they have no *learned*
        state to preserve.  Tier 30 has no runtime population yet; extend
        this snapshot when it gains one.)
        """
        rows: list[tuple[str, str, str]] = []
        for fam in ("v4", "v6"):
            name = f"{TIER_PROJECT_ALLOW}_{fam}"
            try:
                out = self._runner.nft_via_nsenter(
                    container, "list", "set", "inet", NFT_TABLE_NAME, name
                )
            except ExecError:
                continue
            rows += [(name, ip, timeout) for ip, timeout in parse_set_elements(out)]
        return rows

    def _restore_allow_sets(
        self, container: str, rows: list[tuple[str, str, str]], *, skip: Iterable[str]
    ) -> None:
        """Re-add snapshot *rows*, minus IPs already covered by *skip* entries.

        *skip* holds the IPs/CIDRs the rebuild re-added through its own
        channels — restoring one of those would collide inside the nft
        transaction (a duplicate or overlapping interval aborts the whole
        batch).  Restore failure is logged, never raised: coming up with a
        cold allow set beats staying stuck in the down posture.
        """
        keep = [row for row in rows if not _covered(row[1], skip)]
        if not keep:
            return
        by_set: dict[str, list[tuple[str, str]]] = {}
        for name, ip, timeout in keep:
            by_set.setdefault(name, []).append((ip, timeout))
        stdin = "".join(restore_elements(name, els) for name, els in by_set.items())
        try:
            self._runner.nft_via_nsenter(container, stdin=stdin)
        except ExecError as exc:
            logger.warning(
                "allow-set restore failed for %s (workload re-learns via DNS): %s", container, exc
            )

    def _container_ruleset(self, container: str) -> RulesetBuilder:
        """Build a RulesetBuilder with the container's actual DNS settings.

        Prefers persisted upstream DNS (from pre_start) over resolv.conf,
        because dnsmasq mode rewrites resolv.conf to the runtime-specific
        dnsmasq listen address (``127.0.0.1`` by default; a link-local
        address under krun).
        """
        upstream = self._read_upstream_dns()
        dns = upstream if upstream else self._read_container_dns(container)

        # Read persisted DNS tier to determine if set timeouts are needed
        sd = self._config.state_dir.resolve()
        tier_path = StateBundle(sd).dns_tier
        set_timeout = ""
        if tier_path.is_file():
            tier_str = tier_path.read_text().strip()
            if tier_str == DnsTier.DNSMASQ.value:
                set_timeout = NFT_SET_TIMEOUT_DNSMASQ

        if self._gateways is None:
            self._gateways = _gateways_for_mode(self._get_podman_info().network_mode or "pasta")
        gw_v4, gw_v6 = self._gateways
        return RulesetBuilder(
            dns=dns,
            loopback_ports=StateBundle(sd).read_loopback_ports(),
            gateway_v4=gw_v4,
            gateway_v6=gw_v6,
            set_timeout=set_timeout,
        )

    def _read_upstream_dns(self) -> str | None:
        """Read persisted upstream DNS from state (written by pre_start).

        Returns None if the file is absent (pre-dnsmasq container or
        container started before this feature).
        """
        sd = self._config.state_dir.resolve()
        path = StateBundle(sd).upstream_dns
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
            return ShieldState.OFFLINE

        # verify_* returns a list of errors; empty list = ruleset is valid.
        # Block is checked first: its minimal ruleset (no sets, no DNS)
        # would fail all other verifiers.
        if not self._ruleset.verify_quarantine(output):
            return ShieldState.QUARANTINE

        if not self._ruleset.verify_down(output, disengaged=False):
            return ShieldState.DOWN
        if not self._ruleset.verify_down(output, disengaged=True):
            return ShieldState.DISENGAGED

        if not self._ruleset.verify_up(output):
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

    def preview(self, *, down: bool = False, disengaged: bool = False) -> str:
        """Generate the ruleset that would be applied to a container."""
        if down:
            return self._ruleset.build_down(disengaged=disengaged)
        return self._ruleset.build_up()


# ── Module-level helpers ────────────────────────────────


def _dnsmasq_bind(runtime: ShieldRuntime) -> str:
    """Return the dnsmasq listen address for *runtime*."""
    return DNSMASQ_BIND_KRUN if runtime is ShieldRuntime.KRUN else DNSMASQ_BIND_DEFAULT


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


def _gateways_for_mode(network_mode: str) -> tuple[str, str]:
    """Return ``(gateway_v4, gateway_v6)`` for a network mode.

    slirp4netns uses a virtual 10.0.2.0/24 network; the gateway is
    deterministically ``CIDR base + 2`` (reads ``containers.conf`` for a
    custom ``cidr=`` override).  pasta host-service access is handled by
    ``_loopback_port_rules()`` (literal 169.254.1.2) and needs no gateway.
    """
    if network_mode == "slirp4netns":
        return slirp4netns_gateway(), SLIRP4NETNS_GATEWAY_V6
    if network_mode == "pasta":
        return "", ""
    raise ValueError(
        f"Cannot determine gateways for network mode {network_mode!r}. "
        "Add support for this mode in _gateways_for_mode()."
    )


def _covered(ip: str, skip: Iterable[str]) -> bool:
    """True when *ip* overlaps any IP/CIDR entry of *skip*.

    Overlap matters, not just equality: re-adding a snapshot element that
    intersects an interval the rebuild already re-added would abort the
    whole nft restore transaction.  Unparseable *skip* entries are ignored.
    """
    addr = ipaddress.ip_network(ip, strict=False)
    for entry in skip:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if isinstance(net, type(addr)) and addr.overlaps(net):
            return True
    return False


def _is_dnsmasq_tier(state_dir: Path) -> bool:
    """Return True when the container's DNS tier is dnsmasq (or unknown).

    ``allow_domain`` / ``deny_domain`` are dnsmasq-specific enhancements
    (future IP rotation tracking via ``--nftset``).  On lookup/getent tiers
    the static IP-level allow/deny in ``allow_ip``/``deny_ip`` already ran;
    the domain-tracking step is simply not available and callers skip it.

    Returns True when ``dns_tier_path`` is absent (pre_start not yet run —
    pass-through so the caller can still attempt the dnsmasq operation).
    """
    tier_path = StateBundle(state_dir).dns_tier
    if not tier_path.is_file():
        return True
    return tier_path.read_text().strip() == DnsTier.DNSMASQ.value
