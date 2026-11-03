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
import math
import os
import sys
import time
from collections.abc import Collection, Iterable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote

from terok_util import find_host_tool, require_setup

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
    WILDCARDS_NEED_LIVE_TIER,
    DnsTier,
    OverrideRevocation,
    ShieldConfig,
    ShieldReading,
    ShieldRuntime,
    ShieldState,
)
from ..dns import apparmor, dnsmasq
from ..nft.constants import (
    CONTAINER_HOST_ALIAS,
    CONTAINER_HOST_ALIASES,
    DNSMASQ_BIND_DEFAULT,
    DNSMASQ_BIND_KRUN,
    ELEMENT_TIMEOUT_MAX_SECONDS,
    HARD_DENY_RANGES,
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
    add_elements_dual,
    add_override_elements_dual,
    arm_bypass_window,
    delete_deny_elements_dual,
    disarm_bypass_window,
    flush_override_sets,
    parse_set_elements,
    parse_window_expiry,
    restore_elements,
    safe_ip,
)
from ..podman_info.info import PodmanInfo, parse_podman_info
from ..podman_info.network import parse_resolv_conf, slirp4netns_gateway
from ..policy import (
    EXPIRES_MARKER,
    LOCALHOST,
    REASON_MARKER,
    PolicyEntry,
    entry_deadline,
    expiry_deadline,
    ip_targets,
    localhost_ports,
    parse_policy,
    validate_target,
)
from ..resources._oci_state import render_override_expiry
from ..run import ExecError, ShieldNeedsSetup
from ..state import (
    EffectivePolicy,
    OverrideSeed,
    SecurityTier,
    StateBundle,
    override_entry,
    read_name_resolution,
    write_name_resolution,
)
from ..util import is_ip, is_ipv4
from .install import HooksInstaller

logger = logging.getLogger(__name__)

WINDOW_NEEDS_UP = (
    "The bypass window opens only in the UP posture, and {container} is {posture}: "
    "outside UP the window set is unreferenced, so an open window would grant nothing. "
    "Raise the shield first."
)
"""Refusal for arming the timed window outside UP, where nothing would read it."""

_HARD_DENY_NETS = tuple(ipaddress.ip_network(net) for net in HARD_DENY_RANGES)

_OVERRIDE_POSTURES = frozenset({ShieldState.UP, ShieldState.DOWN, ShieldState.DISENGAGED})
"""The postures whose ruleset carries the t10 override set a live override goes into."""

OVERRIDE_NEEDS_RULESET = (
    "{container} is {posture}: a live override goes into a running ruleset's t10 set, "
    "and there is none to take it. An authored shield.override applies from the next start."
)
"""Refusal for a live override on a container with no override set to add to."""

_PODMAN_NO_SUCH_CONTAINER = 1
"""``podman container exists``'s exit status for a container podman has no record of."""

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

        Verifies setup, composes profiles, resolves DNS, writes
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
            terok_util.SetupRequiredError: When global hooks are not installed
                or need refreshing.
        """
        sd = self._config.state_dir.resolve()
        require_setup(HooksInstaller().check_setup(live=True))
        info = self._get_podman_info()
        StateBundle(sd).ensure_dirs()

        # Detect DNS tier, upstream DNS, and gateway addresses
        dnsmasq_bin = dnsmasq.locate(self._config.dnsmasq_path, self._runner)
        tier = self._detect_dns_tier(container, sd, dnsmasq_bin)
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
        bundle.dnsmasq_command.write_text(f"{dnsmasq_bin}\n")
        bundle.network_mode.write_text(f"{mode}\n")
        bundle.record_gateways(gw_v4, gw_v6)
        bundle.loopback_ports.write_text("".join(f"{p}\n" for p in self._config.loopback_ports))
        # The NFLOG reader reads no config, so the creation-time audit choice
        # reaches it — and a later harvest — through the bundle.
        audit_flag = str(self._config.audit_enabled).lower()
        bundle.audit_flag.write_text(f"{audit_flag}\n")
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
        args = self._build_network_args(mode, gw_v4)

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
            f"{ANNOTATION_AUDIT_ENABLED_KEY}={audit_flag}",
            "--annotation",
            f"{ANNOTATION_UPSTREAM_DNS_KEY}={upstream_dns}",
            "--annotation",
            f"{ANNOTATION_DNS_TIER_KEY}={tier.value}",
        ]

        self._audit.log_event(container, "setup", detail="using setup-installed global hooks")

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
        tier = bundle.read_dns_tier()
        mode = bundle.read_network_mode()
        upstream_dns = self._read_upstream_dns()
        if tier is None or not upstream_dns or not mode:
            raise RuntimeError(
                "shield bundle has no persisted DNS tier / upstream DNS / network mode — "
                "pre_start never completed for this container; re-create the task"
            )
        self._gateways = bundle.read_gateways()
        self._author_policy(
            container,
            sd,
            profiles,
            tier,
            upstream_dns,
            self._gateways,
            security_deny=security_deny,
            provider_allow=provider_allow,
            project_allow=project_allow,
            override=override,
        )

    def resolve(self, *, force: bool = False) -> list[str]:
        """Re-resolve the authored policy into its static-resolution caches.

        The resolution step of [`refresh`][terok_shield.hooks.mode.HookMode.refresh]
        on its own: every cache the bundle's policy feeds is refreshed, and no
        tier, ruleset or dnsmasq config is rewritten — the project-allow tier
        keeps every host its caller authored.  *force* re-resolves even when a
        cache is fresh.  Returns the resolved allow IPs, which stay empty on
        the live tier, where dnsmasq resolves per query.

        Raises:
            RuntimeError: When the bundle carries no persisted DNS tier
                (``pre_start`` never ran for this state dir).
        """
        sd = self._config.state_dir.resolve()
        tier = StateBundle(sd).read_dns_tier()
        if tier is None:
            raise RuntimeError(
                "shield bundle has no persisted DNS tier — "
                "pre_start never completed for this container"
            )
        return self._resolve_policy(sd, tier, force=force)

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
        neither path can miss it.  That includes the rotation note: the names
        this tier pins to resolved addresses are logged and audited on both.
        """
        entries = self._profiles.compose_profiles(profiles) + list(project_allow)
        self._write_generated_tiers(container, sd, security_deny, provider_allow, override)
        self._write_project_allow(sd, entries)
        self._resolve_policy(sd, tier)
        self._write_ruleset(sd, tier, upstream_dns, *gateways)
        self._write_dns_artifacts(sd, tier, upstream_dns)
        self._note_override_refusals(container, sd)
        self._note_rotation_risk(container, sd, posture=None)

    def _note_rotation_risk(self, container: str, sd: Path, *, posture: ShieldState | None) -> None:
        """Log and audit, as ``note``, each name the DNS tier pins that matters in *posture*.

        The record half of the degraded-tier warning, following the
        ``override_range`` precedent: one ``logger.warning`` and one audit
        ``note`` per line of [`RotationRisk.lines`][terok_shield.state.RotationRisk.lines].
        Nothing goes to stderr from here — the CLI verbs print the same lines
        themselves, read from the bundle, so an operator sees them whether or
        not audit is on.  *posture* ``None`` is a launch or restart.
        """
        risk = StateBundle(sd).read_rotation_risk()
        for line in risk.lines(posture) if risk is not None else ():
            logger.warning(line)
            self._audit.log_event(container, "note", detail=line)

    def _note_override_refusals(self, container: str, sd: Path) -> None:
        """Log and audit, as ``note``, each address an override names that t10 leaves out.

        The host's own loopback and the hard-deny floor sit above t10, so the
        seed drops them ([`read_override_refusals`][terok_shield.state.StateBundle.read_override_refusals])
        — quietly, were it not for this.  A break-glass name that comes back
        from a refresh pointing at the host or at cloud metadata is what a
        DNS rebinding looks like, so every path that seeds t10 from a fresh
        resolution says so: launch and restart, each ``shield up``/``down``,
        and a live grant, whose re-resolution covers every other override
        name too.
        """
        for line in StateBundle(sd).read_override_refusals():
            logger.warning(line)
            self._audit.log_event(container, "note", detail=line)

    def _refresh_pinned_names(self, sd: Path) -> None:
        """Re-resolve the caches older than an hour, on a tier that pins names — before a rebuild.

        On the tiers without live DNS the allow, override and deny sets are
        seeded from resolution caches, and a container that sat in one
        posture for hours would otherwise come back with the addresses its
        names had at launch.  Not forced: a fresh cache stands, so a posture
        change costs a lookup at most hourly.  Best-effort — a failed refresh
        keeps the caches as they are (a resolve in which no name answered
        never replaces them, and in the deny caches a name that alone answers
        nothing keeps its addresses), so the posture change itself goes ahead
        without ever seeding a thinner deny.  The live tier tracks DNS on its
        own and is left alone.
        """
        tier = StateBundle(sd).read_dns_tier()
        if tier is None or tier.live:
            return
        try:
            self._resolve_policy(sd, tier)
        except (OSError, RuntimeError, ExecError) as exc:
            logger.warning("could not re-resolve the pinned names before the rebuild: %s", exc)

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
        current = self._current_overrides(container, override)
        self._log_override_ranges(container, current)
        bundle.write_tier("override", "".join(f"+{h}\n" for h in current))

    def _current_overrides(self, container: str, override: Sequence[str]) -> list[str]:
        """The t10 lines worth writing: each validated, those already expired dropped and noted.

        An override line may carry an ``%expires`` marker — a date, valid
        through that day — and one that has run out is not authored at all:
        it lands in the log and the audit trail as ``override_expired``
        instead, so a break-glass that lapsed while the task was stopped
        says why it is gone.  An expiry that names no date fails the
        authoring outright: a typo must not quietly keep a door open, nor
        quietly close one.

        Raises:
            ValueError: On an override line the policy grammar rejects, or an
                ``%expires`` that is neither a date nor a timestamp.
        """
        now = time.time()
        current: list[str] = []
        for line in override:
            (entry,) = parse_policy(f"+{line}")
            deadline = entry_deadline(entry)
            if deadline is not None and deadline.timestamp() <= now:
                logger.warning("t10 override %s expired (%s); not applied", entry.target, deadline)
                self._audit.log_event(
                    container,
                    "override_expired",
                    dest=entry.target,
                    detail=f"{EXPIRES_MARKER}={entry.meta[EXPIRES_MARKER]}",
                )
                continue
            current.append(line)
        return current

    def _log_override_ranges(self, container: str, override: Sequence[str]) -> None:
        """Warn about every CIDR in the t10 override tier — a subnet opened above the deny.

        A break-glass override sits above the security-deny, so a range widens
        a whole subnet straight through the firewall.  Opening the agent to
        several local services is a legitimate way to run, so the launch goes
        ahead — but each range lands in the log and the audit trail, so the
        widening never passes unnoticed.
        """
        targets = (entry.target for line in override for entry in parse_policy(f"+{line}"))
        for net in (t for t in targets if "/" in t):
            logger.warning("t10 override opens a whole range above the security-deny: %s", net)
            self._audit.log_event(container, "override_range", detail=net)

    def _write_project_allow(self, sd: Path, entries: list[str]) -> None:
        """Write the composed profiles plus the caller's project hosts as the t40 tier."""
        StateBundle(sd).write_tier("project_allow", "".join(f"+{e}\n" for e in entries))

    def _resolve_policy(self, sd: Path, tier: DnsTier, *, force: bool = False) -> list[str]:
        """Refresh every static-resolution cache the authored policy feeds.

        Launch, restart and [`resolve`][terok_shield.hooks.mode.HookMode.resolve]
        share this one step, so no path refreshes a cache the others skip.
        *force* re-resolves even when a cache is fresh.  Returns the resolved
        allow IPs.
        """
        allow_ips = self._resolve_allow(sd, tier, force=force)
        self._resolve_override(sd, force=force)
        self._resolve_security_deny(sd, force=force)
        return allow_ips

    def _resolve_allow(self, sd: Path, tier: DnsTier, *, force: bool) -> list[str]:
        """Statically resolve the allow tiers wherever no DNS interception covers them.

        The authored ``policy/40-project-allow`` is the source of truth
        (domains + literal IPs).  On the live tier there is **no**
        pre-resolution: dnsmasq commits every answered A/AAAA record to the
        allow sets *before* forwarding the reply (``forward.c`` calls the
        nftset add synchronously while processing the upstream response), so
        a workload can never race its own answer.  The kernel set is
        populated on demand, per query — launch cost stays O(1) in allowlist
        size, and CDN rotation is tracked for free.  Any stale
        ``resolved.ips`` is removed so the ruleset seeds from literal IPs
        only.

        Every other tier has no DNS interception point, so statically
        resolving every admitted target into ``resolved.ips`` (refreshed
        when stale or older than the authored policy) remains its only
        domain-enforcement mechanism.  A wildcard entry names no address to
        resolve, so such a tier refuses it before the launch goes further.

        Raises:
            ShieldNeedsSetup: A wildcard entry on a tier that resolves once.
        """
        bundle = StateBundle(sd)
        if tier.live:
            bundle.resolved_cache.unlink(missing_ok=True)
            return []
        effective = bundle.read_effective()
        if wildcards := effective.wildcard_domains():
            raise ShieldNeedsSetup(
                WILDCARDS_NEED_LIVE_TIER.format(tier=tier.value, names=", ".join(wildcards))
            )
        return self._resolve_tier(
            bundle, effective.allow_targets(), bundle.resolved_cache, force=force
        )

    def _resolve_override(self, sd: Path, *, force: bool) -> None:
        """Statically resolve the t10 break-glass names into the name-keyed override cache.

        The override tier is a *separate* above-deny nft set, resolved
        independently of the allow tiers and statically on every DNS tier —
        break-glass entries are rare and specific, and dnsmasq interception
        would populate t40 (below the deny), defeating the override.  Each
        name keeps its own addresses, because each override keeps its own
        expiry; literal IPs need no resolving, and the tier names them itself.
        Only overrides still valid are resolved.  A name that answers nothing
        keeps the addresses it had: a lookup that times out at a refresh must
        not end a break-glass the operator never revoked.
        """
        bundle = StateBundle(sd)
        names = [t for t in bundle.read_effective().override_targets() if not is_ip(t)]
        if not names:
            bundle.override_resolved.unlink(missing_ok=True)
            return
        self._dns.resolve_names_and_cache(
            names,
            bundle.override_resolved,
            force=force,
            source_mtime=bundle.policy_mtime(),
            keep_unanswered=True,
        )

    def _resolve_security_deny(self, sd: Path, *, force: bool) -> None:
        """Statically resolve the t20 deny targets into the deny seed caches, one per provenance.

        Denied domains must deny by *address*: the deny set is enforced even
        in the shield-down posture (the down transition repopulates it from
        [`read_denied_ips`][terok_shield.state.StateBundle.read_denied_ips]),
        and an address-level deny also catches direct-IP access that never
        consults the DNS plane.  Resolved statically on every DNS tier —
        dnsmasq interception only ever *adds* to allow sets, so it can play
        no part in populating a deny.

        The security tier's names and the runtime overlay's denied names
        resolve into separate caches, so every address in the set still says
        which of the two put it there — the line tier authority draws when a
        live allow arrives ([`allow_ip`][terok_shield.hooks.mode.HookMode.allow_ip]).
        """
        bundle = StateBundle(sd)
        effective = bundle.read_effective()
        self._resolve_deny_names(
            bundle, effective.security_deny_targets(), bundle.deny_resolved, force=force
        )
        self._resolve_deny_names(
            bundle, effective.live_deny_targets(), bundle.live_deny_resolved, force=force
        )

    def _resolve_deny_names(
        self, bundle: StateBundle, targets: list[str], cache: Path, *, force: bool
    ) -> None:
        """Refresh one deny cache name by name; a tier with no name to resolve clears it.

        Literal IPs and CIDRs reach the t20 set from the tier itself, so only
        the names are resolved, each onto a line of its own — and a name that
        answers nothing this time keeps the addresses it had.  A deny cache
        written as one pool of addresses could not do that: the next refresh
        in which one vault host's lookup timed out would drop its addresses,
        and the rebuild after it would seed t20 without them.
        """
        names = [target for target in targets if not is_ip(target)]
        if not names:
            cache.unlink(missing_ok=True)
            return
        self._dns.resolve_names_and_cache(
            names,
            cache,
            force=force,
            source_mtime=bundle.policy_mtime(),
            keep_unanswered=True,
            kind="denied",
        )

    def _resolve_tier(
        self, bundle: StateBundle, targets: list[str], cache: Path, *, force: bool
    ) -> list[str]:
        """Refresh one tier's static-resolution cache; an empty tier clears it.

        *force* re-resolves even when the cache is fresh.  Returns the resolved IPs.
        """
        if not targets:
            cache.unlink(missing_ok=True)
            return []
        return self._dns.resolve_and_cache(
            targets,
            cache,
            force=force,
            source_mtime=bundle.policy_mtime(),
        )

    def _write_ruleset(
        self, sd: Path, tier: DnsTier, upstream_dns: str, gw_v4: str = "", gw_v6: str = ""
    ) -> None:
        """Pre-generate the complete nft ruleset into the state bundle."""
        set_timeout = NFT_SET_TIMEOUT_DNSMASQ if tier.live else ""
        ruleset_builder = RulesetBuilder(
            dns=upstream_dns,
            loopback_ports=StateBundle(sd).read_effective_loopback_ports(),
            gateway_v4=gw_v4,
            gateway_v6=gw_v6,
            set_timeout=set_timeout,
        )
        bundle = StateBundle(sd)
        ips = bundle.read_effective_ips()
        seeds = bundle.read_override_seeds()
        permanent = [seed.address for seed in seeds if seed.deadline is None]
        denied_ips = list(bundle.read_denied_ips())
        ruleset = ruleset_builder.build_up()
        ruleset += ruleset_builder.add_elements_dual(ips)
        if permanent:
            ruleset += add_override_elements_dual(permanent)
        if denied_ips:
            ruleset += add_deny_elements_dual(denied_ips)
        bundle.ruleset.write_text(ruleset)
        # Overrides that expire stay out of ruleset.nft: the OCI hook times
        # them from their deadlines whenever it applies the ruleset.
        bundle.override_expiry.write_text(
            render_override_expiry(
                [(seed.address, int(seed.deadline)) for seed in seeds if seed.deadline is not None]
            )
        )

    def _write_dns_artifacts(self, sd: Path, tier: DnsTier, upstream_dns: str) -> None:
        """Write the container's ``resolv.conf`` on every tier, and its
        ``dnsmasq.conf`` on the tiers that run dnsmasq.

        Shield owns the container's ``resolv.conf`` on every tier. The
        alternative is podman's default ``resolv.conf``. That default lists
        the host's own nameservers. On an AppArmor host such as Manjaro, one
        of those is a LAN router. The egress filter rejects the router as a
        private range, so the container resolves nothing (#1246).  The file is
        bind-mounted read-only over the container's ``/etc/resolv.conf`` — see
        ``WORKAROUND(pasta-dns-bind)`` in ``pre_start``.

        - **dnsmasq tiers**: point ``resolv.conf`` at the per-container dnsmasq
          bind address. dnsmasq forwards to *upstream_dns*; the live tier
          also adds each resolved address to the allow sets.
        - **lookup / getent tiers**: no per-container dnsmasq runs, so point
          ``resolv.conf`` straight at *upstream_dns*, the forwarder the
          firewall allows. Name resolution then uses the forwarder. The nft
          sets still gate egress, so this widens resolution only, never
          reachability. This also removes the dnsmasq artifacts.
        """
        bundle = StateBundle(sd)
        if tier.runs_dnsmasq:
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
                populate=tier.live,
            )
            bundle.dnsmasq_conf.write_text(conf)
            bundle.resolv_conf.write_text(f"nameserver {bind}\noptions ndots:0\n")
            return
        bundle.dnsmasq_conf.unlink(missing_ok=True)
        bundle.dnsmasq_pid.unlink(missing_ok=True)
        bundle.dnsmasq_log.unlink(missing_ok=True)
        bundle.resolv_conf.write_text(f"nameserver {upstream_dns}\noptions ndots:0\n")

    def _build_network_args(self, mode: str, gateway_v4: str) -> list[str]:
        """Build rootless network arguments (pasta, or slirp4netns at its recorded *gateway_v4*)."""
        if os.geteuid() == 0:
            return []
        if mode == "slirp4netns":
            return [
                "--network",
                "slirp4netns:allow_host_loopback=true",
                *_host_alias_args(gateway_v4),
            ]
        # Use pasta --map-host-loopback unconditionally so that
        # CONTAINER_HOST_ALIAS always resolves to an address
        # pasta actually forwards to the host's 127.0.0.1.
        return [
            "--network",
            f"pasta:--map-host-loopback,{PASTA_HOST_LOOPBACK_MAP}",
            *_host_alias_args(PASTA_HOST_LOOPBACK_MAP),
        ]

    def _detect_dns_tier(self, container: str, state_dir: Path, dnsmasq_bin: str) -> DnsTier:
        """Pick the DNS tier and tell the operator when it is degraded.

        A degraded tier is not a silent downgrade: the launcher's stderr is
        where the operator is, so the tier's hint goes there on every launch,
        and an AppArmor cause also lands in the audit log so a later egress
        failure traces back to it.
        """
        tier, apparmor_blocked = apparmor.detect_dns_tier_under_apparmor(
            self._runner, state_dir, dnsmasq_bin
        )
        if apparmor_blocked:
            detail = (
                f"AppArmor confines {dnsmasq_bin} from {state_dir}. Install the terok-shield "
                "AppArmor profile addendum (docs/apparmor.md); 'terok setup' installs it."
            )
            print(detail, file=sys.stderr)
            self._audit.log_event(container, "setup", detail=detail)
        if not tier.live:
            print(f"DNS tier {tier.value}: {tier.hint}", file=sys.stderr)
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

        No-op when the container runs no dnsmasq (the static IP-level allow
        already happened via ``allow_ip()``).
        """
        sd = self._config.state_dir.resolve()
        if not _runs_dnsmasq(sd):
            return
        StateBundle(sd).overlay_set("+", domain)
        self._reload_dnsmasq(container, sd)

    def deny_domain(self, container: str, domain: str) -> None:
        """Record ``-domain`` in the runtime overlay and reload dnsmasq.

        Counterpart of ``allow_domain()``: the dnsmasq restart picks up the
        ``local=`` sinkhole, so *domain* stops resolving (NXDOMAIN) and the
        deny fails fast in the DNS plane instead of timing out against the
        filter.

        No-op when the container runs no dnsmasq.
        """
        sd = self._config.state_dir.resolve()
        if not _runs_dnsmasq(sd):
            return
        StateBundle(sd).overlay_set("-", domain)
        self._reload_dnsmasq(container, sd)

    def _reload_dnsmasq(self, container: str, state_dir: Path) -> bool:
        """Regenerate the dnsmasq config and restart dnsmasq to load it.

        The config is rewritten either way; with no dnsmasq running (PID file
        absent) nothing is relaunched, and the result is ``False``.
        Raises RuntimeError if dnsmasq is dead (stale PID) or fails to restart.
        """
        upstream = self._read_upstream_dns()
        if not upstream:
            raise RuntimeError("Cannot reload dnsmasq: upstream DNS not persisted in state")

        domains = dnsmasq.read_merged_domains(state_dir)
        return dnsmasq.reload(
            state_dir,
            upstream,
            domains,
            deny_domains=dnsmasq.read_denied_domains(state_dir),
            override_domains=dnsmasq.read_override_domains(state_dir),
            container=container,
            runner=self._runner,
        )

    # ── Tier authority ──────────────────────────────────

    def security_tier(self, *, refresh: bool = False) -> SecurityTier:
        """The t20 security tier this container's bundle records, as a matcher.

        With *refresh*, on a DNS tier that runs no dnsmasq, the tier's names
        are resolved afresh and their current addresses join the cached ones.
        Nothing sinkholes a vault host's name on those tiers, so the container
        can reach an address the launch-time resolution never saw — and that
        address arrives as an unattributed refusal an operator may be asked
        to allow.  The dnsmasq tiers sinkhole the names, so the cache stands.
        """
        bundle = StateBundle(self._config.state_dir.resolve())
        fresh: list[str] = []
        tier = bundle.read_dns_tier()
        if refresh and tier is not None and not tier.runs_dnsmasq:
            names = [
                target
                for target in bundle.read_effective().security_deny_targets()
                if not is_ip(target) and not target.startswith("*.")
            ]
            fresh = self._dns.resolve_domains(names, quiet=True) if names else []
        return bundle.read_security_tier(extra_addresses=fresh)

    def check_security_tier(self, target: str, ips: Sequence[str]) -> None:
        """Refuse *target* when the t20 security tier refuses it — by name, suffix, or any of *ips*.

        Meant to run once per grant, before anything changes, with every
        address the target resolved to: a refusal is all or nothing, never a
        grant of some addresses and a refusal of the rest.  The tiers without
        dnsmasq re-resolve the security names first
        ([`security_tier`][terok_shield.hooks.mode.HookMode.security_tier]).

        Raises:
            SecurityTierRefusal: Naming the security-tier entry, and the
                shared address when that is the cause.
        """
        if (refusal := self.security_tier(refresh=True).refusal(target, ips)) is not None:
            raise refusal

    # ── Live operations (IP) ────────────────────────────

    def allow_ip(self, container: str, ip: str) -> None:
        """Live-allow an IP for a running container via nsenter.

        Tier authority holds at this API itself, whoever calls it.  An address
        in the t20 security tier is refused — never deleted from the deny set,
        where it would stay lifted until the next rebuild.  Only the
        operator's own runtime deny (a ``-`` entry of ``policy/live``, or an
        address one of its denied names resolved to) is lifted before the
        address joins the t40 allow set.  The check reads the bundle as it
        stands; [`check_security_tier`][terok_shield.hooks.mode.HookMode.check_security_tier]
        is the caller's place to add a fresh resolution.

        Raises:
            SecurityTierRefusal: When *ip* falls in the security tier.
        """
        ip = safe_ip(ip)
        sd = self._config.state_dir.resolve()
        bundle = StateBundle(sd)
        if (refusal := bundle.read_security_tier().refusal(ip)) is not None:
            raise refusal

        # Un-deny: lift the operator's own runtime deny of this address.
        if ip in bundle.read_live_denied_ips():
            nft_cmd = delete_deny_elements_dual([ip])
            if nft_cmd:
                self._nft_apply_best_effort(container, nft_cmd)

        # When the live set has a default timeout (30 m), permanent IPs must use
        # 'timeout 0s' so they are never evicted by the set's per-element expiry clock.
        tier = bundle.read_dns_tier()
        element = f"{{ {ip} timeout 0s }}" if tier is not None and tier.live else f"{{ {ip} }}"

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

    def allow_offline(self, target: str) -> None:
        """Record ``+target`` for a container that is not running: no nft, nothing live.

        A stopped container has no ruleset to take a live grant, so the grant
        goes where every runtime allow persists — the ``policy/live`` overlay,
        flipping any earlier deny of the same target — and the files the OCI
        hook applies at the next start are re-derived from the bundle at
        once.  The hook replays ``ruleset.nft`` and starts dnsmasq from
        ``dnsmasq.conf`` as they stand, re-deriving nothing, so without that
        a plain ``podman start`` would come up without the grant; terok's
        restart path, which runs [`refresh`][terok_shield.hooks.mode.HookMode.refresh]
        before ``podman start``, carries it either way.  A domain is recorded
        as the name, so its own DNS tier resolves it — at once on a tier that
        pins names, per query on ``dnsmasq-live``.

        Raises:
            SecurityTierRefusal: When the bundle's security tier refuses
                *target* by name, suffix or address.
            RuntimeError: When no launch ever prepared this bundle — no start
                would read the overlay, so recording into it would only look
                like success (a mistyped container, say).
        """
        if is_ip(target):
            target = safe_ip(target)
        sd = self._config.state_dir.resolve()
        bundle = StateBundle(sd)
        tier = bundle.read_dns_tier()
        upstream_dns = self._read_upstream_dns()
        mode = bundle.read_network_mode()
        if tier is None or not upstream_dns or not mode:
            raise RuntimeError(
                f"no shield bundle was prepared in {sd} — pre_start never completed there, "
                "so no start would apply the allow"
            )
        if (refusal := bundle.read_security_tier().refusal(target)) is not None:
            raise refusal
        bundle.overlay_set("+", target)
        self._rederive_start_artifacts(sd, tier, upstream_dns)

    def _rederive_start_artifacts(self, sd: Path, tier: DnsTier, upstream_dns: str) -> None:
        """Rewrite what the OCI hook applies at the next start from the bundle as it stands.

        The policy-change half of [`refresh`][terok_shield.hooks.mode.HookMode.refresh]
        without its tier authoring: the caches the change made stale are
        re-resolved, then ``ruleset.nft`` (with ``override.expiry``) and the
        dnsmasq config are rewritten.  Every launch-time fact comes out of the
        bundle — DNS tier, upstream DNS, the gateways, and the dnsmasq config's
        own listen address — so a caller holding a default config (the CLI)
        never moves a krun container's bind to ``127.0.0.1``.  ``resolv.conf``
        names the same resolver as before and stays as it is.
        """
        self._resolve_policy(sd, tier)
        self._write_ruleset(sd, tier, upstream_dns, *StateBundle(sd).read_gateways())
        if StateBundle(sd).dnsmasq_conf.is_file():
            dnsmasq.rewrite_config(
                sd,
                upstream_dns,
                dnsmasq.read_merged_domains(sd),
                deny_domains=dnsmasq.read_denied_domains(sd),
                override_domains=dnsmasq.read_override_domains(sd),
            )

    def _rewrite_replayed_artifacts(self, sd: Path, *, dnsmasq_conf: bool) -> None:
        """Re-derive what the OCI hook replays at the next start, from the bundle alone.

        ``ruleset.nft`` and ``override.expiry`` are rewritten every time.
        With *dnsmasq_conf* the dnsmasq config is rewritten too, but only for
        a stopped container: a running dnsmasq is brought in line by a reload
        (``_sync_dns_plane``), which decides by comparing the policy with the
        config on disk, so rewriting the file first would hide the change
        from it.  Unlike ``_rederive_start_artifacts``, nothing is resolved:
        the caches stand as they are, so the step needs no resolver.  A
        bundle that no launch ever prepared has nothing to replay.
        """
        bundle = StateBundle(sd)
        tier = bundle.read_dns_tier()
        upstream_dns = self._read_upstream_dns()
        network_mode = bundle.read_network_mode()
        if tier is None or not upstream_dns or not network_mode:
            return
        self._write_ruleset(sd, tier, upstream_dns, *bundle.read_gateways())
        if dnsmasq_conf and bundle.dnsmasq_conf.is_file():
            dnsmasq.rewrite_config(
                sd,
                upstream_dns,
                dnsmasq.read_merged_domains(sd),
                deny_domains=dnsmasq.read_denied_domains(sd),
                override_domains=dnsmasq.read_override_domains(sd),
            )

    # ── Break-glass (t10) ───────────────────────────────

    def override(self, container: str, target: str, expires: str, *, reason: str) -> list[str]:
        """Break glass for *target* on a running container, valid through *expires*, for *reason*.

        The live counterpart of an authored ``shield.override``: *target*
        joins the t10 set — above the security tier and the private ranges —
        with a kernel timeout that runs out at the end of the *expires* day,
        host local time (or at the instant, for a full timestamp).  The kernel
        ends the break-glass on time with nothing in userspace keeping the
        clock, as it closes the bypass window.  Agents keep reaching a
        vault-relayed provider through the vault; the override only adds the
        direct route.

        The grant is recorded in the t10 tier with its ``%expires`` and its
        ``%reason``, so every ``shield down``/``up`` rebuild re-seeds it,
        timed afresh.  The tier stays the orchestrator's: the next restart
        re-derives it from the orchestrator's own policy, which is where an
        override that should outlive the task belongs.  The whole t10 set is
        swapped in one nft transaction — flushed and re-seeded — so every
        element takes its current timeout and nothing overlaps.  A domain
        also opens in the dnsmasq sinkhole, so the workload can resolve it.

        The tier follows the kernel, never the other way round.  The override
        names resolve first, held in memory (``_resolve_grant``).  The rest
        holds the t10 lock
        ([`override_change`][terok_shield.state.StateBundle.override_change]),
        so no revoke or other grant interleaves: the swap is computed from
        the tier as it stands then — whatever a revoke or a grant changed
        while the names resolved — with this grant in place of any earlier
        entry for *target*.  The tier records the grant only once the kernel
        has taken that swap, and the override cache takes the answers the
        swap was seeded from after the tier, so it post-dates the tier it
        answers for.  A refusal or a failed swap leaves both as they were,
        and at no moment does the tier hold a grant the kernel never took.
        The grant is audited as ``override`` — with its expiry and reason —
        the moment the transaction commits, before the tier records it and
        before the dnsmasq reload: once the kernel holds it, the audit trail
        must too, whatever happens next.

        The hard-deny floor (link-local, cloud metadata) sits above t10 and is
        never overridden: a target that is, or resolves into, a hard-deny
        range is refused, and so is a name that resolves to nothing.  So is
        anything that takes in the host's own loopback — the address
        ``host.containers.internal`` names under the recorded network mode —
        which only a ``+localhost:PORT`` grant reaches, one port at a time.  An
        IP or CIDR is judged before anything else, so it is refused with the
        same message in every posture, a stopped container's included.  A
        name is resolved once, so the addresses checked are the addresses
        seeded.  That resolution covers every other override name as well,
        and none of their answers is checked here: the seed itself leaves out
        whatever no override may open, and the grant notes it.  Under
        slirp4netns the ruleset refuses the gateway above t10 regardless.
        An *expires* that runs out while the names resolve is refused like
        one that had passed already: the grant would never reach the kernel.

        Returns:
            The addresses *target* opened (itself, for an IP or a CIDR).

        Raises:
            ValueError: For a target no override can carry (``localhost``,
                the host alias or its address, a wildcard, the hard-deny
                floor, or text that is no target), an *expires* that is no
                date or has passed, or an empty *reason*.
            RuntimeError: When the container has no running ruleset with an
                override set (stopped, quarantined, unrecognised), or the
                target resolves to no address — and, once the kernel holds
                the grant, when the tier or the override cache cannot record
                it or dnsmasq cannot reload to open the name.
        """
        target = _override_target(target)
        if is_ip(target):
            # An address is judged without resolving it, so the floor and the
            # host's loopback refuse it in any posture, ahead of every other check.
            host = StateBundle(self._config.state_dir.resolve()).host_loopback()
            _check_override_addresses(target, [target], host=host)
        if not (reason := reason.strip()):
            raise ValueError(
                f"an override of {target} needs a reason: a break-glass says why it exists"
            )
        if expiry_deadline(expires).timestamp() <= time.time():
            raise ValueError(
                f"expires={expires} has already passed — an override must hold through today "
                "at least"
            )
        posture = self.shield_state(container)
        if posture not in _OVERRIDE_POSTURES:
            raise RuntimeError(
                OVERRIDE_NEEDS_RULESET.format(container=container, posture=posture.value)
            )
        sd = self._config.state_dir.resolve()
        bundle = StateBundle(sd)
        entry = override_entry(target, expires, reason=reason)
        answers = self._resolve_grant(bundle, entry)
        with bundle.override_change():
            # The tier as it stands now, with the grant in it: a revoke that
            # landed while the names resolved stays revoked, a grant stays granted.
            recorded = bundle.read_effective()
            planned = recorded.with_override(entry)
            cached = read_name_resolution(bundle.override_resolved) or {}
            resolution = cached if answers is None else {**cached, **answers}
            addresses = [target] if is_ip(target) else resolution.get(target, [])
            host = bundle.host_loopback()
            _check_override_addresses(target, addresses, host=host)
            moment = time.time()
            if expiry_deadline(expires).timestamp() <= moment:
                raise ValueError(
                    f"expires={expires} ran out while the override names resolved — "
                    "nothing was granted"
                )
            # What a rebuild still seeds for the target should the tier fail to record the grant.
            spelled = bundle.override_entries(target)
            earlier = [prior for prior in recorded.active_override(moment) if prior in spelled]
            seeds = bundle.read_override_seeds(moment, policy=planned, resolution=resolution)
            self._runner.nft_via_nsenter(
                container, stdin=flush_override_sets() + _override_elements(seeds, moment)
            )
            self._audit.log_event(
                container, "override", dest=target, detail=f"expires={expires}; reason={reason}"
            )
            # Only now that the kernel holds the grant does the tier record it.
            unrecorded = _record_grant(container, bundle, target, expires, reason, earlier)
            if unrecorded is None and answers is not None:
                unrecorded = _cache_grant_answers(container, bundle, planned, resolution, target)
        self._note_override_refusals(container, sd)
        self._open_granted_name(container, sd, target, unrecorded)
        return addresses

    def _open_granted_name(
        self, container: str, sd: Path, target: str, unrecorded: RuntimeError | None
    ) -> None:
        """Open a granted name past its dnsmasq sinkhole, then raise why the grant went unrecorded.

        dnsmasq is reloaded whatever the grant's record says, and opens the
        name wherever the tier holds an entry for it — a grant the cache
        could not record, or a re-grant whose earlier entry stands.  A first
        grant the tier could not record stays sinkholed, since dnsmasq's
        config comes from the tier; its error says so.  *unrecorded* is the
        tier's or the cache's failure, raised once dnsmasq has reloaded.
        """
        if not is_ip(target) and _runs_dnsmasq(sd):
            try:
                self._reload_dnsmasq(container, sd)
            except (RuntimeError, ExecError, OSError) as exc:
                held = f"{unrecorded}; and " if unrecorded is not None else ""
                raise RuntimeError(
                    f"{held}the override of {target} holds by address, but dnsmasq could not "
                    f"reload to resolve the name past its sinkhole: {exc}"
                ) from exc
        if unrecorded is not None:
            raise unrecorded

    def _resolve_grant(
        self, bundle: StateBundle, entry: PolicyEntry
    ) -> dict[str, list[str]] | None:
        """Resolve the override names of the tier a grant of *entry* leaves — writing nothing.

        Runs before the grant takes the t10 lock, so a revoke never waits on
        a resolver.  Every name of the recorded tier with *entry* in it
        ([`with_override`][terok_shield.state.EffectivePolicy.with_override])
        resolves once, the target's own among them, so the addresses checked
        for the target are the addresses the swap seeds.  A grant that
        changes the tier is an edit the cache predates: every name resolves
        afresh, and no answer from before the edit stands in for the
        target's own when it fails now.  Another override that answers
        nothing keeps the addresses the cache holds for it, as the deny
        caches do: a lookup that times out during someone else's grant must
        not end a break-glass the operator never revoked.  One the tier
        already holds word for word changes nothing, so a fresh cache
        stands.  Nothing is written: a grant refused for want of an answer
        leaves the cache as it was, and the answers reach the cache only
        once the tier records the grant.

        Returns:
            Every name resolved, with its fresh answer — the cached one for
            another override that answered nothing, empty for the target when
            it did — or ``None`` when the cache stands.
        """
        recorded = bundle.read_effective()
        planned = recorded.with_override(entry)
        names = [t for t in planned.override_targets() if not is_ip(t)]
        if not names:
            return None
        edited = planned.override != recorded.override
        resolved = self._dns.resolve_names(
            names,
            bundle.override_resolved,
            # An edit not yet on disk post-dates every cache: none is fresh for it, none current.
            source_mtime=math.inf if edited else bundle.policy_mtime(),
        )
        if resolved is None:
            return None
        cached = read_name_resolution(bundle.override_resolved) or {}
        return {
            name: resolved.get(name) or ([] if name == entry.target else cached.get(name, []))
            for name in names
        }

    def revoke_override(self, container: str, target: str) -> OverrideRevocation:
        """End *target*'s break-glass on *container* now, ahead of its expiry.

        The counterpart of [`override`][terok_shield.hooks.mode.HookMode.override].
        It ends a live grant and an authored ``shield.override`` alike, since
        the t10 tier records both the same way.  Only an override still in
        force can be revoked.  A target with no t10 entry, or one whose
        ``%expires`` already ran out, is refused, so a typo never passes for
        a door that was closed.

        Closing must not depend on a step that can fail open, so the order
        matters.  The tier entry goes first: every rebuild re-seeds t10 from
        the tier, so from then on no ``shield up``/``down`` re-opens the
        override, whatever fails next.  Next, ``ruleset.nft`` and
        ``override.expiry`` are re-derived from the bundle, because the OCI
        hook replays them at every start, so a plain ``podman start`` does
        not re-open it either.  A rewrite that fails stops nothing after it:
        the swap, the audit and the dnsmasq reload still run, and its error
        is raised last — otherwise the running ruleset would keep admitting
        the target, and a retry would find no override left to revoke.  Last,
        the running ruleset's t10 set is swapped in one nft transaction,
        flushed and re-seeded with the overrides still in force.  The target's elements go, and every other
        element stays, timed to its own deadline.  No DNS lookup takes part:
        a revoke must not wait on, or fail with, a resolver.  From the read of
        the tier through the swap it holds the t10 lock
        ([`override_change`][terok_shield.state.StateBundle.override_change]),
        so a grant whose names resolved meanwhile swaps from the tier as the
        revoke left it and never re-opens the target.  A grant resolves
        before it takes the lock, so the wait is never on a resolver.

        The revoke is audited as ``override_revoked`` once nothing running
        holds the override: when that transaction commits, or at once when
        the ruleset carries no t10 set (a stopped or quarantined container).
        For a name, dnsmasq is then reloaded if its config still punches the
        name through the sinkhole, so the name stops resolving again.  A
        stopped container's dnsmasq config is rewritten on disk instead, for
        its next start.

        "Stopped" is podman's word, never an unreadable ruleset's: a listing
        that fails reads as OFFLINE too, so before a revoke treats the
        container as stopped, podman must confirm it has no process, or has
        no such container
        ([`confirmed_posture`][terok_shield.hooks.mode.HookMode.confirmed_posture]).
        A running container whose ruleset could not be read gets the swap,
        and its failure is raised.

        Connections already established keep running: the ruleset accepts
        established traffic ahead of every tier, so a revoke stops new
        connections, as the override's own expiry does.

        Returns:
            The addresses closed, the ones another override still holds open,
            and whether the container was running.

        Raises:
            ValueError: For text that is no domain, IP or CIDR, and for
                ``localhost``: a ``+localhost:PORT`` grant opens a preamble
                port, which no t10 swap takes back.
            RuntimeError: When *target* has no override in force on the
                container (or it has no state bundle at all), or when
                neither the ruleset nor podman says whether the container
                runs — both before anything changes.
                Also, with the record already gone, when nft cannot drop the
                elements from the running ruleset, dnsmasq cannot reload to
                sinkhole the name again, or the files a plain start replays
                cannot be rewritten — each message saying what still holds.
        """
        target = _revoke_target(target)
        sd = self._config.state_dir.resolve()
        bundle = StateBundle(sd)
        # From the read of the tier through the swap, no grant interleaves:
        # one that resolved its names meanwhile swaps from the tier as this leaves it.
        with bundle.override_change():
            in_force = _overrides_in_force(container, bundle, target, time.time())
            shown = in_force[0].target
            posture = self.confirmed_posture(container)
            held = _held_addresses(bundle, in_force)
            bundle.remove_override(target)
            stale = self._replay_left_stale(sd, shown, dnsmasq_conf=posture is ShieldState.OFFLINE)
            moment = time.time()
            seeds = bundle.read_override_seeds(moment)
            if posture not in (ShieldState.OFFLINE, ShieldState.QUARANTINE):
                self._swap_out_of_t10(container, shown, seeds, moment, stale=stale)
        kept = tuple(address for address in held if _covered_by_seed(address, seeds))
        closed = tuple(address for address in held if address not in kept)
        live = posture is not ShieldState.OFFLINE
        self._audit.log_event(
            container,
            "override_revoked",
            dest=shown,
            detail=_revocation_detail(in_force[0], live=live),
        )
        self._close_revoked_name(container, sd, shown, live=live, stale=stale)
        return OverrideRevocation(target=shown, closed=closed, kept=kept, live=live)

    def _replay_left_stale(
        self, sd: Path, shown: str, *, dnsmasq_conf: bool
    ) -> RuntimeError | None:
        """Re-derive what a plain start replays for a revoke — or the error saying it could not.

        Returned, not raised: the revoke still takes the override out of the
        running ruleset, audits it and sinkholes its name before the caller
        hears that a plain ``podman start`` would re-open it.
        """
        try:
            self._rewrite_replayed_artifacts(sd, dnsmasq_conf=dnsmasq_conf)
        except (OSError, RuntimeError, ValueError) as exc:
            stale = RuntimeError(
                f"the override of {shown} is out of the t10 tier, but the files a plain podman "
                "start replays could not be rewritten, so such a start re-opens it until the "
                f"next shield up or down: {exc}"
            )
            stale.__cause__ = exc
            return stale
        return None

    def _close_revoked_name(
        self, container: str, sd: Path, shown: str, *, live: bool, stale: RuntimeError | None
    ) -> None:
        """Sinkhole a revoked name again in the running dnsmasq, then raise any *stale* replay."""
        if live and not is_ip(shown):
            try:
                self._sync_dns_plane(container, sd, strict=True)
            except (RuntimeError, ExecError, OSError) as exc:
                then = f"; and {stale}" if stale is not None else ""
                raise RuntimeError(
                    f"the override of {shown} is revoked by address, but dnsmasq could not "
                    f"reload to sinkhole the name again: {exc}{then}"
                ) from exc
        if stale is not None:
            raise stale

    def _swap_out_of_t10(
        self,
        container: str,
        shown: str,
        seeds: Sequence[OverrideSeed],
        moment: float,
        *,
        stale: RuntimeError | None = None,
    ) -> None:
        """Swap the running t10 set for *seeds* in one nft transaction — a revoke's kernel step.

        Raises:
            RuntimeError: When nft cannot.  The record is already gone, so no
                rebuild re-opens the override, but the running ruleset admits
                it until the next ``shield up`` or ``down`` — and the message
                says so, along with a *stale* replay if the rewrite failed too.
        """
        command = flush_override_sets() + _override_elements(seeds, moment)
        try:
            self._runner.nft_via_nsenter(container, stdin=command)
        except (ExecError, OSError) as exc:
            then = f"; and {stale}" if stale is not None else ""
            raise RuntimeError(
                f"the override of {shown} is out of the bundle, so no rebuild re-opens it, "
                f"but nft could not drop it from {container}'s running ruleset, which admits "
                f"it until the next shield up or down: {exc}{then}"
            ) from exc

    def deny_ip(self, container: str, ip: str) -> None:
        """Live-deny an IP for a running container via nsenter.

        Removes from the nft allow set (best-effort), adds to the nft deny set,
        and records ``-ip`` in ``policy/live`` so the deny sticks across
        ``shield up`` / restart and flips any prior allow.
        """
        ip = safe_ip(ip)
        sd = self._config.state_dir.resolve()
        bundle = StateBundle(sd)

        with bundle.override_change():
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
                    pat in stderr
                    for pat in ("no such file", "element does not exist", "not in set")
                ):
                    logger.warning("nft delete element failed for %s: %s", ip, e)

            # Add to nft deny set (prevents dnsmasq from re-allowing)
            nft_cmd = add_deny_elements_dual([ip])
            if nft_cmd:
                self._nft_apply_best_effort(container, nft_cmd)

            # Persist before any rebuild can snapshot the policy.
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
        Both postures re-seed the t10 override set: it tags break-glass
        traffic ``ALLOWED`` ahead of the ``DOWN`` catch-all in DISENGAGED
        too, so that traffic is never recorded as accepted only because the
        shield is down.

        On a tier that pins names, caches older than an hour are re-resolved
        first (``_refresh_pinned_names``), so the deny set the down posture keeps enforcing holds the vault
        hosts' current addresses; and plain DOWN notes the denied names a
        rotation would carry past it.
        """
        sd = self._config.state_dir.resolve()
        self._refresh_pinned_names(sd)
        ruleset = self._container_ruleset(container)
        rs = ruleset.build_down(disengaged=disengaged)
        current = self.shield_state(container)
        if current == ShieldState.OFFLINE:
            stdin = rs
        else:
            stdin = f"delete table {NFT_TABLE}\n{rs}"
        snapshot = [] if current == ShieldState.OFFLINE else self._snapshot_allow_sets(container)
        # Publish the accepting table and its mandatory deny entries together.
        # A later seed would leave a window in which a denied connection could
        # become established and survive the restored deny policy.
        bundle = StateBundle(sd)
        with bundle.override_change():
            seeds = "" if disengaged else add_deny_elements_dual(sorted(bundle.read_denied_ips()))
            seeds += _override_elements(bundle.read_override_seeds(), time.time())
            if seeds:
                stdin += f"\n{seeds}"
            self._runner.nft_via_nsenter(container, stdin=stdin)

            # Carry learned IPs across the rebuild before a live deny can remove one.
            # DOWN does not evaluate them, but a later UP snapshots this table.
            self._restore_allow_sets(container, snapshot, skip=())

        # The nft plane is already complete. Synchronize its DNS companion
        # without reopening the transaction or duplicating interval elements.
        self._note_override_refusals(container, sd)
        self._sync_dns_plane(container, sd)

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
        if not disengaged:
            self._note_rotation_risk(container, sd, posture=ShieldState.DOWN)

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

        On a tier that pins names, caches older than an hour are re-resolved
        before anything changes (``_refresh_pinned_names``): a container raised after hours down would otherwise come up seeded
        with its launch-time addresses.  The names the tier still pins are
        noted once the posture holds.
        """
        sd = self._config.state_dir.resolve()
        self._refresh_pinned_names(sd)

        ruleset = self._container_ruleset(container)
        rs = ruleset.build_up()
        current = self.shield_state(container)
        if current == ShieldState.OFFLINE:
            stdin = rs
        else:
            stdin = f"delete table {NFT_TABLE}\n{rs}"
        snapshot = [] if current == ShieldState.OFFLINE else self._snapshot_allow_sets(container)
        with StateBundle(sd).override_change():
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
        self._note_override_refusals(container, sd)
        self._sync_dns_plane(container, sd)

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
        self._note_rotation_risk(container, sd, posture=ShieldState.UP)

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
        self._reseed_override(container, sd)
        return denied_ips

    def _reseed_override(self, container: str, sd: Path) -> None:
        """Repopulate the kernel's t10 override set from the bundle after a table rebuild.

        Every element that expires is timed afresh from its deadline, so a
        rebuild neither revives an override that ran out nor stretches one
        that is about to.  An address no override may open — the host's own
        loopback, the hard-deny floor — stays out of the seed. The caller
        synchronizes DNS after releasing the policy lock.
        """
        if override_cmd := _override_elements(StateBundle(sd).read_override_seeds(), time.time()):
            self._runner.nft_via_nsenter(container, stdin=override_cmd)

    def _sync_dns_plane(self, container: str, sd: Path, *, strict: bool = False) -> None:
        """Reload dnsmasq when its config no longer says what the policy says now.

        The kernel ends an override on time, but its name was opened in the
        dnsmasq sinkhole when it was granted, and a running dnsmasq keeps
        serving the config it loaded: past the expiry the name still
        resolves, and an address the vault host rotates to — one the t20 set
        never held — is accepted in DOWN or through an open window.  So every
        rebuild that re-seeds t10 compares the config the policy calls for
        now with the one on disk and, when they differ, rewrites it and
        relaunches dnsmasq.  Best-effort: a dnsmasq that cannot be reloaded
        leaves the container without DNS at all, which resolves the lapsed
        name no better, so the posture change goes ahead with a warning.

        The config on disk is rewritten even when no dnsmasq runs (no PID
        file): the next start's OCI hook reads it.  Nothing serves it before
        then, which is worth a warning — and an orphaned dnsmasq that lost its
        PID file would keep serving the old one.

        *strict* is for a caller that must not report success over a stale
        config — a revoke, which promises the name stops resolving: a reload
        that fails raises instead of warning, and so does finding no dnsmasq
        to relaunch.
        """
        upstream = self._read_upstream_dns()
        if not (upstream and _runs_dnsmasq(sd) and StateBundle(sd).dnsmasq_conf.is_file()):
            return
        if dnsmasq.config_is_current(
            sd,
            upstream,
            dnsmasq.read_merged_domains(sd),
            deny_domains=dnsmasq.read_denied_domains(sd),
            override_domains=dnsmasq.read_override_domains(sd),
        ):
            return
        try:
            reloaded = self._reload_dnsmasq(container, sd)
        except (RuntimeError, ExecError, OSError) as exc:
            if strict:
                raise
            logger.warning(
                "dnsmasq could not reload to follow the policy on %s: %s", container, exc
            )
            return
        if not reloaded:
            idle = (
                f"no dnsmasq runs for {container} (no PID file), so nothing serves the new "
                "config until its next start, which reads it from disk"
            )
            if strict:
                raise RuntimeError(idle)
            logger.warning(idle)

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
        address under krun).  The gateways are the ones the container
        launched with, as the bundle recorded them — not podman's current
        default or ``containers.conf``'s current ``cidr=``, either of which
        may have changed since: the rebuilt ruleset opens the gateway's
        ports, and refuses the rest of the host's loopback above t10, at the
        address the container really uses.
        """
        upstream = self._read_upstream_dns()
        dns = upstream if upstream else self._read_container_dns(container)

        sd = self._config.state_dir.resolve()
        bundle = StateBundle(sd)
        tier = bundle.read_dns_tier()
        set_timeout = NFT_SET_TIMEOUT_DNSMASQ if tier is not None and tier.live else ""

        if self._gateways is None:
            self._gateways = bundle.read_gateways()
        gw_v4, gw_v6 = self._gateways
        return RulesetBuilder(
            dns=dns,
            loopback_ports=bundle.read_effective_loopback_ports(),
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
        cat = find_host_tool("cat")
        output = (
            self._runner.run(
                ["podman", "unshare", cat, f"/proc/{pid}/root/etc/resolv.conf"],
                check=False,
            )
            if cat
            else ""
        )
        dns = parse_resolv_conf(output)
        if not dns:
            raise RuntimeError(
                f"Cannot determine DNS for container {container}: no nameserver in resolv.conf"
            )
        return dns

    # ── Queries ─────────────────────────────────────────

    # ── Timed allow-all window ──────────────────────────

    def arm_window(self, container: str, timeout: str) -> None:
        """Open the timed allow-all window for *timeout* — in the UP posture only.

        The element carries a kernel timeout, so the window closes itself even
        if nothing ever calls [`disarm_window`][terok_shield.hooks.mode.HookMode.disarm_window]
        — and any disruption (a rebuild, a restart, a crashed host process)
        only closes it sooner.

        Only the UP chain references the window set.  Armed in any other
        posture the element would grant nothing — DOWN accepts by default
        already, quarantine drops everything — while the caller would be told
        a window is open, so arming there is refused instead.

        Raises:
            ValueError: When *timeout* is not an nft timeout.
            RuntimeError: When the container's posture is not UP.
        """
        stdin = arm_bypass_window(timeout)
        if (posture := self.shield_state(container)) is not ShieldState.UP:
            raise RuntimeError(WINDOW_NEEDS_UP.format(container=container, posture=posture.value))
        self._runner.nft_via_nsenter(container, stdin=stdin)

    def disarm_window(self, container: str) -> None:
        """Close the timed allow-all window now, before its timeout runs out."""
        self._runner.nft_via_nsenter(container, stdin=disarm_bypass_window())

    def inspect(self, container: str) -> ShieldReading:
        """Read the container's posture and its timed window from one ruleset listing.

        One ``nft -T list table`` serves both: the posture comes from the
        verifiers, the window's countdown from its own set block, in whole
        seconds — ``-T`` prints them so, where a plain listing would print
        ``4m59s693ms``.  The window keeps no host-side deadline, so the
        kernel's clock is the only record and a stale answer is impossible by
        construction.  Only the UP chain reads the window set, so the
        countdown is reported for UP alone.
        """
        output = self._list_table(container, numeric_time=True)
        state = self._classify(output)
        remaining = parse_window_expiry(output) if state is ShieldState.UP else None
        return ShieldReading(state=state, bypass_remaining=remaining)

    def shield_state(self, container: str) -> ShieldState:
        """Query the live nft ruleset to determine the container's shield state."""
        return self.inspect(container).state

    def confirmed_posture(self, container: str) -> ShieldState:
        """The posture allow and revoke route on: OFFLINE only when podman says no process runs.

        An empty listing reads as OFFLINE, and so does one that failed:
        ``_list_table`` swallows a ``podman inspect``, ``nsenter`` or ``nft``
        error, because a status poll must not crash on one.  A change must not
        take that for a stopped container.  It would skip the kernel, as an
        allow recorded only in the overlay or a revoke with no t10 swap, and
        report the change as waiting for the next start while the running
        ruleset stays as it was.  It would also rewrite the dnsmasq config on
        disk, which a running dnsmasq never reads, and after which no
        reconcile finds anything left to reload.  So an OFFLINE reading is
        checked against podman's own record.  No process (pid 0) is a stopped
        container, and so is one podman has no record of at all: removed, it
        runs nothing, and an orchestrator that recreates it under the same
        name starts it from the same bundle.  A process means a running
        container whose ruleset could not be read, or that carries none at
        all: that reads as ERROR, so the live path is tried and its failure
        reported.

        Raises:
            RuntimeError: When podman cannot say whether the container runs
                either — before the caller changes anything, so the change
                can simply be tried again.
        """
        posture = self.shield_state(container)
        if posture is not ShieldState.OFFLINE:
            return posture
        try:
            pid = self._runner.podman_inspect(container, "{{.State.Pid}}")
        except (ExecError, OSError) as exc:
            if self._podman_has_no_such_container(container):
                return ShieldState.OFFLINE
            raise RuntimeError(
                f"{container}'s ruleset could not be read, and podman cannot say whether it "
                f"is running ({exc}): nothing was changed, so try again"
            ) from exc
        return ShieldState.OFFLINE if pid.strip() in ("", "0") else ShieldState.ERROR

    def _podman_has_no_such_container(self, container: str) -> bool:
        """Whether podman says it has no container named *container*; ``False`` when it cannot say.

        A failed ``podman inspect`` is no such answer: its exit status is the
        same for a missing container as for podman failing to look.
        ``podman container exists`` tells them apart — 0 for a container
        podman has, 1 for one it has not, 125 when it could not look.
        """
        try:
            self._runner.run(["podman", "container", "exists", container])
        except ExecError as exc:
            return exc.rc == _PODMAN_NO_SUCH_CONTAINER
        except OSError:
            return False
        return False

    def _classify(self, output: str) -> ShieldState:
        """The posture a table listing shows; ``OFFLINE`` for no table at all."""
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
        return self._list_table(container)

    def _list_table(self, container: str, *, numeric_time: bool = False) -> str:
        """List the managed table inside *container*'s netns; ``""`` when there is none.

        *numeric_time* adds ``-T``: durations print as whole seconds, the form
        [`parse_window_expiry`][terok_shield.nft.rules.parse_window_expiry]
        reads.  The ``rules`` verb keeps nft's own compound form for people.
        """
        flags = ("-T",) if numeric_time else ()
        try:
            return self._runner.nft_via_nsenter(
                container, *flags, "list", "table", "inet", NFT_TABLE_NAME, check=False
            )
        except ExecError:
            return ""

    def preview(
        self, *, down: bool = False, disengaged: bool = False, profiles: Sequence[str] = ()
    ) -> str:
        """Generate the ruleset that would be applied to a container.

        With *profiles*, the ruleset the hook applies on the live tier at
        ``createRuntime``: their ``+localhost:PORT`` grants join the
        preamble and their literal IPs seed the t40 project-allow set.
        Domains are left out on purpose — the live tier never resolves
        them at apply time (dnsmasq learns them per query), so nothing is
        approximated.  Touches no setup, podman, DNS or state dir, which
        makes it the generator for applying a ruleset by hand.
        """
        entries = parse_policy(
            "".join(f"+{e}\n" for e in self._profiles.compose_profiles(list(profiles)))
        )
        builder = self._ruleset
        if grants := localhost_ports(entries):
            ports = (*self._config.loopback_ports, *grants)
            builder = RulesetBuilder(loopback_ports=tuple(dict.fromkeys(ports)))
        ruleset = builder.build_down(disengaged=disengaged) if down else builder.build_up()
        return ruleset + add_elements_dual(ip_targets(entries))


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


def _host_alias_args(address: str) -> list[str]:
    """Return the ``--add-host`` flags that pin every name of the host to *address*."""
    return [arg for alias in CONTAINER_HOST_ALIASES for arg in ("--add-host", f"{alias}:{address}")]


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


def _override_elements(seeds: Sequence[OverrideSeed], now: float) -> str:
    """nft commands adding *seeds* to the t10 sets, each expiring one timed to its deadline.

    The seconds left are rounded down, and never below one: nft reads
    ``timeout 0s`` as *never*, so an override in its last second must still
    carry a timeout.  A deadline further out than nft takes is cut to the
    longest timeout it does — the element runs out early, never late, and
    the next rebuild re-times it.
    """
    timeouts = {
        seed.address: min(max(int(seed.deadline - now), 1), ELEMENT_TIMEOUT_MAX_SECONDS)
        for seed in seeds
        if seed.deadline is not None
    }
    return add_override_elements_dual([seed.address for seed in seeds], timeouts=timeouts)


def _override_target(target: str) -> str:
    """*target* as a live override records it — or a refusal saying why no override can carry it.

    Raises:
        ValueError: For ``localhost`` and the container's host aliases (all
            host-service grants, ``+localhost:PORT``), a ``*.`` wildcard (it
            names no address, and t10 holds addresses only), or text that is
            no domain, IP or CIDR.
    """
    target = target.strip()
    bare = target.lower().rstrip(".")
    if bare in (LOCALHOST, *CONTAINER_HOST_ALIASES):
        raise ValueError(
            f"{target} is the host itself: reach a host service with a +localhost:PORT grant, "
            "not an override"
        )
    validate_target(target)
    if target.startswith("*."):
        raise ValueError(
            f"{target} is a wildcard: an override opens addresses, and a wildcard names none"
        )
    return safe_ip(target) if is_ip(target) else target


def _check_override_addresses(
    target: str, addresses: Sequence[str], *, host: Collection[str] = ()
) -> None:
    """Refuse an override with nothing to open, or one that reaches the host or the hard-deny floor.

    *host* holds the addresses through which the container reaches the host's
    own loopback (``host.containers.internal`` under its network mode).  Under
    pasta that address sits inside the hard-deny floor anyway; under
    slirp4netns it is the gateway, inside a private range an override could
    otherwise open — and with it every port the host listens on locally,
    where a ``+localhost:PORT`` grant opens one.

    Raises:
        RuntimeError: When *target* resolved to no address.
        ValueError: When any of its addresses takes in a host-loopback
            address, or lies in a hard-deny range — link-local and cloud
            metadata sit above every override.
    """
    if not addresses:
        raise RuntimeError(f"{target} resolves to no address — there is nothing to open")
    for address in addresses:
        if (loopback := _host_loopback_in(address, host)) is not None:
            raise ValueError(
                f"{target} reaches {loopback}, the host's own loopback ({CONTAINER_HOST_ALIAS}): "
                "reach a host service with a +localhost:PORT grant, not an override"
            )
        if (floor := _hard_deny_net(address)) is not None:
            raise ValueError(
                f"{target} reaches {address}, inside the hard-deny floor {floor}: link-local "
                "and cloud-metadata addresses sit above every override, so none is granted"
            )


def _host_loopback_in(address: str, host: Collection[str]) -> str | None:
    """The host-loopback address that *address* (an IP or CIDR) is or takes in, or ``None``."""
    net = ipaddress.ip_network(address, strict=False)
    for loopback in host:
        ip = ipaddress.ip_address(loopback)
        if ip.version == net.version and ip in net:
            return loopback
    return None


def _hard_deny_net(address: str) -> str | None:
    """The hard-deny range *address* (an IP or CIDR) overlaps, or ``None``."""
    net = ipaddress.ip_network(address, strict=False)
    for floor in _HARD_DENY_NETS:
        if net.version == floor.version and net.overlaps(floor):
            return str(floor)
    return None


def _unrecorded_grant(
    container: str, target: str, earlier: Sequence[PolicyEntry], exc: OSError
) -> str:
    """Why a grant the kernel took is not recorded — and what the next rebuild seeds in its place.

    A rebuild re-seeds t10 from the tier, which the failed write left as it
    was ([`write_tier`][terok_shield.state.StateBundle.write_tier]).
    *earlier* holds the tier's entries for *target* still in force: a
    rebuild restores those, each with its own expiry — a later one,
    perhaps, than the grant that failed to replace it.  With none, a rebuild
    ends the grant, and a name stays sinkholed meanwhile wherever dnsmasq
    serves the container: dnsmasq's config comes from the tier.  Whether the
    ``override`` event reached the audit trail goes unsaid: audit may be off,
    or its file on the same full disk.
    """
    holds = (
        f"the override of {target} holds in {container}'s running ruleset, "
        "but the t10 tier could not record it"
    )
    if not earlier:
        sinkholed = (
            "" if is_ip(target) else "; where dnsmasq serves it, the name stays sinkholed meanwhile"
        )
        return f"{holds}, so the next shield up or down ends it{sinkholed}: {exc}"
    recorded = ", ".join(
        dict.fromkeys(
            f"{EXPIRES_MARKER}={entry.meta[EXPIRES_MARKER]}"
            if EXPIRES_MARKER in entry.meta
            else "no expiry"
            for entry in earlier
        )
    )
    return (
        f"{holds}, so the next shield up or down restores the earlier record of it in its "
        f"place ({recorded}): {exc}"
    )


def _record_grant(
    container: str,
    bundle: StateBundle,
    target: str,
    expires: str,
    reason: str,
    earlier: Sequence[PolicyEntry],
) -> RuntimeError | None:
    """Record a grant the kernel took in the t10 tier — or the error saying why it is not.

    Returned, not raised: the grant holds either way, so the dnsmasq reload
    still follows before the caller hears of it.
    """
    try:
        bundle.upsert_override(target, expires, reason=reason)
    except OSError as exc:
        unrecorded = RuntimeError(_unrecorded_grant(container, target, earlier, exc))
        unrecorded.__cause__ = exc
        return unrecorded
    return None


def _cache_grant_answers(
    container: str,
    bundle: StateBundle,
    planned: EffectivePolicy,
    resolution: Mapping[str, Sequence[str]],
    target: str,
) -> RuntimeError | None:
    """Cache the answers a recorded grant's swap was seeded from — after the tier, never before.

    Written after the tier, the cache post-dates it, so the next rebuild
    finds it fresh and resolves nothing.  A cache older than the tier would
    be resolved afresh at the next ``shield up``/``down``, and a name that
    happened not to answer then would drop out of t10.  Only the names of
    *planned* — the tier as the grant recorded it — are kept.

    Returns the error, not raises it, when the cache cannot be written: the
    grant holds and the tier records it, but until the names resolve again a
    rebuild seeds them from the cache as it was, which may leave *target* out.
    The caller reloads dnsmasq first, so the name opens all the same.
    """
    names = [t for t in planned.override_targets() if not is_ip(t)]
    try:
        write_name_resolution(
            bundle.override_resolved, {name: resolution.get(name, []) for name in names}
        )
    except OSError as exc:
        uncached = RuntimeError(
            f"the override of {target} holds in {container}'s running ruleset and the t10 tier "
            "records it, but the addresses it was seeded from could not be cached, so a shield "
            f"up or down before the override names resolve again may leave it out: {exc}"
        )
        uncached.__cause__ = exc
        return uncached
    return None


def _revoke_target(target: str) -> str:
    """*target* as a revoke looks it up — or a refusal saying why no revoke can name it.

    Raises:
        ValueError: For text that is no domain, IP or CIDR, and for
            ``localhost``: a ``+localhost:PORT`` grant opens a preamble port,
            never a t10 element, so no swap could take it back and no revoke
            may claim to.
    """
    target = target.strip()
    validate_target(target)
    if target.lower() == LOCALHOST:
        raise ValueError(
            f"{target} is the host itself: a +localhost:PORT grant opens a host service, "
            "not an override, so there is no override of it to revoke"
        )
    return target


def _overrides_in_force(
    container: str, bundle: StateBundle, target: str, now: float
) -> list[PolicyEntry]:
    """The t10 entries for *target* still in force at *now* — at least one, or a refusal.

    Raises:
        RuntimeError: When *target* has no override in force on *container*:
            it never had one, or each it had ran out.
    """
    recorded = bundle.override_entries(target)
    effective = bundle.read_effective()
    in_force = [entry for entry in effective.active_override(now) if entry in recorded]
    if not in_force:
        raise RuntimeError(
            _no_override_in_force(container, target, recorded, effective.override_targets(now))
        )
    return in_force


def _no_override_in_force(
    container: str, target: str, recorded: Sequence[PolicyEntry], in_force: Sequence[str]
) -> str:
    """Why there is nothing to revoke: the override ran out, or *target* never had one.

    *recorded* holds the t10 entries for *target*, none of them in force any
    more.  *in_force* names every override that is, so a typo is easy to spot.
    """
    if recorded:
        ends = ", ".join(dict.fromkeys(e.meta.get(EXPIRES_MARKER, "unset") for e in recorded))
        return (
            f"the override of {target} on {container} is no longer in force (expires={ends}), "
            "so the kernel holds nothing to revoke"
        )
    listed = ", ".join(in_force) if in_force else "none"
    return f"{container} has no override of {target} to revoke (overrides in force: {listed})"


def _held_addresses(bundle: StateBundle, entries: Sequence[PolicyEntry]) -> list[str]:
    """The addresses *entries* opened: an IP or CIDR target itself, a name's from the override cache.

    Written the way the t10 set lists them — one host bare, a range with its
    prefix — so a report reads like ``nft list`` does.
    """
    resolution = read_name_resolution(bundle.override_resolved) or {}
    held: list[str] = []
    for entry in entries:
        named = [entry.target] if is_ip(entry.target) else resolution.get(entry.target, [])
        for address in filter(is_ip, named):
            net = ipaddress.ip_network(address.strip(), strict=False)
            bare = net.prefixlen == net.max_prefixlen
            held.append(str(net.network_address) if bare else str(net))
    return list(dict.fromkeys(held))


def _covered_by_seed(address: str, seeds: Sequence[OverrideSeed]) -> bool:
    """Whether a t10 seed admits all of *address* — an IP or CIDR inside one seed's range."""
    net = ipaddress.ip_network(address, strict=False)
    for seed in seeds:
        cover = ipaddress.ip_network(seed.address, strict=False)
        # Two CIDR blocks either nest or are disjoint: overlap plus a prefix
        # no longer than the address's means the seed contains it.
        if (
            net.version == cover.version
            and net.overlaps(cover)
            and cover.prefixlen <= net.prefixlen
        ):
            return True
    return False


def _revocation_detail(entry: PolicyEntry, *, live: bool) -> str | None:
    """The ``override_revoked`` audit detail: the grant's own expiry and reason, then when.

    It mirrors the ``override`` event's detail, so a grant and its revoke
    pair up in the trail.  ``at next start`` marks a stopped container's
    revoke, as the ``allowed`` event marks a stopped container's allow.
    """
    parts: list[str] = []
    if (expires := entry.meta.get(EXPIRES_MARKER)) is not None:
        parts.append(f"expires={expires}")
    if (reason := entry.meta.get(REASON_MARKER)) is not None:
        parts.append(f"reason={unquote(reason)}")
    if not live:
        parts.append("at next start")
    return "; ".join(parts) or None


def _runs_dnsmasq(state_dir: Path) -> bool:
    """True when the container runs a per-container dnsmasq, or recorded no tier yet.

    ``allow_domain`` / ``deny_domain`` reload that dnsmasq.  On the lookup
    and getent tiers the static IP-level allow/deny in ``allow_ip`` /
    ``deny_ip`` already ran, and there is no dnsmasq to reload.
    """
    tier = StateBundle(state_dir).read_dns_tier()
    return tier is None or tier.runs_dnsmasq
