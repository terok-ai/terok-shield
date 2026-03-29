# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Hook mode: OCI hooks + per-container netns.

Uses OCI hooks to apply per-container nftables rules inside each
container's network namespace.  No root required -- only podman and nft.
The stdlib-only ``hook_entrypoint.py`` applies the pre-generated ruleset at
container creation; this module handles setup, DNS pre-resolution, and live
allow/deny.

Provides ``HookMode`` (Strategy pattern, implements ``ShieldModeBackend``)
and ``install_hooks()`` for OCI hook file installation.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import TYPE_CHECKING

from . import dnsmasq, state
from .config import (
    ANNOTATION_AUDIT_ENABLED_KEY,
    ANNOTATION_DNS_TIER_KEY,
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
from .nft import NFT_TABLE, RulesetBuilder, safe_ip
from .nft_constants import NFT_SET_TIMEOUT_DNSMASQ, PASTA_DNS, SLIRP4NETNS_DNS
from .podman_info import (
    PodmanInfo,
    global_hooks_hint,
    has_global_hooks,
    parse_podman_info,
    parse_resolv_conf,
)
from .run import ExecError, ShieldNeedsSetup
from .util import is_ip as _is_ip, is_ipv4

if TYPE_CHECKING:
    from .audit import AuditLogger
    from .dns import DnsResolver
    from .profiles import ProfileLoader
    from .run import CommandRunner


# ── Private helpers ──────────────────────────────────────


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


def _generate_entrypoint() -> str:
    """Return the self-contained OCI hook entrypoint script.

    The script uses ``#!/usr/bin/env python3`` so it resolves Python at
    execution time — no virtualenv path is baked in at setup time.
    Works for all install methods: pip, pipx, Poetry, system package.
    """
    return (Path(__file__).parent / "resources" / "hook_entrypoint.py").read_text()


def _generate_hook_json(entrypoint: str, stage: str) -> str:
    """Generate an OCI hook JSON descriptor for a given stage.

    Args:
        entrypoint: Absolute path to the hook entrypoint script.
        stage: OCI hook stage (``createRuntime`` or ``poststop``).
    """
    hook = {
        "version": "1.0.0",
        "hook": {"path": entrypoint, "args": ["terok-shield-hook", stage]},
        "when": {"annotations": {ANNOTATION_KEY: ".*"}},
        "stages": [stage],
    }
    return json.dumps(hook, indent=2) + "\n"


def setup_global_hooks(target_dir: Path, *, use_sudo: bool = False) -> None:
    """Install OCI hooks in a global directory for restart persistence.

    Writes the entrypoint script and hook JSON files directly into
    *target_dir*.  When *use_sudo* is True, writes to a temp directory
    first and copies via ``sudo cp``.

    Args:
        target_dir: Global hooks directory to install into.
        use_sudo: Use ``sudo`` for writing to the target directory.
    """
    import subprocess
    import tempfile

    entrypoint_name = "terok-shield-hook"

    if use_sudo:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Generate JSONs referencing the FINAL entrypoint path
            final_entrypoint = target_dir / entrypoint_name
            _write_hook_files(tmp_path / entrypoint_name, tmp_path, final_entrypoint)
            subprocess.run(
                ["sudo", "mkdir", "-p", str(target_dir)],
                check=True,  # noqa: S603, S607
            )
            files = [str(tmp_path / entrypoint_name)]
            for stage in ("createRuntime", "poststop"):
                files.append(str(tmp_path / f"terok-shield-{stage}.json"))
            subprocess.run(
                ["sudo", "cp", *files, str(target_dir) + "/"],
                check=True,  # noqa: S603, S607
            )
            subprocess.run(
                ["sudo", "chmod", "+x", str(final_entrypoint)],  # noqa: S603, S607
                check=True,
            )
    else:
        target_dir.mkdir(parents=True, exist_ok=True)
        _write_hook_files(target_dir / entrypoint_name, target_dir)


def _write_hook_files(
    hook_entrypoint: Path,
    hooks_dir: Path,
    json_entrypoint_path: Path | None = None,
) -> None:
    """Write entrypoint script and hook JSON files.

    Args:
        hook_entrypoint: Where to write the entrypoint script.
        hooks_dir: Where to write the hook JSON files.
        json_entrypoint_path: Path to embed in hook JSONs (defaults to
            *hook_entrypoint*).  Used when writing to a temp dir but
            the JSONs need to reference the final install location.
    """
    hook_entrypoint.write_text(_generate_entrypoint())
    hook_entrypoint.chmod(hook_entrypoint.stat().st_mode | stat.S_IEXEC)
    ref_path = str(json_entrypoint_path or hook_entrypoint)
    for stage_name in ("createRuntime", "poststop"):
        hook_json = _generate_hook_json(ref_path, stage_name)
        (hooks_dir / f"terok-shield-{stage_name}.json").write_text(hook_json)


def install_hooks(*, hook_entrypoint: Path, hooks_dir: Path) -> None:
    """Install OCI hook entrypoint and hook JSON files.

    Installs hooks for the ``createRuntime`` and ``poststop`` stages.

    Args:
        hook_entrypoint: Path for the entrypoint script.
        hooks_dir: Directory for hook JSON files.
    """
    hook_entrypoint.parent.mkdir(parents=True, exist_ok=True)
    hook_entrypoint.write_text(_generate_entrypoint())
    hook_entrypoint.chmod(hook_entrypoint.stat().st_mode | stat.S_IEXEC)

    hooks_dir.mkdir(parents=True, exist_ok=True)
    for stage_name in ("createRuntime", "poststop"):
        hook_json = _generate_hook_json(str(hook_entrypoint), stage_name)
        (hooks_dir / f"terok-shield-{stage_name}.json").write_text(hook_json)


# ── HookMode (Strategy) ─────────────────────────────────


class HookMode:
    """Strategy: hook-mode shield backend (implements ``ShieldModeBackend``).

    Manages the full lifecycle of OCI-hook-based container firewalling:
    pre-start DNS resolution (including hook installation), live
    allow/deny, bypass, and ruleset preview.  Collaborates with
    ``RulesetBuilder``, ``CommandRunner``, ``AuditLogger``,
    ``DnsResolver``, and ``ProfileLoader`` via constructor injection.
    """

    def __init__(
        self,
        *,
        config: ShieldConfig,
        runner: CommandRunner,
        audit: AuditLogger,
        dns: DnsResolver,
        profiles: ProfileLoader,
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

    def pre_start(self, container: str, profiles: list[str]) -> list[str]:
        """Prepare for container start in hook mode.

        Installs hooks (idempotent), composes profiles, resolves DNS
        domains, writes allowlist, detects DNS tier, sets annotations,
        and returns the podman CLI arguments needed for shield protection.

        Raises:
            ShieldNeedsSetup: On podman < 5.6.0 without global hooks.
        """
        sd = self._config.state_dir.resolve()
        info = self._get_podman_info()

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

        # Resolve DNS and write profile allowlist
        entries = self._profiles.compose_profiles(profiles)
        if tier == DnsTier.DNSMASQ:
            # dnsmasq handles domain→IP resolution at runtime via --nftset.
            # Split entries: write domains for dnsmasq config, resolve only raw IPs.
            domains, raw_ips = _split_domains_ips(entries)
            state.profile_domains_path(sd).write_text("\n".join(domains) + "\n" if domains else "")
            self._dns.resolve_and_cache(raw_ips, state.profile_allowed_path(sd))
        else:
            # dig/getent tier: resolve everything to IPs at pre-start time.
            self._dns.resolve_and_cache(entries, state.profile_allowed_path(sd))

        # Persist runtime params before container starts (hook reads from state dir)
        state.upstream_dns_path(sd).write_text(f"{upstream_dns}\n")
        state.dns_tier_path(sd).write_text(f"{tier.value}\n")

        # Pre-generate complete nft ruleset (gateway sets start empty; hook populates them)
        set_timeout = NFT_SET_TIMEOUT_DNSMASQ if tier == DnsTier.DNSMASQ else ""
        ruleset_builder = RulesetBuilder(
            dns=upstream_dns,
            loopback_ports=self._config.loopback_ports,
            set_timeout=set_timeout,
        )
        ips = state.read_effective_ips(sd)
        state.ruleset_path(sd).write_text(
            ruleset_builder.build_hook() + ruleset_builder.add_elements_dual(ips)
        )

        # Pre-generate dnsmasq config if using dnsmasq tier; otherwise scrub
        # stale artifacts so hook_entrypoint.py does not launch dnsmasq when
        # the tier has changed on a reused state directory.
        if tier == DnsTier.DNSMASQ:
            domains = dnsmasq.read_merged_domains(sd)
            conf = dnsmasq.generate_config(upstream_dns, domains, state.dnsmasq_pid_path(sd))
            state.dnsmasq_conf_path(sd).write_text(conf)
            state.resolv_conf_path(sd).write_text("nameserver 127.0.0.1\noptions ndots:0\n")
        else:
            for stale in (
                state.dnsmasq_conf_path(sd),
                state.dnsmasq_pid_path(sd),
                state.resolv_conf_path(sd),
            ):
                stale.unlink(missing_ok=True)

        # Build podman args
        args: list[str] = []

        if os.geteuid() != 0:
            if mode == "slirp4netns":
                args += [
                    "--network",
                    "slirp4netns:allow_host_loopback=true",
                    "--add-host",
                    "host.containers.internal:10.0.2.2",
                ]
            else:
                tcp_flags = ",".join(f"-T,{p}" for p in self._config.loopback_ports)
                # -t,none / -u,none: disable host→container port forwarding.
                # With -t,auto or -u,auto pasta detects every port the host is
                # listening on (including port 53 from systemd-resolved) and tries
                # to bind them, which requires CAP_NET_BIND_SERVICE and fails
                # rootless.  Terok containers only make outbound connections;
                # inbound host→container forwarding is not needed.
                # The -T flags below handle container-internal loopback redirects;
                # container→internet and pasta's DNS proxy at 169.254.1.1 work via
                # pasta's own NAT and are unaffected by -t/-u.
                pasta_arg = f"pasta:-t,none,-u,none,{tcp_flags},-U,auto" if tcp_flags else "pasta"
                args += [
                    "--network",
                    pasta_arg,
                    "--add-host",
                    "host.containers.internal:127.0.0.1",
                ]

        # Redirect container DNS through the per-container dnsmasq instance.
        #
        # With pasta networking, podman normally generates /etc/resolv.conf pointing
        # to pasta's DNS proxy (169.254.1.1) and bind-mounts it read-only.  We need
        # the container to use 127.0.0.1 (dnsmasq) instead so that every DNS
        # resolution populates the nft allow sets via --nftset — enabling dynamic
        # domain-based egress control.
        #
        # --dns 127.0.0.1 cannot be used: podman passes it to pasta as a DNS-splice
        # target, causing pasta to bind HOST UDP/TCP port 53.  Port 53 is privileged
        # (< 1024) and rootless pasta lacks CAP_NET_BIND_SERVICE, so the container
        # fails to start.
        #
        # Instead, pre_start writes resolv.conf to the state directory and passes
        # it as an explicit volume mount.  Podman detects the user-supplied mount
        # and skips its own resolv.conf generation entirely — pasta's DNS proxy
        # never appears in the container's resolver list.  The :ro flag prevents
        # the container payload from redirecting DNS away from dnsmasq, which would
        # silently break dynamic domain allowlisting.  The :Z flag relabels the
        # file with this container's private MCS label so that container_t can read
        # it even when the state directory is labeled data_home_t.  :Z (private)
        # is correct here because each container has its own state directory and
        # its own resolv.conf — there is no cross-container sharing.
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
        ]

        # Hooks dir: per-container on modern podman, global on old podman
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

    def _detect_dns_tier(self) -> DnsTier:
        """Detect the best available DNS resolution tier.

        Delegates to the shared :func:`detect_dns_tier` helper.
        Probes the installed dnsmasq for ``--nftset`` support before
        selecting the dnsmasq tier.
        """
        return detect_dns_tier(self._runner.has, lambda: dnsmasq.has_nftset_support(self._runner))

    def _get_podman_info(self) -> PodmanInfo:
        """Get podman info, caching the result for the lifetime of this instance."""
        if self._podman_info is None:
            output = self._runner.run(["podman", "info", "-f", "json"], check=False)
            self._podman_info = parse_podman_info(output)
        return self._podman_info

    def _set_for_ip(self, ip: str) -> str:
        """Return the nft set name for an IP address."""
        return "allow_v4" if is_ipv4(ip) else "allow_v6"

    def _live_path(self) -> Path:
        """Return the resolved path to live.allowed (prevents path traversal)."""
        return state.live_allowed_path(self._config.state_dir).resolve()

    def allow_ip(self, container: str, ip: str) -> None:
        """Live-allow an IP for a running container via nsenter."""
        ip = safe_ip(ip)

        # Un-deny: remove from deny.list if present
        sd = self._config.state_dir.resolve()
        dp = state.deny_path(sd)
        if dp.is_file():
            denied = state.read_denied_ips(sd)
            if ip in denied:
                denied.discard(ip)
                dp.write_text("".join(f"{d}\n" for d in sorted(denied)))

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
        If the IP appears in profile.allowed, persists to deny.list so the
        deny survives ``shield_up`` and container restarts.
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
        except ExecError:
            pass

        # Remove from live.allowed
        live_path = self._live_path()
        if live_path.is_file():
            lines = live_path.read_text().splitlines()
            lines = [line for line in lines if line.strip() != ip]
            live_path.write_text("\n".join(lines) + "\n" if lines else "")

        # Persist to deny.list if IP is in profile.allowed
        profile_path = state.profile_allowed_path(sd)
        if profile_path.is_file():
            profile_ips = {
                line.strip() for line in profile_path.read_text().splitlines() if line.strip()
            }
            if ip in profile_ips:
                dp = state.deny_path(sd)
                existing = state.read_denied_ips(sd)
                if ip not in existing:
                    with dp.open("a") as f:
                        f.write(f"{ip}\n")

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

    def _read_upstream_dns(self) -> str | None:
        """Read persisted upstream DNS from state (written by the OCI hook).

        Returns None if the file is absent (pre-dnsmasq container or
        container started before this feature).
        """
        sd = self._config.state_dir.resolve()
        path = state.upstream_dns_path(sd)
        if not path.is_file():
            return None
        value = path.read_text().strip()
        return value or None

    def _container_ruleset(self, container: str) -> RulesetBuilder:
        """Build a RulesetBuilder with the container's actual DNS settings.

        Prefers persisted upstream DNS (from pre_start) over resolv.conf,
        because dnsmasq mode rewrites resolv.conf to ``127.0.0.1``.
        Reads persisted DNS tier to set nft element timeouts for dnsmasq mode.
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
        ruleset = self._container_ruleset(container)
        rs = ruleset.build_hook()
        current = self.shield_state(container)
        if current == ShieldState.INACTIVE:
            stdin = rs
        else:
            stdin = f"delete table {NFT_TABLE}\n{rs}"
        self._runner.nft_via_nsenter(container, stdin=stdin)

        # Re-add effective IPs (allowed minus denied)
        sd = self._config.state_dir.resolve()
        unique_ips = state.read_effective_ips(sd)

        if unique_ips:
            elements_cmd = ruleset.add_elements_dual(unique_ips)
            if elements_cmd:
                self._runner.nft_via_nsenter(container, stdin=elements_cmd)

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
        errors = ruleset.verify_hook(output)
        if errors:
            raise RuntimeError(f"Ruleset verification failed: {'; '.join(errors)}")

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

        if not self._ruleset.verify_hook(output):
            return ShieldState.UP

        return ShieldState.ERROR

    def preview(self, *, down: bool = False, allow_all: bool = False) -> str:
        """Generate the ruleset that would be applied to a container."""
        if down:
            return self._ruleset.build_bypass(allow_all=allow_all)
        return self._ruleset.build_hook()
