# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""terok-shield: nftables-based egress firewalling for Podman containers.

Public API facade.  The ``Shield`` class coordinates collaborators:

- **HookMode** (``hooks.mode``) — per-container nft ruleset lifecycle
- **DnsResolver** (``dns.resolver``) — domain resolution and caching
- **ProfileLoader** (``profiles``) — allowlist profile composition
- **RulesetBuilder** (``nft.rules``) — nftables ruleset generation
- **AuditLogger** (``audit``) — per-container JSONL audit trail
- **CommandRunner** (``run``) — subprocess execution boundary

Core and support modules are imported lazily — ``from terok_shield
import ShieldConfig`` does not pull in nft, dnsmasq, or subprocess
helpers.  Heavy imports are deferred until ``Shield`` is instantiated.
"""

import importlib as _importlib
import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version as _meta_version
from pathlib import Path
from typing import TYPE_CHECKING

# ── Eager: foundation layer (zero-cost, pure data) ─────
from .config import (
    DnsTier,
    ShieldConfig,
    ShieldMode,
    ShieldModeBackend,
    ShieldRuntime,
    ShieldState,
)
from .paths import HOOK_ENTRYPOINT_NAME
from .podman_info import (
    find_hooks_dirs,
    global_hooks_hint,
    has_global_hooks,
    parse_podman_info,
)
from .state import StateBundle
from .util import is_ip as _is_ip

if TYPE_CHECKING:
    from terok_util import ArgDef, CommandDef

    from ._hub_events import HubEventEmitter
    from .audit import AuditLogger
    from .commands import COMMANDS
    from .dns.resolver import DnsResolver
    from .hooks.install import HooksInstaller
    from .nft.rules import RulesetBuilder
    from .profiles import ProfileLoader
    from .run import CommandRunner, ExecError

# ── Lazy: core + support layer ──────────────────────────
# Re-exported names from __all__ that are deferred until first access.
# Keeps ``from terok_shield import ShieldConfig`` lightweight.

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "BinaryCheck": ("terok_shield.prereqs", "BinaryCheck"),
    "ExecError": ("terok_shield.run", "ExecError"),
    "HooksInstaller": ("terok_shield.hooks.install", "HooksInstaller"),
    "ensure_user_hooks_dir_configured": (
        "terok_shield.hooks.install",
        "ensure_user_hooks_dir_configured",
    ),
    "NftNotFoundError": ("terok_shield.run", "NftNotFoundError"),
    "ShieldNeedsSetup": ("terok_shield.run", "ShieldNeedsSetup"),
    "check_firewall_binaries": ("terok_shield.prereqs", "check_firewall_binaries"),
    "check_krun_binaries": ("terok_shield.prereqs", "check_krun_binaries"),
    # Command registry — re-exported for the terok integration layer.
    # ArgDef/CommandDef now live in terok-util; we route through it so
    # existing consumers (terok.lib.integrations.shield) keep working.
    "ArgDef": ("terok_util", "ArgDef"),
    "COMMANDS": ("terok_shield.commands", "COMMANDS"),
    "CommandDef": ("terok_util", "CommandDef"),
}


def __getattr__(name: str) -> object:
    """Lazy import for re-exported core/support layer names."""
    if name in _LAZY_IMPORTS:
        mod_path, attr = _LAZY_IMPORTS[name]
        mod = _importlib.import_module(mod_path)
        value = getattr(mod, attr)
        globals()[name] = value  # cache for subsequent access
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


logger = logging.getLogger(__name__)

__version__: str = "0.0.0"  # placeholder; replaced at build time
try:
    __version__ = _meta_version("terok-shield")
except PackageNotFoundError:
    pass  # editable install or running from source without metadata


@dataclass(frozen=True)
class EnvironmentCheck:
    """Result of [`Shield.check_environment`][terok_shield.Shield.check_environment].

    Machine-readable fields for programmatic consumers (terok TUI, scripts).
    Human-readable ``issues`` and ``setup_hint`` for CLI display.

    Attributes:
        ok: True if no issues found.
        podman_version: Detected podman version tuple.
        hooks: Hook installation type (``per-container``, ``global``,
            ``not-installed``).
        health: Environment health (``ok``, ``setup-needed``, ``stale-hooks``).
        dns_tier: Active DNS resolution tier (``dnsmasq``, ``dig``, ``getent``).
        issues: List of human-readable issue descriptions.
        needs_setup: True if one-time setup is required.
        setup_hint: Setup instructions (empty if not needed).
    """

    dns_tier: str = ""
    ok: bool = True
    podman_version: tuple[int, ...] = (0,)
    hooks: str = "per-container"
    health: str = "ok"
    issues: list[str] = field(default_factory=list)
    needs_setup: bool = False
    setup_hint: str = ""


def _read_installed_hook_version(hooks_dirs: list[Path]) -> int | None:
    """Read ``BUNDLE_VERSION`` from the installed ballast module, or ``None``.

    The ballast (``_oci_state.py``) lives *next to* the role script, not
    necessarily in *hooks_dirs* — shield's own installer keeps them in
    one directory, but another package may register a *hooks_dirs* entry
    that holds only descriptors.  So the ballast is located via the
    descriptor's ``path`` (the load-bearing reference to the role
    script) rather than scanned for directly in *hooks_dirs*.
    """
    import json
    import re

    from .podman_info.hooks_dir import HOOK_JSON_FILENAME

    pattern = re.compile(r"^BUNDLE_VERSION\s*=\s*(\d+)", re.MULTILINE)
    # find_hooks_dirs() yields directories in precedence order with the
    # last entry taking effect (podman's last-wins --hooks-dir rule), so
    # walk in reverse and stop at the first descriptor we find: that is
    # the *active* install.  If its descriptor or ballast is broken we
    # report ``None`` (unknown / broken) rather than falling through to a
    # lower-precedence dir — podman still loads the broken higher one, so
    # reporting a stale lower version would mask the real active install.
    for d in reversed(hooks_dirs):
        descriptor = d / HOOK_JSON_FILENAME
        if not descriptor.is_file():
            continue
        try:
            data = json.loads(descriptor.read_text())
            if not isinstance(data, dict):
                return None
            hook = data.get("hook")
            if not isinstance(hook, dict):
                return None
            argv = hook.get("path")
            if not isinstance(argv, str):
                return None
            ballast = Path(argv).parent / "_oci_state.py"
            if ballast.is_file():
                m = pattern.search(ballast.read_text())
                if m:
                    return int(m.group(1))
        except (OSError, ValueError):
            return None
        return None
    return None


# ── Shield Facade ────────────────────────────────────────


class Shield:
    """Public API facade — coordinates collaborators per container.

    Delegates to ``HookMode`` for netns/nft operations, ``DnsResolver``
    for name resolution, ``ProfileLoader`` for allowlists,
    ``RulesetBuilder`` for ruleset generation, and ``AuditLogger`` for
    the audit trail.  All collaborators are injectable for testing.
    """

    def __init__(
        self,
        config: ShieldConfig,
        *,
        runner: "CommandRunner | None" = None,
        audit: "AuditLogger | None" = None,
        dns: "DnsResolver | None" = None,
        profiles: "ProfileLoader | None" = None,
        ruleset: "RulesetBuilder | None" = None,
        hub_events: "HubEventEmitter | None" = None,
    ) -> None:
        """Create the shield facade.

        Args:
            config: Shield configuration (must include state_dir).
            runner: Command runner (default: ``SubprocessRunner``).
            audit: Audit logger (default: from config.state_dir).
            dns: DNS resolver (default: from runner).
            profiles: Profile loader (default: from config.profiles_dir).
            ruleset: Ruleset builder (default: from config loopback_ports).
            hub_events: Best-effort emitter for ``shield_up`` / ``shield_down``
                events bound for the terok-clearance hub (default: a fresh
                [`HubEventEmitter`][terok_shield._hub_events.HubEventEmitter]).  The
                emitter routes each event to the supervisor's
                per-container socket using the ``container_id`` supplied
                on every [`up`][terok_shield.Shield.up] /
                [`down`][terok_shield.Shield.down] call.  Pass a no-op
                stub in tests that should not touch the socket.
        """
        from ._hub_events import HubEventEmitter
        from .audit import AuditLogger
        from .dns.resolver import DnsResolver
        from .nft.rules import RulesetBuilder
        from .profiles import ProfileLoader
        from .run import SubprocessRunner

        self.config = config
        self.runner = runner or SubprocessRunner()
        self.audit = audit or AuditLogger(
            audit_path=StateBundle(config.state_dir).audit,
            enabled=config.audit_enabled,
        )
        self.dns = dns or DnsResolver(runner=self.runner)
        self.profiles = profiles or ProfileLoader(
            user_dir=config.profiles_dir or Path("/nonexistent"),
        )
        self.ruleset = ruleset or RulesetBuilder(loopback_ports=config.loopback_ports)
        self.hub_events = hub_events or HubEventEmitter()
        self._mode = self._create_mode(config.mode)

    def _create_mode(self, mode: ShieldMode) -> ShieldModeBackend:
        """Create the mode backend for the given mode."""
        if mode == ShieldMode.HOOK:
            from .hooks.mode import HookMode

            return HookMode(
                config=self.config,
                runner=self.runner,
                audit=self.audit,
                dns=self.dns,
                profiles=self.profiles,
                ruleset=self.ruleset,
            )
        raise ValueError(f"Unsupported shield mode: {mode!r}")

    def check_environment(self) -> EnvironmentCheck:
        """Check the podman environment for compatibility issues.

        Proactive check for API consumers (e.g. terok).  Returns an
        [`EnvironmentCheck`][terok_shield.EnvironmentCheck] with detected issues and setup hints.
        Does not raise — the caller decides how to handle issues.
        """
        from . import state
        from .dns import apparmor

        output = self.runner.run(["podman", "info", "-f", "json"], check=False)
        info = parse_podman_info(output)
        issues: list[str] = []
        needs_setup = False
        setup_hint = ""
        hooks = "per-container"
        health = "ok"

        tier, apparmor_blocked = apparmor.detect_dns_tier_under_apparmor(
            self.runner, self.config.state_dir
        )
        dns_tier = tier.value
        if apparmor_blocked:
            issues.append(
                "dnsmasq is present but AppArmor confines it from the shield "
                f"state directory — domain allowlisting falls back to static {tier.value} "
                "resolution (no IP rotation handling). Install the terok AppArmor "
                "profile to enable the dnsmasq tier (see docs/apparmor.md)"
            )
        elif tier == DnsTier.DIG:
            issues.append(
                "dnsmasq unavailable (not installed, or without nftset support) — "
                "domain allowlisting uses static pre-start resolution "
                "(no IP rotation handling). "
                "Install an nftset-capable dnsmasq for dynamic domain-based egress control"
            )
        elif tier == DnsTier.GETENT:
            issues.append(
                "Neither dnsmasq nor dig found — DNS resolution uses getent "
                "(single IP, no AAAA). Install dnsmasq or at minimum dnsutils/bind-utils"
            )

        hooks_dirs = find_hooks_dirs()
        global_hooks = has_global_hooks(hooks_dirs)

        if not info.hooks_dir_persists:
            if global_hooks:
                hooks = "global"
                health = "ok"
                # Check hook version matches current package
                hook_ver = _read_installed_hook_version(hooks_dirs)
                if hook_ver != state.BUNDLE_VERSION:
                    health = "stale-hooks"
                    issues.append(
                        f"Installed hook version {hook_ver} != expected {state.BUNDLE_VERSION}. "
                        "Run `terok-shield setup` to update."
                    )
            else:
                hooks = "not-installed"
                health = "setup-needed"
                needs_setup = True
                setup_hint = global_hooks_hint()
                issues.append(
                    "Global hooks not installed - containers will lose firewall on restart"
                )
        elif global_hooks:
            health = "stale-hooks"
            issues.append(
                "Stale global hooks detected - not needed on podman >= 5.6.0. "
                "Consider removing them."
            )

        return EnvironmentCheck(
            ok=not issues,
            podman_version=info.version,
            hooks=hooks,
            health=health,
            dns_tier=dns_tier,
            issues=issues,
            needs_setup=needs_setup,
            setup_hint=setup_hint,
        )

    def status(self) -> dict:
        """Return current shield status information."""
        return {
            "mode": self.config.mode.value,
            "profiles": self.profiles.list_profiles(),
            "audit_enabled": self.config.audit_enabled,
        }

    def pre_start(self, container: str, profiles: list[str] | None = None) -> list[str]:
        """Prepare shield for container start.  Returns extra podman args."""
        if profiles is None:
            profiles = list(self.config.default_profiles)
        result = self._mode.pre_start(container, profiles)
        self.audit.log_event(container, "setup", detail=f"profiles={','.join(profiles)}")
        return result

    def allow(self, container: str, target: str) -> list[str]:
        """Live-allow a domain or IP for a running container."""
        from .run import ExecError

        is_domain = not _is_ip(target)
        ips = [target] if not is_domain else self.dns.resolve_domains([target])
        allowed: list[str] = []
        for ip in ips:
            try:
                self._mode.allow_ip(container, ip)
            except (ExecError, OSError) as exc:
                logger.warning("allow_ip failed for %s on %s: %s", ip, container, exc)
                continue
            allowed.append(ip)
            self.audit.log_event(container, "allowed", dest=ip, detail=f"target={target}")
        # Update dnsmasq config for domain targets (so future IP rotations are captured)
        if is_domain and allowed:
            self._mode.allow_domain(target)
        return allowed

    def deny(self, container: str, target: str) -> list[str]:
        """Live-deny a domain or IP for a running container."""
        from .run import ExecError

        is_domain = not _is_ip(target)
        ips = [target] if not is_domain else self.dns.resolve_domains([target])
        denied: list[str] = []
        for ip in ips:
            try:
                self._mode.deny_ip(container, ip)
            except (ExecError, OSError) as exc:
                logger.warning("deny_ip failed for %s on %s: %s", ip, container, exc)
                continue
            denied.append(ip)
            self.audit.log_event(container, "denied", dest=ip, detail=f"target={target}")
        # Remove domain from dnsmasq config (stops future auto-population)
        if is_domain and denied:
            self._mode.deny_domain(target)
        return denied

    def rules(self, container: str) -> str:
        """Return current nft rules for a container."""
        return self._mode.list_rules(container)

    def down(self, container: str, container_id: str, *, allow_all: bool = False) -> None:
        """Switch a running container to bypass mode.

        *container* is the operator-facing podman name (audit log key);
        *container_id* is the full podman UUID — the routing key for
        the per-container hub socket the supervisor listens on.  The
        caller knows both at every emit site, so neither carries a
        default.
        """
        self._mode.shield_down(container, allow_all=allow_all)
        self.audit.log_event(
            container,
            "shield_down",
            detail="allow_all=True" if allow_all else None,
        )
        self.hub_events.shield_down(
            container,
            container_id,
            allow_all=allow_all,
            dossier=self._read_dossier(),
        )

    def quarantine(self, container: str) -> None:
        """Total network blackout — drop all traffic, log dropped traffic."""
        self._mode.shield_quarantine(container)
        self.audit.log_event(container, "shield_quarantine")

    def up(self, container: str, container_id: str) -> None:
        """Restore normal deny-all mode for a running container.

        *container* / *container_id* — see
        [`down`][terok_shield.Shield.down].
        """
        self._mode.shield_up(container)
        self.audit.log_event(container, "shield_up")
        self.hub_events.shield_up(container, container_id, dossier=self._read_dossier())

    def _read_dossier(self) -> dict[str, str]:
        """Resolve the wire dossier for this container by reading the orchestrator's task meta.

        The bridge ``createRuntime`` hook writes the ``dossier.meta_path``
        OCI annotation to ``state_dir/meta_path``; ``Shield.up()`` /
        ``Shield.down()`` follow that pointer, open the orchestrator's
        live task-meta JSON, and project it to the wire-dossier shape
        ``{project, task, name}`` — the same projection the per-container
        reader applies to every block event, so every event for one
        container renders identically in the clearance UI.

        Empty meta_path (standalone container, no orchestrator) →
        ``{}`` → bare-container-name popup.  No staleness window: the
        meta JSON is the orchestrator's live state and is re-read on
        every call.
        """
        from .resources._oci_state import read_meta_path, resolve_dossier_from_meta

        return resolve_dossier_from_meta(read_meta_path(self.config.state_dir))

    def state(self, container: str) -> ShieldState:
        """Query the live nft ruleset to determine a container's shield state."""
        return self._mode.shield_state(container)

    def preview(self, *, down: bool = False, allow_all: bool = False) -> str:
        """Generate the ruleset that would be applied to a container."""
        return self._mode.preview(down=down, allow_all=allow_all)

    def resolve(
        self,
        profiles: list[str] | None = None,
        *,
        force: bool = False,
    ) -> list[str]:
        """Resolve DNS profiles and cache the results."""
        if profiles is None:
            profiles = list(self.config.default_profiles)
        entries = self.profiles.compose_profiles(profiles)
        if not entries:
            return []
        max_age = 0 if force else 3600
        cache_path = StateBundle(self.config.state_dir).profile_allowed
        return self.dns.resolve_and_cache(entries, cache_path, max_age=max_age)

    def profiles_list(self) -> list[str]:
        """List available profile names."""
        return self.profiles.list_profiles()

    def tail_log(self, n: int = 50) -> Iterator[dict]:
        """Yield the last *n* audit events."""
        return self.audit.tail_log(n)

    def compose_profiles(self, names: list[str]) -> list[str]:
        """Load and merge multiple profiles."""
        return self.profiles.compose_profiles(names)


__all__ = [
    "ArgDef",
    "BinaryCheck",
    "COMMANDS",
    "CommandDef",
    "EnvironmentCheck",
    "ExecError",
    "HOOK_ENTRYPOINT_NAME",
    "HooksInstaller",
    "NftNotFoundError",
    "Shield",
    "ShieldConfig",
    "ShieldMode",
    "ShieldNeedsSetup",
    "ShieldRuntime",
    "ShieldState",
    "check_firewall_binaries",
    "check_krun_binaries",
    "ensure_user_hooks_dir_configured",
]
