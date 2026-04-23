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
    AuditFileConfig,
    DnsTier,
    ShieldConfig,
    ShieldFileConfig,
    ShieldMode,
    ShieldState,
    detect_dns_tier,
)
from .paths import HOOK_ENTRYPOINT_NAME, reader_script_path
from .podman_info import (
    USER_HOOKS_DIR,
    ensure_containers_conf_hooks_dir,
    find_hooks_dirs,
    global_hooks_hint,
    has_global_hooks,
    parse_podman_info,
    system_hooks_dir,
)
from .util import is_ip as _is_ip

if TYPE_CHECKING:
    from ._hub_events import HubEventEmitter
    from .audit import AuditLogger
    from .dns.resolver import DnsResolver
    from .nft.rules import RulesetBuilder
    from .profiles import ProfileLoader
    from .run import CommandRunner

# ── Lazy: core + support layer ──────────────────────────
# Re-exported names from __all__ that are deferred until first access.
# Keeps ``from terok_shield import ShieldConfig`` lightweight.

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "AuditLogger": ("terok_shield.audit", "AuditLogger"),
    "CommandRunner": ("terok_shield.run", "CommandRunner"),
    "DigNotFoundError": ("terok_shield.run", "DigNotFoundError"),
    "DnsResolver": ("terok_shield.dns.resolver", "DnsResolver"),
    "ExecError": ("terok_shield.run", "ExecError"),
    "NftNotFoundError": ("terok_shield.run", "NftNotFoundError"),
    "ProfileLoader": ("terok_shield.profiles", "ProfileLoader"),
    "RulesetBuilder": ("terok_shield.nft.rules", "RulesetBuilder"),
    "ShieldNeedsSetup": ("terok_shield.run", "ShieldNeedsSetup"),
    "SubprocessRunner": ("terok_shield.run", "SubprocessRunner"),
    "setup_global_hooks": ("terok_shield.hooks.install", "setup_global_hooks"),
    # CLI registry — re-exported for terok integration layer
    "ArgDef": ("terok_shield.cli.registry", "ArgDef"),
    "COMMANDS": ("terok_shield.cli.registry", "COMMANDS"),
    "CommandDef": ("terok_shield.cli.registry", "CommandDef"),
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
    """Result of :meth:`Shield.check_environment`.

    Machine-readable fields for programmatic consumers (terok TUI, scripts).
    Human-readable ``issues`` and ``setup_hint`` for CLI display.

    Attributes:
        ok: True if no issues found.
        podman_version: Detected podman version tuple.
        hooks: Hook installation type (``per-container``, ``global-system``,
            ``global-user``, ``not-installed``).
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
    """Read ``_BUNDLE_VERSION`` from the installed hook entrypoint, or ``None``.

    Scans each hooks directory for the entrypoint script and extracts the
    version from the ``_BUNDLE_VERSION = N`` line.  Returns ``None`` if
    not found or unparseable.
    """
    import re

    pattern = re.compile(r"^_BUNDLE_VERSION\s*=\s*(\d+)", re.MULTILINE)
    for d in hooks_dirs:
        hook = d / "terok-shield-hook"
        if hook.is_file():
            try:
                m = pattern.search(hook.read_text())
                if m:
                    return int(m.group(1))
            except (OSError, ValueError):
                pass
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
                :class:`HubEventEmitter` pointed at the canonical socket).
                Pass a no-op stub in tests that should not touch the socket.
        """
        from . import state
        from ._hub_events import HubEventEmitter
        from .audit import AuditLogger
        from .dns.resolver import DnsResolver
        from .nft.rules import RulesetBuilder
        from .profiles import ProfileLoader
        from .run import SubprocessRunner

        self.config = config
        self.runner = runner or SubprocessRunner()
        self.audit = audit or AuditLogger(
            audit_path=state.audit_path(config.state_dir),
            enabled=config.audit_enabled,
        )
        self.dns = dns or DnsResolver(runner=self.runner)
        self.profiles = profiles or ProfileLoader(
            user_dir=config.profiles_dir or Path("/nonexistent"),
        )
        self.ruleset = ruleset or RulesetBuilder(loopback_ports=config.loopback_ports)
        self.hub_events = hub_events or HubEventEmitter()
        self._mode = self._create_mode(config.mode)

    def _create_mode(self, mode: ShieldMode):  # noqa: ANN202
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
        :class:`EnvironmentCheck` with detected issues and setup hints.
        Does not raise — the caller decides how to handle issues.
        """
        from . import state
        from .dns import dnsmasq

        output = self.runner.run(["podman", "info", "-f", "json"], check=False)
        info = parse_podman_info(output)
        issues: list[str] = []
        needs_setup = False
        setup_hint = ""
        hooks = "per-container"
        health = "ok"

        tier = detect_dns_tier(self.runner.has, lambda: dnsmasq.has_nftset_support(self.runner))
        dns_tier = tier.value
        if tier == DnsTier.DIG:
            issues.append(
                "dnsmasq not found — domain allowlisting uses static pre-start "
                "resolution (no IP rotation handling). "
                "Install dnsmasq for dynamic domain-based egress control"
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
                sys_dir = system_hooks_dir()
                hooks = "global-system" if has_global_hooks([sys_dir]) else "global-user"
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

    def down(self, container: str, *, allow_all: bool = False) -> None:
        """Switch a running container to bypass mode."""
        self._mode.shield_down(container, allow_all=allow_all)
        self.audit.log_event(
            container,
            "shield_down",
            detail="allow_all=True" if allow_all else None,
        )
        self.hub_events.shield_down(container, allow_all=allow_all)

    def block(self, container: str) -> None:
        """Total network blackout — drop all traffic, log for forensics."""
        self._mode.shield_block(container)
        self.audit.log_event(container, "shield_block")

    def up(self, container: str) -> None:
        """Restore normal deny-all mode for a running container."""
        self._mode.shield_up(container)
        self.audit.log_event(container, "shield_up")
        self.hub_events.shield_up(container)

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
        from . import state

        if profiles is None:
            profiles = list(self.config.default_profiles)
        entries = self.profiles.compose_profiles(profiles)
        if not entries:
            return []
        max_age = 0 if force else 3600
        cache_path = state.profile_allowed_path(self.config.state_dir)
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
    "AuditFileConfig",
    "AuditLogger",
    "COMMANDS",
    "CommandDef",
    "CommandRunner",
    "DigNotFoundError",
    "DnsResolver",
    "DnsTier",
    "EnvironmentCheck",
    "ExecError",
    "HOOK_ENTRYPOINT_NAME",
    "NftNotFoundError",
    "ProfileLoader",
    "RulesetBuilder",
    "Shield",
    "ShieldConfig",
    "ShieldFileConfig",
    "ShieldMode",
    "ShieldNeedsSetup",
    "ShieldState",
    "SubprocessRunner",
    "USER_HOOKS_DIR",
    "ensure_containers_conf_hooks_dir",
    "reader_script_path",
    "setup_global_hooks",
    "system_hooks_dir",
]
