# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""terok-shield: nftables-based egress firewalling for Podman containers.

Public API for standalone use and integration with terok.

The primary entry point is the ``Shield`` facade class:

    >>> from terok_shield import Shield, ShieldConfig
    >>> shield = Shield(ShieldConfig(state_dir=Path("/tmp/my-container")))
    >>> shield.pre_start("my-container", ["dev-standard"])
"""

from collections.abc import Iterator
from pathlib import Path

__version__: str = "0.0.0"  # placeholder; replaced at build time

from importlib.metadata import PackageNotFoundError, version as _meta_version

try:
    __version__ = _meta_version("terok-shield")
except PackageNotFoundError:
    pass  # editable install or running from source without metadata

from dataclasses import dataclass, field

from . import state
from .audit import AuditLogger
from .config import ShieldConfig, ShieldMode, ShieldState
from .dns import DnsResolver
from .mode_hook import setup_global_hooks
from .nft import RulesetBuilder
from .podman_info import (
    USER_HOOKS_DIR,
    ensure_containers_conf_hooks_dir,
    find_hooks_dirs,
    global_hooks_hint,
    has_global_hooks,
    parse_podman_info,
    system_hooks_dir,
)
from .profiles import ProfileLoader
from .run import (
    CommandRunner,
    DigNotFoundError,
    ExecError,
    NftNotFoundError,
    ShieldNeedsSetup,
    SubprocessRunner,
)
from .util import is_ip as _is_ip


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
        issues: List of human-readable issue descriptions.
        needs_setup: True if one-time setup is required.
        setup_hint: Setup instructions (empty if not needed).
    """

    ok: bool = True
    podman_version: tuple[int, ...] = (0,)
    hooks: str = "per-container"
    health: str = "ok"
    issues: list[str] = field(default_factory=list)
    needs_setup: bool = False
    setup_hint: str = ""


# ── Shield Facade ────────────────────────────────────────


class Shield:
    """Facade: primary public API for terok-shield.

    Owns and wires together all service objects (audit, DNS, profiles,
    ruleset builder, mode backend).  Construct once with a
    ``ShieldConfig`` and call methods for the full shield lifecycle.

    All collaborators are injectable for testing.
    """

    def __init__(
        self,
        config: ShieldConfig,
        *,
        runner: CommandRunner | None = None,
        audit: AuditLogger | None = None,
        dns: DnsResolver | None = None,
        profiles: ProfileLoader | None = None,
        ruleset: RulesetBuilder | None = None,
    ) -> None:
        """Create the shield facade.

        Args:
            config: Shield configuration (must include state_dir).
            runner: Command runner (default: ``SubprocessRunner``).
            audit: Audit logger (default: from config.state_dir).
            dns: DNS resolver (default: from runner).
            profiles: Profile loader (default: from config.profiles_dir).
            ruleset: Ruleset builder (default: from config loopback_ports).
        """
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
        self._mode = self._create_mode(config.mode)

    def _create_mode(self, mode: ShieldMode):  # noqa: ANN202
        """Create the mode backend for the given mode."""
        if mode == ShieldMode.HOOK:
            from .mode_hook import HookMode

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
        output = self.runner.run(["podman", "info", "-f", "json"], check=False)
        info = parse_podman_info(output)
        issues: list[str] = []
        needs_setup = False
        setup_hint = ""
        hooks = "per-container"
        health = "ok"

        if not self.runner.has("dig"):
            issues.append(
                "dig not found — DNS resolution will fail. "
                "Install: dnsutils (Debian/Ubuntu) or bind-utils (Fedora/RHEL)"
            )

        hooks_dirs = find_hooks_dirs()
        global_hooks = has_global_hooks(hooks_dirs)

        if not info.hooks_dir_persists:
            if global_hooks:
                sys_dir = system_hooks_dir()
                hooks = "global-system" if has_global_hooks([sys_dir]) else "global-user"
                health = "ok"
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
        ips = [target] if _is_ip(target) else self.dns.resolve_domains([target])
        allowed: list[str] = []
        for ip in ips:
            try:
                self._mode.allow_ip(container, ip)
            except (ExecError, OSError):
                continue
            allowed.append(ip)
            self.audit.log_event(container, "allowed", dest=ip, detail=f"target={target}")
        return allowed

    def deny(self, container: str, target: str) -> list[str]:
        """Live-deny a domain or IP for a running container."""
        ips = [target] if _is_ip(target) else self.dns.resolve_domains([target])
        denied: list[str] = []
        for ip in ips:
            try:
                self._mode.deny_ip(container, ip)
            except (ExecError, OSError):
                continue
            denied.append(ip)
            self.audit.log_event(container, "denied", dest=ip, detail=f"target={target}")
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

    def up(self, container: str) -> None:
        """Restore normal deny-all mode for a running container."""
        self._mode.shield_up(container)
        self.audit.log_event(container, "shield_up")

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


from .registry import COMMANDS, ArgDef, CommandDef  # noqa: E402

__all__ = [
    "ArgDef",
    "AuditLogger",
    "COMMANDS",
    "CommandDef",
    "CommandRunner",
    "DigNotFoundError",
    "DnsResolver",
    "EnvironmentCheck",
    "ExecError",
    "NftNotFoundError",
    "ProfileLoader",
    "RulesetBuilder",
    "Shield",
    "ShieldConfig",
    "ShieldMode",
    "ShieldNeedsSetup",
    "ShieldState",
    "SubprocessRunner",
    "USER_HOOKS_DIR",
    "ensure_containers_conf_hooks_dir",
    "setup_global_hooks",
    "system_hooks_dir",
]
