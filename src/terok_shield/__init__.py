# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""terok-shield: nftables-based egress firewalling for Podman containers.

Public API for standalone use and integration with terok.

The primary entry point is the ``Shield`` facade class:

    >>> from terok_shield import Shield, ShieldConfig
    >>> shield = Shield(ShieldConfig())
    >>> shield.setup()
"""

from collections.abc import Iterator

__version__ = "0.1.3"

from .audit import AuditLogger
from .config import ShieldConfig, ShieldMode, ShieldPaths, ShieldState, load_shield_config
from .dns import DnsResolver
from .nft import RulesetBuilder
from .profiles import ProfileLoader
from .run import CommandRunner, ExecError, SubprocessRunner
from .util import is_ip as _is_ip

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
            config: Shield configuration.
            runner: Command runner (default: ``SubprocessRunner``).
            audit: Audit logger (default: from config).
            dns: DNS resolver (default: from config + runner).
            profiles: Profile loader (default: from config).
            ruleset: Ruleset builder (default: from config loopback_ports).
        """
        self.config = config
        self.runner = runner or SubprocessRunner()
        self.audit = audit or AuditLogger.from_config(config)
        self.dns = dns or DnsResolver.from_config(config, self.runner)
        self.profiles = profiles or ProfileLoader.from_config(config)
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

    def setup(self) -> None:
        """Run shield setup (install hooks)."""
        self._mode.setup()

    def status(self) -> dict:
        """Return current shield status information."""
        return {
            "mode": self.config.mode.value,
            "profiles": self.profiles.list_profiles(),
            "audit_enabled": self.config.audit_enabled,
            "log_files": self.audit.list_log_files(),
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
                allowed.append(ip)
                self.audit.log_event(container, "allowed", dest=ip, detail=f"target={target}")
            except Exception:
                pass
        return allowed

    def deny(self, container: str, target: str) -> list[str]:
        """Live-deny a domain or IP for a running container."""
        ips = [target] if _is_ip(target) else self.dns.resolve_domains([target])
        denied: list[str] = []
        for ip in ips:
            try:
                self._mode.deny_ip(container, ip)
                denied.append(ip)
                self.audit.log_event(container, "denied", dest=ip, detail=f"target={target}")
            except Exception:
                pass
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
        container: str,
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
        return self.dns.resolve_and_cache(entries, container, max_age=max_age)

    def log_files(self) -> list[str]:
        """Return container names that have audit logs."""
        return self.audit.list_log_files()

    def profiles_list(self) -> list[str]:
        """List available profile names."""
        return self.profiles.list_profiles()

    def tail_log(self, container: str, n: int = 50) -> Iterator[dict]:
        """Yield the last *n* audit events for a container."""
        return self.audit.tail_log(container, n)

    def compose_profiles(self, names: list[str]) -> list[str]:
        """Load and merge multiple profiles."""
        return self.profiles.compose_profiles(names)


__all__ = [
    "AuditLogger",
    "CommandRunner",
    "DnsResolver",
    "ExecError",
    "ProfileLoader",
    "RulesetBuilder",
    "Shield",
    "ShieldConfig",
    "ShieldMode",
    "ShieldPaths",
    "ShieldState",
    "SubprocessRunner",
    "load_shield_config",
]
