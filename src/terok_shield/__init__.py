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

from .audit import AuditLogger, configure_audit, list_log_files, log_event, tail_log
from .config import ShieldConfig, ShieldMode, ShieldPaths, ShieldState, load_shield_config
from .dns import DnsResolver, resolve_and_cache
from .nft import RulesetBuilder
from .profiles import ProfileLoader, compose_profiles, list_profiles
from .run import CommandRunner, ExecError, SubprocessRunner, dig_all
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


# ── Legacy free-function API (backwards compat) ──────────


def _load_config(config: ShieldConfig | None) -> ShieldConfig:
    """Return the given config or load the default.

    Also configures the audit module so that ``log_event`` calls
    throughout the call chain respect ``audit_enabled`` regardless
    of whether the config was supplied by an API consumer or loaded
    from disk.
    """
    cfg = config if config is not None else load_shield_config()
    configure_audit(enabled=cfg.audit_enabled)
    return cfg


def _mode_module(mode: ShieldMode):  # noqa: ANN202 – returns module
    """Return the backend module for the given mode.

    Currently only hook mode is supported.  Future modes will add
    branches here.
    """
    if mode == ShieldMode.HOOK:
        from . import mode_hook

        return mode_hook

    raise ValueError(f"Unsupported shield mode: {mode!r}")


def shield_setup(*, config: ShieldConfig | None = None) -> None:
    """Run shield setup (install hook).

    Dispatches to the appropriate mode setup based on ``config.mode``.

    Args:
        config: Shield configuration (loads default if None).
    """
    cfg = _load_config(config)
    _mode_module(cfg.mode).setup(cfg)


def shield_status(*, config: ShieldConfig | None = None) -> dict:
    """Return current shield status information.

    Args:
        config: Shield configuration (loads default if None).

    Returns:
        Dict with mode, profiles, audit_enabled, and log_files.
    """
    cfg = _load_config(config)
    return {
        "mode": cfg.mode.value,
        "profiles": list_profiles(),
        "audit_enabled": cfg.audit_enabled,
        "log_files": list_log_files(),
    }


def shield_pre_start(
    container: str,
    profiles: list[str] | None = None,
    *,
    config: ShieldConfig | None = None,
) -> list[str]:
    """Prepare shield for container start.

    Returns extra podman args (including network args).

    Args:
        container: Container name.
        profiles: Profile names (defaults to config.default_profiles).
        config: Shield configuration (loads default if None).

    Returns:
        Extra arguments for ``podman run``.
    """
    cfg = _load_config(config)
    if profiles is None:
        profiles = list(cfg.default_profiles)

    result = _mode_module(cfg.mode).pre_start(cfg, container, profiles)

    log_event(container, "setup", detail=f"profiles={','.join(profiles)}")
    return result


def shield_allow(
    container: str,
    target: str,
    *,
    config: ShieldConfig | None = None,
) -> list[str]:
    """Live-allow a domain or IP for a running container.

    If *target* is a domain, resolves it first.

    Args:
        container: Container name or ID.
        target: Domain name or IP address/CIDR.
        config: Shield configuration (loads default if None).

    Returns:
        List of IPs that were allowed.
    """
    cfg = _load_config(config)
    ips = [target] if _is_ip(target) else dig_all(target)
    mod = _mode_module(cfg.mode)
    allowed: list[str] = []

    for ip in ips:
        try:
            mod.allow_ip(container, ip)
            allowed.append(ip)
            log_event(container, "allowed", dest=ip, detail=f"target={target}")
        except Exception:
            pass

    return allowed


def shield_deny(
    container: str,
    target: str,
    *,
    config: ShieldConfig | None = None,
) -> list[str]:
    """Live-deny a domain or IP for a running container.

    If *target* is a domain, resolves it first.  Failures to remove
    individual IPs are silently ignored (best-effort).

    Args:
        container: Container name or ID.
        target: Domain name or IP address/CIDR.
        config: Shield configuration (loads default if None).

    Returns:
        List of IPs that were denied.
    """
    cfg = _load_config(config)
    ips = [target] if _is_ip(target) else dig_all(target)
    mod = _mode_module(cfg.mode)
    denied: list[str] = []

    for ip in ips:
        try:
            mod.deny_ip(container, ip)
            denied.append(ip)
            log_event(container, "denied", dest=ip, detail=f"target={target}")
        except Exception:
            pass

    return denied


def shield_rules(
    container: str,
    *,
    config: ShieldConfig | None = None,
) -> str:
    """Return current nft rules for a container.

    Args:
        container: Container name or ID.
        config: Shield configuration (loads default if None).

    Returns:
        The nft ruleset/set output.
    """
    cfg = _load_config(config)
    return _mode_module(cfg.mode).list_rules(container)


def shield_down(
    container: str,
    *,
    allow_all: bool = False,
    config: ShieldConfig | None = None,
) -> None:
    """Switch a running container to bypass mode (accept-all + log).

    Atomically replaces the nft ruleset.  RFC1918 reject rules are kept
    unless *allow_all* is True.

    Args:
        container: Container name or ID.
        allow_all: If True, also allow RFC1918/link-local traffic.
        config: Shield configuration (loads default if None).
    """
    cfg = _load_config(config)
    mod = _mode_module(cfg.mode)
    mod.shield_down(cfg, container, allow_all=allow_all)

    log_event(container, "shield_down", detail="allow_all=True" if allow_all else None)


def shield_up(
    container: str,
    *,
    config: ShieldConfig | None = None,
) -> None:
    """Restore normal deny-all mode for a running container.

    Atomically replaces the nft ruleset and re-adds cached resolved IPs.

    Args:
        container: Container name or ID.
        config: Shield configuration (loads default if None).
    """
    cfg = _load_config(config)
    mod = _mode_module(cfg.mode)
    mod.shield_up(cfg, container)

    log_event(container, "shield_up")


def shield_state(
    container: str,
    *,
    config: ShieldConfig | None = None,
) -> ShieldState:
    """Query the live nft ruleset to determine a container's shield state.

    Args:
        container: Container name or ID.
        config: Shield configuration (loads default if None).

    Returns:
        The current ShieldState for the container.
    """
    cfg = _load_config(config)
    return _mode_module(cfg.mode).shield_state(container)


def shield_preview(
    *,
    down: bool = False,
    allow_all: bool = False,
    config: ShieldConfig | None = None,
) -> str:
    """Generate the ruleset that would be applied to a container.

    Returns the nft ruleset text without applying it -- no running
    container required.

    Args:
        down: If True, generate the bypass ruleset.
        allow_all: If True (with *down*), omit RFC1918 reject rules.
        config: Shield configuration (loads default if None).

    Returns:
        The nft ruleset text.
    """
    cfg = _load_config(config)
    return _mode_module(cfg.mode).preview(cfg, down=down, allow_all=allow_all)


def shield_resolve(
    container: str,
    profiles: list[str] | None = None,
    *,
    config: ShieldConfig | None = None,
    force: bool = False,
) -> list[str]:
    """Resolve DNS profiles and cache the results.

    Args:
        container: Container name (cache key).
        profiles: Profile names (defaults to config.default_profiles).
        config: Shield configuration (loads default if None).
        force: If True, bypass cache freshness and re-resolve.

    Returns:
        List of resolved IPs + raw IPs/CIDRs.
    """
    cfg = _load_config(config)
    if profiles is None:
        profiles = list(cfg.default_profiles)

    entries = compose_profiles(profiles)
    if not entries:
        return []

    max_age = 0 if force else 3600
    return resolve_and_cache(entries, container, max_age=max_age)


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
    "configure_audit",
    "list_log_files",
    "list_profiles",
    "load_shield_config",
    "log_event",
    "shield_allow",
    "shield_deny",
    "shield_down",
    "shield_pre_start",
    "shield_preview",
    "shield_resolve",
    "shield_rules",
    "shield_setup",
    "shield_state",
    "shield_status",
    "shield_up",
    "tail_log",
]
