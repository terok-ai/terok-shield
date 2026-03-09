# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""terok-shield: nftables-based egress firewalling for Podman containers.

Public API for standalone use and integration with terok.
"""

__version__ = "0.1.0"

from .audit import list_log_files, log_event, tail_log
from .config import ShieldConfig, ShieldMode, load_shield_config
from .dns import resolve_and_cache
from .profiles import compose_profiles, list_profiles
from .run import ExecError, dig
from .util import is_ipv4 as _is_ip


def _load_config(config: ShieldConfig | None) -> ShieldConfig:
    """Return the given config or load the default."""
    return config if config is not None else load_shield_config()


def _mode_module(mode: ShieldMode):  # noqa: ANN202 – returns module
    """Return the backend module for the given mode."""
    if mode == ShieldMode.BRIDGE:
        from . import mode_bridge

        return mode_bridge

    from . import mode_hook

    return mode_hook


def shield_setup(*, config: ShieldConfig | None = None) -> None:
    """Run shield setup (install hook or verify bridge).

    Dispatches to hook or bridge setup based on ``config.mode``.

    Args:
        config: Shield configuration (loads default if None).
    """
    cfg = _load_config(config)
    if cfg.mode == ShieldMode.BRIDGE:
        from . import mode_bridge

        mode_bridge.setup(cfg)
    else:
        from . import mode_hook

        mode_hook.setup(cfg)


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

    if cfg.mode == ShieldMode.BRIDGE:
        from . import mode_bridge

        result = mode_bridge.pre_start(cfg, container, profiles)
    else:
        from . import mode_hook

        result = mode_hook.pre_start(cfg, container, profiles)

    if cfg.audit_enabled:
        log_event(container, "setup", detail=f"profiles={','.join(profiles)}")
    return result


def shield_post_start(
    container: str,
    profiles: list[str] | None = None,
    *,
    config: ShieldConfig | None = None,
) -> None:
    """Post-start hook.  Only needed for bridge mode.

    Args:
        container: Container name.
        profiles: Profile names (defaults to config.default_profiles).
        config: Shield configuration (loads default if None).
    """
    cfg = _load_config(config)
    if cfg.mode != ShieldMode.BRIDGE:
        return

    if profiles is None:
        profiles = list(cfg.default_profiles)

    from . import mode_bridge

    mode_bridge.post_start(cfg, container, profiles)
    if cfg.audit_enabled:
        log_event(container, "setup", detail="bridge post_start complete")


def shield_pre_stop(
    container: str,
    *,
    config: ShieldConfig | None = None,
) -> None:
    """Pre-stop hook.  Only needed for bridge mode.

    Args:
        container: Container name.
        config: Shield configuration (loads default if None).
    """
    cfg = _load_config(config)
    if cfg.mode != ShieldMode.BRIDGE:
        return

    from . import mode_bridge

    mode_bridge.pre_stop(container)
    if cfg.audit_enabled:
        log_event(container, "teardown")


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
        target: Domain name or IPv4 address/CIDR.
        config: Shield configuration (loads default if None).

    Returns:
        List of IPs that were allowed.
    """
    cfg = _load_config(config)
    ips = [target] if _is_ip(target) else dig(target)
    mod = _mode_module(cfg.mode)
    allowed: list[str] = []

    for ip in ips:
        try:
            mod.allow_ip(container, ip)
            allowed.append(ip)
            if cfg.audit_enabled:
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
        target: Domain name or IPv4 address/CIDR.
        config: Shield configuration (loads default if None).

    Returns:
        List of IPs that were denied.
    """
    cfg = _load_config(config)
    ips = [target] if _is_ip(target) else dig(target)
    mod = _mode_module(cfg.mode)
    denied: list[str] = []

    for ip in ips:
        try:
            mod.deny_ip(container, ip)
            denied.append(ip)
            if cfg.audit_enabled:
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
    "ExecError",
    "ShieldConfig",
    "ShieldMode",
    "list_log_files",
    "list_profiles",
    "load_shield_config",
    "log_event",
    "shield_allow",
    "shield_deny",
    "shield_post_start",
    "shield_pre_start",
    "shield_pre_stop",
    "shield_resolve",
    "shield_rules",
    "shield_setup",
    "shield_status",
    "tail_log",
]
