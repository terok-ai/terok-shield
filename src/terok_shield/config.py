# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shield configuration, constants, and path helpers."""

import enum
import os
from dataclasses import dataclass
from pathlib import Path

from .nft_constants import (
    PASTA_DNS as PASTA_DNS,  # noqa: F401
)

ANNOTATION_KEY = "terok.shield.profiles"
ANNOTATION_NAME_KEY = "terok.shield.name"


class ShieldMode(enum.Enum):
    """Operating mode for the shield firewall.

    Currently only HOOK is supported.  Future modes (e.g. bridge)
    will add members here.
    """

    HOOK = "hook"


class ShieldState(enum.Enum):
    """Per-container shield state, derived from the live nft ruleset.

    UP: Normal enforcing mode (deny-all).
    DOWN: Bypass mode with RFC1918 protection.
    DOWN_ALL: Bypass mode without RFC1918 protection.
    INACTIVE: No ruleset found (container stopped or unshielded).
    ERROR: Ruleset present but unrecognised.
    """

    UP = "up"
    DOWN = "down"
    DOWN_ALL = "down_all"
    INACTIVE = "inactive"
    ERROR = "error"


@dataclass(frozen=True)
class ShieldConfig:
    """Resolved shield configuration."""

    mode: ShieldMode = ShieldMode.HOOK
    default_profiles: tuple[str, ...] = ("dev-standard",)
    loopback_ports: tuple[int, ...] = ()
    audit_enabled: bool = True
    audit_log_allowed: bool = True


# ── Path helpers ─────────────────────────────────────────


def shield_state_root() -> Path:
    """Return the shield state root directory.

    Resolution order:
    1. ``TEROK_SHIELD_STATE_DIR`` (explicit override)
    2. ``XDG_STATE_HOME / "terok-shield"``
    3. ``~/.local/state/terok-shield`` (XDG default)
    """
    env = os.environ.get("TEROK_SHIELD_STATE_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return base / "terok-shield"


def shield_config_root() -> Path:
    """Return the shield config root directory.

    Resolution order:
    1. ``TEROK_SHIELD_CONFIG_DIR`` (explicit override)
    2. ``XDG_CONFIG_HOME / "terok-shield"``
    3. ``~/.config/terok-shield`` (XDG default)
    """
    env = os.environ.get("TEROK_SHIELD_CONFIG_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "terok-shield"


def shield_hooks_dir() -> Path:
    """Return the OCI hooks directory."""
    return shield_state_root() / "hooks"


def shield_hook_entrypoint() -> Path:
    """Return the path to the hook entrypoint script."""
    return shield_state_root() / "terok-shield-hook"


def shield_profiles_dir() -> Path:
    """Return the user profiles directory (overrides bundled)."""
    return shield_config_root() / "profiles"


def shield_logs_dir() -> Path:
    """Return the audit logs directory."""
    return shield_state_root() / "logs"


def shield_dns_dir() -> Path:
    """Return the DNS allowlists directory."""
    return shield_state_root() / "dns"


def shield_resolved_dir() -> Path:
    """Return the directory for pre-resolved IP files."""
    return shield_state_root() / "resolved"


def ensure_shield_dirs() -> None:
    """Create all shield state and config directories."""
    for d in (
        shield_state_root(),
        shield_hooks_dir(),
        shield_logs_dir(),
        shield_dns_dir(),
        shield_resolved_dir(),
        shield_profiles_dir(),
    ):
        d.mkdir(parents=True, exist_ok=True)


# ── Config loading ───────────────────────────────────────


def load_shield_config() -> ShieldConfig:
    """Load shield configuration from ``config.yml``.

    Reads from ``shield_config_root() / "config.yml"``.
    Returns defaults if the file is missing or unparseable.
    """
    import yaml

    config_file = shield_config_root() / "config.yml"
    if not config_file.is_file():
        return ShieldConfig()

    try:
        section = yaml.safe_load(config_file.read_text()) or {}
    except (OSError, yaml.YAMLError):
        return ShieldConfig()

    if not isinstance(section, dict):
        return ShieldConfig()

    mode_str = section.get("mode", "auto")
    if mode_str == "auto":
        mode = _auto_detect_mode()
    elif mode_str == "hook":
        mode = ShieldMode.HOOK
    else:
        raise ValueError(f"Unknown shield mode: {mode_str!r}")

    raw_profiles = section.get("default_profiles", ["dev-standard"])
    if not isinstance(raw_profiles, list):
        raw_profiles = ["dev-standard"]
    profiles = tuple(raw_profiles)

    loopback_ports = _parse_loopback_ports(section.get("loopback_ports", []))

    audit = section.get("audit", {})
    if not isinstance(audit, dict):
        audit = {}

    audit_enabled = audit.get("enabled", True)
    if not isinstance(audit_enabled, bool):
        audit_enabled = True
    audit_log_allowed = audit.get("log_allowed", True)
    if not isinstance(audit_log_allowed, bool):
        audit_log_allowed = True

    return ShieldConfig(
        mode=mode,
        default_profiles=profiles,
        loopback_ports=loopback_ports,
        audit_enabled=audit_enabled,
        audit_log_allowed=audit_log_allowed,
    )


def _parse_loopback_ports(raw: object) -> tuple[int, ...]:
    """Parse and validate loopback_ports from config YAML.

    Accepts a list of ints or a single int.  Invalid entries are silently
    dropped.
    """
    if isinstance(raw, bool):
        return ()
    if isinstance(raw, int):
        raw = [raw]
    if not isinstance(raw, list):
        return ()
    ports: list[int] = []
    for v in raw:
        if isinstance(v, bool) or not isinstance(v, int):
            continue
        if 1 <= v <= 65535:
            ports.append(v)
    return tuple(ports)


def _auto_detect_mode() -> ShieldMode:
    """Auto-detect the best available shield mode.

    Currently only hook mode is supported.  Future modes (e.g. bridge)
    will add detection logic here.

    Raises:
        RuntimeError: If no supported shield mode is available.
    """
    import shutil

    if shutil.which("nft"):
        return ShieldMode.HOOK

    raise RuntimeError("No supported shield mode available. Install nft for hook mode.")
