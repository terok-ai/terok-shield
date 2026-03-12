# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shield configuration, path helpers, and mode protocol.

Houses the core value types (``ShieldConfig``, ``ShieldPaths``,
``ShieldMode``, ``ShieldState``) and the ``ShieldModeBackend`` protocol
that strategy implementations must satisfy.
"""

import enum
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, Self, runtime_checkable

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


# ── ShieldPaths (Value Object) ──────────────────────────


@dataclass(frozen=True)
class ShieldPaths:
    """Immutable value object for all shield filesystem paths.

    Replaces the nine free path-helper functions with a single
    frozen dataclass whose derived paths are ``@property`` accessors.
    Constructed once from environment variables and threaded through
    the config.
    """

    state_root: Path
    config_root: Path

    @classmethod
    def from_env(cls) -> Self:
        """Build paths from environment variables / XDG defaults.

        Resolution order for each root:
        1. Explicit env var (``TEROK_SHIELD_STATE_DIR`` / ``TEROK_SHIELD_CONFIG_DIR``)
        2. XDG base dir (``XDG_STATE_HOME`` / ``XDG_CONFIG_HOME``)
        3. ``~/.local/state`` / ``~/.config`` fallback
        """
        state = _resolve_state_root()
        config = _resolve_config_root()
        return cls(state_root=state, config_root=config)

    @property
    def hooks_dir(self) -> Path:
        """OCI hooks directory."""
        return self.state_root / "hooks"

    @property
    def hook_entrypoint(self) -> Path:
        """Path to the hook entrypoint script."""
        return self.state_root / "terok-shield-hook"

    @property
    def profiles_dir(self) -> Path:
        """User profiles directory (overrides bundled)."""
        return self.config_root / "profiles"

    @property
    def logs_dir(self) -> Path:
        """Audit logs directory."""
        return self.state_root / "logs"

    @property
    def dns_dir(self) -> Path:
        """DNS allowlists directory."""
        return self.state_root / "dns"

    @property
    def resolved_dir(self) -> Path:
        """Pre-resolved IP cache directory."""
        return self.state_root / "resolved"

    def ensure_dirs(self) -> None:
        """Create all shield state and config directories."""
        for d in (
            self.state_root,
            self.hooks_dir,
            self.logs_dir,
            self.dns_dir,
            self.resolved_dir,
            self.profiles_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)


# ── ShieldConfig ─────────────────────────────────────────


@dataclass(frozen=True)
class ShieldConfig:
    """Resolved shield configuration."""

    mode: ShieldMode = ShieldMode.HOOK
    default_profiles: tuple[str, ...] = ("dev-standard",)
    loopback_ports: tuple[int, ...] = ()
    audit_enabled: bool = True
    paths: ShieldPaths = field(default_factory=ShieldPaths.from_env)


# ── ShieldModeBackend Protocol ───────────────────────────


@runtime_checkable
class ShieldModeBackend(Protocol):
    """Strategy protocol for shield mode implementations.

    Each concrete backend (e.g. ``HookMode``) provides the full
    lifecycle: setup, per-container firewalling, live allow/deny,
    bypass, and preview.
    """

    def setup(self) -> None:
        """Install mode-specific infrastructure (hooks, bridges, etc.)."""
        ...

    def pre_start(self, container: str, profiles: list[str]) -> list[str]:
        """Prepare for container start; return extra podman args."""
        ...

    def allow_ip(self, container: str, ip: str) -> None:
        """Live-allow an IP for a running container."""
        ...

    def deny_ip(self, container: str, ip: str) -> None:
        """Live-deny an IP for a running container."""
        ...

    def list_rules(self, container: str) -> str:
        """Return the current nft rules for a running container."""
        ...

    def shield_down(self, container: str, *, allow_all: bool = False) -> None:
        """Switch a container to bypass mode."""
        ...

    def shield_up(self, container: str) -> None:
        """Restore normal deny-all mode for a container."""
        ...

    def shield_state(self, container: str) -> ShieldState:
        """Query a container's shield state from the live ruleset."""
        ...

    def preview(self, *, down: bool = False, allow_all: bool = False) -> str:
        """Generate the ruleset without applying it."""
        ...


# ── Private helpers ──────────────────────────────────────


def _resolve_state_root() -> Path:
    """Resolve the state root from env / XDG / default."""
    env = os.environ.get("TEROK_SHIELD_STATE_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return base / "terok-shield"


def _resolve_config_root() -> Path:
    """Resolve the config root from env / XDG / default."""
    env = os.environ.get("TEROK_SHIELD_CONFIG_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "terok-shield"


# ── Config loading ───────────────────────────────────────


def load_shield_config() -> ShieldConfig:
    """Load shield configuration from ``config.yml``.

    Reads from ``config_root / "config.yml"``.
    Returns defaults if the file is missing or unparseable.
    """
    import yaml

    config_file = _resolve_config_root() / "config.yml"
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

    return ShieldConfig(
        mode=mode,
        default_profiles=profiles,
        loopback_ports=loopback_ports,
        audit_enabled=audit_enabled,
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
