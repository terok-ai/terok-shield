# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shield configuration, constants, and path helpers."""


import enum
import os
from dataclasses import dataclass
from pathlib import Path

# ── Network constants ────────────────────────────────────
# NFT_TABLE, NFT_TABLE_NAME, RFC1918 live in nft_constants.py (single source of truth).

BRIDGE_NETWORK = "ctr-egress"
BRIDGE_SUBNET = "10.91.0.0/24"
BRIDGE_GATEWAY = "10.91.0.1"
PASTA_DNS = "169.254.1.1"

DEFAULT_GATE_PORT = 9418

ANNOTATION_KEY = "terok.shield.profiles"


class ShieldMode(enum.Enum):
    """Operating mode for the shield firewall."""

    DISABLED = "disabled"
    STANDARD = "standard"
    HARDENED = "hardened"


@dataclass(frozen=True)
class ShieldConfig:
    """Resolved shield configuration."""

    mode: ShieldMode = ShieldMode.DISABLED
    default_profiles: tuple[str, ...] = ("dev-standard",)
    gate_port: int = DEFAULT_GATE_PORT
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

    mode_str = section.get("mode", "disabled")
    try:
        mode = ShieldMode(mode_str)
    except ValueError:
        if mode_str == "auto":
            mode = _auto_detect_mode()
        else:
            mode = ShieldMode.DISABLED

    raw_profiles = section.get("default_profiles", ["dev-standard"])
    if not isinstance(raw_profiles, list):
        raw_profiles = ["dev-standard"]
    profiles = tuple(raw_profiles)

    gate_port = section.get("gate_port", DEFAULT_GATE_PORT)
    if isinstance(gate_port, bool) or not isinstance(gate_port, int) or not 1 <= gate_port <= 65535:
        gate_port = DEFAULT_GATE_PORT

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
        gate_port=gate_port,
        audit_enabled=audit_enabled,
        audit_log_allowed=audit_log_allowed,
    )


def get_shield_gate_port() -> int:
    """Return the gate server port for shield rules."""
    return load_shield_config().gate_port


def _auto_detect_mode() -> ShieldMode:
    """Auto-detect the best available shield mode.

    Checks for hardened mode prerequisites (podman bridge network + dnsmasq),
    falls back to standard mode (nft binary), or returns disabled.
    """
    import shutil
    import subprocess

    # Check for hardened mode prerequisites (bridge network)
    try:
        subprocess.run(
            ["podman", "network", "exists", BRIDGE_NETWORK],
            check=True,
            capture_output=True,
        )
        if shutil.which("dnsmasq"):
            return ShieldMode.HARDENED
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Standard mode requires OCI hook support (nft binary)
    if shutil.which("nft"):
        return ShieldMode.STANDARD

    return ShieldMode.DISABLED
