# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Podman environment detection.

Parses ``podman info -f json`` output and ``containers.conf`` to detect
podman capabilities, version, and hooks directory configuration.

This module is stateless — callers cache the result.
"""

from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

# Well-known system hooks directories (containers-common standard).
# Used as fallback when containers.conf doesn't specify hooks_dir.
_SYSTEM_HOOKS_DIRS = (
    Path("/usr/share/containers/oci/hooks.d"),
    Path("/etc/containers/oci/hooks.d"),
)

# containers.conf search paths (system defaults, then system overrides).
# User-level config is resolved dynamically via XDG.
_SYSTEM_CONF_PATHS = (
    Path("/usr/share/containers/containers.conf"),
    Path("/etc/containers/containers.conf"),
)

# Minimum podman version where --hooks-dir persists on restart.
# Ref: containers/podman#17935, fixed in PR #26127, released in v5.6.0.
HOOKS_DIR_PERSIST_VERSION = (5, 6, 0)

# Hook JSON filename used to detect terok-shield global hooks.
HOOK_JSON_FILENAME = "terok-shield-createRuntime.json"


@dataclass(frozen=True)
class PodmanInfo:
    """Parsed podman environment information.

    Constructed from ``podman info -f json`` output.  Stateless — the
    caller manages caching.
    """

    version: tuple[int, ...]
    rootless_network_cmd: str
    pasta_executable: str
    slirp4netns_executable: str

    @property
    def hooks_dir_persists(self) -> bool:
        """Return True if ``--hooks-dir`` survives container restart.

        False for podman < 5.6.0 due to containers/podman#17935.
        """
        return self.version >= HOOKS_DIR_PERSIST_VERSION

    @property
    def network_mode(self) -> str:
        """Determine the rootless network mode.

        Uses ``rootlessNetworkCmd`` when available (podman 5+).
        When absent (podman 4.x), defaults to slirp4netns if its
        executable is available — podman 4.x defaults to slirp4netns.
        """
        if self.rootless_network_cmd in ("pasta", "slirp4netns"):
            return self.rootless_network_cmd
        # Field absent → podman 4.x → default is slirp4netns
        if self.slirp4netns_executable:
            return "slirp4netns"
        return "pasta"


def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse a version string like ``5.4.2`` into an int tuple."""
    parts: list[int] = []
    for part in version_str.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            break
    return tuple(parts) if parts else (0,)


def parse_podman_info(json_str: str) -> PodmanInfo:
    """Parse ``podman info -f json`` output into a :class:`PodmanInfo`.

    Returns a zero-version fallback on invalid input.
    """
    try:
        info = json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return PodmanInfo(
            version=(0,),
            rootless_network_cmd="",
            pasta_executable="",
            slirp4netns_executable="",
        )

    host = info.get("host", {}) if isinstance(info, dict) else {}
    version_section = info.get("version", {}) if isinstance(info, dict) else {}

    return PodmanInfo(
        version=_parse_version(version_section.get("Version", "0")),
        rootless_network_cmd=host.get("rootlessNetworkCmd", ""),
        pasta_executable=host.get("pasta", {}).get("executable", ""),
        slirp4netns_executable=host.get("slirp4netns", {}).get("executable", ""),
    )


# ── containers.conf hooks_dir detection ───────────────────


def _user_containers_conf() -> Path:
    """Return the user-level ``containers.conf`` path (XDG)."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "containers" / "containers.conf"


def _parse_hooks_dir_from_conf(path: Path) -> list[str]:
    """Extract ``hooks_dir`` list from a ``containers.conf`` TOML file.

    Returns an empty list if the file is missing, unreadable, or does
    not contain ``[engine] hooks_dir``.
    """
    if not path.is_file():
        return []
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return []
    hooks = data.get("engine", {}).get("hooks_dir", [])
    if isinstance(hooks, list):
        return [str(h) for h in hooks if isinstance(h, str) and h]
    if isinstance(hooks, str) and hooks:
        return [hooks]
    return []


def find_hooks_dirs() -> list[Path]:
    """Find hooks directories podman would check.

    Reads ``containers.conf`` (user config overrides system config).
    Falls back to well-known system defaults if nothing is configured.

    Returns directories in precedence order (last wins for podman).
    """
    # User config takes precedence over system config
    user_dirs = _parse_hooks_dir_from_conf(_user_containers_conf())
    if user_dirs:
        return [Path(d).expanduser() for d in user_dirs]

    # System configs (checked in order, last found wins)
    for conf_path in reversed(_SYSTEM_CONF_PATHS):
        dirs = _parse_hooks_dir_from_conf(conf_path)
        if dirs:
            return [Path(d).expanduser() for d in dirs]

    # No config → well-known system defaults (only existing ones)
    return [d for d in _SYSTEM_HOOKS_DIRS if d.is_dir()]


def has_global_hooks(hooks_dirs: list[Path] | None = None) -> bool:
    """Check if terok-shield hooks are installed in any global hooks dir.

    Args:
        hooks_dirs: Directories to check (default: auto-detect via
            :func:`find_hooks_dirs`).
    """
    if hooks_dirs is None:
        hooks_dirs = find_hooks_dirs()
    return any((d / HOOK_JSON_FILENAME).is_file() for d in hooks_dirs)


# ── resolv.conf parsing ───────────────────────────────


def parse_resolv_conf(text: str) -> str:
    """Extract the first ``nameserver`` address from resolv.conf content.

    Returns an empty string if no valid nameserver line is found.
    """
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
    return ""


_USER_HOOKS_DIR = "~/.local/share/containers/oci/hooks.d"

_HOOK_FILES = ("terok-shield-createRuntime.json", "terok-shield-poststop.json")


def global_hooks_hint(
    state_dir: Path | None = None,
    hooks_dirs: list[Path] | None = None,
) -> str:
    """Generate a human-readable hint for setting up global hooks.

    When *state_dir* is provided, includes concrete ``cp`` commands
    using the hook files that ``install_hooks()`` already wrote there.

    Args:
        state_dir: Per-container state directory (source of hook files).
        hooks_dirs: Override auto-detected hooks directories.
    """
    if hooks_dirs is None:
        hooks_dirs = find_hooks_dirs()

    lines = [
        "Podman < 5.6.0: --hooks-dir does not persist on container restart",
        "(ref: https://github.com/containers/podman/issues/17935).",
        "",
        "To ensure hooks survive restart, install them in a global hooks directory.",
    ]

    # Locate source files
    hooks_subdir = f"{state_dir}/hooks" if state_dir else "<state_dir>/hooks"
    entrypoint = f"{state_dir}/terok-shield-hook" if state_dir else "<state_dir>/terok-shield-hook"
    cp_files = " ".join(f"{hooks_subdir}/{f}" for f in _HOOK_FILES)

    # Detect system dirs
    system_dirs = [d for d in _SYSTEM_HOOKS_DIRS if d.is_dir()]
    system_dir = system_dirs[0] if system_dirs else _SYSTEM_HOOKS_DIRS[-1]

    # Always show both options so the user can choose
    lines.append("")
    lines.append(f"Hook source files: {hooks_subdir}/")
    lines.append(f"Entrypoint script: {entrypoint}")
    lines.append("")

    # Option 1: system-wide (sudo)
    lines.append("Option 1 — system-wide (needs sudo):")
    lines.append(f"  sudo mkdir -p {system_dir}")
    lines.append(f"  sudo cp {cp_files} {system_dir}/")
    lines.append(f"  sudo cp {entrypoint} {system_dir}/")
    # Fix the entrypoint path in the copied JSONs
    lines.append(f"  sudo sed -i 's|{entrypoint}|{system_dir}/terok-shield-hook|'")
    lines.append(f"    {' '.join(f'{system_dir}/{f}' for f in _HOOK_FILES)}")

    # Option 2: user-local (no root)
    user_dir = _USER_HOOKS_DIR
    lines.append("")
    lines.append("Option 2 — user-local (no root):")
    lines.append(f"  mkdir -p {user_dir}")
    lines.append(f"  cp {cp_files} {user_dir}/")
    lines.append(f"  cp {entrypoint} {user_dir}/")
    lines.append(f"  sed -i 's|{entrypoint}|{user_dir}/terok-shield-hook|'")
    lines.append(f"    {' '.join(f'{user_dir}/{f}' for f in _HOOK_FILES)}")
    lines.append("")
    lines.append("  Then ensure podman checks this directory — add to")
    lines.append("  ~/.config/containers/containers.conf:")
    lines.append("    [engine]")
    lines.append(f'    hooks_dir = ["{user_dir}"]')

    return "\n".join(lines)
