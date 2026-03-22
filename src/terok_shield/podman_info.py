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
# Ref: containers/podman#17935 — originally gated at (5, 6, 0) but
# podman 5.8.0 still drops per-container --hooks-dir on stop/start
# (issue #121, #122).  Set to (99, 0, 0) to effectively disable
# per-container hooks until podman reliably persists them.
HOOKS_DIR_PERSIST_VERSION = (99, 0, 0)

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

        Currently always False — podman drops per-container hooks-dir
        on stop/start even on 5.8.0 (issues #121, #122).  The version
        gate will be lowered when podman fixes this upstream.
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
    """Parse a version string like ``5.4.2`` into an int tuple.

    Extracts leading digits from each dotted component, so
    ``5.6.0-rc1`` parses as ``(5, 6, 0)`` rather than ``(5, 6)``.
    """
    parts: list[int] = []
    for part in version_str.split("."):
        digits = ""
        for ch in part:
            if ch.isdigit():
                digits += ch
            else:
                break
        if digits:
            parts.append(int(digits))
        else:
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


# ── Network detection (resolv.conf, routing table) ───────


def parse_resolv_conf(text: str) -> str:
    """Extract the first ``nameserver`` address from resolv.conf content.

    Returns an empty string if no valid nameserver line is found.
    """
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            return parts[1]
    return ""


def parse_proc_net_route(text: str) -> str:
    """Extract the default gateway IP from ``/proc/{pid}/net/route`` content.

    The gateway field is a 32-bit hex integer in host byte order.
    Returns an empty string if no default route is found.
    """
    import socket
    import struct

    for line in text.splitlines()[1:]:  # skip header
        fields = line.split()
        if len(fields) >= 3 and fields[1] == "00000000":  # default route
            try:
                gw_int = int(fields[2], 16)
                return socket.inet_ntoa(struct.pack("=I", gw_int))
            except (ValueError, struct.error):
                continue
    return ""


USER_HOOKS_DIR = Path("~/.local/share/containers/oci/hooks.d")


def system_hooks_dir() -> Path:
    """Return the best system-level hooks directory.

    Prefers existing directories; falls back to ``/etc/containers/oci/hooks.d``.
    """
    for d in _SYSTEM_HOOKS_DIRS:
        if d.is_dir():
            return d
    return _SYSTEM_HOOKS_DIRS[-1]


def global_hooks_hint() -> str:
    """Short hint telling the user to run ``terok-shield setup``."""
    return (
        "Per-container --hooks-dir does not persist on container restart\n"
        "(ref: https://github.com/containers/podman/issues/17935).\n"
        "\n"
        "Run 'terok-shield setup' to install global hooks."
    )


def ensure_containers_conf_hooks_dir(hooks_dir: Path) -> None:
    """Ensure ``~/.config/containers/containers.conf`` includes *hooks_dir*.

    Creates the file if absent.  Inserts ``hooks_dir`` into the existing
    ``[engine]`` section, or appends a new section if none exists.
    Warns (does not fail) if ``hooks_dir`` is already set differently.

    Uses line-based text manipulation to preserve comments and formatting.
    """
    conf_path = _user_containers_conf()
    hooks_str = str(hooks_dir)
    hooks_line = f'hooks_dir = ["{hooks_str}"]'

    if conf_path.is_file():
        existing = _parse_hooks_dir_from_conf(conf_path)
        if existing:
            if hooks_str in existing or str(hooks_dir.expanduser()) in existing:
                return  # already configured
            print(
                f"Warning: {conf_path} already has hooks_dir = {existing}\n"
                f"Add {hooks_str!r} to the list manually if needed."
            )
            return
        # File exists but no hooks_dir — insert into [engine] or append
        lines = conf_path.read_text().splitlines(keepends=True)
        inserted = False
        for i, line in enumerate(lines):
            # Match actual [engine] section header (not in comments)
            if line.strip() == "[engine]":
                lines.insert(i + 1, hooks_line + "\n")
                inserted = True
                break
        if inserted:
            conf_path.write_text("".join(lines))
        else:
            with conf_path.open("a") as f:
                f.write(f"\n[engine]\n{hooks_line}\n")
    else:
        conf_path.parent.mkdir(parents=True, exist_ok=True)
        conf_path.write_text(f"[engine]\n{hooks_line}\n")
