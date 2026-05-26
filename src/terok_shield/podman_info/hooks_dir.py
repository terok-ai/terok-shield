# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""OCI hooks directory discovery.

Reads ``containers.conf`` to figure out where podman would look for
global hook descriptors, and reports whether shield's own hook is
installed in any of them.
"""

import tomllib
from pathlib import Path

from ._conf import _SYSTEM_CONF_PATHS, _user_containers_conf

# Hook JSON filename used to detect terok-shield global hooks.
HOOK_JSON_FILENAME = "terok-shield-createRuntime.json"


def find_hooks_dirs() -> list[Path]:
    """Find hooks directories podman would check.

    Reads ``containers.conf`` (user config overrides system config).
    Returns the configured directories in precedence order (last wins
    for podman).  Empty when no ``hooks_dir`` entry is configured —
    terok always patches ``containers.conf`` at setup time, so an
    empty result implies setup has not run.
    """
    user_dirs = _parse_hooks_dir_from_conf(_user_containers_conf())
    if user_dirs:
        return [Path(d).expanduser() for d in user_dirs]

    for conf_path in reversed(_SYSTEM_CONF_PATHS):
        dirs = _parse_hooks_dir_from_conf(conf_path)
        if dirs:
            return [Path(d).expanduser() for d in dirs]

    return []


def has_global_hooks(hooks_dirs: list[Path] | None = None) -> bool:
    """Check if terok-shield hooks are installed in any global hooks dir.

    Args:
        hooks_dirs: Directories to check (default: auto-detect via
            [`find_hooks_dirs`][terok_shield.podman_info.hooks_dir.find_hooks_dirs]).
    """
    if hooks_dirs is None:
        hooks_dirs = find_hooks_dirs()
    return any((d / HOOK_JSON_FILENAME).is_file() for d in hooks_dirs)


def global_hooks_hint() -> str:
    """Short hint telling the user to run ``terok-shield setup``."""
    return (
        "Per-container --hooks-dir does not persist on container restart\n"
        "(ref: https://github.com/containers/podman/issues/17935).\n"
        "\n"
        "Run 'terok-shield setup' to install global hooks."
    )


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
    engine = data.get("engine")
    if not isinstance(engine, dict):
        return []
    hooks = engine.get("hooks_dir", [])
    if isinstance(hooks, list):
        return [str(h) for h in hooks if isinstance(h, str) and h]
    if isinstance(hooks, str) and hooks:
        return [hooks]
    return []
