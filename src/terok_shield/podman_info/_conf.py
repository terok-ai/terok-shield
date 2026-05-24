# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared ``containers.conf`` location resolution.

Both [`hooks_dir`][terok_shield.podman_info.hooks_dir] and
[`network`][terok_shield.podman_info.network] read fields from podman's
``containers.conf`` files; this module owns the system + user search paths
so each consumer parses its own key from the same well-defined set of files.
"""

import os
from pathlib import Path

# containers.conf search paths (system defaults, then system overrides).
# User-level config is resolved dynamically via XDG.
_SYSTEM_CONF_PATHS = (
    Path("/usr/share/containers/containers.conf"),
    Path("/etc/containers/containers.conf"),
)


def _user_containers_conf() -> Path:
    """Return the user-level ``containers.conf`` path (XDG)."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "containers" / "containers.conf"
