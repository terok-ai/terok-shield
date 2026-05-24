# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Podman environment detection.

Grouped into three submodules so each concern stands on its own:

- [`info`][terok_shield.podman_info.info] — version + capability parsing.
- [`hooks_dir`][terok_shield.podman_info.hooks_dir] — global hook directory
  discovery via ``containers.conf``.
- [`network`][terok_shield.podman_info.network] — slirp4netns CIDR/gateway
  and ``resolv.conf`` parsing.

Public names are re-exported here for convenience; new code is welcome
to import from the specific submodule when intent is clearer.
"""

from .hooks_dir import (
    HOOK_JSON_FILENAME,
    USER_HOOKS_DIR,
    find_hooks_dirs,
    global_hooks_hint,
    has_global_hooks,
    system_hooks_dir,
)
from .info import HOOKS_DIR_PERSIST_VERSION, PodmanInfo, parse_podman_info
from .network import parse_resolv_conf, parse_slirp4netns_cidr, slirp4netns_gateway

__all__ = [
    "HOOKS_DIR_PERSIST_VERSION",
    "HOOK_JSON_FILENAME",
    "PodmanInfo",
    "USER_HOOKS_DIR",
    "find_hooks_dirs",
    "global_hooks_hint",
    "has_global_hooks",
    "parse_podman_info",
    "parse_resolv_conf",
    "parse_slirp4netns_cidr",
    "slirp4netns_gateway",
    "system_hooks_dir",
]
