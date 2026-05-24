# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Rootless networking helpers.

The slirp4netns gateway and ``resolv.conf`` parsing live here so
nothing in the firewall path has to reach into the broader podman_info
package just to derive a host address or DNS server.
"""

import ipaddress
import os
import tomllib
from pathlib import Path

from ..nft.constants import SLIRP4NETNS_CIDR as _DEFAULT_SLIRP4NETNS_CIDR
from ._conf import _SYSTEM_CONF_PATHS, _user_containers_conf


def slirp4netns_gateway(cidr: str | None = None) -> str:
    """Compute the slirp4netns gateway address (``CIDR base + 2``).

    Reads ``containers.conf`` for a ``cidr=`` override when *cidr* is None.
    Falls back to the default CIDR on malformed input.
    """
    try:
        net = ipaddress.IPv4Network(cidr or parse_slirp4netns_cidr())
    except ValueError:
        net = ipaddress.IPv4Network(_DEFAULT_SLIRP4NETNS_CIDR)
    return str(net.network_address + 2)


def parse_slirp4netns_cidr() -> str:
    """Read the slirp4netns CIDR from ``containers.conf``, or return the default.

    User config (XDG) is checked first in rootless mode, then system paths.
    When running as root, user config is skipped to prevent untrusted
    ``XDG_CONFIG_HOME`` from influencing firewall rules.
    """
    paths = list(reversed(_SYSTEM_CONF_PATHS))
    if os.geteuid() != 0:
        paths.insert(0, _user_containers_conf())
    for path in paths:
        for opt in _parse_network_cmd_options(path):
            if opt.startswith("cidr="):
                return opt.split("=", 1)[1]
    return _DEFAULT_SLIRP4NETNS_CIDR


def _parse_network_cmd_options(path: Path) -> list[str]:
    """Extract ``[engine] network_cmd_options`` from a ``containers.conf``."""
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
    opts = engine.get("network_cmd_options", [])
    return [o for o in opts if isinstance(o, str) and o] if isinstance(opts, list) else []


def parse_resolv_conf(text: str) -> str:
    """Extract the first ``nameserver`` address from resolv.conf content.

    Returns an empty string if no valid nameserver line is found.
    """
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            return parts[1]
    return ""
