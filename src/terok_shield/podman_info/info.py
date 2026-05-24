# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Podman version and capability detection.

Parses ``podman info -f json`` into a structured
[`PodmanInfo`][terok_shield.podman_info.info.PodmanInfo] dataclass, with
just enough metadata for shield to choose a network mode and decide
whether per-container ``--hooks-dir`` will survive a restart.

This module is stateless — callers cache the result.
"""

import json
from dataclasses import dataclass

# Minimum podman version where --hooks-dir persists on restart.
# WORKAROUND(hooks-dir-persist): podman drops per-container --hooks-dir
# on stop/start even on 5.8.0 (containers/podman#17935, #121, #122).
# Originally gated at (5, 6, 0), set to (99, 0, 0) to effectively
# disable per-container hooks until podman reliably persists them.
# When lowered, per-container hooks become the default and global
# hook installation is no longer required.
HOOKS_DIR_PERSIST_VERSION = (99, 0, 0)


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


def parse_podman_info(json_str: str) -> PodmanInfo:
    """Parse ``podman info -f json`` output into a [`PodmanInfo`][terok_shield.podman_info.info.PodmanInfo].

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
