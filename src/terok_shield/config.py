# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shield configuration and mode protocol.

Houses the core value types (``ShieldConfig``, ``ShieldMode``,
``ShieldState``) and the ``ShieldModeBackend`` protocol that strategy
implementations must satisfy.
"""

import enum
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

ANNOTATION_KEY = "terok.shield.profiles"
ANNOTATION_NAME_KEY = "terok.shield.name"
ANNOTATION_STATE_DIR_KEY = "terok.shield.state_dir"
ANNOTATION_LOOPBACK_PORTS_KEY = "terok.shield.loopback_ports"
ANNOTATION_VERSION_KEY = "terok.shield.version"


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


# -- ShieldConfig -----------------------------------------


@dataclass(frozen=True)
class ShieldConfig:
    """Per-container shield configuration.

    The library is a pure function of its inputs.  Given a
    ``ShieldConfig`` with ``state_dir``, it writes to that directory
    and nowhere else.  No env-var reading, no config-file parsing.
    """

    state_dir: Path
    mode: ShieldMode = ShieldMode.HOOK
    default_profiles: tuple[str, ...] = ("dev-standard",)
    loopback_ports: tuple[int, ...] = ()
    audit_enabled: bool = True
    profiles_dir: Path | None = None


# -- ShieldModeBackend Protocol ---------------------------


@runtime_checkable
class ShieldModeBackend(Protocol):
    """Strategy protocol for shield mode implementations.

    Each concrete backend (e.g. ``HookMode``) provides the full
    lifecycle: per-container firewalling, live allow/deny, bypass,
    and preview.
    """

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
