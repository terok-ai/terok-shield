# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shield configuration and mode protocol.

Houses the core value types (``ShieldConfig``, ``ShieldMode``,
``ShieldState``) and the ``ShieldModeBackend`` protocol that strategy
implementations must satisfy.
"""

import enum
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

ANNOTATION_KEY = "terok.shield.profiles"
ANNOTATION_NAME_KEY = "terok.shield.name"
ANNOTATION_STATE_DIR_KEY = "terok.shield.state_dir"
ANNOTATION_LOOPBACK_PORTS_KEY = "terok.shield.loopback_ports"
ANNOTATION_VERSION_KEY = "terok.shield.version"
ANNOTATION_AUDIT_ENABLED_KEY = "terok.shield.audit_enabled"
ANNOTATION_UPSTREAM_DNS_KEY = "terok.shield.upstream_dns"
ANNOTATION_DNS_TIER_KEY = "terok.shield.dns_tier"


class DnsTier(enum.Enum):
    """DNS resolution tier for egress control.

    Determines how domain-based allowlists are enforced:

    DNSMASQ: Per-container dnsmasq with ``--nftset`` auto-populates nft
        allow sets on every DNS query.  Handles IP rotation.
    DIG: Static resolution at pre-start via ``dig`` (current fallback).
    GETENT: Single-IP resolution via ``getent hosts`` (minimal fallback).
    """

    DNSMASQ = "dnsmasq"
    DIG = "dig"
    GETENT = "getent"


def detect_dns_tier(
    has: Callable[[str], bool],
    dnsmasq_nftset_ok: Callable[[], bool] = lambda: True,
) -> DnsTier:
    """Detect the best available DNS resolution tier.

    Uses *has* to probe for executables on ``PATH``.  Shared by
    ``HookMode._detect_dns_tier`` and ``Shield.check_environment``.

    Args:
        has: Callable that returns True if the named executable exists
            (e.g. ``CommandRunner.has``).
        dnsmasq_nftset_ok: Callable that returns True if the installed
            dnsmasq supports ``--nftset``.  Defaults to ``lambda: True``
            (skip capability probe); production callers with a live runner
            should pass :func:`~terok_shield.dnsmasq.has_nftset_support`.
    """
    if has("dnsmasq") and dnsmasq_nftset_ok():
        return DnsTier.DNSMASQ
    if has("dig"):
        return DnsTier.DIG
    return DnsTier.GETENT


class ShieldMode(enum.Enum):
    """Operating mode for the shield firewall.

    Currently only HOOK is supported.  Future modes (e.g. bridge)
    will add members here.
    """

    HOOK = "hook"


class ShieldState(enum.Enum):
    """Per-container shield state, derived from the live nft ruleset.

    UP: Normal enforcing mode (deny-all).
    DOWN: Bypass mode with private-range protection (RFC 1918 + RFC 4193).
    DOWN_ALL: Bypass mode without private-range protection.
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

    def allow_domain(self, domain: str) -> None:
        """Live-allow a domain (update dnsmasq config if active)."""
        ...

    def deny_ip(self, container: str, ip: str) -> None:
        """Live-deny an IP for a running container."""
        ...

    def deny_domain(self, domain: str) -> None:
        """Live-deny a domain (remove from dnsmasq config if active)."""
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
