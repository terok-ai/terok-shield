# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shield configuration types, enums, and mode protocol.

Defines the vocabulary shared across the entire codebase: what a shield
configuration looks like, what modes and states exist, and what contract
a mode backend must satisfy.
"""

from __future__ import annotations

import enum
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

# ── OCI annotation keys ─────────────────────────────────

# Delimiter for list-valued annotations (profiles).
# Podman ≤4.9.x registers --annotation as StringSliceVar (pflag), which
# splits values on commas.  Fixed in 5.0.0 (containers/podman#20945).
# Colons are safe across all versions.
ANNOTATION_LIST_SEP = ":"

ANNOTATION_KEY = "terok.shield.profiles"
ANNOTATION_NAME_KEY = "terok.shield.name"
ANNOTATION_STATE_DIR_KEY = "terok.shield.state_dir"
ANNOTATION_VERSION_KEY = "terok.shield.version"
ANNOTATION_AUDIT_ENABLED_KEY = "terok.shield.audit_enabled"
ANNOTATION_UPSTREAM_DNS_KEY = "terok.shield.upstream_dns"
ANNOTATION_DNS_TIER_KEY = "terok.shield.dns_tier"


# ── DNS tier ────────────────────────────────────────────


class DnsTier(enum.Enum):
    """How domain allowlists reach the nft allow sets.

    DNSMASQ_LIVE: dnsmasq with ``--nftset`` adds every answered address to the
        allow sets before the reply reaches the workload.  Follows IP rotation,
        covers subdomains, accepts wildcard entries, names blocked domains.
    DNSMASQ_STATIC: a dnsmasq built without nftset support.  The allow sets are
        resolved once at launch; the query log still names blocked domains.
    LOOKUP: no dnsmasq.  The allow sets are resolved once at launch with
        ``dig`` or ``drill``.
    GETENT: no dnsmasq and no lookup tool.  The allow sets are resolved once
        at launch with ``getent hosts``.
    """

    DNSMASQ_LIVE = "dnsmasq-live"
    DNSMASQ_STATIC = "dnsmasq-static"
    LOOKUP = "lookup"
    GETENT = "getent"

    @property
    def live(self) -> bool:
        """True when the allow sets follow DNS answers as they arrive."""
        return self is DnsTier.DNSMASQ_LIVE

    @property
    def runs_dnsmasq(self) -> bool:
        """True when a per-container dnsmasq serves the container's DNS."""
        return self in (DnsTier.DNSMASQ_LIVE, DnsTier.DNSMASQ_STATIC)

    @property
    def hint(self) -> str:
        """What a degraded tier lacks and what restores the live one; empty for the live tier."""
        return _TIER_HINTS.get(self, "")

    @classmethod
    def parse(cls, recorded: str) -> DnsTier | None:
        """The tier a recorded name means; ``None`` for a name that is not a tier.

        A retired name reads as the tier it named, so a container recorded under
        it restarts instead of being recreated.
        """
        try:
            return cls(_RETIRED_TIER_NAMES.get(recorded, recorded))
        except ValueError:
            return None


_TIER_HINTS = {
    DnsTier.DNSMASQ_STATIC: (
        "This dnsmasq has no nftset support, so allow sets are fixed at launch. "
        "A dnsmasq built with nftset support restores live resolution."
    ),
    DnsTier.LOOKUP: (
        "No dnsmasq: allow sets are fixed at launch and blocked connections show "
        "IP addresses only. Install dnsmasq with nftset support for live resolution."
    ),
    DnsTier.GETENT: (
        "No dnsmasq and no dig: allow sets are fixed at launch through getent and "
        "blocked connections show IP addresses only. "
        "Install dnsmasq with nftset support for live resolution."
    ),
}
"""The operator-facing line for each degraded tier."""

_RETIRED_TIER_NAMES = {"dig": "lookup", "dnsmasq": "dnsmasq-live"}
"""Recorded tier names that a rename retired, mapped to the current name."""

WILDCARDS_NEED_LIVE_TIER = (
    "Wildcard entries need live DNS resolution, and this host runs the {tier} tier: {names}. "
    "Use an allowlist without wildcard entries, or install dnsmasq with nftset support."
)
"""Launch refusal for a ``*.`` entry on a tier that resolves names once."""


def detect_dns_tier(
    has: Callable[[str], bool], *, dnsmasq_usable: bool = False, nftset: bool = False
) -> DnsTier:
    """The best tier the host supports.

    Args:
        has: Says whether a named tool exists on the host (``dig``, ``drill``).
        dnsmasq_usable: A dnsmasq binary was found and can read its config
            from the state directory.
        nftset: That dnsmasq is built with nftset support.
    """
    if dnsmasq_usable:
        return DnsTier.DNSMASQ_LIVE if nftset else DnsTier.DNSMASQ_STATIC
    if has("dig") or has("drill"):
        return DnsTier.LOOKUP
    return DnsTier.GETENT


# ── Shield mode and state ───────────────────────────────


class ShieldMode(enum.Enum):
    """Operating mode for the shield firewall.

    Currently only HOOK is supported.  Future modes (e.g. bridge)
    will add members here.
    """

    HOOK = "hook"


class ShieldState(enum.Enum):
    """Per-container shield state, derived from the live nft ruleset.

    QUARANTINE: Total network blackout — all traffic dropped, dropped traffic logged.
    UP: Normal enforcing mode (deny-all with allowlists).
    DOWN: Accept-by-default posture, private-range protection retained (RFC 1918 + RFC 4193).
    DISENGAGED: Accept-everything posture — no deny set, no private-range or hard-deny reject.
    OFFLINE: No ruleset found (container stopped or unshielded).
    ERROR: Ruleset present but unrecognised.
    """

    QUARANTINE = "quarantine"
    UP = "up"
    DOWN = "down"
    DISENGAGED = "disengaged"
    OFFLINE = "offline"
    ERROR = "error"


# ── ShieldRuntime ───────────────────────────────────────


class ShieldRuntime(enum.Enum):
    """Container runtime category — drives DNS-reachability assumptions.

    DEFAULT: crun / runc / youki.  The container shares the netns,
        so dnsmasq on ``127.0.0.1`` is reachable directly.
    KRUN: libkrun microVM.  The guest has its own loopback isolated
        from the netns, so dnsmasq must bind to a link-local address
        on netns ``lo`` that the guest can reach via passt.
    """

    DEFAULT = "default"
    KRUN = "krun"

    @classmethod
    def from_runtime_name(cls, name: str | None) -> ShieldRuntime:
        """Map a podman ``--runtime <name>`` string (or ``None``) to the enum.

        Centralises the wire-format vocabulary so callers don't repeat
        ``"krun" → KRUN`` mappings inline.  Anything other than
        ``"krun"`` (including ``None`` and unknown runtime names) maps
        to ``DEFAULT`` — the loopback-shared-with-netns assumption holds
        for every runtime shield has been tested against besides krun.
        """
        return cls.KRUN if name == "krun" else cls.DEFAULT


# ── ShieldConfig ────────────────────────────────────────


@dataclass(frozen=True)
class ShieldConfig:
    """Per-container shield configuration.

    The library is a pure function of its inputs.  Given a
    ``ShieldConfig`` with ``state_dir``, it writes to that directory
    and nowhere else.  No env-var reading, no config-file parsing.
    """

    state_dir: Path
    mode: ShieldMode = ShieldMode.HOOK
    default_profiles: tuple[str, ...] = ()
    """Profiles to compose when a call's *profiles* argument is ``None``; empty composes no profile."""
    loopback_ports: tuple[int, ...] = ()
    audit_enabled: bool = True
    profiles_dir: Path | None = None
    runtime: ShieldRuntime = ShieldRuntime.DEFAULT
    dns_cache_dir: Path | None = None
    """Resolved-allowlist cache shared across containers.

    The one deliberate exception to the state_dir-only rule: many tasks with the
    same allowlist share one resolve.  ``None`` selects
    [`dns_cache_dir`][terok_shield.paths.dns_cache_dir] under the shield state
    root.  Only the tiers that resolve at launch use it.
    """
    dnsmasq_path: Path | None = None
    """The dnsmasq binary to run; ``None`` finds one on PATH or in the sbin directories.

    Set it for a dnsmasq built outside the distro package, for example one
    built with nftset support in the operator's home.
    """


# ── ShieldModeBackend protocol ──────────────────────────


@runtime_checkable
class ShieldModeBackend(Protocol):
    """Strategy protocol for shield mode implementations.

    Each concrete backend (e.g. ``HookMode``) provides the full
    lifecycle: per-container firewalling, live allow/deny, posture
    transitions, and preview.
    """

    def pre_start(
        self,
        container: str,
        profiles: list[str],
        *,
        security_deny: Sequence[str] = (),
        provider_allow: Sequence[str] = (),
        project_allow: Sequence[str] = (),
        override: Sequence[str] = (),
    ) -> list[str]:
        """Prepare for container start; return extra podman args.

        *security_deny* / *provider_allow* / *project_allow* / *override* are the
        caller-generated t20 / t30 / t40 / t10 tiers
        (see [`Shield.pre_start`][terok_shield.Shield.pre_start]).
        """
        ...

    def refresh(
        self,
        container: str,
        profiles: list[str],
        *,
        security_deny: Sequence[str] = (),
        provider_allow: Sequence[str] = (),
        project_allow: Sequence[str] = (),
        override: Sequence[str] = (),
    ) -> None:
        """Recompute an existing container's policy bundle before a plain restart.

        Same tier data as
        [`pre_start`][terok_shield.config.ShieldModeBackend.pre_start], no
        launch half — rewrites tiers, caches, and pre-applied artifacts only.
        """
        ...

    def resolve(self, *, force: bool = False) -> list[str]:
        """Re-resolve the authored policy into its static-resolution caches.

        Rewrites no tier; *force* re-resolves even when a cache is fresh.
        """
        ...

    def allow_ip(self, container: str, ip: str) -> None:
        """Live-allow an IP for a running container."""
        ...

    def allow_domain(self, container: str, domain: str) -> None:
        """Live-allow a domain (reload dnsmasq if active)."""
        ...

    def deny_ip(self, container: str, ip: str) -> None:
        """Live-deny an IP for a running container."""
        ...

    def deny_domain(self, container: str, domain: str) -> None:
        """Live-deny a domain (reload dnsmasq if active)."""
        ...

    def list_rules(self, container: str) -> str:
        """Return the current nft rules for a running container."""
        ...

    def shield_down(self, container: str, *, disengaged: bool = False) -> None:
        """Switch a container to the DOWN posture."""
        ...

    def shield_quarantine(self, container: str) -> None:
        """Total network blackout — drop all traffic."""
        ...

    def shield_up(self, container: str) -> None:
        """Restore normal deny-all mode for a container."""
        ...

    def shield_reset(self, container: str) -> None:
        """Forget learned allow-set state, keeping the authored policy seeds."""
        ...

    def shield_state(self, container: str) -> ShieldState:
        """Query a container's shield state from the live ruleset."""
        ...

    def preview(self, *, down: bool = False, disengaged: bool = False) -> str:
        """Generate the ruleset without applying it."""
        ...
