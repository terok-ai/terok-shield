# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Live nft-mutation verbs — allow, deny, up, down, quarantine, rules, preview.

Each verb mutates or inspects a running container's shield ruleset.  The
handlers accept ``(shield, [container], **kwargs)`` and print to stdout;
the CLI dispatcher builds the [`Shield`][terok_shield.Shield] and forwards
the parsed argv.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from terok_util import ArgDef, CommandDef

from ._common import CONTAINER_ARG, CONTAINER_ID_ARG, NEEDS_CTR

if TYPE_CHECKING:
    from terok_shield import Shield


def _handle_allow(shield: Shield, container: str, *, target: str) -> None:
    """Live-allow a domain or IP."""
    ips = shield.allow(container, target)
    if ips:
        print(f"Allowed {target} -> {', '.join(ips)} for {container}")
    else:
        raise RuntimeError(f"No IPs allowed for {container}")


def _handle_deny(shield: Shield, container: str, *, target: str) -> None:
    """Live-deny a domain or IP."""
    ips = shield.deny(container, target)
    if ips:
        print(f"Denied {target} ({', '.join(ips)}) for {container}")
    else:
        raise RuntimeError(f"No IPs denied for {container}")


def _handle_down(
    shield: Shield,
    container: str,
    *,
    container_id: str,
    disengaged: bool = False,
) -> None:
    """Switch container to the DOWN posture.

    *container_id* — full podman UUID; supplied by the orchestrator at
    the call site, used to route the hub event to the supervisor's
    per-container socket.  Required, no default.
    """
    shield.down(container, container_id, disengaged=disengaged)
    label = " (disengaged)" if disengaged else ""
    print(f"Shield down for {container}{label}")


def _handle_up(shield: Shield, container: str, *, container_id: str) -> None:
    """Restore deny-all mode.

    *container_id* — see ``_handle_down``.
    """
    shield.up(container, container_id)
    print(f"Shield up for {container}")


def _handle_reset(shield: Shield, container: str) -> None:
    """Forget DNS-learned allow state."""
    shield.reset(container)
    print(f"Shield reset for {container} — learned allow state forgotten")


def _handle_quarantine(shield: Shield, container: str) -> None:
    """Total network blackout."""
    shield.quarantine(container)
    print(f"Shield QUARANTINED for {container} — all traffic dropped")


def _handle_rules(shield: Shield, container: str) -> None:
    """Show nft rules for a container."""
    st = shield.state(container)
    print(f"State: {st.value}")
    rules = shield.rules(container)
    if rules.strip():
        print(rules)
    else:
        print(f"No rules found for {container}")


def _handle_preview(shield: Shield, *, down: bool = False, disengaged: bool = False) -> None:
    """Show ruleset that would be applied."""
    if disengaged and not down:
        raise ValueError("--disengage requires --down")
    ruleset = shield.preview(down=down, disengaged=disengaged)
    label = ("disengaged" if disengaged else "down") if down else "up"
    print(f"# Ruleset preview ({label}):")
    print(ruleset)


ALLOW = CommandDef(
    name="allow",
    help="Live-allow a domain or IP for a container",
    handler=_handle_allow,
    extras=NEEDS_CTR,
    args=(CONTAINER_ARG, ArgDef(name="target", help="Domain name or IP address to allow")),
)

DENY = CommandDef(
    name="deny",
    help="Live-deny a domain or IP for a container",
    handler=_handle_deny,
    extras=NEEDS_CTR,
    args=(CONTAINER_ARG, ArgDef(name="target", help="Domain name or IP address to deny")),
)

DOWN = CommandDef(
    name="down",
    help="Switch container to the DOWN posture (accept + log; private ranges still rejected)",
    handler=_handle_down,
    extras=NEEDS_CTR,
    args=(
        CONTAINER_ARG,
        CONTAINER_ID_ARG,
        ArgDef(
            name="--disengage",
            action="store_true",
            dest="disengaged",
            help="Enforce nothing — lift the deny set and every range reject (DISENGAGED posture)",
        ),
    ),
)

UP = CommandDef(
    name="up",
    help="Restore deny-all mode for a container",
    handler=_handle_up,
    extras=NEEDS_CTR,
    args=(CONTAINER_ARG, CONTAINER_ID_ARG),
)

RESET = CommandDef(
    name="reset",
    help="Forget DNS-learned allow state (back to authored policy seeds)",
    handler=_handle_reset,
    extras=NEEDS_CTR,
    args=(CONTAINER_ARG,),
)

QUARANTINE = CommandDef(
    name="quarantine",
    help="Total network blackout (drop all, log dropped traffic)",
    handler=_handle_quarantine,
    extras=NEEDS_CTR,
    args=(CONTAINER_ARG,),
)

RULES = CommandDef(
    name="rules",
    help="Show current nft rules for a container",
    handler=_handle_rules,
    extras=NEEDS_CTR,
    args=(CONTAINER_ARG,),
)

PREVIEW = CommandDef(
    name="preview",
    help="Show ruleset that would be applied",
    handler=_handle_preview,
    args=(
        ArgDef(name="--down", action="store_true", help="Show the DOWN-posture ruleset"),
        ArgDef(
            name="--disengage",
            action="store_true",
            dest="disengaged",
            help="Show the DISENGAGED ruleset: no deny set, no range rejects (requires --down)",
        ),
    ),
)
