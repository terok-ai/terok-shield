# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""The top-level command registry — a forest of lazy verb roots.

[`COMMANDS`][terok_shield.commands.COMMANDS] is a
[`CommandTree`][terok_util.cli_types.CommandTree] whose every root is a
**lazy reference**: it carries only ``name`` + ``help`` (enough to render
``terok-shield --help``) and a ``source`` string resolving to the fully
populated [`CommandDef`][terok_util.cli_types.CommandDef] in the verb's
own module under [`terok_shield.verbs`][terok_shield.verbs].  Building this
registry — and wiring the top-level help listing — therefore imports none
of the handler modules;
[`CommandTree.wire`][terok_util.cli_types.CommandTree.wire] resolves only
the single verb the user actually typed, so ``terok-shield <verb>`` pulls
in that one verb's module and nothing else.

The tree is the single source of truth consumed by both the standalone CLI
([`cli.main`][terok_shield.cli.main]) and the terok integration layer.
Shield-specific flags (``needs_container``, ``standalone_only``) ride in
each resolved [`CommandDef.extras`][terok_util.cli_types.CommandDef]; the
CLI dispatcher reads them via the
[`needs_container`][terok_shield.commands.needs_container] and
[`standalone_only`][terok_shield.commands.standalone_only] helpers below.
"""
# WAYPOINT: main (cli.main)

from __future__ import annotations

from terok_util import CommandDef, CommandTree


def needs_container(cmd: CommandDef) -> bool:
    """Whether *cmd* requires a ``container`` positional arg.

    Stored in
    [`CommandDef.extras`][terok_util.cli_types.CommandDef] rather than as
    a first-class field so the registry uses the unified terok-util
    vocabulary across siblings.  Read on a **resolved** node — a lazy root
    carries no ``extras``.
    """
    return bool(cmd.extras.get("needs_container", False))


def standalone_only(cmd: CommandDef) -> bool:
    """Whether *cmd* is only available in the standalone CLI, not via terok.

    Stored in
    [`CommandDef.extras`][terok_util.cli_types.CommandDef] — see
    [`needs_container`][terok_shield.commands.needs_container].  Read on a
    **resolved** node.
    """
    return bool(cmd.extras.get("standalone_only", False))


def _lazy(name: str, help: str, source: str) -> CommandDef:  # noqa: A002 — argparse vocabulary
    """Build a lazy root referencing *source* (``"module:CONST"`` under verbs)."""
    return CommandDef(name=name, help=help, source=f"terok_shield.verbs.{source}")


# ── Command registry (lazy roots) ─────────────────────────

COMMANDS: CommandTree = CommandTree(
    (
        _lazy("status", "Show shield configuration overview", "observe:STATUS"),
        _lazy("prepare", "Prepare shield and print podman flags", "launch:PREPARE"),
        _lazy("run", "Launch a shielded container via podman", "launch:RUN"),
        _lazy("resolve", "Resolve DNS profiles and cache IPs", "launch:RESOLVE"),
        _lazy("allow", "Live-allow a domain or IP for a container", "control:ALLOW"),
        _lazy("deny", "Live-deny a domain or IP for a container", "control:DENY"),
        _lazy("down", "Switch container to the DOWN posture (accept + log)", "control:DOWN"),
        _lazy("up", "Restore deny-all mode for a container", "control:UP"),
        _lazy(
            "reset",
            "Forget DNS-learned allow state (back to authored policy seeds)",
            "control:RESET",
        ),
        _lazy(
            "quarantine",
            "Total network blackout (drop all, log dropped traffic)",
            "control:QUARANTINE",
        ),
        _lazy("rules", "Show current nft rules for a container", "control:RULES"),
        _lazy(
            "watch",
            "Stream shield events — DNS blocks, audit log, NFLOG packets (requires dnsmasq tier)",
            "stream:WATCH",
        ),
        _lazy(
            "simple-clearance",
            "Terminal clearance fallback — prompts operator for each blocked connection (no D-Bus)",
            "stream:SIMPLE_CLEARANCE",
        ),
        _lazy("logs", "Show audit log entries", "observe:LOGS"),
        _lazy("profiles", "List available shield profiles", "observe:PROFILES"),
        _lazy("setup", "Install global OCI hooks for restart persistence", "launch:SETUP"),
        _lazy(
            "check-environment",
            "Check podman environment for compatibility issues",
            "observe:CHECK_ENVIRONMENT",
        ),
        _lazy("preview", "Show ruleset that would be applied", "control:PREVIEW"),
    )
)
