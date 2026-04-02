# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Command registry for terok-shield.

Provides :class:`CommandDef` and :class:`ArgDef` dataclasses that describe
every shield subcommand — its arguments, handler function, and metadata.
The ``COMMANDS`` tuple is the single source of truth consumed by both the
standalone CLI and the terok integration layer.

Handler functions accept ``(shield, container?, **kwargs)`` and print to
stdout, making them reusable across different CLI frontends.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from . import EnvironmentCheck, Shield


@dataclass(frozen=True)
class ArgDef:
    """Definition of a single CLI argument for a command."""

    name: str
    help: str = ""
    type: Callable[[str], Any] | None = None
    default: Any = None
    action: str | None = None
    dest: str | None = None
    nargs: int | str | None = None


@dataclass(frozen=True)
class CommandDef:
    """Definition of a shield subcommand.

    Attributes:
        name: Subcommand name (e.g. ``"allow"``).
        help: One-line help string for ``--help``.
        handler: Callable that implements the command logic.
        needs_container: Whether the command requires a ``container`` positional arg.
        args: Extra arguments beyond the implicit ``container``.
        standalone_only: If True, only available in the standalone CLI, not via terok.
    """

    name: str
    help: str = ""
    handler: Callable[..., None] | None = None
    needs_container: bool = False
    args: tuple[ArgDef, ...] = ()
    standalone_only: bool = False


# ── Handler functions ─────────────────────────────────────


def _format_version(v: tuple[int, ...]) -> str:
    """Format a version tuple as a dotted string."""
    return ".".join(str(p) for p in v) if v != (0,) else "unknown"


def _print_env_hint(env: EnvironmentCheck) -> None:
    """Print human-readable environment issues and setup hint."""
    if env.issues:
        print()
        for issue in env.issues:
            print(f"  {issue}")
    if env.setup_hint:
        print()
        print(env.setup_hint)


def _handle_status(shield: Shield, *, container: str | None = None) -> None:
    """Show shield status, or query a container's firewall state."""
    if container:
        st = shield.state(container)
        print(st.value)
    else:
        from importlib.metadata import PackageNotFoundError, version as _meta_version

        try:
            shield_version = _meta_version("terok-shield")
        except PackageNotFoundError:
            shield_version = "dev"
        status = shield.status()
        env = shield.check_environment()
        print(f"Version:  {shield_version}")
        print(f"Podman:   {_format_version(env.podman_version)}")
        print(f"Mode:     {status['mode']}")
        print(f"Hooks:    {env.hooks}")
        print(f"Health:   {env.health}")
        print(f"Audit:    {'enabled' if status['audit_enabled'] else 'disabled'}")
        print(f"Profiles: {', '.join(status['profiles']) or '(none)'}")
        _print_env_hint(env)


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


def _handle_down(shield: Shield, container: str, *, allow_all: bool = False) -> None:
    """Switch container to bypass mode."""
    shield.down(container, allow_all=allow_all)
    label = " (all traffic)" if allow_all else ""
    print(f"Shield down for {container}{label}")


def _handle_up(shield: Shield, container: str) -> None:
    """Restore deny-all mode."""
    shield.up(container)
    print(f"Shield up for {container}")


def _handle_rules(shield: Shield, container: str) -> None:
    """Show nft rules for a container."""
    st = shield.state(container)
    print(f"State: {st.value}")
    rules = shield.rules(container)
    if rules.strip():
        print(rules)
    else:
        print(f"No rules found for {container}")


def _handle_logs(shield: Shield, container: str, *, n: int = 50) -> None:
    """Show per-container audit log entries."""
    for entry in shield.tail_log(n):
        print(json.dumps(entry))


def _handle_profiles(shield: Shield) -> None:
    """List available shield profiles."""
    for name in shield.profiles_list():
        print(name)


def _handle_check_environment(shield: Shield) -> None:
    """Check podman environment for compatibility issues."""
    result = shield.check_environment()
    # Machine-readable block
    print(f"podman_version={_format_version(result.podman_version)}")
    print(f"hooks={result.hooks}")
    print(f"health={result.health}")
    # Human-readable details (shared with status)
    _print_env_hint(result)


def _handle_watch(shield: Shield, container: str) -> None:
    """Stream blocked-access events as JSON lines."""
    from .watch import run_watch

    run_watch(shield.config.state_dir, container)


def _handle_preview(shield: Shield, *, down: bool = False, allow_all: bool = False) -> None:
    """Show ruleset that would be applied."""
    if allow_all and not down:
        raise ValueError("--all requires --down")
    ruleset = shield.preview(down=down, allow_all=allow_all)
    label = "bypass" if down else "enforce"
    if allow_all:
        label += " (all traffic)"
    print(f"# Ruleset preview ({label}):")
    print(ruleset)


# ── Command definitions ───────────────────────────────────

COMMANDS: tuple[CommandDef, ...] = (
    CommandDef(
        name="status",
        help="Show shield configuration overview",
        handler=_handle_status,
        args=(
            ArgDef(
                name="container",
                nargs="?",
                help="Container name — prints firewall state (up/down/down_all/inactive/error)",
            ),
        ),
    ),
    CommandDef(
        name="prepare",
        help="Prepare shield and print podman flags",
        needs_container=True,
        standalone_only=True,
        args=(
            ArgDef(name="--profiles", nargs="+", help="Override default profiles"),
            ArgDef(name="--json", action="store_true", dest="output_json", help="JSON output"),
        ),
    ),
    CommandDef(
        name="run",
        help="Launch a shielded container via podman",
        needs_container=True,
        standalone_only=True,
        args=(ArgDef(name="--profiles", nargs="+", help="Override default profiles"),),
    ),
    CommandDef(
        name="resolve",
        help="Resolve DNS profiles and cache IPs",
        needs_container=True,
        standalone_only=True,
        args=(ArgDef(name="--force", action="store_true", help="Bypass cache freshness"),),
    ),
    CommandDef(
        name="allow",
        help="Live-allow a domain or IP for a container",
        handler=_handle_allow,
        needs_container=True,
        args=(ArgDef(name="target", help="Domain name or IP address to allow"),),
    ),
    CommandDef(
        name="deny",
        help="Live-deny a domain or IP for a container",
        handler=_handle_deny,
        needs_container=True,
        args=(ArgDef(name="target", help="Domain name or IP address to deny"),),
    ),
    CommandDef(
        name="down",
        help="Switch container to bypass mode (accept-all + log)",
        handler=_handle_down,
        needs_container=True,
        args=(
            ArgDef(
                name="--all",
                action="store_true",
                dest="allow_all",
                help="Also allow private-range traffic",
            ),
        ),
    ),
    CommandDef(
        name="up",
        help="Restore deny-all mode for a container",
        handler=_handle_up,
        needs_container=True,
    ),
    CommandDef(
        name="rules",
        help="Show current nft rules for a container",
        handler=_handle_rules,
        needs_container=True,
    ),
    CommandDef(
        name="watch",
        help="Stream shield events — DNS blocks, audit log, NFLOG packets (requires dnsmasq tier)",
        handler=_handle_watch,
        needs_container=True,
    ),
    # NOTE: CLI special-cases logs with --container optional for aggregated mode.
    # The terok integration layer always has a per-container Shield, so the
    # handler receives container and tails that container's audit log.
    CommandDef(
        name="logs",
        help="Show audit log entries",
        handler=_handle_logs,
        needs_container=True,
        args=(ArgDef(name="-n", type=int, default=50, help="Number of recent entries"),),
    ),
    CommandDef(
        name="profiles",
        help="List available shield profiles",
        handler=_handle_profiles,
    ),
    CommandDef(
        name="setup",
        help="Install global OCI hooks for restart persistence",
        standalone_only=True,
        args=(
            ArgDef(name="--root", action="store_true", help="Install system-wide (uses sudo)"),
            ArgDef(name="--user", action="store_true", help="Install to user directory"),
        ),
    ),
    CommandDef(
        name="check-environment",
        help="Check podman environment for compatibility issues",
        handler=_handle_check_environment,
    ),
    CommandDef(
        name="preview",
        help="Show ruleset that would be applied",
        handler=_handle_preview,
        args=(
            ArgDef(name="--down", action="store_true", help="Show bypass ruleset"),
            ArgDef(
                name="--all",
                action="store_true",
                dest="allow_all",
                help="Omit private-range reject rules (requires --down)",
            ),
        ),
    ),
)
