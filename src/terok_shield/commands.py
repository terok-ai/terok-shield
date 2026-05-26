# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Every subcommand terok-shield exposes — arguments, handler, and help text.

The ``COMMANDS`` tuple is the single source of truth consumed by both the
standalone CLI and the terok integration layer.  Handler functions accept
``(shield, container?, **kwargs)`` and print to stdout, making them
reusable across different CLI frontends.

``CommandDef`` and ``ArgDef`` are re-exported from
[`terok_util`][terok_util] — the unified vocabulary every sibling
package shares.  Shield-specific flags (``needs_container``,
``standalone_only``) ride along in
[`CommandDef.extras`][terok_util.cli_types.CommandDef.extras]; the
shield CLI dispatcher reads them via the
[`needs_container`][terok_shield.commands.needs_container] and
[`standalone_only`][terok_shield.commands.standalone_only] helpers
defined below.
"""
# WAYPOINT: main (cli.main)

import json
from typing import Any

from terok_util import ArgDef, CommandDef

from . import EnvironmentCheck, Shield


def _csv_list(value: str) -> list[str]:
    """Split a comma-separated CLI value into a list, stripping whitespace.

    Used as ``ArgDef.type`` for multi-value optional flags so they don't
    rely on argparse's greedy ``nargs="+"`` (which silently slurps the
    following positional, turning ``--profiles a b mycontainer`` into
    ``profiles=["a","b","mycontainer"]``).  Comma-separated single-value
    matches podman's convention (``--cap-add=A,B,C``).
    """
    return [p.strip() for p in value.split(",") if p.strip()]


def needs_container(cmd: CommandDef) -> bool:
    """Whether *cmd* requires a ``container`` positional arg.

    Stored in
    [`CommandDef.extras`][terok_util.cli_types.CommandDef.extras]
    rather than as a first-class field so the registry uses the
    unified terok-util vocabulary across siblings.
    """
    return bool(cmd.extras.get("needs_container", False))


def standalone_only(cmd: CommandDef) -> bool:
    """Whether *cmd* is only available in the standalone CLI, not via terok.

    Stored in
    [`CommandDef.extras`][terok_util.cli_types.CommandDef.extras] —
    see [`needs_container`][terok_shield.commands.needs_container].
    """
    return bool(cmd.extras.get("standalone_only", False))


# ── Handler functions (ordered to match COMMANDS) ────────


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


def _handle_down(
    shield: Shield,
    container: str,
    *,
    container_id: str,
    allow_all: bool = False,
) -> None:
    """Switch container to bypass mode.

    *container_id* — full podman UUID; supplied by the orchestrator at
    the call site, used to route the hub event to the supervisor's
    per-container socket.  Required, no default.
    """
    shield.down(container, container_id, allow_all=allow_all)
    label = " (all traffic)" if allow_all else ""
    print(f"Shield down for {container}{label}")


def _handle_up(shield: Shield, container: str, *, container_id: str) -> None:
    """Restore deny-all mode.

    *container_id* — see ``_handle_down``.
    """
    shield.up(container, container_id)
    print(f"Shield up for {container}")


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


def _handle_watch(shield: Shield, container: str) -> None:
    """Stream blocked-access events as JSON lines."""
    from .watch import run_watch

    run_watch(shield.config.state_dir, container)


def _handle_simple_clearance(shield: Shield, container: str) -> None:
    """Run the terminal clearance fallback for hosts without the D-Bus hub."""
    from .simple_clearance import run_simple_clearance

    run_simple_clearance(shield.config.state_dir, container)


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
    print(f"podman_version={_format_version(result.podman_version)}")
    print(f"hooks={result.hooks}")
    print(f"health={result.health}")
    _print_env_hint(result)


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


# Shield-specific extras keys (read by [`needs_container`][terok_shield.commands.needs_container]
# / [`standalone_only`][terok_shield.commands.standalone_only]).
_NEEDS_CTR: dict[str, Any] = {"needs_container": True}
_STANDALONE: dict[str, Any] = {"standalone_only": True}
_NEEDS_CTR_STANDALONE: dict[str, Any] = {"needs_container": True, "standalone_only": True}


# ``--container-id`` is the per-container hub socket routing key
# (full podman UUID).  Every emit-bearing verb (``up`` / ``down``)
# accepts it as a required option — the caller (terok-sandbox) knows
# the full UUID at every site that runs ``terok-shield <verb>``.
_CONTAINER_ID_ARG = ArgDef(
    name="--container-id",
    required=True,
    help="Full podman container UUID — routes hub events to the per-container supervisor socket",
)


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
                help="Container name — prints firewall state (up/down/disengaged/offline/error)",
            ),
        ),
    ),
    CommandDef(
        name="prepare",
        help="Prepare shield and print podman flags",
        extras=_NEEDS_CTR_STANDALONE,
        args=(
            ArgDef(
                name="--profiles",
                type=_csv_list,
                help="Override default profiles (comma-separated, e.g. 'dev,pypi')",
            ),
            ArgDef(name="--json", action="store_true", dest="output_json", help="JSON output"),
        ),
    ),
    CommandDef(
        name="run",
        help="Launch a shielded container via podman",
        extras=_NEEDS_CTR_STANDALONE,
        args=(
            ArgDef(
                name="--profiles",
                type=_csv_list,
                help="Override default profiles (comma-separated, e.g. 'dev,pypi')",
            ),
        ),
    ),
    CommandDef(
        name="resolve",
        help="Resolve DNS profiles and cache IPs",
        extras=_NEEDS_CTR_STANDALONE,
        args=(ArgDef(name="--force", action="store_true", help="Bypass cache freshness"),),
    ),
    CommandDef(
        name="allow",
        help="Live-allow a domain or IP for a container",
        handler=_handle_allow,
        extras=_NEEDS_CTR,
        args=(ArgDef(name="target", help="Domain name or IP address to allow"),),
    ),
    CommandDef(
        name="deny",
        help="Live-deny a domain or IP for a container",
        handler=_handle_deny,
        extras=_NEEDS_CTR,
        args=(ArgDef(name="target", help="Domain name or IP address to deny"),),
    ),
    CommandDef(
        name="down",
        help="Switch container to bypass mode (accept-all + log)",
        handler=_handle_down,
        extras=_NEEDS_CTR,
        args=(
            _CONTAINER_ID_ARG,
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
        extras=_NEEDS_CTR,
        args=(_CONTAINER_ID_ARG,),
    ),
    CommandDef(
        name="quarantine",
        help="Total network blackout (drop all, log dropped traffic)",
        handler=_handle_quarantine,
        extras=_NEEDS_CTR,
    ),
    CommandDef(
        name="rules",
        help="Show current nft rules for a container",
        handler=_handle_rules,
        extras=_NEEDS_CTR,
    ),
    CommandDef(
        name="watch",
        help="Stream shield events — DNS blocks, audit log, NFLOG packets (requires dnsmasq tier)",
        handler=_handle_watch,
        extras=_NEEDS_CTR,
    ),
    CommandDef(
        name="simple-clearance",
        help="Terminal clearance fallback — prompts operator for each blocked connection (no D-Bus)",
        handler=_handle_simple_clearance,
        extras=_NEEDS_CTR,
    ),
    # NOTE: CLI special-cases logs with --container optional for aggregated mode.
    # The terok integration layer always has a per-container Shield, so the
    # handler receives container and tails that container's audit log.
    CommandDef(
        name="logs",
        help="Show audit log entries",
        handler=_handle_logs,
        extras=_NEEDS_CTR,
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
        extras=_STANDALONE,
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
