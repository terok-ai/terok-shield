# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Read-only query verbs — status, check-environment, profiles, logs.

These verbs inspect shield state without mutating any ruleset.  ``status``
takes an optional container (bare = config overview, with = live firewall
state); ``logs`` supports an optional ``--container`` filter and is
dispatched by the CLI's own aggregated-mode handler
([`_cmd_logs_cli`][terok_shield.cli.main]).
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import TYPE_CHECKING

from terok_util import ArgDef, CommandDef

from ._common import CONTAINER_ARG, NEEDS_CTR, format_version, print_env_hint

if TYPE_CHECKING:
    from terok_shield import Shield


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
        print(f"Version:            {shield_version}")
        print(f"Podman:             {format_version(env.podman_version)}")
        print(f"Mode:               {status['mode']}")
        print(f"Hooks:              {env.hooks}")
        print(f"Health:             {env.health}")
        print(f"Audit:              {'enabled' if status['audit_enabled'] else 'disabled'}")
        print(f"Available profiles: {', '.join(status['profiles']) or '(none)'}")
        print_env_hint(env)


def _handle_check_environment(shield: Shield) -> None:
    """Check podman environment for compatibility issues."""
    result = shield.check_environment()
    print(f"podman_version={format_version(result.podman_version)}")
    print(f"hooks={result.hooks}")
    print(f"health={result.health}")
    print_env_hint(result)


def _handle_profiles(shield: Shield) -> None:
    """List available shield profiles."""
    for name in shield.profiles_list():
        print(name)


def _handle_logs(shield: Shield, container: str, *, n: int = 50) -> None:
    """Show per-container audit log entries."""
    for entry in shield.tail_log(n):
        print(json.dumps(entry))


def _handle_harvest(shield: Shield, container: str, *, output_json: bool = False) -> None:
    """Show what this container reached for, refusals first."""
    entries = shield.harvest()
    if output_json:
        print(json.dumps([asdict(entry) for entry in entries]))
        return
    if not entries:
        print(f"Nothing harvested for {container} — no refusals, no window accepts")
        return
    for entry in entries:
        ports = ",".join(str(port) for port in entry.ports) or "-"
        print(
            f"{entry.action:<8} {entry.target:<40} x{entry.count:<5} :{ports:<12} {entry.last_seen}"
        )


STATUS = CommandDef(
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
)

CHECK_ENVIRONMENT = CommandDef(
    name="check-environment",
    help="Check podman environment for compatibility issues",
    handler=_handle_check_environment,
)

PROFILES = CommandDef(
    name="profiles",
    help="List available shield profiles",
    handler=_handle_profiles,
)

# ``logs`` carries ``--container`` (optional) for the standalone CLI's
# aggregated mode; the CLI dispatches it via ``_cmd_logs_cli`` rather than
# the generic per-container path, so the ``needs_container`` marker here is
# for downstream (terok-sandbox) filtering semantics only.
LOGS = CommandDef(
    name="logs",
    help="Show audit log entries",
    handler=_handle_logs,
    extras=NEEDS_CTR,
    args=(
        ArgDef(name="--container", default=None, help="Filter by container name"),
        ArgDef(name="-n", type=int, default=50, help="Number of recent entries"),
    ),
)

HARVEST = CommandDef(
    name="harvest",
    help="Show what a container reached for — refusals and window accepts",
    handler=_handle_harvest,
    extras=NEEDS_CTR,
    args=(
        CONTAINER_ARG,
        ArgDef(
            name="--json",
            dest="output_json",
            action="store_true",
            help="Emit the entries as JSON instead of a table",
        ),
    ),
)
