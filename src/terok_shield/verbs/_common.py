# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared building blocks for the per-verb command modules.

Small, dependency-light helpers reused across
[`control`][terok_shield.verbs.control],
[`observe`][terok_shield.verbs.observe], and
[`launch`][terok_shield.verbs.launch]: the argument-value splitter, the
container-argument definitions, the ``extras`` marker maps read by
[`needs_container`][terok_shield.commands.needs_container] /
[`standalone_only`][terok_shield.commands.standalone_only], and the
version/environment formatting used by the status-style verbs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from terok_util import ArgDef

if TYPE_CHECKING:
    from terok_shield import EnvironmentCheck


def csv_list(value: str) -> list[str]:
    """Split a comma-separated CLI value into a list, stripping whitespace.

    Used as ``ArgDef.type`` for multi-value optional flags so they don't
    rely on argparse's greedy ``nargs="+"`` (which silently slurps the
    following positional, turning ``--profiles a b mycontainer`` into
    ``profiles=["a","b","mycontainer"]``).  Comma-separated single-value
    matches podman's convention (``--cap-add=A,B,C``).
    """
    return [p.strip() for p in value.split(",") if p.strip()]


#: Required container positional for the per-container verbs.  Baked into
#: each verb's ``args`` so the generic wire layer adds it — shield's
#: dispatcher passes it positionally to the handler.
CONTAINER_ARG = ArgDef(name="container", help="Container name or ID")

#: ``--profiles`` for every verb that composes a policy — the launch verbs
#: and ``preview`` — so one spelling and one help text serve them all.
PROFILES_ARG = ArgDef(
    name="--profiles",
    type=csv_list,
    help=(
        "Profiles to apply instead of default_profiles from config.yml "
        "(comma-separated, e.g. 'dev-standard,dev-python')"
    ),
)

#: ``--container-id`` is the per-container hub socket routing key (full
#: podman UUID).  Every emit-bearing verb (``up`` / ``down``) accepts it
#: as a required option — the caller knows the full UUID at every site
#: that runs ``terok-shield <verb>``.
CONTAINER_ID_ARG = ArgDef(
    name="--container-id",
    required=True,
    help="Full podman container UUID — routes hub events to the per-container supervisor socket",
)

#: ``extras`` marker maps — read by the CLI dispatcher via
#: [`needs_container`][terok_shield.commands.needs_container] /
#: [`standalone_only`][terok_shield.commands.standalone_only].
NEEDS_CTR: dict[str, Any] = {"needs_container": True}
STANDALONE: dict[str, Any] = {"standalone_only": True}
NEEDS_CTR_STANDALONE: dict[str, Any] = {"needs_container": True, "standalone_only": True}


def format_version(v: tuple[int, ...]) -> str:
    """Format a version tuple as a dotted string."""
    return ".".join(str(p) for p in v) if v != (0,) else "unknown"


def print_env_hint(env: EnvironmentCheck) -> None:
    """Print human-readable environment issues and setup hint."""
    if env.issues:
        print()
        for issue in env.issues:
            print(f"  {issue}")
    if env.setup_hint:
        print()
        print(env.setup_hint)
