# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Standalone container-launch verbs — prepare, run, resolve, setup.

These verbs carry ``standalone_only`` in their ``extras``: their argv
shapes (the ``run`` ``--`` separator, ``prepare``'s eval-friendly output,
``setup``'s hook install) don't lift cleanly into a generic
Shield-injecting handler, so they have ``handler=None`` and the CLI
dispatches them through dedicated bodies in
[`terok_shield.cli.main`][terok_shield.cli.main].  Only their argument
definitions and help live here.
"""

from __future__ import annotations

from terok_util import ArgDef, CommandDef

from ._common import CONTAINER_ARG, NEEDS_CTR_STANDALONE, STANDALONE, csv_list

_PROFILES_ARG = ArgDef(
    name="--profiles",
    type=csv_list,
    help=(
        "Profiles to apply instead of default_profiles from config.yml "
        "(comma-separated, e.g. 'dev-standard,dev-python')"
    ),
)

PREPARE = CommandDef(
    name="prepare",
    help="Prepare shield and print podman flags",
    extras=NEEDS_CTR_STANDALONE,
    epilog=(
        "Resolve DNS, install hooks, and print the podman flags needed to "
        "launch a shielded container.  Use with eval:\n\n"
        '  eval "podman run $(terok-shield prepare my-ctr) alpine:latest sh"'
    ),
    args=(
        CONTAINER_ARG,
        _PROFILES_ARG,
        ArgDef(name="--json", action="store_true", dest="output_json", help="JSON output"),
    ),
)

RUN = CommandDef(
    name="run",
    help="Launch a shielded container via podman",
    extras=NEEDS_CTR_STANDALONE,
    epilog=(
        "Prepare shield and exec into podman run with the correct flags.  "
        "Everything after '--' is passed to podman run as-is:\n\n"
        "  terok-shield run my-container -- alpine:latest sh"
    ),
    args=(CONTAINER_ARG, _PROFILES_ARG),
)

RESOLVE = CommandDef(
    name="resolve",
    help="Resolve DNS profiles and cache IPs",
    extras=NEEDS_CTR_STANDALONE,
    args=(
        CONTAINER_ARG,
        ArgDef(name="--force", action="store_true", help="Re-resolve even when the cache is fresh"),
    ),
)

SETUP = CommandDef(
    name="setup",
    help="Install global OCI hooks for restart persistence",
    extras=STANDALONE,
)
