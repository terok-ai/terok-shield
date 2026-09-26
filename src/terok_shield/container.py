# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Bottom-up container→state_dir resolution via podman annotations.

Shielded containers are launched with a ``terok.shield.state_dir``
annotation that points at the per-container state directory written by
``pre_start()``.  The OCI hook already reads that annotation out of the
runtime-provided OCI state JSON (see ``resources/hook_entrypoint.py``).
This module does the same lookup for consumers that only have a
container *name* and no in-process ``ShieldConfig`` — the clearance
hub's verdict path, ad-hoc CLI invocations against a live container,
anything that enters from the podman side of the handoff rather than
from terok's task orchestration.

The annotation is the *single source of truth* for a shielded
container's state directory: both the OCI hook (via crun's stdin) and
the CLI (via this module) converge on the same string.  In-process
callers (``terok-sandbox.make_shield``) supply ``state_dir`` at
construction and don't need to do a lookup.

On hosts where ``podman inspect`` isn't reachable (no podman on PATH,
no rootless user namespace, container simply doesn't exist), the
resolver returns ``None`` and callers fall back to whatever legacy
behaviour they had.
"""

from __future__ import annotations

import json
import logging
import subprocess  # nosec B404 — podman is a trusted host binary
from dataclasses import dataclass
from pathlib import Path

from terok_util import find_host_tool

from .config import ANNOTATION_STATE_DIR_KEY, ANNOTATION_VERSION_KEY

_log = logging.getLogger(__name__)

_INSPECT_TIMEOUT_S = 10


def _inspect_records(container: str) -> object | None:
    """Run ``podman inspect --format=json`` for *container*; return parsed records or ``None``.

    Any failure — podman missing, container absent, non-zero exit, malformed
    JSON — collapses to ``None`` so callers fall through.  ``--`` bars podman
    from reading a hostile *container* value as one of its own flags
    (``--all``, ``--latest``, …) — the public contract accepts identifiers from
    external callers that may not have validated them.
    """
    podman = find_host_tool("podman")
    if not podman:
        _log.warning("podman not on PATH — cannot inspect %s", container)
        return None
    try:
        result = subprocess.run(  # nosec B603
            [podman, "inspect", "--format=json", "--", container],
            check=False,
            capture_output=True,
            text=True,
            timeout=_INSPECT_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _log.warning("podman inspect failed for %s: %s", container, exc)
        return None
    if result.returncode != 0:
        # Warn — every failure here translates into a downstream miss.
        # Operators need *why* podman couldn't speak to its own state.
        _log.warning(
            "podman inspect %s returned %d: %s", container, result.returncode, result.stderr.strip()
        )
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        _log.warning("podman inspect %s returned malformed JSON: %s", container, exc)
        return None


def _annotations(records: object) -> dict | None:
    """Pull the OCI annotations dict out of one ``podman inspect`` record set."""
    if not isinstance(records, list) or not records:
        return None
    head = records[0]
    if not isinstance(head, dict):
        return None
    config = head.get("Config")
    if not isinstance(config, dict):
        return None
    annotations = config.get("Annotations")
    return annotations if isinstance(annotations, dict) else None


def _state_dir_from(annotations: dict) -> Path | None:
    """Parse the ``terok.shield.state_dir`` value out of *annotations*, ``None`` on any defect."""
    raw = annotations.get(ANNOTATION_STATE_DIR_KEY)
    if not isinstance(raw, str) or not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        _log.warning("container carries a non-absolute state_dir annotation: %r", raw)
        return None
    try:
        return path.resolve()
    except OSError as exc:
        _log.warning("failed to resolve state_dir annotation %r: %s", raw, exc)
        return None


def _version_from(annotations: dict) -> int | None:
    """Parse the ``terok.shield.version`` value out of *annotations*, ``None`` when non-integer."""
    raw = annotations.get(ANNOTATION_VERSION_KEY)
    if not isinstance(raw, str):
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def resolve_state_dir(container: str) -> Path | None:
    """Return the per-container ``state_dir`` from podman annotations, or ``None``.

    Reads the ``terok.shield.state_dir`` annotation out of the container's
    config.  Any failure — podman missing, container absent, annotation not
    set, non-absolute, JSON malformed — collapses to ``None`` so callers can
    fall through.

    Args:
        container: Container name or ID (short or full) as podman knows it.

    Returns:
        The resolved ``Path`` if the annotation is present and absolute,
        otherwise ``None``.
    """
    annotations = _annotations(_inspect_records(container))
    return None if annotations is None else _state_dir_from(annotations)


def resolve_shield_version(container: str) -> int | None:
    """Return the bundle version a container was prepared with, or ``None``.

    Reads the ``terok.shield.version`` OCI annotation stamped by
    [`Shield.pre_start`][terok_shield.Shield.pre_start].  ``None`` when the
    container is absent, unshielded, or the annotation is missing / non-integer
    — callers treat that as "cannot determine" and fall through rather than
    block.  An orchestrator compares this against
    [`BUNDLE_VERSION`][terok_shield.state.BUNDLE_VERSION] to refuse restarting a
    container whose bundle predates the installed shield (fail-fast, re-create).
    """
    annotations = _annotations(_inspect_records(container))
    return None if annotations is None else _version_from(annotations)


@dataclass(frozen=True)
class ShieldAnnotations:
    """Every shield-owned OCI annotation read off one container in one inspect.

    Each field carries the same "cannot determine" ``None`` its
    single-annotation resolver uses; a failed inspect (podman missing,
    container absent) yields a record with every field ``None``.
    """

    version: int | None
    """Bundle version — see [`resolve_shield_version`][terok_shield.container.resolve_shield_version]."""

    state_dir: Path | None
    """State directory — see [`resolve_state_dir`][terok_shield.container.resolve_state_dir]."""


def resolve_annotations(container: str) -> ShieldAnnotations:
    """Read the shield annotations off *container* in a single ``podman inspect``.

    A sweep that needs both the bundle version and the state dir pays one
    inspect here instead of one per
    [`resolve_shield_version`][terok_shield.container.resolve_shield_version] /
    [`resolve_state_dir`][terok_shield.container.resolve_state_dir] call.
    Per-field failures collapse to ``None`` exactly as in the single
    resolvers.

    Args:
        container: Container name or ID (short or full) as podman knows it.

    Returns:
        A [`ShieldAnnotations`][terok_shield.container.ShieldAnnotations]
        record; all fields are ``None`` when the inspect itself fails.
    """
    annotations = _annotations(_inspect_records(container))
    if annotations is None:
        return ShieldAnnotations(version=None, state_dir=None)
    return ShieldAnnotations(
        version=_version_from(annotations),
        state_dir=_state_dir_from(annotations),
    )
