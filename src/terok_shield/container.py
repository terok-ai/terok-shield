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
import shutil
import subprocess  # nosec B404 — podman is a trusted host binary
from pathlib import Path

from .config import ANNOTATION_STATE_DIR_KEY

_log = logging.getLogger(__name__)

_INSPECT_TIMEOUT_S = 10


def resolve_state_dir(container: str) -> Path | None:
    """Return the per-container ``state_dir`` from podman annotations, or ``None``.

    Calls ``podman inspect --format=json`` and pulls the
    ``terok.shield.state_dir`` annotation out of the container's config.
    Any failure — podman missing, container absent, annotation not set,
    JSON malformed — collapses to ``None`` so callers can fall through.

    Args:
        container: Container name or ID (short or full) as podman knows it.

    Returns:
        The resolved ``Path`` if the annotation is present and absolute,
        otherwise ``None``.
    """
    podman = shutil.which("podman")
    if not podman:
        _log.warning("podman not on PATH — cannot resolve state_dir for %s", container)
        return None
    try:
        # ``--`` bars podman from interpreting a hostile *container* value as
        # one of its own flags (``--all``, ``--latest``, ``--format=bad`` …).
        # The module's public contract accepts container identifiers from
        # external callers that may not have validated them; ``--`` makes
        # the positional boundary explicit regardless of what the caller did.
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
        # Warn — every failure here translates into a verdict that silently
        # fails downstream.  Operators hitting this need to know *why*
        # podman couldn't speak to its own state (sandbox / hardening
        # interaction, stale pause process, missing socket, etc.) rather
        # than just "no annotation".
        _log.warning(
            "podman inspect %s returned %d: %s",
            container,
            result.returncode,
            result.stderr.strip(),
        )
        return None
    try:
        records = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        _log.warning("podman inspect %s returned malformed JSON: %s", container, exc)
        return None
    return _extract_state_dir(records)


def _extract_state_dir(records: object) -> Path | None:
    """Pull ``terok.shield.state_dir`` out of one ``podman inspect`` record set."""
    if not isinstance(records, list) or not records:
        return None
    head = records[0]
    if not isinstance(head, dict):
        return None
    config = head.get("Config")
    if not isinstance(config, dict):
        return None
    annotations = config.get("Annotations")
    if not isinstance(annotations, dict):
        return None
    raw = annotations.get(ANNOTATION_STATE_DIR_KEY)
    if not isinstance(raw, str) or not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        _log.warning(
            "container %r carries a non-absolute state_dir annotation: %r",
            head.get("Name") or head.get("Id") or "?",
            raw,
        )
        return None
    try:
        return path.resolve()
    except OSError as exc:
        _log.warning("failed to resolve state_dir annotation %r: %s", raw, exc)
        return None
