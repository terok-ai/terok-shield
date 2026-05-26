# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Best-effort JSON event emitter for the terok-clearance hub.

Shield CLI calls (``up``/``down``) notify the hub so desktop/TUI consumers
can reflect the state change — in particular, the hub closes pending
block notifications for a container whose shield just dropped.  Stays
stdlib-only so the reader script resource (which bypasses the package)
can mirror the same wire format without importing this module.

Every emit targets the *per-container* ingester socket under
``$XDG_RUNTIME_DIR/terok/events/<short_id>.sock``, where ``<short_id>``
is the 12-char prefix of the container id — the same addressing the
NFLOG reader uses, and deliberately distinct from the varlink
subscriber socket at ``terok/clearance/<id>.sock`` that operator UIs
glob.  Callers therefore supply ``container_id`` (the full podman
container UUID) on every call: the destination socket is per-container,
so the id is what selects it.

Fails silent when the hub isn't listening: flipping shield state must
never be held up by a desktop-side daemon being absent.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import socket
from pathlib import Path

from terok_shield._wire_sanitize import sanitize, sanitize_mapping
from terok_shield.validation import validate_container_id

_log = logging.getLogger(__name__)

#: Cap on the socket connect/send syscalls so a dead but unreaped hub
#: (listener exists, accept thread wedged) can't block the shield CLI
#: for longer than the operator will patiently hold the keyboard.
_IO_TIMEOUT_S = 0.5


def _per_container_hub_socket(container_id: str) -> Path:
    """Return the per-container ingester path under ``$XDG_RUNTIME_DIR``.

    Mirrors the NFLOG reader's path scheme (12-char short ID under
    ``terok/events/``) so every event for one container converges on the
    same supervisor-owned ingester socket — without the truncation
    match, ``shield_up``/``shield_down`` events and ``pending`` events
    for the same container land on different sockets.

    *container_id* is validated as a hex id before it is spliced into
    the path: a malformed value (path separators, ``..``, leading slash)
    could otherwise escape ``terok/events/`` or redirect the connection.

    Raises:
        ValueError: If *container_id* is not a 12-to-64-char hex string.
    """
    validate_container_id(container_id)
    xdg = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return Path(xdg) / "terok" / "events" / f"{container_id[:12]}.sock"


class HubEventEmitter:
    """One-shot writer of JSON-line events to the hub's unix ingester.

    Each ``emit_*`` call opens a fresh connection to the per-container
    socket, sends a single line, and closes.  The hub stays up across
    many CLI invocations while each CLI invocation is short-lived —
    pooling would save nothing and would complicate the fail-silent
    semantics.
    """

    def shield_up(
        self,
        container: str,
        container_id: str,
        *,
        dossier: dict[str, str] | None = None,
    ) -> None:
        """Emit a ``shield_up`` event for *container* (optional *dossier*).

        *container_id* — full podman container UUID; routes the event
        to the supervisor's per-container hub socket.

        *dossier* mirrors the orchestrator-supplied identity bundle the
        per-container reader already attaches to ``connection_blocked``
        events; passing it through here keeps the clearance UI's
        rendering of every event for the same container consistent
        (``project/task · name`` rather than the bare container slug).
        Empty / omitted dossier omits the key entirely.
        """
        self._send(container_id, {"type": "shield_up", "container": container}, dossier)

    def shield_down(
        self,
        container: str,
        container_id: str,
        *,
        allow_all: bool = False,
        dossier: dict[str, str] | None = None,
    ) -> None:
        """Emit a ``shield_down`` (or ``shield_disengaged``) event for *container*.

        *container_id* — see
        [`shield_up`][terok_shield._hub_events.HubEventEmitter.shield_up].

        *dossier* — see
        [`shield_up`][terok_shield._hub_events.HubEventEmitter.shield_up].
        """
        event_type = "shield_disengaged" if allow_all else "shield_down"
        self._send(container_id, {"type": event_type, "container": container}, dossier)

    def _send(
        self,
        container_id: str,
        payload: dict,
        dossier: dict[str, str] | None = None,
    ) -> None:
        """Write one JSON line to the per-container ingester socket, swallowing all I/O errors.

        *container_id* selects the destination socket
        (``$XDG_RUNTIME_DIR/terok/events/<short_id>.sock`` where
        ``<short_id> = container_id[:12]``); the caller — the shield
        CLI — knows the full UUID at every emit site.

        *dossier* is folded into the payload only when non-empty —
        keeps the wire flat for standalone containers (``podman run``
        without orchestrator annotations) so the ingester only has
        to handle the dossier key when one is actually populated.

        Every string value is run through the producer-side sanitiser
        (``WIRE_SPEC(safe-string)``) before serialisation so the wire
        format invariant — printable ASCII, length-capped — holds at
        the boundary the container actually crosses.  The clearance
        hub re-applies the same rule on receive as belt-and-braces.
        """
        sanitised: dict[str, object] = {
            k: sanitize(v) if isinstance(v, str) else v for k, v in payload.items()
        }
        if dossier:
            sanitised["dossier"] = sanitize_mapping(dossier)
        line = (json.dumps(sanitised, separators=(",", ":")) + "\n").encode()
        path = _per_container_hub_socket(container_id)
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(_IO_TIMEOUT_S)
            with contextlib.closing(sock):
                sock.connect(str(path))
                sock.sendall(line)
        except OSError as exc:
            # Hub absent, socket path stale, peer buffer full — none of
            # these should block a state-change CLI command.  Log at debug
            # so a diagnosing operator can still see the reason.
            _log.debug("hub event emit failed (%s): %s", payload.get("type"), exc)
