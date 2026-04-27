# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Best-effort JSON event emitter for the terok-clearance hub.

Shield CLI calls (``up``/``down``) notify the hub so desktop/TUI consumers
can reflect the state change — in particular, the hub closes pending
block notifications for a container whose shield just dropped.  Stays
stdlib-only so the reader script resource (which bypasses the package)
can mirror the same wire format without importing this module.

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

_log = logging.getLogger(__name__)

_SOCKET_BASENAME = "terok-shield-events.sock"
#: Cap on the socket connect/send syscalls so a dead but unreaped hub
#: (listener exists, accept thread wedged) can't block the shield CLI
#: for longer than the operator will patiently hold the keyboard.
_IO_TIMEOUT_S = 0.5


def hub_socket_path() -> Path:
    """Return the canonical hub ingester path under ``$XDG_RUNTIME_DIR``."""
    xdg = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return Path(xdg) / _SOCKET_BASENAME


class HubEventEmitter:
    """One-shot writer of JSON-line events to the hub's unix ingester.

    Each ``emit_*`` call opens a fresh connection, sends a single line,
    and closes.  The hub stays up across many CLI invocations while each
    CLI invocation is short-lived — pooling would save nothing and would
    complicate the fail-silent semantics.
    """

    def __init__(self, socket_path: Path | None = None) -> None:
        """Remember the target socket; defaults to `hub_socket_path`."""
        self._path = socket_path or hub_socket_path()

    def shield_up(self, container: str) -> None:
        """Emit a ``shield_up`` event for *container*."""
        self._send({"type": "shield_up", "container": container})

    def shield_down(self, container: str, *, allow_all: bool = False) -> None:
        """Emit a ``shield_down`` (or ``shield_down_all``) event for *container*."""
        event_type = "shield_down_all" if allow_all else "shield_down"
        self._send({"type": event_type, "container": container})

    def _send(self, payload: dict) -> None:
        """Write one JSON line to the hub socket, swallowing all I/O errors."""
        line = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(_IO_TIMEOUT_S)
            with contextlib.closing(sock):
                sock.connect(str(self._path))
                sock.sendall(line)
        except OSError as exc:
            # Hub absent, socket path stale, peer buffer full — none of
            # these should block a state-change CLI command.  Log at debug
            # so a diagnosing operator can still see the reason.
            _log.debug("hub event emit failed (%s): %s", payload.get("type"), exc)
