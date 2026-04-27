# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Terminal-based clearance fallback for hosts without the D-Bus hub.

``simple-clearance`` is the stripped-down sibling of the full Clearance
flow: instead of desktop notifications and a TUI sharing signals over
``org.terok.Shield1``, it streams blocked-connection events from a
subprocess NFLOG reader and prompts the operator on a terminal.
Verdicts are applied by shelling out to the audited
``terok-shield allow|deny`` CLI, so the trust boundary is identical.

Refuses to run when the D-Bus hub is active on the session bus —
concurrent application from both paths would race on the same verdict,
so only one is enabled at a time.
"""

from __future__ import annotations

import contextlib
import json
import os
import select
import signal
import subprocess  # nosec B404
import sys
from dataclasses import dataclass
from pathlib import Path

from terok_shield.resources import __file__ as _resources_init  # pragma: no cover

_RESOURCES_DIR = Path(_resources_init).parent
_READER_SCRIPT = _RESOURCES_DIR / "nflog_reader.py"
_HUB_BUS_NAME = "org.terok.Shield1"


# ── Entry point ──────────────────────────────────────────


def run_simple_clearance(state_dir: Path, container: str) -> None:
    """Run the terminal clearance fallback for *container*.

    Refuses to start when ``org.terok.Shield1`` already has an owner on
    the session bus — the D-Bus hub would race this tool on every verdict.

    Args:
        state_dir: Per-container shield state directory.
        container: Container name.
    """
    if _dbus_hub_active():
        print(
            "D-Bus hub (org.terok.Shield1) is active — use a D-Bus clearance "
            "client (desktop notifier or TUI).  To use this terminal fallback, "
            "stop the hub first:  systemctl --user stop terok-clearance-hub",
            file=sys.stderr,
        )
        raise SystemExit(1)

    session = ClearanceSession(state_dir=state_dir, container=container)
    session.run()


# ── Session ──────────────────────────────────────────────


@dataclass
class _Pending:
    """A blocked connection awaiting the operator's verdict."""

    request_id: str
    dest: str
    port: int
    domain: str


class ClearanceSession:
    """Drive the terminal clearance loop for a single container.

    Owns the reader subprocess, the operator prompt UI, and the verdict
    subprocess calls.  Lives until the reader exits or the operator
    interrupts with Ctrl-C.
    """

    def __init__(self, *, state_dir: Path, container: str) -> None:
        """Prepare the session — the reader is spawned in [`run`][terok_shield.cli.simple_clearance.ClearanceSession.run]."""
        self._state_dir = state_dir
        self._container = container
        self._queue: list[_Pending] = []
        self._stop_requested = False

    def run(self) -> None:  # pragma: no cover — real subprocess + tty I/O, integration path
        """Spawn the reader, then multiplex its stdout with stdin prompts."""
        reader = self._spawn_reader()
        if reader.stdout is None:
            print("Error: reader stdout is closed.", file=sys.stderr)
            raise SystemExit(1)

        self._install_signal_handlers()
        print("Watching for blocked connections... (Ctrl-C to stop)\n", flush=True)
        try:
            self._event_loop(reader)
        finally:
            self._shutdown_reader(reader)

    def _spawn_reader(self) -> subprocess.Popen:
        """Start the NFLOG reader subprocess in JSON mode."""
        if not _READER_SCRIPT.exists():
            print(f"Error: NFLOG reader script missing at {_READER_SCRIPT}", file=sys.stderr)
            raise SystemExit(1)
        return subprocess.Popen(  # nosec B603
            [
                sys.executable,
                str(_READER_SCRIPT),
                str(self._state_dir),
                self._container,
                "--emit=json",
            ],
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            bufsize=1,
        )

    def _shutdown_reader(self, reader: subprocess.Popen) -> None:
        """Terminate the reader cleanly on loop exit."""
        if reader.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                reader.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                reader.wait(timeout=2)
        if reader.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                reader.kill()

    def _event_loop(self, reader: subprocess.Popen) -> None:  # pragma: no cover
        """Read reader JSON lines on stdout and operator verdicts on stdin.

        No-cover because the loop ticks require a real reader subprocess and
        a real stdin fd set to non-blocking.  The per-fd drain helpers
        (``_drain_reader``, ``_drain_stdin``) are covered directly.
        """
        reader_fd = reader.stdout.fileno()  # type: ignore[union-attr]
        stdin_fd = sys.stdin.fileno()
        _set_nonblocking(stdin_fd)
        reader_buf = ""
        stdin_buf = ""
        while not self._stop_requested:
            try:
                readable, _, _ = select.select([reader_fd, stdin_fd], [], [], 0.5)
            except (OSError, ValueError):
                return
            reader_buf, reader_eof = self._drain_reader(reader_fd, reader_buf, readable)
            stdin_buf, stdin_eof = self._drain_stdin(stdin_fd, stdin_buf, readable)
            if reader_eof or stdin_eof:
                return

    def _drain_reader(self, reader_fd: int, buf: str, readable: list[int]) -> tuple[str, bool]:
        """Dispatch any reader-side events sitting in the pipe; carry over partials."""
        if reader_fd not in readable:
            return buf, False
        buf, eof = _read_into_buffer(reader_fd, buf)
        for line in _drain_lines(buf):
            self._handle_reader_event(line)
        return _tail_partial(buf), eof

    def _drain_stdin(self, stdin_fd: int, buf: str, readable: list[int]) -> tuple[str, bool]:
        """Dispatch any operator keystrokes sitting on stdin; carry over partials."""
        if stdin_fd not in readable:
            return buf, False
        buf, eof = _read_into_buffer(stdin_fd, buf)
        for line in _drain_lines(buf):
            self._handle_operator_input(line.strip())
        return _tail_partial(buf), eof

    def _handle_reader_event(self, line: str) -> None:
        """Enqueue a pending event and prompt if it's the head of the queue."""
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return
        if event.get("type") != "pending":
            return
        pending = _Pending(
            request_id=str(event.get("id", "")),
            dest=str(event.get("dest", "")),
            port=int(event.get("port", 0)),
            domain=str(event.get("domain", "")),
        )
        self._queue.append(pending)
        if len(self._queue) > 1:
            label = f"{pending.dest} ({pending.domain})" if pending.domain else pending.dest
            print(f"\n[BLOCKED] {label} :{pending.port} (queued)", flush=True)
        self._prompt_head()

    def _handle_operator_input(self, line: str) -> None:
        """Map operator keystrokes to accept/deny; apply to the head of queue."""
        action = _INPUT_MAP.get(line.lower())
        if action is None:
            print("  Unknown input. Type 'a' to allow or 'd' to deny.", flush=True)
            self._prompt_head()
            return
        if not self._queue:
            return
        head = self._queue[0]
        ok = self._apply_verdict(head, action)
        if ok:
            self._queue.pop(0)
            mark = "\u2713" if action == "allow" else "\u2717"
            verb = "allowed" if action == "allow" else "denied"
            label = f"{head.dest} ({head.domain})" if head.domain else head.dest
            print(f"  {mark} {verb} {label}")
        else:
            print(f"  ! verdict failed for {head.dest} (retry with a/d)")
        self._prompt_head()

    def _apply_verdict(self, pending: _Pending, action: str) -> bool:
        """Apply *action* to *pending* by shelling out to ``terok-shield <action>``."""
        # Under Nix (and other setups where ``sys.executable`` is a wrapper
        # that normally rewrites the env on startup) spawning ``python -m
        # terok_shield.cli`` from inside a running terok_shield process
        # bypasses that wrapper, and the child can't find the ``terok_shield``
        # package on its import path.  Passing the parent's ``sys.path``
        # through as ``PYTHONPATH`` lets the subprocess resolve the same
        # install this process is running from.  See #242 by Franz Pöschel.
        env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
        result = subprocess.run(  # nosec B603
            [sys.executable, "-m", "terok_shield.cli", action, self._container, pending.dest],
            check=False,
            capture_output=True,
            env=env,
        )
        return result.returncode == 0

    def _prompt_head(self) -> None:
        """Print the allow/deny prompt for the head-of-queue pending event."""
        if not self._queue:
            return
        head = self._queue[0]
        label = f"{head.dest} ({head.domain})" if head.domain else head.dest
        print(f"[BLOCKED] {label} :{head.port} \u2014 allow/deny? ", end="", flush=True)

    def _install_signal_handlers(self) -> None:
        """Arrange a clean exit on SIGINT / SIGTERM."""
        signal.signal(signal.SIGINT, self._on_stop_signal)
        signal.signal(signal.SIGTERM, self._on_stop_signal)

    def _on_stop_signal(self, _signum: int, _frame: object) -> None:
        """Flip the stop flag — the select loop picks it up on the next tick."""
        self._stop_requested = True


# ── Hub-liveness guard ───────────────────────────────────


def _dbus_hub_active() -> bool:
    """Return True when ``org.terok.Shield1`` is owned on the session bus."""
    try:
        result = subprocess.run(  # nosec B603, B607
            [
                "dbus-send",
                "--session",
                "--print-reply",
                "--dest=org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus.NameHasOwner",
                f"string:{_HUB_BUS_NAME}",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and "boolean true" in result.stdout


# ── Operator-input vocabulary ────────────────────────────

_INPUT_MAP: dict[str, str] = {
    "a": "allow",
    "allow": "allow",
    "d": "deny",
    "deny": "deny",
}


# ── Buffer helpers ───────────────────────────────────────


def _read_into_buffer(fd: int, buf: str) -> tuple[str, bool]:
    """Append readable bytes from *fd* to *buf*; returns the buffer and EOF flag."""
    try:
        data = os.read(fd, 4096)
    except OSError:
        return buf, False
    if not data:
        return buf, True
    return buf + data.decode("utf-8", errors="replace"), False


def _drain_lines(buf: str) -> list[str]:
    """Split *buf* into complete lines; the partial suffix stays in the buffer."""
    if "\n" not in buf:
        return []
    parts = buf.split("\n")
    return [p for p in parts[:-1] if p]


def _tail_partial(buf: str) -> str:
    """Return the partial trailing segment after the last newline."""
    if "\n" not in buf:
        return buf
    return buf.rsplit("\n", 1)[-1]


def _set_nonblocking(fd: int) -> None:
    """Put a file descriptor into non-blocking mode for the select loop."""
    import fcntl

    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
