# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""NFLOG-based interactive connection handler.

Implements a JSON-lines protocol for interactive verdict flow:

1. **pending** — emitted when a new outbound connection is detected via NFLOG.
   Contains ``id``, ``dest`` (IP), ``port``, ``proto``, and ``domain`` (if
   resolvable from the dnsmasq log).
2. **verdict** — received on stdin from the controlling process.  Must contain
   ``type: "verdict"``, ``id`` (matching a pending event), and ``action``
   (``"accept"`` or ``"deny"``).
3. **verdict_applied** — emitted after the verdict has been persisted to the
   nft ruleset and state files.  Contains ``id``, ``dest``, ``action``, and
   ``ok`` (boolean indicating success).

The handler deduplicates by destination IP — only the first packet to a given
IP triggers a pending event.  Accepted IPs are added to the allow sets and
persisted to ``live.allowed``; denied IPs are added to the deny sets and
persisted to ``deny.list``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import select
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from . import state
from .nft import add_deny_elements_dual, add_elements_dual
from .run import CommandRunner, SubprocessRunner
from .state import read_interactive_tier
from .watch import NflogWatcher, WatchEvent

logger = logging.getLogger(__name__)

# Matches dnsmasq log lines like:
#   reply github.com is 140.82.121.4
_REPLY_RE = re.compile(r"reply\s+(\S+)\s+is\s+(\S+)")

# How often (seconds) to refresh the IP→domain cache from the dnsmasq log.
_DOMAIN_REFRESH_INTERVAL = 10.0

# Module-level stop flag, set by signal handler.
_running = True


def _handle_signal(_signum: int, _frame: object) -> None:
    """Set the module-level stop flag on SIGINT/SIGTERM."""
    global _running  # noqa: PLW0603
    _running = False


# ── Data types ─────────────────────────────────────────


@dataclass
class _PendingPacket:
    """A packet awaiting an interactive verdict."""

    dest: str
    port: int
    proto: int
    queued_at: float
    domain: str = ""
    packet_id: int = 0


# ── Session ────────────────────────────────────────────


class InteractiveSession:
    """Drive the interactive NFLOG verdict loop.

    Creates an :class:`NflogWatcher`, listens for queued-connection events,
    emits pending events as JSON lines on stdout, reads verdict commands
    from stdin, and applies them to the nft ruleset and state files.
    """

    def __init__(
        self,
        *,
        runner: CommandRunner,
        state_dir: Path,
        container: str,
    ) -> None:
        """Initialise the session.

        Args:
            runner: Command runner for nft operations.
            state_dir: Per-container state directory.
            container: Container name (for nft nsenter).
        """
        self._runner = runner
        self._state_dir = state_dir
        self._container = container

        self._seen_ips: set[str] = set()
        self._pending_by_ip: dict[str, _PendingPacket] = {}
        self._ip_to_domain: dict[str, str] = {}
        self._last_domain_refresh: float = 0.0
        self._next_id: int = 1

    def run(self) -> None:
        """Enter the interactive event loop.

        Creates the NFLOG watcher, sets stdin to non-blocking, installs
        signal handlers, and delegates to :meth:`_loop`.  Exits with
        code 1 if the NFLOG watcher cannot be created.
        """
        watcher = NflogWatcher.create(self._container)
        if watcher is None:
            print(
                "Error: could not create NFLOG watcher (netlink unavailable).",
                file=sys.stderr,
            )
            raise SystemExit(1)

        stdin_fd = sys.stdin.fileno()
        _set_nonblocking(stdin_fd)

        global _running  # noqa: PLW0603
        _running = True
        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        try:
            self._loop(watcher, stdin_fd)
        finally:
            watcher.close()

    def _loop(self, watcher: NflogWatcher, stdin_fd: int) -> None:
        """Select-based event loop multiplexing NFLOG and stdin.

        Args:
            watcher: The NFLOG netlink watcher.
            stdin_fd: File descriptor for stdin (set to non-blocking).
        """
        buf = ""
        while _running:
            try:
                readable, _, _ = select.select([watcher, stdin_fd], [], [], 1.0)
            except (OSError, ValueError):
                break

            if watcher.fileno() in (r if isinstance(r, int) else r.fileno() for r in readable):
                for event in watcher.poll():
                    if event.action == "queued_connection" and event.dest:
                        self._handle_nflog_event(event)

            if stdin_fd in (r if isinstance(r, int) else r.fileno() for r in readable):
                result = self._read_stdin(buf)
                if result is None:
                    break
                buf = result

            # Periodically refresh the domain cache.
            now = time.monotonic()
            if now - self._last_domain_refresh > _DOMAIN_REFRESH_INTERVAL:
                self._refresh_domain_cache()

    def _handle_nflog_event(self, event: WatchEvent) -> None:
        """Process a queued-connection NFLOG event.

        Deduplicates by destination IP — only the first packet to a
        given IP emits a pending event.

        Args:
            event: The NFLOG watch event with action ``queued_connection``.
        """
        ip = event.dest
        if ip in self._seen_ips:
            return

        self._seen_ips.add(ip)
        domain = self._ip_to_domain.get(ip, "")
        packet_id = self._next_id
        self._next_id += 1

        pending = _PendingPacket(
            dest=ip,
            port=event.port,
            proto=event.proto,
            queued_at=time.monotonic(),
            domain=domain,
            packet_id=packet_id,
        )
        self._pending_by_ip[ip] = pending

        out = {
            "type": "pending",
            "id": packet_id,
            "dest": ip,
            "port": event.port,
            "proto": event.proto,
            "domain": domain,
        }
        print(json.dumps(out, separators=(",", ":")), flush=True)

    def _read_stdin(self, buf: str) -> str | None:
        """Read available bytes from stdin and process complete lines.

        Returns the updated buffer, or ``None`` on EOF.

        Args:
            buf: Accumulated partial line from previous reads.
        """
        try:
            data = os.read(sys.stdin.fileno(), 4096)
        except OSError:
            return buf
        if not data:
            return None

        buf += data.decode("utf-8", errors="replace")
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            line = line.strip()
            if line:
                self._process_command(line)
        return buf

    def _process_command(self, line: str) -> None:
        """Parse and execute a single JSON command from stdin.

        Expected format::

            {"type": "verdict", "id": 1, "action": "accept"}

        Args:
            line: A single JSON line from the controlling process.
        """
        try:
            cmd = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Invalid JSON on stdin: %s", line)
            return

        if not isinstance(cmd, dict):
            logger.warning("Expected JSON object, got %s", type(cmd).__name__)
            return
        if cmd.get("type") != "verdict":
            logger.warning("Unknown command type: %s", cmd.get("type"))
            return

        verdict_id = cmd.get("id")
        if isinstance(verdict_id, bool) or not isinstance(verdict_id, int):
            logger.warning("Verdict id must be an integer, got %r", verdict_id)
            return

        action = cmd.get("action")
        if action not in ("accept", "deny"):
            logger.warning("Verdict action must be 'accept' or 'deny', got %r", action)
            return

        # Find the pending packet by id.
        pending: _PendingPacket | None = None
        for p in self._pending_by_ip.values():
            if p.packet_id == verdict_id:
                pending = p
                break

        if pending is None:
            logger.warning("No pending packet with id %d", verdict_id)
            return

        ok = self._apply_verdict(pending, accept=(action == "accept"))

        out = {
            "type": "verdict_applied",
            "id": verdict_id,
            "dest": pending.dest,
            "action": action,
            "ok": ok,
        }
        print(json.dumps(out, separators=(",", ":")), flush=True)

    def _apply_verdict(self, pending: _PendingPacket, *, accept: bool) -> bool:
        """Apply an accept or deny verdict to the nft ruleset and persist it.

        Args:
            pending: The pending packet to verdict.
            accept: True for accept, False for deny.

        Returns:
            True if the verdict was successfully applied.
        """
        ip = pending.dest
        if accept:
            nft_cmd = add_elements_dual([ip], permanent=True)
        else:
            nft_cmd = add_deny_elements_dual([ip])

        if nft_cmd and not self._nft_apply(nft_cmd):
            return False

        # Persist to state files.
        if accept:
            _append_unique(state.live_allowed_path(self._state_dir), ip)
        else:
            _append_unique(state.deny_path(self._state_dir), ip)

        return True

    def _nft_apply(self, nft_cmd: str) -> bool:
        """Apply nft commands via nsenter into the container's network namespace.

        Args:
            nft_cmd: One or more nft commands (newline-separated).

        Returns:
            True if all commands succeeded.
        """
        for line in nft_cmd.strip().splitlines():
            parts = line.strip().split()
            if not parts:
                continue
            try:
                self._runner.nft_via_nsenter(self._container, *parts)
            except Exception:
                logger.exception("nft command failed: %s", line)
                return False
        return True

    def _refresh_domain_cache(self) -> None:
        """Reload the IP-to-domain mapping from the dnsmasq query log.

        Parses ``reply`` lines to build a reverse lookup table.  On
        ``OSError`` the previous cache is preserved.
        """
        self._last_domain_refresh = time.monotonic()
        log_path = state.dnsmasq_log_path(self._state_dir)
        try:
            text = log_path.read_text()
        except OSError:
            return

        mapping: dict[str, str] = {}
        for m in _REPLY_RE.finditer(text):
            domain, ip = m.group(1), m.group(2)
            mapping[ip] = domain.lower().rstrip(".")
        self._ip_to_domain = mapping


# ── Helpers ────────────────────────────────────────────


def _set_nonblocking(fd: int) -> None:
    """Set a file descriptor to non-blocking mode."""
    import fcntl

    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


def _append_unique(path: Path, value: str) -> None:
    """Append *value* to a newline-delimited file if not already present.

    Creates the file if it does not exist.

    Args:
        path: Path to the file.
        value: The value to append (without trailing newline).
    """
    existing: set[str] = set()
    if path.is_file():
        existing = {line.strip() for line in path.read_text().splitlines() if line.strip()}
    if value in existing:
        return
    with open(path, "a") as f:
        f.write(value + "\n")


# ── Entry point ────────────────────────────────────────


def run_interactive(state_dir: Path, container: str) -> None:
    """Start the interactive NFLOG handler for a container.

    Validates that the interactive tier is configured, then creates a
    :class:`SubprocessRunner` and :class:`InteractiveSession` and enters
    the event loop.

    Args:
        state_dir: Per-container state directory (may be relative).
        container: Container name.

    Raises:
        SystemExit: If the interactive tier is not configured or NFLOG
            watcher creation fails.
    """
    state_dir = state_dir.resolve()
    tier = read_interactive_tier(state_dir)
    if tier is None:
        print(
            "Error: interactive tier not configured for this container.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    runner = SubprocessRunner()
    session = InteractiveSession(runner=runner, state_dir=state_dir, container=container)
    session.run()
