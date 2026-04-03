# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Interactive NFQUEUE verdict loop for operator-driven egress control.

Orchestrates :class:`~terok_shield.nfqueue.NfqueueHandler` with state
persistence, nft set updates, and a bidirectional JSON-lines protocol
on stdin/stdout for consumer integration.

Protocol::

    Handler → stdout:  {"type":"pending","id":42,"dest":"1.2.3.4","port":443,"proto":6,"domain":"..."}
    Consumer → stdin:  {"type":"verdict","id":42,"action":"accept"}
    Handler → stdout:  {"type":"verdict_applied","id":42,"action":"accept","dest":"1.2.3.4"}

Timeout: packets without a verdict within *nfqueue_timeout* seconds are
auto-dropped (NF_DROP) without persisting to the deny list.
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
from .nfqueue import NfqueueHandler, QueuedPacket
from .nft_constants import NFQUEUE_NUM
from .run import CommandRunner, SubprocessRunner
from .state import interactive_path

logger = logging.getLogger(__name__)

# Matches dnsmasq log lines:  "... reply <domain> is <ip>"
_REPLY_RE = re.compile(r"reply\s+(\S+)\s+is\s+(\S+)")

# How often (seconds) to refresh the domain cache from dnsmasq log.
_DOMAIN_REFRESH_INTERVAL = 10.0

_running = True


def _handle_signal(_signum: int, _frame: object) -> None:
    """Set the stop flag on SIGINT/SIGTERM."""
    global _running  # noqa: PLW0603
    _running = False


# ── Pending packet tracking ────────────────────────────


@dataclass
class _PendingPacket:
    """A queued packet awaiting operator verdict."""

    packet: QueuedPacket
    queued_at: float
    domain: str = ""


# ── InteractiveSession ─────────────────────────────────


class InteractiveSession:
    """Orchestrates the NFQUEUE verdict loop with I/O and state.

    Reads queued packets from :class:`NfqueueHandler`, enriches them
    with domain information from the dnsmasq log, emits JSON-lines events
    to stdout, reads verdict commands from stdin, and issues nft set
    updates + kernel verdicts.
    """

    def __init__(
        self,
        *,
        runner: CommandRunner,
        state_dir: Path,
        container: str,
        nfqueue_num: int = NFQUEUE_NUM,
        timeout: int = 5,
    ) -> None:
        """Initialise the session with validated parameters.

        Args:
            runner: Command runner for nft set modifications.
            state_dir: Per-container state directory.
            container: Container name (for nft_via_nsenter).
            nfqueue_num: NFQUEUE group number to bind.
            timeout: Seconds before auto-dropping queued packets.
        """
        self._runner = runner
        self._state_dir = state_dir
        self._container = container
        self._nfqueue_num = nfqueue_num
        self._timeout = timeout
        self._pending: dict[int, _PendingPacket] = {}
        self._ip_to_domain: dict[str, str] = {}
        self._last_domain_refresh = 0.0

    def run(self) -> None:
        """Enter the main verdict loop.

        Blocks until SIGINT/SIGTERM or stdin EOF.  Emits JSON-lines to stdout,
        reads verdict commands from stdin.
        """
        handler = NfqueueHandler.create(self._nfqueue_num)
        if handler is None:
            print(
                "Error: cannot bind to NFQUEUE — check permissions or kernel module.",
                file=sys.stderr,
            )
            raise SystemExit(1)

        self._refresh_domain_cache()
        stdin_fd = sys.stdin.fileno()
        _set_nonblocking(stdin_fd)

        global _running  # noqa: PLW0603
        _running = True
        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        try:
            self._loop(handler, stdin_fd)
        finally:
            self._drain_pending(handler)
            handler.close()

    def _drain_pending(self, handler: NfqueueHandler) -> None:
        """Reject all remaining pending packets on shutdown."""
        for _pid, pending in self._pending.items():
            handler.verdict(pending.packet.packet_id, accept=False)
        self._pending.clear()

    def _loop(self, handler: NfqueueHandler, stdin_fd: int) -> None:
        """Core select() loop: NFQUEUE socket + stdin + timeout sweep."""
        stdin_buf = ""
        while _running:
            readable = self._select_readable(handler, stdin_fd)
            self._poll_nfqueue(handler, readable)
            stdin_buf = self._poll_stdin(handler, stdin_buf, readable)
            if stdin_buf is None:
                break
            self._sweep_timeouts(handler)
            self._maybe_refresh_domains()

    def _select_readable(self, handler: NfqueueHandler, stdin_fd: int) -> set[int]:
        """Run select() and return a set of ready file descriptors."""
        readable, _, _ = select.select([handler, stdin_fd], [], [], 1.0)
        return {r if isinstance(r, int) else r.fileno() for r in readable}

    def _poll_nfqueue(self, handler: NfqueueHandler, ready: set[int]) -> None:
        """Read queued packets if the NFQUEUE socket is ready."""
        if handler.fileno() in ready:
            for pkt in handler.poll():
                self._handle_queued(pkt)

    def _poll_stdin(self, handler: NfqueueHandler, buf: str, ready: set[int]) -> str | None:
        """Read and process stdin commands if stdin is ready."""
        if sys.stdin.fileno() not in ready:
            return buf
        return self._read_stdin(handler, buf)

    def _maybe_refresh_domains(self) -> None:
        """Refresh domain cache if the refresh interval has elapsed."""
        if time.monotonic() - self._last_domain_refresh > _DOMAIN_REFRESH_INTERVAL:
            self._refresh_domain_cache()

    def _handle_queued(self, pkt: QueuedPacket) -> None:
        """Process a newly queued packet: enrich, emit, track."""
        domain = self._ip_to_domain.get(pkt.dest, "")
        pending = _PendingPacket(packet=pkt, queued_at=time.monotonic(), domain=domain)
        self._pending[pkt.packet_id] = pending

        event: dict = {
            "type": "pending",
            "id": pkt.packet_id,
            "dest": pkt.dest,
            "port": pkt.port,
            "proto": pkt.proto,
        }
        if domain:
            event["domain"] = domain
        print(json.dumps(event, separators=(",", ":")), flush=True)

    def _read_stdin(self, handler: NfqueueHandler, buf: str) -> str | None:
        """Read available stdin data and process complete JSON lines.

        Returns updated buffer, or ``None`` if stdin was closed.
        """
        try:
            chunk = os.read(sys.stdin.fileno(), 4096).decode()
        except OSError:
            return buf
        if not chunk:
            return None  # EOF

        buf += chunk
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            line = line.strip()
            if line:
                self._process_command(handler, line)
        return buf

    def _process_command(self, handler: NfqueueHandler, line: str) -> None:
        """Parse and execute a single JSON verdict command."""
        try:
            cmd = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Ignoring invalid JSON on stdin")
            return

        if not isinstance(cmd, dict) or cmd.get("type") != "verdict":
            return

        packet_id = cmd.get("id")
        action = cmd.get("action")
        if not isinstance(packet_id, int) or isinstance(packet_id, bool):
            return
        if not isinstance(action, str):
            return
        action = action.lower()
        if action not in ("accept", "deny"):
            return

        pending = self._pending.pop(packet_id, None)
        if pending is None:
            return  # already timed out or unknown

        accept = action == "accept"
        handler.verdict(pending.packet.packet_id, accept=accept)
        ok = self._apply_verdict(pending, accept=accept)

        result: dict = {
            "type": "verdict_applied" if ok else "verdict_failed",
            "id": packet_id,
            "action": action,
            "dest": pending.packet.dest,
        }
        if pending.domain:
            result["domain"] = pending.domain
        print(json.dumps(result, separators=(",", ":")), flush=True)

    def _apply_verdict(self, pending: _PendingPacket, *, accept: bool) -> bool:
        """Persist the verdict to nft sets and state files.

        Returns True on success, False if the nft update failed.
        """
        ip = pending.packet.dest
        if accept:
            from .nft import add_elements_dual

            nft_cmd = add_elements_dual([ip])
        else:
            from .nft import add_deny_elements_dual

            nft_cmd = add_deny_elements_dual([ip])

        if nft_cmd and not self._nft_apply(nft_cmd):
            return False

        target = (
            state.live_allowed_path(self._state_dir) if accept else state.deny_path(self._state_dir)
        )
        _append_unique(target, ip)
        return True

    def _nft_apply(self, nft_cmd: str) -> bool:
        """Apply nft commands via nsenter.  Returns True on success."""
        for line in nft_cmd.strip().splitlines():
            parts = line.strip().split()
            if parts:
                try:
                    self._runner.nft_via_nsenter(self._container, *parts)
                except Exception:
                    logger.warning("Failed to apply nft command: %s", line)
                    return False
        return True

    def _sweep_timeouts(self, handler: NfqueueHandler) -> None:
        """Drop packets that have exceeded the verdict timeout."""
        now = time.monotonic()
        expired = [pid for pid, p in self._pending.items() if now - p.queued_at > self._timeout]
        for pid in expired:
            pending = self._pending.pop(pid)
            handler.verdict(pending.packet.packet_id, accept=False)
            event: dict = {
                "type": "verdict_timeout",
                "id": pid,
                "dest": pending.packet.dest,
                "port": pending.packet.port,
            }
            if pending.domain:
                event["domain"] = pending.domain
            print(json.dumps(event, separators=(",", ":")), flush=True)

    def _refresh_domain_cache(self) -> None:
        """Refresh IP→domain cache from the dnsmasq query log.

        Builds a fresh cache on each call so log rotation doesn't leave
        stale entries.  Called periodically during the select loop.
        """
        log_path = state.dnsmasq_log_path(self._state_dir)
        if not log_path.is_file():
            self._last_domain_refresh = time.monotonic()
            return
        new_map: dict[str, str] = {}
        try:
            for line in log_path.read_text().splitlines():
                m = _REPLY_RE.search(line)
                if m:
                    domain, ip = m.group(1).lower().rstrip("."), m.group(2)
                    new_map[ip] = domain
        except OSError:
            pass
        self._ip_to_domain = new_map
        self._last_domain_refresh = time.monotonic()


# ── Helpers ────────────────────────────────────────────


def _set_nonblocking(fd: int) -> None:
    """Set a file descriptor to non-blocking mode."""
    import fcntl

    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


def _append_unique(path: Path, value: str) -> None:
    """Append *value* to a newline-separated file if not already present."""
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = set(path.read_text().splitlines()) if path.is_file() else set()
    if value not in existing:
        with path.open("a") as f:
            f.write(f"{value}\n")


# ── Entry point ────────────────────────────────────────


def run_interactive(state_dir: Path, container: str, *, timeout: int = 5) -> None:
    """Start the interactive NFQUEUE verdict handler.

    Validates that interactive mode is enabled for this container,
    then enters the verdict loop.  Blocks until SIGINT/SIGTERM or
    stdin EOF.

    Args:
        state_dir: Per-container state directory.
        container: Container name.
        timeout: Seconds before auto-dropping queued packets.

    Raises:
        SystemExit: If interactive mode is not enabled or NFQUEUE
            cannot be bound.
    """
    if not interactive_path(state_dir).is_file():
        print("Error: interactive mode is not enabled for this container.", file=sys.stderr)
        raise SystemExit(1)

    runner = SubprocessRunner()
    session = InteractiveSession(
        runner=runner,
        state_dir=state_dir,
        container=container,
        timeout=timeout,
    )
    session.run()
