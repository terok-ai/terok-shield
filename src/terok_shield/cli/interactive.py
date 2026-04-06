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

# Needed for forward-referencing SessionIO in InteractiveSession annotations.
# Remove once we target Python 3.14+ (PEP 649 makes evaluation lazy by default).
from __future__ import annotations

import json
import logging
import os
import select
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..core import state
from ..core.nft import add_deny_elements_dual, add_elements_dual
from ..core.run import CommandRunner, SubprocessRunner
from ..lib.watchers import DomainCache, NflogWatcher, WatchEvent

logger = logging.getLogger(__name__)

# Environment variables for the nsenter re-exec handshake.
_NSENTER_ENV = "_TEROK_SHIELD_NFLOG_NSENTER"
_RAW_ENV = "_TEROK_SHIELD_NFLOG_RAW"

# How often (seconds) to refresh the domain cache from the dnsmasq log.
_DOMAIN_REFRESH_INTERVAL = 10.0


# ── Entry point ──────────────────────────────────────────


def run_interactive(state_dir: Path, container: str, *, raw: bool = False) -> None:
    """Start the interactive NFLOG handler for a container.

    The NFLOG netlink socket must be inside the container's network
    namespace to receive packets logged by nft rules.  On first
    invocation, re-execs via ``podman unshare nsenter`` into the
    container's netns.  The re-exec sets ``_TEROK_SHIELD_NFLOG_NSENTER``
    so the second invocation runs the handler directly.

    The terminal deny rule always logs with the BLOCKED prefix to
    NFLOG group 100, so the interactive handler works for any shielded
    container without special configuration.

    Args:
        state_dir: Per-container state directory (may be relative).
        container: Container name.
        raw: If ``True``, use JSON-lines protocol; otherwise use the
            human-friendly CLI (default).
    """
    state_dir = state_dir.resolve()

    if os.environ.get(_NSENTER_ENV) != "1":
        _nsenter_reexec(state_dir, container, raw=raw)
        return

    io: SessionIO = JsonSessionIO() if raw else CliSessionIO()
    runner = SubprocessRunner()
    session = InteractiveSession(runner=runner, state_dir=state_dir, container=container, io=io)
    session.run()


def _main() -> None:
    """CLI entry point for ``python -m terok_shield.cli.interactive``."""
    if len(sys.argv) != 3:
        print(
            f"Usage: {sys.executable} -m terok_shield.cli.interactive <state_dir> <container>",
            file=sys.stderr,
        )
        raise SystemExit(2)
    raw = os.environ.get(_RAW_ENV) == "1"
    run_interactive(Path(sys.argv[1]), sys.argv[2], raw=raw)


# ── Interactive session ──────────────────────────────────


@dataclass
class _PendingPacket:
    """A packet awaiting an interactive verdict."""

    dest: str
    port: int
    proto: int
    queued_at: float
    domain: str = ""
    packet_id: int = 0


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
        io: SessionIO | None = None,
    ) -> None:
        """Initialise the session.

        Args:
            runner: Command runner for nft operations.
            state_dir: Per-container state directory.
            container: Container name (for nft nsenter).
            io: I/O protocol implementation (defaults to :class:`JsonSessionIO`).
        """
        self._runner = runner
        self._state_dir = state_dir
        self._container = container
        self._io: SessionIO = io if io is not None else JsonSessionIO()
        self._domain_cache = DomainCache(state_dir)

        self._seen_ips: set[str] = set()
        self._pending_by_ip: dict[str, _PendingPacket] = {}
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

        self._io.emit_banner()

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
            if time.monotonic() - self._last_domain_refresh > _DOMAIN_REFRESH_INTERVAL:
                self._domain_cache.refresh()
                self._last_domain_refresh = time.monotonic()

            try:
                readable, _, _ = select.select([watcher, stdin_fd], [], [], 1.0)
            except (OSError, ValueError):
                break

            fds = _readable_fds(readable)
            if watcher.fileno() in fds:
                self._drain_watcher(watcher)
            if stdin_fd in fds:
                result = self._read_stdin(buf)
                if result is None:
                    break
                buf = result

    def _drain_watcher(self, watcher: NflogWatcher) -> None:
        """Process all pending NFLOG events from the watcher.

        Args:
            watcher: The NFLOG netlink watcher to drain.
        """
        for event in watcher.poll():
            if event.action == "queued_connection" and event.dest:
                self._handle_nflog_event(event)

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
        domain = self._domain_cache.lookup(ip)
        if not domain:
            self._domain_cache.refresh()
            domain = self._domain_cache.lookup(ip)
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

        self._io.emit_pending(packet_id, ip, event.port, event.proto, domain)

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
        """Parse and execute a single command from stdin.

        Delegates parsing to the :class:`SessionIO` implementation, then
        looks up the pending packet, applies the verdict, and emits the
        result.

        Args:
            line: A single line of operator input.
        """
        parsed = self._io.parse_command(line)
        if parsed is None:
            return

        verdict_id, action = parsed

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

        # Consume the entry on success; keep it for retry on failure.
        if ok:
            self._pending_by_ip.pop(pending.dest, None)

        self._io.emit_verdict_applied(verdict_id, pending.dest, action, ok=ok)

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
            # Only use timeout 0s (permanent) when allow sets have timeout flags
            # (dnsmasq tier).  In dig/getent tier the sets lack timeout support
            # and 'timeout 0s' would be rejected by nft.
            permanent = self._is_dnsmasq_tier()
            nft_cmd = add_elements_dual([ip], permanent=permanent)
        else:
            nft_cmd = add_deny_elements_dual([ip])

        if nft_cmd and not self._nft_apply(nft_cmd):
            return False

        # Persist to state files.
        if accept:
            _append_unique(state.live_allowed_path(self._state_dir), ip)
            if pending.domain and self._is_dnsmasq_tier():
                self._allow_domain(pending.domain)
        else:
            _append_unique(state.deny_path(self._state_dir), ip)
            if pending.domain and self._is_dnsmasq_tier():
                self._deny_domain(pending.domain)

        return True

    def _allow_domain(self, domain: str) -> None:
        """Add domain to dnsmasq config and signal reload.

        Delegates to :func:`dnsmasq.add_domain` which persists to
        ``live.domains`` and removes from ``denied.domains``.  A SIGHUP
        makes the change take effect immediately — future DNS resolutions
        for *domain* auto-populate the nft allow sets.
        """
        from ..core import dnsmasq

        if not dnsmasq.add_domain(self._state_dir, domain):
            return
        self._reload_dnsmasq()

    def _deny_domain(self, domain: str) -> None:
        """Remove domain from dnsmasq config and signal reload.

        Counterpart of :meth:`_allow_domain`.  Stops dnsmasq from
        auto-populating nft sets for *domain* on future DNS queries.
        """
        from ..core import dnsmasq

        if not dnsmasq.remove_domain(self._state_dir, domain):
            return
        self._reload_dnsmasq()

    def _reload_dnsmasq(self) -> None:
        """Regenerate dnsmasq config and send SIGHUP."""
        from ..core import dnsmasq

        try:
            upstream = state.upstream_dns_path(self._state_dir).read_text().strip()
        except OSError:
            logger.warning("Cannot reload dnsmasq: upstream DNS not persisted")
            return
        domains = dnsmasq.read_merged_domains(self._state_dir)
        try:
            dnsmasq.reload(self._state_dir, upstream, domains)
        except RuntimeError:
            logger.exception("dnsmasq reload failed")

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

    def _is_dnsmasq_tier(self) -> bool:
        """Return True when the container uses the dnsmasq DNS tier."""
        tier_path = state.dns_tier_path(self._state_dir)
        try:
            return tier_path.is_file() and tier_path.read_text().strip() == "dnsmasq"
        except OSError:
            return False


# ── I/O protocol ─────────────────────────────────────────


@runtime_checkable
class SessionIO(Protocol):
    """I/O protocol for the interactive session.

    Decouples rendering and parsing from the verdict engine so the same
    :class:`InteractiveSession` can drive both machine-readable JSON-lines
    (``--raw``) and human-friendly CLI output.
    """

    def emit_pending(self, packet_id: int, dest: str, port: int, proto: int, domain: str) -> None:
        """Emit a pending-connection event to the operator."""
        ...

    def emit_verdict_applied(self, verdict_id: int, dest: str, action: str, *, ok: bool) -> None:
        """Emit a verdict-applied confirmation."""
        ...

    def parse_command(self, line: str) -> tuple[int, str] | None:
        """Parse one line of operator input into *(packet_id, action)*.

        Returns ``None`` when the line is invalid or unparseable.
        """
        ...

    def emit_banner(self) -> None:
        """Print a startup banner (no-op for machine protocols)."""
        ...


class JsonSessionIO:
    """JSON-lines session I/O — machine-readable protocol.

    Emits compact JSON objects (one per line) and expects JSON verdict
    commands on stdin.  This is the original protocol from PR #162.
    """

    def emit_pending(self, packet_id: int, dest: str, port: int, proto: int, domain: str) -> None:
        """Emit a pending event as a JSON line."""
        out = {
            "type": "pending",
            "id": packet_id,
            "dest": dest,
            "port": port,
            "proto": proto,
            "domain": domain,
        }
        print(json.dumps(out, separators=(",", ":")), flush=True)

    def emit_verdict_applied(self, verdict_id: int, dest: str, action: str, *, ok: bool) -> None:
        """Emit a verdict-applied confirmation as a JSON line."""
        out = {
            "type": "verdict_applied",
            "id": verdict_id,
            "dest": dest,
            "action": action,
            "ok": ok,
        }
        print(json.dumps(out, separators=(",", ":")), flush=True)

    def parse_command(self, line: str) -> tuple[int, str] | None:
        """Parse a JSON verdict command.

        Expected format: ``{"type": "verdict", "id": 1, "action": "accept"}``.
        Returns ``(id, action)`` on success or ``None`` on any validation failure.
        """
        try:
            cmd = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Invalid JSON on stdin: %s", line)
            return None
        if not isinstance(cmd, dict):
            logger.warning("Expected JSON object, got %s", type(cmd).__name__)
            return None
        if cmd.get("type") != "verdict":
            logger.warning("Unknown command type: %s", cmd.get("type"))
            return None
        verdict_id = cmd.get("id")
        if isinstance(verdict_id, bool) or not isinstance(verdict_id, int):
            logger.warning("Verdict id must be an integer, got %r", verdict_id)
            return None
        action = cmd.get("action")
        if action not in ("accept", "deny"):
            logger.warning("Verdict action must be 'accept' or 'deny', got %r", action)
            return None
        return (verdict_id, action)

    def emit_banner(self) -> None:
        """No-op — machine protocol has no banner."""


# Mapping of human-friendly input to canonical action names.
_INPUT_MAP: dict[str, str] = {
    "a": "accept",
    "allow": "accept",
    "d": "deny",
    "deny": "deny",
}


class CliSessionIO:
    """Human-friendly interactive CLI session I/O.

    Renders blocked connections as readable lines and accepts short
    operator input (``a``/``d`` or ``allow``/``deny``).  Pending packets
    are tracked in a FIFO queue — input always targets the oldest.
    """

    def __init__(self) -> None:
        """Initialise with empty pending-packet queues."""
        self._queue: list[int] = []
        """FIFO of pending packet IDs awaiting a verdict."""

        self._info: dict[int, tuple[str, int, str]] = {}
        """Packet metadata: *id* → *(dest, port, domain)*."""

    def _prompt_head(self) -> None:
        """Print the allow/deny prompt for the head-of-queue packet."""
        if not self._queue:
            return
        info = self._info.get(self._queue[0])
        if info is None:
            return
        dest, port, domain = info
        label = f"{dest} ({domain})" if domain else dest
        print(f"[BLOCKED] {label} :{port} \u2014 allow/deny? ", end="", flush=True)

    def emit_pending(self, packet_id: int, dest: str, port: int, proto: int, domain: str) -> None:
        """Show a ``[BLOCKED]`` line and queue the packet for verdict."""
        label = f"{dest} ({domain})" if domain else dest
        self._queue.append(packet_id)
        self._info[packet_id] = (dest, port, domain)
        if len(self._queue) == 1:
            self._prompt_head()
        else:
            # Additional pending while the operator is thinking.
            print(f"\n[BLOCKED] {label} :{port} (queued)", flush=True)
            self._prompt_head()

    def emit_verdict_applied(self, verdict_id: int, dest: str, action: str, *, ok: bool) -> None:
        """Show verdict result and prompt the next queued packet if any.

        On success the packet is removed from the queue.  On failure it
        stays queued so the operator can retry with the same ``a``/``d``
        input (mirrors :meth:`InteractiveSession._process_command` which
        keeps failed verdicts in ``_pending_by_ip``).
        """
        info = self._info.get(verdict_id)
        target = info[2] if info and info[2] else dest
        if ok:
            self._info.pop(verdict_id, None)
            if verdict_id in self._queue:
                self._queue.remove(verdict_id)
            mark = "\u2713" if action == "accept" else "\u2717"
            verb = "allowed" if action == "accept" else "denied"
            print(f"  {mark} {verb} {target}")
        else:
            print(f"  ! verdict failed for {target} (retry with a/d)")
        self._prompt_head()

    def parse_command(self, line: str) -> tuple[int, str] | None:
        """Map operator input to the oldest pending packet.

        Accepts ``a``, ``d``, ``allow``, ``deny`` (case-insensitive).
        Returns ``None`` and prints a hint on unrecognised input.
        """
        action = _INPUT_MAP.get(line.strip().lower())
        if action is None:
            print("  Unknown input. Type 'a' to allow or 'd' to deny.", flush=True)
            self._prompt_head()
            return None
        if not self._queue:
            return None
        return (self._queue[0], action)

    def emit_banner(self) -> None:
        """Print a startup message."""
        print("Watching for blocked connections... (Ctrl-C to stop)\n", flush=True)


# ── nsenter re-exec ──────────────────────────────────────


def _nsenter_reexec(state_dir: Path, container: str, *, raw: bool) -> None:
    """Re-exec the interactive handler inside the container's network namespace.

    NFLOG messages are delivered per-netns — the watcher must be inside the
    container's netns to receive packets logged by its nft rules.  Uses
    ``podman unshare nsenter -t PID -n`` to enter the netns, then runs this
    module as ``__main__``.

    Args:
        state_dir: Per-container state directory.
        container: Container name.
        raw: Whether to use raw JSON-lines protocol.
    """
    import subprocess

    runner = SubprocessRunner()
    pid = runner.podman_inspect(container, "{{.State.Pid}}")

    cmd = [
        "podman",
        "unshare",
        "nsenter",
        "-t",
        pid,
        "-n",
        sys.executable,
        "-m",
        "terok_shield.cli.interactive",
        str(state_dir),
        container,
    ]
    env = {**os.environ, _NSENTER_ENV: "1"}
    if raw:
        env[_RAW_ENV] = "1"
    else:
        env.pop(_RAW_ENV, None)
    try:
        subprocess.run(cmd, env=env, check=True)  # noqa: S603
    except subprocess.CalledProcessError as e:
        raise SystemExit(e.returncode) from e


# ── Helpers ──────────────────────────────────────────────

# Module-level stop flag, set by signal handler.
_running = True


def _handle_signal(_signum: int, _frame: object) -> None:
    """Set the module-level stop flag on SIGINT/SIGTERM."""
    global _running  # noqa: PLW0603
    _running = False


def _readable_fds(readable: list) -> set[int]:
    """Extract file descriptor ints from a ``select.select()`` readable list.

    Handles both raw int fds and objects with a ``fileno()`` method.
    """
    return {r if isinstance(r, int) else r.fileno() for r in readable}


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


if __name__ == "__main__":
    _main()
