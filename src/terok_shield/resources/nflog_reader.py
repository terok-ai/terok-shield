#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Stream blocked-connection events out of one container for the clearance flow.

Subscribes to the kernel's NFLOG group inside a single container's network
namespace, deduplicates by destination IP, and publishes each unique block as
an event.  Events always travel as JSON; the reader itself never speaks
D-Bus.  Two destinations are supported:

* ``--emit=socket`` (default): write events to a unix socket served by the
  ``terok-clearance`` hub.  The hub lives in the *host* user namespace, where
  it can emit the matching ``org.terok.Shield1`` signals onto the session
  bus.  The reader itself is stuck inside ``NS_ROOTLESS`` (that's where
  the container netns lives) and the session ``dbus-daemon`` rejects its
  ``SO_PEERCRED`` check — so the reader can't emit D-Bus directly.

* ``--emit=json``: write events as JSON lines on stdout.  Drives the
  ``terok-shield simple-clearance`` terminal fallback, which runs in the
  operator's own userns and parses the stream directly.

The OCI bridge hook spawns one reader per shielded container at
``createRuntime`` and SIGTERMs it at ``poststop`` — the process tree is what
ties the reader's lifetime to the container's.

Stdlib-only by design: shipped as a resource that ``/usr/bin/python3`` can
execute anywhere without depending on the terok-shield virtual environment.
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import logging
import os
import re
import select
import shutil
import signal
import socket
import struct
import subprocess  # nosec B404 — podman/nsenter re-exec for container netns
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

_log = logging.getLogger("terok-shield.nflog-reader")

# ── Protocol constants duplicated from terok-shield core ──────────────
# The script is standalone so it cannot import from the package.  Keep in sync
# with the canonical definitions:
#   NFLOG_GROUP           ↔ terok_shield.nft.constants.NFLOG_GROUP
#   _BLOCKED_PREFIX_TAG   ↔ terok_shield.nft.rules nflog prefix for the
#                           interactive deny rule
NFLOG_GROUP = 100
_BLOCKED_PREFIX_TAG = "BLOCKED"

#: Reserved dossier key — the *orchestrator-side* path to the per-container
#: meta JSON.  Read by the reader as plumbing; never appears on the wire or
#: in the audit log.  ``_resolve_dossier`` strips it from any dict it merges.
_META_PATH_KEY = "meta_path"

# ── nsenter handshake ─────────────────────────────────────────────────
# Re-exec sets this so the second invocation knows it's already inside
# the container netns and skips the podman-unshare dance.
_NSENTER_ENV = "_TEROK_SHIELD_NFLOG_NSENTER"

# ── Linux netlink / nflog wire format ─────────────────────────────────
# From linux/netfilter/nfnetlink.h and linux/netfilter/nfnetlink_log.h.
_NETLINK_NETFILTER = 12
_NFNL_SUBSYS_ULOG = 4
_NFULNL_MSG_CONFIG = 1
_NFULNL_MSG_PACKET = 0
_NFULNL_CFG_CMD_BIND = 1
_NFULA_PREFIX = 10
_NFULA_PAYLOAD = 9
_NLM_F_REQUEST = 1
_NLM_F_ACK = 4
_AF_INET = 2
_IPPROTO_TCP = 6
_IPPROTO_UDP = 17

#: Human-readable protocol names for audit entries.  Numeric IP protocol
#: numbers leak in for anything outside TCP/UDP — rare in practice (ICMP
#: is suppressed earlier as noise) but better than a misleading "tcp" label.
_PROTO_NAMES: dict[int, str] = {_IPPROTO_TCP: "tcp", _IPPROTO_UDP: "udp"}

_NLMSG_HDR = struct.Struct("=IHHII")
_NFGEN_HDR = struct.Struct("=BBH")
_NFULNL_CFG_CMD = struct.Struct("=BBH")
_NFA_HDR = struct.Struct("=HH")


Dossier = dict[str, str]
"""Orchestrator-supplied identity bundle resolved at emit time.

Keys are the orchestrator's contract — terok publishes ``project``,
``task``, ``name``, etc. under the ``dossier.*`` OCI annotation
namespace, but the reader treats the dict as opaque payload and
forwards whatever keys it sees.  An empty dossier is the
shield-only-deployment shape; the consumer renders the bare
container short-id in that case.
"""


@dataclass(frozen=True)
class BlockedEvent:
    """A packet the kernel dropped at the interactive-deny rule — one per unique dest IP."""

    container: str
    request_id: str
    dest: str
    port: int
    proto: int
    domain: str
    dossier: Dossier = field(default_factory=dict)


# ── Entry point ───────────────────────────────────────────────────────


def main() -> None:  # pragma: no cover — real argparse + subprocess re-exec
    """Parse arguments, cross into the container netns if needed, and run the loop.

    On first entry (``_TEROK_SHIELD_NFLOG_NSENTER`` unset) this process re-execs
    itself under ``nsenter`` — with ``podman unshare`` prepended when we're not
    already in ``NS_ROOTLESS`` — so the NFLOG bind happens in the container's
    netns.  The re-exec carries the same ``--emit`` and ``--annotations`` choice
    forward, so the destination (unix socket or stdout JSON) and the orchestrator
    dossier stay whatever the caller picked.
    """
    args = _parse_args()
    logging.basicConfig(level=logging.INFO, format="nflog-reader: %(message)s")

    if os.environ.get(_NSENTER_ENV) != "1":
        _reexec_inside_container_netns(
            args.state_dir, args.container, args.emit, args.annotations_raw
        )
        return

    emitter = _select_emitter(args.emit)
    session = ReaderSession(
        state_dir=args.state_dir,
        container=args.container,
        emitter=emitter,
        static_dossier=args.annotations,
    )
    try:
        session.run()
    finally:
        emitter.close()


def _select_emitter(mode: str) -> EventEmitter:
    """Pick the emitter matching ``--emit`` — socket by default, JSON for the CLI."""
    if mode == "json":
        return JsonEmitter()
    return SocketEmitter(_events_socket_path())


def _events_socket_path() -> Path:
    """Return the canonical hub-ingester socket path (mirrors ``terok_clearance``)."""
    xdg = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return Path(xdg) / "terok-shield-events.sock"


# ── nsenter re-exec ───────────────────────────────────────────────────
#
# ``main()``'s first branch hands off here.  Grouping the three helpers
# with ``main`` keeps the whole re-exec stanza on one page; the reader
# loop below doesn't need any of them.


def _reexec_inside_container_netns(
    state_dir: Path, container: str, emit: str, annotations_raw: str
) -> None:  # pragma: no cover — real subprocess re-exec
    """Re-enter this script inside the container's netns so NFLOG is reachable.

    When we're already in ``NS_ROOTLESS`` (uid 0 inside the rootless userns
    — the normal hook execution context), plain ``nsenter -n`` is enough.
    When we're in the initial userns (a manual CLI run), prepend
    ``podman unshare`` to cross into ``NS_ROOTLESS`` first and pick up
    ``CAP_SYS_ADMIN`` over the container-owning userns.

    ``annotations_raw`` is forwarded verbatim — keeping the JSON exactly as it
    arrived avoids one round of dict→JSON re-encoding (and the dict-key-order
    drift it would inflict on the cmdline that ``_is_our_reader`` later compares
    against).
    """
    pid = _podman_container_pid(container)
    script = Path(__file__).resolve()
    podman = _resolve_binary("podman")
    nsenter = _resolve_binary("nsenter")
    python3 = _resolve_binary("python3")
    tail = [
        python3,
        str(script),
        str(state_dir),
        container,
        f"--emit={emit}",
        f"--annotations={annotations_raw}",
    ]
    cmd = (
        [nsenter, "-t", pid, "-n", *tail]
        if os.geteuid() == 0
        else [podman, "unshare", nsenter, "-t", pid, "-n", *tail]
    )
    env = {**os.environ, _NSENTER_ENV: "1"}
    try:
        # argv is built from our own resolved binary paths and integer-like
        # container PIDs; no shell involvement.
        subprocess.run(cmd, env=env, check=True)  # noqa: S603  # nosec B603
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode) from exc


def _podman_container_pid(container: str) -> str:  # pragma: no cover — real podman subprocess
    """Resolve a container's host PID so nsenter can target its network namespace."""
    podman = _resolve_binary("podman")
    # argv is a fixed literal plus the caller-supplied container name; no
    # shell involvement.
    result = subprocess.run(  # noqa: S603  # nosec B603
        [podman, "inspect", "--format", "{{.State.Pid}}", container],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _resolve_binary(name: str) -> str:
    """Return the absolute path to *name* or fall back to ``/usr/bin/<name>``.

    Turns a partial executable name into a full path so Sonar's "starting a
    process with a partial executable path" rule is satisfied — and so the
    subprocess actually resolves the binary against a known PATH rather than
    whatever the caller's env happened to have.  Fallback to ``/usr/bin/<name>``
    keeps the reader working on minimal images where PATH isn't inherited.
    """
    return shutil.which(name) or f"/usr/bin/{name}"


# ── Session ───────────────────────────────────────────────────────────

#: IPv6 link-local multicast — MLD, router / neighbor discovery, mDNS.
#: The kernel and systemd emit these routinely; the shield correctly
#: blocks them but the operator has no useful decision to make, so the
#: reader drops them before dedup / emit.  See polish backlog.
_IPV6_LINK_LOCAL_MULTICAST = ipaddress.IPv6Network("ff02::/16")


def _is_noise_dest(dest: str) -> bool:
    """Return True for traffic the clearance flow should silently drop."""
    try:
        addr = ipaddress.ip_address(dest)
    except ValueError:
        return False
    return isinstance(addr, ipaddress.IPv6Address) and addr in _IPV6_LINK_LOCAL_MULTICAST


class ReaderSession:
    """Orchestrates the container's block-event stream for the clearance flow.

    Owns the NFLOG socket, a rolling dedup window, the domain cache, and the
    signal handler.  Lives for the container's lifetime: emits
    ``ContainerStarted`` on open, streams ``ConnectionBlocked`` for each
    unique block within a dedup window, and emits ``ContainerExited`` on
    SIGTERM or NFLOG close.

    The dedup key is the *domain* when the reader has one cached from the
    per-container dnsmasq log, otherwise the raw destination IP.  That means
    a multi-A-record name like ``example.com → 1.1.1.1 + 1.0.0.1`` collapses
    to one prompt rather than two — which matches the operator's mental
    model ("do I allow example.com?"), not the kernel's ("two distinct
    packets went to two IPs").

    The dedup window rate-limits retries within a single application's
    attempt (TCP SYN retransmits, wget's own retries, etc.) without
    suppressing legitimate re-attempts after the operator has actually seen
    and dismissed the first notification.  Notification-level dedup
    (replacing still-visible notifications) belongs to the notifier.
    """

    #: Seconds for which a dedup key stays muted after one emission.  Short
    #: enough that the operator can re-trigger a block and get a fresh
    #: notification when the previous one auto-dismissed; long enough that a
    #: single wget retry burst doesn't produce a pile of duplicate signals.
    _DEDUP_WINDOW_S = 30.0

    def __init__(
        self,
        *,
        state_dir: Path,
        container: str,
        emitter: EventEmitter,
        static_dossier: Dossier | None = None,
    ) -> None:
        """Prepare the session; the socket is opened in [`run`][terok_shield.resources.nflog_reader.ReaderSession.run].

        ``static_dossier`` is the orchestrator-supplied identity bundle pulled
        out of the container's ``dossier.*`` annotations at hook spawn time —
        ``container_name``, ``project``, ``task``, and ``meta_path`` are the
        keys terok itself uses, but the reader treats the dict as opaque.  A
        ``meta_path`` entry, when present, points at a JSON file the reader
        will re-read at every emit so name-changes (e.g. podman rename) and
        late-bound metadata land on the wire without restarting the reader.
        """
        self._state_dir = state_dir
        self._container = container
        self._emitter = emitter
        self._static_dossier = dict(static_dossier or {})
        meta_path = self._static_dossier.get(_META_PATH_KEY)
        self._meta_path: Path | None = Path(meta_path) if meta_path else None
        # Precomputed static floor — meta_path stripped, since it never
        # leaks onto the wire.  Recomputing the comprehension on every
        # emit would be tiny but is on the per-NFLOG-packet hot path.
        self._static_dossier_floor: Dossier = {
            k: v for k, v in self._static_dossier.items() if k != _META_PATH_KEY
        }
        self._domain_cache = _DomainCache(state_dir)
        # Two independent dedup windows, both keyed on (domain or dest):
        #
        # * ``_last_emit`` rate-limits *wire* delivery — only updated when
        #   the hub accepts the event, so a hub-down period leaves the
        #   key un-marked and the next NFLOG packet retries the emit.
        # * ``_last_audit`` rate-limits *audit-log* writes — updated when
        #   the JSONL append succeeds, so a hub outage doesn't flood
        #   ``audit.jsonl`` with one entry per TCP-retransmit.
        #
        # Splitting them is what keeps the audit-volume bound honest
        # ("one entry per (container, dest) per ``_DEDUP_WINDOW_S``")
        # without giving up the wire's retry-on-failure semantics.
        self._last_emit: dict[str, float] = {}
        self._last_audit: dict[str, float] = {}
        self._next_id = 1
        self._stop_requested = False

    def run(self) -> None:
        """Enter the reader loop until SIGTERM/SIGINT or NFLOG closes."""
        sock = _open_nflog_socket(NFLOG_GROUP)
        if sock is None:
            _log.warning("could not open NFLOG socket — skipping clearance stream")
            return

        self._install_signal_handlers()
        self._emitter.container_started(self._container)
        try:
            self._loop(sock)
        finally:
            sock.close()
            self._emitter.container_exited(self._container, reason=self._exit_reason())

    def _loop(self, sock: socket.socket) -> None:
        """Read NFLOG messages, dedupe per rolling window, emit one signal per hit."""
        self._domain_cache.refresh()
        while not self._stop_requested:
            try:
                readable, _, _ = select.select([sock], [], [], 1.0)
            except (OSError, ValueError):
                return
            if sock not in readable:
                continue
            now = time.monotonic()
            for event in _drain(sock):
                self._maybe_emit(event, now)

    def _maybe_emit(self, event: _RawBlockEvent, now: float) -> None:
        """Filter noise, dedupe by domain-or-dest, emit if fresh.

        The wire dedup key (``_last_emit``) is only mutated once the
        emit actually reaches the hub.  Marking before the emit would
        poison the 30-s window when the write fails (hub restarted,
        socket unreachable, …), silently suppressing retries even
        though the operator never saw a popup for the first attempt.

        Audit dedup is independent (``_last_audit``): it's marked
        whenever the JSONL append succeeds, regardless of whether the
        wire emit lands.  Without this split, a hub outage would
        re-trigger ``_emit_connection_blocked`` every NFLOG packet
        (because ``_last_emit`` stays unmarked), and *each* of those
        retries would currently re-write the same ``"blocked"`` line
        to ``audit.jsonl`` — flooding the forensic log during the
        very window where it's least helpful.

        Dossier resolution happens once per fresh tick; both the audit
        line and the wire payload see the same snapshot, and a renamed
        container won't appear differently on either side of the same
        block.
        """
        if _is_noise_dest(event.dest):
            return
        domain = self._resolve_domain(event.dest)
        dedup_key = domain or event.dest
        last_emit = self._last_emit.get(dedup_key)
        last_audit = self._last_audit.get(dedup_key)
        emit_fresh = last_emit is None or (now - last_emit) >= self._DEDUP_WINDOW_S
        audit_fresh = last_audit is None or (now - last_audit) >= self._DEDUP_WINDOW_S
        if not emit_fresh and not audit_fresh:
            return
        dossier = self._resolve_dossier()
        if audit_fresh and self._append_audit_block(event, domain, dossier):
            self._last_audit[dedup_key] = now
        if emit_fresh:
            request_id = f"{self._container}:{self._next_id}"
            self._next_id += 1
            if self._emit_connection_blocked(event, domain, request_id, dossier):
                self._last_emit[dedup_key] = now

    def _resolve_domain(self, dest: str) -> str:
        """Look *dest* up in the domain cache, refreshing once on miss."""
        domain = self._domain_cache.lookup(dest)
        if not domain:
            self._domain_cache.refresh()
            domain = self._domain_cache.lookup(dest)
        return domain

    def _emit_connection_blocked(
        self,
        event: _RawBlockEvent,
        domain: str,
        request_id: str,
        dossier: Dossier,
    ) -> bool:
        """Publish one ``ConnectionBlocked`` for *event* — caller supplies the domain.

        Audit-vs-wire dedup is split: ``_maybe_emit`` decides
        independently whether each side should fire and tracks them
        in separate windows (``_last_audit`` / ``_last_emit``).  This
        method handles only the wire half.

        Returns ``True`` when the emitter accepted the event; ``False``
        when it was dropped (socket emitter: hub unreachable).  Callers
        use the result to decide whether to mark the wire dedup window.
        """
        return self._emitter.connection_blocked(
            BlockedEvent(
                container=self._container,
                request_id=request_id,
                dest=event.dest,
                port=event.port,
                proto=event.proto,
                domain=domain,
                dossier=dossier,
            )
        )

    def _resolve_dossier(self) -> Dossier:
        """Merge the orchestrator's wire-dossier JSON file into the static floor.

        Static ``dossier.*`` annotations from the OCI state form a
        floor (mostly relevant for standalone containers without a
        meta-file orchestrator).  When ``dossier.meta_path`` was
        supplied, the file at that path *is* the wire dossier — same
        keys the clearance UI renders, JSON dict-of-strings, no
        projection — re-read on every emit so podman rename /
        late-bound naming propagate without a reader restart.

        Soft-fail at every step — missing file, EACCES, malformed JSON,
        non-object payload — drops back to the static floor rather
        than dropping the event.
        """
        dossier = dict(self._static_dossier_floor)
        if self._meta_path is None:
            return dossier
        try:
            decoded = json.loads(self._meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return dossier
        if not isinstance(decoded, dict):
            return dossier
        for key, value in decoded.items():
            if value:
                dossier[str(key)] = str(value)
        return dossier

    def _append_audit_block(self, event: _RawBlockEvent, domain: str, dossier: Dossier) -> bool:
        """Write one ``"action": "blocked"`` entry to ``state_dir/audit.jsonl``.

        Inlined (rather than importing ``terok_shield.audit.AuditLogger``)
        because the reader script is shipped as a stdlib-only resource —
        keeping the dependency surface flat preserves the
        ``/usr/bin/python3``-can-run-it invariant.  Concurrent appends
        with the host-side shield's own ``log_event`` writer are safe
        for short JSON lines (atomic up to PIPE_BUF on Linux), so the
        timeline interleaves cleanly without locks.

        Returns ``True`` on a successful append, ``False`` on any
        ``OSError``.  Soft-fail behaviour is preserved (callers do
        nothing on a ``False`` return), but the failure is logged at
        ``WARNING`` so a sudden silence in ``audit.jsonl`` doesn't
        disappear into DEBUG noise on a host where the default log
        level is INFO — see ``terok_shield.audit.AuditLogger``'s
        host-side path for the same posture.

        The optional ``dossier`` field carries whatever orchestrator
        identity the wire event also got — present only when non-empty
        so shield-only deployments don't pad audit rows with ``{}``.
        """
        entry = {
            "ts": datetime.now(UTC).isoformat(timespec="seconds"),
            "container": self._container,
            "action": "blocked",
            "dest": event.dest,
            "port": event.port,
            "proto": _PROTO_NAMES.get(event.proto, str(event.proto)),
        }
        if domain:
            entry["domain"] = domain
        if dossier:
            entry["dossier"] = dossier
        line = json.dumps(entry, separators=(",", ":")) + "\n"
        path = self._state_dir / "audit.jsonl"
        try:
            with path.open("a", encoding="utf-8") as f:
                f.write(line)
        except OSError as exc:
            _log.warning("audit append failed (%s): %s", path, exc)
            return False
        return True

    def _install_signal_handlers(self) -> None:
        """Arrange a clean shutdown on SIGTERM / SIGINT."""
        signal.signal(signal.SIGTERM, self._on_stop_signal)
        signal.signal(signal.SIGINT, self._on_stop_signal)

    def _on_stop_signal(self, _signum: int, _frame: object) -> None:
        """Flip the stop flag — the select loop picks it up on the next tick."""
        self._stop_requested = True

    def _exit_reason(self) -> str:
        """Describe why the loop left: intentional stop, or something else."""
        return "poststop" if self._stop_requested else "eof"


# ── Wire-payload builders ─────────────────────────────────────────────
#
# One canonical place for the JSON shape so the two emitters can't
# silently drift on a future field addition.


def _started_payload(container: str) -> dict:
    """Build the wire payload for a ``container_started`` lifecycle event."""
    return {"type": "container_started", "container": container}


def _exited_payload(container: str, reason: str) -> dict:
    """Build the wire payload for a ``container_exited`` lifecycle event."""
    return {"type": "container_exited", "container": container, "reason": reason}


def _pending_payload(event: BlockedEvent) -> dict:
    """Build the wire payload for a blocked-connection (``pending``) event."""
    return {
        "type": "pending",
        "container": event.container,
        "id": event.request_id,
        "dest": event.dest,
        "port": event.port,
        "proto": event.proto,
        "domain": event.domain,
        "dossier": event.dossier,
        "ts": datetime.now(UTC).isoformat(),
    }


# ── Emission strategies ───────────────────────────────────────────────


class EventEmitter(Protocol):
    """The two publishing channels a reader can speak — hub socket or JSON stdout."""

    def container_started(self, container: str) -> None:
        """Publish a ``ContainerStarted`` lifecycle event."""
        ...

    def container_exited(self, container: str, *, reason: str) -> None:
        """Publish a ``ContainerExited`` lifecycle event."""
        ...

    def connection_blocked(self, event: BlockedEvent) -> bool:
        """Publish one unique-destination block event.

        Returns ``True`` if the event was successfully delivered,
        ``False`` if it was dropped (e.g. hub socket unreachable).
        """
        ...

    def close(self) -> None:
        """Release any held resources (sockets, file handles); no-op when stateless."""
        ...


class SocketEmitter:
    """Stream JSON events to the hub's unix-socket ingester.

    The hub owns the D-Bus bus name in host userns and re-emits the signals
    we feed it.  We only have the socket file to cross the userns boundary:
    ``dbus-send --session`` from ``NS_ROOTLESS`` is rejected by the session
    ``dbus-daemon``'s ``SO_PEERCRED`` check, but a plain AF_UNIX stream to
    the same user's runtime dir still works fine.

    Reconnect-on-failure lazily, so a hub restart doesn't kill the reader.
    A persistent missing hub is logged once and then silently swallowed —
    the NFLOG reader stays useful (counter, audit log) even when no hub is
    up to receive the events.
    """

    def __init__(self, path: Path) -> None:
        """Remember the socket path but don't connect until the first send."""
        self._path = path
        self._sock: socket.socket | None = None
        self._warned_unreachable = False

    def container_started(self, container: str) -> None:
        """Queue a ``container_started`` JSON event onto the hub socket."""
        self._send(_started_payload(container))

    def container_exited(self, container: str, *, reason: str) -> None:
        """Queue a ``container_exited`` JSON event onto the hub socket."""
        self._send(_exited_payload(container, reason))

    def connection_blocked(self, event: BlockedEvent) -> bool:
        """Queue a ``pending`` JSON event (block) onto the hub socket."""
        return self._send(_pending_payload(event))

    def close(self) -> None:
        """Disconnect from the hub socket if we're currently connected."""
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.close()
            self._sock = None

    def _ensure_connected(self) -> bool:
        """Lazily connect; return True on success, False when the hub is absent."""
        if self._sock is not None:
            return True
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(str(self._path))
        except OSError:
            # ConnectionError subclasses OSError — covered by the single catch.
            if not self._warned_unreachable:
                _log.warning("hub event socket unreachable at %s", self._path)
                self._warned_unreachable = True
            return False
        self._sock = sock
        self._warned_unreachable = False
        return True

    def _send(self, payload: dict) -> bool:
        """Serialise *payload* to a JSON line and push it to the hub socket.

        Returns ``True`` on successful send, ``False`` when the hub
        swallowed neither a fresh nor a reconnected attempt.  One
        reconnect is tried automatically: a hub restart leaves our
        cached socket fd dangling, so the first write fails with
        ``BrokenPipeError`` / ``ConnectionResetError``; reopening
        against the (now fresh) socket file lets the same event land
        on the new hub instead of being silently lost to
        ``_maybe_emit``'s dedup window.
        """
        line = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
        for attempt in (1, 2):
            if not self._ensure_connected() or self._sock is None:
                return False
            try:
                self._sock.sendall(line)
                return True
            except OSError as exc:
                # ConnectionError subclasses OSError — covered by the single catch.
                if attempt == 1:
                    _log.info("hub event socket needs reconnect: %s", exc)
                else:
                    _log.warning("hub event socket send failed: %s", exc)
                self.close()
        return False


class JsonEmitter:
    """Publish events as JSON lines on stdout — drives the terminal fallback CLI."""

    def container_started(self, container: str) -> None:
        """Emit a ``container_started`` JSON line."""
        _print_json(_started_payload(container))

    def container_exited(self, container: str, *, reason: str) -> None:
        """Emit a ``container_exited`` JSON line."""
        _print_json(_exited_payload(container, reason))

    def connection_blocked(self, event: BlockedEvent) -> bool:
        """Emit a ``pending`` JSON line carrying the full event payload."""
        _print_json(_pending_payload(event))
        # Stdout writes are effectively unfailable here; the fallback
        # CLI treats every emit as delivered.
        return True

    def close(self) -> None:
        """No-op — the JSON emitter holds no external state."""


# ── NFLOG socket / parsing ────────────────────────────────────────────


@dataclass(frozen=True)
class _RawBlockEvent:
    """Pre-enrichment fields pulled straight from one NFLOG packet."""

    dest: str
    port: int
    proto: int


def _open_nflog_socket(
    group: int,
) -> socket.socket | None:  # pragma: no cover — real AF_NETLINK socket
    """Bind an ``AF_NETLINK`` socket to *group*, or ``None`` if unavailable.

    Returns ``None`` in environments without NFLOG support (non-Linux, missing
    ``CAP_NET_ADMIN`` in the owning user namespace, kernel module absent).
    """
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, _NETLINK_NETFILTER)
        sock.bind((0, 0))
        sock.settimeout(2.0)
        sock.send(_build_bind_msg(group))
        ack = sock.recv(4096)
        if len(ack) >= _NLMSG_HDR.size + 4:
            err = struct.unpack_from("=i", ack, _NLMSG_HDR.size)[0]
            if err < 0:
                _log.warning("NFLOG bind rejected: %s", os.strerror(-err))
                sock.close()
                return None
        sock.setblocking(False)
        return sock
    except (OSError, AttributeError):
        if sock is not None:
            sock.close()
        return None


def _drain(sock: socket.socket) -> list[_RawBlockEvent]:  # pragma: no cover — real socket recv
    """Read every pending NFLOG message and extract its block events."""
    events: list[_RawBlockEvent] = []
    while True:
        try:
            data = sock.recv(65535)
        except OSError:
            break
        if not data:
            break
        events.extend(_parse_messages(data))
    return events


def _parse_messages(data: bytes) -> list[_RawBlockEvent]:
    """Pull ``BLOCKED``-prefixed packet events out of a netlink message batch."""
    events: list[_RawBlockEvent] = []
    offset = 0
    while offset + _NLMSG_HDR.size <= len(data):
        nl_len, nl_type, _flags, _seq, _pid = _NLMSG_HDR.unpack_from(data, offset)
        if nl_len < _NLMSG_HDR.size or offset + nl_len > len(data):
            break
        subsys = (nl_type >> 8) & 0xFF
        msg = nl_type & 0xFF
        if subsys == _NFNL_SUBSYS_ULOG and msg == _NFULNL_MSG_PACKET:
            attrs = _parse_attrs(data[offset + _NLMSG_HDR.size + _NFGEN_HDR.size : offset + nl_len])
            event = _attrs_to_event(attrs)
            if event is not None:
                events.append(event)
        offset += (nl_len + 3) & ~3
    return events


def _parse_attrs(data: bytes) -> dict[int, bytes]:
    """Unpack the TLV attribute section of one NFLOG packet message."""
    attrs: dict[int, bytes] = {}
    offset = 0
    while offset + _NFA_HDR.size <= len(data):
        nfa_len, nfa_type = _NFA_HDR.unpack_from(data, offset)
        if nfa_len < _NFA_HDR.size:
            break
        nfa_type &= 0x7FFF
        attrs[nfa_type] = data[offset + _NFA_HDR.size : offset + nfa_len]
        offset += (nfa_len + 3) & ~3
    return attrs


def _attrs_to_event(attrs: dict[int, bytes]) -> _RawBlockEvent | None:
    """Keep only ``BLOCKED``-prefixed packets; drop everything else."""
    prefix = attrs.get(_NFULA_PREFIX, b"").rstrip(b"\x00").decode("ascii", errors="replace")
    if _BLOCKED_PREFIX_TAG not in prefix:
        return None
    dest, proto, port = _extract_ip_dest(attrs.get(_NFULA_PAYLOAD, b""))
    if not dest:
        return None
    return _RawBlockEvent(dest=dest, port=port, proto=proto)


def _extract_ip_dest(payload: bytes) -> tuple[str, int, int]:
    """Pick destination IP, protocol, and port out of a raw IPv4/IPv6 packet."""
    if len(payload) < 20:
        return ("", 0, 0)
    version = (payload[0] >> 4) & 0xF
    if version == 6 and len(payload) >= 40:
        dest = socket.inet_ntop(socket.AF_INET6, payload[24:40])
        proto = payload[6]
        port = (
            struct.unpack_from("!H", payload, 42)[0]
            if proto in (_IPPROTO_TCP, _IPPROTO_UDP) and len(payload) >= 44
            else 0
        )
        return (dest, proto, port)
    if version != 4:
        return ("", 0, 0)
    ihl = (payload[0] & 0xF) * 4
    if ihl < 20:
        return ("", 0, 0)
    proto = payload[9]
    dest = socket.inet_ntop(socket.AF_INET, payload[16:20])
    port = (
        struct.unpack_from("!H", payload, ihl + 2)[0]
        if proto in (_IPPROTO_TCP, _IPPROTO_UDP) and len(payload) >= ihl + 4
        else 0
    )
    return (dest, proto, port)


def _build_bind_msg(group: int) -> bytes:
    """Construct the netlink message that subscribes us to an NFLOG group."""
    msg_type = (_NFNL_SUBSYS_ULOG << 8) | _NFULNL_MSG_CONFIG
    nfgen = _NFGEN_HDR.pack(_AF_INET, 0, socket.htons(group))
    cmd_payload = _NFULNL_CFG_CMD.pack(_NFULNL_CFG_CMD_BIND, 0, socket.htons(_AF_INET))
    attr = _NFA_HDR.pack(_NFA_HDR.size + len(cmd_payload), 1) + cmd_payload
    payload = nfgen + attr
    return (
        _NLMSG_HDR.pack(
            _NLMSG_HDR.size + len(payload),
            msg_type,
            _NLM_F_REQUEST | _NLM_F_ACK,
            0,
            0,
        )
        + payload
    )


# ── Domain cache ──────────────────────────────────────────────────────

_REPLY_RE = re.compile(r"(?:reply|cached)\s+(\S+)\s+is\s+(\S+)")


class _DomainCache:
    """Reverse-lookup from resolved IP back to the dnsmasq-observed domain."""

    def __init__(self, state_dir: Path) -> None:
        """Watch the dnsmasq log under *state_dir*."""
        self._log_path = state_dir / "dnsmasq.log"
        self._mapping: dict[str, str] = {}

    def lookup(self, ip: str) -> str:
        """Return the last-seen domain for *ip* or ``""`` when no reply is cached."""
        return self._mapping.get(ip, "")

    def refresh(self) -> None:
        """Re-parse the dnsmasq log; preserves the previous cache on read errors."""
        try:
            text = self._log_path.read_text()
        except OSError:
            return
        self._mapping = {
            m.group(2): m.group(1).lower().rstrip(".") for m in _REPLY_RE.finditer(text)
        }


# ── Utility helpers ───────────────────────────────────────────────────


def _parse_args() -> argparse.Namespace:  # pragma: no cover — thin argparse wrapper
    """Define the CLI surface — positional state_dir + container, ``--emit``, dossier."""
    parser = argparse.ArgumentParser(
        prog="nflog-reader",
        description="Stream one container's blocked-connection events to the clearance flow.",
    )
    parser.add_argument("state_dir", type=Path, help="Per-container shield state directory.")
    parser.add_argument("container", help="Container name (carried in event payloads).")
    parser.add_argument(
        "--emit",
        choices=("socket", "json"),
        default="socket",
        help=(
            "Where to publish events: the hub's unix-socket ingester (default) "
            "or JSON lines on stdout for the terminal fallback CLI."
        ),
    )
    parser.add_argument(
        "--annotations",
        default="{}",
        help=(
            "JSON object of orchestrator-supplied dossier fields (project, task, "
            "container_name, meta_path, …) extracted from the container's "
            "``dossier.*`` OCI annotations.  Forwarded verbatim through the "
            "nsenter re-exec; defaults to ``{}`` for orchestrator-less use."
        ),
    )
    args = parser.parse_args()
    args.annotations_raw = args.annotations
    args.annotations = _parse_annotations(args.annotations)
    return args


def _parse_annotations(raw: str) -> Dossier:
    """Parse a JSON-encoded ``--annotations`` argument into a ``Dossier`` — soft-fail to empty.

    Malformed input or a non-object payload lands at ``{}`` rather than
    crashing the reader: the bridge hook is opt-in and a corrupt
    annotation block must not block container start.  Non-string values
    are coerced via ``str()`` so a numeric annotation (rare but legal
    in the OCI spec) still surfaces.
    """
    try:
        decoded = json.loads(raw) if raw else {}
    except ValueError:
        _log.warning("ignoring malformed --annotations payload: %r", raw)
        return {}
    if not isinstance(decoded, dict):
        _log.warning("ignoring non-object --annotations payload: %r", raw)
        return {}
    return {str(k): str(v) for k, v in decoded.items()}


def _print_json(payload: dict) -> None:
    """Emit *payload* as a single compact JSON line on stdout."""
    print(json.dumps(payload, separators=(",", ":")), flush=True)


if __name__ == "__main__":  # pragma: no cover — script entry point
    main()
