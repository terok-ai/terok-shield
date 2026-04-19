#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Stream blocked-connection events out of one container for the clearance flow.

Subscribes to the kernel's NFLOG group inside a single container's network
namespace, deduplicates by destination IP, and publishes each unique block as
an event — either as an ``org.terok.Shield1.ConnectionBlocked`` D-Bus signal
(for the host-side clearance hub) or as a JSON line on stdout (for the
terminal fallback).  Emits ``ContainerStarted`` / ``ContainerExited`` around
its own lifetime so consumers see the container's arrival and departure.

The OCI bridge hook spawns one reader per shielded container at
``createRuntime`` and SIGTERMs it at ``poststop`` — the process tree is what
ties the reader's lifetime to the container's.

Stdlib-only by design: shipped as a resource that ``/usr/bin/python3`` can
execute anywhere without depending on the terok-shield virtual environment.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import select
import signal
import socket
import struct
import subprocess  # nosec B404 — dbus-send is a trusted host binary
from dataclasses import dataclass
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

_SHIELD_BUS_NAME = "org.terok.Shield1"
_SHIELD_OBJECT_PATH = "/org/terok/Shield1"
_SHIELD_INTERFACE = "org.terok.Shield1"

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

_NLMSG_HDR = struct.Struct("=IHHII")
_NFGEN_HDR = struct.Struct("=BBH")
_NFULNL_CFG_CMD = struct.Struct("=BBH")
_NFA_HDR = struct.Struct("=HH")


@dataclass(frozen=True)
class BlockedEvent:
    """A packet the kernel dropped at the interactive-deny rule — one per unique dest IP."""

    container: str
    request_id: str
    dest: str
    port: int
    proto: int
    domain: str


# ── Entry point ───────────────────────────────────────────────────────


def main() -> None:
    """Parse arguments, enter the container netns if needed, and run the reader."""
    args = _parse_args()
    logging.basicConfig(level=logging.INFO, format="nflog-reader: %(message)s")

    if os.environ.get(_NSENTER_ENV) != "1":
        _reexec_inside_container_netns(args.state_dir, args.container, args.emit)
        return

    emitter = _select_emitter(args.emit)
    session = ReaderSession(
        state_dir=args.state_dir,
        container=args.container,
        emitter=emitter,
    )
    session.run()


# ── Session ───────────────────────────────────────────────────────────


class ReaderSession:
    """Orchestrates the container's block-event stream for the clearance flow.

    Owns the NFLOG socket, the dedup set, the domain cache, and the signal
    handler.  Lives for the container's lifetime: emits ``ContainerStarted``
    on open, streams ``ConnectionBlocked`` for each unique-destination block,
    and emits ``ContainerExited`` on SIGTERM or NFLOG close.
    """

    def __init__(self, *, state_dir: Path, container: str, emitter: EventEmitter) -> None:
        """Prepare the session; the socket is opened in :meth:`run`."""
        self._state_dir = state_dir
        self._container = container
        self._emitter = emitter
        self._domain_cache = _DomainCache(state_dir)
        self._seen: set[str] = set()
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
        """Read NFLOG messages, dedupe by dest IP, emit one signal per novelty."""
        self._domain_cache.refresh()
        while not self._stop_requested:
            try:
                readable, _, _ = select.select([sock], [], [], 1.0)
            except (OSError, ValueError):
                return
            if sock not in readable:
                continue
            for event in _drain(sock):
                if event.dest in self._seen:
                    continue
                self._seen.add(event.dest)
                self._emit_connection_blocked(event)

    def _emit_connection_blocked(self, event: _RawBlockEvent) -> None:
        """Enrich an NFLOG event with domain + request-id and publish it."""
        domain = self._domain_cache.lookup(event.dest)
        if not domain:
            self._domain_cache.refresh()
            domain = self._domain_cache.lookup(event.dest)
        request_id = f"{self._container}:{self._next_id}"
        self._next_id += 1
        self._emitter.connection_blocked(
            BlockedEvent(
                container=self._container,
                request_id=request_id,
                dest=event.dest,
                port=event.port,
                proto=event.proto,
                domain=domain,
            )
        )

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


# ── Emission strategies ───────────────────────────────────────────────


class EventEmitter(Protocol):
    """The two publishing channels a reader can speak — D-Bus or JSON stdout."""

    def container_started(self, container: str) -> None:
        """Publish a ``ContainerStarted`` lifecycle event."""
        ...

    def container_exited(self, container: str, *, reason: str) -> None:
        """Publish a ``ContainerExited`` lifecycle event."""
        ...

    def connection_blocked(self, event: BlockedEvent) -> None:
        """Publish one unique-destination block event."""
        ...


class DbusEmitter:
    """Publish ephemeral D-Bus signals on ``org.terok.Shield1`` via ``dbus-send``.

    Ownership of the well-known name lives with the host-side clearance hub;
    this emitter is just a sender — any process can emit signals on an
    interface without claiming its bus name.
    """

    def container_started(self, container: str) -> None:
        """Send a ``ContainerStarted`` signal on the session bus."""
        self._send("ContainerStarted", _dbus_str(container))

    def container_exited(self, container: str, *, reason: str) -> None:
        """Send a ``ContainerExited`` signal on the session bus."""
        self._send("ContainerExited", _dbus_str(container), _dbus_str(reason))

    def connection_blocked(self, event: BlockedEvent) -> None:
        """Send a ``ConnectionBlocked`` signal carrying the full event payload."""
        self._send(
            "ConnectionBlocked",
            _dbus_str(event.container),
            _dbus_str(event.request_id),
            _dbus_str(event.dest),
            f"uint32:{event.port}",
            f"uint32:{event.proto}",
            _dbus_str(event.domain),
        )

    def _send(self, member: str, *args: str) -> None:
        """Invoke ``dbus-send`` for one signal; log & continue on any failure."""
        cmd = [
            "dbus-send",
            "--session",
            "--type=signal",
            _SHIELD_OBJECT_PATH,
            f"{_SHIELD_INTERFACE}.{member}",
            *args,
        ]
        try:
            subprocess.run(cmd, check=False, capture_output=True)  # noqa: S603
        except FileNotFoundError:
            _log.warning("dbus-send missing — signal %s dropped", member)
        except OSError as exc:
            _log.warning("dbus-send failed for %s: %s", member, exc)


class JsonEmitter:
    """Publish events as JSON lines on stdout — drives the terminal fallback CLI."""

    def container_started(self, container: str) -> None:
        """Emit a ``container_started`` JSON line."""
        _print_json({"type": "container_started", "container": container})

    def container_exited(self, container: str, *, reason: str) -> None:
        """Emit a ``container_exited`` JSON line."""
        _print_json({"type": "container_exited", "container": container, "reason": reason})

    def connection_blocked(self, event: BlockedEvent) -> None:
        """Emit a ``pending`` JSON line carrying the full event payload."""
        _print_json(
            {
                "type": "pending",
                "container": event.container,
                "id": event.request_id,
                "dest": event.dest,
                "port": event.port,
                "proto": event.proto,
                "domain": event.domain,
                "ts": datetime.now(UTC).isoformat(),
            }
        )


def _select_emitter(mode: str) -> EventEmitter:
    """Resolve the ``--emit`` flag to the matching emitter implementation."""
    return DbusEmitter() if mode == "dbus" else JsonEmitter()


# ── NFLOG socket / parsing ────────────────────────────────────────────


@dataclass(frozen=True)
class _RawBlockEvent:
    """Pre-enrichment fields pulled straight from one NFLOG packet."""

    dest: str
    port: int
    proto: int


def _open_nflog_socket(group: int) -> socket.socket | None:
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


def _drain(sock: socket.socket) -> list[_RawBlockEvent]:
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


# ── nsenter re-exec ───────────────────────────────────────────────────


def _reexec_inside_container_netns(state_dir: Path, container: str, emit: str) -> None:
    """Re-enter this script inside the container's netns so NFLOG is reachable.

    NFLOG is delivered per-netns; the reader must bind from inside the
    container's network namespace.  ``podman unshare`` enters the persistent
    rootless user namespace that owns the container netns (not the inner
    userns) so ``CAP_NET_ADMIN`` is available for the NFLOG bind.
    """
    pid = _podman_container_pid(container)
    script = Path(__file__).resolve()
    cmd = [
        "podman",
        "unshare",
        "nsenter",
        "-t",
        pid,
        "-n",
        "/usr/bin/python3",
        str(script),
        str(state_dir),
        container,
        f"--emit={emit}",
    ]
    env = {**os.environ, _NSENTER_ENV: "1"}
    try:
        subprocess.run(cmd, env=env, check=True)  # noqa: S603
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode) from exc


def _podman_container_pid(container: str) -> str:
    """Resolve a container's host PID so nsenter can target its network namespace."""
    result = subprocess.run(  # noqa: S603
        ["podman", "inspect", "--format", "{{.State.Pid}}", container],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


# ── Utility helpers ───────────────────────────────────────────────────


def _parse_args() -> argparse.Namespace:
    """Define the CLI surface — positional state_dir + container, ``--emit`` channel."""
    parser = argparse.ArgumentParser(
        prog="nflog-reader",
        description="Stream one container's blocked-connection events to the clearance flow.",
    )
    parser.add_argument("state_dir", type=Path, help="Per-container shield state directory.")
    parser.add_argument("container", help="Container name (carried in event payloads).")
    parser.add_argument(
        "--emit",
        choices=("dbus", "json"),
        default="dbus",
        help="Where to publish events: session-bus D-Bus signals (default) or JSON lines on stdout.",
    )
    return parser.parse_args()


def _dbus_str(value: str) -> str:
    """Format a Python string as a ``dbus-send`` string argument."""
    return f"string:{value}"


def _print_json(payload: dict) -> None:
    """Emit *payload* as a single compact JSON line on stdout."""
    print(json.dumps(payload, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
