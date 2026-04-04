# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Live blocked-access event stream for ``shield watch``.

Multiplexes three event sources into a single JSON-lines stream:

1. **DNS log** (``DnsLogWatcher``): tails the per-container dnsmasq query log
   and emits events for blocked domain lookups.  Requires the dnsmasq DNS tier.
2. **Audit log** (``AuditLogWatcher``): tails the per-container ``audit.jsonl``
   and surfaces shield lifecycle events (allow, deny, up, down, setup, teardown).
3. **NFLOG** (``NflogWatcher``): reads denied packets via ``AF_NETLINK`` and
   emits events for raw-IP connections that bypassed DNS.  Optional — graceful
   degradation when netlink is unavailable.
"""

from __future__ import annotations

import json
import logging
import os
import re
import select
import signal
import socket
import struct
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from . import dnsmasq, state
from .config import DnsTier
from .nft_constants import NFLOG_GROUP

logger = logging.getLogger(__name__)

# ── Constants ───────────────────────────────────────────

# Matches dnsmasq log-queries lines like:
#   Mar 31 12:00:00 dnsmasq[123]: query[A] evil.example.com from 127.0.0.1
#   Mar 31 12:00:00 dnsmasq[123]: query[AAAA] evil.example.com from 127.0.0.1
_QUERY_RE = re.compile(r"query\[(A{1,4})\]\s+(\S+)\s+from\s+")

# How often (seconds) to refresh the allowed domain list.
_DOMAIN_REFRESH_INTERVAL = 30.0


# ── Data types ──────────────────────────────────────────


@dataclass(frozen=True)
class WatchEvent:
    """A single watch event emitted to the output stream.

    Core fields (always present): ``ts``, ``source``, ``action``, ``container``.
    DNS-specific: ``domain``, ``query_type``.
    Audit/NFLOG: ``dest``, ``detail``, ``port``, ``proto``.
    """

    ts: str
    source: str
    action: str
    container: str
    domain: str = ""
    query_type: str = ""
    dest: str = ""
    detail: str = ""
    port: int = 0
    proto: int = 0
    extra: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialize to a compact JSON line, omitting empty optional fields."""
        d = {
            k: v
            for k, v in asdict(self).items()
            if v or k in ("ts", "source", "action", "container")
        }
        return json.dumps(d, separators=(",", ":"))


# ── DNS log watcher ─────────────────────────────────────


class DnsLogWatcher:
    """Tail the dnsmasq query log and yield events for blocked domains.

    Opens the log file, seeks to the end, and watches for new query
    lines.  Domains are classified by suffix-matching against the
    merged allowed domain set (profile + live - denied).
    """

    def __init__(self, log_path: Path, state_dir: Path, container: str) -> None:
        """Open *log_path*, seek to end, and load the initial allowed domain set."""
        self._log_path = log_path
        self._state_dir = state_dir
        self._container = container
        self._fh = open(log_path)  # noqa: SIM115 — needs fileno() for select
        try:
            self._fh.seek(0, os.SEEK_END)
            self._allowed_domains: set[str] = set()
            self._last_refresh = 0.0
            self._refresh_domains()
        except Exception:
            self._fh.close()
            raise

    def fileno(self) -> int:
        """Return the file descriptor for ``select.select()`` multiplexing."""
        return self._fh.fileno()

    def close(self) -> None:
        """Close the underlying file handle."""
        self._fh.close()

    def _refresh_domains(self) -> None:
        """Reload the merged domain set from state files."""
        self._allowed_domains = set(dnsmasq.read_merged_domains(self._state_dir))
        self._last_refresh = _monotonic()

    def _is_allowed(self, domain: str) -> bool:
        """Return True if *domain* (or a parent) is in the allowed set.

        dnsmasq ``--nftset`` matches subdomains, so ``x.y.z`` is allowed
        if ``y.z`` is in the set.
        """
        d = domain.lower().rstrip(".")
        while d:
            if d in self._allowed_domains:
                return True
            dot = d.find(".")
            if dot < 0:
                break
            d = d[dot + 1 :]
        return False

    def poll(self) -> list[WatchEvent]:
        """Read new lines and return events for blocked queries."""
        if _monotonic() - self._last_refresh > _DOMAIN_REFRESH_INTERVAL:
            self._refresh_domains()

        events: list[WatchEvent] = []
        while line := self._fh.readline():
            m = _QUERY_RE.search(line)
            if not m:
                continue
            query_type, domain = m.group(1), m.group(2).lower().rstrip(".")
            if self._is_allowed(domain):
                continue
            events.append(
                WatchEvent(
                    ts=datetime.now(UTC).isoformat(),
                    source="dns",
                    action="blocked_query",
                    domain=domain,
                    query_type=query_type,
                    container=self._container,
                )
            )
        return events


# ── Audit log watcher ──────────────────────────────────


class AuditLogWatcher:
    """Tail ``audit.jsonl`` and yield events for shield lifecycle changes.

    Opens the audit log, seeks to the end, and watches for new JSON-lines
    entries written by :class:`~terok_shield.audit.AuditLogger`.  Every new
    entry is surfaced as a :class:`WatchEvent` with ``source="audit"``.
    """

    def __init__(self, audit_path: Path, container: str) -> None:
        """Open *audit_path* and seek to end.

        Args:
            audit_path: Path to the per-container ``audit.jsonl`` file.
            container: Container name (for event metadata).
        """
        self._audit_path = audit_path
        self._container = container
        audit_path.touch(exist_ok=True)
        self._fh = open(audit_path)  # noqa: SIM115 — needs fileno() for select
        self._fh.seek(0, os.SEEK_END)

    def fileno(self) -> int:
        """Return the file descriptor for ``select.select()`` multiplexing."""
        return self._fh.fileno()

    def close(self) -> None:
        """Close the underlying file handle."""
        self._fh.close()

    def poll(self) -> list[WatchEvent]:
        """Read new audit lines and return watch events."""
        events: list[WatchEvent] = []
        while line := self._fh.readline():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue
            events.append(
                WatchEvent(
                    ts=entry.get("ts", datetime.now(UTC).isoformat()),
                    source="audit",
                    action=entry.get("action", "unknown"),
                    container=entry.get("container", self._container),
                    dest=entry.get("dest", ""),
                    detail=entry.get("detail", ""),
                )
            )
        return events


# ── NFLOG watcher ──────────────────────────────────────

# Linux netlink / nflog constants (from linux/netfilter/nfnetlink.h and
# linux/netfilter/nfnetlink_log.h).
_NETLINK_NETFILTER = 12
_NFNL_SUBSYS_ULOG = 4
_NFULNL_MSG_CONFIG = 1
_NFULNL_MSG_PACKET = 0

# nflog config commands
_NFULNL_CFG_CMD_BIND = 1
_NFULNL_CFG_CMD_UNBIND = 0

# nflog attribute types (TLV in the packet payload)
_NFULA_PACKET_HDR = 1
_NFULA_PREFIX = 10  # NFULA_PREFIX (nfnetlink_log.h)
_NFULA_PAYLOAD = 9

# IP protocol numbers
_IPPROTO_TCP = 6
_IPPROTO_UDP = 17

# Netlink message header: length(4) + type(2) + flags(2) + seq(4) + pid(4)
_NLMSG_HDR = struct.Struct("=IHHII")
# nfgenmsg: family(1) + version(1) + res_id(2)
_NFGEN_HDR = struct.Struct("=BBH")
# nflog config command: command(1) + pad(1) + pf(2)
_NFULNL_CFG_CMD = struct.Struct("=BBH")
# nflog TLV attribute header: length(2) + type(2)
_NFA_HDR = struct.Struct("=HH")

_NLM_F_REQUEST = 1
_NLM_F_ACK = 4

# AF_INET is 2 on all Linux platforms
_AF_INET = 2


def _build_nflog_bind_msg(group: int) -> bytes:
    """Build a netlink message to bind to an NFLOG group.

    Constructs the raw NFULNL_MSG_CONFIG message with CMD_BIND
    for the specified NFLOG group number.
    """
    msg_type = (_NFNL_SUBSYS_ULOG << 8) | _NFULNL_MSG_CONFIG
    nfgen = _NFGEN_HDR.pack(_AF_INET, 0, socket.htons(group))
    # Config command attribute: NFULA_CFG_CMD
    cmd_payload = _NFULNL_CFG_CMD.pack(_NFULNL_CFG_CMD_BIND, 0, socket.htons(_AF_INET))
    # Attribute TLV: type=1 (NFULA_CFG_CMD), length=header+payload
    attr = _NFA_HDR.pack(_NFA_HDR.size + len(cmd_payload), 1) + cmd_payload
    payload = nfgen + attr
    nlmsg = (
        _NLMSG_HDR.pack(
            _NLMSG_HDR.size + len(payload),
            msg_type,
            _NLM_F_REQUEST | _NLM_F_ACK,
            0,
            0,
        )
        + payload
    )
    return nlmsg


def _parse_nflog_attrs(data: bytes) -> dict[int, bytes]:
    """Parse TLV attributes from an NFLOG packet message.

    Returns a dict mapping attribute type to raw attribute value bytes.
    """
    attrs: dict[int, bytes] = {}
    offset = 0
    while offset + _NFA_HDR.size <= len(data):
        nfa_len, nfa_type = _NFA_HDR.unpack_from(data, offset)
        if nfa_len < _NFA_HDR.size:
            break
        # Mask out the nested/byteorder flags from the type field
        nfa_type &= 0x7FFF
        value = data[offset + _NFA_HDR.size : offset + nfa_len]
        attrs[nfa_type] = value
        # Attributes are 4-byte aligned
        offset += (nfa_len + 3) & ~3
    return attrs


def _extract_ip_dest(payload: bytes) -> tuple[str, int, int]:
    """Extract destination IP, protocol, and port from a raw IP packet.

    Handles IPv4 only (NFLOG in inet tables delivers the IP header).
    Returns ``("", 0, 0)`` if the packet cannot be parsed.
    """
    if len(payload) < 20:
        return ("", 0, 0)
    version = (payload[0] >> 4) & 0xF
    if version != 4:
        # IPv6 parsing: 40-byte header, dest at offset 24
        if version == 6 and len(payload) >= 40:
            dest_bytes = payload[24:40]
            dest = socket.inet_ntop(socket.AF_INET6, dest_bytes)
            proto = payload[6]  # Next Header
            port = 0
            if proto in (_IPPROTO_TCP, _IPPROTO_UDP) and len(payload) >= 44:
                port = struct.unpack_from("!H", payload, 42)[0]  # dest port
            return (dest, proto, port)
        return ("", 0, 0)
    ihl = (payload[0] & 0xF) * 4
    if ihl < 20:
        return ("", 0, 0)
    proto = payload[9]
    dest = socket.inet_ntop(socket.AF_INET, payload[16:20])
    port = 0
    if proto in (_IPPROTO_TCP, _IPPROTO_UDP) and len(payload) >= ihl + 4:
        port = struct.unpack_from("!H", payload, ihl + 2)[0]  # dest port
    return (dest, proto, port)


class NflogWatcher:
    """Read NFLOG messages via ``AF_NETLINK`` and yield events for denied packets.

    Subscribes to the kernel's nflog group (default 100) to receive copies of
    packets that matched ``log group`` rules in the nft ruleset.  Extracts the
    destination IP, port, and log prefix from each message.

    Optional — ``create()`` returns ``None`` if netlink is unavailable (e.g.
    missing kernel module, insufficient permissions).
    """

    def __init__(self, sock: socket.socket, container: str) -> None:
        """Wrap an already-bound NFLOG netlink socket.

        Use :meth:`create` instead of calling this directly.
        """
        self._sock = sock
        self._container = container

    @classmethod
    def create(cls, container: str, group: int = NFLOG_GROUP) -> NflogWatcher | None:
        """Create and bind an NFLOG watcher, or return ``None`` on failure.

        Failure is expected in environments without ``AF_NETLINK`` support,
        unprivileged containers, or missing kernel modules.  The caller
        should log a notice and continue without NFLOG events.

        Args:
            container: Container name (for event metadata).
            group: NFLOG group number to subscribe to.
        """
        sock: socket.socket | None = None
        try:
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, _NETLINK_NETFILTER)
            sock.bind((0, 0))

            # Handshake in blocking mode so the bind ACK is reliably received.
            sock.settimeout(2.0)
            sock.send(_build_nflog_bind_msg(group))
            ack = sock.recv(4096)
            if len(ack) >= _NLMSG_HDR.size + 4:
                err = struct.unpack_from("=i", ack, _NLMSG_HDR.size)[0]
                if err < 0:
                    sock.close()
                    logger.debug("NFLOG bind rejected (errno %d) — skipping", -err)
                    return None

            # Switch to non-blocking for the poll() loop
            sock.setblocking(False)
            return cls(sock, container)
        except (OSError, AttributeError):
            # OSError: netlink/timeout unavailable; AttributeError: AF_NETLINK
            # missing on non-Linux platforms.
            logger.debug("NFLOG socket unavailable — skipping packet events")
            if sock is not None:
                sock.close()
            return None

    def fileno(self) -> int:
        """Return the file descriptor for ``select.select()`` multiplexing."""
        return self._sock.fileno()

    def close(self) -> None:
        """Close the netlink socket."""
        self._sock.close()

    def poll(self) -> list[WatchEvent]:
        """Read pending NFLOG messages and return watch events."""
        events: list[WatchEvent] = []
        while True:
            try:
                data = self._sock.recv(65535)
            except OSError:
                break
            if not data:
                break
            events.extend(self._parse_messages(data))
        return events

    def _parse_messages(self, data: bytes) -> list[WatchEvent]:
        """Parse one or more netlink messages from raw *data*."""
        events: list[WatchEvent] = []
        offset = 0
        while offset + _NLMSG_HDR.size <= len(data):
            nl_len, nl_type, _flags, _seq, _pid = _NLMSG_HDR.unpack_from(data, offset)
            if nl_len < _NLMSG_HDR.size or offset + nl_len > len(data):
                break
            # Check this is an NFLOG packet message
            subsys = (nl_type >> 8) & 0xFF
            msg = nl_type & 0xFF
            if subsys == _NFNL_SUBSYS_ULOG and msg == _NFULNL_MSG_PACKET:
                # Skip nlmsg header + nfgenmsg (4 bytes)
                attr_offset = _NLMSG_HDR.size + _NFGEN_HDR.size
                if offset + attr_offset < offset + nl_len:
                    attrs = _parse_nflog_attrs(data[offset + attr_offset : offset + nl_len])
                    event = self._attr_to_event(attrs)
                    if event:
                        events.append(event)
            # Advance to next message (4-byte aligned)
            offset += (nl_len + 3) & ~3
        return events

    def _attr_to_event(self, attrs: dict[int, bytes]) -> WatchEvent | None:
        """Convert parsed NFLOG attributes into a :class:`WatchEvent`."""
        prefix_raw = attrs.get(_NFULA_PREFIX, b"")
        prefix = prefix_raw.rstrip(b"\x00").decode("ascii", errors="replace").strip()

        # Determine action from the nft log prefix
        if "DENIED" in prefix:
            action = "blocked_connection"
        elif "PRIVATE" in prefix:
            action = "private_range"
        elif "ALLOWED" in prefix:
            action = "allowed_connection"
        elif "BYPASS" in prefix:
            action = "bypass_connection"
        elif "QUEUED" in prefix:
            action = "queued_connection"
        else:
            action = "nflog"

        payload = attrs.get(_NFULA_PAYLOAD, b"")
        dest, proto, port = _extract_ip_dest(payload)
        if not dest:
            return None

        return WatchEvent(
            ts=datetime.now(UTC).isoformat(),
            source="nflog",
            action=action,
            container=self._container,
            dest=dest,
            port=port,
            proto=proto,
            detail=prefix,
        )


# ── Entry point ─────────────────────────────────────────

_running = True


def _handle_signal(_signum: int, _frame: object) -> None:
    """Set the stop flag on SIGINT/SIGTERM."""
    global _running  # noqa: PLW0603
    _running = False


def _ensure_log_file(log_path: Path) -> None:
    """Create the dnsmasq log file if it does not exist yet.

    ``pre_start()`` configures ``log-facility=<path>`` in the dnsmasq
    config, but dnsmasq may not have written any queries yet when
    ``shield watch`` starts.  Creating the file ensures the watcher
    can open it immediately.
    """
    log_path.touch(exist_ok=True)


def _validate_dnsmasq_tier(state_dir: Path) -> None:
    """Verify the dnsmasq DNS tier is active, or exit with an error.

    Raises:
        SystemExit: If the DNS tier file is missing or not dnsmasq.
    """
    tier_path = state.dns_tier_path(state_dir)
    if tier_path.is_file():
        tier_value = tier_path.read_text().strip()
        if tier_value != DnsTier.DNSMASQ.value:
            print(
                f"Error: shield watch requires dnsmasq tier, got {tier_value!r}.",
                file=sys.stderr,
            )
            raise SystemExit(1)
    else:
        print(
            "Error: DNS tier not set — container may not be shielded.",
            file=sys.stderr,
        )
        raise SystemExit(1)


def run_watch(state_dir: Path, container: str) -> None:
    """Stream blocked-access events as JSON lines to stdout.

    Validates that the dnsmasq tier is active, then enters a
    ``select.select()`` loop tailing the query log, audit log,
    and (optionally) the NFLOG netlink socket.  Clean exit
    on SIGINT or SIGTERM.

    Args:
        state_dir: Per-container state directory.
        container: Container name (for event metadata).

    Raises:
        SystemExit: If the DNS tier is not dnsmasq.
    """
    _validate_dnsmasq_tier(state_dir)

    log_path = state.dnsmasq_log_path(state_dir)
    _ensure_log_file(log_path)

    global _running  # noqa: PLW0603
    _running = True
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    dns_watcher = DnsLogWatcher(log_path, state_dir, container)
    audit_watcher = AuditLogWatcher(state.audit_path(state_dir), container)
    nflog_watcher = NflogWatcher.create(container)

    try:
        while _running:
            # Only use select() for the netlink socket (real fd);
            # regular files always appear readable in select() so we
            # poll them unconditionally each iteration.
            if nflog_watcher:
                readable, _, _ = select.select([nflog_watcher], [], [], 1.0)
                if readable:
                    for event in nflog_watcher.poll():
                        print(event.to_json(), flush=True)
            else:
                # No netlink socket — just sleep to avoid busy-looping
                select.select([], [], [], 1.0)

            for event in dns_watcher.poll():
                print(event.to_json(), flush=True)
            for event in audit_watcher.poll():
                print(event.to_json(), flush=True)
    finally:
        dns_watcher.close()
        audit_watcher.close()
        if nflog_watcher:
            nflog_watcher.close()


def _monotonic() -> float:
    """Return monotonic time (seconds).  Extracted for testability."""
    return time.monotonic()
