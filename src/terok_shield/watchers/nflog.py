# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Read denied packets via ``AF_NETLINK`` NFLOG and emit watch events.

Subscribes to the kernel's nflog group to receive copies of packets that
matched ``log group`` rules in the nft ruleset.  Extracts destination IP,
port, and log prefix from each message.

Optional — ``NflogWatcher.create()`` returns ``None`` if netlink is
unavailable (missing kernel module, insufficient permissions).
"""

import logging
import socket
import struct
from datetime import UTC, datetime

from ..nft.constants import NFLOG_GROUP
from ._event import WatchEvent

logger = logging.getLogger(__name__)

# ── Linux netlink / nflog constants ─────────────────────
# From linux/netfilter/nfnetlink.h and linux/netfilter/nfnetlink_log.h.

_NETLINK_NETFILTER = 12
_NFNL_SUBSYS_ULOG = 4
_NFULNL_MSG_CONFIG = 1
_NFULNL_MSG_PACKET = 0

_NFULNL_CFG_CMD_BIND = 1
_NFULNL_CFG_CMD_UNBIND = 0

# nflog attribute types (TLV in the packet payload)
_NFULA_PACKET_HDR = 1
_NFULA_PREFIX = 10
_NFULA_PAYLOAD = 9

# IP protocol numbers
_IPPROTO_TCP = 6
_IPPROTO_UDP = 17

# Struct formats for netlink message parsing
_NLMSG_HDR = struct.Struct("=IHHII")  # length, type, flags, seq, pid
_NFGEN_HDR = struct.Struct("=BBH")  # family, version, res_id
_NFULNL_CFG_CMD = struct.Struct("=BBH")  # command, pad, pf
_NFA_HDR = struct.Struct("=HH")  # length, type

_NLM_F_REQUEST = 1
_NLM_F_ACK = 4
_AF_INET = 2


class NflogWatcher:
    """Read NFLOG messages via ``AF_NETLINK`` and yield events for denied packets."""

    @classmethod
    def create(cls, container: str, group: int = NFLOG_GROUP) -> "NflogWatcher | None":
        """Create and bind an NFLOG watcher, or return ``None`` on failure.

        Failure is expected in environments without ``AF_NETLINK`` support,
        unprivileged containers, or missing kernel modules.

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

    def __init__(self, sock: socket.socket, container: str) -> None:
        """Wrap an already-bound NFLOG netlink socket.

        Use :meth:`create` instead of calling this directly.
        """
        self._sock = sock
        self._container = container

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
            subsys = (nl_type >> 8) & 0xFF
            msg = nl_type & 0xFF
            if subsys == _NFNL_SUBSYS_ULOG and msg == _NFULNL_MSG_PACKET:
                attr_offset = _NLMSG_HDR.size + _NFGEN_HDR.size
                if offset + attr_offset < offset + nl_len:
                    attrs = _parse_nflog_attrs(data[offset + attr_offset : offset + nl_len])
                    event = self._attr_to_event(attrs)
                    if event:
                        events.append(event)
            offset += (nl_len + 3) & ~3
        return events

    def _attr_to_event(self, attrs: dict[int, bytes]) -> WatchEvent | None:
        """Convert parsed NFLOG attributes into a :class:`WatchEvent`."""
        prefix_raw = attrs.get(_NFULA_PREFIX, b"")
        prefix = prefix_raw.rstrip(b"\x00").decode("ascii", errors="replace").strip()

        if "BLOCKED" in prefix:
            action = "queued_connection"
        elif "DENIED" in prefix:
            action = "blocked_connection"
        elif "PRIVATE" in prefix:
            action = "private_range"
        elif "ALLOWED" in prefix:
            action = "allowed_connection"
        elif "BYPASS" in prefix:
            action = "bypass_connection"
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


# ── Netlink helpers ─────────────────────────────────────


def _build_nflog_bind_msg(group: int) -> bytes:
    """Build a netlink message to bind to an NFLOG group."""
    msg_type = (_NFNL_SUBSYS_ULOG << 8) | _NFULNL_MSG_CONFIG
    nfgen = _NFGEN_HDR.pack(_AF_INET, 0, socket.htons(group))
    cmd_payload = _NFULNL_CFG_CMD.pack(_NFULNL_CFG_CMD_BIND, 0, socket.htons(_AF_INET))
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
    """Parse TLV attributes from an NFLOG packet message."""
    attrs: dict[int, bytes] = {}
    offset = 0
    while offset + _NFA_HDR.size <= len(data):
        nfa_len, nfa_type = _NFA_HDR.unpack_from(data, offset)
        if nfa_len < _NFA_HDR.size:
            break
        nfa_type &= 0x7FFF
        value = data[offset + _NFA_HDR.size : offset + nfa_len]
        attrs[nfa_type] = value
        offset += (nfa_len + 3) & ~3
    return attrs


def _extract_ip_dest(payload: bytes) -> tuple[str, int, int]:
    """Extract destination IP, protocol, and port from a raw IP packet.

    Handles both IPv4 and IPv6.  Returns ``("", 0, 0)`` if the packet
    cannot be parsed.
    """
    if len(payload) < 20:
        return ("", 0, 0)
    version = (payload[0] >> 4) & 0xF
    if version != 4:
        if version == 6 and len(payload) >= 40:
            dest_bytes = payload[24:40]
            dest = socket.inet_ntop(socket.AF_INET6, dest_bytes)
            proto = payload[6]
            port = 0
            if proto in (_IPPROTO_TCP, _IPPROTO_UDP) and len(payload) >= 44:
                port = struct.unpack_from("!H", payload, 42)[0]
            return (dest, proto, port)
        return ("", 0, 0)
    ihl = (payload[0] & 0xF) * 4
    if ihl < 20:
        return ("", 0, 0)
    proto = payload[9]
    dest = socket.inet_ntop(socket.AF_INET, payload[16:20])
    port = 0
    if proto in (_IPPROTO_TCP, _IPPROTO_UDP) and len(payload) >= ihl + 4:
        port = struct.unpack_from("!H", payload, ihl + 2)[0]
    return (dest, proto, port)
