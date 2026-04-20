# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the standalone NFLOG reader resource.

The reader lives at ``src/terok_shield/resources/nflog_reader.py`` and is
shipped verbatim as a stdlib-only script.  It is also importable as
``terok_shield.resources.nflog_reader`` for unit coverage — no import
in the script itself requires anything outside the standard library.
"""

from __future__ import annotations

import json
import socket
import struct
from pathlib import Path
from unittest import mock

import pytest

from terok_shield.resources import nflog_reader as reader

from ..testnet import TEST_DOMAIN, TEST_IP1

# ── Packet-format helpers (pure constructors for fixtures) ────────────


def _ipv4_tcp_packet(*, dest: str, port: int) -> bytes:
    """Build the minimal IPv4+TCP header bytes NFLOG will deliver to us."""
    ihl_words = 5  # 20-byte header
    version_ihl = (4 << 4) | ihl_words
    tcp_header = struct.pack("!HHIIBBHHH", 12345, port, 0, 0, (5 << 4), 0, 0, 0, 0)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        ihl_words * 4 + len(tcp_header),
        0,
        0,
        64,
        socket.IPPROTO_TCP,
        0,
        socket.inet_aton("10.0.0.1"),
        socket.inet_aton(dest),
    )
    return ip_header + tcp_header


def _ipv6_udp_packet(*, dest: str, port: int) -> bytes:
    """Build the minimal IPv6+UDP header bytes NFLOG will deliver to us."""
    version_tc_flow = (6 << 28).to_bytes(4, "big")
    payload_len = (8).to_bytes(2, "big")
    next_header = bytes([socket.IPPROTO_UDP])
    hop_limit = bytes([64])
    src = socket.inet_pton(socket.AF_INET6, "::1")
    dst = socket.inet_pton(socket.AF_INET6, dest)
    ip_header = version_tc_flow + payload_len + next_header + hop_limit + src + dst
    udp_header = struct.pack("!HHHH", 12345, port, 8, 0)
    return ip_header + udp_header


def _nflog_message(prefix: str, payload: bytes) -> bytes:
    """Wrap a packet payload into one NFLOG-formatted netlink message."""
    attrs = _tlv(reader._NFULA_PREFIX, prefix.encode() + b"\x00") + _tlv(
        reader._NFULA_PAYLOAD, payload
    )
    nfgen = reader._NFGEN_HDR.pack(reader._AF_INET, 0, 0)
    body = nfgen + attrs
    nl_type = (reader._NFNL_SUBSYS_ULOG << 8) | reader._NFULNL_MSG_PACKET
    nl_header = reader._NLMSG_HDR.pack(reader._NLMSG_HDR.size + len(body), nl_type, 0, 0, 0)
    return nl_header + body


def _tlv(attr_type: int, value: bytes) -> bytes:
    """Encode one netlink TLV attribute (length-type-value with 4-byte align)."""
    nfa_len = reader._NFA_HDR.size + len(value)
    header = reader._NFA_HDR.pack(nfa_len, attr_type)
    padding = b"\x00" * ((4 - nfa_len % 4) % 4)
    return header + value + padding


# ── IP packet parsing ─────────────────────────────────────────────────


class TestExtractIpDest:
    """``_extract_ip_dest`` must surface the fields a blocked-connection event needs."""

    def test_ipv4_tcp_packet_yields_dest_proto_port(self) -> None:
        packet = _ipv4_tcp_packet(dest=TEST_IP1, port=443)
        assert reader._extract_ip_dest(packet) == (TEST_IP1, socket.IPPROTO_TCP, 443)

    def test_ipv6_udp_packet_yields_dest_proto_port(self) -> None:
        packet = _ipv6_udp_packet(dest="2001:db8::1", port=53)
        assert reader._extract_ip_dest(packet) == ("2001:db8::1", socket.IPPROTO_UDP, 53)

    def test_short_packet_returns_empty_tuple(self) -> None:
        assert reader._extract_ip_dest(b"\x00" * 10) == ("", 0, 0)

    def test_unknown_version_returns_empty_tuple(self) -> None:
        assert reader._extract_ip_dest(b"\x50" + b"\x00" * 40) == ("", 0, 0)


class TestAttrsToEvent:
    """``_attrs_to_event`` must keep only BLOCKED-prefixed packets."""

    def test_blocked_prefix_returns_event(self) -> None:
        attrs = {
            reader._NFULA_PREFIX: b"BLOCKED\x00",
            reader._NFULA_PAYLOAD: _ipv4_tcp_packet(dest=TEST_IP1, port=443),
        }
        event = reader._attrs_to_event(attrs)
        assert event is not None
        assert event.dest == TEST_IP1

    def test_non_blocked_prefix_returns_none(self) -> None:
        attrs = {
            reader._NFULA_PREFIX: b"ALLOWED\x00",
            reader._NFULA_PAYLOAD: _ipv4_tcp_packet(dest=TEST_IP1, port=443),
        }
        assert reader._attrs_to_event(attrs) is None

    def test_unparsable_payload_returns_none(self) -> None:
        attrs = {
            reader._NFULA_PREFIX: b"BLOCKED\x00",
            reader._NFULA_PAYLOAD: b"\x00" * 5,
        }
        assert reader._attrs_to_event(attrs) is None


class TestParseMessages:
    """``_parse_messages`` must handle batched netlink messages."""

    def test_single_blocked_packet_yields_one_event(self) -> None:
        message = _nflog_message("BLOCKED", _ipv4_tcp_packet(dest=TEST_IP1, port=80))
        events = reader._parse_messages(message)
        assert len(events) == 1
        assert events[0].dest == TEST_IP1

    def test_mixed_batch_returns_only_blocked(self) -> None:
        blocked = _nflog_message("BLOCKED", _ipv4_tcp_packet(dest=TEST_IP1, port=80))
        allowed = _nflog_message("ALLOWED", _ipv4_tcp_packet(dest="192.0.2.99", port=443))
        events = reader._parse_messages(blocked + allowed)
        assert len(events) == 1
        assert events[0].dest == TEST_IP1


class TestBuildBindMsg:
    """``_build_bind_msg`` must produce a well-formed netlink bind request."""

    def test_length_field_matches_buffer_size(self) -> None:
        msg = reader._build_bind_msg(100)
        declared_length = reader._NLMSG_HDR.unpack_from(msg, 0)[0]
        assert declared_length == len(msg)

    def test_message_type_targets_ulog_subsys(self) -> None:
        msg = reader._build_bind_msg(100)
        nl_type = reader._NLMSG_HDR.unpack_from(msg, 0)[1]
        subsys = (nl_type >> 8) & 0xFF
        command = nl_type & 0xFF
        assert subsys == reader._NFNL_SUBSYS_ULOG
        assert command == reader._NFULNL_MSG_CONFIG


# ── Domain cache ──────────────────────────────────────────────────────


class TestDomainCache:
    """``_DomainCache`` reverses dnsmasq replies back to a domain."""

    def test_lookup_returns_domain_after_refresh(self, tmp_path: Path) -> None:
        log = tmp_path / "dnsmasq.log"
        log.write_text(f"reply {TEST_DOMAIN} is {TEST_IP1}\n")
        cache = reader._DomainCache(tmp_path)
        cache.refresh()
        assert cache.lookup(TEST_IP1) == TEST_DOMAIN

    def test_lookup_returns_empty_string_when_missing(self, tmp_path: Path) -> None:
        cache = reader._DomainCache(tmp_path)
        cache.refresh()
        assert cache.lookup(TEST_IP1) == ""

    def test_refresh_survives_missing_log(self, tmp_path: Path) -> None:
        cache = reader._DomainCache(tmp_path)
        cache.refresh()  # no log file — should not raise
        assert cache.lookup(TEST_IP1) == ""


# ── Emitters ──────────────────────────────────────────────────────────


class TestJsonEmitter:
    """``JsonEmitter`` writes one JSON object per event, one per line."""

    def test_connection_blocked_prints_pending_line(self, capsys: pytest.CaptureFixture) -> None:
        emitter = reader.JsonEmitter()
        emitter.connection_blocked(
            reader.BlockedEvent(
                container="c1",
                request_id="c1:1",
                dest=TEST_IP1,
                port=443,
                proto=socket.IPPROTO_TCP,
                domain=TEST_DOMAIN,
            )
        )
        line = capsys.readouterr().out.strip()
        payload = json.loads(line)
        assert payload["type"] == "pending"
        assert payload["container"] == "c1"
        assert payload["dest"] == TEST_IP1
        assert payload["domain"] == TEST_DOMAIN

    def test_container_lifecycle_prints_own_types(self, capsys: pytest.CaptureFixture) -> None:
        emitter = reader.JsonEmitter()
        emitter.container_started("c1")
        emitter.container_exited("c1", reason="poststop")
        lines = capsys.readouterr().out.strip().splitlines()
        types = [json.loads(line)["type"] for line in lines]
        assert types == ["container_started", "container_exited"]


class TestSocketEmitter:
    """``SocketEmitter`` streams JSON lines to the hub's unix socket."""

    def test_connection_blocked_sends_pending_line(self, tmp_path: Path) -> None:
        path = tmp_path / "events.sock"
        fake_sock = mock.MagicMock()
        emitter = reader.SocketEmitter(path)
        with mock.patch.object(reader.socket, "socket", return_value=fake_sock):
            emitter.connection_blocked(
                reader.BlockedEvent(
                    container="c1",
                    request_id="c1:1",
                    dest=TEST_IP1,
                    port=443,
                    proto=socket.IPPROTO_TCP,
                    domain=TEST_DOMAIN,
                )
            )
        fake_sock.connect.assert_called_once_with(str(path))
        sent = fake_sock.sendall.call_args[0][0]
        assert sent.endswith(b"\n")
        payload = json.loads(sent)
        assert payload["type"] == "pending"
        assert payload["container"] == "c1"
        assert payload["domain"] == TEST_DOMAIN

    def test_connects_lazily_and_reuses_socket(self, tmp_path: Path) -> None:
        path = tmp_path / "events.sock"
        fake_sock = mock.MagicMock()
        emitter = reader.SocketEmitter(path)
        with mock.patch.object(reader.socket, "socket", return_value=fake_sock) as make_sock:
            emitter.container_started("c1")
            emitter.container_started("c1")
        assert make_sock.call_count == 1  # single connection reused
        assert fake_sock.sendall.call_count == 2

    def test_reconnects_after_send_failure(self, tmp_path: Path) -> None:
        path = tmp_path / "events.sock"
        first = mock.MagicMock()
        first.sendall.side_effect = ConnectionResetError("peer gone")
        second = mock.MagicMock()
        emitter = reader.SocketEmitter(path)
        with mock.patch.object(reader.socket, "socket", side_effect=[first, second]):
            emitter.container_started("c1")  # first try fails, socket closed
            emitter.container_started("c1")  # second try connects fresh
        assert first.close.called
        assert second.sendall.called

    def test_hub_unreachable_is_non_fatal(self, tmp_path: Path) -> None:
        """If the hub socket isn't there, sends are silently dropped after one warning."""
        path = tmp_path / "events.sock"
        fake_sock = mock.MagicMock()
        fake_sock.connect.side_effect = FileNotFoundError(path)
        emitter = reader.SocketEmitter(path)
        with mock.patch.object(reader.socket, "socket", return_value=fake_sock):
            emitter.container_started("c1")
            emitter.container_started("c1")  # must not raise, must not reconnect-loop
        assert fake_sock.sendall.call_count == 0

    def test_close_disconnects(self, tmp_path: Path) -> None:
        path = tmp_path / "events.sock"
        fake_sock = mock.MagicMock()
        emitter = reader.SocketEmitter(path)
        with mock.patch.object(reader.socket, "socket", return_value=fake_sock):
            emitter.container_started("c1")
            emitter.close()
        fake_sock.close.assert_called_once()
        emitter.close()  # idempotent


# ── Session integration ───────────────────────────────────────────────


class _RecordingEmitter:
    """Test double that captures every emission in call-order."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def container_started(self, container: str) -> None:
        self.calls.append(("started", container))

    def container_exited(self, container: str, *, reason: str) -> None:
        self.calls.append(("exited", (container, reason)))

    def connection_blocked(self, event: reader.BlockedEvent) -> None:
        self.calls.append(("blocked", event))


class TestReaderSession:
    """``ReaderSession`` dedupes by dest IP and wraps events with lifecycle signals."""

    def test_no_socket_means_no_events(self, tmp_path: Path) -> None:
        recorder = _RecordingEmitter()
        session = reader.ReaderSession(state_dir=tmp_path, container="c1", emitter=recorder)
        with mock.patch.object(reader, "_open_nflog_socket", return_value=None):
            session.run()
        assert recorder.calls == []

    def test_duplicate_dest_is_emitted_only_once(self, tmp_path: Path) -> None:
        recorder = _RecordingEmitter()
        session = reader.ReaderSession(state_dir=tmp_path, container="c1", emitter=recorder)
        fake_sock = _FakeSocket()

        raw = reader._RawBlockEvent(dest=TEST_IP1, port=443, proto=socket.IPPROTO_TCP)

        def fake_select(rfds: list, *_args: object, **_kwargs: object) -> tuple[list, list, list]:
            session._stop_requested = True  # exit after the first tick
            return (list(rfds), [], [])

        with (
            mock.patch.object(reader, "_open_nflog_socket", return_value=fake_sock),
            mock.patch.object(reader, "_drain", return_value=[raw, raw]),
            mock.patch.object(reader.select, "select", side_effect=fake_select),
        ):
            session.run()

        blocked_events = [payload for kind, payload in recorder.calls if kind == "blocked"]
        assert len(blocked_events) == 1
        assert blocked_events[0].dest == TEST_IP1

    def test_lifecycle_brackets_the_stream(self, tmp_path: Path) -> None:
        recorder = _RecordingEmitter()
        session = reader.ReaderSession(state_dir=tmp_path, container="c1", emitter=recorder)

        def fake_select(*_args: object, **_kwargs: object) -> tuple[list, list, list]:
            session._stop_requested = True
            return ([], [], [])

        with (
            mock.patch.object(reader, "_open_nflog_socket", return_value=_FakeSocket()),
            mock.patch.object(reader.select, "select", side_effect=fake_select),
        ):
            session.run()

        kinds = [kind for kind, _ in recorder.calls]
        assert kinds[0] == "started"
        assert kinds[-1] == "exited"


class _FakeSocket:
    """Minimal file-like stand-in for the NFLOG netlink socket."""

    def close(self) -> None:
        """No-op — present so ``ReaderSession.run``'s finally block can call it."""
