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

from ..testfs import AUDIT_FILENAME, DNSMASQ_LOG_FILENAME, READER_EVENTS_SOCK_FILENAME
from ..testnet import (
    IPV6_MCAST_ALL_ROUTERS,
    IPV6_MCAST_MLDV2,
    TEST_DOMAIN,
    TEST_IP1,
    TEST_IP2,
    TEST_IP99,
)

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

    def test_ipv4_with_invalid_ihl_returns_empty_tuple(self) -> None:
        """IHL < 5 (<20 bytes of header) is malformed — must not decode anything."""
        bad = bytearray(b"\x00" * 40)
        bad[0] = 0x40  # version 4, IHL 0
        assert reader._extract_ip_dest(bytes(bad)) == ("", 0, 0)


class TestParseMessagesBoundary:
    """``_parse_messages`` must give up on short / malformed netlink headers."""

    def test_short_nlmsg_len_breaks_loop(self) -> None:
        """nl_len smaller than the header stops parsing without crashing."""
        bad = reader._NLMSG_HDR.pack(8, 0, 0, 0, 0)  # nl_len < header size
        assert reader._parse_messages(bad) == []


class TestParseAttrsBoundary:
    """``_parse_attrs`` must bail on a too-small TLV length field."""

    def test_short_nfa_len_breaks_loop(self) -> None:
        """nfa_len smaller than its own header → parser stops, returns what it has."""
        bad = reader._NFA_HDR.pack(2, 0)  # nfa_len < header size
        assert reader._parse_attrs(bad) == {}


class TestSelectEmitter:
    """``_select_emitter`` picks the right emitter for ``--emit``."""

    def test_json_mode_returns_json_emitter(self) -> None:
        assert isinstance(reader._select_emitter("json"), reader.JsonEmitter)

    def test_default_mode_returns_socket_emitter(self) -> None:
        assert isinstance(reader._select_emitter("socket"), reader.SocketEmitter)


class TestParseAnnotations:
    """``_parse_annotations`` turns the JSON ``--annotations`` payload into a flat dict."""

    def test_well_formed_json_object_returns_dict(self) -> None:
        assert reader._parse_annotations('{"task": "abc", "project": "terok"}') == {
            "task": "abc",
            "project": "terok",
        }

    def test_empty_string_returns_empty_dict(self) -> None:
        assert reader._parse_annotations("") == {}

    def test_empty_object_returns_empty_dict(self) -> None:
        assert reader._parse_annotations("{}") == {}

    def test_malformed_json_soft_fails_to_empty(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level("WARNING", logger=reader.__name__)
        assert reader._parse_annotations("{not json") == {}
        assert any("malformed" in r.message for r in caplog.records)

    def test_non_object_payload_soft_fails_to_empty(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level("WARNING", logger=reader.__name__)
        assert reader._parse_annotations("[1, 2, 3]") == {}
        assert any("non-object" in r.message for r in caplog.records)

    def test_non_string_values_are_coerced(self) -> None:
        assert reader._parse_annotations('{"port": 1234}') == {"port": "1234"}


class TestReaderSessionDossierStorage:
    """ReaderSession holds onto the static dossier and meta_path for emit-time use."""

    def test_static_dossier_round_trips_unchanged(self, tmp_path: Path) -> None:
        session = reader.ReaderSession(
            state_dir=tmp_path,
            container="c1",
            emitter=_RecordingEmitter(),
            static_dossier={"task": "abc", "project": "terok"},
        )
        assert session._static_dossier == {"task": "abc", "project": "terok"}
        assert session._meta_path is None

    def test_meta_path_is_lifted_into_a_path(self, tmp_path: Path) -> None:
        meta = tmp_path / "task.json"
        session = reader.ReaderSession(
            state_dir=tmp_path,
            container="c1",
            emitter=_RecordingEmitter(),
            static_dossier={"meta_path": str(meta)},
        )
        assert session._meta_path == meta

    def test_default_static_dossier_is_empty(self, tmp_path: Path) -> None:
        session = reader.ReaderSession(
            state_dir=tmp_path,
            container="c1",
            emitter=_RecordingEmitter(),
        )
        assert session._static_dossier == {}
        assert session._meta_path is None


class TestResolveDossier:
    """``_resolve_dossier`` merges the orchestrator's wire-dossier JSON file with static annotations.

    The file at ``meta_path`` is wire-shape JSON (the keys the
    clearance UI renders directly) so the resolver is just a
    soft-fail merge.  Orchestrator bookkeeping lives in a separate
    file the orchestrator alone consumes — never on the wire.
    """

    def test_static_only_when_no_meta_path(self, tmp_path: Path) -> None:
        """Standalone path: static ``dossier.*`` annotations alone form the wire dossier."""
        session = reader.ReaderSession(
            state_dir=tmp_path,
            container="c1",
            emitter=_RecordingEmitter(),
            static_dossier={"task": "abc", "project": "terok"},
        )
        assert session._resolve_dossier() == {"task": "abc", "project": "terok"}

    def test_meta_path_key_does_not_leak_into_dossier(self, tmp_path: Path) -> None:
        """``meta_path`` is plumbing — it must never appear on the wire."""
        session = reader.ReaderSession(
            state_dir=tmp_path,
            container="c1",
            emitter=_RecordingEmitter(),
            static_dossier={"task": "abc", "meta_path": "/some/file.json"},
        )
        # File doesn't exist → dossier is just the static floor minus meta_path.
        assert session._resolve_dossier() == {"task": "abc"}

    def test_dossier_file_overrides_static_keys(self, tmp_path: Path) -> None:
        """Live wire-dossier JSON wins over static floor for matching keys.

        Static ``dossier.task=original`` (set at podman run) is
        overridden by the dossier JSON's ``task=renamed`` — the file is
        the orchestrator's live wire dossier and re-read on every emit
        so renames surface without a reader restart.
        """
        meta = tmp_path / "dossier.json"
        meta.write_text(json.dumps({"project": "terok", "task": "renamed", "name": "live-name"}))
        session = reader.ReaderSession(
            state_dir=tmp_path,
            container="c1",
            emitter=_RecordingEmitter(),
            static_dossier={"task": "original", "project": "terok", "meta_path": str(meta)},
        )
        assert session._resolve_dossier() == {
            "task": "renamed",
            "project": "terok",
            "name": "live-name",
        }

    def test_missing_meta_file_falls_back_to_static(self, tmp_path: Path) -> None:
        """A pointer at a deleted task → drop to the static-only floor."""
        session = reader.ReaderSession(
            state_dir=tmp_path,
            container="c1",
            emitter=_RecordingEmitter(),
            static_dossier={"task": "abc", "meta_path": str(tmp_path / "missing.json")},
        )
        assert session._resolve_dossier() == {"task": "abc"}

    def test_malformed_meta_file_falls_back_to_static(self, tmp_path: Path) -> None:
        meta = tmp_path / "dossier.json"
        meta.write_text("{not json")
        session = reader.ReaderSession(
            state_dir=tmp_path,
            container="c1",
            emitter=_RecordingEmitter(),
            static_dossier={"task": "abc", "meta_path": str(meta)},
        )
        assert session._resolve_dossier() == {"task": "abc"}

    def test_non_object_meta_file_falls_back_to_static(self, tmp_path: Path) -> None:
        """A JSON list/scalar at meta_path is rejected without crashing."""
        meta = tmp_path / "dossier.json"
        meta.write_text("[1, 2, 3]")
        session = reader.ReaderSession(
            state_dir=tmp_path,
            container="c1",
            emitter=_RecordingEmitter(),
            static_dossier={"task": "abc", "meta_path": str(meta)},
        )
        assert session._resolve_dossier() == {"task": "abc"}

    def test_falsy_values_in_meta_drop_out(self, tmp_path: Path) -> None:
        """Empty / null fields in the file don't bloat the wire."""
        meta = tmp_path / "dossier.json"
        meta.write_text(json.dumps({"project": "terok", "task": "abc", "name": ""}))
        session = reader.ReaderSession(
            state_dir=tmp_path,
            container="c1",
            emitter=_RecordingEmitter(),
            static_dossier={"meta_path": str(meta)},
        )
        assert session._resolve_dossier() == {"project": "terok", "task": "abc"}

    def test_meta_file_values_are_string_coerced(self, tmp_path: Path) -> None:
        """Forward-compat int/bool values still land as strings on the wire."""
        meta = tmp_path / "dossier.json"
        meta.write_text(json.dumps({"task": 42, "name": True}))
        session = reader.ReaderSession(
            state_dir=tmp_path,
            container="c1",
            emitter=_RecordingEmitter(),
            static_dossier={"meta_path": str(meta)},
        )
        assert session._resolve_dossier() == {"task": "42", "name": "True"}


class TestIsNoiseDest:
    """``_is_noise_dest`` filters IPv6 link-local multicast only."""

    def test_ff02_address_is_noise(self) -> None:
        assert reader._is_noise_dest(IPV6_MCAST_ALL_ROUTERS) is True
        assert reader._is_noise_dest(IPV6_MCAST_MLDV2) is True

    def test_regular_ipv6_is_not_noise(self) -> None:
        """A public IPv6 destination must surface normally."""
        assert reader._is_noise_dest("2001:db8::1") is False

    def test_ipv4_is_not_noise(self) -> None:
        assert reader._is_noise_dest(TEST_IP1) is False

    def test_non_address_string_is_not_noise(self) -> None:
        """Unparseable input maps to False so malformed data falls through to emit."""
        assert reader._is_noise_dest("not-an-ip") is False


class TestEventsSocketPath:
    """``_events_socket_path`` honours XDG, falls back to /run/user/<uid>."""

    def test_xdg_runtime_dir_wins(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
        assert reader._events_socket_path() == tmp_path / "terok-shield-events.sock"

    def test_xdg_missing_falls_back_to_run_user(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        path = reader._events_socket_path()
        assert str(path).startswith("/run/user/")
        assert path.name == "terok-shield-events.sock"


class TestResolveBinary:
    """``_resolve_binary`` returns an absolute path or the /usr/bin fallback."""

    def test_which_hit_returns_absolute_path(self) -> None:
        with mock.patch.object(reader.shutil, "which", return_value="/opt/custom/bin/podman"):
            assert reader._resolve_binary("podman") == "/opt/custom/bin/podman"

    def test_which_miss_returns_usr_bin_fallback(self) -> None:
        with mock.patch.object(reader.shutil, "which", return_value=None):
            assert reader._resolve_binary("podman") == "/usr/bin/podman"


class TestOnStopSignal:
    """SIGTERM handler flips the stop flag so the select loop exits next tick."""

    def test_flips_stop_requested(self, tmp_path: Path) -> None:
        session = reader.ReaderSession(
            state_dir=tmp_path,
            container="c1",
            emitter=_RecordingEmitter(),
        )
        assert session._stop_requested is False
        session._on_stop_signal(15, None)
        assert session._stop_requested is True


class TestSocketEmitterContainerExited:
    """Ensure ``container_exited`` publishes a well-formed JSON frame with reason."""

    def test_emits_exited_payload(self, tmp_path: Path) -> None:
        path = tmp_path / READER_EVENTS_SOCK_FILENAME
        fake_sock = mock.MagicMock()
        emitter = reader.SocketEmitter(path)
        with mock.patch.object(reader.socket, "socket", return_value=fake_sock):
            emitter.container_exited("c1", reason="poststop")
        sent = fake_sock.sendall.call_args[0][0]
        payload = json.loads(sent)
        assert payload == {"type": "container_exited", "container": "c1", "reason": "poststop"}


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
        allowed = _nflog_message("ALLOWED", _ipv4_tcp_packet(dest=TEST_IP99, port=443))
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
        log = tmp_path / DNSMASQ_LOG_FILENAME
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
        assert payload["dossier"] == {}

    def test_connection_blocked_carries_dossier(self, capsys: pytest.CaptureFixture) -> None:
        """A non-empty ``dossier`` field lands as a JSON object on the wire."""
        emitter = reader.JsonEmitter()
        emitter.connection_blocked(
            reader.BlockedEvent(
                container="c1",
                request_id="c1:1",
                dest=TEST_IP1,
                port=443,
                proto=socket.IPPROTO_TCP,
                domain=TEST_DOMAIN,
                dossier={"task": "abc", "container_name": "n1"},
            )
        )
        payload = json.loads(capsys.readouterr().out.strip())
        assert payload["dossier"] == {"task": "abc", "container_name": "n1"}

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
        path = tmp_path / READER_EVENTS_SOCK_FILENAME
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
                    dossier={"task": "abc"},
                )
            )
        fake_sock.connect.assert_called_once_with(str(path))
        sent = fake_sock.sendall.call_args[0][0]
        assert sent.endswith(b"\n")
        payload = json.loads(sent)
        assert payload["type"] == "pending"
        assert payload["container"] == "c1"
        assert payload["domain"] == TEST_DOMAIN
        assert payload["dossier"] == {"task": "abc"}

    def test_connects_lazily_and_reuses_socket(self, tmp_path: Path) -> None:
        path = tmp_path / READER_EVENTS_SOCK_FILENAME
        fake_sock = mock.MagicMock()
        emitter = reader.SocketEmitter(path)
        with mock.patch.object(reader.socket, "socket", return_value=fake_sock) as make_sock:
            emitter.container_started("c1")
            emitter.container_started("c1")
        assert make_sock.call_count == 1  # single connection reused
        assert fake_sock.sendall.call_count == 2

    def test_reconnects_after_send_failure(self, tmp_path: Path) -> None:
        path = tmp_path / READER_EVENTS_SOCK_FILENAME
        first = mock.MagicMock()
        first.sendall.side_effect = ConnectionResetError("peer gone")
        second = mock.MagicMock()
        emitter = reader.SocketEmitter(path)
        with mock.patch.object(reader.socket, "socket", side_effect=[first, second]):
            emitter.container_started("c1")  # first try fails, socket closed
            emitter.container_started("c1")  # second try connects fresh
        assert first.close.called
        assert second.sendall.called

    def test_single_send_retries_once_after_stale_socket(self, tmp_path: Path) -> None:
        """Hub restart leaves our cached fd dangling — one call must reach the new hub."""
        path = tmp_path / READER_EVENTS_SOCK_FILENAME
        stale = mock.MagicMock()
        stale.sendall.side_effect = BrokenPipeError("hub restarted")
        fresh = mock.MagicMock()
        emitter = reader.SocketEmitter(path)
        with mock.patch.object(reader.socket, "socket", side_effect=[stale, fresh]):
            ok = emitter.connection_blocked(
                reader.BlockedEvent(
                    container="c1",
                    request_id="c1:1",
                    dest=TEST_IP1,
                    port=443,
                    proto=socket.IPPROTO_TCP,
                    domain=TEST_DOMAIN,
                )
            )
        assert ok is True
        assert stale.close.called
        fresh.sendall.assert_called_once()

    def test_send_returns_false_when_hub_unreachable(self, tmp_path: Path) -> None:
        """Persistent unreachability is the no-dedup signal ``_maybe_emit`` wants."""
        path = tmp_path / READER_EVENTS_SOCK_FILENAME
        fake_sock = mock.MagicMock()
        fake_sock.connect.side_effect = FileNotFoundError(path)
        emitter = reader.SocketEmitter(path)
        with mock.patch.object(reader.socket, "socket", return_value=fake_sock):
            ok = emitter.connection_blocked(
                reader.BlockedEvent(
                    container="c1",
                    request_id="c1:1",
                    dest=TEST_IP1,
                    port=443,
                    proto=socket.IPPROTO_TCP,
                    domain=TEST_DOMAIN,
                )
            )
        assert ok is False

    def test_send_returns_false_when_retry_also_fails(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Both attempts fail → WARNING + return False (no silent dedup)."""
        path = tmp_path / READER_EVENTS_SOCK_FILENAME
        first = mock.MagicMock()
        first.sendall.side_effect = ConnectionResetError("peer gone")
        second = mock.MagicMock()
        second.sendall.side_effect = BrokenPipeError("still gone")
        emitter = reader.SocketEmitter(path)
        caplog.set_level("INFO", logger=reader.__name__)
        with mock.patch.object(reader.socket, "socket", side_effect=[first, second]):
            ok = emitter.connection_blocked(
                reader.BlockedEvent(
                    container="c1",
                    request_id="c1:1",
                    dest=TEST_IP1,
                    port=443,
                    proto=socket.IPPROTO_TCP,
                    domain=TEST_DOMAIN,
                )
            )
        assert ok is False
        assert any("hub event socket send failed" in r.message for r in caplog.records)

    def test_hub_unreachable_is_non_fatal(self, tmp_path: Path) -> None:
        """If the hub socket isn't there, sends are silently dropped after one warning."""
        path = tmp_path / READER_EVENTS_SOCK_FILENAME
        fake_sock = mock.MagicMock()
        fake_sock.connect.side_effect = FileNotFoundError(path)
        emitter = reader.SocketEmitter(path)
        with mock.patch.object(reader.socket, "socket", return_value=fake_sock):
            emitter.container_started("c1")
            emitter.container_started("c1")  # must not raise, must not reconnect-loop
        assert fake_sock.sendall.call_count == 0

    def test_close_disconnects(self, tmp_path: Path) -> None:
        path = tmp_path / READER_EVENTS_SOCK_FILENAME
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

    def connection_blocked(self, event: reader.BlockedEvent) -> bool:
        self.calls.append(("blocked", event))
        return True


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

    def test_failed_emit_does_not_poison_dedup_window(self, tmp_path: Path) -> None:
        """Hub unreachable → emit fails → retry on next NFLOG tick must still fire."""

        class _FlakyEmitter:
            calls = 0

            def container_started(self, container: str) -> None: ...
            def container_exited(self, container: str, *, reason: str) -> None: ...
            def close(self) -> None: ...

            def connection_blocked(self, event: reader.BlockedEvent) -> bool:
                self.calls += 1
                return self.calls > 1  # first call fails, second succeeds

        emitter = _FlakyEmitter()
        session = reader.ReaderSession(state_dir=tmp_path, container="c1", emitter=emitter)
        raw = reader._RawBlockEvent(dest=TEST_IP1, port=443, proto=socket.IPPROTO_TCP)
        # Drive two ticks so a failed emit on tick 1 can retry on tick 2
        # without the dedup window suppressing the retry.
        session._maybe_emit(raw, now=0.0)
        session._maybe_emit(raw, now=1.0)
        assert emitter.calls == 2

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

    def test_select_oserror_exits_cleanly(self, tmp_path: Path) -> None:
        """If the NFLOG socket closes mid-loop, ``select.select`` raises — we return."""
        recorder = _RecordingEmitter()
        session = reader.ReaderSession(state_dir=tmp_path, container="c1", emitter=recorder)
        with (
            mock.patch.object(reader, "_open_nflog_socket", return_value=_FakeSocket()),
            mock.patch.object(reader.select, "select", side_effect=OSError("bad fd")),
        ):
            session.run()
        # No blocked events emitted, but the container_started/exited bracket still runs.
        kinds = [kind for kind, _ in recorder.calls]
        assert kinds[0] == "started"
        assert kinds[-1] == "exited"

    def test_ipv6_link_local_multicast_is_silently_dropped(self, tmp_path: Path) -> None:
        """MLD / router-discovery blocks are kernel noise — the reader drops them."""
        recorder = _RecordingEmitter()
        session = reader.ReaderSession(state_dir=tmp_path, container="c1", emitter=recorder)
        fake_sock = _FakeSocket()
        noise = [
            reader._RawBlockEvent(dest=IPV6_MCAST_ALL_ROUTERS, port=0, proto=socket.IPPROTO_ICMPV6),
            reader._RawBlockEvent(dest=IPV6_MCAST_MLDV2, port=0, proto=socket.IPPROTO_ICMPV6),
        ]

        def fake_select(rfds: list, *_args: object, **_kwargs: object) -> tuple[list, list, list]:
            session._stop_requested = True
            return (list(rfds), [], [])

        with (
            mock.patch.object(reader, "_open_nflog_socket", return_value=fake_sock),
            mock.patch.object(reader, "_drain", return_value=noise),
            mock.patch.object(reader.select, "select", side_effect=fake_select),
        ):
            session.run()

        blocked_events = [payload for kind, payload in recorder.calls if kind == "blocked"]
        assert blocked_events == []

    def test_multi_ip_for_one_domain_is_emitted_once(self, tmp_path: Path) -> None:
        """Two IPs that resolve to the same domain collapse to one block event."""
        recorder = _RecordingEmitter()
        session = reader.ReaderSession(state_dir=tmp_path, container="c1", emitter=recorder)
        # Seed the domain cache so both IPs map to the same name.
        session._domain_cache._mapping = {TEST_IP1: TEST_DOMAIN, TEST_IP2: TEST_DOMAIN}
        fake_sock = _FakeSocket()
        events = [
            reader._RawBlockEvent(dest=TEST_IP1, port=443, proto=socket.IPPROTO_TCP),
            reader._RawBlockEvent(dest=TEST_IP2, port=443, proto=socket.IPPROTO_TCP),
        ]

        def fake_select(rfds: list, *_args: object, **_kwargs: object) -> tuple[list, list, list]:
            session._stop_requested = True
            return (list(rfds), [], [])

        with (
            mock.patch.object(reader, "_open_nflog_socket", return_value=fake_sock),
            mock.patch.object(reader, "_drain", return_value=events),
            mock.patch.object(reader.select, "select", side_effect=fake_select),
        ):
            session.run()

        blocked_events = [payload for kind, payload in recorder.calls if kind == "blocked"]
        assert len(blocked_events) == 1
        assert blocked_events[0].domain == TEST_DOMAIN

    def test_emit_carries_resolved_dossier_on_blocked_event(self, tmp_path: Path) -> None:
        """End-to-end: static floor + wire-dossier JSON file land in ``BlockedEvent.dossier``."""
        meta = tmp_path / "dossier.json"
        meta.write_text(json.dumps({"task": "live", "name": "diligent-octopus"}))
        recorder = _RecordingEmitter()
        session = reader.ReaderSession(
            state_dir=tmp_path,
            container="c1",
            emitter=recorder,
            static_dossier={
                "project": "terok",
                "task": "stale",
                "meta_path": str(meta),
            },
        )
        raw = reader._RawBlockEvent(dest=TEST_IP1, port=443, proto=socket.IPPROTO_TCP)
        session._maybe_emit(raw, now=0.0)

        blocked = next(payload for kind, payload in recorder.calls if kind == "blocked")
        assert blocked.dossier == {
            "project": "terok",
            "task": "live",  # the live dossier file overrides the stale static value
            "name": "diligent-octopus",
        }

    def test_dedup_falls_back_to_dest_when_domain_unknown(self, tmp_path: Path) -> None:
        """With no cached domain, dedup stays on raw dest IP — no regression."""
        recorder = _RecordingEmitter()
        session = reader.ReaderSession(state_dir=tmp_path, container="c1", emitter=recorder)
        fake_sock = _FakeSocket()
        # Two *distinct* IPs, no domain in cache → two emissions expected.
        events = [
            reader._RawBlockEvent(dest=TEST_IP1, port=443, proto=socket.IPPROTO_TCP),
            reader._RawBlockEvent(dest=TEST_IP99, port=443, proto=socket.IPPROTO_TCP),
        ]

        def fake_select(rfds: list, *_args: object, **_kwargs: object) -> tuple[list, list, list]:
            session._stop_requested = True
            return (list(rfds), [], [])

        with (
            mock.patch.object(reader, "_open_nflog_socket", return_value=fake_sock),
            mock.patch.object(reader, "_drain", return_value=events),
            mock.patch.object(reader.select, "select", side_effect=fake_select),
        ):
            session.run()

        blocked_events = [payload for kind, payload in recorder.calls if kind == "blocked"]
        assert {e.dest for e in blocked_events} == {TEST_IP1, TEST_IP99}


class TestAuditBlockAppend:
    """Reader writes ``"action": "blocked"`` to ``state_dir/audit.jsonl`` per emit.

    Closes the audit-trail asymmetry: lifecycle (``shield_up`` /
    ``shield_down``) and verdicts (``allowed`` / ``denied``) were
    already audited by host-side shield code; blocks were not, leaving
    the timeline missing the very events that triggered every verdict.
    """

    def test_block_writes_audit_line_with_expected_shape(self, tmp_path: Path) -> None:
        recorder = _RecordingEmitter()
        session = reader.ReaderSession(state_dir=tmp_path, container="c1", emitter=recorder)
        raw = reader._RawBlockEvent(dest=TEST_IP1, port=443, proto=socket.IPPROTO_TCP)
        session._maybe_emit(raw, now=0.0)

        audit_path = tmp_path / AUDIT_FILENAME
        assert audit_path.is_file()
        entries = [json.loads(line) for line in audit_path.read_text().splitlines()]
        assert len(entries) == 1
        entry = entries[0]
        assert entry["action"] == "blocked"
        assert entry["container"] == "c1"
        assert entry["dest"] == TEST_IP1
        assert entry["port"] == 443
        assert entry["proto"] == "tcp"
        assert "ts" in entry  # don't pin timestamp content; just ensure presence

    def test_audit_includes_domain_when_resolved(self, tmp_path: Path) -> None:
        """Resolved domain ends up in the audit entry alongside dest IP."""
        # Seed the dnsmasq log so DomainCache resolves TEST_IP1 → TEST_DOMAIN.
        log_path = tmp_path / DNSMASQ_LOG_FILENAME
        log_path.write_text(f"... reply {TEST_DOMAIN} is {TEST_IP1}\n")

        recorder = _RecordingEmitter()
        session = reader.ReaderSession(state_dir=tmp_path, container="c1", emitter=recorder)
        raw = reader._RawBlockEvent(dest=TEST_IP1, port=443, proto=socket.IPPROTO_TCP)
        session._maybe_emit(raw, now=0.0)

        entries = [
            json.loads(line) for line in (tmp_path / AUDIT_FILENAME).read_text().splitlines()
        ]
        assert entries[0]["domain"] == TEST_DOMAIN

    def test_audit_omits_domain_when_unresolved(self, tmp_path: Path) -> None:
        """No resolved domain → no ``domain`` key in the audit entry (vs. empty string)."""
        recorder = _RecordingEmitter()
        session = reader.ReaderSession(state_dir=tmp_path, container="c1", emitter=recorder)
        raw = reader._RawBlockEvent(dest=TEST_IP1, port=443, proto=socket.IPPROTO_TCP)
        session._maybe_emit(raw, now=0.0)

        entry = json.loads((tmp_path / AUDIT_FILENAME).read_text().splitlines()[0])
        assert "domain" not in entry

    def test_audit_includes_dossier_when_non_empty(self, tmp_path: Path) -> None:
        """Resolved dossier flows into the audit entry alongside dest/port/proto."""
        recorder = _RecordingEmitter()
        session = reader.ReaderSession(
            state_dir=tmp_path,
            container="c1",
            emitter=recorder,
            static_dossier={"task": "abc", "project": "terok"},
        )
        raw = reader._RawBlockEvent(dest=TEST_IP1, port=443, proto=socket.IPPROTO_TCP)
        session._maybe_emit(raw, now=0.0)

        entry = json.loads((tmp_path / AUDIT_FILENAME).read_text().splitlines()[0])
        assert entry["dossier"] == {"task": "abc", "project": "terok"}

    def test_audit_omits_dossier_when_empty(self, tmp_path: Path) -> None:
        """Shield-only deployments don't pad audit rows with an empty ``dossier`` key."""
        recorder = _RecordingEmitter()
        session = reader.ReaderSession(state_dir=tmp_path, container="c1", emitter=recorder)
        raw = reader._RawBlockEvent(dest=TEST_IP1, port=443, proto=socket.IPPROTO_TCP)
        session._maybe_emit(raw, now=0.0)

        entry = json.loads((tmp_path / AUDIT_FILENAME).read_text().splitlines()[0])
        assert "dossier" not in entry

    def test_audit_written_before_wire_emit(self, tmp_path: Path) -> None:
        """Hub down (emitter returns False) → audit entry is still recorded.

        Auditing should be terminal-end, not best-effort: the operator
        can lose a popup to a hub restart and still need the forensic
        record of which destination got blocked when.
        """

        class _AlwaysFailingEmitter:
            def container_started(self, container: str) -> None: ...
            def container_exited(self, container: str, *, reason: str) -> None: ...
            def close(self) -> None: ...

            def connection_blocked(self, event: reader.BlockedEvent) -> bool:
                return False  # hub unreachable

        emitter = _AlwaysFailingEmitter()
        session = reader.ReaderSession(state_dir=tmp_path, container="c1", emitter=emitter)
        raw = reader._RawBlockEvent(dest=TEST_IP1, port=443, proto=socket.IPPROTO_TCP)
        session._maybe_emit(raw, now=0.0)

        audit_path = tmp_path / AUDIT_FILENAME
        assert audit_path.is_file()
        assert "blocked" in audit_path.read_text()

    def test_audit_failure_does_not_break_wire_emit(self, tmp_path: Path) -> None:
        """Unwriteable audit log soft-fails — the wire emit must still happen."""
        recorder = _RecordingEmitter()
        # Make the audit write impossible by replacing audit.jsonl with a directory.
        (tmp_path / AUDIT_FILENAME).mkdir()

        session = reader.ReaderSession(state_dir=tmp_path, container="c1", emitter=recorder)
        raw = reader._RawBlockEvent(dest=TEST_IP1, port=443, proto=socket.IPPROTO_TCP)
        session._maybe_emit(raw, now=0.0)

        # Wire still received the event despite audit failure.
        kinds = [kind for kind, _ in recorder.calls]
        assert "blocked" in kinds

    def test_proto_falls_back_to_numeric_for_non_tcp_udp(self, tmp_path: Path) -> None:
        """Anything other than TCP/UDP gets the numeric proto in the audit entry."""
        recorder = _RecordingEmitter()
        session = reader.ReaderSession(state_dir=tmp_path, container="c1", emitter=recorder)
        raw = reader._RawBlockEvent(dest=TEST_IP1, port=0, proto=132)  # SCTP
        session._maybe_emit(raw, now=0.0)

        entry = json.loads((tmp_path / AUDIT_FILENAME).read_text().splitlines()[0])
        assert entry["proto"] == "132"

    def test_hub_outage_does_not_flood_audit_log(self, tmp_path: Path) -> None:
        """Repeated retries during a hub outage produce one audit line per dedup window.

        Without separate audit/wire dedup tracking, a hub-down scenario
        would re-trigger ``_emit_connection_blocked`` on every NFLOG
        packet (because ``_last_emit`` stays unmarked while the wire
        keeps failing) and *each* of those retries would re-write the
        same ``"blocked"`` line — flooding the forensic log during the
        very window where it's least helpful.  ``_last_audit`` is the
        knob that prevents that without giving up wire-side retries.
        """

        class _AlwaysFailingEmitter:
            def container_started(self, container: str) -> None: ...
            def container_exited(self, container: str, *, reason: str) -> None: ...
            def close(self) -> None: ...

            def connection_blocked(self, event: reader.BlockedEvent) -> bool:
                return False

        emitter = _AlwaysFailingEmitter()
        session = reader.ReaderSession(state_dir=tmp_path, container="c1", emitter=emitter)
        raw = reader._RawBlockEvent(dest=TEST_IP1, port=443, proto=socket.IPPROTO_TCP)
        # Five NFLOG packets within the same dedup window — TCP retries.
        for t in (0.0, 1.0, 2.0, 5.0, 10.0):
            session._maybe_emit(raw, now=t)

        lines = (tmp_path / AUDIT_FILENAME).read_text().splitlines()
        assert len(lines) == 1, (
            "audit-log dedup window must collapse retry storms to one entry; "
            f"got {len(lines)} entries"
        )


class _FakeSocket:
    """Minimal file-like stand-in for the NFLOG netlink socket."""

    def close(self) -> None:
        """No-op — present so ``ReaderSession.run``'s finally block can call it."""
