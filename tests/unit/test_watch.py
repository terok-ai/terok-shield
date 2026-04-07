# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the watch module (DNS log, audit log, and NFLOG event streams)."""

from __future__ import annotations

import json
import socket
import struct
from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import terok_shield.cli.watch as _cli_watch_mod
from terok_shield.cli.watch import (
    _enrich_nflog,
    _ensure_log_file,
    _handle_signal,
    run_watch,
)
from terok_shield.config import DnsTier
from terok_shield.nft.constants import (
    ALLOWED_LOG_PREFIX,
    BLOCKED_LOG_PREFIX,
    BYPASS_LOG_PREFIX,
    DENIED_LOG_PREFIX,
    NFLOG_GROUP,
    PRIVATE_LOG_PREFIX,
)
from terok_shield.watchers import (
    AuditLogWatcher,
    DnsLogWatcher,
    DomainCache,
    NflogWatcher,
    WatchEvent,
)
from terok_shield.watchers.dns_log import _DOMAIN_REFRESH_INTERVAL, _QUERY_RE
from terok_shield.watchers.nflog import (
    _NFA_HDR,
    _NFGEN_HDR,
    _NFNL_SUBSYS_ULOG,
    _NFULA_PAYLOAD,
    _NFULA_PREFIX,
    _NFULNL_MSG_PACKET,
    _NLMSG_HDR,
    _build_nflog_bind_msg,
    _extract_ip_dest,
    _parse_nflog_attrs,
)
from tests.testnet import (
    BLOCKED_DOMAIN,
    BLOCKED_SUBDOMAIN,
    DNSMASQ_DOMAIN,
    TEST_DOMAIN,
    TEST_DOMAIN2,
    TEST_IP1,
    TEST_IP2,
)

_CONTAINER = "test-container"


@pytest.fixture(autouse=False)
def _restore_running() -> Generator[None, None, None]:
    """Capture and restore ``terok_shield.cli.watch._running`` around tests that mutate it."""
    original = _cli_watch_mod._running
    yield
    _cli_watch_mod._running = original


# ── WatchEvent ──────────────────────────────────────────


class TestWatchEvent:
    """Test WatchEvent dataclass and serialization."""

    def test_to_json_round_trips(self) -> None:
        """JSON output can be parsed back to the same fields."""
        event = WatchEvent(
            ts="2026-03-31T12:00:00+00:00",
            source="dns",
            action="blocked_query",
            domain=BLOCKED_DOMAIN,
            query_type="A",
            container=_CONTAINER,
        )
        parsed = json.loads(event.to_json())
        assert parsed["domain"] == BLOCKED_DOMAIN
        assert parsed["action"] == "blocked_query"
        assert parsed["source"] == "dns"
        assert parsed["query_type"] == "A"
        assert parsed["container"] == _CONTAINER

    def test_to_json_is_compact(self) -> None:
        """JSON output uses compact separators (no spaces)."""
        event = WatchEvent(
            ts="2026-01-01T00:00:00+00:00",
            source="dns",
            action="blocked_query",
            domain=BLOCKED_DOMAIN,
            query_type="AAAA",
            container=_CONTAINER,
        )
        raw = event.to_json()
        assert ": " not in raw
        assert ", " not in raw

    def test_to_json_omits_empty_optional_fields(self) -> None:
        """Empty optional fields are omitted from JSON output."""
        event = WatchEvent(
            ts="2026-01-01T00:00:00+00:00",
            source="audit",
            action="allowed",
            container=_CONTAINER,
        )
        parsed = json.loads(event.to_json())
        assert "domain" not in parsed
        assert "query_type" not in parsed
        assert "dest" not in parsed
        assert "detail" not in parsed
        assert "port" not in parsed
        assert "proto" not in parsed
        assert "extra" not in parsed
        assert parsed["source"] == "audit"
        assert parsed["action"] == "allowed"

    def test_to_json_includes_nonempty_optional_fields(self) -> None:
        """Non-empty optional fields are included in JSON output."""
        event = WatchEvent(
            ts="2026-01-01T00:00:00+00:00",
            source="nflog",
            action="blocked_connection",
            container=_CONTAINER,
            dest="192.0.2.1",
            port=443,
            proto=6,
            detail="TEROK_SHIELD_DENIED:",
            extra={"reason": "no-dns"},
        )
        parsed = json.loads(event.to_json())
        assert parsed["dest"] == "192.0.2.1"
        assert parsed["port"] == 443
        assert parsed["proto"] == 6
        assert parsed["detail"] == "TEROK_SHIELD_DENIED:"
        assert parsed["extra"] == {"reason": "no-dns"}

    def test_core_fields_always_present(self) -> None:
        """Core fields are always present even when their values are empty-ish."""
        event = WatchEvent(
            ts="",
            source="",
            action="",
            container="",
        )
        parsed = json.loads(event.to_json())
        assert "ts" in parsed
        assert "source" in parsed
        assert "action" in parsed
        assert "container" in parsed


# ── Query regex ─────────────────────────────────────────


class TestQueryRegex:
    """Test the dnsmasq query log line regex."""

    @pytest.mark.parametrize(
        ("line", "expected_type", "expected_domain"),
        [
            pytest.param(
                f"Mar 31 12:00:00 dnsmasq[123]: query[A] {BLOCKED_DOMAIN} from 127.0.0.1",
                "A",
                BLOCKED_DOMAIN,
                id="query-A",
            ),
            pytest.param(
                f"Mar 31 12:00:00 dnsmasq[123]: query[AAAA] {BLOCKED_DOMAIN} from 127.0.0.1",
                "AAAA",
                BLOCKED_DOMAIN,
                id="query-AAAA",
            ),
        ],
    )
    def test_matches_query_lines(self, line: str, expected_type: str, expected_domain: str) -> None:
        """Regex extracts query type and domain from dnsmasq log lines."""
        m = _QUERY_RE.search(line)
        assert m is not None
        assert m.group(1) == expected_type
        assert m.group(2) == expected_domain

    @pytest.mark.parametrize(
        "line",
        [
            pytest.param(
                f"Mar 31 12:00:00 dnsmasq[123]: reply {BLOCKED_DOMAIN} is 1.2.3.4",
                id="reply-line",
            ),
            pytest.param(
                f"Mar 31 12:00:00 dnsmasq[123]: forwarded {BLOCKED_DOMAIN} to 169.254.1.1",
                id="forwarded-line",
            ),
            pytest.param(
                "Mar 31 12:00:00 dnsmasq[123]: started, cache size 150",
                id="startup-line",
            ),
            pytest.param("", id="empty-line"),
        ],
    )
    def test_ignores_non_query_lines(self, line: str) -> None:
        """Regex does not match non-query dnsmasq log lines."""
        assert _QUERY_RE.search(line) is None


# ── DnsLogWatcher ───────────────────────────────────────


class TestDnsLogWatcher:
    """Test DnsLogWatcher file tailing and domain classification."""

    @pytest.fixture
    def state_dir(self, tmp_path: Path) -> Path:
        """Create a minimal state dir with profile.domains."""
        sd = tmp_path / "state"
        sd.mkdir()
        # Write allowed domains
        (sd / "profile.domains").write_text(f"{TEST_DOMAIN}\n{TEST_DOMAIN2}\n")
        # Create the log file
        (sd / "dnsmasq.log").write_text("")
        return sd

    def test_blocked_domain_produces_event(self, state_dir: Path) -> None:
        """A query for a non-allowed domain yields a blocked_query event."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        with log.open("a") as f:
            f.write(f"query[A] {BLOCKED_DOMAIN} from 127.0.0.1\n")
        events = watcher.poll()
        watcher.close()
        assert len(events) == 1
        assert events[0].domain == BLOCKED_DOMAIN
        assert events[0].action == "blocked_query"

    def test_allowed_domain_produces_no_event(self, state_dir: Path) -> None:
        """A query for an allowed domain yields no event."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        with log.open("a") as f:
            f.write(f"query[A] {TEST_DOMAIN} from 127.0.0.1\n")
        events = watcher.poll()
        watcher.close()
        assert events == []

    def test_subdomain_of_allowed_is_allowed(self, state_dir: Path) -> None:
        """Subdomains of allowed domains are also allowed (nftset behavior)."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        with log.open("a") as f:
            f.write(f"query[A] api.{TEST_DOMAIN} from 127.0.0.1\n")
        events = watcher.poll()
        watcher.close()
        assert events == []

    def test_subdomain_of_blocked_is_blocked(self, state_dir: Path) -> None:
        """Subdomains of non-allowed domains are also blocked."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        with log.open("a") as f:
            f.write(f"query[A] {BLOCKED_SUBDOMAIN} from 127.0.0.1\n")
        events = watcher.poll()
        watcher.close()
        assert len(events) == 1
        assert events[0].domain == BLOCKED_SUBDOMAIN

    def test_empty_read_produces_no_events(self, state_dir: Path) -> None:
        """poll() returns empty list when no new lines are available."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        events = watcher.poll()
        watcher.close()
        assert events == []

    def test_multiple_queries_in_batch(self, state_dir: Path) -> None:
        """Multiple queries appended at once are all processed."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        with log.open("a") as f:
            f.write(
                f"query[A] {BLOCKED_DOMAIN} from 127.0.0.1\n"
                f"query[AAAA] {BLOCKED_DOMAIN} from 127.0.0.1\n"
                f"query[A] {TEST_DOMAIN} from 127.0.0.1\n"
            )
        events = watcher.poll()
        watcher.close()
        assert len(events) == 2
        assert {e.query_type for e in events} == {"A", "AAAA"}

    def test_non_query_lines_are_skipped(self, state_dir: Path) -> None:
        """Reply and forwarded lines do not produce events."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        with log.open("a") as f:
            f.write(
                f"reply {BLOCKED_DOMAIN} is 1.2.3.4\nforwarded {BLOCKED_DOMAIN} to 169.254.1.1\n"
            )
        events = watcher.poll()
        watcher.close()
        assert events == []

    def test_fileno_returns_int(self, state_dir: Path) -> None:
        """fileno() returns a valid file descriptor for select()."""
        log = state_dir / "dnsmasq.log"
        watcher = DnsLogWatcher(log, state_dir, _CONTAINER)
        assert isinstance(watcher.fileno(), int)
        watcher.close()

    def test_init_closes_fh_on_refresh_failure(self, tmp_path: Path) -> None:
        """File handle is closed if _refresh_domains() raises during __init__."""
        sd = tmp_path / "state"
        sd.mkdir()
        log = sd / "dnsmasq.log"
        log.write_text("")
        # Make read_merged_domains raise by putting an unreadable file
        domains = sd / "profile.domains"
        domains.write_text(f"{TEST_DOMAIN}\n")
        with patch(
            "terok_shield.watchers.dns_log.dnsmasq.read_merged_domains",
            side_effect=OSError("boom"),
        ):
            with pytest.raises(OSError, match="boom"):
                DnsLogWatcher(log, sd, _CONTAINER)
        # File handle should be closed — opening again must succeed (not leak fds)
        with log.open() as f:
            assert f.readable()


# ── AuditLogWatcher ────────────────────────────────────


class TestAuditLogWatcher:
    """Test AuditLogWatcher file tailing and event conversion."""

    def test_new_audit_entry_produces_event(self, tmp_path: Path) -> None:
        """A new JSON line in audit.jsonl yields a watch event."""
        audit = tmp_path / "audit.jsonl"
        audit.write_text("")
        watcher = AuditLogWatcher(audit, _CONTAINER)
        entry = {
            "ts": "2026-04-01T12:00:00+00:00",
            "container": _CONTAINER,
            "action": "allowed",
            "dest": "192.0.2.1",
            "detail": "target=github.com",
        }
        with audit.open("a") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        events = watcher.poll()
        watcher.close()
        assert len(events) == 1
        assert events[0].source == "audit"
        assert events[0].action == "allowed"
        assert events[0].dest == "192.0.2.1"
        assert events[0].detail == "target=github.com"
        assert events[0].ts == "2026-04-01T12:00:00+00:00"

    def test_empty_audit_log_produces_no_events(self, tmp_path: Path) -> None:
        """poll() returns empty list when no new lines are available."""
        audit = tmp_path / "audit.jsonl"
        audit.write_text("")
        watcher = AuditLogWatcher(audit, _CONTAINER)
        events = watcher.poll()
        watcher.close()
        assert events == []

    def test_malformed_json_is_skipped(self, tmp_path: Path) -> None:
        """Malformed JSON lines are silently skipped."""
        audit = tmp_path / "audit.jsonl"
        audit.write_text("")
        watcher = AuditLogWatcher(audit, _CONTAINER)
        with audit.open("a") as f:
            f.write("not valid json\n")
            f.write('{"ts":"2026-04-01T00:00:00","action":"setup","container":"x"}\n')
        events = watcher.poll()
        watcher.close()
        assert len(events) == 1
        assert events[0].action == "setup"

    def test_multiple_entries_in_batch(self, tmp_path: Path) -> None:
        """Multiple audit lines appended at once are all processed."""
        audit = tmp_path / "audit.jsonl"
        audit.write_text("")
        watcher = AuditLogWatcher(audit, _CONTAINER)
        with audit.open("a") as f:
            for action in ("setup", "allowed", "denied", "shield_down"):
                entry = {"ts": "2026-04-01T00:00:00", "action": action, "container": _CONTAINER}
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        events = watcher.poll()
        watcher.close()
        assert len(events) == 4
        assert [e.action for e in events] == ["setup", "allowed", "denied", "shield_down"]

    def test_fileno_returns_int(self, tmp_path: Path) -> None:
        """fileno() returns a valid file descriptor for select()."""
        audit = tmp_path / "audit.jsonl"
        audit.write_text("")
        watcher = AuditLogWatcher(audit, _CONTAINER)
        assert isinstance(watcher.fileno(), int)
        watcher.close()

    def test_creates_missing_file(self, tmp_path: Path) -> None:
        """AuditLogWatcher creates audit.jsonl if it does not exist."""
        audit = tmp_path / "audit.jsonl"
        assert not audit.exists()
        watcher = AuditLogWatcher(audit, _CONTAINER)
        assert audit.is_file()
        watcher.close()

    def test_preserves_existing_content(self, tmp_path: Path) -> None:
        """AuditLogWatcher skips pre-existing lines (seeks to end on init)."""
        audit = tmp_path / "audit.jsonl"
        existing = {"ts": "2026-03-31T00:00:00", "action": "old", "container": _CONTAINER}
        audit.write_text(json.dumps(existing, separators=(",", ":")) + "\n")
        watcher = AuditLogWatcher(audit, _CONTAINER)
        # No new content — should produce no events (old line was before seek)
        events = watcher.poll()
        watcher.close()
        assert events == []

    def test_blank_lines_are_skipped(self, tmp_path: Path) -> None:
        """Blank lines in the audit log are silently skipped."""
        audit = tmp_path / "audit.jsonl"
        audit.write_text("")
        watcher = AuditLogWatcher(audit, _CONTAINER)
        with audit.open("a") as f:
            f.write("\n\n")
            f.write('{"ts":"2026-04-01T00:00:00","action":"shield_up","container":"x"}\n')
            f.write("\n")
        events = watcher.poll()
        watcher.close()
        assert len(events) == 1
        assert events[0].action == "shield_up"

    def test_non_dict_json_is_skipped(self, tmp_path: Path) -> None:
        """JSON values that are not dicts (lists, strings, null) are silently skipped."""
        audit = tmp_path / "audit.jsonl"
        audit.write_text("")
        watcher = AuditLogWatcher(audit, _CONTAINER)
        with audit.open("a") as f:
            f.write('"just a string"\n')
            f.write("[1, 2, 3]\n")
            f.write("null\n")
            f.write("42\n")
            f.write('{"ts":"2026-04-01T00:00:00","action":"setup","container":"x"}\n')
        events = watcher.poll()
        watcher.close()
        assert len(events) == 1
        assert events[0].action == "setup"

    def test_missing_optional_fields_default_empty(self, tmp_path: Path) -> None:
        """Audit entries with missing optional fields get empty-string defaults."""
        audit = tmp_path / "audit.jsonl"
        audit.write_text("")
        watcher = AuditLogWatcher(audit, _CONTAINER)
        entry = {"ts": "2026-04-01T00:00:00", "action": "setup", "container": _CONTAINER}
        with audit.open("a") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        events = watcher.poll()
        watcher.close()
        assert events[0].dest == ""
        assert events[0].detail == ""


# ── NflogWatcher ───────────────────────────────────────


def _make_nflog_packet(
    prefix: str,
    dest_ip: str = "192.0.2.1",
    proto: int = 6,
    dest_port: int = 443,
) -> bytes:
    """Build a synthetic NFLOG netlink message for testing.

    Constructs a minimal netlink + nfgenmsg + NFULA_PREFIX + NFULA_PAYLOAD
    message that can be parsed by ``NflogWatcher._parse_messages``.
    Detects IPv6 addresses automatically via ``:`` in *dest_ip*.
    """
    if ":" in dest_ip:
        # IPv6: 40-byte header + transport
        ip6_header = bytearray(40)
        ip6_header[0] = 0x60  # version=6
        ip6_header[6] = proto  # Next Header
        ip6_header[24:40] = socket.inet_pton(socket.AF_INET6, dest_ip)
        transport = struct.pack("!HH", 12345, dest_port)
        raw_ip = bytes(ip6_header) + transport
        af_family = socket.AF_INET6
    else:
        # IPv4: 20-byte header + transport
        ip_header = bytearray(20)
        ip_header[0] = 0x45  # version=4, IHL=5
        ip_header[9] = proto
        ip_header[16:20] = socket.inet_aton(dest_ip)
        transport = struct.pack("!HH", 12345, dest_port)
        raw_ip = bytes(ip_header) + transport
        af_family = socket.AF_INET

    # Build NFLOG attributes
    attrs = b""

    # NFULA_PREFIX attribute
    prefix_bytes = prefix.encode("ascii") + b"\x00"
    prefix_attr_len = _NFA_HDR.size + len(prefix_bytes)
    attrs += _NFA_HDR.pack(prefix_attr_len, _NFULA_PREFIX)
    attrs += prefix_bytes
    # Pad to 4-byte alignment
    pad = (4 - (prefix_attr_len % 4)) % 4
    attrs += b"\x00" * pad

    # NFULA_PAYLOAD attribute
    payload_attr_len = _NFA_HDR.size + len(raw_ip)
    attrs += _NFA_HDR.pack(payload_attr_len, _NFULA_PAYLOAD)
    attrs += raw_ip
    pad = (4 - (payload_attr_len % 4)) % 4
    attrs += b"\x00" * pad

    # nfgenmsg header
    nfgen = _NFGEN_HDR.pack(af_family, 0, socket.htons(NFLOG_GROUP))

    # netlink message header
    msg_type = (_NFNL_SUBSYS_ULOG << 8) | _NFULNL_MSG_PACKET
    payload = nfgen + attrs
    nlmsg = _NLMSG_HDR.pack(
        _NLMSG_HDR.size + len(payload),
        msg_type,
        0,
        0,
        0,
    )
    return nlmsg + payload


class TestExtractIpDest:
    """Test raw IP packet destination extraction."""

    def test_ipv4_tcp(self) -> None:
        """Extracts destination IP and port from an IPv4/TCP packet."""
        ip_header = bytearray(20)
        ip_header[0] = 0x45  # version=4, IHL=5
        ip_header[9] = 6  # TCP
        ip_header[16:20] = socket.inet_aton("198.51.100.1")
        transport = struct.pack("!HH", 54321, 8080)
        dest, proto, port = _extract_ip_dest(bytes(ip_header) + transport)
        assert dest == "198.51.100.1"
        assert proto == 6
        assert port == 8080

    def test_ipv4_udp(self) -> None:
        """Extracts destination IP and port from an IPv4/UDP packet."""
        ip_header = bytearray(20)
        ip_header[0] = 0x45
        ip_header[9] = 17  # UDP
        ip_header[16:20] = socket.inet_aton("203.0.113.1")
        transport = struct.pack("!HH", 12345, 53)
        dest, proto, port = _extract_ip_dest(bytes(ip_header) + transport)
        assert dest == "203.0.113.1"
        assert proto == 17
        assert port == 53

    def test_ipv6(self) -> None:
        """Extracts destination IP and port from an IPv6/TCP packet."""
        # Minimal IPv6 header: 40 bytes
        ip6_header = bytearray(40)
        ip6_header[0] = 0x60  # version=6
        ip6_header[6] = 6  # Next Header = TCP
        # Destination address at offset 24
        ip6_header[24:40] = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        transport = struct.pack("!HH", 54321, 443)
        dest, proto, port = _extract_ip_dest(bytes(ip6_header) + transport)
        assert dest == "2001:db8::1"
        assert proto == 6
        assert port == 443

    def test_too_short_returns_empty(self) -> None:
        """Packet shorter than minimum IP header returns empty tuple."""
        assert _extract_ip_dest(b"\x45" * 10) == ("", 0, 0)

    def test_unknown_version_returns_empty(self) -> None:
        """Packet with unknown IP version returns empty tuple."""
        pkt = bytearray(20)
        pkt[0] = 0x35  # version=3 — invalid
        assert _extract_ip_dest(bytes(pkt)) == ("", 0, 0)

    def test_malformed_ihl_returns_empty(self) -> None:
        """IPv4 packet with IHL < 5 (20 bytes) is rejected as malformed."""
        pkt = bytearray(20)
        pkt[0] = 0x43  # version=4, IHL=3 (12 bytes — below minimum)
        assert _extract_ip_dest(bytes(pkt)) == ("", 0, 0)


class TestParseNflogAttrs:
    """Test NFLOG attribute TLV parsing."""

    def test_parses_prefix_and_payload(self) -> None:
        """Parses NFULA_PREFIX and NFULA_PAYLOAD attributes from raw data."""
        prefix = b"TEROK_SHIELD_DENIED: \x00"
        payload = b"\x45" + b"\x00" * 23  # minimal IP header

        attrs_data = b""
        # PREFIX attr
        attr_len = _NFA_HDR.size + len(prefix)
        attrs_data += _NFA_HDR.pack(attr_len, _NFULA_PREFIX) + prefix
        pad = (4 - (attr_len % 4)) % 4
        attrs_data += b"\x00" * pad
        # PAYLOAD attr
        attr_len = _NFA_HDR.size + len(payload)
        attrs_data += _NFA_HDR.pack(attr_len, _NFULA_PAYLOAD) + payload
        pad = (4 - (attr_len % 4)) % 4
        attrs_data += b"\x00" * pad

        parsed = _parse_nflog_attrs(attrs_data)
        assert _NFULA_PREFIX in parsed
        assert _NFULA_PAYLOAD in parsed
        assert b"DENIED" in parsed[_NFULA_PREFIX]

    def test_empty_data_returns_empty_dict(self) -> None:
        """Empty data returns empty attribute dict."""
        assert _parse_nflog_attrs(b"") == {}

    def test_truncated_attr_stops_parsing(self) -> None:
        """Attribute with length shorter than header stops parsing."""
        # Attribute claiming 2-byte length (less than 4-byte header)
        data = _NFA_HDR.pack(2, _NFULA_PREFIX)
        assert _parse_nflog_attrs(data) == {}


class TestBuildNflogBindMsg:
    """Test NFLOG bind message construction."""

    def test_produces_valid_netlink_message(self) -> None:
        """Bind message has correct netlink header structure."""
        msg = _build_nflog_bind_msg(NFLOG_GROUP)
        # Must be at least nlmsg header size
        assert len(msg) >= _NLMSG_HDR.size
        nl_len, nl_type, _flags, _seq, _pid = _NLMSG_HDR.unpack_from(msg, 0)
        assert nl_len == len(msg)
        # Type should be ULOG subsystem + CONFIG msg
        assert (nl_type >> 8) == _NFNL_SUBSYS_ULOG


class TestNflogWatcherParsing:
    """Test NflogWatcher message parsing (unit-level, no real netlink)."""

    def _make_watcher(self) -> NflogWatcher:
        """Create a NflogWatcher with a mock socket."""
        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.fileno.return_value = 42
        return NflogWatcher(mock_sock, _CONTAINER)

    def test_denied_packet_produces_blocked_connection(self) -> None:
        """NFLOG message with DENIED prefix yields blocked_connection event."""
        watcher = self._make_watcher()
        data = _make_nflog_packet(f"{DENIED_LOG_PREFIX}: ", "192.0.2.1", 6, 443)
        events = watcher._parse_messages(data)
        assert len(events) == 1
        assert events[0].action == "blocked_connection"
        assert events[0].dest == "192.0.2.1"
        assert events[0].port == 443
        assert events[0].proto == 6
        assert events[0].source == "nflog"

    def test_allowed_packet_produces_allowed_connection(self) -> None:
        """NFLOG message with ALLOWED prefix yields allowed_connection event."""
        watcher = self._make_watcher()
        data = _make_nflog_packet(f"{ALLOWED_LOG_PREFIX}: ", "198.51.100.1", 6, 80)
        events = watcher._parse_messages(data)
        assert len(events) == 1
        assert events[0].action == "allowed_connection"
        assert events[0].dest == "198.51.100.1"

    def test_private_range_packet(self) -> None:
        """NFLOG message with PRIVATE prefix yields private_range event."""
        watcher = self._make_watcher()
        data = _make_nflog_packet(f"{PRIVATE_LOG_PREFIX}: ", "10.0.0.1", 6, 22)
        events = watcher._parse_messages(data)
        assert len(events) == 1
        assert events[0].action == "private_range"

    def test_bypass_packet(self) -> None:
        """NFLOG message with BYPASS prefix yields bypass_connection event."""
        watcher = self._make_watcher()
        data = _make_nflog_packet(f"{BYPASS_LOG_PREFIX}: ", "203.0.113.1", 17, 53)
        events = watcher._parse_messages(data)
        assert len(events) == 1
        assert events[0].action == "bypass_connection"
        assert events[0].port == 53
        assert events[0].proto == 17

    def test_blocked_packet_produces_queued_connection(self) -> None:
        """NFLOG message with BLOCKED prefix yields queued_connection event."""
        watcher = self._make_watcher()
        data = _make_nflog_packet(f"{BLOCKED_LOG_PREFIX}: ", "192.0.2.1", 6, 443)
        events = watcher._parse_messages(data)
        assert len(events) == 1
        assert events[0].action == "queued_connection"

    def test_unknown_prefix_yields_nflog_action(self) -> None:
        """NFLOG message with unrecognized prefix yields generic nflog action."""
        watcher = self._make_watcher()
        data = _make_nflog_packet("CUSTOM_PREFIX: ", "192.0.2.99", 6, 8080)
        events = watcher._parse_messages(data)
        assert len(events) == 1
        assert events[0].action == "nflog"

    def test_ipv6_packet_produces_event(self) -> None:
        """NFLOG message with an IPv6 payload extracts dest and port correctly."""
        watcher = self._make_watcher()
        data = _make_nflog_packet(f"{DENIED_LOG_PREFIX}: ", "2001:db8::1", 6, 443)
        events = watcher._parse_messages(data)
        assert len(events) == 1
        assert events[0].dest == "2001:db8::1"
        assert events[0].port == 443
        assert events[0].proto == 6
        assert events[0].action == "blocked_connection"

    def test_empty_payload_produces_no_event(self) -> None:
        """NFLOG message without IP payload is skipped."""
        watcher = self._make_watcher()
        # Build a message with prefix but no payload attribute
        prefix_bytes = b"TEROK_SHIELD_DENIED: \x00"
        prefix_attr_len = _NFA_HDR.size + len(prefix_bytes)
        attrs = _NFA_HDR.pack(prefix_attr_len, _NFULA_PREFIX) + prefix_bytes
        pad = (4 - (prefix_attr_len % 4)) % 4
        attrs += b"\x00" * pad

        nfgen = _NFGEN_HDR.pack(2, 0, socket.htons(NFLOG_GROUP))
        msg_type = (_NFNL_SUBSYS_ULOG << 8) | _NFULNL_MSG_PACKET
        payload = nfgen + attrs
        nlmsg = _NLMSG_HDR.pack(_NLMSG_HDR.size + len(payload), msg_type, 0, 0, 0) + payload
        events = watcher._parse_messages(nlmsg)
        assert events == []

    def test_poll_reads_from_socket(self) -> None:
        """poll() reads data from socket and parses into events."""
        watcher = self._make_watcher()
        data = _make_nflog_packet(f"{DENIED_LOG_PREFIX}: ", "192.0.2.1", 6, 443)
        watcher._sock.recv.side_effect = [data, BlockingIOError]
        events = watcher.poll()
        assert len(events) == 1
        assert events[0].action == "blocked_connection"

    def test_poll_handles_blocking_io(self) -> None:
        """poll() returns empty list when socket has no data."""
        watcher = self._make_watcher()
        watcher._sock.recv.side_effect = BlockingIOError
        events = watcher.poll()
        assert events == []

    def test_poll_stops_on_empty_recv(self) -> None:
        """poll() stops reading when recv() returns empty bytes."""
        watcher = self._make_watcher()
        watcher._sock.recv.side_effect = [b""]
        events = watcher.poll()
        assert events == []

    def test_parse_messages_stops_on_invalid_nllen(self) -> None:
        """_parse_messages stops when nl_len is smaller than header size."""
        watcher = self._make_watcher()
        # Craft a message with nl_len = 4 (less than NLMSG_HDR.size=16)
        bad_msg = _NLMSG_HDR.pack(4, 0, 0, 0, 0)
        events = watcher._parse_messages(bad_msg)
        assert events == []

    def test_fileno_delegates_to_socket(self) -> None:
        """fileno() returns the socket's file descriptor."""
        watcher = self._make_watcher()
        assert watcher.fileno() == 42

    def test_close_closes_socket(self) -> None:
        """close() closes the underlying socket."""
        watcher = self._make_watcher()
        watcher.close()
        watcher._sock.close.assert_called_once()


class TestNflogWatcherCreate:
    """Test NflogWatcher.create() factory method."""

    def test_returns_none_on_oserror(self) -> None:
        """create() returns None when AF_NETLINK socket fails."""
        with patch("terok_shield.watchers.nflog.socket.socket", side_effect=OSError("no netlink")):
            result = NflogWatcher.create(_CONTAINER)
        assert result is None

    def test_returns_watcher_on_success(self) -> None:
        """create() returns a NflogWatcher when bind ACK succeeds."""
        mock_sock = MagicMock(spec=socket.socket)
        # Build a success ACK (error code 0)
        ack_payload = struct.pack("=i", 0)
        ack = _NLMSG_HDR.pack(_NLMSG_HDR.size + len(ack_payload), 2, 0, 0, 0) + ack_payload
        mock_sock.recv.return_value = ack
        with patch("terok_shield.watchers.nflog.socket.socket", return_value=mock_sock):
            result = NflogWatcher.create(_CONTAINER)
        assert result is not None
        assert isinstance(result, NflogWatcher)
        mock_sock.bind.assert_called_once_with((0, 0))
        mock_sock.settimeout.assert_called_once_with(2.0)
        mock_sock.setblocking.assert_called_once_with(False)
        mock_sock.send.assert_called_once()
        assert len(mock_sock.send.call_args[0][0]) >= _NLMSG_HDR.size
        result.close()

    def test_returns_none_on_attribute_error(self) -> None:
        """create() returns None on non-Linux where AF_NETLINK is missing."""
        with patch("terok_shield.watchers.nflog.socket.socket", side_effect=AttributeError):
            result = NflogWatcher.create(_CONTAINER)
        assert result is None

    def test_returns_none_and_closes_socket_on_timeout(self) -> None:
        """create() returns None and closes the socket when recv times out."""
        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.recv.side_effect = OSError("timed out")
        with patch("terok_shield.watchers.nflog.socket.socket", return_value=mock_sock):
            result = NflogWatcher.create(_CONTAINER)
        assert result is None
        mock_sock.close.assert_called_once()

    def test_returns_none_on_bind_nack(self) -> None:
        """create() returns None when the kernel ACK contains a negative error code."""
        mock_sock = MagicMock(spec=socket.socket)
        # Build an NLMSG_ERROR ACK with errno -1 (EPERM)
        ack_payload = struct.pack("=i", -1)
        ack = _NLMSG_HDR.pack(_NLMSG_HDR.size + len(ack_payload), 2, 0, 0, 0) + ack_payload
        mock_sock.recv.return_value = ack
        with patch("terok_shield.watchers.nflog.socket.socket", return_value=mock_sock):
            result = NflogWatcher.create(_CONTAINER)
        assert result is None
        mock_sock.close.assert_called_once()

    def test_returns_watcher_on_success_ack(self) -> None:
        """create() succeeds when the kernel ACK has error code 0."""
        mock_sock = MagicMock(spec=socket.socket)
        ack_payload = struct.pack("=i", 0)
        ack = _NLMSG_HDR.pack(_NLMSG_HDR.size + len(ack_payload), 2, 0, 0, 0) + ack_payload
        mock_sock.recv.return_value = ack
        with patch("terok_shield.watchers.nflog.socket.socket", return_value=mock_sock):
            result = NflogWatcher.create(_CONTAINER)
        assert result is not None
        result.close()


# ── Tier validation ─────────────────────────────────────


class TestRunWatchValidation:
    """Test run_watch() tier validation."""

    def test_rejects_dig_tier(self, tmp_path: Path) -> None:
        """run_watch() exits with error on dig tier."""
        sd = tmp_path / "state"
        sd.mkdir()
        (sd / "dns.tier").write_text(DnsTier.DIG.value)
        with pytest.raises(SystemExit, match="1"):
            run_watch(sd, _CONTAINER)

    def test_rejects_getent_tier(self, tmp_path: Path) -> None:
        """run_watch() exits with error on getent tier."""
        sd = tmp_path / "state"
        sd.mkdir()
        (sd / "dns.tier").write_text(DnsTier.GETENT.value)
        with pytest.raises(SystemExit, match="1"):
            run_watch(sd, _CONTAINER)

    def test_rejects_missing_tier(self, tmp_path: Path) -> None:
        """run_watch() exits with error when dns.tier is missing."""
        sd = tmp_path / "state"
        sd.mkdir()
        with pytest.raises(SystemExit, match="1"):
            run_watch(sd, _CONTAINER)


# ── Domain refresh ──────────────────────────────────────


class TestDomainRefresh:
    """Test that DnsLogWatcher refreshes its domain set after the interval."""

    def test_poll_refreshes_domains_after_interval(self, tmp_path: Path) -> None:
        """poll() reloads the allowed domain set when the refresh interval elapses."""
        sd = tmp_path / "state"
        sd.mkdir()
        (sd / "profile.domains").write_text(f"{TEST_DOMAIN}\n")
        log = sd / "dnsmasq.log"
        log.write_text("")

        # Monotonic clock: returns 0 during init to set _last_refresh
        with patch("terok_shield.watchers.dns_log._monotonic", return_value=0.0):
            watcher = DnsLogWatcher(log, sd, _CONTAINER)

        # Add BLOCKED_DOMAIN to allowed set *after* watcher was created
        (sd / "profile.domains").write_text(f"{TEST_DOMAIN}\n{BLOCKED_DOMAIN}\n")

        # Append a query — before refresh, BLOCKED_DOMAIN would be blocked
        with log.open("a") as f:
            f.write(f"query[A] {BLOCKED_DOMAIN} from 127.0.0.1\n")

        # Force the clock past the refresh threshold
        with patch(
            "terok_shield.watchers.dns_log._monotonic",
            return_value=_DOMAIN_REFRESH_INTERVAL + 1.0,
        ):
            events = watcher.poll()
        watcher.close()

        # After refresh, the domain is now allowed — no event
        assert events == []


# ── Signal handler ──────────────────────────────────────


@pytest.mark.usefixtures("_restore_running")
class TestSignalHandler:
    """Test the SIGINT/SIGTERM handler."""

    def test_handle_signal_sets_running_false(self) -> None:
        """_handle_signal() clears the module-level _running flag."""
        _cli_watch_mod._running = True
        _handle_signal(2, None)
        assert _cli_watch_mod._running is False


# ── run_watch happy path ────────────────────────────────


@pytest.mark.usefixtures("_restore_running")
class TestRunWatchHappyPath:
    """Test run_watch() select loop, event output, and log file creation."""

    @pytest.fixture
    def dnsmasq_state(self, tmp_path: Path) -> Path:
        """State dir with dnsmasq tier, profile domains, and dnsmasq config."""
        sd = tmp_path / "state"
        sd.mkdir()
        (sd / "dns.tier").write_text(DnsTier.DNSMASQ.value)
        (sd / "profile.domains").write_text(f"{TEST_DOMAIN}\n")
        (sd / "dnsmasq.conf").write_text("# stub config\n")
        return sd

    def test_creates_log_file_if_missing(self, dnsmasq_state: Path) -> None:
        """run_watch() creates dnsmasq.log if it does not exist yet."""
        log = dnsmasq_state / "dnsmasq.log"
        assert not log.exists()

        def _stop_immediately(*_args: object, **_kwargs: object) -> tuple[list, list, list]:
            _cli_watch_mod._running = False
            return ([], [], [])

        with (
            patch("terok_shield.cli.watch.select.select", side_effect=_stop_immediately),
            patch("terok_shield.cli.watch.NflogWatcher.create", return_value=None),
        ):
            run_watch(dnsmasq_state, _CONTAINER)

        assert log.is_file()

    def test_outputs_blocked_event_as_json(
        self, dnsmasq_state: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """run_watch() prints a JSON line for each blocked query."""
        log = dnsmasq_state / "dnsmasq.log"
        log.write_text("")

        iteration = 0

        def _select_then_stop(*_args: object, **_kwargs: object) -> tuple:
            nonlocal iteration
            iteration += 1
            if iteration == 1:
                # Simulate dnsmasq writing a query between select calls
                with log.open("a") as f:
                    f.write(f"query[A] {BLOCKED_DOMAIN} from 127.0.0.1\n")
                return ([], [], [])
            # Stop on second iteration
            _cli_watch_mod._running = False
            return ([], [], [])

        with (
            patch("terok_shield.cli.watch.select.select", side_effect=_select_then_stop),
            patch("terok_shield.cli.watch.NflogWatcher.create", return_value=None),
        ):
            run_watch(dnsmasq_state, _CONTAINER)

        output = capsys.readouterr().out.strip()
        parsed = json.loads(output)
        assert parsed["domain"] == BLOCKED_DOMAIN
        assert parsed["action"] == "blocked_query"

    def test_allowed_domain_produces_no_output(
        self, dnsmasq_state: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """run_watch() produces no output for queries to allowed domains."""
        log = dnsmasq_state / "dnsmasq.log"
        log.write_text("")

        iteration = 0

        def _select_then_stop(*_args: object, **_kwargs: object) -> tuple:
            nonlocal iteration
            iteration += 1
            if iteration == 1:
                with log.open("a") as f:
                    f.write(f"query[A] {TEST_DOMAIN} from 127.0.0.1\n")
                return ([], [], [])
            _cli_watch_mod._running = False
            return ([], [], [])

        with (
            patch("terok_shield.cli.watch.select.select", side_effect=_select_then_stop),
            patch("terok_shield.cli.watch.NflogWatcher.create", return_value=None),
        ):
            run_watch(dnsmasq_state, _CONTAINER)

        assert capsys.readouterr().out == ""

    def test_audit_events_appear_in_output(
        self, dnsmasq_state: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """run_watch() outputs audit log events alongside DNS events."""
        log = dnsmasq_state / "dnsmasq.log"
        log.write_text("")
        audit = dnsmasq_state / "audit.jsonl"
        audit.write_text("")

        iteration = 0

        def _select_then_stop(*_args: object, **_kwargs: object) -> tuple:
            nonlocal iteration
            iteration += 1
            if iteration == 1:
                entry = {
                    "ts": "2026-04-01T12:00:00",
                    "action": "shield_up",
                    "container": _CONTAINER,
                }
                with audit.open("a") as f:
                    f.write(json.dumps(entry, separators=(",", ":")) + "\n")
                return ([], [], [])
            _cli_watch_mod._running = False
            return ([], [], [])

        with (
            patch("terok_shield.cli.watch.select.select", side_effect=_select_then_stop),
            patch("terok_shield.cli.watch.NflogWatcher.create", return_value=None),
        ):
            run_watch(dnsmasq_state, _CONTAINER)

        output = capsys.readouterr().out.strip()
        parsed = json.loads(output)
        assert parsed["source"] == "audit"
        assert parsed["action"] == "shield_up"

    def test_nflog_events_appear_in_output(
        self, dnsmasq_state: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """run_watch() outputs NFLOG events when the netlink watcher is active."""
        log = dnsmasq_state / "dnsmasq.log"
        log.write_text("")

        mock_nflog = MagicMock(spec=NflogWatcher)
        mock_nflog.fileno.return_value = 99
        nflog_event = WatchEvent(
            ts="2026-04-01T12:00:00+00:00",
            source="nflog",
            action="blocked_connection",
            container=_CONTAINER,
            dest="192.0.2.1",
            port=443,
        )
        # First poll returns an event, second poll returns nothing
        mock_nflog.poll.side_effect = [[nflog_event], []]

        iteration = 0

        def _select_then_stop(rlist: list, *_args: object, **_kwargs: object) -> tuple:
            nonlocal iteration
            iteration += 1
            if iteration == 1:
                return (rlist, [], [])
            _cli_watch_mod._running = False
            return ([], [], [])

        with (
            patch("terok_shield.cli.watch.select.select", side_effect=_select_then_stop),
            patch("terok_shield.cli.watch.NflogWatcher.create", return_value=mock_nflog),
        ):
            run_watch(dnsmasq_state, _CONTAINER)

        mock_nflog.close.assert_called_once()
        output = capsys.readouterr().out.strip().splitlines()[0]
        parsed = json.loads(output)
        assert parsed["source"] == "nflog"
        assert parsed["action"] == "blocked_connection"
        assert parsed["dest"] == "192.0.2.1"

    def test_mixed_sources_in_same_cycle(
        self, dnsmasq_state: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """run_watch() emits events from all sources in a single loop iteration."""
        log = dnsmasq_state / "dnsmasq.log"
        log.write_text("")
        audit = dnsmasq_state / "audit.jsonl"
        audit.write_text("")

        mock_nflog = MagicMock(spec=NflogWatcher)
        mock_nflog.fileno.return_value = 99
        nflog_event = WatchEvent(
            ts="2026-04-01T12:00:00+00:00",
            source="nflog",
            action="blocked_connection",
            container=_CONTAINER,
            dest="192.0.2.1",
            port=443,
        )
        mock_nflog.poll.side_effect = [[nflog_event], []]

        iteration = 0

        def _select_then_stop(rlist: list, *_args: object, **_kwargs: object) -> tuple:
            nonlocal iteration
            iteration += 1
            if iteration == 1:
                # Write audit + DNS events in the same cycle
                entry = {"ts": "2026-04-01T12:00:00", "action": "allowed", "container": "x"}
                with audit.open("a") as f:
                    f.write(json.dumps(entry, separators=(",", ":")) + "\n")
                with log.open("a") as f:
                    f.write(f"query[A] {BLOCKED_DOMAIN} from 127.0.0.1\n")
                return (rlist, [], [])  # nflog also readable
            _cli_watch_mod._running = False
            return ([], [], [])

        with (
            patch("terok_shield.cli.watch.select.select", side_effect=_select_then_stop),
            patch("terok_shield.cli.watch.NflogWatcher.create", return_value=mock_nflog),
        ):
            run_watch(dnsmasq_state, _CONTAINER)

        lines = capsys.readouterr().out.strip().splitlines()
        sources = {json.loads(line)["source"] for line in lines}
        assert "nflog" in sources
        assert "dns" in sources
        assert "audit" in sources
        mock_nflog.close.assert_called_once()


# ── _ensure_log_file ────────────────────────────────────


class TestEnsureLogFile:
    """Test log file creation for shield watch."""

    def test_creates_missing_file(self, tmp_path: Path) -> None:
        """Creates the log file when it does not exist."""
        log = tmp_path / "dnsmasq.log"
        _ensure_log_file(log)
        assert log.is_file()

    def test_idempotent_on_existing_file(self, tmp_path: Path) -> None:
        """No-op when the log file already exists."""
        log = tmp_path / "dnsmasq.log"
        log.write_text("existing content\n")
        _ensure_log_file(log)
        assert log.read_text() == "existing content\n"


# ── _enrich_nflog ─────────────────────────────────────────


class TestEnrichNflog:
    """Tests for NFLOG event domain enrichment via DomainCache."""

    def test_enriches_event_with_cached_domain(self, tmp_path: Path) -> None:
        """_enrich_nflog attaches a cached domain to an NFLOG event."""
        cache = DomainCache(tmp_path)
        cache._mapping[TEST_IP1] = DNSMASQ_DOMAIN
        event = WatchEvent(
            ts="t",
            source="nflog",
            action="blocked_connection",
            container=_CONTAINER,
            dest=TEST_IP1,
            port=443,
        )
        enriched = _enrich_nflog([event], cache)
        assert enriched[0].domain == DNSMASQ_DOMAIN

    def test_refreshes_cache_on_miss(self, tmp_path: Path) -> None:
        """_enrich_nflog refreshes the cache when the IP is not initially mapped."""
        from terok_shield import state as st

        log_path = st.dnsmasq_log_path(tmp_path)
        log_path.write_text(f"reply {DNSMASQ_DOMAIN} is {TEST_IP1}\n")
        cache = DomainCache(tmp_path)
        event = WatchEvent(
            ts="t",
            source="nflog",
            action="blocked_connection",
            container=_CONTAINER,
            dest=TEST_IP1,
            port=443,
        )
        enriched = _enrich_nflog([event], cache)
        assert enriched[0].domain == DNSMASQ_DOMAIN

    def test_leaves_domain_empty_when_unknown(self, tmp_path: Path) -> None:
        """_enrich_nflog leaves domain empty when no DNS entry exists."""
        cache = DomainCache(tmp_path)
        event = WatchEvent(
            ts="t",
            source="nflog",
            action="blocked_connection",
            container=_CONTAINER,
            dest=TEST_IP1,
            port=443,
        )
        enriched = _enrich_nflog([event], cache)
        assert enriched[0].domain == ""

    def test_skips_events_with_existing_domain(self, tmp_path: Path) -> None:
        """_enrich_nflog does not overwrite events that already have a domain."""
        cache = DomainCache(tmp_path)
        event = WatchEvent(
            ts="t",
            source="nflog",
            action="blocked_connection",
            container=_CONTAINER,
            dest=TEST_IP1,
            port=443,
            domain="already.set",
        )
        enriched = _enrich_nflog([event], cache)
        assert enriched[0].domain == "already.set"

    def test_skips_events_without_dest(self, tmp_path: Path) -> None:
        """_enrich_nflog skips events that have no dest IP."""
        cache = DomainCache(tmp_path)
        event = WatchEvent(
            ts="t",
            source="nflog",
            action="blocked_connection",
            container=_CONTAINER,
        )
        enriched = _enrich_nflog([event], cache)
        assert enriched[0].domain == ""

    def test_refreshes_cache_at_most_once_per_batch(self, tmp_path: Path) -> None:
        """_enrich_nflog refreshes the cache only once even with multiple misses."""
        cache = DomainCache(tmp_path)
        ev1 = WatchEvent(
            ts="t",
            source="nflog",
            action="blocked_connection",
            container=_CONTAINER,
            dest=TEST_IP1,
            port=443,
        )
        ev2 = WatchEvent(
            ts="t",
            source="nflog",
            action="blocked_connection",
            container=_CONTAINER,
            dest=TEST_IP2,
            port=80,
        )
        original_refresh = cache.refresh
        cache.refresh = MagicMock(side_effect=original_refresh)
        _enrich_nflog([ev1, ev2], cache)
        assert cache.refresh.call_count == 1
