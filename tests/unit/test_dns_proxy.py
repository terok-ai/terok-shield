# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the minimal DNS responder (the tier for hosts without dnsmasq).

Every test drives the real protocol object over a real UDP socket, with
the resolver and the nft callback replaced by lists.  The wire format is
the contract here, so nothing stubs it.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from typing import TYPE_CHECKING

import pytest

from terok_shield.dns import proxy
from tests.testnet import IPV6_VERBOSE_CANONICAL, TEST_DOMAIN, TEST_DOMAIN2, TEST_IP1, TEST_IP2

if TYPE_CHECKING:
    from collections.abc import Iterator

_QTYPE_A = 1
_QTYPE_AAAA = 28
_QTYPE_SRV = 33
_QTYPE_HTTPS = 65
_LOOPBACK = "127.0.0.1"


class Harness:
    """A running responder plus the record of what it resolved and allowed."""

    def __init__(self, port: int) -> None:
        """Record the port; the lists start empty."""
        self.port = port
        self.resolved: list[str] = []
        self.allowed: list[str] = []
        self.answers: dict[str, list[str]] = {}
        self.permitted: set[str] = set()

    def resolve(self, name: str) -> list[str]:
        """Stand in for the shield's resolver."""
        self.resolved.append(name)
        return self.answers.get(name, [])

    def ask(self, payload: bytes) -> bytes:
        """Send one query and return the answer, off the responder's loop."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        try:
            sock.sendto(payload, (_LOOPBACK, self.port))
            return sock.recvfrom(4096)[0]
        finally:
            sock.close()


def query(name: str, qtype: int, *, questions: int = 1) -> bytes:
    """Build one DNS query for *name*."""
    encoded = b"".join(bytes([len(p)]) + p for p in name.encode().split(b".")) + b"\x00"
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, questions, 0, 0, 0)
    return header + encoded + struct.pack("!HH", qtype, 1)


def rcode(answer: bytes) -> int:
    """The response code of an answer."""
    return struct.unpack_from("!H", answer, 2)[0] & 0xF


def answers(answer: bytes) -> int:
    """How many records an answer carries."""
    return struct.unpack_from("!H", answer, 6)[0]


def addresses(answer: bytes, qtype: int) -> list[str]:
    """The addresses in an answer, read back off the wire."""
    size = 4 if qtype == _QTYPE_A else 16
    family = socket.AF_INET if qtype == _QTYPE_A else socket.AF_INET6
    out, offset = [], len(answer) - answers(answer) * (size + 12)
    for _ in range(answers(answer)):
        out.append(socket.inet_ntop(family, answer[offset + 12 : offset + 12 + size]))
        offset += size + 12
    return out


def _free_udp_port() -> int:
    """A loopback UDP port nothing holds, for the responder to bind."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((_LOOPBACK, 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


@pytest.fixture
def harness() -> Iterator[Harness]:
    """A responder serving on a free loopback port for the duration of one test."""
    bench = Harness(_free_udp_port())

    async def _serve() -> None:
        await proxy.serve(
            resolve=bench.resolve,
            permits=bench.permitted.__contains__,
            allow=bench.allowed.append,
            upstream=_LOOPBACK,
            listen=_LOOPBACK,
            port=bench.port,
        )
        await asyncio.Event().wait()

    loop = asyncio.new_event_loop()
    task: list[asyncio.Task] = []

    import threading

    ready = threading.Event()

    def _run() -> None:
        asyncio.set_event_loop(loop)
        task.append(loop.create_task(_serve()))
        loop.call_soon(ready.set)
        loop.run_forever()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    ready.wait(5)
    try:
        yield bench
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=5)
        loop.close()


class TestAnswers:
    """What the responder serves itself, and what it allows for it."""

    def test_an_allowed_name_is_answered_and_allowed(self, harness: Harness) -> None:
        harness.answers[TEST_DOMAIN] = [TEST_IP1, TEST_IP2]
        harness.permitted.add(TEST_DOMAIN)

        answer = harness.ask(query(TEST_DOMAIN, _QTYPE_A))

        assert rcode(answer) == 0
        assert addresses(answer, _QTYPE_A) == [TEST_IP1, TEST_IP2]
        assert harness.allowed == [TEST_IP1, TEST_IP2]

    def test_a_name_outside_the_allowlist_resolves_but_is_not_allowed(
        self, harness: Harness
    ) -> None:
        """Name resolution is not the enforcement layer — the filter is."""
        harness.answers[TEST_DOMAIN2] = [TEST_IP1]

        answer = harness.ask(query(TEST_DOMAIN2, _QTYPE_A))

        assert addresses(answer, _QTYPE_A) == [TEST_IP1]
        assert harness.allowed == []

    def test_the_family_asked_for_is_the_family_answered(self, harness: Harness) -> None:
        harness.answers[TEST_DOMAIN] = [TEST_IP1, IPV6_VERBOSE_CANONICAL]
        harness.permitted.add(TEST_DOMAIN)

        answer = harness.ask(query(TEST_DOMAIN, _QTYPE_AAAA))

        assert addresses(answer, _QTYPE_AAAA) == [IPV6_VERBOSE_CANONICAL]
        assert harness.allowed == [IPV6_VERBOSE_CANONICAL]

    def test_a_name_with_no_addresses_is_nxdomain(self, harness: Harness) -> None:
        assert rcode(harness.ask(query(TEST_DOMAIN, _QTYPE_A))) == 3

    def test_a_repeat_within_the_ttl_does_not_resolve_again(self, harness: Harness) -> None:
        """The nft call sits on the answer path, so the cache is what keeps it off."""
        harness.answers[TEST_DOMAIN] = [TEST_IP1]
        harness.permitted.add(TEST_DOMAIN)

        harness.ask(query(TEST_DOMAIN, _QTYPE_A))
        harness.ask(query(TEST_DOMAIN, _QTYPE_A))

        assert harness.resolved == [TEST_DOMAIN]

    def test_the_cache_cannot_be_grown_without_bound(self) -> None:
        """The container picks the names, so a flood of made-up ones must stay bounded.

        Every name it invents is a cache miss and an entry.  Unbounded,
        that is a host-side process growing until someone notices.
        """
        responder = proxy.Responder(
            resolve=lambda _name: [],
            permits=lambda _name: False,
            allow=lambda _ip: None,
            upstream=_LOOPBACK,
        )

        async def _flood() -> None:
            for index in range(proxy._CACHE_MAX * 2):
                await responder._addresses(f"n{index}.{TEST_DOMAIN2}", _QTYPE_A)

        asyncio.run(_flood())

        assert len(responder._cache) <= proxy._CACHE_MAX

    def test_an_address_is_allowed_before_the_answer_leaves(self) -> None:
        """A client must never be able to reach for an address the filter lacks.

        This is the race the design note on the issue expected to live
        with.  Ordering the nft write ahead of the reply removes it, and
        the order is the whole of the guarantee — so it is asserted
        against the transport rather than over a socket, where the two
        events are not separable.
        """
        events: list[str] = []

        class _Transport:
            def sendto(self, _payload: bytes, _addr: tuple) -> None:
                events.append("answer")

        responder = proxy.Responder(
            resolve=lambda _name: [TEST_IP1],
            permits=lambda _name: True,
            allow=lambda _ip: events.append("allow"),
            upstream=_LOOPBACK,
        )
        responder.connection_made(_Transport())

        asyncio.run(responder._serve(query(TEST_DOMAIN, _QTYPE_A), (_LOOPBACK, 1234)))

        assert events == ["allow", "answer"]


class TestRefusals:
    """Queries this responder will not read, and the ones it hands on."""

    def test_more_than_one_question_is_a_format_error(self, harness: Harness) -> None:
        assert rcode(harness.ask(query(TEST_DOMAIN, _QTYPE_A, questions=3))) == 1

    def test_a_non_ascii_name_is_a_format_error(self, harness: Harness) -> None:
        """No IDN: a name is refused rather than guessed at.  Punycode is ASCII already."""
        raw = b"\x04caf\xc3\xa9\x07example\x00"
        payload = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + raw
        payload += struct.pack("!HH", _QTYPE_A, 1)

        assert rcode(harness.ask(payload)) == 1

    def test_svcb_is_answered_empty(self, harness: Harness) -> None:
        """Its address hints would let a client connect without ever asking A/AAAA."""
        harness.answers[TEST_DOMAIN] = [TEST_IP1]
        harness.permitted.add(TEST_DOMAIN)

        answer = harness.ask(query(TEST_DOMAIN, _QTYPE_HTTPS))

        assert rcode(answer) == 0
        assert answers(answer) == 0
        assert harness.allowed == []

    def test_a_service_label_reaches_the_relay(self, harness: Harness) -> None:
        """``_https._tcp`` and friends are SRV names, and SRV is relayed.

        The label rule has to admit them: refusing to read the name would
        refuse the relay with it.
        """
        answer = harness.ask(query("_https._tcp." + TEST_DOMAIN, _QTYPE_SRV))

        assert rcode(answer) != 1  # anything but "this responder would not read it"
        assert harness.resolved == []
