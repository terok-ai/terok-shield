# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Minimal DNS responder for hosts with no nftset-capable dnsmasq.

The dnsmasq tier keeps a domain allowlist working by adding each answer
to an nft set as it hands the answer out, so the filter follows the
addresses behind a name when they rotate.  A host without an
nftset-capable dnsmasq has no such tier: its allowlist is resolved once,
before the container starts, and goes stale the moment a CDN moves.
This module is that tier for those hosts.

It answers A and AAAA itself — from the same resolver
([`DnsResolver`][terok_shield.dns.resolver.DnsResolver], so ``dig`` then
``drill`` then ``getent``) — and allows every address it hands out
*before* the answer leaves, so a client cannot reach for an address the
filter has not been told about yet.  Every other query type is relayed
to the upstream untouched: those name no address a client will connect
to, and the ``SRV`` case proves the rule, because the host it names is
then resolved by an ``A`` query that comes back here.

Deliberately degraded, and only worth running where dnsmasq is absent.
No TCP, no EDNS, no DNSSEC signatures on what it synthesises, no
compression pointers in the names it reads, one question per query, and
no cache beyond ``_TTL``.  Resolution itself is unaffected: it happens
host-side through the system resolver, which validates or does not
validate exactly as it would for any other caller.

Runs where dnsmasq runs — the host's PID and mount namespaces, the
container's network namespace — so the container reaches it as a peer on
a socket and in no other way.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
import struct
import subprocess  # nosec B404 — argv-only nft calls inside the container netns
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

_QTYPE_A = 1
_QTYPE_AAAA = 28
#: HTTPS/SVCB.  Answered empty on purpose — its address hints would let a
#: client connect without ever asking for A/AAAA, which is the only path
#: this responder can populate the allow set from.
_QTYPE_HTTPS = 65
_CLASS_IN = 1

_RCODE_OK = 0
_RCODE_FORMERR = 1
_RCODE_SERVFAIL = 2
_RCODE_NXDOMAIN = 3

#: Short on purpose: the client comes back often, so the set is refreshed
#: about as often as the addresses behind the name can rotate.
_TTL = 30
_MAX_NAME = 253
_UPSTREAM_TIMEOUT = 2.0

#: The cache holds one entry per name asked for, and the container
#: chooses the names.  Without a bound it would answer a flood of
#: made-up names by growing until the host notices.  Emptying it whole
#: at the cap costs a re-resolve for names still in use, which is the
#: right price for a bound that cannot be gamed.
_CACHE_MAX = 512

#: One label, ASCII only: anything else — a raw UTF-8 name, a leading
#: dash — is refused rather than guessed at.  Punycode needs no special
#: case, being ASCII already.  The leading underscore is the service-label
#: convention (``_https._tcp``, ``_acme-challenge``); those names reach
#: this responder as SRV and TXT queries, which it relays, and refusing
#: to read the name would refuse the relay with it.
_LABEL = re.compile(rb"^_?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

_RR = struct.Struct("!HHIH")


def _question(query: bytes) -> tuple[str, int, int, int] | None:
    """``(name, qtype, qclass, end)`` of a one-question query, else ``None``."""
    if len(query) < 12:
        return None
    flags, qdcount = struct.unpack_from("!HH", query, 2)
    if flags & 0xF800 or qdcount != 1:  # a response, or an opcode we don't serve
        return None
    labels, off = [], 12
    while off < len(query):
        size = query[off]
        if size == 0:
            off += 1
            break
        if size > 63 or off + 1 + size > len(query):
            return None
        label = query[off + 1 : off + 1 + size].lower()
        if not _LABEL.match(label):
            return None
        labels.append(label)
        off += 1 + size
    else:
        return None
    name = b".".join(labels)
    if not labels or len(name) > _MAX_NAME or off + 4 > len(query):
        return None
    qtype, qclass = struct.unpack_from("!HH", query, off)
    return name.decode("ascii"), qtype, qclass, off + 4


def _reply(query: bytes, end: int, rcode: int, records: bytes = b"") -> bytes:
    """The query echoed back as an answer carrying *records*."""
    count = records.count(b"\xc0\x0c")
    return (
        query[:2] + struct.pack("!HHHHH", 0x8180 | rcode, 1, count, 0, 0) + query[12:end] + records
    )


def _refuse(query: bytes, rcode: int) -> bytes:
    """A header-only answer, for a query this responder will not read."""
    return query[:2] + struct.pack("!HHHHH", 0x8180 | rcode, 0, 0, 0, 0)


def _record(qtype: int, ip: str) -> bytes:
    """One answer record, its name a pointer to the question's."""
    family = socket.AF_INET if qtype == _QTYPE_A else socket.AF_INET6
    rdata = socket.inet_pton(family, ip)
    return b"\xc0\x0c" + _RR.pack(qtype, _CLASS_IN, _TTL, len(rdata)) + rdata


class Responder(asyncio.DatagramProtocol):
    """Serves A/AAAA from *resolve*, relays the rest, allows what it answers.

    *allow* receives every address handed out for a name *permits*
    accepts — the same rule the dnsmasq tier writes as an ``nftset``
    entry, and the reason this exists at all.
    """

    def __init__(
        self,
        *,
        resolve: Callable[[str], list[str]],
        permits: Callable[[str], bool],
        allow: Callable[[str], None],
        upstream: str,
    ) -> None:
        """Bind the responder to its resolver, its allowlist, and its upstream."""
        self._resolve = resolve
        self._permits = permits
        self._allow = allow
        self._upstream = upstream
        self._cache: dict[tuple[str, int], tuple[float, list[str]]] = {}
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Keep the transport to answer on."""
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        """Serve each query on its own task; a slow lookup must not queue the rest."""
        asyncio.get_running_loop().create_task(self._serve(data, addr))

    async def _serve(self, query: bytes, addr: tuple) -> None:
        """Answer one query."""
        parsed = _question(query)
        if parsed is None:
            self._send(_refuse(query, _RCODE_FORMERR), addr)
            return
        name, qtype, qclass, end = parsed
        if qclass != _CLASS_IN or qtype == _QTYPE_HTTPS:
            self._send(_reply(query, end, _RCODE_OK), addr)
            return
        if qtype not in (_QTYPE_A, _QTYPE_AAAA):
            self._send(await self._relay(query), addr)
            return
        ips = await self._addresses(name, qtype)
        if not ips:
            self._send(_reply(query, end, _RCODE_NXDOMAIN), addr)
            return
        self._send(_reply(query, end, _RCODE_OK, b"".join(_record(qtype, ip) for ip in ips)), addr)

    async def _addresses(self, name: str, qtype: int) -> list[str]:
        """The addresses for *name* of this family, allowing each one first."""
        loop = asyncio.get_running_loop()
        key = (name, qtype)
        cached = self._cache.get(key)
        if cached and cached[0] > loop.time():
            return cached[1]
        wants_v6 = qtype == _QTYPE_AAAA
        resolved = await asyncio.to_thread(self._resolve, name)
        ips = [ip for ip in resolved if (":" in ip) is wants_v6]
        if ips and self._permits(name):
            for ip in ips:
                self._allow(ip)
        if len(self._cache) >= _CACHE_MAX:
            self._cache.clear()
        self._cache[key] = (loop.time() + _TTL, ips)
        return ips

    async def _relay(self, query: bytes) -> bytes:
        """Hand a query this responder does not serve to the upstream, verbatim."""

        def _ask() -> bytes:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(_UPSTREAM_TIMEOUT)
                sock.sendto(query, (self._upstream, 53))
                return sock.recv(4096)

        try:
            return await asyncio.to_thread(_ask)
        except OSError:
            return _refuse(query, _RCODE_SERVFAIL)

    def _send(self, payload: bytes, addr: tuple) -> None:
        """Write one answer back."""
        if self._transport is not None:
            self._transport.sendto(payload, addr)


async def serve(
    *,
    resolve: Callable[[str], list[str]],
    permits: Callable[[str], bool],
    allow: Callable[[str], None],
    upstream: str,
    listen: str = "127.0.0.1",
    port: int = 53,
) -> asyncio.DatagramTransport:
    """Start the responder on *listen*:*port* and return its transport."""
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: Responder(resolve=resolve, permits=permits, allow=allow, upstream=upstream),
        local_addr=(listen, port),
    )
    return transport


# ── Entry point ─────────────────────────────────────────


def _matches(name: str, allowed: frozenset[str]) -> bool:
    """Does *name* fall under one of *allowed*?

    Suffix matching, the same rule dnsmasq applies to an ``nftset``
    entry: a listed domain covers itself and every name under it.  The
    two tiers have to agree here — an allowlist that means one thing on
    a host with dnsmasq and another on a host without it is worse than
    either rule alone.
    """
    return any(name == entry or name.endswith(f".{entry}") for entry in allowed)


def _allow_element(runner_nft: str, table: str, set_v4: str, set_v6: str) -> Callable[[str], None]:
    """Return a callback adding one address to the matching nft set.

    Runs ``nft`` directly: this process is already in the container's
    network namespace, which is the only place that table exists.
    """

    def _allow(ip: str) -> None:
        target = set_v6 if ":" in ip else set_v4
        subprocess.run(  # noqa: S603 — argv, no shell; ip is inet_pton-validated before this
            [runner_nft, "add", "element", "inet", table, target, f"{{ {ip} }}"],
            capture_output=True,
            check=False,
            timeout=5,
        )

    return _allow


def main(argv: list[str] | None = None) -> int:
    """Run the responder until killed.  Started the way dnsmasq is started."""
    import argparse

    from ..nft.constants import NFT_TABLE_NAME, TIER_PROJECT_ALLOW
    from ..run import SubprocessRunner
    from ..state import StateBundle
    from .resolver import DnsResolver

    parser = argparse.ArgumentParser(prog="terok-shield-dns-proxy")
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", default=53, type=int)
    parser.add_argument("--nft", default="nft")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="terok-shield-dns-proxy: %(message)s")
    bundle = StateBundle(args.state_dir)
    resolver = DnsResolver(runner=SubprocessRunner())

    def _permits(name: str) -> bool:
        """Read the allowlist per query: ``shield allow`` writes the file, and that is the signal."""
        return _matches(name, frozenset(bundle.read_effective().allow_targets()))

    allow = _allow_element(
        args.nft, NFT_TABLE_NAME, f"{TIER_PROJECT_ALLOW}_v4", f"{TIER_PROJECT_ALLOW}_v6"
    )

    async def _run() -> None:
        await serve(
            resolve=lambda name: resolver.resolve_domains([name]),
            permits=_permits,
            allow=allow,
            upstream=args.upstream,
            listen=args.listen,
            port=args.port,
        )
        await asyncio.Event().wait()

    asyncio.run(_run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
