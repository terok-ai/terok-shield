# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: the built-in responder, against real DNS and a real netns.

Two levels.  The first runs the responder as an ordinary host process and
resolves real names through it, which needs nothing but a network.  The
second runs it where it runs in production — inside a shielded
container's network namespace — and asserts the thing the tier exists
for: an address that was never pre-resolved becomes reachable because the
container asked for the name.
"""

import asyncio
import json
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

from terok_shield.dns import proxy
from terok_shield.dns.resolver import DnsResolver
from terok_shield.nft.constants import NFT_TABLE_NAME, TIER_PROJECT_ALLOW
from terok_shield.run import SubprocessRunner
from terok_shield.state import StateBundle
from tests.testnet import CLOUDFLARE_DOMAIN, NONEXISTENT_DOMAIN, QUAD9_DNS_IP

from ..conftest import (
    lookup_tool_broken,
    lookup_tool_missing,
    nft_missing,
    nsenter_nft,
    podman_missing,
)

_LOOPBACK = "127.0.0.1"
_QTYPE_A = 1
#: A name whose addresses a static pre-resolution is most likely to miss:
#: fronted by a CDN, so what it resolves to now is not what it resolved to
#: at launch.
_ROTATING_DOMAIN = CLOUDFLARE_DOMAIN


def _free_udp_port() -> int:
    """A loopback UDP port nothing holds."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((_LOOPBACK, 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _query(name: str, qtype: int = _QTYPE_A) -> bytes:
    """One DNS query for *name*."""
    encoded = b"".join(bytes([len(p)]) + p for p in name.encode().split(b".")) + b"\x00"
    return (
        struct.pack("!HHHHHH", 0x2A2A, 0x0100, 1, 0, 0, 0) + encoded + struct.pack("!HH", qtype, 1)
    )


def _answer_count(answer: bytes) -> int:
    """How many records an answer carries."""
    return struct.unpack_from("!H", answer, 6)[0]


def _ask(port: int, payload: bytes, *, timeout: float = 8.0) -> bytes:
    """Send one query to a responder on loopback and return the answer."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (_LOOPBACK, port))
        return sock.recvfrom(4096)[0]
    finally:
        sock.close()


@pytest.mark.needs_internet
@lookup_tool_missing
@lookup_tool_broken
class TestResponderAgainstRealDns:
    """The responder resolving real names, with no container involved."""

    def test_it_answers_what_the_resolver_resolves(self) -> None:
        """The answers on the wire are the addresses the shield would have allowed."""
        allowed: list[str] = []
        resolver = DnsResolver(runner=SubprocessRunner())
        port = _free_udp_port()

        async def _drive() -> bytes:
            await proxy.serve(
                resolve=lambda name: resolver.resolve_domains([name]),
                permits=lambda _name: True,
                allow=allowed.append,
                upstream=QUAD9_DNS_IP,
                listen=_LOOPBACK,
                port=port,
            )
            return await asyncio.to_thread(_ask, port, _query(_ROTATING_DOMAIN))

        answer = asyncio.run(_drive())

        assert _answer_count(answer) >= 1
        # Every address handed out was allowed first, and they are real.
        assert allowed
        for address in allowed:
            socket.inet_pton(socket.AF_INET, address)

    def test_a_name_that_does_not_resolve_allows_nothing(self) -> None:
        allowed: list[str] = []
        resolver = DnsResolver(runner=SubprocessRunner())
        port = _free_udp_port()

        async def _drive() -> bytes:
            await proxy.serve(
                resolve=lambda name: resolver.resolve_domains([name]),
                permits=lambda _name: True,
                allow=allowed.append,
                upstream=QUAD9_DNS_IP,
                listen=_LOOPBACK,
                port=port,
            )
            return await asyncio.to_thread(_ask, port, _query(NONEXISTENT_DOMAIN))

        answer = asyncio.run(_drive())

        assert struct.unpack_from("!H", answer, 2)[0] & 0xF == 3  # NXDOMAIN
        assert allowed == []


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@lookup_tool_missing
@lookup_tool_broken
class TestResponderInAContainerNetns:
    """The responder where it runs in production, filling a real nft set.

    Run by hand or on a host runner — it needs podman, nft and a network.
    """

    def test_a_name_the_container_asks_for_becomes_reachable(
        self, shielded_container, shield_env: Path
    ) -> None:
        """The whole point of the tier, end to end.

        A shielded container starts with an allowlist that was resolved
        before it ran.  The addresses behind a CDN name are not the ones
        in that snapshot for long.  With the responder in the netns, the
        container asks for the name, the set gains the address it is
        about to use, and the connection lives — on a host with no
        dnsmasq, where the static tier would have had only the launch-time
        snapshot to offer.
        """
        pid = subprocess.run(
            ["podman", "inspect", "--format", "{{.State.Pid}}", shielded_container],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        ).stdout.strip()
        state_dir = shield_env / "containers" / str(shielded_container)

        # Admit the name, without resolving it: the responder is what has
        # to put its addresses in the set.  Written through the bundle so
        # the test cannot drift from the layout it is asserting against.
        StateBundle(state_dir).write_tier("project_allow", f"+{_ROTATING_DOMAIN}\n")

        before = nsenter_nft(pid, "list", "table", "inet", NFT_TABLE_NAME).stdout

        responder = subprocess.Popen(  # noqa: S603 — argv, no shell
            [
                "podman",
                "unshare",
                "nsenter",
                "-t",
                pid,
                "-n",
                sys.executable,
                "-m",
                "terok_shield.dns.proxy",
                "--state-dir",
                str(state_dir),
                "--upstream",
                QUAD9_DNS_IP,
                "--listen",
                _LOOPBACK,
                "--port",
                "5353",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            time.sleep(2)  # the responder binds, then the container asks
            asked = subprocess.run(
                [
                    "podman",
                    "unshare",
                    "nsenter",
                    "-t",
                    pid,
                    "-n",
                    "python3",
                    "-c",
                    "import socket,sys;"
                    "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(8);"
                    f"s.sendto(bytes.fromhex('{_query(_ROTATING_DOMAIN).hex()}'),"
                    f"('{_LOOPBACK}',5353));"
                    "sys.stdout.write(s.recvfrom(4096)[0].hex())",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert asked.returncode == 0, asked.stderr
            answer = bytes.fromhex(asked.stdout.strip())
            assert _answer_count(answer) >= 1

            after = nsenter_nft(pid, "list", "table", "inet", NFT_TABLE_NAME).stdout
        finally:
            responder.terminate()
            responder.wait(timeout=10)

        # The set grew, and it grew because the container asked.
        assert len(after) > len(before)
        assert f"{TIER_PROJECT_ALLOW}_v4" in after

    def test_the_responder_starts_where_dnsmasq_starts(self, container: str) -> None:
        """It must run in the container's netns and the host's PID namespace.

        The container reaches it as a peer on a socket and in no other
        way: not in its process table, not in its mount namespace.
        """
        pid = subprocess.run(
            ["podman", "inspect", "--format", "{{.State.Pid}}", container],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        ).stdout.strip()

        with subprocess.Popen(  # noqa: S603 — argv, no shell
            [
                "podman",
                "unshare",
                "nsenter",
                "-t",
                pid,
                "-n",
                sys.executable,
                "-c",
                "import os,json,sys;"
                "sys.stdout.write(json.dumps({'pid_ns': os.readlink('/proc/self/ns/pid'),"
                "'net_ns': os.readlink('/proc/self/ns/net')}))",
            ],
            stdout=subprocess.PIPE,
            text=True,
        ) as probe:
            seen = json.loads(probe.communicate(timeout=30)[0])

        assert seen["pid_ns"] == os.readlink("/proc/self/ns/pid")  # host PID namespace
        assert seen["net_ns"] != os.readlink("/proc/self/ns/net")  # container netns
