#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Probe network reachability and report the exact ICMP error code.

Standalone diagnostic script designed to run INSIDE containers.  Uses
``IP_RECVERR`` + ``MSG_ERRQUEUE`` on a regular UDP socket to retrieve
the kernel's ``sock_extended_err`` struct, which preserves the original
ICMP type and code — unlike ``connect()`` errno, which maps several
distinct ICMP codes to the same ``EHOSTUNREACH``.

No special capabilities (``CAP_NET_RAW``, ``CAP_NET_ADMIN``) are needed.

Usage::

    shield_probe.py HOST [PORT]

Exit codes:

- 0: probe completed (check JSON output for result)
- 1: usage error or unexpected failure

Output is a single JSON object on stdout.
"""

import json
import select
import socket
import struct
import sys

# Stable Linux kernel ABI constants.
_SOL_IP = 0
_IP_RECVERR = getattr(socket, "IP_RECVERR", 11)  # Added to Python in 3.14
_SO_EE_ORIGIN_ICMP = 2

# ICMP Destination Unreachable (type 3) code names.
_ICMP_UNREACH_CODES: dict[int, str] = {
    0: "net-unreachable",
    1: "host-unreachable",
    2: "protocol-unreachable",
    3: "port-unreachable",
    4: "fragmentation-needed",
    5: "source-route-failed",
    6: "net-unknown",
    7: "host-unknown",
    9: "net-admin-prohibited",
    10: "host-admin-prohibited",
    13: "admin-prohibited",
}

# Layout of struct sock_extended_err (linux/errqueue.h):
#   uint32_t ee_errno
#   uint8_t  ee_origin
#   uint8_t  ee_type
#   uint8_t  ee_code
#   uint8_t  ee_pad
#   uint32_t ee_info
#   uint32_t ee_data
_SOCK_EE_FMT = "@IBBBxII"
_SOCK_EE_SIZE = struct.calcsize(_SOCK_EE_FMT)


def probe(host: str, port: int = 443, timeout: float = 3.0) -> dict:
    """Probe *host*:*port* and return a result dict.

    The dict always contains ``"host"``, ``"port"``, and ``"result"``
    (one of ``"open"``, ``"icmp-error"``, ``"timeout"``).  On ICMP
    errors it also contains ``"icmp_type"``, ``"icmp_code"``,
    ``"icmp_code_name"``, and ``"errno"``.
    """
    base: dict = {"host": host, "port": port}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setblocking(False)
        sock.setsockopt(_SOL_IP, _IP_RECVERR, 1)
        sock.connect((host, port))
        # Send a minimal datagram to trigger the ICMP response.
        try:
            sock.send(b"\x00")
        except OSError:
            pass

        # Wait for the ICMP error to arrive on the error queue.
        # poll() + POLLERR reliably detects error queue events on Linux;
        # select() exceptfds does NOT signal them on many kernels.
        poller = select.poll()
        poller.register(sock, select.POLLERR)
        if not poller.poll(timeout * 1000):
            # No error within timeout — confirm reachability with a second send.
            # With IP_RECVERR enabled, the kernel queues ICMP errors on the
            # socket's error queue and makes subsequent send() fail with the
            # cached errno.  A successful send() therefore means no ICMP
            # unreachable was received — the host is genuinely reachable.
            try:
                sock.send(b"\x00")
                return {**base, "result": "open"}
            except OSError:
                pass
            # Re-check the error queue one more time.
            if not poller.poll(100):
                return {**base, "result": "timeout"}

        # Read the ICMP error from the error queue.
        try:
            _data, ancdata, _flags, _addr = sock.recvmsg(1024, 1024, socket.MSG_ERRQUEUE)
        except OSError:
            return {**base, "result": "timeout"}

        icmp = _parse_icmp_error(ancdata)
        return {**base, **icmp} if icmp else {**base, "result": "timeout"}
    finally:
        sock.close()


def main() -> int:
    """CLI entry point."""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} HOST [PORT]", file=sys.stderr)
        return 1

    host = sys.argv[1]
    try:
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    except ValueError:
        print(json.dumps({"error": f"invalid port: {sys.argv[2]!r}"}))
        return 1

    try:
        result = probe(host, port)
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return 1

    print(json.dumps(result))
    return 0


# ── Private helpers ────────────────────────────────────


def _parse_icmp_error(ancdata: list) -> dict | None:
    """Extract ICMP error fields from recvmsg ancillary data, or return None."""
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level != _SOL_IP or cmsg_type != _IP_RECVERR:
            continue
        if len(cmsg_data) < _SOCK_EE_SIZE:
            continue
        ee_errno, ee_origin, ee_type, ee_code, _, _ = struct.unpack(
            _SOCK_EE_FMT, cmsg_data[:_SOCK_EE_SIZE]
        )
        if ee_origin != _SO_EE_ORIGIN_ICMP:
            continue
        return {
            "result": "icmp-error",
            "icmp_type": ee_type,
            "icmp_code": ee_code,
            "icmp_code_name": _ICMP_UNREACH_CODES.get(ee_code, f"code-{ee_code}"),
            "errno": ee_errno,
        }
    return None


if __name__ == "__main__":
    sys.exit(main())
