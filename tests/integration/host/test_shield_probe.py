# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for shield_probe — exercises the real kernel IP_RECVERR path.

These tests depend on Linux kernel ``IP_RECVERR`` support on the loopback
interface.  They do NOT require containers, nftables, or root — just a
standard Linux kernel.  If ``IP_RECVERR`` is not available (e.g. non-Linux
host), the tests will fail naturally, which is the desired signal.
"""

import socket
import unittest

import pytest

from terok_shield.resources.shield_probe import probe


@pytest.mark.needs_host_features
class TestProbeRealSocket(unittest.TestCase):
    """Test probe() against real kernel ICMP via localhost sockets."""

    def test_port_unreachable_on_localhost(self) -> None:
        """Probing an unused localhost port gets ICMP port-unreachable."""
        # Allocate an ephemeral port, then close so it's guaranteed unused.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        _, port = sock.getsockname()
        sock.close()

        result = probe("127.0.0.1", port, timeout=2.0)
        self.assertEqual(result["result"], "icmp-error")
        self.assertEqual(result["icmp_type"], 3)
        self.assertEqual(result["icmp_code"], 3)
        self.assertEqual(result["icmp_code_name"], "port-unreachable")

    def test_open_port_on_localhost(self) -> None:
        """Probing a port with a listening UDP socket does not report ICMP error."""
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            server.bind(("127.0.0.1", 0))
            _, port = server.getsockname()
            result = probe("127.0.0.1", port, timeout=1.0)
            self.assertNotEqual(result["result"], "icmp-error")
        finally:
            server.close()
