# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: ICMP probe detection (host + container)."""

import json
import socket
import subprocess
import unittest

import pytest

from terok_shield.nft.rules import hook_ruleset
from terok_shield.resources.shield_probe import probe
from tests.testnet import ALLOWED_TARGET_IPS, BLOCKED_TARGET_IP

from ..conftest import nft_missing, nsenter_nft, podman_missing
from ..helpers import exec_in_container as _exec

# ── Host-level probe (no container needed) ───────────────


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


# ── Container-level probe (admin-prohibited detection) ───


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestShieldProbe:
    """Verify shield_probe detects the exact ICMP admin-prohibited code."""

    def _run_probe(self, container: str, host: str, port: int = 443, timeout: int = 15) -> dict:
        """Run shield_probe.py inside the container and return parsed JSON."""
        r = _exec(
            container, "python3", "/usr/local/bin/shield_probe.py", host, str(port), timeout=timeout
        )
        assert r.returncode == 0, f"shield_probe failed: {r.stderr}"
        return json.loads(r.stdout)

    def test_admin_prohibited_detected(self, probe_container: str) -> None:
        """Blocked traffic reports ICMP type 3, code 13 (admin-prohibited)."""
        # Apply the hook-mode firewall.
        pid = subprocess.run(
            ["podman", "inspect", "--format", "{{.State.Pid}}", probe_container],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        r = nsenter_nft(pid, stdin=hook_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"

        result = self._run_probe(probe_container, BLOCKED_TARGET_IP)
        assert result["result"] == "icmp-error", f"Expected icmp-error, got: {result}"
        assert result["icmp_type"] == 3, f"Expected ICMP type 3, got: {result}"
        assert result["icmp_code"] == 13, f"Expected ICMP code 13, got: {result}"
        assert result["icmp_code_name"] == "admin-prohibited"

    def test_allowed_ip_is_open(self, probe_container: str) -> None:
        """Without a firewall, probe reports open/timeout (not icmp-error)."""
        result = self._run_probe(probe_container, ALLOWED_TARGET_IPS[0], port=53)
        assert result["result"] != "icmp-error", f"Unexpected ICMP error: {result}"
