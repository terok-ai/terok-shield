# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: nft set element manipulation."""

import pytest

from terok_shield.nft import add_elements, hook_ruleset
from tests.testnet import ALLOWED_TARGET_IPS, GOOGLE_DNS_IP, QUAD9_DNS_IP, TEST_IP1

from ..conftest import nft_missing, nsenter_nft, podman_missing


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestAddElementsLive:
    """Verify add_elements works with real nft."""

    def test_elements_appear_in_set(self, container: str, container_pid: str) -> None:
        """IPs added via add_elements appear in 'nft list set'."""
        r = nsenter_nft(container_pid, stdin=hook_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"
        r = nsenter_nft(container_pid, stdin=add_elements("allow_v4", [TEST_IP1]))
        assert r.returncode == 0, f"Add elements failed: {r.stderr}"

        listed = nsenter_nft(container_pid, "list", "set", "inet", "terok_shield", "allow_v4")
        assert listed.returncode == 0
        assert TEST_IP1 in listed.stdout

    def test_multiple_elements(self, container: str, container_pid: str) -> None:
        """Multiple IPs can be added to the set."""
        ips = [*ALLOWED_TARGET_IPS, GOOGLE_DNS_IP, QUAD9_DNS_IP]
        r = nsenter_nft(container_pid, stdin=hook_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"
        r = nsenter_nft(container_pid, stdin=add_elements("allow_v4", ips))
        assert r.returncode == 0, f"Add elements failed: {r.stderr}"

        listed = nsenter_nft(container_pid, "list", "set", "inet", "terok_shield", "allow_v4")
        assert listed.returncode == 0
        for ip in ips:
            assert ip in listed.stdout
