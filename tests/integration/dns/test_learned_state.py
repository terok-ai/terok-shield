# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: learned allow-set state on the dnsmasq tier.

The dnsmasq tier does no pre-resolution — the container's own DNS queries
populate the allow sets, before the answer reaches the workload.  These
tests pin the three guarantees that model rests on:

1. **Cold start works**: the first connection to an allowlisted domain
   succeeds with no ``resolved.ips`` seed at all.
2. **State survives transitions**: a ``shield down`` / ``shield up`` round
   trip must never forget learned elements (clients cache answers and will
   not re-query on our schedule).
3. **Forgetting is explicit**: ``shield reset`` — and only ``shield reset``
   — returns the allow sets to their just-launched contents.

Plus the DNS-plane deny: a runtime ``shield deny <domain>`` restarts dnsmasq so
the name stops resolving (NXDOMAIN), not merely IP-filtered.
"""

import subprocess

import pytest

from terok_shield import Shield, ShieldConfig
from terok_shield.nft.constants import NFT_TABLE_NAME, TIER_PROJECT_ALLOW
from terok_shield.run import which_sbin_aware
from terok_shield.state import StateBundle
from tests.testnet import (
    ALLOWED_TARGET_DOMAIN,
    ALLOWED_TARGET_DOMAIN_HTTP,
    ALLOWED_TARGET_HTTP,
    ALLOWED_TARGET_IPS,
    GOOGLE_DNS_DOMAIN,
)

from ..conftest import (
    CTR_PREFIX,
    IMAGE,
    _podman_rm,
    nft_missing,
    nsenter_nft,
    podman_missing,
)
from ..helpers import (
    assert_blocked,
    assert_reachable,
    exec_in_container,
    start_shielded_container,
)

_ALLOW_PROFILE = "learned-state"

dnsmasq_missing = pytest.mark.skipif(
    not which_sbin_aware("dnsmasq"),
    reason="dnsmasq not installed",
)


def _container_pid(name: str) -> str:
    """Host PID of a running container (for nsenter into its netns)."""
    r = subprocess.run(
        ["podman", "inspect", "--format", "{{.State.Pid}}", name],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    pid = r.stdout.strip()
    assert pid, f"podman inspect returned empty PID for container {name!r}"
    return pid


def _allow_set_v4(pid: str) -> str:
    """Contents of the tier-40 IPv4 allow set inside the container's netns."""
    r = nsenter_nft(pid, "list", "set", "inet", NFT_TABLE_NAME, f"{TIER_PROJECT_ALLOW}_v4")
    assert r.returncode == 0, f"listing the allow set failed: {r.stderr}"
    return r.stdout


def _learn(name: str, pid: str) -> None:
    """Resolve the allowed domain in-container and assert the set learned it."""
    exec_in_container(name, "nslookup", ALLOWED_TARGET_DOMAIN)
    contents = _allow_set_v4(pid)
    assert any(ip in contents for ip in ALLOWED_TARGET_IPS), (
        f"none of {ALLOWED_TARGET_IPS} learned into the allow set after resolving "
        f"{ALLOWED_TARGET_DOMAIN}:\n{contents}"
    )


@pytest.mark.needs_podman
@pytest.mark.needs_hooks
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@dnsmasq_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestLearnedStateLifecycle:
    """Learned allow-set state: cold start, down/up survival, explicit reset."""

    @pytest.fixture
    def learned_container(self, _pull_image: None, shield_env):
        """Container on the dnsmasq tier with the allowed domain in its profile.

        The domain rides a custom profile so it is allowlisted *at launch*
        (authored policy), not injected post-start via ``shield allow`` —
        the cold-start test must exercise the launch path with no seed.
        """
        profiles_dir = shield_env / "profiles"
        profiles_dir.mkdir(exist_ok=True)
        (profiles_dir / f"{_ALLOW_PROFILE}.txt").write_text(f"+{ALLOWED_TARGET_DOMAIN}\n")

        name = f"{CTR_PREFIX}-learned-{id(self)}"
        sd = shield_env / "containers" / name
        shield = Shield(ShieldConfig(state_dir=sd, profiles_dir=profiles_dir))

        _podman_rm(name)
        try:
            extra_args = shield.pre_start(name, [_ALLOW_PROFILE])
            if "terok.shield.dns_tier=dnsmasq" not in " ".join(extra_args):
                pytest.skip("dnsmasq tier not selected on this host")
            cid = start_shielded_container(name, extra_args, IMAGE)
            yield name, sd, shield, cid
        finally:
            _podman_rm(name)

    def test_cold_start_first_connection_needs_no_seed(self, learned_container) -> None:
        """The very first connection to an allowlisted domain succeeds unseeded.

        dnsmasq commits the nftset add while processing the upstream reply,
        before the client receives the answer — so the workload cannot race
        its own resolution.  This is the property that lets pre-resolution
        be dropped from the launch path entirely.
        """
        name, sd, _shield, _cid = learned_container
        assert not StateBundle(sd).resolved_cache.exists(), (
            "dnsmasq-tier launch must not write a resolved.ips seed"
        )
        assert_reachable(name, ALLOWED_TARGET_DOMAIN_HTTP)

    def test_learned_state_survives_down_up_round_trip(self, learned_container) -> None:
        """A down/up round trip must never forget what the workload learned.

        After ``shield up``, the learned IP is still in the allow set and a
        raw-IP fetch succeeds **without** a fresh DNS query — exactly the
        situation of a client that cached its answer across the down window.
        """
        name, _sd, shield, cid = learned_container
        pid = _container_pid(name)
        _learn(name, pid)

        shield.down(name, cid)
        shield.up(name, cid)

        contents = _allow_set_v4(pid)
        assert any(ip in contents for ip in ALLOWED_TARGET_IPS), (
            f"learned allow-set state lost across down/up:\n{contents}"
        )
        assert_reachable(name, ALLOWED_TARGET_HTTP)  # raw IP — no re-query involved

    def test_reset_forgets_learned_state_and_relearns(self, learned_container) -> None:
        """``shield reset`` — and only it — drops learned state, reversibly.

        After the reset the raw-IP fetch is blocked again (the set is back
        to its just-launched contents); a fresh in-container resolution
        re-learns and restores connectivity.
        """
        name, _sd, shield, _cid = learned_container
        pid = _container_pid(name)
        _learn(name, pid)

        shield.reset(name)

        contents = _allow_set_v4(pid)
        assert not any(ip in contents for ip in ALLOWED_TARGET_IPS), (
            f"reset left learned IPs in the allow set:\n{contents}"
        )
        assert_blocked(name, ALLOWED_TARGET_HTTP)  # raw IP, no DNS → stays cold

        _learn(name, pid)  # the workload re-earns its state
        assert_reachable(name, ALLOWED_TARGET_HTTP)

    def test_runtime_denied_domain_gets_nxdomain(self, learned_container) -> None:
        """A runtime ``shield deny <domain>`` sinkholes it in the DNS plane.

        ``deny`` restarts dnsmasq so it loads the fresh ``local=`` sinkhole
        (dnsmasq does not re-read its main config on SIGHUP), so the name
        stops resolving — not merely IP-filtered.
        """
        name, _sd, shield, _cid = learned_container
        shield.deny(name, GOOGLE_DNS_DOMAIN)

        r = exec_in_container(name, "nslookup", GOOGLE_DNS_DOMAIN)
        assert r.returncode != 0 or "NXDOMAIN" in (r.stdout + r.stderr), (
            f"denied domain still resolves:\n{r.stdout}\n{r.stderr}"
        )

    def test_dnsmasq_cache_is_disabled(self, learned_container) -> None:
        """cache-size=0 in the generated config — a cached answer would skip
        the nftset add and hand out an IP whose set element was never re-armed."""
        _name, sd, _shield, _cid = learned_container
        assert "cache-size=0" in StateBundle(sd).dnsmasq_conf.read_text()
