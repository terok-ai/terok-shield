# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Story-style integration tests for the dnsmasq per-container DNS lifecycle.

Each test class tells a user story end-to-end: tier detection, config
generation, dnsmasq launch inside a container's netns, live domain
allow/deny with SIGHUP reload, and poststop cleanup.

These tests require podman, nft, and dnsmasq on the host.  They create
real containers and verify actual DNS/nft behavior — no mocking.
"""

import shutil as _shutil
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from terok_shield import Shield, ShieldConfig, state
from terok_shield.config import DnsTier, detect_dns_tier
from terok_shield.dnsmasq import generate_config, nftset_entry, read_domains
from terok_shield.nft_constants import DNSMASQ_BIND, PASTA_DNS
from tests.testnet import (
    ALLOWED_TARGET_HTTP,
    BLOCKED_TARGET_HTTP,
    GOOGLE_DNS_DOMAIN,
    GOOGLE_DNS_IP,
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

dnsmasq_missing = pytest.mark.skipif(
    _shutil.which("dnsmasq") is None,
    reason="dnsmasq not installed",
)


# ── Helpers ──────────────────────────────────────────────


def _extract_annotation(args: list[str], key: str) -> str | None:
    """Extract an annotation value from podman args, or None if absent."""
    for i, arg in enumerate(args[:-1]):
        if arg == "--annotation" and args[i + 1].startswith(f"{key}="):
            return args[i + 1].split("=", 1)[1]
    return None


def _tier_from_args(args: list[str]) -> str | None:
    """Extract the dns_tier annotation value from podman args."""
    return _extract_annotation(args, "terok.shield.dns_tier")


# ── Story 1: DNS tier detection ──────────────────────────


@pytest.mark.needs_podman
@podman_missing
class TestDnsTierDetection:
    """Verify that DNS tier detection picks the right tier based on installed binaries."""

    def test_detect_tier_matches_host(self) -> None:
        """detect_dns_tier() returns a valid tier for the current host."""
        # Use a lightweight has() instead of SubprocessRunner (which needs nft)
        tier = detect_dns_tier(lambda name: _shutil.which(name) is not None)
        assert tier in (DnsTier.DNSMASQ, DnsTier.DIG, DnsTier.GETENT)

    def test_check_environment_reports_tier(self) -> None:
        """Shield.check_environment() includes dns_tier in its result."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = mock.MagicMock()
            runner.has.side_effect = lambda name: _shutil.which(name) is not None
            runner.run.return_value = "{}"  # minimal podman info
            shield = Shield(ShieldConfig(state_dir=Path(tmp)), runner=runner)
            env = shield.check_environment()
        assert env.dns_tier in ("dnsmasq", "dig", "getent")


# ── Story 2: dnsmasq config generation ───────────────────


class TestDnsmasqConfigGeneration:
    """Verify dnsmasq config is generated correctly for real profiles."""

    def test_nftset_entry_format(self) -> None:
        """nftset_entry produces the correct dnsmasq directive."""
        entry = nftset_entry("github.com")
        assert entry.startswith("nftset=/github.com/")
        assert "allow_v4" in entry
        assert "allow_v6" in entry

    def test_generate_config_with_real_domains(self, tmp_path: Path) -> None:
        """generate_config() produces a valid dnsmasq config for real domains."""
        pid_path = tmp_path / "dnsmasq.pid"
        config = generate_config(PASTA_DNS, ["github.com", "pypi.org"], pid_path)

        assert f"server={PASTA_DNS}" in config
        assert f"listen-address={DNSMASQ_BIND}" in config
        assert "nftset=/github.com/" in config
        assert "nftset=/pypi.org/" in config
        assert "bind-interfaces" in config
        assert "no-resolv" in config

    def test_config_written_to_state_dir(self, tmp_path: Path) -> None:
        """Config is written to the state directory alongside other state files."""
        state.ensure_state_dirs(tmp_path)
        conf_path = state.dnsmasq_conf_path(tmp_path)
        pid_path = state.dnsmasq_pid_path(tmp_path)
        config = generate_config(PASTA_DNS, ["example.org"], pid_path)
        conf_path.write_text(config)

        assert conf_path.is_file()
        assert "example.org" in conf_path.read_text()


# ── Story 3: pre_start with dnsmasq tier ─────────────────


@pytest.mark.needs_podman
@podman_missing
@nft_missing
@dnsmasq_missing
class TestPreStartDnsmasqTier:
    """pre_start() detects dnsmasq tier and sets correct podman args."""

    def test_pre_start_mounts_resolv_conf(self) -> None:
        """When dnsmasq tier is selected, pre_start() volume-mounts resolv.conf.

        The code cannot use ``--dns 127.0.0.1`` because podman passes it to
        pasta as a DNS-splice target, causing pasta to bind host port 53
        (privileged, fails rootless).  Instead it writes a custom resolv.conf
        and mounts it read-only into the container.
        """
        with tempfile.TemporaryDirectory() as tmp:
            sd = Path(tmp)
            shield = Shield(ShieldConfig(state_dir=sd))
            args = shield.pre_start("test-ctr")

            tier = _tier_from_args(args)
            if tier != "dnsmasq":
                pytest.skip(f"pre_start selected tier '{tier}', not dnsmasq")
            # --dns must NOT be used (causes pasta to bind host port 53)
            assert "--dns" not in args
            # resolv.conf volume mount replaces the old --dns flag
            vol_args = [args[i + 1] for i, v in enumerate(args) if v == "--volume"]
            expected_mount = f"{state.resolv_conf_path(sd)}:/etc/resolv.conf:ro,Z"
            assert expected_mount in vol_args, (
                f"expected exact resolv.conf mount {expected_mount!r}, got: {vol_args!r}"
            )

    def test_pre_start_writes_profile_domains(self) -> None:
        """pre_start() writes profile domains to state for the OCI hook."""
        with tempfile.TemporaryDirectory() as tmp:
            sd = Path(tmp)
            shield = Shield(ShieldConfig(state_dir=sd))
            args = shield.pre_start("test-ctr")

            tier = _tier_from_args(args)
            if tier != "dnsmasq":
                pytest.skip(f"pre_start selected tier '{tier}', not dnsmasq")
            domains_path = state.profile_domains_path(sd)
            assert domains_path.is_file()
            domains = read_domains(domains_path)
            assert len(domains) > 0

    def test_pre_start_sets_dns_tier_annotation(self) -> None:
        """pre_start() sets a dns_tier annotation."""
        with tempfile.TemporaryDirectory() as tmp:
            shield = Shield(ShieldConfig(state_dir=Path(tmp)))
            args = shield.pre_start("test-ctr")

        tier = _tier_from_args(args)
        assert tier is not None, "dns_tier annotation not found in pre_start args"
        assert tier in ("dnsmasq", "dig", "getent")


# ── Story 4: full dnsmasq lifecycle in a real container ──


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@pytest.mark.needs_hooks
@podman_missing
@nft_missing
@dnsmasq_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestDnsmasqInContainer:
    """End-to-end: dnsmasq launches inside a container's netns via OCI hook.

    This is the full story:
    1. pre_start() detects dnsmasq, mounts a resolv.conf volume (127.0.0.1)
    2. Container starts with the mounted resolv.conf, OCI hook fires
    3. Hook applies nft ruleset + launches dnsmasq in the netns
    4. Container's resolv.conf already points to 127.0.0.1 via the mount
    5. DNS queries inside container go through dnsmasq
    6. dnsmasq auto-populates nft allow sets via --nftset
    7. Container stop kills dnsmasq (poststop hook)
    """

    @pytest.fixture
    def dnsmasq_container(self, _pull_image: None, shield_env: Path):
        """Start a container with dnsmasq-tier shield protection."""
        name = f"{CTR_PREFIX}-dnsmasq-{id(self)}"
        sd = shield_env / "containers" / name
        cfg = ShieldConfig(state_dir=sd)
        shield = Shield(cfg)

        _podman_rm(name)
        try:
            extra_args = shield.pre_start(name)
            tier = _tier_from_args(extra_args)
            if tier != "dnsmasq":
                pytest.skip(f"dnsmasq tier not selected (got '{tier}')")

            start_shielded_container(name, extra_args, IMAGE)
            yield name, sd, shield
        finally:
            _podman_rm(name)

    def test_resolv_conf_points_to_dnsmasq(self, dnsmasq_container) -> None:
        """Container's resolv.conf points to 127.0.0.1 (dnsmasq)."""
        name, _sd, _shield = dnsmasq_container
        r = exec_in_container(name, "cat", "/etc/resolv.conf")
        assert r.returncode == 0
        assert "127.0.0.1" in r.stdout

    def test_dnsmasq_pid_file_exists(self, dnsmasq_container) -> None:
        """dnsmasq PID file was written to state directory."""
        _name, sd, _shield = dnsmasq_container
        pid_path = state.dnsmasq_pid_path(sd)
        assert pid_path.is_file()
        pid_str = pid_path.read_text().strip()
        assert pid_str.isdigit()

    def test_dnsmasq_config_exists(self, dnsmasq_container) -> None:
        """dnsmasq config was generated in state directory."""
        _name, sd, _shield = dnsmasq_container
        conf_path = state.dnsmasq_conf_path(sd)
        assert conf_path.is_file()
        config = conf_path.read_text()
        assert "listen-address=127.0.0.1" in config
        assert "nftset=/" in config

    def test_upstream_dns_persisted(self, dnsmasq_container) -> None:
        """Upstream DNS address was persisted to state."""
        _name, sd, _shield = dnsmasq_container
        upstream_path = state.upstream_dns_path(sd)
        assert upstream_path.is_file()
        upstream = upstream_path.read_text().strip()
        assert upstream  # non-empty

    def test_nft_sets_have_timeout(self, dnsmasq_container) -> None:
        """nft allow sets have timeout flag when dnsmasq is active."""
        name, _sd, _shield = dnsmasq_container
        result = subprocess.run(
            ["podman", "inspect", "--format", "{{.State.Pid}}", name],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        pid = result.stdout.strip()
        if not pid:
            pytest.fail(f"podman inspect returned empty PID for container {name!r}")

        r = nsenter_nft(pid, "list", "ruleset")
        assert r.returncode == 0
        assert "timeout" in r.stdout

    def test_allowed_domain_resolves_and_is_reachable(self, dnsmasq_container) -> None:
        """Traffic to allowed domains works through dnsmasq resolution."""
        name, _sd, _shield = dnsmasq_container
        assert_reachable(name, ALLOWED_TARGET_HTTP)

    def test_blocked_target_is_denied(self, dnsmasq_container) -> None:
        """Traffic to non-allowed targets is denied by nft."""
        name, _sd, _shield = dnsmasq_container
        assert_blocked(name, BLOCKED_TARGET_HTTP)

    def test_poststop_kills_dnsmasq(self, dnsmasq_container) -> None:
        """Container stop triggers the poststop hook, which kills dnsmasq."""
        name, sd, _shield = dnsmasq_container

        pid_str = state.dnsmasq_pid_path(sd).read_text().strip()
        assert Path(f"/proc/{pid_str}/cmdline").exists(), (
            "dnsmasq should be running before container stop"
        )

        subprocess.run(
            ["podman", "stop", "--time=5", name], capture_output=True, check=True, timeout=30
        )

        assert not Path(f"/proc/{pid_str}").exists(), (
            f"dnsmasq PID {pid_str} still in /proc after container stop — "
            "poststop hook may not have run"
        )


# ── Story 5: live domain allow/deny ─────────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@pytest.mark.needs_hooks
@podman_missing
@nft_missing
@dnsmasq_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestLiveDomainAllowDeny:
    """Live allow/deny updates dnsmasq config and nft sets."""

    @pytest.fixture
    def shielded(self, _pull_image: None, shield_env: Path):
        """Start a shielded container for allow/deny testing."""
        name = f"{CTR_PREFIX}-allowdeny-{id(self)}"
        sd = shield_env / "containers" / name
        cfg = ShieldConfig(state_dir=sd)
        shield = Shield(cfg)

        _podman_rm(name)
        try:
            extra_args = shield.pre_start(name)
            tier = _tier_from_args(extra_args)
            if tier != "dnsmasq":
                pytest.skip(
                    f"dnsmasq tier not selected (got '{tier}') — live domain reload not testable"
                )

            start_shielded_container(name, extra_args, IMAGE)
            yield name, sd, shield
        finally:
            _podman_rm(name)

    def test_allow_domain_updates_live_domains(self, shielded) -> None:
        """shield.allow(domain) adds the domain to live.domains."""
        name, sd, shield = shielded
        shield.allow(name, GOOGLE_DNS_DOMAIN)
        domains = read_domains(state.live_domains_path(sd))
        assert GOOGLE_DNS_DOMAIN in domains

    def test_deny_domain_adds_to_denied_domains(self, shielded) -> None:
        """shield.deny(domain) adds the domain to denied.domains."""
        name, sd, shield = shielded
        shield.allow(name, GOOGLE_DNS_DOMAIN)
        shield.deny(name, GOOGLE_DNS_DOMAIN)
        denied = read_domains(state.denied_domains_path(sd))
        assert GOOGLE_DNS_DOMAIN in denied

    def test_allow_domain_populates_nft_set(self, shielded) -> None:
        """Allowing a domain and querying it causes dnsmasq to populate the nft allow set."""
        name, _sd, shield = shielded

        shield.allow(name, GOOGLE_DNS_DOMAIN)

        # DNS query inside the container — dnsmasq resolves and fires --nftset
        exec_in_container(name, "nslookup", GOOGLE_DNS_DOMAIN)

        result = subprocess.run(
            ["podman", "inspect", "--format", "{{.State.Pid}}", name],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        pid = result.stdout.strip()
        if not pid:
            pytest.fail(f"podman inspect returned empty PID for container {name!r}")

        r = nsenter_nft(pid, "list", "set", "inet", "terok_shield", "allow_v4")
        assert r.returncode == 0
        assert GOOGLE_DNS_IP in r.stdout, (
            f"{GOOGLE_DNS_IP} not found in allow_v4 set after resolving {GOOGLE_DNS_DOMAIN}; "
            f"set contents: {r.stdout!r}"
        )


# ── Story 6: graceful degradation (dig fallback) ─────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
class TestGracefulDegradation:
    """Verify shield works without dnsmasq (dig/getent fallback)."""

    def test_pre_start_without_dnsmasq(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """pre_start() falls back to a non-dnsmasq tier when dnsmasq is absent."""
        import shutil

        original_which = shutil.which

        def _which_no_dnsmasq(name: str, *a, **kw):
            if name == "dnsmasq":
                return None
            return original_which(name, *a, **kw)

        monkeypatch.setattr(shutil, "which", _which_no_dnsmasq)

        with tempfile.TemporaryDirectory() as tmp:
            shield = Shield(ShieldConfig(state_dir=Path(tmp)))
            # The Shield constructor pre-populates shield.runner._has_cache before
            # the monkeypatch above overrides shield.runner.has.  Clear the cache
            # so that detect_dns_tier(shield.runner.has) uses the patched lookup
            # rather than returning the cached pre-patch result.
            shield.runner._has_cache.clear()

            # Determine expected tier with dnsmasq hidden
            expected_tier = detect_dns_tier(shield.runner.has)

            args = shield.pre_start("test-ctr")

        # Should NOT have --dns flag (non-dnsmasq tier resolves at pre-start)
        assert "--dns" not in args
        # dns_tier annotation should match what detect_dns_tier returned
        tier = _tier_from_args(args)
        assert tier is not None, "dns_tier annotation not found"
        assert tier == expected_tier.value
        assert tier != "dnsmasq"


# ── Story 7: state dir reuse across container lifecycle ───


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@pytest.mark.needs_hooks
@podman_missing
@nft_missing
@dnsmasq_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestRestartWithReusedStateDir:
    """Stop+remove a container and re-create it with the same state dir.

    Verifies that dnsmasq starts cleanly on the second run — no stale PID
    file from the previous lifecycle fools the post-launch existence check.
    This directly exercises the ``_clear_pid_file()`` call added to
    ``dnsmasq.launch()`` to guard against reused state directories.
    """

    def test_dnsmasq_restarts_cleanly_on_reuse(self, _pull_image: None, shield_env: Path) -> None:
        """dnsmasq gets a fresh PID when the container is re-created with the same state dir."""
        name = f"{CTR_PREFIX}-restart-{id(self)}"
        sd = shield_env / "containers" / name
        shield = Shield(ShieldConfig(state_dir=sd))

        _podman_rm(name)
        try:
            # First run
            extra_args = shield.pre_start(name)
            tier = _tier_from_args(extra_args)
            if tier != "dnsmasq":
                pytest.skip(f"dnsmasq tier not selected (got '{tier}')")

            start_shielded_container(name, extra_args, IMAGE)

            first_pid = state.dnsmasq_pid_path(sd).read_text().strip()
            assert first_pid.isdigit()

            # Stop and remove — poststop hook kills dnsmasq, PID file remains on disk
            subprocess.run(["podman", "stop", "--time=5", name], capture_output=True, timeout=30)
            subprocess.run(["podman", "rm", name], capture_output=True, timeout=15)

            assert not Path(f"/proc/{first_pid}").exists(), (
                "dnsmasq should be gone after container stop"
            )

            # Second run with the same state dir — pre_start is idempotent
            extra_args2 = shield.pre_start(name)
            start_shielded_container(name, extra_args2, IMAGE)

            second_pid = state.dnsmasq_pid_path(sd).read_text().strip()
            assert second_pid.isdigit()
            assert second_pid != first_pid, (
                "dnsmasq should have a new PID after re-creation with same state dir"
            )

            r = exec_in_container(name, "cat", "/etc/resolv.conf")
            assert "127.0.0.1" in r.stdout
        finally:
            _podman_rm(name)
