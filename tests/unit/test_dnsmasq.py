# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the dnsmasq lifecycle module."""

from pathlib import Path
from unittest import mock

import pytest

from terok_shield.config import DnsTier
from terok_shield.dns.dnsmasq import (
    _validate_domain,
    deny_config_lines,
    generate_config,
    has_nftset_support,
    locate,
    nftset_entry,
    read_denied_domains,
    read_merged_domains,
    read_override_domains,
    reload,
)
from terok_shield.nft.constants import (
    DNSMASQ_BIND_DEFAULT,
    DNSMASQ_BIND_KRUN,
    NFT_TABLE_NAME,
    PASTA_DNS,
)
from terok_shield.run import ShieldNeedsSetup
from terok_shield.state import StateBundle

from ..testfs import DNSMASQ_SBIN
from ..testnet import TEST_DOMAIN, TEST_DOMAIN2

# ── _validate_domain ────────────────────────────────────


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        pytest.param("github.com", "github.com", id="simple"),
        pytest.param("GITHUB.COM", "github.com", id="uppercase"),
        pytest.param("api.github.com", "api.github.com", id="subdomain"),
        pytest.param("*.github.com", "*.github.com", id="wildcard"),
        pytest.param("a-b.example.org", "a-b.example.org", id="hyphen"),
    ],
)
def test_validate_domain_accepts_valid(domain: str, expected: str) -> None:
    """Valid domain names are accepted and lowercased."""
    assert _validate_domain(domain) == expected


@pytest.mark.parametrize(
    "domain",
    [
        pytest.param("", id="empty"),
        pytest.param("192.0.2.1", id="ip-address"),
        pytest.param("-bad.com", id="leading-hyphen"),
        pytest.param("no spaces.com", id="spaces"),
        pytest.param("; rm -rf /", id="injection-attempt"),
        pytest.param("../../etc/passwd", id="traversal"),
        pytest.param("com", id="tld-only"),
        pytest.param("*.com", id="wildcard-tld-only"),
        pytest.param("org", id="tld-only-org"),
    ],
)
def test_validate_domain_rejects_invalid(domain: str) -> None:
    """Invalid or dangerous domain names are rejected."""
    with pytest.raises(ValueError):
        _validate_domain(domain)


# ── nftset_entry ─────────────────────────────────────────


def test_nftset_entry_format() -> None:
    """nftset_entry() generates the correct dnsmasq nftset config line."""
    result = nftset_entry("github.com")
    assert result == (
        f"nftset=/github.com/4#inet#{NFT_TABLE_NAME}#t40_project_allow_v4"
        f",6#inet#{NFT_TABLE_NAME}#t40_project_allow_v6"
    )


def test_nftset_entry_strips_wildcard() -> None:
    """Wildcard prefix is stripped (dnsmasq nftset matches subdomains inherently)."""
    result = nftset_entry("*.github.com")
    assert "*.github.com" not in result
    assert "nftset=/github.com/" in result


def test_nftset_entry_rejects_invalid_domain() -> None:
    """Invalid domain raises ValueError."""
    with pytest.raises(ValueError):
        nftset_entry("; injection")


# ── generate_config ──────────────────────────────────────


def test_generate_config_basic(tmp_path: Path) -> None:
    """generate_config() produces valid dnsmasq config with nftset entries."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    config = generate_config(
        PASTA_DNS, [TEST_DOMAIN, TEST_DOMAIN2], pid_path, listen_address=DNSMASQ_BIND_DEFAULT
    )

    assert f"server={PASTA_DNS}" in config
    assert f"listen-address={DNSMASQ_BIND_DEFAULT}" in config
    assert "port=53" in config
    assert "bind-interfaces" in config
    assert "no-resolv" in config
    assert f"pid-file={pid_path}" in config
    assert f"nftset=/{TEST_DOMAIN}/" in config
    assert f"nftset=/{TEST_DOMAIN2}/" in config


def test_generate_config_without_population_keeps_the_sinkholes(tmp_path: Path) -> None:
    """A dnsmasq without nftset support gets no ``nftset=`` lines but still every sinkhole."""
    config = generate_config(
        PASTA_DNS,
        [TEST_DOMAIN],
        StateBundle(tmp_path).dnsmasq_pid,
        listen_address=DNSMASQ_BIND_DEFAULT,
        deny_domains=[TEST_DOMAIN2],
        populate=False,
    )
    assert "nftset=" not in config
    assert f"local=/{TEST_DOMAIN2}/" in config


def test_generate_config_krun_listen_address(tmp_path: Path) -> None:
    """generate_config(listen_address=DNSMASQ_BIND_KRUN) emits the krun bind."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    config = generate_config(PASTA_DNS, [TEST_DOMAIN], pid_path, listen_address=DNSMASQ_BIND_KRUN)

    assert f"listen-address={DNSMASQ_BIND_KRUN}" in config
    assert "listen-address=127.0.0.1" not in config


def test_generate_config_rejects_invalid_listen_address(tmp_path: Path) -> None:
    """generate_config() raises ValueError when listen_address isn't an IP."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    with pytest.raises(ValueError):
        generate_config(PASTA_DNS, [], pid_path, listen_address="not-an-ip")


def test_generate_config_skips_invalid_domains(tmp_path: Path) -> None:
    """Invalid domains are silently skipped."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    config = generate_config(
        PASTA_DNS,
        [TEST_DOMAIN, "; rm -rf /", TEST_DOMAIN2],
        pid_path,
        listen_address=DNSMASQ_BIND_DEFAULT,
    )

    assert f"nftset=/{TEST_DOMAIN}/" in config
    assert f"nftset=/{TEST_DOMAIN2}/" in config
    assert "rm -rf" not in config


def test_generate_config_empty_domains(tmp_path: Path) -> None:
    """Empty domain list produces config without nftset lines."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    config = generate_config(PASTA_DNS, [], pid_path, listen_address=DNSMASQ_BIND_DEFAULT)

    assert "nftset" not in config
    assert f"server={PASTA_DNS}" in config


def test_generate_config_with_log_path(tmp_path: Path) -> None:
    """log_path enables query logging directives."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    log_path = StateBundle(tmp_path).dnsmasq_log
    config = generate_config(
        PASTA_DNS, [TEST_DOMAIN], pid_path, listen_address=DNSMASQ_BIND_DEFAULT, log_path=log_path
    )

    assert "log-queries" in config
    assert f"log-facility={log_path}" in config


def test_generate_config_without_log_path(tmp_path: Path) -> None:
    """Default (no log_path) omits query logging directives."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    config = generate_config(
        PASTA_DNS, [TEST_DOMAIN], pid_path, listen_address=DNSMASQ_BIND_DEFAULT
    )

    assert "log-queries" not in config
    assert "log-facility" not in config


# ── _clear_pid_file ──────────────────────────────────────


def test_clear_pid_file_removes_file(tmp_path: Path) -> None:
    """_clear_pid_file removes the PID file."""
    from terok_shield.dns.dnsmasq import _clear_pid_file

    StateBundle(tmp_path).dnsmasq_pid.write_text("12345\n")
    _clear_pid_file(tmp_path)
    assert not StateBundle(tmp_path).dnsmasq_pid.exists()


def test_clear_pid_file_ignores_missing(tmp_path: Path) -> None:
    """_clear_pid_file silently ignores missing PID file."""
    from terok_shield.dns.dnsmasq import _clear_pid_file

    _clear_pid_file(tmp_path)  # should not raise


# ── read_merged_domains (policy-backed) ──────────────────


def test_read_merged_domains_empty(tmp_path: Path) -> None:
    """read_merged_domains() returns empty list when no policy exists."""
    StateBundle(tmp_path).ensure_dirs()
    assert read_merged_domains(tmp_path) == []


def test_read_merged_domains_project_tier(tmp_path: Path) -> None:
    """Admitted domains from the project-allow tier are returned in order."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.write_tier("project_allow", f"+{TEST_DOMAIN}\n+{TEST_DOMAIN2}\n")
    assert read_merged_domains(tmp_path) == [TEST_DOMAIN, TEST_DOMAIN2]


def test_read_merged_domains_merges_live_overlay(tmp_path: Path) -> None:
    """The runtime overlay (policy/live) adds to the admitted domains."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.write_tier("project_allow", f"+{TEST_DOMAIN}\n")
    bundle.overlay_set("+", TEST_DOMAIN2)
    merged = read_merged_domains(tmp_path)
    assert TEST_DOMAIN in merged
    assert TEST_DOMAIN2 in merged


def test_read_merged_domains_subtracts_denied(tmp_path: Path) -> None:
    """A '-' overlay entry removes a domain from the dnsmasq list."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.write_tier("project_allow", f"+{TEST_DOMAIN}\n+{TEST_DOMAIN2}\n")
    bundle.overlay_set("-", TEST_DOMAIN)
    merged = read_merged_domains(tmp_path)
    assert TEST_DOMAIN not in merged
    assert TEST_DOMAIN2 in merged


# ── reload ───────────────────────────────────────────────


def _launched(tmp_path: Path, tier: DnsTier = DnsTier.DNSMASQ_LIVE) -> StateBundle:
    """A bundle as ``pre_start`` and the hook leave it: tier, binary, and a live PID."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.dns_tier.write_text(f"{tier.value}\n")
    bundle.dnsmasq_bin.write_text(f"{DNSMASQ_SBIN}\n")
    bundle.dnsmasq_command.write_text("dnsmasq\n")
    bundle.dnsmasq_pid.write_text("12345\n")
    return bundle


def _run_reload(tmp_path: Path, *args: object, **kwargs: object) -> mock.MagicMock:
    """Invoke reload() with a mock runner and stubbed stop/verify, return the runner.

    ``_terminate`` (kill loop) and ``_await_restart`` (pidfile poll) have their
    own direct tests below, so the reload-flow tests stub them out.
    """
    runner = mock.MagicMock()
    with (
        mock.patch("terok_shield.dns.dnsmasq.is_our_dnsmasq", return_value=True),
        mock.patch("terok_shield.dns.dnsmasq.require_host_tool", return_value=DNSMASQ_SBIN),
        mock.patch("terok_shield.dns.dnsmasq._terminate"),
        mock.patch("terok_shield.dns.dnsmasq._await_restart"),
    ):
        reload(tmp_path, *args, container="test-ctr", runner=runner, **kwargs)  # type: ignore[arg-type]
    return runner


def test_reload_regenerates_config_and_restarts(tmp_path: Path) -> None:
    """reload() regenerates the config and relaunches the recorded dnsmasq in the netns.

    dnsmasq does not re-read its main config on SIGHUP, so the reload must
    restart it for the new nftset/sinkhole directives to take effect.
    """
    bundle = _launched(tmp_path)

    runner = _run_reload(tmp_path, PASTA_DNS, [TEST_DOMAIN])

    assert f"nftset=/{TEST_DOMAIN}/" in bundle.dnsmasq_conf.read_text()
    runner.dnsmasq_via_nsenter.assert_called_once_with(
        "test-ctr", str(bundle.dnsmasq_conf), binary=DNSMASQ_SBIN
    )


def test_reload_on_the_static_dnsmasq_tier_emits_no_nftset_lines(tmp_path: Path) -> None:
    """A dnsmasq without nftset support is relaunched with sinkholes only."""
    bundle = _launched(tmp_path, DnsTier.DNSMASQ_STATIC)

    _run_reload(tmp_path, PASTA_DNS, [TEST_DOMAIN], deny_domains=[TEST_DOMAIN2])

    conf = bundle.dnsmasq_conf.read_text()
    assert "nftset=" not in conf
    assert f"local=/{TEST_DOMAIN2}/" in conf


def test_reload_preserves_krun_listen_address(tmp_path: Path) -> None:
    """reload() reads the existing conf's listen-address and re-emits it.

    Without this, a krun-runtime container's reload would silently rebind
    dnsmasq onto netns ``127.0.0.1`` and break DNS for the guest.
    """
    _launched(tmp_path).dnsmasq_conf.write_text(
        f"listen-address={DNSMASQ_BIND_KRUN}\nport=53\nbind-interfaces\n"
    )

    _run_reload(tmp_path, PASTA_DNS, [TEST_DOMAIN])

    new_conf = StateBundle(tmp_path).dnsmasq_conf.read_text()
    assert f"listen-address={DNSMASQ_BIND_KRUN}" in new_conf
    assert f"listen-address={DNSMASQ_BIND_DEFAULT}" not in new_conf


def test_reload_falls_back_to_default_when_listen_address_missing(tmp_path: Path) -> None:
    """reload() emits the default bind when the prior conf had no ``listen-address=`` line."""
    _launched(tmp_path).dnsmasq_conf.write_text("port=53\nbind-interfaces\n")

    _run_reload(tmp_path, PASTA_DNS, [TEST_DOMAIN])

    assert (
        f"listen-address={DNSMASQ_BIND_DEFAULT}" in StateBundle(tmp_path).dnsmasq_conf.read_text()
    )


def test_reload_noop_when_not_running(tmp_path: Path) -> None:
    """reload() is a no-op (no relaunch) when the dnsmasq PID file is absent."""
    StateBundle(tmp_path).ensure_dirs()
    runner = _run_reload(tmp_path, PASTA_DNS, [TEST_DOMAIN])
    runner.dnsmasq_via_nsenter.assert_not_called()


def test_reload_raises_on_stale_pid(tmp_path: Path) -> None:
    """reload() raises RuntimeError when the PID is not our dnsmasq (stale)."""
    _launched(tmp_path)
    runner = mock.MagicMock()

    with mock.patch("terok_shield.dns.dnsmasq.is_our_dnsmasq", return_value=False):
        with pytest.raises(RuntimeError, match="not dnsmasq"):
            reload(tmp_path, PASTA_DNS, [TEST_DOMAIN], container="c", runner=runner)


def test_terminate_sigterms_then_sigkills(tmp_path: Path) -> None:
    """_terminate SIGTERMs, then SIGKILLs a process that outlives the timeout."""
    import signal

    from terok_shield.dns.dnsmasq import _terminate

    with (
        mock.patch("terok_shield.dns.dnsmasq.is_our_dnsmasq", return_value=True),  # never dies
        mock.patch("terok_shield.dns.dnsmasq.os.kill") as mock_kill,
        mock.patch("terok_shield.dns.dnsmasq.time.sleep"),
    ):
        _terminate(12345, tmp_path, timeout_s=0.0)

    assert mock.call(12345, signal.SIGTERM) in mock_kill.call_args_list
    assert mock.call(12345, signal.SIGKILL) in mock_kill.call_args_list


def test_await_restart_raises_when_dnsmasq_absent(tmp_path: Path) -> None:
    """_await_restart raises when no fresh dnsmasq appears within the timeout."""
    from terok_shield.dns.dnsmasq import _await_restart

    StateBundle(tmp_path).ensure_dirs()  # no pid file written
    with mock.patch("terok_shield.dns.dnsmasq.time.sleep"):
        with pytest.raises(RuntimeError, match="did not restart"):
            _await_restart(tmp_path, timeout_s=0.0)


def test_terminate_stops_at_sigterm_when_the_process_exits(tmp_path: Path) -> None:
    """A dnsmasq that exits on SIGTERM never sees SIGKILL."""
    import signal

    from terok_shield.dns.dnsmasq import _terminate

    with (
        mock.patch("terok_shield.dns.dnsmasq.is_our_dnsmasq", return_value=False),  # gone
        mock.patch("terok_shield.dns.dnsmasq.os.kill") as mock_kill,
    ):
        _terminate(12345, tmp_path)

    assert mock_kill.call_args_list == [mock.call(12345, signal.SIGTERM)]


def test_await_restart_returns_when_fresh_dnsmasq_present(tmp_path: Path) -> None:
    """_await_restart returns cleanly once a fresh dnsmasq owns the conf."""
    from terok_shield.dns.dnsmasq import _await_restart

    StateBundle(tmp_path).ensure_dirs()
    StateBundle(tmp_path).dnsmasq_pid.write_text("999\n")
    with mock.patch("terok_shield.dns.dnsmasq.is_our_dnsmasq", return_value=True):
        _await_restart(tmp_path)  # must not raise


# ── generate_config validation ───────────────────────────


def test_generate_config_rejects_invalid_upstream(tmp_path: Path) -> None:
    """generate_config() raises ValueError for non-IP upstream."""
    with pytest.raises(ValueError):
        generate_config(
            "not-an-ip", [], tmp_path / "dnsmasq.pid", listen_address=DNSMASQ_BIND_DEFAULT
        )


# ── has_nftset_support ───────────────────────────────────


def test_has_nftset_support_detects_support() -> None:
    """has_nftset_support() asks the given binary and reads 'nftset' in its options."""
    runner = mock.MagicMock()
    runner.run.return_value = (
        "Dnsmasq version 2.92  Copyright (c) 2000-2025 Simon Kelley\n"
        "Compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 "
        "no-Lua TFTP conntrack ipset nftset auth DNSSEC loop-detect inotify dumpfile\n"
    )
    assert has_nftset_support(runner, DNSMASQ_SBIN) is True
    assert runner.run.call_args.args[0][0] == DNSMASQ_SBIN


def test_has_nftset_support_detects_no_support() -> None:
    """has_nftset_support() returns False when version output lists 'no-nftset'."""
    runner = mock.MagicMock()
    runner.run.return_value = (
        "Dnsmasq version 2.90\n"
        "Compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 "
        "no-Lua TFTP conntrack ipset no-nftset auth DNSSEC loop-detect inotify dumpfile\n"
    )
    assert has_nftset_support(runner, DNSMASQ_SBIN) is False


def test_has_nftset_support_false_when_the_binary_prints_nothing() -> None:
    """A binary that cannot run yields no options, hence no nftset support."""
    runner = mock.MagicMock()
    runner.run.return_value = ""
    assert has_nftset_support(runner, DNSMASQ_SBIN) is False


# ── locate ───────────────────────────────────────────────


def test_locate_uses_the_configured_binary(tmp_path: Path) -> None:
    """An explicit executable file is the binary, whatever PATH holds."""
    binary = tmp_path / "dnsmasq-nftset"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    runner = mock.MagicMock()
    assert locate(binary, runner) == str(binary.resolve())
    runner.has.assert_not_called()


def test_locate_refuses_a_configured_path_that_is_not_executable(tmp_path: Path) -> None:
    """A configured path that is not an executable file is refused, never replaced."""
    missing = tmp_path / "missing"
    runner = mock.MagicMock()
    with pytest.raises(ShieldNeedsSetup, match=str(missing)):
        locate(missing, runner)


def test_locate_is_empty_when_the_host_has_no_dnsmasq() -> None:
    """Without a configured path, the host's own probe decides."""
    runner = mock.MagicMock()
    runner.has.return_value = False
    assert locate(None, runner) == ""


# ── cache-size + DNS-plane deny ─────────────────────────


def test_generate_config_disables_dnsmasq_cache(tmp_path: Path) -> None:
    """cache-size=0: a cached answer would skip the --nftset add and hand the
    workload an IP whose (timed) allow-set element was never re-armed."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    config = generate_config(PASTA_DNS, [], pid_path, listen_address=DNSMASQ_BIND_DEFAULT)
    assert "cache-size=0" in config


def test_generate_config_sinkholes_denied_domains(tmp_path: Path) -> None:
    """A denied domain gets a local=/dom/ NXDOMAIN sinkhole line."""
    pid_path = StateBundle(tmp_path).dnsmasq_pid
    config = generate_config(
        PASTA_DNS,
        [TEST_DOMAIN],
        pid_path,
        listen_address=DNSMASQ_BIND_DEFAULT,
        deny_domains=[TEST_DOMAIN2],
    )
    assert f"local=/{TEST_DOMAIN2}/" in config
    assert f"nftset=/{TEST_DOMAIN}/" in config


class TestDenyConfigLines:
    """deny_config_lines() — sinkholes, punch-throughs, and their edge cases."""

    def test_denied_domain_is_sinkholed(self) -> None:
        """Plain deny → one local=/dom/ line, nothing else."""
        assert deny_config_lines([], [TEST_DOMAIN], PASTA_DNS) == [f"local=/{TEST_DOMAIN}/"]

    def test_allowed_subdomain_of_denied_ancestor_gets_punch_through(self) -> None:
        """dnsmasq matches by longest suffix — the specific allow must outrank
        the ancestor sinkhole, mirroring the policy engine's composition."""
        sub = f"api.{TEST_DOMAIN}"
        lines = deny_config_lines([sub], [TEST_DOMAIN], PASTA_DNS)
        assert f"local=/{TEST_DOMAIN}/" in lines
        assert f"server=/{sub}/{PASTA_DNS}" in lines

    def test_wildcards_are_stripped_on_both_sides(self) -> None:
        """*.dom deny and *.sub allow behave as their base domains."""
        sub = f"api.{TEST_DOMAIN}"
        lines = deny_config_lines([f"*.{sub}"], [f"*.{TEST_DOMAIN}"], PASTA_DNS)
        assert f"local=/{TEST_DOMAIN}/" in lines
        assert f"server=/{sub}/{PASTA_DNS}" in lines

    def test_same_name_conflict_emits_no_sinkhole(self) -> None:
        """Deny at exactly an allowed name: a same-specificity dnsmasq directive
        conflict has no defined winner — leave the verdict to the IP tiers."""
        assert deny_config_lines([TEST_DOMAIN], [TEST_DOMAIN], PASTA_DNS) == []

    def test_unrelated_allow_gets_no_punch_through(self) -> None:
        """Only strict subdomains of the denied base punch through."""
        lines = deny_config_lines([TEST_DOMAIN2], [TEST_DOMAIN], PASTA_DNS)
        assert lines == [f"local=/{TEST_DOMAIN}/"]

    def test_invalid_deny_entries_are_skipped(self) -> None:
        """Malformed deny entries are dropped with a warning, like the nftset path."""
        assert deny_config_lines([], ["not a domain!"], PASTA_DNS) == []

    def test_duplicate_lines_are_deduplicated(self) -> None:
        """Two denied ancestors of one allow yield a single punch-through."""
        sub_base = f"sub.{TEST_DOMAIN}"
        allowed = f"api.{sub_base}"
        lines = deny_config_lines([allowed], [TEST_DOMAIN, sub_base], PASTA_DNS)
        assert lines.count(f"server=/{allowed}/{PASTA_DNS}") == 1


def test_read_denied_domains_composes_from_policy(tmp_path: Path) -> None:
    """read_denied_domains() surfaces '-' domains from the tiered bundle."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.write_tier("project_allow", f"+{TEST_DOMAIN}\n")
    bundle.overlay_set("-", TEST_DOMAIN2)
    assert read_denied_domains(tmp_path) == [TEST_DOMAIN2]


def test_read_override_domains_composes_from_policy(tmp_path: Path) -> None:
    """read_override_domains() surfaces '+' t10 domains from the tiered bundle."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.write_tier("override", f"+{TEST_DOMAIN}\n")
    assert read_override_domains(tmp_path) == [TEST_DOMAIN]


def test_generate_config_override_punches_through_exact_deny(tmp_path: Path) -> None:
    """A t10 override at exactly a denied name suppresses its sinkhole.

    The override host is usually *also* t20-denied — without the
    punch-through it would NXDOMAIN before the statically seeded t10 set
    ever saw a packet — while staying out of the ``nftset=`` population
    (its addresses live in the t10 set, not t40).
    """
    config = generate_config(
        PASTA_DNS,
        [],
        tmp_path / "dnsmasq.pid",
        listen_address=DNSMASQ_BIND_DEFAULT,
        deny_domains=[TEST_DOMAIN],
        override_domains=[TEST_DOMAIN],
    )
    assert f"local=/{TEST_DOMAIN}/" not in config
    assert f"nftset=/{TEST_DOMAIN}/" not in config


def test_generate_config_override_subdomain_gets_punch_through(tmp_path: Path) -> None:
    """A t10 override below a denied ancestor gets a server=/sub/upstream punch-through."""
    sub = f"api.{TEST_DOMAIN}"
    config = generate_config(
        PASTA_DNS,
        [],
        tmp_path / "dnsmasq.pid",
        listen_address=DNSMASQ_BIND_DEFAULT,
        deny_domains=[TEST_DOMAIN],
        override_domains=[sub],
    )
    assert f"local=/{TEST_DOMAIN}/" in config
    assert f"server=/{sub}/{PASTA_DNS}" in config


def test_reload_writes_deny_sinkholes(tmp_path: Path) -> None:
    """reload() regenerates the config with the deny sinkholes included."""
    bundle = _launched(tmp_path)
    bundle.dnsmasq_conf.write_text(f"listen-address={DNSMASQ_BIND_DEFAULT}\n")

    _run_reload(tmp_path, PASTA_DNS, [TEST_DOMAIN], deny_domains=[TEST_DOMAIN2])

    conf = bundle.dnsmasq_conf.read_text()
    assert f"nftset=/{TEST_DOMAIN}/" in conf
    assert f"local=/{TEST_DOMAIN2}/" in conf
