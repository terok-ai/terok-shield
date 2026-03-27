# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the dnsmasq lifecycle module."""

from pathlib import Path
from unittest import mock

import pytest

from terok_shield import state
from terok_shield.dnsmasq import (
    _validate_domain,
    add_domain,
    generate_config,
    kill,
    launch,
    nftset_entry,
    reload,
    remove_domain,
    write_resolv_conf,
)
from terok_shield.nft_constants import DNSMASQ_BIND, NFT_TABLE_NAME, PASTA_DNS

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
        f"nftset=/github.com/4#inet#{NFT_TABLE_NAME}#allow_v4,6#inet#{NFT_TABLE_NAME}#allow_v6"
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
    pid_path = state.dnsmasq_pid_path(tmp_path)
    config = generate_config(PASTA_DNS, [TEST_DOMAIN, TEST_DOMAIN2], pid_path)

    assert f"server={PASTA_DNS}" in config
    assert f"listen-address={DNSMASQ_BIND}" in config
    assert "port=53" in config
    assert "bind-interfaces" in config
    assert "no-resolv" in config
    assert f"pid-file={pid_path}" in config
    assert f"nftset=/{TEST_DOMAIN}/" in config
    assert f"nftset=/{TEST_DOMAIN2}/" in config


def test_generate_config_skips_invalid_domains(tmp_path: Path) -> None:
    """Invalid domains are silently skipped."""
    pid_path = state.dnsmasq_pid_path(tmp_path)
    config = generate_config(PASTA_DNS, [TEST_DOMAIN, "; rm -rf /", TEST_DOMAIN2], pid_path)

    assert f"nftset=/{TEST_DOMAIN}/" in config
    assert f"nftset=/{TEST_DOMAIN2}/" in config
    assert "rm -rf" not in config


def test_generate_config_empty_domains(tmp_path: Path) -> None:
    """Empty domain list produces config without nftset lines."""
    pid_path = state.dnsmasq_pid_path(tmp_path)
    config = generate_config(PASTA_DNS, [], pid_path)

    assert "nftset" not in config
    assert f"server={PASTA_DNS}" in config


# ── launch ───────────────────────────────────────────────


def test_launch_writes_config_and_runs_nsenter(tmp_path: Path) -> None:
    """launch() writes config file and calls runner with nsenter command."""
    state.ensure_state_dirs(tmp_path)
    runner = mock.MagicMock()
    runner.run.return_value = ""

    # Pre-create PID file to simulate dnsmasq writing it
    state.dnsmasq_pid_path(tmp_path).write_text("12345\n")

    launch(runner, "42", tmp_path, PASTA_DNS, [TEST_DOMAIN])

    # Config was written
    conf = state.dnsmasq_conf_path(tmp_path)
    assert conf.is_file()
    assert TEST_DOMAIN in conf.read_text()

    # nsenter command was called
    runner.run.assert_called_once()
    cmd = runner.run.call_args[0][0]
    assert cmd[0] == "nsenter"
    assert "-t" in cmd
    assert "42" in cmd
    assert "-n" in cmd
    assert "dnsmasq" in cmd


def test_launch_raises_when_pid_file_missing(tmp_path: Path) -> None:
    """launch() raises RuntimeError if dnsmasq doesn't write PID file."""
    state.ensure_state_dirs(tmp_path)
    runner = mock.MagicMock()
    runner.run.return_value = ""

    with pytest.raises(RuntimeError, match="PID file not written"):
        launch(runner, "42", tmp_path, PASTA_DNS, [])


# ── kill ─────────────────────────────────────────────────


def test_kill_sends_sigterm(tmp_path: Path) -> None:
    """kill() reads PID file, verifies identity, and sends SIGTERM."""
    state.dnsmasq_pid_path(tmp_path).write_text("12345\n")

    with (
        mock.patch("terok_shield.dnsmasq._is_dnsmasq_pid", return_value=True),
        mock.patch("terok_shield.dnsmasq.os.kill") as mock_kill,
    ):
        kill(tmp_path)

    import signal

    mock_kill.assert_called_once_with(12345, signal.SIGTERM)


def test_kill_silently_ignores_missing_pid_file(tmp_path: Path) -> None:
    """kill() does nothing if PID file is absent."""
    kill(tmp_path)  # should not raise


def test_kill_silently_ignores_stale_pid(tmp_path: Path) -> None:
    """kill() silently handles ProcessLookupError (already dead)."""
    state.dnsmasq_pid_path(tmp_path).write_text("99999\n")

    with (
        mock.patch("terok_shield.dnsmasq._is_dnsmasq_pid", return_value=True),
        mock.patch("terok_shield.dnsmasq.os.kill", side_effect=ProcessLookupError),
    ):
        kill(tmp_path)  # should not raise


def test_kill_clears_stale_pid_file(tmp_path: Path) -> None:
    """kill() clears PID file when PID is not a dnsmasq process."""
    state.dnsmasq_pid_path(tmp_path).write_text("12345\n")

    with mock.patch("terok_shield.dnsmasq._is_dnsmasq_pid", return_value=False):
        kill(tmp_path)

    assert not state.dnsmasq_pid_path(tmp_path).is_file()


def test_kill_silently_ignores_invalid_pid_content(tmp_path: Path) -> None:
    """kill() silently handles non-numeric PID content."""
    state.dnsmasq_pid_path(tmp_path).write_text("not-a-number\n")
    kill(tmp_path)  # should not raise


# ── write_resolv_conf ────────────────────────────────────


# ── add_domain / remove_domain ────────────────────────────


def test_add_domain_appends(tmp_path: Path) -> None:
    """add_domain() appends a new domain to profile.domains."""
    state.ensure_state_dirs(tmp_path)
    assert add_domain(tmp_path, TEST_DOMAIN) is True
    assert TEST_DOMAIN in state.profile_domains_path(tmp_path).read_text()


def test_add_domain_deduplicates(tmp_path: Path) -> None:
    """add_domain() returns False for an already-present domain."""
    state.ensure_state_dirs(tmp_path)
    add_domain(tmp_path, TEST_DOMAIN)
    assert add_domain(tmp_path, TEST_DOMAIN) is False


def test_remove_domain(tmp_path: Path) -> None:
    """remove_domain() removes a domain from profile.domains."""
    state.ensure_state_dirs(tmp_path)
    add_domain(tmp_path, TEST_DOMAIN)
    add_domain(tmp_path, TEST_DOMAIN2)
    assert remove_domain(tmp_path, TEST_DOMAIN) is True
    content = state.profile_domains_path(tmp_path).read_text()
    assert TEST_DOMAIN not in content
    assert TEST_DOMAIN2 in content


def test_remove_domain_not_found(tmp_path: Path) -> None:
    """remove_domain() returns False when domain is not present."""
    state.ensure_state_dirs(tmp_path)
    assert remove_domain(tmp_path, TEST_DOMAIN) is False


# ── reload ───────────────────────────────────────────────


def test_reload_regenerates_config_and_sends_sighup(tmp_path: Path) -> None:
    """reload() regenerates config and sends SIGHUP to dnsmasq."""
    state.ensure_state_dirs(tmp_path)
    state.dnsmasq_pid_path(tmp_path).write_text("12345\n")

    with (
        mock.patch("terok_shield.dnsmasq._is_dnsmasq_pid", return_value=True),
        mock.patch("terok_shield.dnsmasq.os.kill") as mock_kill,
    ):
        reload(tmp_path, PASTA_DNS, [TEST_DOMAIN])

    # Config was regenerated
    assert TEST_DOMAIN in state.dnsmasq_conf_path(tmp_path).read_text()
    # SIGHUP sent (not SIGTERM)
    import signal

    mock_kill.assert_called_once_with(12345, signal.SIGHUP)


def test_reload_noop_when_not_running(tmp_path: Path) -> None:
    """reload() is a no-op when dnsmasq PID file is absent."""
    state.ensure_state_dirs(tmp_path)
    with mock.patch("terok_shield.dnsmasq.os.kill") as mock_kill:
        reload(tmp_path, PASTA_DNS, [TEST_DOMAIN])
    mock_kill.assert_not_called()


# ── write_resolv_conf ────────────────────────────────────


def test_write_resolv_conf(tmp_path: Path) -> None:
    """write_resolv_conf() overwrites the resolv.conf file."""
    # Simulate /proc/{pid}/root/etc/resolv.conf via monkeypatch
    resolv_path = tmp_path / "resolv.conf"
    resolv_path.write_text("nameserver 169.254.1.1\n")

    with mock.patch("terok_shield.dnsmasq.Path", return_value=resolv_path):
        write_resolv_conf("42")

    assert resolv_path.read_text() == f"nameserver {DNSMASQ_BIND}\n"
