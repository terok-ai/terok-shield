# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Host binary prerequisite probes exported for higher-layer consumers."""

from __future__ import annotations

import pytest

from terok_shield.prereqs import (
    BinaryCheck,
    check_firewall_binaries,
    check_krun_binaries,
)

from ..testfs import DIG_BINARY, DNSMASQ_SBIN, IP_SBIN, NFT_BINARY, NFT_SBIN

# ── BinaryCheck ─────────────────────────────────────────────


def test_binary_check_ok_true_on_found_path() -> None:
    """``ok`` mirrors ``bool(path)`` — caller can treat the result as a truthy flag."""
    assert BinaryCheck("nft", NFT_BINARY, "x").ok is True


def test_binary_check_ok_false_on_empty_path() -> None:
    """Empty path → ``ok`` is False so aggregators can shortcut on presence."""
    assert BinaryCheck("nft", "", "x").ok is False


# ── check_firewall_binaries ────────────────────────────────


def test_check_firewall_binaries_shape() -> None:
    """All three expected binaries appear with the documented purposes."""
    results = check_firewall_binaries()
    names = [r.name for r in results]
    assert names == ["nft", "dnsmasq", "dig/drill"]
    purposes = {r.name: r.purpose for r in results}
    assert "nftables" in purposes["nft"]
    assert "DNS" in purposes["dnsmasq"]
    assert "DNS" in purposes["dig/drill"]


def test_check_firewall_binaries_reports_all_found(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every binary locatable via PATH or sbin → every check ``ok``."""
    expected = {"nft": NFT_SBIN, "dnsmasq": DNSMASQ_SBIN, "dig/drill": DIG_BINARY}

    monkeypatch.setattr(
        "terok_shield.prereqs.find_host_tool",
        lambda name: expected.get("dig/drill" if name == "dig" else name),
    )
    results = check_firewall_binaries()
    assert all(r.ok for r in results)
    assert {r.name: r.path for r in results} == expected


def test_check_firewall_binaries_reports_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing on PATH, nothing in sbin → every check reports an empty path."""
    monkeypatch.setattr("terok_shield.prereqs.find_host_tool", lambda _name: None)
    results = check_firewall_binaries()
    assert not any(r.ok for r in results)
    assert {r.path for r in results} == {""}


# ── check_krun_binaries ───────────────────────────────────


def test_check_krun_binaries_shape() -> None:
    """The krun probe covers exactly ``ip`` with a krun-specific purpose."""
    results = check_krun_binaries()
    assert [r.name for r in results] == ["ip"]
    assert "krun" in results[0].purpose


def test_check_krun_binaries_reports_ok_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    """``ip`` resolvable via ``/usr/sbin`` → check is OK with that path."""

    monkeypatch.setattr("terok_shield.prereqs.find_host_tool", lambda name: IP_SBIN)
    [ip_check] = check_krun_binaries()
    assert ip_check.ok is True
    assert ip_check.path == IP_SBIN


def test_check_krun_binaries_reports_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """No ``ip`` anywhere on the host → ``ok`` is False, path is empty."""
    monkeypatch.setattr("terok_shield.prereqs.find_host_tool", lambda _name: None)
    [ip_check] = check_krun_binaries()
    assert ip_check.ok is False
    assert ip_check.path == ""
