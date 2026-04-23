# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Host binary prerequisite probes exported for higher-layer consumers."""

from __future__ import annotations

import shutil
from pathlib import Path
from unittest import mock

import pytest

from terok_shield.prereqs import (
    BinaryCheck,
    check_firewall_binaries,
    which_sbin_aware,
)

from ..testfs import DIG_BINARY, DNSMASQ_SBIN, NFT_BINARY, NFT_SBIN

# ── which_sbin_aware ────────────────────────────────────────


def test_which_sbin_aware_uses_path_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """Found on PATH → that path is returned, sbin dirs are not consulted."""
    monkeypatch.setattr(shutil, "which", lambda _name: NFT_BINARY)
    assert which_sbin_aware("nft") == NFT_BINARY


def test_which_sbin_aware_falls_back_to_usr_sbin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing from PATH → ``/usr/sbin/<name>`` is reached before ``/sbin``."""
    monkeypatch.setattr(shutil, "which", lambda _name: None)

    def _is_file(self: Path) -> bool:
        return str(self) == NFT_SBIN

    with mock.patch.object(Path, "is_file", _is_file):
        assert which_sbin_aware("nft") == NFT_SBIN


def test_which_sbin_aware_empty_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """No PATH match and no sbin match → empty string, never ``None``."""
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with mock.patch.object(Path, "is_file", return_value=False):
        assert which_sbin_aware("dnsmasq") == ""


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
    assert names == ["nft", "dnsmasq", "dig"]
    purposes = {r.name: r.purpose for r in results}
    assert "nftables" in purposes["nft"]
    assert "DNS" in purposes["dnsmasq"]
    assert "DNS" in purposes["dig"]


def test_check_firewall_binaries_reports_all_found(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every binary locatable via PATH or sbin → every check ``ok``."""
    fakes = {"nft": NFT_SBIN, "dnsmasq": DNSMASQ_SBIN, "dig": DIG_BINARY}
    monkeypatch.setattr(shutil, "which", lambda n: fakes.get(n))
    results = check_firewall_binaries()
    assert all(r.ok for r in results)
    assert {r.name: r.path for r in results} == fakes


def test_check_firewall_binaries_reports_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing on PATH, nothing in sbin → every check reports an empty path."""
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with mock.patch.object(Path, "is_file", return_value=False):
        results = check_firewall_binaries()
    assert not any(r.ok for r in results)
    assert {r.path for r in results} == {""}
