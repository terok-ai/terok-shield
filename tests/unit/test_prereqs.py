# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Host binary prerequisite probes exported for higher-layer consumers."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from terok_shield.prereqs import (
    BinaryCheck,
    check_firewall_binaries,
    which_sbin_aware,
)

from ..testfs import DIG_BINARY, DNSMASQ_SBIN, NFT_BINARY, NFT_SBIN


def _fake_which(matches: dict[str | None, str]) -> object:
    """Return a ``shutil.which`` stand-in keyed by the ``path`` kwarg.

    Lets tests express "binary lives only on ``/sbin``" without mocking
    filesystem state — the SUT now asks ``shutil.which`` for each
    directory, so keying the fake by search path is the natural model.
    """

    def _which(_name: str, path: str | None = None) -> str | None:
        return matches.get(path)

    return _which


# ── which_sbin_aware ────────────────────────────────────────


def test_which_sbin_aware_uses_path_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """Found on PATH → that path is returned, sbin dirs are not consulted."""
    monkeypatch.setattr(shutil, "which", _fake_which({None: NFT_BINARY}))
    assert which_sbin_aware("nft") == NFT_BINARY


def test_which_sbin_aware_falls_back_to_usr_sbin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing from PATH → ``/usr/sbin/<name>`` is reached before ``/sbin``."""
    monkeypatch.setattr(shutil, "which", _fake_which({"/usr/sbin": NFT_SBIN}))
    assert which_sbin_aware("nft") == NFT_SBIN


def test_which_sbin_aware_falls_back_to_sbin(monkeypatch: pytest.MonkeyPatch) -> None:
    """``/sbin`` still reached when ``/usr/sbin`` doesn't have the binary.

    Covers the second sbin directory in ``_SBIN_DIRS`` — some distros
    install daemon binaries there rather than in ``/usr/sbin``.
    """
    monkeypatch.setattr(shutil, "which", _fake_which({"/sbin": "/sbin/nft"}))
    assert which_sbin_aware("nft") == "/sbin/nft"


def test_which_sbin_aware_empty_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """No PATH match and no sbin match → empty string, never ``None``."""
    monkeypatch.setattr(shutil, "which", _fake_which({}))
    assert which_sbin_aware("dnsmasq") == ""


def test_which_sbin_aware_skips_non_executable_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-executable regular file in sbin doesn't count as a hit.

    Exercises the executability check that real :func:`shutil.which`
    performs (``os.X_OK``) — the reason we migrated from
    :meth:`Path.is_file` to ``shutil.which(name, path=dir)``.  A host
    with a mode-0o644 ``/usr/sbin/nft`` (rpm gone wrong, chmod
    accident) must probe as missing, not as present-but-broken.
    """
    monkeypatch.setattr("terok_shield.prereqs._SBIN_DIRS", (str(tmp_path),))
    # Isolated empty PATH so the real ``shutil.which`` can't find ``nft``
    # on the host — otherwise the assertion depends on /usr/bin being
    # clean, which CI runners often aren't.
    monkeypatch.setenv("PATH", str(tmp_path))
    plain = tmp_path / "nft"
    plain.write_text("#!/bin/sh\n")
    plain.chmod(0o644)
    assert which_sbin_aware("nft") == ""
    plain.chmod(0o755)
    assert which_sbin_aware("nft") == str(plain)


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
    expected = {"nft": NFT_SBIN, "dnsmasq": DNSMASQ_SBIN, "dig": DIG_BINARY}

    def _which(name: str, path: str | None = None) -> str | None:
        # ``dig`` lives on PATH; ``nft`` / ``dnsmasq`` only in sbin —
        # matches the fixture shape a real Fedora host tends to have.
        if name == "dig" and path is None:
            return DIG_BINARY
        if name in ("nft", "dnsmasq") and path == "/usr/sbin":
            return expected[name]
        return None

    monkeypatch.setattr(shutil, "which", _which)
    results = check_firewall_binaries()
    assert all(r.ok for r in results)
    assert {r.name: r.path for r in results} == expected


def test_check_firewall_binaries_reports_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing on PATH, nothing in sbin → every check reports an empty path."""
    monkeypatch.setattr(shutil, "which", _fake_which({}))
    results = check_firewall_binaries()
    assert not any(r.ok for r in results)
    assert {r.path for r in results} == {""}
