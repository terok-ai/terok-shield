# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for terok_shield.dns.apparmor and the tier fallback it feeds."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

from terok_shield.config import DnsTier, detect_dns_tier
from terok_shield.dns.apparmor import (
    detect_dns_tier_under_apparmor,
    dnsmasq_can_read_state_dir,
)
from terok_shield.run import ExecError

_NFTSET_VERSION = "Dnsmasq version 2.92\nCompile time options: nftset DNSSEC\n"
_NO_NFTSET_VERSION = "Dnsmasq version 2.92\nCompile time options: no-nftset DNSSEC\n"


def _fake_runner(*, present=("dnsmasq", "dig"), nftset=True, readable=True):
    """A MagicMock runner whose ``--version``/``--test`` answers are scriptable."""
    runner = mock.MagicMock()
    runner.has.side_effect = lambda name: name in present

    def _run(cmd: list[str], **_kw: object) -> str:
        if "--version" in cmd:
            return _NFTSET_VERSION if nftset else _NO_NFTSET_VERSION
        if "--test" in cmd:
            if readable:
                return "dnsmasq: syntax check OK.\n"
            raise ExecError(cmd, 3, "dnsmasq: cannot read config: Permission denied\n")
        return ""

    runner.run.side_effect = _run
    return runner


def _probed_apparmor(runner: mock.MagicMock) -> bool:
    """True if the runner was asked to run the ``dnsmasq --test`` probe."""
    return any("--test" in call.args[0] for call in runner.run.call_args_list)


# ── detect_dns_tier: the new state-readable gate ─────────


def test_tier_is_dnsmasq_when_present_capable_and_readable() -> None:
    """dnsmasq wins when it exists, supports nftset, and can read its config."""
    tier = detect_dns_tier(lambda _n: True, lambda: True, lambda: True)
    assert tier is DnsTier.DNSMASQ


def test_tier_falls_back_to_dig_when_confined() -> None:
    """dnsmasq present + nftset-capable but AppArmor-confined → dig."""
    has = lambda n: n in {"dnsmasq", "dig"}  # noqa: E731
    tier = detect_dns_tier(has, lambda: True, lambda: False)
    assert tier is DnsTier.DIG


def test_tier_falls_back_to_getent_when_confined_and_no_dig() -> None:
    """Confined dnsmasq with no dig present drops all the way to getent."""
    tier = detect_dns_tier(lambda n: n == "dnsmasq", lambda: True, lambda: False)
    assert tier is DnsTier.GETENT


# ── dnsmasq_can_read_state_dir: behavioural probe ────────


def test_can_read_true_when_test_succeeds(tmp_path: Path) -> None:
    """A clean ``dnsmasq --test`` means the state dir is readable; probe is cleaned up."""
    runner = mock.MagicMock()
    runner.run.return_value = "dnsmasq: syntax check OK.\n"
    assert dnsmasq_can_read_state_dir(runner, tmp_path) is True
    assert list(tmp_path.iterdir()) == []


def test_can_read_false_on_permission_denied(tmp_path: Path) -> None:
    """A permission-denied stderr (AppArmor) downgrades the tier."""
    runner = mock.MagicMock()
    runner.run.side_effect = ExecError(
        ["dnsmasq", "--test"], 3, "dnsmasq: cannot read config: Permission denied\n"
    )
    assert dnsmasq_can_read_state_dir(runner, tmp_path) is False
    assert list(tmp_path.iterdir()) == []


def test_can_read_true_on_non_permission_error(tmp_path: Path) -> None:
    """A parse error (not a denial) must not trigger a spurious downgrade."""
    runner = mock.MagicMock()
    runner.run.side_effect = ExecError(
        ["dnsmasq", "--test"], 1, "dnsmasq: bad command line options\n"
    )
    assert dnsmasq_can_read_state_dir(runner, tmp_path) is True


def test_can_read_true_when_probe_unwritable(tmp_path: Path) -> None:
    """An unwritable state dir is not an AppArmor read problem — do not downgrade."""
    runner = mock.MagicMock()
    missing = tmp_path / "absent-parent" / "shield"  # parent missing → write fails
    assert dnsmasq_can_read_state_dir(runner, missing) is True
    runner.run.assert_not_called()


# ── detect_dns_tier_under_apparmor: wiring + apparmor_blocked flag ──


def test_helper_keeps_dnsmasq_when_usable(tmp_path: Path) -> None:
    """Present, nftset-capable, readable dnsmasq → dnsmasq tier, not blocked."""
    tier, apparmor_blocked = detect_dns_tier_under_apparmor(_fake_runner(), tmp_path)
    assert tier is DnsTier.DNSMASQ
    assert apparmor_blocked is False


def test_helper_downgrades_to_dig_when_confined(tmp_path: Path) -> None:
    """AppArmor-confined dnsmasq with dig present → dig tier, flagged, after probing."""
    runner = _fake_runner(readable=False)
    tier, apparmor_blocked = detect_dns_tier_under_apparmor(runner, tmp_path)
    assert tier is DnsTier.DIG
    assert apparmor_blocked is True
    assert _probed_apparmor(runner)


def test_helper_flags_block_even_when_falling_to_getent(tmp_path: Path) -> None:
    """Confined dnsmasq with no dig → getent, still flagged (not a dig-only signal)."""
    runner = _fake_runner(present=("dnsmasq",), readable=False)
    tier, apparmor_blocked = detect_dns_tier_under_apparmor(runner, tmp_path)
    assert tier is DnsTier.GETENT
    assert apparmor_blocked is True


def test_helper_skips_probe_when_nftset_unsupported(tmp_path: Path) -> None:
    """dnsmasq without nftset is disqualified first — the AppArmor probe never runs."""
    runner = _fake_runner(nftset=False)
    tier, apparmor_blocked = detect_dns_tier_under_apparmor(runner, tmp_path)
    assert tier is DnsTier.DIG
    assert apparmor_blocked is False
    assert not _probed_apparmor(runner)


def test_helper_absent_dnsmasq_is_not_blocked(tmp_path: Path) -> None:
    """No dnsmasq → dig, not flagged, and no probe runs."""
    runner = _fake_runner(present=("dig",))
    tier, apparmor_blocked = detect_dns_tier_under_apparmor(runner, tmp_path)
    assert tier is DnsTier.DIG
    assert apparmor_blocked is False
    assert not _probed_apparmor(runner)
