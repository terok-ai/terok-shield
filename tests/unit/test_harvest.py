# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Reading a task's audit log back as promotion candidates.

Harvest collects nothing new — it folds the lines the NFLOG reader already
wrote into one entry per target, which is the unit a promotion decision is
made in.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from terok_shield.harvest import HarvestEntry, harvest

from ..testnet import TEST_DOMAIN, TEST_DOMAIN2, TEST_IP1, TEST_IP2

CONTAINER = "test-ctr"


def _write_log(state_dir: Path, *records: dict) -> None:
    """Write *records* as the container's audit log, one JSON object per line."""
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "audit.jsonl").write_text("".join(json.dumps(record) + "\n" for record in records))


def _blocked(ts: str, dest: str = TEST_IP1, *, domain: str = "", port: int = 443) -> dict:
    """One refusal, the shape the reader appends."""
    record = {
        "ts": ts,
        "container": CONTAINER,
        "action": "blocked",
        "dest": dest,
        "port": port,
        "proto": "tcp",
    }
    if domain:
        record["domain"] = domain
    return record


def test_no_log_harvests_nothing(tmp_path: Path) -> None:
    """A task that never tried anything and one whose log is gone read the same."""
    assert harvest(tmp_path) == []


def test_refusals_group_by_target(tmp_path: Path) -> None:
    """Repeated refusals to one host are one entry with a count, not three rows."""
    _write_log(
        tmp_path,
        _blocked("2026-09-30T10:00:00+00:00", domain=TEST_DOMAIN),
        _blocked("2026-09-30T10:00:31+00:00", domain=TEST_DOMAIN),
        _blocked("2026-09-30T10:01:02+00:00", domain=TEST_DOMAIN),
    )

    (entry,) = harvest(tmp_path)

    assert entry == HarvestEntry(
        action="blocked",
        target=TEST_DOMAIN,
        count=3,
        first_seen="2026-09-30T10:00:00+00:00",
        last_seen="2026-09-30T10:01:02+00:00",
        ports=(443,),
        addresses=(TEST_IP1,),
    )


def test_the_domain_is_the_target_when_the_reader_recovered_one(tmp_path: Path) -> None:
    """An allowlist entry for a rotating CDN is worth nothing as an IP."""
    _write_log(
        tmp_path,
        _blocked("2026-09-30T10:00:00+00:00", dest=TEST_IP1, domain=TEST_DOMAIN),
        _blocked("2026-09-30T10:05:00+00:00", dest=TEST_IP2, domain=TEST_DOMAIN),
    )

    (entry,) = harvest(tmp_path)

    assert entry.target == TEST_DOMAIN
    assert entry.addresses == (TEST_IP1, TEST_IP2)


def test_an_address_stands_in_when_no_domain_was_recovered(tmp_path: Path) -> None:
    """Without a domain the address is all there is to promote."""
    _write_log(tmp_path, _blocked("2026-09-30T10:00:00+00:00", dest=TEST_IP1))

    (entry,) = harvest(tmp_path)

    assert entry.target == TEST_IP1
    assert entry.addresses == ()


def test_window_accepts_are_harvested_too(tmp_path: Path) -> None:
    """What the bypass window let through is exactly what the task turned out to need."""
    _write_log(
        tmp_path,
        {
            "ts": "2026-09-30T10:00:00+00:00",
            "container": CONTAINER,
            "action": "bypass",
            "dest": TEST_IP2,
            "port": 80,
            "proto": "tcp",
            "domain": TEST_DOMAIN2,
        },
    )

    (entry,) = harvest(tmp_path)

    assert (entry.action, entry.target, entry.ports) == ("bypass", TEST_DOMAIN2, (80,))


def test_refusals_come_first_then_the_loudest(tmp_path: Path) -> None:
    """Ordering puts the entry an operator is most likely to act on at the top."""
    _write_log(
        tmp_path,
        {
            "ts": "2026-09-30T10:00:00+00:00",
            "container": CONTAINER,
            "action": "bypass",
            "dest": TEST_IP2,
            "port": 80,
            "proto": "tcp",
        },
        _blocked("2026-09-30T10:00:00+00:00", domain=TEST_DOMAIN),
        _blocked("2026-09-30T10:01:00+00:00", domain=TEST_DOMAIN),
        _blocked("2026-09-30T10:02:00+00:00", dest=TEST_IP1),
    )

    entries = harvest(tmp_path)

    assert [(e.action, e.target) for e in entries] == [
        ("blocked", TEST_DOMAIN),
        ("blocked", TEST_IP1),
        ("bypass", TEST_IP2),
    ]


@pytest.mark.parametrize(
    "action",
    ["setup", "allowed", "denied", "shield_down", "bypass_armed", "note", "error"],
)
def test_the_operators_own_entries_are_not_candidates(tmp_path: Path, action: str) -> None:
    """Posture changes and verdicts say nothing about what the task reached for."""
    _write_log(
        tmp_path,
        {"ts": "2026-09-30T10:00:00+00:00", "container": CONTAINER, "action": action},
    )

    assert harvest(tmp_path) == []


def test_a_truncated_line_does_not_stop_the_read(tmp_path: Path) -> None:
    """Two writers append to this log; a half-written final line is ordinary."""
    state_dir = tmp_path
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "audit.jsonl").write_text(
        json.dumps(_blocked("2026-09-30T10:00:00+00:00", domain=TEST_DOMAIN)) + '\n{"ts": "2026'
    )

    (entry,) = harvest(state_dir)

    assert entry.target == TEST_DOMAIN


def test_a_record_without_a_target_is_skipped(tmp_path: Path) -> None:
    """Nothing to promote, nothing to show."""
    _write_log(
        tmp_path,
        {"ts": "2026-09-30T10:00:00+00:00", "container": CONTAINER, "action": "blocked"},
    )

    assert harvest(tmp_path) == []
