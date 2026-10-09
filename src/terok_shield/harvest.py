# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""What a task reached for, read back out of its audit log.

A deny-by-default box is only workable if the operator can find out what the
policy refused and decide whether it should have.  That record already exists:
the NFLOG reader writes one line per refusal, and one per accept through the
timed allow-all window, into the container's ``audit.jsonl``.  Harvest is a
*reader* over that file, not a second mechanism — nothing new is collected, and
nothing here writes policy.

Grouping is by target, the way a promotion decision is made: a domain when the
reader recovered one from the DNS cache, the address otherwise.  Counts come
from the log, and the reader records at most one line per target per 30 s, so a
count is a floor on how often the workload tried, never a connection count.
"""

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .state import StateBundle

#: Audit actions the workload's own traffic produces.  Everything else in the
#: log is the operator's or the shield's own doing — setup steps, posture
#: changes, runtime allow/deny verdicts — and says nothing about what the task
#: needed.
HARVESTED_ACTIONS = ("blocked", "bypass")


@dataclass(frozen=True, slots=True)
class HarvestEntry:
    """One destination a task reached for, and what the shield did about it."""

    action: str
    """``blocked`` — refused by the policy — or ``bypass`` — let through by the
    timed allow-all window."""
    target: str
    """The domain the reader recovered, or the address when it had none.

    This is what a promotion would name, which is why it is the grouping key:
    an allowlist entry for a rotating CDN is worth nothing as an IP.
    """
    count: int
    """Audit lines seen for this target.

    A floor on attempts, not a connection count: the reader records one line
    per target per 30 s, so a tight retry loop and a single request can both
    land as one.
    """
    first_seen: str
    last_seen: str
    ports: tuple[int, ...]
    """Destination ports, ascending — a promotion candidate on 443 and one on
    25 deserve different scrutiny."""
    addresses: tuple[str, ...]
    """Addresses seen behind *target*, in first-seen order; empty when the
    target is itself an address."""


@dataclass
class _Tally:
    """Mutable accumulator for one ``(action, target)`` pair."""

    count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    ports: set[int] = field(default_factory=set)
    addresses: dict[str, None] = field(default_factory=dict)

    def add(self, record: dict) -> None:
        """Fold one audit record into the tally, keeping first/last seen honest."""
        timestamp = str(record.get("ts", ""))
        self.count += 1
        self.first_seen = min(self.first_seen, timestamp) if self.first_seen else timestamp
        self.last_seen = max(self.last_seen, timestamp)
        port = record.get("port")
        if isinstance(port, int):
            self.ports.add(port)
        dest = record.get("dest")
        if record.get("domain") and isinstance(dest, str):
            self.addresses[dest] = None


def harvest(state_dir: Path) -> list[HarvestEntry]:
    """Summarise what the container in *state_dir* reached for.

    Refusals first, then window accepts, each ordered by how often the target
    appeared and then by name, so the entry an operator is most likely to act
    on is the one at the top.  A missing or unreadable audit log yields no
    entries: a task that never tried anything and a task whose log is gone read
    the same from here, and neither is an error worth raising at a reader.
    """
    return _summarise(_records(StateBundle(state_dir).audit))


def _records(path: Path) -> Iterator[dict]:
    """Yield the harvestable records of an audit log, skipping what it cannot parse.

    The log is appended by two writers — the host-side shield and the in-netns
    NFLOG reader — so a truncated final line is an ordinary sight after a kill,
    not corruption to report.
    """
    try:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if isinstance(record, dict) and record.get("action") in HARVESTED_ACTIONS:
                    yield record
    except OSError:
        return


def _summarise(records: Iterable[dict]) -> list[HarvestEntry]:
    """Fold records into one entry per ``(action, target)``, ordered for review."""
    tallies: dict[tuple[str, str], _Tally] = {}
    for record in records:
        target = record.get("domain") or record.get("dest")
        if not isinstance(target, str) or not target:
            continue
        tallies.setdefault((str(record["action"]), target), _Tally()).add(record)

    entries = [
        HarvestEntry(
            action=action,
            target=target,
            count=tally.count,
            first_seen=tally.first_seen,
            last_seen=tally.last_seen,
            ports=tuple(sorted(tally.ports)),
            addresses=tuple(tally.addresses),
        )
        for (action, target), tally in tallies.items()
    ]
    order = {action: rank for rank, action in enumerate(HARVESTED_ACTIONS)}
    entries.sort(key=lambda e: (order.get(e.action, len(order)), -e.count, e.target))
    return entries
