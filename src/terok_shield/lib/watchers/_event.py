# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared event type emitted by all watchers."""

import json
from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class WatchEvent:
    """A single watch event emitted to the output stream.

    Core fields (always present): ``ts``, ``source``, ``action``, ``container``.
    DNS-specific: ``domain``, ``query_type``.
    Audit/NFLOG: ``dest``, ``detail``, ``port``, ``proto``.
    """

    ts: str
    source: str
    action: str
    container: str
    domain: str = ""
    query_type: str = ""
    dest: str = ""
    detail: str = ""
    port: int = 0
    proto: int = 0
    extra: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialize to a compact JSON line, omitting empty optional fields."""
        d = {
            k: v
            for k, v in asdict(self).items()
            if v or k in ("ts", "source", "action", "container")
        }
        return json.dumps(d, separators=(",", ":"))
