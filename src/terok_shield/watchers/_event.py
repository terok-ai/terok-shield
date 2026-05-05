# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared event type emitted by all watchers."""

import json
from dataclasses import asdict, dataclass, field

from terok_shield._wire_sanitize import sanitize, sanitize_mapping


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
        """Serialise to a compact JSON line, omitting empty optional fields.

        Every string value passes through the producer-side
        ``WIRE_SPEC(safe-string)`` sanitiser — container-controlled
        bytes (DNS query name, dest IP, audit detail) reach this
        method straight from kernel logs / dnsmasq output, so the
        boundary lives here, not in any caller.
        """
        d = {}
        for k, v in asdict(self).items():
            if not v and k not in ("ts", "source", "action", "container"):
                continue
            if isinstance(v, str):
                d[k] = sanitize(v)
            elif isinstance(v, dict):
                d[k] = sanitize_mapping(v)
            else:
                d[k] = v
        return json.dumps(d, separators=(",", ":"))
