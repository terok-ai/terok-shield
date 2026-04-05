# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Live blocked-access event stream for ``shield watch``.

Multiplexes three event sources into a single JSON-lines stream:

1. **DNS log** — tails the per-container dnsmasq query log and emits
   events for blocked domain lookups.
2. **Audit log** — tails ``audit.jsonl`` and surfaces shield lifecycle
   events (allow, deny, up, down, setup, teardown).
3. **NFLOG** — reads denied packets via ``AF_NETLINK`` and emits events
   for raw-IP connections that bypassed DNS.  Optional — graceful
   degradation when netlink is unavailable.
"""

from ._event import WatchEvent
from .audit_log import AuditLogWatcher
from .dns_log import DnsLogWatcher
from .domain_cache import DomainCache
from .nflog import NflogWatcher

__all__ = [
    "AuditLogWatcher",
    "DnsLogWatcher",
    "DomainCache",
    "NflogWatcher",
    "WatchEvent",
]
