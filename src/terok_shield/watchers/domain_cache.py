# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""IP-to-domain reverse lookup from the dnsmasq query log.

Parses ``reply`` / ``cached`` lines to build a mapping from resolved
IPs to their domain names.  Used by ``shield watch`` and the
interactive session for NFLOG event enrichment.
"""

import re
from pathlib import Path

from .. import state

# Matches dnsmasq reply/cached lines like:
#   reply github.com is 140.82.121.4
_REPLY_RE = re.compile(r"(?:reply|cached)\s+(\S+)\s+is\s+(\S+)")


class DomainCache:
    """IP-to-domain reverse lookup cache."""

    def __init__(self, state_dir: Path) -> None:
        """Initialise with the dnsmasq log path derived from *state_dir*."""
        self._log_path = state.dnsmasq_log_path(state_dir)
        self._mapping: dict[str, str] = {}

    def lookup(self, ip: str) -> str:
        """Return the cached domain for *ip*, or empty string if unknown."""
        return self._mapping.get(ip, "")

    def refresh(self) -> None:
        """Reload the IP-to-domain mapping from the dnsmasq query log.

        On ``OSError`` the previous cache is preserved.
        """
        try:
            text = self._log_path.read_text()
        except OSError:
            return
        mapping: dict[str, str] = {}
        for m in _REPLY_RE.finditer(text):
            domain, ip = m.group(1), m.group(2)
            mapping[ip] = domain.lower().rstrip(".")
        self._mapping = mapping
