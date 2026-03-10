# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared nftables constants — single source of truth.

This module contains only literals (no logic, no non-stdlib imports)
so it can be safely imported by the nft.py security boundary.
"""

NFT_TABLE = "inet terok_shield"
NFT_TABLE_NAME = "terok_shield"

# ── Network defaults ────────────────────────────────────
# Used as parameter defaults in nft.py and re-exported by config.py.

PASTA_DNS = "169.254.1.1"  # pasta default DNS forwarder (link-local)

# RFC1918 + link-local ranges: rejected by default, access attempts
# and whitelisting logged with a notice.
RFC1918: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
)

# ── Log prefixes ───────────────────────────────────────
BYPASS_LOG_PREFIX = "TEROK_SHIELD_BYPASS"
