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

# pasta --map-host-loopback address: container traffic to this link-local
# address is translated by pasta to 127.0.0.1 on the host.  Using a
# non-loopback address avoids the pasta 2.x "two loopbacks" splice bug
# where container→127.0.0.1 + pasta→127.0.0.1 causes Connection reset.
PASTA_HOST_LOOPBACK_MAP = "169.254.1.2"

# RFC 1918 private ranges + RFC 3927 link-local: rejected by default,
# access attempts and whitelisting logged with a notice.
RFC1918: tuple[str, ...] = (
    "10.0.0.0/8",  # RFC 1918
    "172.16.0.0/12",  # RFC 1918
    "192.168.0.0/16",  # RFC 1918
    "169.254.0.0/16",  # RFC 3927 (IPv4 link-local)
)

# RFC 4193 (ULA) + RFC 4291 (link-local): IPv6 equivalents of RFC 1918.
# Same treatment — rejected by default, logged when whitelisted.
IPV6_PRIVATE: tuple[str, ...] = (
    "fc00::/7",  # RFC 4193 (Unique Local Addresses)
    "fe80::/10",  # RFC 4291 (link-local)
)

# Combined private ranges (RFC 1918 + RFC 4193/4291) — single source of truth
# for rule generation and verification.
PRIVATE_RANGES: tuple[str, ...] = RFC1918 + IPV6_PRIVATE

# ── slirp4netns defaults ──────────────────────────────
SLIRP4NETNS_DNS = "10.0.2.3"  # slirp4netns default DNS forwarder

# ── dnsmasq defaults ─────────────────────────────────
DNSMASQ_BIND = "127.0.0.1"  # dnsmasq listen address inside container
NFT_SET_TIMEOUT_DNSMASQ = "30m"  # set element timeout when dnsmasq manages IPs

# ── NFLOG ──────────────────────────────────────────────
# nflog is a superset of log — it still writes to the kernel log AND makes
# packets available via AF_NETLINK for userspace consumers (shield watch).
NFLOG_GROUP = 100  # nflog group number for terok-shield rules

# ── Log prefixes ───────────────────────────────────────
DENIED_LOG_PREFIX = "TEROK_SHIELD_DENIED"
PRIVATE_LOG_PREFIX = "TEROK_SHIELD_PRIVATE"
ALLOWED_LOG_PREFIX = "TEROK_SHIELD_ALLOWED"
BYPASS_LOG_PREFIX = "TEROK_SHIELD_BYPASS"
