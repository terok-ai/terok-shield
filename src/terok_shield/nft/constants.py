# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""nftables table names, network defaults, and log prefixes.

Pure literals with no logic — safe for import by the nft.py security boundary.
"""

NFT_TABLE = "inet terok_shield"
NFT_TABLE_NAME = "terok_shield"

# ── Tier set base names ────────────────────────────────
# One named set per tier per family (``<base>_v4`` / ``<base>_v6``).  Each base
# mirrors its ``policy/<NN>-<name>`` bundle file 1:1 so the file→rule mapping is
# self-evident.  Tier 00 (hard-deny) is static CIDR ranges, not a set.
TIER_OVERRIDE = "t10_override"  # tier 10 — break-glass allow, above the deny
TIER_SECURITY_DENY = "t20_security_deny"  # tier 20 — vault hosts + operator deny
TIER_PROVIDER_ALLOW = "t30_provider_allow"  # tier 30 — agent/provider egress (executor)
TIER_PROJECT_ALLOW = "t40_project_allow"  # tier 40 — common sets + git remote + custom
SET_BYPASS_WINDOW = "bypass_window"  # timed allow-all (kernel-timeout elements)

# ── Network defaults ────────────────────────────────────
# Used as parameter defaults in nft.py and re-exported by config.py.

PASTA_DNS = "169.254.1.1"  # pasta default DNS forwarder (link-local)

# pasta --map-host-loopback address: container traffic to this link-local
# address is translated by pasta to 127.0.0.1 on the host.  Using a
# non-loopback address avoids the pasta 2.x "two loopbacks" splice bug
# where container→127.0.0.1 + pasta→127.0.0.1 causes Connection reset.
PASTA_HOST_LOOPBACK_MAP = "169.254.1.2"

# ── Tier denial floors (two distinct, differently-overridable classes) ──
#
# HARD_DENY_RANGES — link-local, including the cloud-metadata IMDS
# (169.254.169.254).  Rejected ABOVE the override tier, so it is absolute:
# not even an explicit operator override can reach it (SSRF/metadata floor).
HARD_DENY_RANGES: tuple[str, ...] = (
    "169.254.0.0/16",  # RFC 3927 IPv4 link-local — includes cloud-metadata IMDS  # NOSONAR
    "fe80::/10",  # RFC 4291 IPv6 link-local
    # AWS IMDS IPv6 endpoint.  Pinned here even though it falls inside ULA
    # fc00::/7: the ULA reject lives in PRIVATE_RANGES, *below* the override
    # tier, so without this entry an operator override carving out ULA space
    # could reach the v6 metadata service — the absolute-IMDS guarantee
    # would be v4-only.  Bare address (no /128): nft strips a /128 prefix
    # when listing, so the verifier's literal round-trip needs the bare form.
    "fd00:ec2::254",  # AWS IMDS IPv6 endpoint  # NOSONAR
)

# PRIVATE_RANGES — RFC 1918 + RFC 4193 (ULA): the private LAN.  Denied by
# default (anti-lateral-movement) but BELOW the override tier, so a specific
# internal host:port can be deliberately carved out via an operator override
# while the rest of the LAN stays blocked.
PRIVATE_RANGES: tuple[str, ...] = (
    "10.0.0.0/8",  # RFC 1918
    "172.16.0.0/12",  # RFC 1918
    "192.168.0.0/16",  # RFC 1918
    "fc00::/7",  # RFC 4193 IPv6 ULA
)

# ── slirp4netns defaults ──────────────────────────────
# Gateway and DNS are deterministic offsets from the CIDR base address.
# Only the --cidr flag can change them; the +2/+3 offsets are compile-time
# constants in slirp4netns (DEFAULT_VHOST_OFFSET / DEFAULT_VNAMESERVER_OFFSET).
# IPv6 is hardcoded at fd00::/64 with no override flag.
SLIRP4NETNS_CIDR = "10.0.2.0/24"
SLIRP4NETNS_GATEWAY = "10.0.2.2"  # CIDR base + 2
SLIRP4NETNS_GATEWAY_V6 = "fd00::2"  # fd00:: + 2 (no --cidr6 exists)
SLIRP4NETNS_DNS = "10.0.2.3"  # CIDR base + 3

# ── dnsmasq defaults ─────────────────────────────────
# Link-local slots shield owns are kept disjoint:
#     169.254.1.1 → pasta's built-in DNS forwarder (PASTA_DNS above)
#     169.254.1.2 → pasta --map-host-loopback (PASTA_HOST_LOOPBACK_MAP)
#     169.254.1.3 → dnsmasq under krun (DNSMASQ_BIND_KRUN)
DNSMASQ_BIND_DEFAULT = "127.0.0.1"
DNSMASQ_BIND_KRUN = "169.254.1.3"
NFT_SET_TIMEOUT_DNSMASQ = "30m"  # set element timeout when dnsmasq manages IPs

# ── NFLOG ──────────────────────────────────────────────
# nflog is a superset of log — it still writes to the kernel log AND makes
# packets available via AF_NETLINK for userspace consumers (shield watch).
NFLOG_GROUP = 100  # nflog group number for terok-shield rules

# ── Log prefixes ───────────────────────────────────────
BLOCKED_LOG_PREFIX = "TEROK_SHIELD_BLOCKED"  # terminal default-deny (unclassified)
DENIED_LOG_PREFIX = "TEROK_SHIELD_DENIED"  # explicit deny set (operator refused)
PRIVATE_LOG_PREFIX = "TEROK_SHIELD_PRIVATE"
ALLOWED_LOG_PREFIX = "TEROK_SHIELD_ALLOWED"
BYPASS_LOG_PREFIX = "TEROK_SHIELD_BYPASS"  # accepted through the timed bypass window
DOWN_LOG_PREFIX = "TEROK_SHIELD_DOWN"  # new connection accepted while the shield is down
