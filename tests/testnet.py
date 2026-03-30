# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared test constants: IP addresses, domains, and URLs.

RFC 5737 TEST-NET addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
are reserved for documentation and testing.  They are guaranteed non-routable —
no real host will ever have them, and packets will be dropped at the network edge.

Public DNS IPs (Cloudflare, Google, Quad9) are used in integration tests that
verify real network connectivity.  Centralizing them here means SonarCloud only
flags the constant definition, not every usage.
"""

# ── Container networking constants ──

CONTAINER_HOSTNAME = "host.containers.internal"
"""Hostname Podman exposes for reaching services on the host."""

# ── Test domains (used as mock compose_profiles return value) ──

TEST_DOMAIN = "github.com"
TEST_DOMAIN2 = "example.org"  # Secondary test domain for multi-domain tests
CUSTOM_DOMAIN = "custom.example.com"  # Fixture domain for user-override profile tests

# ── RFC 5737 TEST-NET addresses (non-routable, safe for unit tests) ──

# TEST-NET-1 (192.0.2.0/24)
TEST_IP1 = "192.0.2.1"
TEST_IP2 = "192.0.2.2"
TEST_IP99 = "192.0.2.99"

# TEST-NET-2 (198.51.100.0/24)
TEST_IP3 = "198.51.100.1"

# TEST-NET-3 (203.0.113.0/24)
TEST_IP4 = "203.0.113.1"

# CIDR form for tests that need network notation
TEST_NET1 = "192.0.2.0/24"
BROAD_CIDR_8 = "203.0.0.0/8"  # Broad CIDR (prefix <= 16) for classification tests

# ── RFC 1918 / link-local addresses (used to test blocking rules) ──

RFC1918_HOST = "10.0.0.1"  # Single host in 10.0.0.0/8
RFC1918_CIDR_10: str = "10.0.0.0/8"  # Broad RFC1918 CIDR (prefix <= 16)
RFC1918_CIDR_192: str = "192.168.1.0/24"  # Narrow RFC1918 CIDR (prefix > 16)
LINK_LOCAL_DNS = "169.254.0.1"  # Link-local DNS forwarder (pasta-style)

# ── slirp4netns default network (10.0.2.0/24) ──

SLIRP4NETNS_GATEWAY = "10.0.2.2"  # Default slirp4netns gateway
SLIRP4NETNS_DNS = "10.0.2.3"  # Default slirp4netns DNS forwarder

# --8<-- [start:outbound-targets]
# ── Allowed target: Cloudflare (anycast 1.1.1.1 + 1.0.0.1) ──
# Both IPs must be in the allow set because Cloudflare's anycast may respond
# from either address.  The domain resolves to both IPs.

ALLOWED_TARGET_IPS = ["1.1.1.1", "1.0.0.1"]  # Cloudflare anycast pair
ALLOWED_TARGET_DOMAIN = "one.one.one.one"  # Resolves to both IPs above
ALLOWED_TARGET_HTTP = "http://1.1.1.1/"  # Plain HTTP (port 80)
ALLOWED_TARGET_HTTPS = f"https://{ALLOWED_TARGET_DOMAIN}/"  # HTTPS (port 443)

# ── Blocked target: Google DNS (used as a non-allowed destination) ──

BLOCKED_TARGET_IP = "8.8.8.8"  # Google Public DNS
BLOCKED_TARGET_NET: str = "8.8.8.0/24"  # Public network CIDR (for classification tests)
BLOCKED_TARGET_HTTP = (
    f"http://{BLOCKED_TARGET_IP}/"  # No HTTP server on port 80; for assert_blocked only
)
BLOCKED_TARGET_DNS_PORT = 53  # DNS port (always open on BLOCKED_TARGET_IP)

# ── Connectivity check targets (non-allowed, respond on HTTP/HTTPS) ──
# Purpose-built endpoints for internet reachability testing during bypass.
# They resolve to IPs NOT in the default allow set.

CONNCHECK_HTTP = "http://connectivitycheck.gstatic.com/generate_204"  # Google, HTTP 204
CONNCHECK_HTTPS = "https://dns.google/"  # Google DNS-over-HTTPS (resolves to 8.8.8.8/8.8.4.4)

# ── Other public DNS resolvers (used in add-elements / multi-IP tests) ──

GOOGLE_DNS_IP = "8.8.8.8"  # Google Public DNS (same as BLOCKED_TARGET_IP)
QUAD9_DNS_IP = "9.9.9.9"  # Quad9 DNS

# ── Well-known domains (used for DNS resolution tests) ──

CLOUDFLARE_DOMAIN = "one.one.one.one"  # Cloudflare DNS (always resolves)
GOOGLE_DNS_DOMAIN = "dns.google"  # Google DNS (always resolves)
NONEXISTENT_DOMAIN = "this-domain-does-not-exist.invalid"  # RFC 2606 reserved
ALIAS_DOMAIN = "alias.example.com."  # CNAME-style answer for dig output filtering tests

# ── IPv6 targets (used to verify IPv6 allowlisting and blocking) ──

IPV6_LOOPBACK = "::1"  # IPv6 loopback address
IPV6_CLOUDFLARE = "2606:4700:4700::1111"  # Cloudflare DNS over IPv6
IPV6_NET1 = "2001:db8::/32"  # RFC 3849 documentation prefix (CIDR form)
IPV6_GOOGLE = "2001:4860:4860::8888"  # Google Public DNS over IPv6
IPV6_HTTP_URL = f"http://[{IPV6_CLOUDFLARE}]/"  # HTTP via IPv6 literal

# ── IPv6 private ranges (used for private-range classification tests) ──

IPV6_ULA = "fd00::1"  # Unique Local Address (RFC 4193, fc00::/7)
IPV6_ULA_CIDR = "fc00::/7"  # Unique Local Address CIDR (RFC 4193)
IPV6_LINK_LOCAL = "fe80::1"  # Link-local address (RFC 4291, fe80::/10)

# ── Expected private ranges (test-owned, independent from implementation) ──
# These duplicate the implementation constants intentionally so tests catch
# accidental removal of a range from the production code.
EXPECTED_PRIVATE_RANGES: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
)
# ── Normalization test pairs (non-canonical → canonical) ──

IPV6_VERBOSE = "2001:0db8:0000:0000:0000:0000:0000:0001"  # Verbose IPv6 form
IPV6_VERBOSE_CANONICAL = "2001:db8::1"  # Expected canonical form after normalization
IPV4_CIDR_HOST_BITS = "192.168.1.5/24"  # CIDR with host bits set
IPV4_CIDR_HOST_BITS_CANONICAL = "192.168.1.0/24"  # Expected network address after normalization

# --8<-- [end:outbound-targets]
