# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""RFC 5737 TEST-NET addresses for use in tests.

These addresses are reserved for documentation and testing.
They are guaranteed non-routable — no real host will ever have them,
and packets to them will be dropped at the network edge.

Use these instead of arbitrary IPs (1.2.3.4, 5.6.7.8, etc.) to avoid
unintended connections in integration tests.
"""

# TEST-NET-1 (192.0.2.0/24)
TEST_IP1 = "192.0.2.1"
TEST_IP2 = "192.0.2.2"

# TEST-NET-2 (198.51.100.0/24)
TEST_IP3 = "198.51.100.1"

# TEST-NET-3 (203.0.113.0/24)
TEST_IP4 = "203.0.113.1"
