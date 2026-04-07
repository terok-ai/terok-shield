# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""IPv4 / IPv6 address and CIDR validation helpers."""

import ipaddress


def is_ipv4(value: str) -> bool:
    """Return True if *value* is an IPv4 address or CIDR notation."""
    try:
        if "/" in value:
            ipaddress.IPv4Network(value, strict=False)
        else:
            ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def is_ipv6(value: str) -> bool:
    """Return True if *value* is an IPv6 address or CIDR notation."""
    try:
        if "/" in value:
            ipaddress.IPv6Network(value, strict=False)
        else:
            ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


def is_ip(value: str) -> bool:
    """Return True if *value* is an IPv4 or IPv6 address or CIDR."""
    return is_ipv4(value) or is_ipv6(value)
