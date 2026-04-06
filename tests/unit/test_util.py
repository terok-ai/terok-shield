# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for shared utility functions."""

import pytest

from terok_shield.util import is_ip, is_ipv4, is_ipv6

from ..testnet import (
    IPV6_CLOUDFLARE,
    IPV6_LOOPBACK,
    IPV6_ULA_CIDR,
    TEST_DOMAIN,
    TEST_IP1,
    TEST_NET1,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(TEST_IP1, True, id="ipv4-address"),
        pytest.param(TEST_NET1, True, id="ipv4-cidr"),
        pytest.param(TEST_DOMAIN, False, id="domain"),
        pytest.param("", False, id="empty"),
        pytest.param(IPV6_LOOPBACK, False, id="ipv6"),
    ],
)
def test_is_ipv4(value: str, expected: bool) -> None:
    """``is_ipv4()`` accepts only IPv4 addresses and CIDRs."""
    assert is_ipv4(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(IPV6_CLOUDFLARE, True, id="ipv6-address"),
        pytest.param(IPV6_ULA_CIDR, True, id="ipv6-cidr"),
        pytest.param(TEST_DOMAIN, False, id="domain"),
        pytest.param("", False, id="empty"),
        pytest.param(TEST_IP1, False, id="ipv4"),
    ],
)
def test_is_ipv6(value: str, expected: bool) -> None:
    """``is_ipv6()`` accepts only IPv6 addresses and CIDRs."""
    assert is_ipv6(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(TEST_IP1, True, id="ipv4"),
        pytest.param(IPV6_LOOPBACK, True, id="ipv6"),
        pytest.param(TEST_DOMAIN, False, id="domain"),
    ],
)
def test_is_ip(value: str, expected: bool) -> None:
    """``is_ip()`` accepts both IPv4 and IPv6 addresses."""
    assert is_ip(value) is expected
