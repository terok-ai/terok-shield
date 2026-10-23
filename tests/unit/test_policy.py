# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the unified ``+``/``-`` policy line format (``terok_shield.policy``)."""

import pytest

from terok_shield.policy import (
    LOCALHOST,
    PolicyEntry,
    domain_targets,
    ip_targets,
    is_ip,
    localhost_ports,
    parse_policy,
    render_policy,
    render_target,
)
from tests.testfs import FORBIDDEN_TRAVERSAL
from tests.testnet import (
    DEV_PYPI_DOMAIN,
    IPV6_NET1,
    IPV6_VERBOSE_CANONICAL,
    LINK_LOCAL_DNS,
    RFC1918_CIDR_10,
    TEST_DOMAIN,
    TEST_DOMAIN2,
    TEST_DOMAIN_ATTACK,
    TEST_IP1,
    TEST_NET1,
)

WILDCARD = f"*.{TEST_DOMAIN2}"


def test_parses_allow_and_deny() -> None:
    """A leading ``+``/``-`` becomes the entry action."""
    assert parse_policy(f"+{TEST_DOMAIN}\n-{DEV_PYPI_DOMAIN}\n") == [
        PolicyEntry("+", TEST_DOMAIN),
        PolicyEntry("-", DEV_PYPI_DOMAIN),
    ]


def test_ignores_blank_and_comment_lines() -> None:
    """Blank lines and full-line ``#`` comments are skipped."""
    assert parse_policy(f"\n# a comment\n   \n+{TEST_DOMAIN}\n") == [PolicyEntry("+", TEST_DOMAIN)]


@pytest.mark.parametrize(
    "target",
    [
        TEST_DOMAIN,
        WILDCARD,
        TEST_IP1,
        TEST_NET1,
        RFC1918_CIDR_10,
        LINK_LOCAL_DNS,
        IPV6_VERBOSE_CANONICAL,
        IPV6_NET1,
    ],
)
def test_accepts_valid_targets(target: str) -> None:
    """Domains, wildcards, IP literals, and CIDRs (v4 and v6) all parse."""
    assert parse_policy(f"+{target}") == [PolicyEntry("+", target)]


def test_parses_ipv4_port() -> None:
    """A trailing ``:port`` on an IPv4/host target is split off."""
    assert parse_policy(f"+{TEST_IP1}:8080") == [PolicyEntry("+", TEST_IP1, 8080)]


def test_parses_bracketed_ipv6_port() -> None:
    """An IPv6 literal carries a port only when bracketed."""
    assert parse_policy(f"+[{IPV6_VERBOSE_CANONICAL}]:443") == [
        PolicyEntry("+", IPV6_VERBOSE_CANONICAL, 443)
    ]


def test_bracketed_ipv6_without_port() -> None:
    """A bracketed IPv6 literal with no ``:port`` parses with ``port=None``."""
    (entry,) = parse_policy(f"+[{IPV6_VERBOSE_CANONICAL}]")
    assert entry == PolicyEntry("+", IPV6_VERBOSE_CANONICAL)


def test_bare_ipv6_has_no_port() -> None:
    """A bare (unbracketed) IPv6 literal is never split on its colons."""
    (entry,) = parse_policy(f"+{IPV6_VERBOSE_CANONICAL}")
    assert entry.port is None
    assert entry.target == IPV6_VERBOSE_CANONICAL


def test_metadata_markers() -> None:
    """``%key=value`` markers are parsed into ``meta``; values may contain ``=``."""
    (entry,) = parse_policy(f"+{TEST_DOMAIN}  %reason=test %expires=2026-06-09 %c=x=y")
    assert entry.meta == {"reason": "test", "expires": "2026-06-09", "c": "x=y"}


def test_comment_bears_zero_load() -> None:
    """Everything after ``#`` is ignored — including stray ``%`` markers."""
    (entry,) = parse_policy(f"+{TEST_DOMAIN}  %reason=keep  # free text %ignored=marker")
    assert entry == PolicyEntry("+", TEST_DOMAIN, None, {"reason": "keep"})


def test_localhost_grant_parses_with_port() -> None:
    """``+localhost:PORT`` parses as the reserved host-service grant."""
    assert parse_policy("+localhost:8000") == [PolicyEntry("+", LOCALHOST, 8000)]


def test_localhost_ports_extracts_grants() -> None:
    """``localhost_ports`` collects every ``+localhost:PORT`` port, skipping other entries."""
    entries = parse_policy(f"+localhost:8000\n+{TEST_DOMAIN}\n+localhost:9090\n")
    assert localhost_ports(entries) == (8000, 9090)


def test_ip_and_domain_targets_partition_entries() -> None:
    """``ip_targets``/``domain_targets`` split entries by kind, excluding ``localhost``."""
    entries = parse_policy(
        f"+{TEST_DOMAIN}\n+{TEST_IP1}\n+{RFC1918_CIDR_10}\n+localhost:8000\n-{TEST_DOMAIN2}\n"
    )
    assert ip_targets(entries) == [TEST_IP1, RFC1918_CIDR_10]
    assert domain_targets(entries) == [TEST_DOMAIN, TEST_DOMAIN2]


def test_is_ip_classifies_literals_cidrs_and_domains() -> None:
    """``is_ip`` accepts IP literals and CIDRs (v4/v6) and rejects domains/localhost."""
    assert is_ip(TEST_IP1)
    assert is_ip(RFC1918_CIDR_10)
    assert is_ip(IPV6_VERBOSE_CANONICAL)
    assert not is_ip(TEST_DOMAIN)
    assert not is_ip(LOCALHOST)


def test_round_trip_render_parse() -> None:
    """``parse_policy(render_policy(x)) == x`` — including bracketed IPv6 ports and metadata."""
    text = (
        f"+{TEST_DOMAIN}\n"
        f"+{WILDCARD}\n"
        f"+{TEST_IP1}:8080\n"
        f"-{DEV_PYPI_DOMAIN}\n"
        f"+{RFC1918_CIDR_10}\n"
        f"+[{IPV6_VERBOSE_CANONICAL}]:443\n"
        f"+{TEST_DOMAIN}  %reason=keep\n"
    )
    entries = parse_policy(text)
    assert parse_policy(render_policy(entries)) == entries


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        (PolicyEntry("+", TEST_DOMAIN), TEST_DOMAIN),
        (PolicyEntry("+", TEST_IP1, 8080), f"{TEST_IP1}:8080"),
        (PolicyEntry("+", LOCALHOST, 8000), f"{LOCALHOST}:8000"),
        (PolicyEntry("+", IPV6_VERBOSE_CANONICAL, 443), f"[{IPV6_VERBOSE_CANONICAL}]:443"),
        (PolicyEntry("+", IPV6_VERBOSE_CANONICAL), IPV6_VERBOSE_CANONICAL),
    ],
)
def test_render_target_keeps_the_port_and_brackets_ipv6(entry: PolicyEntry, expected: str) -> None:
    """``render_target`` is the line minus action and markers: ``target[:port]``, v6 bracketed."""
    assert render_target(entry) == expected


@pytest.mark.parametrize(
    "bad",
    [
        TEST_DOMAIN,  # missing +/- prefix
        "+",  # empty target
        "+   ",  # empty target (whitespace only)
        f"+{TEST_DOMAIN}:99999",  # port out of range (high)
        f"+{TEST_DOMAIN}:0",  # port out of range (low)
        f"+{TEST_DOMAIN_ATTACK}",  # control bytes in target
        f"+{FORBIDDEN_TRAVERSAL}",  # path-traversal shape
        "+a/b",  # slash (path-ish) in target
        f"+[{IPV6_VERBOSE_CANONICAL}",  # unterminated IPv6 bracket
        f"+[{IPV6_VERBOSE_CANONICAL}]junk",  # trailing junk after ']'
        f"+{TEST_DOMAIN} bar",  # bare token without a '%' prefix
        f"+{TEST_DOMAIN} %nokey",  # metadata marker missing '=value'
        "+localhost",  # reserved 'localhost' grant needs an explicit port
        "-localhost:8000",  # 'localhost' is allow-only
    ],
)
def test_rejects_malformed(bad: str) -> None:
    """Malformed lines fail fast with a ``ValueError``."""
    with pytest.raises(ValueError):
        parse_policy(bad)
