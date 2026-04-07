# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for validation.py shared validators."""

import re

import pytest

from terok_shield.validation import (
    SAFE_CONTAINER,
    SAFE_NAME,
    parse_entries,
    validate_container_name,
    validate_safe_name,
)

from ..testfs import FORBIDDEN_ABSOLUTE, FORBIDDEN_TRAVERSAL
from ..testnet import TEST_DOMAIN, TEST_DOMAIN2, TEST_IP1


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("mycontainer", id="simple"),
        pytest.param("my-ctr.123_test", id="dots-dashes-underscores"),
        pytest.param("_hidden", id="leading-underscore"),
    ],
)
def test_validate_container_name_accepts_valid_names(value: str) -> None:
    """``validate_container_name()`` preserves valid Podman-style names."""
    assert validate_container_name(value) == value


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("", id="empty"),
        pytest.param(FORBIDDEN_TRAVERSAL, id="path-traversal"),
        pytest.param("foo/bar", id="slash"),
        pytest.param(FORBIDDEN_ABSOLUTE, id="absolute-path"),
        pytest.param("my container", id="space"),
        pytest.param("name@", id="at"),
        pytest.param("name!", id="bang"),
        pytest.param("name$", id="dollar"),
        pytest.param("name&", id="ampersand"),
        pytest.param("name;", id="semicolon"),
        pytest.param("name|", id="pipe"),
    ],
)
def test_validate_container_name_rejects_unsafe_names(value: str) -> None:
    """``validate_container_name()`` rejects traversal and shell metacharacters."""
    with pytest.raises(ValueError):
        validate_container_name(value)


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("dev-standard", id="simple"),
        pytest.param("my.profile-v2", id="dots-dashes"),
    ],
)
def test_validate_safe_name_accepts_valid_names(value: str) -> None:
    """``validate_safe_name()`` preserves safe profile names."""
    assert validate_safe_name(value) == value


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("_hidden", id="leading-underscore"),
        pytest.param(".hidden", id="leading-dot"),
        pytest.param("-flag", id="leading-dash"),
        pytest.param("", id="empty"),
        pytest.param(FORBIDDEN_TRAVERSAL, id="path-traversal"),
    ],
)
def test_validate_safe_name_rejects_unsafe_names(value: str) -> None:
    """``validate_safe_name()`` is stricter than container-name validation."""
    with pytest.raises(ValueError):
        validate_safe_name(value)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(f"{TEST_DOMAIN}\n{TEST_IP1}\n", [TEST_DOMAIN, TEST_IP1], id="basic"),
        pytest.param(
            f"# comment\n{TEST_DOMAIN}\n# another\n{TEST_DOMAIN2}\n",
            [TEST_DOMAIN, TEST_DOMAIN2],
            id="comments",
        ),
        pytest.param(
            f"\n{TEST_DOMAIN}\n\n\n{TEST_DOMAIN2}\n",
            [TEST_DOMAIN, TEST_DOMAIN2],
            id="blank-lines",
        ),
        pytest.param(
            f"  {TEST_DOMAIN}  \n  {TEST_DOMAIN2}  \n",
            [TEST_DOMAIN, TEST_DOMAIN2],
            id="whitespace",
        ),
        pytest.param("", [], id="empty"),
        pytest.param(
            f"  # indented comment\n{TEST_DOMAIN}\n", [TEST_DOMAIN], id="indented-comment"
        ),
    ],
)
def test_parse_entries(text: str, expected: list[str]) -> None:
    """``parse_entries()`` strips comments, blanks, and surrounding whitespace."""
    assert parse_entries(text) == expected


@pytest.mark.parametrize(
    ("pattern", "value", "matches"),
    [
        pytest.param(SAFE_CONTAINER, "_test", True, id="container-allows-underscore-prefix"),
        pytest.param(SAFE_NAME, "_test", False, id="safe-name-rejects-underscore-prefix"),
        pytest.param(SAFE_CONTAINER, "test\nname", False, id="container-rejects-newline"),
        pytest.param(SAFE_NAME, "test\nname", False, id="safe-name-rejects-newline"),
    ],
)
def test_regex_patterns(pattern: re.Pattern[str], value: str, matches: bool) -> None:
    """Direct regex checks stay aligned with the validator behavior."""
    result = pattern.fullmatch(value)
    assert (result is not None) is matches
