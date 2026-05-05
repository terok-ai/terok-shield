# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the producer-side wire-format sanitiser."""

from __future__ import annotations

import pytest

from terok_shield._wire_sanitize import (
    DEFAULT_MAX_LEN,
    sanitize,
    sanitize_mapping,
)


class TestSanitize:
    """``sanitize`` collapses input to printable ASCII and applies the length cap."""

    def test_empty_string_round_trips(self) -> None:
        assert sanitize("") == ""

    def test_plain_ascii_unchanged(self) -> None:
        assert sanitize("alpine-7-redis") == "alpine-7-redis"

    def test_full_printable_ascii_passes_through(self) -> None:
        full = "".join(chr(c) for c in range(0x20, 0x7F))
        assert sanitize(full) == full

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("café", "caf "),
            ("münchen", "m nchen"),
            ("naïve", "na ve"),
        ],
    )
    def test_non_ascii_letters_become_spaces(self, raw: str, expected: str) -> None:
        assert sanitize(raw) == expected

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("line1\nline2", "line1 line2"),
            ("tab\there", "tab here"),
            ("null\x00byte", "null byte"),
            ("esc\x1bseq", "esc seq"),
            ("del\x7fchar", "del char"),
        ],
    )
    def test_control_chars_become_spaces(self, raw: str, expected: str) -> None:
        assert sanitize(raw) == expected

    def test_markup_chars_pass_through(self) -> None:
        """``& < >`` are printable ASCII — wire layer leaves them untouched."""
        assert sanitize("<script>alert(1)</script>") == "<script>alert(1)</script>"

    def test_rtlo_bidi_override_is_neutralised(self) -> None:
        """U+202E becomes a space — kills the homoglyph attack at the boundary."""
        assert sanitize("evil‮.com") == "evil .com"

    def test_length_cap_uses_ascii_marker(self) -> None:
        out = sanitize("x" * 1000, max_len=10)
        assert out == "xxxxxxx..."
        assert len(out) == 10

    def test_value_at_exact_cap_passes_through(self) -> None:
        assert sanitize("x" * 10, max_len=10) == "x" * 10

    def test_default_max_len_is_generous(self) -> None:
        name = "warp-core/t42-feature-rebuild-2026-04"
        assert len(name) < DEFAULT_MAX_LEN
        assert sanitize(name) == name


class TestSanitizeMapping:
    """``sanitize_mapping`` applies the rule to every value in a dict."""

    def test_sanitises_values_only(self) -> None:
        out = sanitize_mapping({"task": "<a>", "name": "b\nc"})
        assert out == {"task": "<a>", "name": "b c"}

    def test_keys_pass_through_unchanged(self) -> None:
        out = sanitize_mapping({"<weird>": "v"})
        assert "<weird>" in out

    def test_empty_dict_round_trips(self) -> None:
        assert sanitize_mapping({}) == {}
