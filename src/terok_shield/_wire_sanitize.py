# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Producer-side wire-format invariant — printable ASCII, length-capped.

# WIRE_SPEC(safe-string): keep in sync with
# terok_clearance/src/terok_clearance/wire/sanitize.py — same rule,
# same character class, same length cap.  ``grep WIRE_SPEC`` finds
# every copy across the producer/consumer boundary; clearance owns
# the canonical version (it's the wire-format consumer).

The threat model: container processes can craft DNS names, hostnames,
or annotation bytes that flow through the shield's watchers and the
NFLOG reader straight onto the hub socket.  A consumer downstream
(notification daemon, terminal TUI, audit listener) sees those bytes
verbatim unless someone trims them along the way.

Sanitising at every emit point — here, in `_hub_events`, in the
reader resource — is belt-and-braces: clearance also applies the
same rule on the receive side, so a regression on either side keeps
the contract.  Producer-side sanitisation specifically protects the
container-out path that's the primary attack surface; consumer-side
catches every other event source.

Rule (single, simple):

* Printable ASCII (``[\\x20, \\x7E]``) passes through unchanged.
* Anything else — control bytes, non-ASCII, RTLO/LRO bidi overrides,
  the lot — collapses to a single space, position-preserving.
* Strings longer than ``max_len`` are truncated with a trailing
  ``...`` ASCII marker.

Stdlib-only by design — no external imports — so this module sits in
the foundation tach layer alongside `_hub_events`.
"""

from __future__ import annotations

#: Default per-value length cap.  Wide enough for any realistic
#: hostname or task name; tighter caps suit titles or compact labels.
DEFAULT_MAX_LEN = 256

_PRINTABLE_LO = 0x20
_PRINTABLE_HI = 0x7E

#: Truncation marker — three ASCII dots rather than ``…`` (which is
#: itself non-ASCII under the very rule this module enforces).
_TRUNCATION_MARKER = "..."


def sanitize(value: str, *, max_len: int = DEFAULT_MAX_LEN) -> str:
    """Coerce *value* to printable ASCII, capped at *max_len* characters."""
    if not value:
        return ""
    cleaned = "".join(ch if _PRINTABLE_LO <= ord(ch) <= _PRINTABLE_HI else " " for ch in value)
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[: max_len - len(_TRUNCATION_MARKER)] + _TRUNCATION_MARKER


def sanitize_mapping(mapping: dict[str, str], *, max_len: int = DEFAULT_MAX_LEN) -> dict[str, str]:
    """Apply [`sanitize`][terok_shield._wire_sanitize.sanitize] to every value in *mapping*."""
    return {k: sanitize(v, max_len=max_len) for k, v in mapping.items()}
