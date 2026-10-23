# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""The unified ``+``/``-`` policy line format — one grammar for every tier.

A policy file is one entry per line::

    +pypi.org                          # allow a domain
    +*.pythonhosted.org                # allow every subdomain
    +192.168.1.50:8080                 # allow one host:port
    +localhost:8000                    # reach a service on the host's localhost
    -telemetry.vendor.com              # deny
    +api.anthropic.com  %reason=harness-test %expires=2026-06-09T12:00Z

The leading ``+`` (allow) or ``-`` (deny) is **mandatory**.  ``%key=value``
markers carry optional metadata (``reason``, ``expires``, ``from``,
``first``/``last``, ``hits``); ``#`` starts a free-text comment that the
parser ignores entirely.  Blank and comment-only lines are skipped.

The reserved target ``localhost`` is a host-service grant: ``+localhost:PORT``
opens the host machine's own ``localhost:PORT`` to the container (the loader
routes it to the backend host-loopback address, accepted above the deny tiers).
It requires an explicit port and the ``+`` action.

This module is the single parser for shipped, generated, and authored
policy alike.  Stdlib-only, so it is cheap to audit and safe to import
from anywhere.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Literal

Action = Literal["+", "-"]
"""A policy verdict prefix: ``"+"`` (allow) or ``"-"`` (deny)."""

LOCALHOST = "localhost"
"""Reserved target: ``+localhost:PORT`` grants the container access to the host's localhost."""

# A DNS name: dot-separated alphanumeric/hyphen/underscore labels, with an
# optional leading ``*.`` wildcard for "any subdomain".
_DOMAIN = re.compile(r"^(?:\*\.)?(?:[A-Za-z0-9_-]+\.)*[A-Za-z0-9_-]+$")
_MAX_PORT = 65535


@dataclass(frozen=True, slots=True)
class PolicyEntry:
    """One parsed policy line.

    Attributes:
        action: ``"+"`` (allow) or ``"-"`` (deny).
        target: a domain (optionally ``*.``-prefixed), an IP literal, or a CIDR.
        port: the optional ``:port`` (``None`` when unspecified).
        meta: the ``%key=value`` markers parsed off the line (empty when none).
    """

    action: Action
    target: str
    port: int | None = None
    meta: dict[str, str] = field(default_factory=dict)


def parse_policy(text: str) -> list[PolicyEntry]:
    """Parse policy text into entries, failing fast on a malformed line.

    Raises:
        ValueError: on a missing ``+``/``-`` prefix, an empty or invalid
            target, an out-of-range port, or a malformed ``%key=value``
            marker — annotated with the line number.
    """
    entries: list[PolicyEntry] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        body, _, _comment = line.partition("#")  # comments bear zero load
        try:
            entries.append(_parse_line(body.strip()))
        except ValueError as exc:
            raise ValueError(f"line {lineno}: {exc} ({raw!r})") from exc
    return entries


def render_target(entry: PolicyEntry) -> str:
    """Render an entry's ``target[:port]`` — the line minus its action and markers.

    An IPv6 literal carrying a port is bracketed, else ``addr:port`` is
    indistinguishable from a longer IPv6 address on re-parse.
    """
    if entry.port is None:
        return entry.target
    host = f"[{entry.target}]" if ":" in entry.target else entry.target
    return f"{host}:{entry.port}"


def render_policy(entries: list[PolicyEntry]) -> str:
    """Render entries back to canonical text (round-trips [`parse_policy`][terok_shield.policy.parse_policy])."""
    lines = [
        f"{e.action}{render_target(e)}"
        + "".join(f" %{key}={value}" for key, value in sorted(e.meta.items()))
        for e in entries
    ]
    return "\n".join(lines) + "\n" if lines else ""


def localhost_ports(entries: list[PolicyEntry]) -> tuple[int, ...]:
    """Ports from the ``+localhost:PORT`` host-service grants, fed to the builder's ``loopback_ports``.

    Only admitting (``+``) entries grant a port — a programmatically built
    ``-localhost`` entry (which ``parse_policy`` would reject) is never a grant.
    """
    return tuple(
        e.port for e in entries if e.action == "+" and e.target == LOCALHOST and e.port is not None
    )


def is_ip(target: str) -> bool:
    """True when *target* is an IP literal or CIDR (a domain or ``localhost`` is False)."""
    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    return True


def ip_targets(entries: list[PolicyEntry]) -> list[str]:
    """The IP/CIDR targets among *entries* (domains and ``localhost`` excluded), order-preserving."""
    return [e.target for e in entries if is_ip(e.target)]


def domain_targets(entries: list[PolicyEntry]) -> list[str]:
    """The domain targets among *entries* (IPs and ``localhost`` excluded), order-preserving."""
    return [e.target for e in entries if e.target != LOCALHOST and not is_ip(e.target)]


def _parse_line(body: str) -> PolicyEntry:
    """Parse one non-comment ``body``: ``+``/``-`` target ``[:port]`` plus ``%key=value`` markers."""
    head, *markers = body.split()
    if not head or head[0] not in "+-":
        raise ValueError("entry must start with '+' (allow) or '-' (deny)")
    action: Action = head[0]  # type: ignore[assignment]
    target, port = _split_port(head[1:])
    if not target:
        raise ValueError("empty target")
    if target == LOCALHOST:
        _validate_localhost(action, port)
    else:
        _validate_target(target)
    return PolicyEntry(action, target, port, _parse_markers(markers))


def _validate_localhost(action: Action, port: int | None) -> None:
    """The reserved ``localhost`` host-service grant needs the ``+`` action and a port."""
    if action != "+":
        raise ValueError("'localhost' is allow-only (it grants host-service access)")
    if port is None:
        raise ValueError("'localhost' needs an explicit port, e.g. +localhost:8000")


def _parse_markers(markers: list[str]) -> dict[str, str]:
    """Parse ``%key=value`` metadata markers; any other token is an error."""
    meta: dict[str, str] = {}
    for token in markers:
        if not token.startswith("%"):
            raise ValueError(f"unexpected token {token!r} (metadata needs a '%' prefix)")
        key, sep, value = token[1:].partition("=")
        if not key or not sep:
            raise ValueError(f"malformed metadata {token!r} (expected '%key=value')")
        meta[key] = value
    return meta


def _split_port(spec: str) -> tuple[str, int | None]:
    """Split an optional ``:port``, handling bracketed and bare IPv6 literals."""
    if spec.startswith("["):  # [ipv6] or [ipv6]:port
        host, sep, rest = spec[1:].partition("]")
        if not sep:
            raise ValueError("unterminated '[' in IPv6 literal")
        if not rest:
            return host, None
        if not rest.startswith(":"):
            raise ValueError(f"trailing characters after ']': {rest!r}")
        return host, _parse_port(rest[1:])  # _parse_port rejects any non-numeric tail
    if spec.count(":") >= 2:  # bare IPv6 literal — a port needs brackets
        return spec, None
    host, sep, maybe_port = spec.rpartition(":")
    if sep and maybe_port.isdigit():
        return host, _parse_port(maybe_port)
    return spec, None


def _parse_port(text: str) -> int:
    """Parse and range-check a 1..65535 port number."""
    if not text.isdigit() or not 1 <= (port := int(text)) <= _MAX_PORT:
        raise ValueError(f"invalid port: {text!r}")
    return port


def _validate_target(target: str) -> None:
    """Accept a domain (optionally ``*.``-prefixed), an IP literal, or a CIDR."""
    try:
        ipaddress.ip_network(target, strict=False)
        return
    except ValueError:
        pass
    if not _DOMAIN.fullmatch(target):
        raise ValueError(f"invalid target: {target!r}")


__all__ = [
    "LOCALHOST",
    "Action",
    "PolicyEntry",
    "domain_targets",
    "ip_targets",
    "is_ip",
    "localhost_ports",
    "parse_policy",
    "render_policy",
    "render_target",
]
