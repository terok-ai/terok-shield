# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Host binary prerequisite checks for the shield runtime.

Exported for higher layers (terok-sandbox aggregator, operator
diagnostics) so the place that owns each binary — shield — is the
place that publishes the list of binaries it depends on.  Keeps the
install-time preflight and the runtime failure sites honest about
what the shield actually needs.

Pure probes: every check uses the shared host PATH resolver.
No subprocess invocation, no side effects.
"""

from __future__ import annotations

from dataclasses import dataclass

from terok_util import find_host_tool


@dataclass(frozen=True)
class BinaryCheck:
    """Result of probing for a single prerequisite binary."""

    name: str
    """Invocation name, as the shell would resolve it."""

    path: str
    """Absolute path to the resolved binary, or empty string if missing."""

    purpose: str
    """One-line rationale, rendered in verbose CLI output."""

    @property
    def ok(self) -> bool:
        """True when the binary was located on the current host PATH."""
        return bool(self.path)


def check_firewall_binaries() -> tuple[BinaryCheck, ...]:
    """Probe the host for binaries the shield runtime uses.

    Returns a stable-ordered tuple covering ``nft`` (ruleset
    enforcement), ``dnsmasq`` (optional local DNS tier), and a lookup
    tool — ``dig`` or ``drill`` (profile-domain resolution).  Callers render the results however
    they want and decide whether a missing entry should warn, block,
    or be ignored for their workflow.
    """
    return (
        BinaryCheck("nft", find_host_tool("nft") or "", "nftables ruleset enforcement"),
        BinaryCheck("dnsmasq", find_host_tool("dnsmasq") or "", "local DNS caching resolver"),
        BinaryCheck(
            "dig/drill",
            find_host_tool("dig") or find_host_tool("drill") or "",
            "DNS resolution for allowlist domains",
        ),
    )


def check_krun_binaries() -> tuple[BinaryCheck, ...]:
    """Probe the host for binaries the krun runtime path adds.

    Separate from [`check_firewall_binaries`][terok_shield.prereqs.check_firewall_binaries]
    because the krun runtime is experimental — callers should gate this
    probe on whatever flag they use to expose krun (in terok, the
    top-level ``experimental:`` toggle).  Reporting ``ip`` as missing
    to an operator who never touches krun would be noise.
    """
    return (
        BinaryCheck(
            "ip",
            find_host_tool("ip") or "",
            "in-netns IP assignment for the krun runtime",
        ),
    )
