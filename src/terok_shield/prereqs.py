# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Host binary prerequisite checks for the shield runtime.

Exported for higher layers (terok-sandbox aggregator, operator
diagnostics) so the place that owns each binary — shield — is the
place that publishes the list of binaries it depends on.  Keeps the
install-time preflight and the runtime failure sites honest about
what the shield actually needs.

Pure probes: every check is ``shutil.which`` or a sbin-aware variant.
No subprocess invocation, no side effects.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass

#: Directories searched after ``PATH`` when probing daemon binaries.
#: rootless users regularly have neither on their login PATH; probing
#: them anyway lets the aggregator report a usable host rather than
#: fail on a shell-configuration quirk.
_SBIN_DIRS: tuple[str, ...] = ("/usr/sbin", "/sbin")


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
        """True when the binary was located on PATH or a standard sbin directory."""
        return bool(self.path)


def check_firewall_binaries() -> tuple[BinaryCheck, ...]:
    """Probe the host for binaries the shield runtime uses.

    Returns a stable-ordered tuple covering ``nft`` (ruleset
    enforcement), ``dnsmasq`` (optional local DNS tier), and ``dig``
    (profile-domain resolution).  Callers render the results however
    they want and decide whether a missing entry should warn, block,
    or be ignored for their workflow.
    """
    return (
        BinaryCheck("nft", which_sbin_aware("nft"), "nftables ruleset enforcement"),
        BinaryCheck("dnsmasq", which_sbin_aware("dnsmasq"), "local DNS caching resolver"),
        BinaryCheck("dig", shutil.which("dig") or "", "DNS resolution for allowlist domains"),
    )


def which_sbin_aware(name: str) -> str:
    """Resolve *name* like :func:`shutil.which`, falling back to sbin directories.

    Returns the absolute path of the first match or an empty string
    when the binary is not on ``PATH`` and not in ``/usr/sbin`` or
    ``/sbin``.  The sbin fallback reuses :func:`shutil.which` with an
    explicit ``path=`` so executability (``os.X_OK``) is checked the
    same way ``PATH`` resolution would — a regular non-executable file
    in ``/usr/sbin`` shouldn't count as a hit.
    """
    for search_path in (None, *_SBIN_DIRS):
        found = shutil.which(name, path=search_path)
        if found:
            return found
    return ""
