# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0
"""AppArmor awareness for the per-container dnsmasq DNS tier.

Some distros (Arch/Manjaro, the ``apparmor.d`` profile set) ship an
enforcing AppArmor profile for ``/usr/sbin/dnsmasq`` that forbids the
shield state directory under the operator's home, so the per-container
dnsmasq cannot read its config and the container would fail to launch.
This module probes for that confinement behaviourally (via ``dnsmasq
--test`` — no root needed) and drives a fallback to the ``lookup`` tier.
The profile addendum that lets operators keep the dnsmasq tier is
documented in ``docs/apparmor.md``.
"""

from __future__ import annotations

from pathlib import Path

from ..config import DNS_TIER_AUTO, DnsTier, detect_dns_tier
from ..run import CommandRunner, ExecError, which_sbin_aware
from . import dnsmasq

# Throwaway config dnsmasq --test reads to probe state-dir access.  The name
# MUST start with ``dnsmasq.`` so the profile addendum's
# ``owner .../shield/dnsmasq.* rwk`` grant covers it (see
# terok-sandbox ``install_profile.sh``).  A name outside that glob would be
# denied even with the correct profile installed, so the probe would report
# confinement on every AppArmor host and shield would never use the dnsmasq
# tier.  It also makes the probe a true test of the addendum: an old profile
# that named the individual files, not the glob, correctly fails it.
_PROBE_NAME = "dnsmasq.apparmor-probe.conf"
_PROBE_CONTENT = "# terok-shield AppArmor access probe\n"
_PROBE_TIMEOUT_S = 10  # dnsmasq --test only parses and exits


def detect_dns_tier_under_apparmor(
    runner: CommandRunner,
    state_dir: Path,
    *,
    requested: str = DNS_TIER_AUTO,
    proxy_enabled: bool = True,
) -> tuple[DnsTier, bool]:
    """Pick the DNS tier and report whether AppArmor blocked dnsmasq.

    Returns ``(tier, apparmor_blocked)``.  *apparmor_blocked* is True when
    an otherwise-eligible dnsmasq was rejected because AppArmor confines
    it from *state_dir*, so *tier* dropped to whatever ranks below it.
    The confinement probe runs only once dnsmasq is otherwise eligible,
    so it is skipped when dnsmasq is already out.

    *requested* and *proxy_enabled* are the operator's tier choice, and
    they are threaded through rather than defaulted here: a host that
    confines dnsmasq is exactly a host whose operator may have named a
    tier, and ignoring the choice on that path would grant it everywhere
    but where it matters.

    Raises:
        DnsTierUnavailableError: A tier was named and this host cannot
            provide it.
    """
    nftset_ok = runner.has("dnsmasq") and dnsmasq.has_nftset_support(runner)
    readable = dnsmasq_can_read_state_dir(runner, state_dir) if nftset_ok else True
    tier = detect_dns_tier(
        runner.has,
        lambda: nftset_ok,
        lambda: readable,
        requested=requested,
        proxy_enabled=proxy_enabled,
    )
    return tier, nftset_ok and not readable


def dnsmasq_can_read_state_dir(runner: CommandRunner, state_dir: Path) -> bool:
    """Return True if dnsmasq can read a config file inside *state_dir*.

    Writes a throwaway probe config and runs ``dnsmasq --test`` on it; a
    permission denial (AppArmor) returns False.  Parse errors, a missing
    binary, or an unwritable probe return True so tier selection never
    downgrades spuriously.
    """
    probe = state_dir / _PROBE_NAME
    try:
        probe.write_text(_PROBE_CONTENT)
    except OSError:
        return True
    try:
        runner.run(
            [which_sbin_aware("dnsmasq") or "dnsmasq", "--test", f"--conf-file={probe}"],
            check=True,
            timeout=_PROBE_TIMEOUT_S,
        )
        return True
    except ExecError as exc:
        # AppArmor-denied open() surfaces as EACCES → "...: Permission denied".
        return "permission denied" not in exc.stderr.lower()
    finally:
        probe.unlink(missing_ok=True)
