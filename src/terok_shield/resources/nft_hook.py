#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0
"""OCI hook: apply pre-generated terok-shield nft ruleset.

Applies ``ruleset.nft`` (written by ``pre_start()``) and optionally
starts dnsmasq if ``dnsmasq.conf`` is present in the state directory.
Gateway addresses are baked into the ruleset at generation time — no
runtime ``/proc`` discovery needed.

Stdlib-only by design, except for a sibling-module import of
``_oci_state`` shipped to the same hooks directory at install time.
The OCI runtime executes us with ``/usr/bin/python3`` outside any
virtualenv, so a dependency on ``terok_shield`` would fail to import.

The hook is invoked by crun, which runs inside podman's rootless user
namespace (``NS_ROOTLESS``).  Inside ``NS_ROOTLESS`` ``os.getuid() ==
0`` and ``CAP_NET_ADMIN`` is already available, so ``nsenter -n -t
<pid>`` is used directly.  When run from a normal shell
(``NS_INIT``, uid != 0), ``podman unshare nsenter -n -t <pid>`` is
used instead — see ``_oci_state.nsenter`` for the dispatch.
"""

import contextlib
import json
import os
import signal
import sys
from pathlib import Path

# Sibling-module import: ``_oci_state.py`` lives next to this script in
# the same hooks directory, and Python's default ``sys.path[0]`` (the
# directory of the invoked script) makes it importable directly.  We
# import the module qualified — every helper is reached as
# ``_oci_state.foo`` — so unit tests can patch one canonical attribute
# (``_oci_state.nsenter``) and have it apply to every caller.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _oci_state  # noqa: E402 — sys.path bootstrap precedes import

# WORKAROUND(selinux-nft-stdin): nft runs as iptables_t (SELinux
# domain), which cannot read files in data_home_t (~/.local/share/…).
# Piping the ruleset via stdin (``-f -``) bypasses the file-read
# restriction — the hook process (not nft) opens the file.
# Remove when: SELinux policy grants nft read access to user state
# dirs, or state_dir moves to an nft-accessible location.

_RULESET_NAME = "ruleset.nft"
_DNSMASQ_CONF_NAME = "dnsmasq.conf"
_DNSMASQ_PID_NAME = "dnsmasq.pid"
_CONTAINER_ID_NAME = "container.id"


def main() -> int:
    """OCI hook entry point: dispatch by stage."""
    _oci_state.bootstrap_env()
    stage = sys.argv[1] if len(sys.argv) > 1 else "createRuntime"
    try:
        oci = json.load(sys.stdin)
    except ValueError as exc:
        _oci_state.log(f"terok-shield hook: bad OCI state: {exc}")
        return 1

    sd = _oci_state.state_dir_from_oci(oci)
    if sd is None:
        return 1

    # All subsequent errors go to <state_dir>/hook-error.log so they
    # survive even when the OCI runtime does not forward the hook's
    # stderr.
    log_path = sd / "hook-error.log"

    try:
        return _nft_main(oci, sd, stage, log_path)
    except Exception as exc:  # noqa: BLE001
        _oci_state.log(f"terok-shield hook: {exc}", log_path)
        return 1


def _nft_main(oci: dict, sd: Path, stage: str, log_path: Path) -> int:
    """Apply the nft ruleset and (optionally) dnsmasq at the right stage."""
    # poststop cleanup must run regardless of bundle-version — a
    # container that was started before a terok-shield upgrade still
    # needs its dnsmasq reaped on stop.
    if stage == "poststop":
        _poststop(sd)
        return 0
    if stage != "createRuntime":
        _oci_state.log(f"terok-shield hook: unknown stage {stage!r}", log_path)
        return 1

    ann = oci.get("annotations") or {}
    ver = ann.get(_oci_state.ANN_VERSION, "")
    if not ver or str(ver) != str(_oci_state.BUNDLE_VERSION):
        _oci_state.log(
            f"terok-shield hook: bundle version {ver!r} != {_oci_state.BUNDLE_VERSION}. Re-run pre_start().",
            log_path,
        )
        return 1

    pid = str(oci.get("pid") or "")
    if not pid:
        _oci_state.log("terok-shield hook: missing pid in OCI state", log_path)
        return 1

    # Persist container ID for D-Bus bridge bus-name derivation.  The
    # OCI state includes "id" (full 64-char hex); store the short form.
    container_id = str(oci.get("id") or "")
    if container_id:
        (sd / _CONTAINER_ID_NAME).write_text(container_id[:12] + "\n")

    _createruntime(pid, sd)
    return 0


def _createruntime(pid: str, sd: Path) -> None:
    """Apply the pre-generated ruleset and optionally start dnsmasq."""
    # Verify the target PID's network namespace file exists before
    # invoking nsenter.  Use stat() rather than exists(): Path.exists()
    # silently swallows PermissionError in Python 3.14+, whereas stat()
    # reliably raises it.  PermissionError means the file is present
    # but we can't read it (non-root caller) — that's fine, proceed.
    # Any other OSError (FileNotFoundError, etc.) means the PID is gone.
    ns_net = Path(f"/proc/{pid}/ns/net")
    try:
        ns_net.stat()
    except PermissionError:
        pass
    except OSError:
        raise RuntimeError(f"network namespace file missing for pid {pid}: {ns_net}")

    ruleset = sd / _RULESET_NAME
    if not ruleset.exists():
        raise RuntimeError(f"ruleset.nft not found: {ruleset}")
    nft = _oci_state.find_nft()
    # WORKAROUND(selinux-nft-stdin): pipe ruleset via stdin; see header.
    _oci_state.nsenter(pid, nft, "-f", "-", stdin=ruleset.read_text())

    # Gateway addresses are baked into ruleset.nft by pre_start() — no
    # /proc discovery or dynamic nft set population needed.

    _start_container_dnsmasq(pid, sd)


def _start_container_dnsmasq(pid: str, sd: Path) -> None:
    """Launch dnsmasq in the container's netns and verify it started.

    No-op if ``dnsmasq.conf`` is absent (pre_start did not enable
    dnsmasq).  resolv.conf is pre-written by pre_start and bind-mounted
    :ro, so DNS already points to 127.0.0.1 before the hook runs.

    Mirrors ``terok_shield.dns.dnsmasq.launch()`` defensive measures:
    clears stale PID file, then verifies the new PID file and process
    identity after start.
    """
    dnsmasq_conf = sd / _DNSMASQ_CONF_NAME
    if not dnsmasq_conf.exists():
        return

    pid_file = sd / _DNSMASQ_PID_NAME
    # Idempotent: if a dnsmasq is already running against our conf
    # (because the hook fired twice — restart, re-dispatch, sibling
    # hook re-entry, etc.), don't try to bind port 53 again.  Verifying
    # pid + conf-arg avoids hitting an unrelated process that happens
    # to hold the recycled PID.
    if _our_dnsmasq_alive(pid_file, dnsmasq_conf):
        return

    # Remove stale PID file so the post-launch check is not fooled by a
    # leftover from a previous run (mirrors dnsmasq.launch()).
    try:
        pid_file.unlink()
    except OSError:
        pass

    _oci_state.nsenter(pid, _oci_state.find_dnsmasq(), f"--conf-file={dnsmasq_conf}")

    try:
        dnsmasq_pid = int(pid_file.read_text().strip())
    except (OSError, ValueError):
        raise RuntimeError(
            f"dnsmasq started but PID file not written at {pid_file}. "
            "The container's DNS may not be functional."
        )
    if not _is_our_dnsmasq(dnsmasq_pid, dnsmasq_conf):
        raise RuntimeError(
            f"dnsmasq PID {dnsmasq_pid} is not the expected process. "
            "The container's DNS may not be functional."
        )


def _poststop(sd: Path) -> None:
    """Send SIGTERM to the per-container dnsmasq process (best-effort).

    Verifies PID identity against ``/proc/{pid}/cmdline`` before
    signalling to avoid hitting an unrelated process when the original
    dnsmasq PID is recycled after container stop.
    """
    pid_file = sd / _DNSMASQ_PID_NAME
    conf_path = sd / _DNSMASQ_CONF_NAME
    if not pid_file.exists():
        return
    try:
        pid_int = int(pid_file.read_text().strip())
    except (ValueError, OSError):
        return
    if not _is_our_dnsmasq(pid_int, conf_path):
        with contextlib.suppress(OSError):
            pid_file.unlink()
        return
    try:
        os.kill(pid_int, signal.SIGTERM)
    except OSError:
        pass


def _our_dnsmasq_alive(pid_file: Path, conf_path: Path) -> bool:
    """``True`` when ``pid_file`` names a live dnsmasq using ``conf_path``."""
    try:
        pid_int = int(pid_file.read_text().strip())
    except (OSError, ValueError):
        return False
    return _is_our_dnsmasq(pid_int, conf_path)


def _is_our_dnsmasq(pid_int: int, conf_path: Path) -> bool:
    """``True`` if pid_int is a dnsmasq process using our conf file.

    Parses ``/proc/{pid}/cmdline`` as a NUL-separated argv vector.
    Requires argv[0] to be the dnsmasq binary (exact name or absolute
    path) and ``--conf-file=<our-conf>`` to be present as a separate
    argument.  Mirrors ``terok_shield.dnsmasq._is_our_dnsmasq()`` without
    any imports.
    """
    conf_arg = b"--conf-file=" + str(conf_path).encode()
    try:
        raw = Path(f"/proc/{pid_int}/cmdline").read_bytes()
    except OSError:
        return False
    args = raw.rstrip(b"\x00").split(b"\x00")
    if not args:  # pragma: no cover — bytes.split() never returns empty
        return False
    exe = args[0]
    return (exe == b"dnsmasq" or exe.endswith(b"/dnsmasq")) and conf_arg in args


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
