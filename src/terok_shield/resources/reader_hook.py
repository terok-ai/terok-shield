#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0
"""OCI hook: spawn / reap the per-container NFLOG reader.

Soft-fails on every error path: a missing reader script, an
unreachable session bus, or a failed Popen all log and return
normally so the container still starts.  The clearance UI degrades
gracefully to "no events, no desktop notifications" in those cases.

Stdlib-only by design, except for a sibling-module import of
``_oci_state`` shipped to the same hooks directory at install time.
"""

import contextlib
import json
import os
import signal
import subprocess  # nosec B404
import sys
import time
from pathlib import Path

# Sibling-module import — see the header in ``nft_hook.py`` for why
# this works.  Both role scripts share the same lookup convention so
# auditors can read either file in isolation.  Imported qualified so
# unit tests have a single canonical attribute to patch.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _oci_state  # noqa: E402 — sys.path bootstrap precedes import

# SIGTERM→SIGKILL grace: how long to wait for the reader to exit
# cleanly after poststop sends SIGTERM.  10 × 0.2s poll intervals = 2s.
_REAP_POLL_INTERVAL_S = 0.2
_REAP_POLL_TICKS = 10

_READER_PID_NAME = "reader.pid"
_READER_LOG_NAME = "reader.log"


def main() -> None:
    """OCI hook entry point: spawn or reap the NFLOG reader by stage.

    Returns ``None`` unconditionally — the bridge path is soft-fail by
    contract: container start must never be blocked by a missing
    reader, an unreachable session bus, a corrupt OCI state JSON, or a
    failed Popen.  ``sys.exit(None)`` (the call site below) exits 0,
    which is exactly the OCI-hook signal we want.  (Compare
    ``nft_hook.main()``, which *does* return ``int`` because the nft
    path is fail-closed.)
    """
    _oci_state.bootstrap_env()
    stage = sys.argv[1] if len(sys.argv) > 1 else "createRuntime"
    try:
        oci = json.load(sys.stdin)
    except ValueError as exc:
        _oci_state.log(f"terok-shield bridge hook: bad OCI state: {exc}")
        return

    sd = _oci_state.state_dir_from_oci(oci)
    if sd is None:
        return

    log_path = sd / "hook-error.log"

    try:
        _bridge_main(oci, sd, stage, log_path)
    except Exception as exc:  # noqa: BLE001
        _oci_state.log(f"terok-shield bridge hook: {exc}", log_path)


def _bridge_main(oci: dict, sd: Path, stage: str, log_path: Path) -> None:
    """Dispatch by stage — spawn at createRuntime, reap at poststop."""
    if stage == "poststop":
        _reap_reader(sd)
        return
    if stage != "createRuntime":
        _oci_state.log(f"terok-shield bridge hook: unknown stage {stage!r}", log_path)
        return

    container_id = str(oci.get("id") or "")[:12]
    if not container_id:
        _oci_state.log("terok-shield bridge hook: missing container id — skipping reader", log_path)
        return

    annotations = oci.get("annotations") or {}
    dossier = _extract_dossier(annotations if isinstance(annotations, dict) else {})
    # Persist before spawn so a Popen failure still leaves the host-side
    # ``Shield.up()`` / ``Shield.down()`` with the meta-path pointer
    # they need to resolve dossiers for their hub events.  Spawn is the
    # costly step; the file write is one syscall and soft-fails on its own.
    _oci_state.persist_meta_path(sd, dossier.get("meta_path", ""))
    _spawn_reader(sd, container_id, dossier)


def _extract_dossier(annotations: dict) -> dict[str, str]:
    """Pluck the orchestrator-supplied identity bundle out of OCI annotations.

    Annotations under the ``dossier.*`` namespace are the orchestrator's
    contract with the shield: ``dossier.task`` etc. flow through to the
    clearance UI as event-payload fields.  The prefix is stripped here
    so the reader sees a flat dict it can pass through verbatim.

    Non-string keys/values are coerced to ``str``.
    """
    out: dict[str, str] = {}
    for key, value in annotations.items():
        if not isinstance(key, str) or not key.startswith("dossier."):
            continue
        out[key[len("dossier.") :]] = str(value)
    return out


def _spawn_reader(sd: Path, container_id: str, dossier: dict[str, str] | None = None) -> None:
    """Start the NFLOG reader for *container_id* as a detached child.

    No-op when the reader script is missing (``--no-dbus-bridge``
    installs) or the operator's session bus is unreachable (headless
    host).  Safe to call repeatedly — a second call while the prior
    reader is still alive is treated as a no-op via the ``reader.pid``
    liveness check.

    *dossier* — orchestrator-supplied identity fields
    (``container_name``, ``project``, ``task``, ``meta_path``, …)
    forwarded to the reader as a JSON-encoded ``--annotations`` argv
    element so the reader (which composes the wire payload) doesn't
    re-parse the OCI state itself.
    """
    reader = _reader_script_path()
    if not reader.exists():
        _oci_state.log(
            f"terok-shield bridge hook: nflog-reader missing at {reader} — rerun `terok setup`"
        )
        return
    bus = _session_bus_address()
    if bus is None:
        _oci_state.log("terok-shield bridge hook: no session bus reachable — skipping reader")
        return
    pid_file = sd / _READER_PID_NAME
    if _reader_alive(pid_file):
        return  # idempotent respawn
    env = {**os.environ, "DBUS_SESSION_BUS_ADDRESS": bus}
    # Keep the reader's stderr capturable — a silent /dev/null here
    # means any startup crash (nsenter failure, missing binary, NFLOG
    # bind denial) leaves the operator with a live pid file and nothing
    # to diagnose from.
    err_log = sd / _READER_LOG_NAME
    try:
        err_fh = err_log.open("ab")
    except OSError as exc:
        _oci_state.log(f"terok-shield bridge hook: cannot open reader.log: {exc}")
        return
    annotations_json = json.dumps(dossier or {}, separators=(",", ":"), sort_keys=True)
    # argv is a fixed literal plus paths constructed from validated OCI
    # annotations and the 12-char container id; no shell involvement.
    try:
        proc = subprocess.Popen(  # noqa: S603  # nosec B603  # NOSONAR
            [
                "/usr/bin/python3",
                str(reader),
                str(sd),
                container_id,
                "--emit=socket",
                f"--annotations={annotations_json}",
            ],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=err_fh,
            stderr=err_fh,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        err_fh.close()
        _oci_state.log(f"terok-shield bridge hook: reader spawn failed: {exc}")
        return
    finally:
        # Popen dup'd the fd; the parent's copy is safe to close.
        err_fh.close()
    # Guard the pid-file write so a state-dir ENOSPC / EPERM doesn't
    # escape as an exception that fails container start — bridge is
    # opt-out; soft-fail everywhere.  If the write fails after the
    # child already started, stop it ourselves so we don't leak a
    # reader nobody tracks.
    try:
        pid_file.write_text(f"{proc.pid}\n")
    except OSError as exc:
        _oci_state.log(f"terok-shield bridge hook: failed to write reader.pid: {exc}")
        with contextlib.suppress(ProcessLookupError, OSError):
            # Signaling our own direct child from the same hook
            # invocation — proc.pid was just returned by Popen, no race
            # window, no PID recycle risk.
            os.kill(proc.pid, signal.SIGTERM)  # NOSONAR


def _reap_reader(sd: Path) -> None:
    """SIGTERM the NFLOG reader at poststop, SIGKILL if it lingers past 2 s.

    Validates the PID against the expected reader cmdline before
    sending signals — mirrors the ``_is_our_dnsmasq`` pattern in
    ``nft_hook``.  A recycled / stale PID with the same number would
    otherwise get SIGTERMed, potentially killing an unrelated user
    process.  If the PID doesn't match we unlink ``reader.pid`` and
    return quietly: nothing to reap.
    """
    pid_file = sd / _READER_PID_NAME
    if not pid_file.exists():
        return
    try:
        pid = int(pid_file.read_text().strip())
    except (OSError, ValueError):
        pid_file.unlink(missing_ok=True)
        return
    if not _is_our_reader(pid, sd):
        pid_file.unlink(missing_ok=True)
        return
    try:
        # PID validated by ``_is_our_reader`` cmdline check above.
        os.kill(pid, signal.SIGTERM)  # NOSONAR
    except ProcessLookupError:
        pid_file.unlink(missing_ok=True)
        return
    except OSError as exc:
        _oci_state.log(f"terok-shield bridge hook: reader SIGTERM failed: {exc}")
        pid_file.unlink(missing_ok=True)
        return

    for _ in range(_REAP_POLL_TICKS):
        time.sleep(_REAP_POLL_INTERVAL_S)
        if not _oci_state.pid_exists(pid):
            break
    else:
        with contextlib.suppress(ProcessLookupError, OSError):
            # Reader didn't exit within the grace window; force-kill
            # the same validated PID.
            os.kill(pid, signal.SIGKILL)  # NOSONAR
    pid_file.unlink(missing_ok=True)


def _reader_alive(pid_file: Path) -> bool:
    """``True`` only when ``reader.pid`` names a live reader process.

    Existence of the PID isn't enough — a recycled PID number would
    fool a pure ``_oci_state.pid_exists`` check, and we'd skip spawning a fresh
    reader while that unrelated process happily runs.  Use the cmdline
    identity guard.
    """
    try:
        pid = int(pid_file.read_text().strip())
    except (OSError, ValueError):
        return False
    if not _oci_state.pid_exists(pid):
        return False
    return _is_our_reader(pid, pid_file.parent)


def _is_our_reader(pid_int: int, sd: Path) -> bool:
    """``True`` if ``pid_int`` is the NFLOG reader we spawned for ``sd``.

    Reads ``/proc/{pid}/cmdline`` and compares to the invocation shape
    from ``_spawn_reader``.  Two signatures are accepted:

    * the outer Popen shape — ``python3 <reader.py> <sd> <container>
      --emit=socket [--annotations=…]``
    * the nsenter-exec'd self the reader produces when it re-enters
      its own namespaces (argv mutated but sd still encoded in an arg)

    Missing / unreadable cmdline maps to ``False``.  Lenient on
    ``argv[0]`` (accept any python binary path) to tolerate different
    distros and venv layouts.
    """
    try:
        raw = Path(f"/proc/{pid_int}/cmdline").read_bytes()
    except OSError:
        return False
    args = raw.rstrip(b"\x00").split(b"\x00")
    if len(args) < 4:
        return False
    script_bytes = str(_reader_script_path()).encode()
    sd_bytes = str(sd).encode()
    return args[0].endswith(b"python3") and args[1] == script_bytes and sd_bytes in args[2:]


def _reader_script_path() -> Path:
    """Return the on-disk path ``terok setup`` places the reader script at."""
    data_home = os.environ.get("XDG_DATA_HOME") or f"{os.environ.get('HOME', '')}/.local/share"
    return Path(data_home) / "terok-shield" / "nflog-reader.py"


def _session_bus_address() -> str | None:
    """Locate the operator's D-Bus session bus, or ``None`` for headless.

    Probes the *host* UID's runtime dir rather than the namespaced
    ``os.getuid()``: the hook runs in ``NS_ROOTLESS`` where our UID is
    0 but the real session bus lives at ``/run/user/<host-uid>/bus``.
    """
    addr = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    if addr:
        return addr
    uid = _oci_state.outer_host_uid()
    path = Path(f"/run/user/{uid}/bus")
    if path.exists():
        return f"unix:path={path}"
    return None


if __name__ == "__main__":  # pragma: no cover
    main()  # always returns None — see ``main`` docstring
