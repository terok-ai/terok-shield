#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0
"""OCI hook: apply pre-generated terok-shield nft ruleset.

Applies ``ruleset.nft`` (written by ``pre_start()``) and optionally starts
dnsmasq if ``dnsmasq.conf`` is present in the state directory.  Gateway
addresses are baked into the ruleset at generation time — no runtime
``/proc`` discovery needed.

Zero ``terok_shield.*`` imports — only ``python3`` (stdlib), ``podman``,
``nft``, ``nsenter``, and optionally ``dnsmasq`` are required.  This makes
the hook independent of any specific Python virtualenv or install method.

The hook is invoked by crun, which runs inside podman's rootless user
namespace (NS_ROOTLESS).  Inside NS_ROOTLESS ``os.getuid() == 0`` and
``CAP_NET_ADMIN`` is already available, so ``nsenter -n -t <pid>`` is used
directly.  When the hook is run from a normal shell (NS_INIT, uid != 0),
``podman unshare nsenter -n -t <pid>`` is used instead to enter NS_ROOTLESS
first — mirroring ``SubprocessRunner.nft_via_nsenter()`` in ``run.py``.
"""

import contextlib
import json
import os
import pwd
import shutil
import signal
import subprocess  # nosec B404
import sys
import time
from pathlib import Path

# These constants are intentionally duplicated from the terok_shield
# package so this script stays stdlib-only (no terok_shield imports).
# Keep in sync:
#   _BUNDLE_VERSION       ↔  state.BUNDLE_VERSION
#   _RULESET_NAME         ↔  state.ruleset_path()
#   _DNSMASQ_CONF_NAME    ↔  state.dnsmasq_conf_path()
#   _DNSMASQ_PID_NAME     ↔  state.dnsmasq_pid_path()
#   _CONTAINER_ID_NAME    ↔  state.container_id_path()
#   _READER_PID_NAME      ↔  state.reader_pid_path()
#   _reader_script_path() ↔  paths.reader_script_path()
# (``reader.log`` is bridge-local — no state.py counterpart.)
_ANN_STATE_DIR = "terok.shield.state_dir"
_ANN_VERSION = "terok.shield.version"
_BUNDLE_VERSION = 10
_TABLE = "inet terok_shield"
_RULESET_NAME = "ruleset.nft"
_DNSMASQ_CONF_NAME = "dnsmasq.conf"
_DNSMASQ_PID_NAME = "dnsmasq.pid"
_CONTAINER_ID_NAME = "container.id"
_READER_PID_NAME = "reader.pid"
_READER_LOG_NAME = "reader.log"

# ── Bridge-hook dispatch ──────────────────────────────
# Dispatch between the nft + dnsmasq pair and the optional bridge pair
# happens via an explicit ``--bridge`` token in the hook JSON ``args``
# (``args[1]`` in the JSON, ``sys.argv[1]`` after shebang rewriting).
# WORKAROUND(shebang-argv0-stripped): the kernel's shebang loader
# (``fs/binfmt_script.c``) substitutes the original ``argv[0]`` with the
# script path before ``env`` re-execs Python — so ``args[0]`` from the
# hook JSON (the conventional program name) is *not* visible to the
# entrypoint.  Dispatching by ``sys.argv[0].name`` would route both hook
# kinds to the same branch.  Remove the workaround if the entrypoint is
# ever compiled to a real binary (shebangs no longer apply).
_BRIDGE_DISPATCH_FLAG = "--bridge"

# SIGTERM→SIGKILL grace: how long to wait for the reader to exit cleanly
# after poststop sends SIGTERM.  10 × 0.2s poll intervals = 2s total.
_REAP_POLL_INTERVAL_S = 0.2
_REAP_POLL_TICKS = 10

# WORKAROUND(selinux-nft-stdin): nft runs as iptables_t (SELinux domain),
# which cannot read files in data_home_t (~/.local/share/…).  Piping the
# ruleset via stdin ("-f -") bypasses the file-read restriction — the hook
# process (not nft) opens the file.
# Remove when: SELinux policy grants nft read access to user state dirs,
# or state_dir moves to an nft-accessible location.


# ── Entry point ────────────────────────────────────────


def main() -> int:
    """OCI hook entry point: dispatch by explicit role flag and stage."""
    _bootstrap_env()
    is_bridge, stage = _parse_dispatch(sys.argv[1:])
    try:
        oci = json.load(sys.stdin)
    except ValueError as exc:
        _log(f"terok-shield hook: bad OCI state: {exc}")
        return 1

    sd = _state_dir_from_oci(oci)
    if sd is None:
        return 1

    # All subsequent errors go to <state_dir>/hook-error.log so they survive
    # even when the OCI runtime does not forward the hook's stderr.
    log_path = sd / "hook-error.log"

    try:
        if is_bridge:
            _bridge_main(oci, sd, stage, log_path)
            # The bridge path is soft-fail by contract: every failure mode
            # logs and returns normally.  Container start must never be
            # blocked by a missing reader / unreachable session bus / Popen
            # error — clearance degrades to "no events", nothing else.
            return 0
        return _nft_main(oci, sd, stage, log_path)
    except Exception as exc:  # noqa: BLE001
        _log(f"terok-shield hook: {exc}", log_path)
        return 1


def _parse_dispatch(argv_tail: list[str]) -> tuple[bool, str]:
    """Split the post-script argv into a bridge-flag and a stage name."""
    is_bridge = bool(argv_tail) and argv_tail[0] == _BRIDGE_DISPATCH_FLAG
    remaining = argv_tail[1:] if is_bridge else argv_tail
    stage = remaining[0] if remaining else "createRuntime"
    return is_bridge, stage


def _nft_main(oci: dict, sd: Path, stage: str, log_path: Path) -> int:
    """Apply the nft ruleset and (optionally) dnsmasq at the right stage."""
    # poststop cleanup must run regardless of bundle-version — a container that was
    # started before a terok-shield upgrade still needs its dnsmasq reaped on stop.
    if stage == "poststop":
        _poststop(sd)
        return 0
    if stage != "createRuntime":
        _log(f"terok-shield hook: unknown stage {stage!r}", log_path)
        return 1

    ann = oci.get("annotations") or {}
    ver = ann.get(_ANN_VERSION, "")
    if not ver or str(ver) != str(_BUNDLE_VERSION):
        _log(
            f"terok-shield hook: bundle version {ver!r} != {_BUNDLE_VERSION}. Re-run pre_start().",
            log_path,
        )
        return 1

    pid = str(oci.get("pid") or "")
    if not pid:
        _log("terok-shield hook: missing pid in OCI state", log_path)
        return 1

    # Persist container ID for D-Bus bridge bus-name derivation.
    # The OCI state includes "id" (full 64-char hex); store the short form.
    container_id = str(oci.get("id") or "")
    if container_id:
        (sd / _CONTAINER_ID_NAME).write_text(container_id[:12] + "\n")

    _createruntime(pid, sd)
    return 0


def _bridge_main(oci: dict, sd: Path, stage: str, log_path: Path) -> None:
    """Spawn or reap the per-container NFLOG reader for the clearance flow.

    Soft-fails on every error path: a missing reader script, an unreachable
    session bus, or a failed Popen all log and return normally so the
    container still starts.  The clearance UI degrades gracefully to the
    pre-bridge behaviour (no events, no desktop notifications) in those
    cases.

    Returns ``None`` — caller (``main``) supplies the ``0`` exit code
    unconditionally for the bridge path.  A different return value per
    outcome would suggest container start is contingent on this function
    succeeding; it isn't.
    """
    if stage == "poststop":
        _reap_reader(sd)
        return
    if stage != "createRuntime":
        _log(f"terok-shield bridge hook: unknown stage {stage!r}", log_path)
        return  # unknown stage is a no-op for the optional bridge path

    container_id = str(oci.get("id") or "")[:12]
    if not container_id:
        _log("terok-shield bridge hook: missing container id — skipping reader", log_path)
        return

    _spawn_reader(sd, container_id)


# ── Nft hook: ruleset + dnsmasq ────────────────────────
#
# Everything below this banner is exclusive to the nft+dnsmasq path.
# A reader tracing ``_nft_main`` stays in contiguous territory until the
# next banner.


def _createruntime(pid: str, sd: Path) -> None:
    """Apply the pre-generated ruleset and optionally start dnsmasq."""
    # Verify the target PID's network namespace file exists before invoking nsenter.
    # Use stat() rather than exists(): Path.exists() silently swallows PermissionError
    # in Python 3.14+, whereas stat() reliably raises it.  PermissionError means the
    # file is present but we can't read it (non-root caller) — that's fine, proceed.
    # Any other OSError (FileNotFoundError, etc.) means the PID is gone.
    ns_net = Path(f"/proc/{pid}/ns/net")
    try:
        ns_net.stat()
    except PermissionError:
        pass  # Namespace file exists but cannot be stat'd from this context — proceed.
    except OSError:
        raise RuntimeError(f"network namespace file missing for pid {pid}: {ns_net}")

    ruleset = sd / _RULESET_NAME
    if not ruleset.exists():
        raise RuntimeError(f"ruleset.nft not found: {ruleset}")
    nft = _find_nft()
    # WORKAROUND(selinux-nft-stdin): pipe ruleset via stdin; see module header.
    _nsenter(pid, nft, "-f", "-", stdin=ruleset.read_text())

    # Gateway addresses are baked into ruleset.nft by pre_start() —
    # no /proc discovery or dynamic nft set population needed.

    # Start per-container dnsmasq if config was pre-generated by pre_start()
    _start_container_dnsmasq(pid, sd)


def _start_container_dnsmasq(pid: str, sd: Path) -> None:
    """Launch dnsmasq in the container's netns and verify it started.

    No-op if ``dnsmasq.conf`` is absent (pre_start did not enable dnsmasq).
    resolv.conf is pre-written by pre_start and bind-mounted :ro, so DNS
    already points to 127.0.0.1 before the hook runs.

    Mirrors ``terok_shield.dns.dnsmasq.launch()`` defensive measures:
    clears stale PID file, then verifies the new PID file and process
    identity after start.
    """
    dnsmasq_conf = sd / _DNSMASQ_CONF_NAME
    if not dnsmasq_conf.exists():
        return

    pid_file = sd / _DNSMASQ_PID_NAME
    # Idempotent: if a dnsmasq is already running against our conf (because the
    # hook fired twice — restart, re-dispatch, sibling hook re-entry, etc.),
    # don't try to bind port 53 again.  Verifying pid + conf-arg avoids hitting
    # an unrelated process that happens to hold the recycled PID.
    if _our_dnsmasq_alive(pid_file, dnsmasq_conf):
        return

    # Remove stale PID file so the post-launch check is not fooled
    # by a leftover from a previous run (mirrors dnsmasq.launch()).
    try:
        pid_file.unlink()
    except OSError:
        pass

    _nsenter(pid, _find_dnsmasq(), f"--conf-file={dnsmasq_conf}")

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

    Verifies PID identity against ``/proc/{pid}/cmdline`` before signalling
    to avoid hitting an unrelated process when the original dnsmasq PID is
    recycled after container stop.
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
        try:
            pid_file.unlink()
        except OSError:
            pass
        return
    try:
        os.kill(pid_int, signal.SIGTERM)
    except OSError:
        pass


def _our_dnsmasq_alive(pid_file: Path, conf_path: Path) -> bool:
    """Return True when ``pid_file`` names a live dnsmasq using ``conf_path``."""
    try:
        pid_int = int(pid_file.read_text().strip())
    except (OSError, ValueError):
        return False
    return _is_our_dnsmasq(pid_int, conf_path)


def _is_our_dnsmasq(pid_int: int, conf_path: Path) -> bool:
    """Return True if pid_int is a dnsmasq process using our conf file.

    Parses ``/proc/{pid}/cmdline`` as a NUL-separated argv vector.
    Requires argv[0] to be the dnsmasq binary (exact name or absolute path)
    and ``--conf-file=<our-conf>`` to be present as a separate argument.
    Mirrors ``terok_shield.dnsmasq._is_our_dnsmasq()`` without any imports.
    """
    conf_arg = b"--conf-file=" + str(conf_path).encode()
    try:
        raw = Path(f"/proc/{pid_int}/cmdline").read_bytes()
    except OSError:
        return False
    args = raw.rstrip(b"\x00").split(b"\x00")
    if not args:  # pragma: no cover — bytes.split() never returns an empty list
        return False
    exe = args[0]
    return (exe == b"dnsmasq" or exe.endswith(b"/dnsmasq")) and conf_arg in args


# ── Bridge hook: reader lifecycle ──────────────────────
#
# Everything below this banner is exclusive to the bridge path.
# A reader tracing ``_bridge_main`` stays in contiguous territory until the
# next banner.


def _spawn_reader(sd: Path, container_id: str) -> None:
    """Start the NFLOG reader for *container_id* as a detached child.

    No-op when the reader script is missing (``--no-dbus-bridge`` installs)
    or the operator's session bus is unreachable (headless host).  Safe to
    call repeatedly — a second call while the prior reader is still alive
    is treated as a no-op via the ``reader.pid`` liveness check.
    """
    reader = _reader_script_path()
    if not reader.exists():
        _log(f"terok-shield bridge hook: nflog-reader missing at {reader} — rerun `terok setup`")
        return
    bus = _session_bus_address()
    if bus is None:
        _log("terok-shield bridge hook: no session bus reachable — skipping reader")
        return
    pid_file = sd / _READER_PID_NAME
    if _reader_alive(pid_file):
        return  # idempotent respawn
    env = {**os.environ, "DBUS_SESSION_BUS_ADDRESS": bus}
    # Keep the reader's stderr capturable — a silent /dev/null here means any
    # startup crash (nsenter failure, missing binary, NFLOG bind denial) leaves
    # the operator with a live pid file and nothing to diagnose from.
    err_log = sd / _READER_LOG_NAME
    try:
        err_fh = err_log.open("ab")
    except OSError as exc:
        _log(f"terok-shield bridge hook: cannot open reader.log: {exc}")
        return
    # argv is a fixed literal plus paths we constructed from validated OCI
    # annotations (shield's own pre_start wrote them) and the 12-char
    # container id we already pulled out of the OCI state earlier in this
    # hook.  No shell involvement, no untrusted tokens.
    try:
        proc = subprocess.Popen(  # noqa: S603  # nosec B603  # NOSONAR(pythonsecurity:S6350)
            ["/usr/bin/python3", str(reader), str(sd), container_id, "--emit=socket"],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=err_fh,
            stderr=err_fh,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        err_fh.close()
        _log(f"terok-shield bridge hook: reader spawn failed: {exc}")
        return
    finally:
        # Popen dup'd the fd; the parent's copy is safe to close.
        err_fh.close()
    # Guard the pid-file write so a state-dir ENOSPC / EPERM doesn't escape
    # as an exception that fails container start — bridge is opt-out; soft-
    # fail everywhere.  If the write fails after the child already started,
    # stop it ourselves so we don't leak a reader nobody tracks.
    try:
        pid_file.write_text(f"{proc.pid}\n")
    except OSError as exc:
        _log(f"terok-shield bridge hook: failed to write reader.pid: {exc}")
        with contextlib.suppress(ProcessLookupError, OSError):
            # Signaling our own direct child from the same hook invocation —
            # proc.pid was just returned by Popen, no race window, no PID
            # recycle risk.
            os.kill(proc.pid, signal.SIGTERM)  # NOSONAR(python:S4828)


def _reap_reader(sd: Path) -> None:
    """SIGTERM the NFLOG reader at poststop, SIGKILL if it lingers past 2 s.

    Validates the PID against the expected reader cmdline before sending
    signals — mirrors the ``_is_our_dnsmasq`` pattern elsewhere in this
    file.  A recycled / stale PID with the same number would otherwise get
    SIGTERMed here, potentially killing an unrelated user process.  If the
    PID doesn't match we unlink ``reader.pid`` and return quietly: nothing
    to reap.
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
        # PID validated by `_is_our_reader` cmdline check above — this is the
        # reader we spawned, not a random recycled PID.
        os.kill(pid, signal.SIGTERM)  # NOSONAR(python:S4828)
    except ProcessLookupError:
        pid_file.unlink(missing_ok=True)
        return
    except OSError as exc:
        _log(f"terok-shield bridge hook: reader SIGTERM failed: {exc}")
        pid_file.unlink(missing_ok=True)
        return

    for _ in range(_REAP_POLL_TICKS):
        time.sleep(_REAP_POLL_INTERVAL_S)
        if not _pid_exists(pid):
            break
    else:
        with contextlib.suppress(ProcessLookupError, OSError):
            # Reader we identified above didn't exit within the grace window;
            # force-kill the same validated PID.
            os.kill(pid, signal.SIGKILL)  # NOSONAR(python:S4828)
    pid_file.unlink(missing_ok=True)


def _reader_alive(pid_file: Path) -> bool:
    """Return True only when ``reader.pid`` names a *live reader* process.

    Existence of the PID isn't enough — a recycled PID number would fool a
    pure ``_pid_exists`` check, and we'd skip spawning a fresh reader while
    that unrelated process happily runs.  Use the cmdline identity guard.
    """
    try:
        pid = int(pid_file.read_text().strip())
    except (OSError, ValueError):
        return False
    if not _pid_exists(pid):
        return False
    return _is_our_reader(pid, pid_file.parent)


def _is_our_reader(pid_int: int, sd: Path) -> bool:
    """Return True if ``pid_int`` is the NFLOG reader we spawned for ``sd``.

    Reads ``/proc/{pid}/cmdline`` and compares to the invocation shape from
    ``_spawn_reader``.  Two signatures are accepted:

    * the outer Popen shape — ``python3 <reader.py> <sd> <container> --emit=socket``
    * the nsenter-exec'd self we produce when the reader re-enters its own
      namespaces (argv mutated but sd still encoded in an arg)

    Missing / unreadable cmdline maps to ``False``.  Lenient on argv[0]
    (accept any python binary path) to tolerate different distros and
    venv layouts.
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
    """Locate the operator's D-Bus session bus, or return ``None`` for headless.

    Probes the *host* UID's runtime dir rather than the namespaced ``os.getuid()``:
    the hook runs in ``NS_ROOTLESS`` where our UID is 0 but the real session
    bus lives at ``/run/user/<host-uid>/bus``.
    """
    addr = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    if addr:
        return addr
    uid = _outer_host_uid()
    path = Path(f"/run/user/{uid}/bus")
    if path.exists():
        return f"unix:path={path}"
    return None


# ── Shared infrastructure ──────────────────────────────
#
# OCI state parsing, namespace execution, PID checks, environment
# bootstrap.  Used by both hook kinds.


def _state_dir_from_oci(oci: object) -> Path | None:
    """Extract the ``terok.shield.state_dir`` annotation as an absolute Path.

    Returns ``None`` (and logs) on any validation failure so callers can
    early-exit without hand-written boilerplate.
    """
    if not isinstance(oci, dict):
        _log("terok-shield hook: OCI state must be a JSON object")
        return None
    ann = oci.get("annotations") or {}
    if not isinstance(ann, dict):
        _log("terok-shield hook: annotations must be a JSON object")
        return None
    sd_str = ann.get(_ANN_STATE_DIR, "")
    if not sd_str:
        _log("terok-shield hook: missing state_dir annotation")
        return None
    try:
        path = Path(sd_str)
        if not path.is_absolute():
            raise ValueError(f"state_dir must be absolute: {sd_str!r}")
        return path.resolve()
    except (TypeError, ValueError, OSError) as exc:
        _log(f"terok-shield hook: invalid state_dir: {exc}")
        return None


def _nsenter(pid: str, *cmd: str, stdin: str | None = None) -> None:
    """Run *cmd* inside the container's network namespace.

    Two execution contexts are handled automatically:

    **OCI hook context (crun invokes the hook)** — crun runs inside podman's
    rootless user namespace (NS_ROOTLESS, where ``os.getuid() == 0`` and
    ``CAP_NET_ADMIN`` is available).  The hook inherits that namespace, so
    ``nsenter -n -t <pid>`` is sufficient: no ``podman unshare`` is needed and
    calling it from NS_ROOTLESS would fail (cannot nest into the same namespace).

    **Shell / manual invocation context** — the caller is in the initial user
    namespace (NS_INIT, uid != 0, no elevated capabilities).  ``podman unshare``
    enters NS_ROOTLESS first to gain ``CAP_NET_ADMIN``, then ``nsenter -n``
    enters the container's network namespace.  This mirrors
    ``SubprocessRunner.nft_via_nsenter()`` in run.py.

    Captures both stdout and stderr — some nft versions write errors to stdout.
    """
    if os.getuid() == 0:
        # Already in NS_ROOTLESS (crun hook context): CAP_NET_ADMIN is available.
        ns_cmd = [_find_nsenter(), "-n", "-t", pid, "--", *cmd]
    else:
        # In NS_INIT (shell): enter NS_ROOTLESS first via podman unshare.
        ns_cmd = [_find_podman(), "unshare", _find_nsenter(), "-n", "-t", pid, "--", *cmd]
    # ns_cmd is built from _find_*() resolved binary paths and the container
    # PID (already validated as a bare integer-like string when the hook
    # parsed OCI state).  No shell involvement, no untrusted tokens.
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603  # NOSONAR(pythonsecurity:S6350)
            ns_cmd,
            input=stdin,
            text=True,
            capture_output=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"nsenter command timed out after 30 s: cmd={cmd!r}")
    if result.returncode != 0:
        # Combine stdout and stderr — some nft versions write errors to stdout.
        combined = (result.stderr + result.stdout).strip()
        raise RuntimeError(
            f"nsenter command failed (exit {result.returncode}) cmd={cmd!r}"
            + (f":\n{combined}" if combined else " (no output)")
        )


def _pid_exists(pid: int) -> bool:
    """Ask the kernel whether *pid* is still a running process."""
    try:
        # Signal 0 is an existence probe — it never delivers a signal, only
        # triggers the kernel's PID-validity / permission check.
        os.kill(pid, 0)  # NOSONAR(python:S4828)
    except ProcessLookupError:
        return False
    except OSError:
        # EPERM means the process exists but we don't own it — treat as alive.
        return True
    return True


def _bootstrap_env() -> None:
    """Ensure critical environment variables are set before running podman unshare.

    OCI hooks (crun/runc) may be invoked with a stripped environment — no HOME,
    no XDG_RUNTIME_DIR, and sometimes no PATH.  ``podman unshare`` reads
    ``/etc/subuid``, ``~/.config/containers/``, and the rootless podman socket
    via these variables.  Without them it exits 1 silently.

    Under rootless podman, the hook runs inside ``NS_ROOTLESS`` — ``os.getuid()``
    is ``0`` (mapped from the invoking operator's host UID), so naively
    resolving resources as if that were actually root points at ``/root`` /
    ``/run/user/0`` instead of the operator's real home / session.
    ``_outer_host_uid()`` parses ``/proc/self/uid_map`` to recover the host UID
    and the resolution uses that throughout.

    Only sets variables that are absent; never overrides values the runtime did
    pass through.
    """
    uid = _outer_host_uid()

    if not os.environ.get("HOME"):
        try:
            home = pwd.getpwuid(uid).pw_dir
        except KeyError:
            home = "/root" if uid == 0 else f"/home/{uid}"
        os.environ["HOME"] = home

    if not os.environ.get("XDG_RUNTIME_DIR"):
        os.environ["XDG_RUNTIME_DIR"] = f"/run/user/{uid}"

    if not os.environ.get("PATH"):
        os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def _outer_host_uid() -> int:
    """Return the invoking operator's host UID, even from inside ``NS_ROOTLESS``.

    Parses ``/proc/self/uid_map`` to find the outer-side UID that the current
    in-namespace UID maps to.  Each map line has the shape
    ``<inner_start> <outer_start> <length>`` — we pick the mapping whose inner
    range covers ``os.getuid()`` and project through it.

    Falls back to ``os.getuid()`` on any parse trouble (init userns, no
    uid_map, unreadable, unexpected format) — that path is valid for non-
    rootless contexts where there's no userns layer to see through.
    """
    my_uid = os.getuid()
    try:
        raw = Path("/proc/self/uid_map").read_text()
    except OSError:
        return my_uid
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        try:
            inner_start = int(parts[0])
            outer_start = int(parts[1])
            length = int(parts[2])
        except ValueError:
            continue
        if inner_start <= my_uid < inner_start + length:
            return outer_start + (my_uid - inner_start)
    return my_uid


# ── Binary finders ─────────────────────────────────────


def _find_podman() -> str:
    """Return the path to the podman binary, falling back to /usr/bin/podman."""
    return shutil.which("podman") or "/usr/bin/podman"


def _find_nsenter() -> str:
    """Return the path to the nsenter binary, falling back to /usr/bin/nsenter."""
    return shutil.which("nsenter") or "/usr/bin/nsenter"


def _find_nft() -> str:
    """Return the path to the nft binary, falling back to /usr/sbin/nft."""
    return shutil.which("nft") or "/usr/sbin/nft"


def _find_dnsmasq() -> str:
    """Return the path to the dnsmasq binary, falling back to /usr/sbin/dnsmasq."""
    return shutil.which("dnsmasq") or "/usr/sbin/dnsmasq"


# ── Logging ────────────────────────────────────────────


def _log(msg: str, log_path: Path | None = None) -> None:
    """Write *msg* to stderr and to a persistent log file (best-effort).

    The OCI runtime (crun/runc) typically swallows hook stderr.  Writing to a
    file in the state directory (or /tmp as fallback) makes errors visible.
    """
    print(msg, file=sys.stderr)
    path = log_path or Path("/tmp/terok-hook-error.log")  # nosec B108
    try:
        with path.open("a") as f:
            f.write(f"{msg}\n")
    except OSError:
        pass


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
