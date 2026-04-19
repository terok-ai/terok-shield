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

# These constants are intentionally duplicated from src/terok_shield/state.py
# so this script stays stdlib-only (no terok_shield imports).  Keep in sync:
#   _BUNDLE_VERSION  ↔  state.BUNDLE_VERSION
#   "ruleset.nft"    ↔  state.ruleset_path()
#   "dnsmasq.conf"   ↔  state.dnsmasq_conf_path()
#   "dnsmasq.pid"    ↔  state.dnsmasq_pid_path()
#   "container.id"   ↔  state.container_id_path()
#   "reader.pid"     ↔  state.reader_pid_path()
_ANN_STATE_DIR = "terok.shield.state_dir"
_ANN_VERSION = "terok.shield.version"
_BUNDLE_VERSION = 5
_TABLE = "inet terok_shield"

# ── Bridge-hook dispatch ──────────────────────────────
# Hook programs are dispatched by argv[0]: the nft + dnsmasq pair uses
# "terok-shield-hook"; the optional bridge pair uses
# "terok-shield-bridge-hook".  Both share this entrypoint script and are
# installed (or not) independently by `terok setup [--no-dbus-bridge]`.
_HOOK_NAME_NFT = "terok-shield-hook"
_HOOK_NAME_BRIDGE = "terok-shield-bridge-hook"

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
    """OCI hook entry point: dispatch by program name and stage."""
    _bootstrap_env()
    hook_name = Path(sys.argv[0]).name if sys.argv else _HOOK_NAME_NFT
    stage = sys.argv[1] if len(sys.argv) > 1 else "createRuntime"
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
        if hook_name == _HOOK_NAME_BRIDGE:
            return _bridge_main(oci, sd, stage, log_path)
        return _nft_main(oci, sd, stage, log_path)
    except Exception as exc:  # noqa: BLE001
        _log(f"terok-shield hook: {exc}", log_path)
        return 1


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
        (sd / "container.id").write_text(container_id[:12] + "\n")

    _createruntime(pid, sd)
    return 0


def _bridge_main(oci: dict, sd: Path, stage: str, log_path: Path) -> int:
    """Spawn or reap the per-container NFLOG reader for the clearance flow.

    Soft-fails on every error path: a missing reader script, an unreachable
    session bus, or a failed Popen all log and return 0 so the container
    still starts.  The clearance UI degrades gracefully to the pre-bridge
    behaviour (no events, no desktop notifications) in those cases.
    """
    if stage == "poststop":
        _reap_reader(sd)
        return 0
    if stage != "createRuntime":
        _log(f"terok-shield bridge hook: unknown stage {stage!r}", log_path)
        return 0  # unknown stage is a no-op for the optional bridge path

    container_id = str(oci.get("id") or "")[:12]
    if not container_id:
        _log("terok-shield bridge hook: missing container id — skipping reader", log_path)
        return 0

    _spawn_reader(sd, container_id)
    return 0


# ── OCI state parsing ──────────────────────────────────


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


# ── Stage handlers ─────────────────────────────────────


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

    ruleset = sd / "ruleset.nft"
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
    dnsmasq_conf = sd / "dnsmasq.conf"
    if not dnsmasq_conf.exists():
        return

    pid_file = sd / "dnsmasq.pid"
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
    pid_file = sd / "dnsmasq.pid"
    conf_path = sd / "dnsmasq.conf"
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


# ── Reader (per-container NFLOG → D-Bus emitter) ──────


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
    pid_file = sd / "reader.pid"
    if _reader_alive(pid_file):
        return  # idempotent respawn
    env = {**os.environ, "DBUS_SESSION_BUS_ADDRESS": bus}
    try:
        proc = subprocess.Popen(  # nosec B603
            ["/usr/bin/python3", str(reader), str(sd), container_id, "--emit=dbus"],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        _log(f"terok-shield bridge hook: reader spawn failed: {exc}")
        return
    pid_file.write_text(f"{proc.pid}\n")


def _reap_reader(sd: Path) -> None:
    """SIGTERM the NFLOG reader at poststop, SIGKILL if it lingers past 2 s."""
    pid_file = sd / "reader.pid"
    if not pid_file.exists():
        return
    try:
        pid = int(pid_file.read_text().strip())
    except (OSError, ValueError):
        pid_file.unlink(missing_ok=True)
        return
    try:
        os.kill(pid, signal.SIGTERM)
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
            os.kill(pid, signal.SIGKILL)
    pid_file.unlink(missing_ok=True)


def _reader_alive(pid_file: Path) -> bool:
    """Return True when ``reader.pid`` names a live process."""
    try:
        pid = int(pid_file.read_text().strip())
    except (OSError, ValueError):
        return False
    return _pid_exists(pid)


def _pid_exists(pid: int) -> bool:
    """Ask the kernel whether *pid* is still a running process."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        # EPERM means the process exists but we don't own it — treat as alive.
        return True
    return True


def _reader_script_path() -> Path:
    """Return the on-disk path ``terok setup`` places the reader script at."""
    data_home = os.environ.get("XDG_DATA_HOME") or f"{os.environ.get('HOME', '')}/.local/share"
    return Path(data_home) / "terok-shield" / "nflog-reader.py"


def _session_bus_address() -> str | None:
    """Locate the operator's D-Bus session bus, or return ``None`` for headless."""
    addr = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    if addr:
        return addr
    uid = os.getuid()
    path = Path(f"/run/user/{uid}/bus")
    if path.exists():
        return f"unix:path={path}"
    return None


# ── Namespace execution ────────────────────────────────


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
    try:
        result = subprocess.run(  # nosec B603
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


# ── Process identity ───────────────────────────────────


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
    if not args:
        return False
    exe = args[0]
    return (exe == b"dnsmasq" or exe.endswith(b"/dnsmasq")) and conf_arg in args


# ── Environment bootstrap ─────────────────────────────


def _bootstrap_env() -> None:
    """Ensure critical environment variables are set before running podman unshare.

    OCI hooks (crun/runc) may be invoked with a stripped environment — no HOME,
    no XDG_RUNTIME_DIR, and sometimes no PATH.  ``podman unshare`` reads
    ``/etc/subuid``, ``~/.config/containers/``, and the rootless podman socket
    via these variables.  Without them it exits 1 silently.

    Only sets variables that are absent; never overrides values the runtime did
    pass through.
    """
    uid = os.getuid()

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
