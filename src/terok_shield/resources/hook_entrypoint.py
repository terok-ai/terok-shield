#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0
"""OCI hook: apply pre-generated terok-shield nft ruleset.

Applies ``ruleset.nft`` (written by ``pre_start()``), discovers the container
gateway dynamically from ``/proc/{pid}/net/route``, and optionally starts
dnsmasq if ``dnsmasq.conf`` is present in the state directory.

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

import ipaddress
import json
import os
import pwd
import shutil
import signal
import socket
import struct
import subprocess  # nosec B404
import sys
from pathlib import Path

# These constants are intentionally duplicated from src/terok_shield/state.py
# so this script stays stdlib-only (no terok_shield imports).  Keep in sync:
#   _BUNDLE_VERSION  ↔  state.BUNDLE_VERSION
#   "ruleset.nft"    ↔  state.ruleset_path()
#   "gateway"        ↔  state.gateway_path()
#   "gateway_v6"     ↔  state.gateway_v6_path()
#   "dnsmasq.conf"   ↔  state.dnsmasq_conf_path()
#   "dnsmasq.pid"    ↔  state.dnsmasq_pid_path()
#   "container.id"   ↔  state.container_id_path()
_ANN_STATE_DIR = "terok.shield.state_dir"
_ANN_VERSION = "terok.shield.version"
_BUNDLE_VERSION = 4
_TABLE = "inet terok_shield"

# WORKAROUND(selinux-nft-stdin): nft runs as iptables_t (SELinux domain),
# which cannot read files in data_home_t (~/.local/share/…).  Piping the
# ruleset via stdin ("-f -") bypasses the file-read restriction — the hook
# process (not nft) opens the file.
# Remove when: SELinux policy grants nft read access to user state dirs,
# or state_dir moves to an nft-accessible location.


# ── Entry point ────────────────────────────────────────


def main() -> int:
    """OCI hook entry point: dispatch to createRuntime or poststop handler."""
    _bootstrap_env()
    stage = sys.argv[1] if len(sys.argv) > 1 else "createRuntime"
    try:
        oci = json.load(sys.stdin)
    except ValueError as exc:
        _log(f"terok-shield hook: bad OCI state: {exc}")
        return 1

    if not isinstance(oci, dict):
        _log("terok-shield hook: OCI state must be a JSON object")
        return 1

    ann = oci.get("annotations", {})
    if not isinstance(ann, dict):
        _log("terok-shield hook: annotations must be a JSON object")
        return 1

    sd_str = ann.get(_ANN_STATE_DIR, "")
    if not sd_str:
        _log("terok-shield hook: missing state_dir annotation")
        return 1
    try:
        _p = Path(sd_str)
        if not _p.is_absolute():
            raise ValueError(f"state_dir must be absolute: {sd_str!r}")
        sd = _p.resolve()
    except (TypeError, ValueError, OSError) as exc:
        _log(f"terok-shield hook: invalid state_dir: {exc}")
        return 1

    # All subsequent errors go to <state_dir>/hook-error.log so they survive
    # even when the OCI runtime does not forward the hook's stderr.
    log_path = sd / "hook-error.log"

    # poststop cleanup must run regardless of bundle-version — a container that was
    # started before a terok-shield upgrade still needs its dnsmasq reaped on stop.
    try:
        if stage == "poststop":
            _poststop(sd)
            return 0
        if stage != "createRuntime":
            _log(f"terok-shield hook: unknown stage {stage!r}", log_path)
            return 1
    except Exception as exc:  # noqa: BLE001
        _log(f"terok-shield hook: {exc}", log_path)
        return 1

    ver = ann.get(_ANN_VERSION, "")
    if not ver or str(ver) != str(_BUNDLE_VERSION):
        _log(
            f"terok-shield hook: bundle version {ver!r} != {_BUNDLE_VERSION}. Re-run pre_start().",
            log_path,
        )
        return 1
    try:
        pid = str(oci.get("pid") or "")
        if not pid:
            _log("terok-shield hook: missing pid in OCI state", log_path)
            return 1

        # Persist container ID for D-Bus bridge bus name derivation.
        # The OCI state includes "id" (full 64-char hex); store the short form.
        container_id = str(oci.get("id") or "")
        if container_id:
            (sd / "container.id").write_text(container_id[:12] + "\n")

        _createruntime(pid, sd)
    except Exception as exc:  # noqa: BLE001
        _log(f"terok-shield hook: {exc}", log_path)
        return 1
    return 0


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

    # Discover gateways from routing tables, persist, and populate nft sets.
    # Clear any stale files from a previous run so shield_up() doesn't
    # repopulate the wrong gateway into a reused state directory.
    for gw, file_name, set_name in (
        (_read_gateway(pid), "gateway", "gateway_v4"),
        (_read_gateway_v6(pid), "gateway_v6", "gateway_v6"),
    ):
        gw_file = sd / file_name
        if gw:
            gw_file.write_text(f"{gw}\n")
            _nsenter(pid, nft, "add", "element", _TABLE, set_name, f"{{ {gw} }}")
        else:
            try:
                gw_file.unlink()
            except OSError:
                pass

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


# ── Gateway discovery ──────────────────────────────────


def _read_gateway(pid: str) -> str:
    """Read the default IPv4 gateway from the container's routing table.

    Parses ``/proc/{pid}/net/route`` (the kernel routing table for the
    container's network namespace).  Returns an empty string when no default
    route is present (e.g. pasta mode) or when parsing fails — fail-closed:
    the nft ruleset is still applied, gateway sets stay empty.
    """
    try:
        for line in Path(f"/proc/{pid}/net/route").read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 3 and fields[1] == "00000000":
                gw = socket.inet_ntoa(struct.pack("=I", int(fields[2], 16)))
                ipaddress.ip_address(gw)  # validate — raises ValueError if malformed
                return gw
    except (OSError, ValueError, struct.error):
        pass
    return ""


def _read_gateway_v6(pid: str) -> str:
    """Read the default IPv6 gateway from the container's routing table.

    Parses ``/proc/{pid}/net/ipv6_route``.  Each line has 10 space-separated
    hex fields; the default route has dest_net=32 zeros and prefix_len=00.
    The nexthop (field index 4) is a 128-bit address stored as 32 hex chars.
    Returns an empty string when no default route is present or parsing fails.
    """
    try:
        for line in Path(f"/proc/{pid}/net/ipv6_route").read_text().splitlines():
            fields = line.split()
            if len(fields) >= 5 and fields[0] == "0" * 32 and fields[1] == "00":
                addr = ipaddress.IPv6Address(bytes.fromhex(fields[4]))
                if not addr.is_unspecified:
                    return addr.compressed
    except (OSError, ValueError):
        pass
    return ""


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
