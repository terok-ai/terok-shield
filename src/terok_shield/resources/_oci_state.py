# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared OCI-hook ballast — used by both ``nft_hook`` and ``reader_hook``.

This module is shipped verbatim alongside the two role-specific hook
scripts and imported by them at runtime.  The role scripts add
``Path(__file__).parent`` to ``sys.path`` (Python does this implicitly
when ``python3 script.py`` is invoked, but the relative-import contract
is what the isolation test checks against), and from there ``from
_oci_state import …`` resolves to this file.

Stdlib-only by design (audited by ``test_hook_entrypoint_isolation``):
the OCI runtime executes us with ``/usr/bin/python3`` outside any
virtualenv, so a dependency on ``terok_shield`` would fail to import.

Keep in sync with the package-side definitions:

* ``BUNDLE_VERSION``     ↔ ``terok_shield.state.BUNDLE_VERSION``
* ``ANN_STATE_DIR``      ↔ ``terok_shield.config.ANNOTATION_STATE_DIR_KEY``
* ``ANN_VERSION``        ↔ ``terok_shield.config.ANNOTATION_VERSION_KEY``
* ``META_PATH_FILE_NAME`` ↔ ``terok_shield.state.meta_path_file``
"""

from __future__ import annotations

import json
import os
import pwd
import shutil
import stat
import subprocess  # nosec B404
import sys
from pathlib import Path

# ── Annotation contract ──────────────────────────────────

ANN_STATE_DIR = "terok.shield.state_dir"
"""OCI annotation carrying the per-container shield state directory."""

ANN_VERSION = "terok.shield.version"
"""OCI annotation carrying the bundle version this container was prepared with."""

BUNDLE_VERSION = 12
"""Wire-protocol version for the hook ↔ pre_start state-bundle contract.

Bumped whenever the on-disk file layout, the hook → reader argv
shape, or the wire payload changes incompatibly.  The nft hook hard-
fails on a version mismatch — operator must re-run ``terok setup``.

v12: the createRuntime bridge hook persists the orchestrator's
``dossier.meta_path`` annotation as ``state_dir/meta_path`` (a
single-line pointer) so host-side ``Shield.up()`` / ``Shield.down()``
can resolve dossiers from the same task-meta JSON the reader merges
on every block emit.  Single source of truth: the orchestrator's
meta JSON.  No snapshot file, no second copy of project/task IDs;
all dossier consumers project the live JSON to ``{project, task,
name}``.
"""

META_PATH_FILE_NAME = "meta_path"
"""Per-container pointer to the orchestrator's wire-dossier JSON.

A single-line text file.  The bridge ``createRuntime`` hook writes
it from the ``dossier.meta_path`` OCI annotation; ``Shield.up()`` /
``Shield.down()`` and the per-container reader both follow it to
the orchestrator's dossier file and forward its contents onto the
wire verbatim.  Empty / absent file degrades gracefully to a bare
container name on the wire — same shape as a standalone
non-orchestrator container.

**Contract.**  The file at ``meta_path`` is JSON, ``{str: str}``,
in *wire-dossier shape* (``project`` / ``task`` / ``name`` keys
the clearance UI renders directly).  This is deliberate: the
file's audience is shield consumers, so it speaks the wire's
language — no translation table, no projection, no orchestrator-
internal storage keys leaking through.  Orchestrator bookkeeping
lives elsewhere.
"""

#: System paths that must never appear as state_dir prefixes — even a
#: well-formed OCI annotation pointing here means something is wrong
#: upstream and we'd rather hard-fail the container start.  These are
#: root-owned on the host; in NS_ROOTLESS the per-uid mapping makes
#: them appear as overflow uid (typically 65534), so the ownership
#: check downstream catches them too — but failing fast on the prefix
#: alone gives a cleaner error message and saves a stat.
#:
#: ``/tmp`` and ``/var/tmp`` are intentionally **not** on this list:
#: they're world-writable but sticky-bit, so attacker-planted entries
#: below them are owned by the attacker and the ownership check
#: rejects them.  Excluding them here keeps pytest's ``tmp_path``
#: usable in tests.
_SENSITIVE_PREFIXES = (
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/boot",
    "/root",
)


# ── OCI state parsing ────────────────────────────────────


def state_dir_from_oci(oci: object) -> Path | None:
    """Extract and validate the ``terok.shield.state_dir`` annotation.

    Returns the resolved Path on success, ``None`` (and logs) on any
    validation failure so callers can early-exit without hand-written
    boilerplate.

    The OCI annotation is treated as adversarial input: even when the
    orchestrator we expect (terok) is the one that wrote it, a defence-
    in-depth shape lets us reject paths that look nothing like a real
    state bundle — sensitive system directories, world-writable
    locations, leaf symlinks (TOCTOU rotation surface), or paths the
    current user doesn't actually own.  Any of these would let a
    crafted annotation steer the hook into reading / writing files
    outside its intended bundle.
    """
    if not isinstance(oci, dict):
        log("terok-shield hook: OCI state must be a JSON object")
        return None
    ann = oci.get("annotations") or {}
    if not isinstance(ann, dict):
        log("terok-shield hook: annotations must be a JSON object")
        return None
    sd_str = ann.get(ANN_STATE_DIR, "")
    if not sd_str:
        log("terok-shield hook: missing state_dir annotation")
        return None
    try:
        path = Path(sd_str)
    except (TypeError, ValueError) as exc:
        log(f"terok-shield hook: invalid state_dir: {exc}")
        return None
    if not path.is_absolute():
        log(f"terok-shield hook: state_dir must be absolute: {sd_str!r}")
        return None

    # Reject obvious sensitive prefixes before resolve() — this catches
    # the easy case where the raw annotation already names ``/etc/...``
    # and saves an unnecessary stat.  ``resolve()`` later catches the
    # symlinked variants.
    if _under_sensitive_prefix(path):
        log(f"terok-shield hook: state_dir refuses sensitive location: {path}")
        return None

    # ``resolve(strict=True)`` requires the directory already exists —
    # the hook never creates state_dir; pre_start is the only writer.
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        log(f"terok-shield hook: state_dir does not exist or unreadable: {exc}")
        return None

    if _under_sensitive_prefix(resolved):
        log(f"terok-shield hook: resolved state_dir under sensitive location: {resolved}")
        return None

    # The annotation pointing at a leaf symlink is a TOCTOU red flag —
    # the symlink could rotate between resolve() and the hook's
    # subsequent open() / write_text() calls.  pre_start always writes
    # a real directory; refuse the indirection.  ``resolve(strict=True)``
    # already followed any symlink at the leaf, so we lstat the original
    # un-resolved annotation path here — that's where a symlink would
    # actually appear on disk.
    try:
        st = path.lstat()
    except OSError as exc:
        log(f"terok-shield hook: state_dir lstat failed: {exc}")
        return None

    if stat.S_ISLNK(st.st_mode):
        log(f"terok-shield hook: state_dir must not be a symlink: {sd_str!r}")
        return None
    if not stat.S_ISDIR(st.st_mode):
        log(f"terok-shield hook: state_dir is not a directory: {resolved}")
        return None

    # Ownership check: in NS_ROOTLESS the operator's host UID maps to
    # in-namespace UID 0; files outside the user's uid_map range
    # (e.g. host-root-owned files) appear as overflow uid (typically
    # 65534) and are rejected here.  In init userns, ``geteuid()`` is
    # the actual operator UID and the same equality check applies.
    if st.st_uid != os.geteuid():
        log(
            f"terok-shield hook: state_dir not owned by current uid "
            f"(uid={st.st_uid} != euid={os.geteuid()}): {resolved}"
        )
        return None

    # Group- or world-writable directories let any local peer drop a
    # ``ruleset.nft`` for the hook to apply with CAP_NET_ADMIN.
    if st.st_mode & 0o022:
        log(f"terok-shield hook: state_dir must not be group/world-writable: {resolved}")
        return None

    return resolved


def _under_sensitive_prefix(path: Path) -> bool:
    """``True`` if *path* lives under one of ``_SENSITIVE_PREFIXES``."""
    s = str(path)
    return any(s == prefix or s.startswith(prefix + "/") for prefix in _SENSITIVE_PREFIXES)


# ── Dossier resolution ──────────────────────────────────


def persist_meta_path(state_dir: Path, meta_path: str) -> None:
    """Write *meta_path* to ``state_dir/meta_path``, soft-fail.

    The bridge ``createRuntime`` hook calls this with the value of the
    orchestrator's ``dossier.meta_path`` OCI annotation — a single-line
    pointer is everything the host needs to resolve dossiers later
    (the meta JSON itself is the single source of truth for ``project``,
    ``task``, ``name``).  Empty *meta_path* is a no-op: standalone
    containers without an orchestrator have nothing to point at, and a
    missing file degrades downstream to a bare container name.
    """
    if not meta_path:
        return
    try:
        (state_dir / META_PATH_FILE_NAME).write_text(meta_path)
    except OSError as exc:
        log(f"terok-shield bridge hook: meta_path persist failed: {exc}")


def read_meta_path(state_dir: Path) -> str:
    """Return the persisted ``meta_path`` for *state_dir*, or ``""`` if absent."""
    try:
        return (state_dir / META_PATH_FILE_NAME).read_text().strip()
    except OSError:
        return ""


def resolve_dossier_from_meta(meta_path: str | Path) -> dict[str, str]:
    """Open the orchestrator's wire-dossier JSON and return it as ``{str: str}``.

    The file at *meta_path* is the orchestrator's contract with
    shield: a small JSON object whose keys *are* the wire-dossier
    keys the clearance UI renders (``project`` / ``task`` / ``name``).
    No projection, no key translation — bookkeeping the orchestrator
    keeps for itself lives in a different file the orchestrator alone
    consumes.  Empty / falsy values are dropped so the wire stays
    minimal.

    Soft-fail by contract — both the per-block reader and the
    host-side ``Shield.up()`` / ``Shield.down()`` call this on every
    event; an unreadable or malformed file degrades to ``{}``, which
    the renderer turns into a bare-container-name popup (same as a
    non-orchestrator container).
    """
    if not meta_path:
        return {}
    try:
        decoded = json.loads(Path(meta_path).read_text())
    except (OSError, ValueError):
        return {}
    if not isinstance(decoded, dict):
        return {}
    return {str(k): str(v) for k, v in decoded.items() if v}


# ── Environment bootstrap ─────────────────────────────────

#: Trusted ``$PATH`` for hook subprocess execution.  Set unconditionally
#: in ``bootstrap_env()`` so an attacker who can influence the OCI
#: runtime's environment cannot point ``shutil.which`` at a planted
#: binary.  Order mirrors the typical sysadmin precedence (system
#: locations before user locations, sbin before bin) without including
#: any of the user-writable directories that ``$PATH``-injection
#: attacks rely on.
_TRUSTED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

#: Environment variables that influence the dynamic linker or Python
#: import resolution and that an attacker could use to hijack
#: subprocess execution from the hook.  Wiped unconditionally in
#: ``bootstrap_env()`` so the ``nsenter`` / ``podman unshare`` /
#: ``nft`` / ``dnsmasq`` calls below run under a clean environment.
_DANGEROUS_ENV_VARS = (
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "PYTHONPATH",
    "PYTHONHOME",
)


def bootstrap_env() -> None:
    """Sanitise the inherited environment before the hook does any subprocess work.

    OCI hooks (crun/runc) may be invoked with a stripped environment —
    no ``HOME``, no ``XDG_RUNTIME_DIR``, sometimes no ``PATH`` — *or*
    with an attacker-influenced one.  Inside ``NS_ROOTLESS``
    ``os.getuid()`` is the mapped 0; resolving resources naively would
    point at ``/root`` instead of the operator's real home.
    ``outer_host_uid()`` parses ``/proc/self/uid_map`` to recover the
    host UID and we use that throughout.

    Hardened against ``$PATH`` / ``LD_PRELOAD`` injection: we
    unconditionally pin ``$PATH`` to a trusted constant and wipe the
    dynamic-linker variables that would let a poisoned environment
    hijack the binaries we ``shutil.which()`` and exec below.
    """
    uid = outer_host_uid()

    if not os.environ.get("HOME"):
        try:
            home = pwd.getpwuid(uid).pw_dir
        except KeyError:
            home = "/root" if uid == 0 else f"/home/{uid}"
        os.environ["HOME"] = home

    if not os.environ.get("XDG_RUNTIME_DIR"):
        os.environ["XDG_RUNTIME_DIR"] = f"/run/user/{uid}"

    # Trusted ``$PATH`` is set unconditionally — an inherited PATH that
    # prepends an attacker-controlled directory would otherwise let
    # ``shutil.which`` resolve ``nsenter`` / ``podman`` / ``nft`` /
    # ``dnsmasq`` to a planted binary, and the hook executes those with
    # CAP_NET_ADMIN inside the container netns.
    os.environ["PATH"] = _TRUSTED_PATH

    # Wipe dynamic-linker / Python-import injection vectors before any
    # subprocess call.  These would otherwise propagate via ``os.environ``
    # to the children spawned by ``nsenter()``.
    for var in _DANGEROUS_ENV_VARS:
        os.environ.pop(var, None)


def outer_host_uid() -> int:
    """Return the invoking operator's host UID, even from inside ``NS_ROOTLESS``.

    Parses ``/proc/self/uid_map`` to find the outer-side UID that the
    current in-namespace UID maps to.  Each map line has the shape
    ``<inner_start> <outer_start> <length>`` — pick the mapping whose
    inner range covers ``os.getuid()`` and project through it.

    Falls back to ``os.getuid()`` on any parse trouble (init userns, no
    uid_map, unreadable, unexpected format) — that path is valid for
    non-rootless contexts where there's no userns layer to see through.
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


# ── Namespace execution ──────────────────────────────────


def nsenter(pid: str, *cmd: str, stdin: str | None = None) -> None:
    """Run *cmd* inside the container's network namespace.

    Two execution contexts are handled automatically:

    **OCI hook context (crun invokes the hook)** — crun runs inside
    podman's rootless user namespace (``NS_ROOTLESS``, where
    ``os.getuid() == 0`` and ``CAP_NET_ADMIN`` is available).  The hook
    inherits that namespace, so ``nsenter -n -t <pid>`` is sufficient.

    **Shell / manual invocation context** — the caller is in the
    initial user namespace (``NS_INIT``, uid != 0, no elevated caps).
    ``podman unshare`` enters ``NS_ROOTLESS`` first to gain
    ``CAP_NET_ADMIN``, then ``nsenter -n`` enters the container's
    network namespace.  Mirrors ``SubprocessRunner.nft_via_nsenter()``
    in run.py.

    Captures both stdout and stderr — some nft versions write errors
    to stdout.
    """
    if os.getuid() == 0:
        ns_cmd = [find_nsenter(), "-n", "-t", pid, "--", *cmd]
    else:
        ns_cmd = [find_podman(), "unshare", find_nsenter(), "-n", "-t", pid, "--", *cmd]
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603
            ns_cmd,
            input=stdin,
            text=True,
            capture_output=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"nsenter command timed out after 30 s: cmd={cmd!r}")
    if result.returncode != 0:
        combined = (result.stderr + result.stdout).strip()
        raise RuntimeError(
            f"nsenter command failed (exit {result.returncode}) cmd={cmd!r}"
            + (f":\n{combined}" if combined else " (no output)")
        )


def pid_exists(pid: int) -> bool:
    """Ask the kernel whether *pid* is still a running process."""
    try:
        # Signal 0 is an existence probe — never delivers a signal,
        # only triggers the kernel's PID-validity / permission check.
        os.kill(pid, 0)  # NOSONAR
    except ProcessLookupError:
        return False
    except OSError:
        # EPERM means the process exists but we don't own it — treat as alive.
        return True
    return True


# ── Binary finders ───────────────────────────────────────


def find_podman() -> str:
    """Path to the podman binary, falling back to ``/usr/bin/podman``."""
    return shutil.which("podman") or "/usr/bin/podman"


def find_nsenter() -> str:
    """Path to the nsenter binary, falling back to ``/usr/bin/nsenter``."""
    return shutil.which("nsenter") or "/usr/bin/nsenter"


def find_nft() -> str:
    """Path to the nft binary, falling back to ``/usr/sbin/nft``."""
    return shutil.which("nft") or "/usr/sbin/nft"


def find_dnsmasq() -> str:
    """Path to the dnsmasq binary, falling back to ``/usr/sbin/dnsmasq``."""
    return shutil.which("dnsmasq") or "/usr/sbin/dnsmasq"


# ── Logging ──────────────────────────────────────────────


def log(msg: str, log_path: Path | None = None) -> None:
    """Write *msg* to stderr, plus a per-container log file when available.

    The OCI runtime (crun/runc) typically swallows hook stderr; the
    persistent file is what the operator inspects after a failed
    container start.  *log_path* should always be the state-dir-local
    ``hook-error.log`` once ``state_dir_from_oci()`` has resolved the
    bundle.  Errors that occur before that resolution (malformed OCI
    state, missing annotation) get stderr only — we deliberately avoid
    a predictable ``/tmp`` fallback because another local user could
    pre-create it as a symlink to a sensitive file and have the hook
    follow the link with the operator's UID.

    The on-disk write uses ``O_NOFOLLOW`` so even a TOCTOU race that
    swaps ``log_path`` for a symlink between resolution and open fails
    closed instead of writing through the symlink.
    """
    print(msg, file=sys.stderr)
    if log_path is None:
        return
    try:
        fd = os.open(
            log_path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except OSError:
        return
    try:
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(f"{msg}\n")
    except OSError:
        pass
