# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Subprocess helpers for shield.  Every external command goes through here."""

import ipaddress as _ipaddress
import shutil
import subprocess


class ExecError(Exception):
    """Raised when a subprocess fails."""

    def __init__(self, cmd: list[str], rc: int, stderr: str) -> None:
        """Store command details and format the error message."""
        self.cmd = cmd
        self.rc = rc
        self.stderr = stderr
        super().__init__(f"{cmd!r} failed (rc={rc}): {stderr.strip()}")


def run(
    cmd: list[str],
    *,
    check: bool = True,
    stdin: str | None = None,
    timeout: int | None = None,
) -> str:
    """Run a command, return stdout.  Raise ExecError on failure when check=True."""
    try:
        r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as e:
        if check:
            raise ExecError(cmd, 127, str(e)) from e
        return ""
    except subprocess.TimeoutExpired as e:
        if check:
            raise ExecError(cmd, -1, f"timed out after {timeout}s") from e
        return ""
    if check and r.returncode != 0:
        raise ExecError(cmd, r.returncode, r.stderr or "")
    return r.stdout or ""


def has(name: str) -> bool:
    """Return True if an executable is on PATH."""
    return shutil.which(name) is not None


# ── nft wrappers ─────────────────────────────────────────


def nft(*args: str, stdin: str | None = None, check: bool = True) -> str:
    """Run nft command directly (hook mode, inside container netns)."""
    if stdin is not None:
        return run(["nft", *args, "-f", "-"], stdin=stdin, check=check)
    return run(["nft", *args], check=check)


def nft_via_nsenter(
    container: str,
    *args: str,
    pid: str | None = None,
    stdin: str | None = None,
    check: bool = True,
) -> str:
    """Run nft inside a running container's network namespace."""
    if pid is None:
        pid = podman_inspect(container, "{{.State.Pid}}")
    cmd = ["podman", "unshare", "nsenter", "-t", pid, "-n", "nft"]
    if stdin is not None:
        return run([*cmd, *args, "-f", "-"], stdin=stdin, check=check)
    return run([*cmd, *args], check=check)


# ── Other helpers ────────────────────────────────────────


def podman_inspect(container: str, fmt: str) -> str:
    """Inspect a container attribute via podman."""
    return run(["podman", "inspect", "--format", fmt, container]).strip()


def dig_all(domain: str, *, timeout: int = 10) -> list[str]:
    """Resolve domain to both IPv4 and IPv6 addresses in a single query.

    Runs ``dig +short domain A domain AAAA`` and validates each line
    with ``ipaddress``.  Returns empty list on failure or timeout.
    """
    out = run(["dig", "+short", domain, "A", domain, "AAAA"], check=False, timeout=timeout)
    result: list[str] = []
    for line in out.splitlines():
        addr = line.strip()
        if not addr:
            continue
        try:
            _ipaddress.ip_address(addr)
            result.append(addr)
        except ValueError:
            continue
    return result
