# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Subprocess helpers for shield.

Provides ``CommandRunner`` (Protocol) and ``SubprocessRunner``
(default implementation).  Every external command goes through here.
"""

from __future__ import annotations

import ipaddress as _ipaddress
import shutil
import subprocess
from typing import Protocol, runtime_checkable


class ExecError(Exception):
    """Raised when a subprocess fails."""

    def __init__(self, cmd: list[str], rc: int, stderr: str) -> None:
        """Store command details and format the error message."""
        self.cmd = cmd
        self.rc = rc
        self.stderr = stderr
        super().__init__(f"{cmd!r} failed (rc={rc}): {stderr.strip()}")


# ── CommandRunner Protocol ───────────────────────────────


@runtime_checkable
class CommandRunner(Protocol):
    """Protocol for executing external commands.

    Decouples all subprocess calls behind a testable interface.
    Production code uses ``SubprocessRunner``; tests inject fakes.
    """

    def run(
        self,
        cmd: list[str],
        *,
        check: bool = True,
        stdin: str | None = None,
        timeout: int | None = None,
    ) -> str:
        """Run a command, return stdout."""
        ...

    def has(self, name: str) -> bool:
        """Return True if an executable is on PATH."""
        ...

    def nft(self, *args: str, stdin: str | None = None, check: bool = True) -> str:
        """Run nft command directly (inside container netns)."""
        ...

    def nft_via_nsenter(
        self,
        container: str,
        *args: str,
        pid: str | None = None,
        stdin: str | None = None,
        check: bool = True,
    ) -> str:
        """Run nft inside a running container's network namespace."""
        ...

    def podman_inspect(self, container: str, fmt: str) -> str:
        """Inspect a container attribute via podman."""
        ...

    def dig_all(self, domain: str, *, timeout: int = 10) -> list[str]:
        """Resolve domain to both IPv4 and IPv6 addresses."""
        ...


# ── SubprocessRunner ─────────────────────────────────────


class SubprocessRunner:
    """Default ``CommandRunner`` implementation using ``subprocess.run``.

    Stateless -- all methods delegate to the standard library.
    """

    def run(
        self,
        cmd: list[str],
        *,
        check: bool = True,
        stdin: str | None = None,
        timeout: int | None = None,
    ) -> str:
        """Run a command, return stdout.  Raise ExecError on failure when check=True."""
        try:
            r = subprocess.run(
                cmd,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
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

    def has(self, name: str) -> bool:
        """Return True if an executable is on PATH."""
        return shutil.which(name) is not None

    def nft(self, *args: str, stdin: str | None = None, check: bool = True) -> str:
        """Run nft command directly (hook mode, inside container netns)."""
        if stdin is not None:
            return self.run(["nft", *args, "-f", "-"], stdin=stdin, check=check)
        return self.run(["nft", *args], check=check)

    def nft_via_nsenter(
        self,
        container: str,
        *args: str,
        pid: str | None = None,
        stdin: str | None = None,
        check: bool = True,
    ) -> str:
        """Run nft inside a running container's network namespace."""
        if pid is None:
            pid = self.podman_inspect(container, "{{.State.Pid}}")
        cmd = ["podman", "unshare", "nsenter", "-t", pid, "-n", "nft"]
        if stdin is not None:
            return self.run([*cmd, *args, "-f", "-"], stdin=stdin, check=check)
        return self.run([*cmd, *args], check=check)

    def podman_inspect(self, container: str, fmt: str) -> str:
        """Inspect a container attribute via podman."""
        return self.run(["podman", "inspect", "--format", fmt, container]).strip()

    def dig_all(self, domain: str, *, timeout: int = 10) -> list[str]:
        """Resolve domain to both IPv4 and IPv6 addresses in a single query.

        Runs ``dig +short domain A domain AAAA`` and validates each line
        with ``ipaddress``.  Returns empty list on failure or timeout.
        """
        out = self.run(
            ["dig", "+short", domain, "A", domain, "AAAA"],
            check=False,
            timeout=timeout,
        )
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


# ── Module-level free functions (backwards compat) ───────
# Thin wrappers around a module-level SubprocessRunner instance.
# New code should inject a runner; existing callers keep working.

_default_runner = SubprocessRunner()


def run(
    cmd: list[str],
    *,
    check: bool = True,
    stdin: str | None = None,
    timeout: int | None = None,
) -> str:
    """Run a command, return stdout.  Raise ExecError on failure when check=True."""
    return _default_runner.run(cmd, check=check, stdin=stdin, timeout=timeout)


def has(name: str) -> bool:
    """Return True if an executable is on PATH."""
    return _default_runner.has(name)


def nft(*args: str, stdin: str | None = None, check: bool = True) -> str:
    """Run nft command directly (hook mode, inside container netns)."""
    return _default_runner.nft(*args, stdin=stdin, check=check)


def nft_via_nsenter(
    container: str,
    *args: str,
    pid: str | None = None,
    stdin: str | None = None,
    check: bool = True,
) -> str:
    """Run nft inside a running container's network namespace."""
    return _default_runner.nft_via_nsenter(container, *args, pid=pid, stdin=stdin, check=check)


def podman_inspect(container: str, fmt: str) -> str:
    """Inspect a container attribute via podman."""
    return _default_runner.podman_inspect(container, fmt)


def dig_all(domain: str, *, timeout: int = 10) -> list[str]:
    """Resolve domain to both IPv4 and IPv6 addresses in a single query."""
    return _default_runner.dig_all(domain, timeout=timeout)
