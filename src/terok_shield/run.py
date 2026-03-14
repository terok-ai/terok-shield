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
from pathlib import Path
from typing import Protocol, runtime_checkable

_SBIN_DIRS = ("/usr/sbin", "/sbin")


def find_nft() -> str:
    """Locate the nft binary, checking PATH then common sbin directories.

    Returns the absolute path as a string, or empty string if not found.
    """
    found = shutil.which("nft")
    if found:
        return found
    for d in _SBIN_DIRS:
        candidate = Path(d) / "nft"
        if candidate.is_file():
            return str(candidate)
    return ""


class NftNotFoundError(RuntimeError):
    """Raised when the ``nft`` binary is not found on the host."""


class ShieldNeedsSetup(RuntimeError):
    """Raised when the podman environment requires one-time setup.

    Typically raised on podman < 5.6.0 when global hooks are not
    installed and ``--hooks-dir`` would not persist across container
    restarts.  The message includes system-specific setup hints.
    """


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

    Resolves the nft binary path at construction time and raises
    ``NftNotFoundError`` immediately if nft is not installed.
    """

    def __init__(self) -> None:
        """Resolve the nft binary path, raising NftNotFoundError if missing."""
        self._nft = find_nft()
        if not self._nft:
            raise NftNotFoundError(
                "nft binary not found. Install nftables:\n"
                "  Debian/Ubuntu: sudo apt install nftables\n"
                "  Fedora/RHEL:   sudo dnf install nftables\n"
                "  Arch:          sudo pacman -S nftables"
            )

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
            # All external commands flow through this boundary as explicit argv
            # lists with ``shell=False`` so call sites stay auditable and testable.
            r = subprocess.run(
                cmd,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,  # nosec B603
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
            return self.run([self._nft, *args, "-f", "-"], stdin=stdin, check=check)
        return self.run([self._nft, *args], check=check)

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
        cmd = ["podman", "unshare", "nsenter", "-t", pid, "-n", self._nft]
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
