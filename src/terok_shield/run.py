# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Subprocess execution boundary for all external commands.

Every shell-out in terok-shield flows through the [`CommandRunner`][terok_shield.run.CommandRunner]
protocol.  Production code uses [`SubprocessRunner`][terok_shield.run.SubprocessRunner]; tests inject
fakes.  This keeps external dependencies auditable and mockable in one
place.
"""
# WAYPOINT: Shield (__init__), HookMode (hooks.mode)

import ipaddress as _ipaddress
import shutil
import subprocess
from pathlib import Path
from typing import Protocol, runtime_checkable

# ── CommandRunner protocol ──────────────────────────────


@runtime_checkable
class CommandRunner(Protocol):
    """Protocol for executing external commands.

    Decouples all subprocess calls behind a testable interface.
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

    def getent_hosts(self, domain: str) -> list[str]:
        """Resolve domain via ``getent hosts`` (fallback when dig is missing)."""
        ...


# ── SubprocessRunner (default implementation) ───────────


class SubprocessRunner:
    """Default ``CommandRunner`` implementation using ``subprocess.run``.

    Resolves the nft binary path at construction time and raises
    ``NftNotFoundError`` immediately if nft is not installed.
    """

    def __init__(self) -> None:
        """Resolve the nft binary path, raising NftNotFoundError if missing."""
        self._has_cache: dict[str, bool] = {}
        self._nft = find_nft()
        if not self._nft:
            raise NftNotFoundError(
                "nft binary not found. Install nftables:\n"
                "  Debian/Ubuntu: sudo apt install nftables\n"
                "  Fedora/RHEL:   sudo dnf install nftables\n"
                "  Arch:          sudo pacman -S nftables"
            )

    # ── Core execution ──────────────────────────────────

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
            # Explicit argv list with shell=False — auditable and testable
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
        """Return True if an executable is on PATH (cached per name)."""
        if name not in self._has_cache:
            self._has_cache[name] = shutil.which(name) is not None
        return self._has_cache[name]

    # ── nft ─────────────────────────────────────────────

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

    # ── Podman ──────────────────────────────────────────

    def podman_inspect(self, container: str, fmt: str) -> str:
        """Inspect a container attribute via podman."""
        return self.run(["podman", "inspect", "--format", fmt, container]).strip()

    # ── DNS resolution ──────────────────────────────────

    def dig_all(self, domain: str, *, timeout: int = 10) -> list[str]:
        """Resolve domain to both IPv4 and IPv6 addresses in a single query.

        Runs ``dig +short domain A domain AAAA`` and validates each line
        with ``ipaddress``.  Returns empty list on lookup failure or
        timeout.

        Raises:
            DigNotFoundError: If ``dig`` is not installed.
        """
        if not self.has("dig"):
            raise DigNotFoundError(
                "dig binary not found. Install DNS utilities:\n"
                "  Debian/Ubuntu: sudo apt install dnsutils\n"
                "  Fedora/RHEL:   sudo dnf install bind-utils\n"
                "  Arch:          sudo pacman -S bind"
            )
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

    def getent_hosts(self, domain: str) -> list[str]:
        """Resolve domain via ``getent hosts`` (fallback when dig is missing).

        Returns validated IP addresses from NSS resolution.  Typically
        returns fewer results than ``dig`` (often a single address).
        """
        out = self.run(["getent", "hosts", domain], check=False, timeout=10)
        result: list[str] = []
        for line in out.splitlines():
            parts = line.strip().split()
            if not parts:
                continue
            try:
                _ipaddress.ip_address(parts[0])
                result.append(parts[0])
            except ValueError:
                continue
        return result


# ── Exceptions ──────────────────────────────────────────


class ExecError(Exception):
    """Raised when a subprocess fails."""

    def __init__(self, cmd: list[str], rc: int, stderr: str) -> None:
        """Store command details and format the error message."""
        self.cmd = cmd
        self.rc = rc
        self.stderr = stderr
        super().__init__(f"{cmd!r} failed (rc={rc}): {stderr.strip()}")


class NftNotFoundError(RuntimeError):
    """Raised when the ``nft`` binary is not found on the host."""


class DigNotFoundError(RuntimeError):
    """Raised when the ``dig`` binary is not found on the host.

    DNS resolution requires ``dig`` (from ``bind-utils`` / ``dnsutils``).
    """


class ShieldNeedsSetup(RuntimeError):
    """Raised when global OCI hooks are not installed.

    Per-container ``--hooks-dir`` does not persist across container
    restarts, so global hooks are required.  The message includes
    system-specific setup hints.
    """


# ── Standalone helpers ──────────────────────────────────

_SBIN_DIRS = ("/usr/sbin", "/sbin")


def find_nft() -> str:
    """Locate the nft binary, checking PATH then common sbin directories.

    sbin directories are checked explicitly because rootless users often
    lack them in PATH.  Returns empty string if not found.
    """
    found = shutil.which("nft")
    if found:
        return found
    for d in _SBIN_DIRS:
        candidate = Path(d) / "nft"
        if candidate.is_file():
            return str(candidate)
    return ""
