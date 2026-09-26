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
import subprocess
from typing import Protocol, runtime_checkable

from terok_util import SetupRequiredError, find_host_tool, require_host_tool

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

    def dnsmasq_via_nsenter(
        self, container: str, conf_path: str, *, binary: str, pid: str | None = None
    ) -> str:
        """Launch the dnsmasq at *binary* inside a running container's network namespace."""
        ...

    def podman_inspect(self, container: str, fmt: str) -> str:
        """Inspect a container attribute via podman."""
        ...

    def lookup_all(self, domain: str, *, timeout: int = 10) -> list[str]:
        """Resolve domain to both IPv4 and IPv6 addresses."""
        ...

    def getent_hosts(self, domain: str, *, timeout: int = 10) -> list[str]:
        """Resolve domain via ``getent hosts`` (fallback when no lookup tool exists)."""
        ...


# ── SubprocessRunner (default implementation) ───────────


class SubprocessRunner:
    """Default ``CommandRunner`` implementation using ``subprocess.run``.

    Resolves the nft binary path at construction time and raises
    ``NftNotFoundError`` immediately if nft is not installed.
    """

    def __init__(self) -> None:
        """Resolve the nft binary path, raising NftNotFoundError if missing."""
        if not find_nft():
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
                [require_host_tool(cmd[0]), *cmd[1:]],
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
        """Return True when the current host PATH supplies an executable."""
        return bool(find_host_tool(name))

    # ── nft ─────────────────────────────────────────────

    def nft(self, *args: str, stdin: str | None = None, check: bool = True) -> str:
        """Run nft command directly (hook mode, inside container netns)."""
        if stdin is not None:
            return self.run([require_host_tool("nft"), *args, "-f", "-"], stdin=stdin, check=check)
        return self.run([require_host_tool("nft"), *args], check=check)

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
        cmd = [
            "podman",
            "unshare",
            require_host_tool("nsenter"),
            "-t",
            pid,
            "-n",
            require_host_tool("nft"),
        ]
        if stdin is not None:
            return self.run([*cmd, *args, "-f", "-"], stdin=stdin, check=check)
        return self.run([*cmd, *args], check=check)

    def dnsmasq_via_nsenter(
        self, container: str, conf_path: str, *, binary: str, pid: str | None = None
    ) -> str:
        """Launch the dnsmasq at *binary* inside a running container's network namespace.

        dnsmasq runs in the host PID namespace but the container's network
        namespace (like the OCI hook's own launch), so a host-side reload can
        relaunch it here.  dnsmasq daemonizes and writes its own pid-file; the
        command returns once it has forked into the background.
        """
        if pid is None:
            pid = self.podman_inspect(container, "{{.State.Pid}}")
        return self.run(
            [
                "podman",
                "unshare",
                require_host_tool("nsenter"),
                "-t",
                pid,
                "-n",
                binary,
                f"--conf-file={conf_path}",
            ]
        )

    # ── Podman ──────────────────────────────────────────

    def podman_inspect(self, container: str, fmt: str) -> str:
        """Inspect a container attribute via podman."""
        return self.run(["podman", "inspect", "--format", fmt, container]).strip()

    # ── DNS resolution ──────────────────────────────────

    def lookup_all(self, domain: str, *, timeout: int = 10) -> list[str]:
        """Resolve domain to both IPv4 and IPv6 addresses with the host's lookup tool.

        Prefers ``dig`` (one two-type query) and falls back to ``drill``
        (ldns, the Arch/Manjaro default; one type per invocation).
        Validates each output line with ``ipaddress``.  Returns an empty
        list on lookup failure or timeout.

        Raises:
            LookupToolNotFoundError: If neither tool is installed.
        """
        if self.has("dig"):
            out = self.run(
                ["dig", "+short", domain, "A", domain, "AAAA"],
                check=False,
                timeout=timeout,
            )
        elif self.has("drill"):
            out = "\n".join(
                self.run(["drill", "-Q", domain, rrtype], check=False, timeout=timeout)
                for rrtype in ("A", "AAAA")
            )
        else:
            raise LookupToolNotFoundError(
                "no DNS lookup tool found. Install one:\n"
                "  Debian/Ubuntu: sudo apt install dnsutils\n"
                "  Fedora/RHEL:   sudo dnf install bind-utils\n"
                "  Arch/Manjaro:  sudo pacman -S ldns   (drill) or bind (dig)"
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

    def getent_hosts(self, domain: str, *, timeout: int = 10) -> list[str]:
        """Resolve domain via NSS (fallback when the lookup tool is missing or broken).

        Queries both address families explicitly: plain ``getent hosts``
        stops at the first family glibc resolves (AAAA for dual-stack
        names), which left ``allow_v4`` empty on the one host whose lookup tool
        crashes -- an allowed literal-IPv4 target then hit the terminal
        reject as "Host is unreachable" (terok#1119).

        *timeout* bounds each family query; on expiry that family yields
        nothing (best-effort, matching ``lookup_all``).
        """
        result: list[str] = []
        for database in ("ahostsv4", "ahostsv6"):
            out = self.run(["getent", database, domain], check=False, timeout=timeout)
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) < 2 or parts[1] != "STREAM":
                    continue
                try:
                    _ipaddress.ip_address(parts[0])
                except ValueError:
                    continue
                if parts[0] not in result:
                    result.append(parts[0])
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


class LookupToolNotFoundError(RuntimeError):
    """Raised when neither ``dig`` nor ``drill`` is found on the host."""


class ShieldNeedsSetup(SetupRequiredError):
    """Raised when global OCI hooks are not installed.

    Per-container ``--hooks-dir`` does not persist across container
    restarts, so global hooks are required.  The message includes
    system-specific setup hints.
    """


# ── Standalone helpers ──────────────────────────────────


def find_nft() -> str:
    """Locate nft using the same current PATH as every other host tool."""
    return find_host_tool("nft") or ""
