# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared test utilities for integration tests.

Provides container exec helpers and assertion functions used by both
the internal firewall tests and the public API / CLI lifecycle tests.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path

from terok_shield import Shield, ShieldConfig

_DISPOSABLE_DIRS: list[tempfile.TemporaryDirectory] = []
"""Managed temp dirs for nft-only tests (cleaned up at process exit)."""


def disposable_shield() -> Shield:
    """Create a Shield with a disposable state_dir (for nft-only ops).

    The temp directory is kept alive until process exit by appending to
    the module-level ``_DISPOSABLE_DIRS`` list.
    """
    td = tempfile.TemporaryDirectory()
    _DISPOSABLE_DIRS.append(td)
    return Shield(ShieldConfig(state_dir=Path(td.name)))


def _hook_diagnostics(extra_args: list[str]) -> str:
    """Gather OCI hook file diagnostics from extra_args (called only on failure)."""
    try:
        idx = extra_args.index("--hooks-dir")
        hooks_dir = Path(extra_args[idx + 1])
        hook_json = hooks_dir / "terok-shield-createRuntime.json"
        if not hook_json.exists():
            return f"\n  [diag] hook JSON missing: {hook_json}"
        data = json.loads(hook_json.read_text())
        ep = Path(data["hook"]["path"])
        parts = [f"entrypoint={ep}", f"exists={ep.exists()}"]
        if ep.exists():
            parts.append(f"executable={os.access(ep, os.X_OK)}")
            parts.append(f"content={ep.read_text().strip()!r}")
        return f"\n  [diag] {', '.join(parts)}"
    except Exception as exc:
        return f"\n  [diag] error: {exc}"


def start_shielded_container(
    name: str, extra_args: list[str], image: str, timeout: int = 30
) -> None:
    """Start a container with shield args, providing detailed errors on failure.

    Unlike plain ``subprocess.run(..., check=True, capture_output=True)`` which
    hides stderr, this helper includes the actual podman error message and OCI
    hook file diagnostics in the exception so hook failures are visible.

    Args:
        name: Container name.
        extra_args: Extra arguments from ``Shield.pre_start()``.
        image: Container image to run.
        timeout: Podman timeout in seconds.

    Raises:
        RuntimeError: If podman run exits non-zero, with stderr/stdout details.
    """
    result = subprocess.run(
        ["podman", "run", "-d", "--name", name, *extra_args, image, "sleep", "120"],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        diag = _hook_diagnostics(extra_args)
        raise RuntimeError(
            f"podman run failed (exit {result.returncode}):\n"
            f"  stderr: {result.stderr.strip()}\n"
            f"  stdout: {result.stdout.strip()}\n"
            f"  extra_args: {extra_args}{diag}"
        )


def assert_connectable(container: str, ip: str, port: int = 53, timeout: int = 5) -> None:
    """Assert that a TCP connection to ip:port succeeds from inside a container.

    Uses ``nc -z`` for a fast, protocol-agnostic connectivity check.
    Preferred over HTTP-based checks when the target may not serve HTTP
    (e.g. 8.8.8.8 only serves DNS on port 53, not HTTP on port 80).

    Args:
        container: Container name or ID.
        ip: Target IP address.
        port: Target TCP port (default: 53, DNS).
        timeout: Connection timeout in seconds.
    """
    _assert_container_running(container)
    r = exec_in_container(
        container, "nc", "-z", "-w", str(timeout), ip, str(port), timeout=timeout + 5
    )
    assert r.returncode == 0, (
        f"Expected {ip}:{port} to be reachable, but connection failed: {r.stderr}"
    )


def assert_not_connectable(container: str, ip: str, port: int = 53, timeout: int = 5) -> None:
    """Assert that a TCP connection to ip:port is blocked from inside a container.

    Inverse of :func:`assert_connectable`.  Uses ``nc -z`` and expects failure.

    Args:
        container: Container name or ID.
        ip: Target IP address.
        port: Target TCP port (default: 53, DNS).
        timeout: Connection timeout in seconds.
    """
    _assert_container_running(container)
    r = exec_in_container(
        container, "nc", "-z", "-w", str(timeout), ip, str(port), timeout=timeout + 5
    )
    assert r.returncode != 0, f"Expected {ip}:{port} to be blocked, but connection succeeded"


def exec_in_container(container: str, *cmd: str, timeout: int = 10) -> subprocess.CompletedProcess:
    """Run a command inside a container via ``podman exec``.

    Args:
        container: Container name or ID.
        *cmd: Command and arguments to execute.
        timeout: Timeout in seconds.

    Returns:
        Completed process result.
    """
    return subprocess.run(
        ["podman", "exec", container, *cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def wget(container: str, url: str, timeout: int = 5) -> subprocess.CompletedProcess:
    """Attempt an outbound HTTP/HTTPS request from inside a container.

    Args:
        container: Container name or ID.
        url: URL to fetch.
        timeout: wget timeout in seconds.

    Returns:
        Completed process result.
    """
    return exec_in_container(
        container,
        "wget",
        "-q",
        "-O",
        "/dev/null",
        f"--timeout={timeout}",
        url,
        timeout=timeout + 5,
    )


def _assert_container_running(container: str) -> None:
    """Assert that a container is running (guard against false positives).

    Args:
        container: Container name or ID.
    """
    r = subprocess.run(
        ["podman", "inspect", "--format", "{{.State.Running}}", container],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert r.returncode == 0 and r.stdout.strip() == "true", (
        f"Container {container} is not running — cannot assert network behavior: {r.stderr}"
    )


def assert_blocked(container: str, url: str, timeout: int = 10) -> None:
    """Assert that a URL is blocked (wget fails) from inside a container.

    Verifies the container is running first to avoid false positives from
    a dead container or failed ``podman exec``.

    Args:
        container: Container name or ID.
        url: URL that should be unreachable.
        timeout: wget timeout in seconds.
    """
    _assert_container_running(container)
    r = wget(container, url, timeout=timeout)
    assert r.returncode != 0, f"Expected {url} to be blocked, but it was reachable"


def assert_reachable(container: str, url: str, timeout: int = 10) -> None:
    """Assert that a URL is reachable from inside a container.

    Delegates to :func:`is_reachable` which tolerates busybox wget
    redirect failures (``bad address``) as proof of TCP connectivity.

    Args:
        container: Container name or ID.
        url: URL that should be reachable.
        timeout: wget timeout in seconds.
    """
    _assert_container_running(container)
    r = wget(container, url, timeout=timeout)
    assert is_reachable(r), f"Expected {url} to be reachable, but it was blocked: {r.stderr}"


def is_reachable(result: subprocess.CompletedProcess) -> bool:
    """Check if a wget result indicates the target was reachable.

    Returns True if wget succeeded, or if wget got an HTTP redirect
    to a hostname it couldn't resolve (``bad address``).  The redirect
    proves TCP connectivity was established — the DNS failure is
    expected in shielded containers where only the forwarder is allowed.
    """
    if result.returncode == 0:
        return True
    return "bad address" in result.stderr


def assert_ruleset_applied(container: str) -> None:
    """Assert that the terok_shield nft ruleset is applied to a container.

    Uses ``Shield.rules()`` from the public API to check.

    Args:
        container: Container name or ID.
    """
    from terok_shield import Shield, ShieldConfig

    with tempfile.TemporaryDirectory() as tmp:
        rules = Shield(ShieldConfig(state_dir=Path(tmp))).rules(container)
    assert "terok_shield" in rules, f"Expected terok_shield rules applied, got: {rules[:200]}"
