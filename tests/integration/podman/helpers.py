# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared test utilities for podman integration tests.

Provides container exec helpers and assertion functions used by both
the internal firewall tests and the public API / CLI lifecycle tests.
"""

import subprocess


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
        container, "wget", "-q", "--spider", f"--timeout={timeout}", url, timeout=timeout + 5
    )


def assert_blocked(container: str, url: str, timeout: int = 10) -> None:
    """Assert that a URL is blocked (wget fails) from inside a container.

    Args:
        container: Container name or ID.
        url: URL that should be unreachable.
        timeout: wget timeout in seconds.
    """
    r = wget(container, url, timeout=timeout)
    assert r.returncode != 0, f"Expected {url} to be blocked, but it was reachable"


def assert_reachable(container: str, url: str, timeout: int = 10) -> None:
    """Assert that a URL is reachable (wget succeeds) from inside a container.

    Args:
        container: Container name or ID.
        url: URL that should be reachable.
        timeout: wget timeout in seconds.
    """
    r = wget(container, url, timeout=timeout)
    assert r.returncode == 0, f"Expected {url} to be reachable, but it was blocked: {r.stderr}"


def assert_ruleset_applied(container: str) -> None:
    """Assert that the terok_shield nft ruleset is applied to a container.

    Uses ``shield_rules()`` from the public API to check.

    Args:
        container: Container name or ID.
    """
    from terok_shield import shield_rules

    rules = shield_rules(container)
    assert "terok_shield" in rules, f"Expected terok_shield rules applied, got: {rules[:200]}"
