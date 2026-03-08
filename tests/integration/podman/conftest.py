# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Fixtures and skip markers for integration tests.

Integration tests are organized into tiers by environment requirements:

- ``needs_host_features``: Linux kernel features only (no containers).
  Run via: ``make test-host`` (also runs in CI).
- ``needs_internet``: Outbound connectivity + dig (no containers).
- ``needs_podman``: Podman + nft on the host.
- ``needs_podman`` + ``needs_internet``: Full firewall tests.

Run all tiers locally via: ``make test-podman``
"""

import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

IMAGE = "docker.io/library/alpine:latest"
CTR_PREFIX = "shield-itest"


def _has(binary: str) -> bool:
    return shutil.which(binary) is not None


def _image_available() -> bool:
    """Check if the test image is already pulled."""
    r = subprocess.run(
        ["podman", "image", "exists", IMAGE],
        capture_output=True,
    )
    return r.returncode == 0


# ── Skip conditions ─────────────────────────────────────
# Cheap binary-existence checks only.  The real nft capability check
# is the session-scoped `nft_in_netns` fixture (needs a running container).

podman_missing = pytest.mark.skipif(not _has("podman"), reason="podman not installed")
nft_missing = pytest.mark.skipif(not _has("nft"), reason="nft not installed")


# ── Fixtures ─────────────────────────────────────────────


@pytest.fixture(scope="session")
def _pull_image() -> None:
    """Pull the test image once per session (skipped if already present)."""
    if not _has("podman"):
        pytest.skip("podman not installed")
    if not _image_available():
        subprocess.run(["podman", "pull", IMAGE], check=True, timeout=120)


@pytest.fixture(scope="session")
def nft_in_netns(_pull_image: None) -> None:
    """Verify nft works inside a container's network namespace.

    Unlike ``podman unshare nft list ruleset`` (which operates on the
    host netns and requires root), this tests the actual shield use case:
    nft inside a container-owned netns via nsenter, where the user
    namespace *does* have CAP_NET_ADMIN.
    """
    if not _has("podman") or not _has("nft"):
        pytest.skip("podman or nft not installed")
    name = f"{CTR_PREFIX}-nftcheck"
    subprocess.run(["podman", "rm", "-f", name], capture_output=True)
    try:
        subprocess.run(
            ["podman", "run", "-d", "--name", name, IMAGE, "sleep", "30"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        pid = subprocess.run(
            ["podman", "inspect", "--format", "{{.State.Pid}}", name],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        r = subprocess.run(
            ["podman", "unshare", "nsenter", "-t", pid, "-n", "nft", "list", "ruleset"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode != 0:
            pytest.skip(f"nft not usable inside container netns: {r.stderr.strip()}")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        pytest.skip(f"nft pre-check failed: {e}")
    finally:
        subprocess.run(["podman", "rm", "-f", name], capture_output=True)


@pytest.fixture
def container(_pull_image: None) -> Iterator[str]:
    """Start a disposable Alpine container, yield its name, clean up after."""
    name = f"{CTR_PREFIX}-{os.getpid()}"
    subprocess.run(["podman", "rm", "-f", name], capture_output=True)
    subprocess.run(
        ["podman", "run", "-d", "--name", name, IMAGE, "sleep", "120"],
        check=True,
        capture_output=True,
    )
    yield name
    subprocess.run(["podman", "rm", "-f", name], capture_output=True)


@pytest.fixture
def container_pid(container: str) -> str:
    """Return the host PID of a running container."""
    from terok_shield.run import podman_inspect

    return podman_inspect(container, "{{.State.Pid}}")


@pytest.fixture
def probe_container(_pull_image: None) -> Iterator[str]:
    """Start an Alpine container with Python and shield_probe installed."""
    name = f"{CTR_PREFIX}-probe-{os.getpid()}"
    subprocess.run(["podman", "rm", "-f", name], capture_output=True)
    try:
        subprocess.run(
            ["podman", "run", "-d", "--name", name, IMAGE, "sleep", "120"],
            check=True,
            capture_output=True,
        )
        # Install Python inside the container.
        subprocess.run(
            ["podman", "exec", name, "apk", "add", "--no-cache", "python3"],
            check=True,
            capture_output=True,
            timeout=120,
        )
        # Copy the probe script into the container.
        probe_src = Path(__file__).resolve().parent.parent.parent / (
            "src/terok_shield/resources/shield_probe.py"
        )
        if not probe_src.exists():
            pytest.skip(f"shield_probe.py not found at {probe_src}")
        subprocess.run(
            ["podman", "cp", str(probe_src), f"{name}:/usr/local/bin/shield_probe.py"],
            check=True,
            capture_output=True,
        )
        yield name
    finally:
        subprocess.run(["podman", "rm", "-f", name], capture_output=True)


def nsenter_nft(pid: str, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    """Run nft inside a container's netns via nsenter."""
    cmd = ["podman", "unshare", "nsenter", "-t", pid, "-n", "nft", *args]
    if stdin is not None:
        cmd.extend(["-f", "-"])
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=30)
