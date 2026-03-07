# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Fixtures for podman integration tests.

These tests require podman and nft on the host. They are NOT run in CI
(GitHub Actions lacks nftables kernel support for user namespaces).
Run manually via: make test-podman
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

IMAGE = "docker.io/library/alpine:latest"
CTR_PREFIX = "shield-itest"


def _has(binary: str) -> bool:
    return shutil.which(binary) is not None


def _nft_usable() -> bool:
    """Check if nft works inside a podman user namespace."""
    if not _has("podman") or not _has("nft"):
        return False
    r = subprocess.run(
        ["podman", "unshare", "nft", "list", "ruleset"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return r.returncode == 0


def _image_available() -> bool:
    """Check if the test image is already pulled."""
    r = subprocess.run(
        ["podman", "image", "exists", IMAGE],
        capture_output=True,
    )
    return r.returncode == 0


# ── Skip conditions ─────────────────────────────────────

podman_missing = pytest.mark.skipif(not _has("podman"), reason="podman not installed")
nft_missing = pytest.mark.skipif(not _has("nft"), reason="nft not installed")
nft_unusable = pytest.mark.skipif(not _nft_usable(), reason="nft not usable via podman unshare")


# ── Fixtures ─────────────────────────────────────────────


@pytest.fixture(scope="session", autouse=True)
def _pull_image():
    """Pull the test image once per session (skipped if already present)."""
    if not _has("podman"):
        pytest.skip("podman not installed")
    if not _image_available():
        subprocess.run(["podman", "pull", IMAGE], check=True, timeout=120)


@pytest.fixture
def container():
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


def nsenter_nft(pid: str, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    """Run nft inside a container's netns via nsenter."""
    cmd = ["podman", "unshare", "nsenter", "-t", pid, "-n", "nft", *args]
    if stdin is not None:
        cmd.extend(["-f", "-"])
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=30)
