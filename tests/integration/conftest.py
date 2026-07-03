# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Fixtures and skip markers for all integration tests.

Tests are organized by workflow/feature area. Environment requirements
are expressed via pytest markers, not directory placement:

- ``needs_host_features``: Linux kernel features only (no containers).
- ``needs_internet``: Outbound connectivity + dig (no containers).
- ``needs_podman``: Podman + nft on the host.

Makefile targets filter by marker:

- ``make test-integration-host``:    ``-m needs_host_features``
- ``make test-integration-network``: ``-m "needs_internet and not needs_podman"``
- ``make test-integration-podman``:  ``-m needs_podman``
"""

import os
import shutil
import socket
import subprocess
import tempfile
import warnings
from collections.abc import Iterator
from pathlib import Path

import pytest

from terok_shield.podman_info import has_global_hooks, parse_podman_info
from terok_shield.run import find_nft, which_sbin_aware
from tests.testnet import ALLOWED_TARGET_IPS

from .helpers import start_shielded_container

IMAGE = "docker.io/library/alpine:latest"
CTR_PREFIX = "shield-itest"
_PODMAN_RM_TIMEOUT = 60


class ShieldedContainer(str):
    """A container name (``str``) that also carries its real podman id.

    Behaves as the operator-facing container name everywhere a plain name
    string is expected (``.name`` mirrors the ``str`` value), while also
    exposing the full 64-hex podman container id via ``.id`` — the
    ``--container-id`` routing key now required by
    [`Shield.down`][terok_shield.Shield.down] /
    [`Shield.up`][terok_shield.Shield.up].
    """

    _cid: str

    def __new__(cls, name: str, cid: str) -> "ShieldedContainer":
        """Create the name-string carrying container id ``cid``."""
        obj = super().__new__(cls, name)
        obj._cid = cid
        return obj

    @property
    def name(self) -> str:
        """The operator-facing container name (the ``str`` value)."""
        return str(self)

    @property
    def id(self) -> str:
        """The full 64-hex podman container id."""
        return self._cid


def _podman_rm(name: str) -> None:
    """Best-effort container removal with bounded timeout.

    Used in fixture teardown and finally blocks.  Catches TimeoutExpired
    so a slow ``podman rm`` never masks the real test failure.
    """
    try:
        subprocess.run(
            ["podman", "rm", "-f", name], capture_output=True, timeout=_PODMAN_RM_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        warnings.warn(
            f"podman rm -f {name} timed out after {_PODMAN_RM_TIMEOUT}s",
            RuntimeWarning,
            stacklevel=2,
        )


def _has(binary: str) -> bool:
    """Check if a binary is available on PATH."""
    return shutil.which(binary) is not None


def _image_available() -> bool:
    """Check if the test image is already pulled."""
    r = subprocess.run(
        ["podman", "image", "exists", IMAGE],
        capture_output=True,
        timeout=10,
    )
    return r.returncode == 0


# -- Skip conditions -----------------------------------------
# Cheap binary-existence checks only.  The real nft capability check
# is the session-scoped `nft_in_netns` fixture (needs a running container).
#
# These `skipif` markers complement the `@pytest.mark.needs_podman` /
# `needs_internet` custom markers defined in pyproject.toml.  The custom
# markers are for **test selection** (`pytest -m needs_podman`), while
# `podman_missing` / `nft_missing` / `dig_missing` are **skip guards**
# that gracefully degrade when binaries are absent.

podman_missing = pytest.mark.skipif(not _has("podman"), reason="podman not installed")
nft_missing = pytest.mark.skipif(not find_nft(), reason="nft not installed")
dig_missing = pytest.mark.skipif(not _has("dig"), reason="dig not installed")


def _dig_functional() -> bool:
    """Whether dig can execute at all — present-but-crashing builds exist.

    Mageia's aarch64 bind (jemalloc built for 4K pages) SIGABRTs on
    64K-page kernels before sending a single query; dig-tier tests must
    skip there with the real reason, not fail on empty output.
    """
    if not _has("dig"):
        return False
    try:
        return (
            subprocess.run(["dig", "+short", ".", "NS"], capture_output=True, timeout=10).returncode
            == 0
        )
    except (OSError, subprocess.TimeoutExpired):
        return False


dig_broken = pytest.mark.skipif(
    _has("dig") and not _dig_functional(),
    reason="dig present but non-functional on this host",
)


def _infra_problem(message: str) -> None:
    """Broken container infrastructure: skip locally, fail in the matrix.

    The matrix images guarantee working nested podman, so a failed
    pre-check there is a real finding that must turn the slot red —
    skipping let a collapsed slot report green (95 skips in 5 seconds).
    Outside the matrix (TEROK_MATRIX unset) a missing capability is a
    legitimate host limitation and skipping stays correct.
    """
    if os.environ.get("TEROK_MATRIX"):
        pytest.fail(message, pytrace=False)
    pytest.skip(message)


def _hooks_available() -> bool:
    """Return True if OCI hooks will fire on container start.

    Either per-container ``--hooks-dir`` persists (future podman fix)
    or global hooks are installed via ``terok-shield setup``.
    """
    if has_global_hooks():
        return True
    if _has("podman"):
        output = subprocess.run(
            ["podman", "info", "-f", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout
        return parse_podman_info(output).hooks_dir_persists
    return False


# -- Matrix capability contract ------------------------------
# On a dev machine a missing binary is a host limitation, and the skip
# guards above are the right degradation.  Inside the matrix the harness
# BUILT the image, so every capability it declares (TEROK_EXPECT,
# exported by run-matrix.sh) is a contract: absence means the slot is
# broken and must fail at session start — not dissolve into skips that
# read as green (a collapsed slot once reported PASS on 95 skips).
# Presence-level probes only: host-dependent dysfunction (dig_broken on
# 64K-page kernels) stays a visible skip, because the image cannot
# control it.

_CAPABILITY_PROBES = {
    "podman": lambda: _has("podman"),
    "nft": lambda: bool(find_nft()),
    "dnsmasq": lambda: bool(which_sbin_aware("dnsmasq")),
    "dig": lambda: _has("dig"),
    "getent": lambda: _has("getent"),
    "hooks": _hooks_available,
    "internet": lambda: _tcp_reachable(ALLOWED_TARGET_IPS[0], 53),
}


def _tcp_reachable(ip: str, port: int, timeout: float = 5.0) -> bool:
    """Whether a TCP connection to ``ip:port`` succeeds within *timeout*."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def pytest_sessionstart(session: pytest.Session) -> None:
    """Fail the whole session when the matrix capability contract is broken."""
    expected = {c for c in os.environ.get("TEROK_EXPECT", "").split(",") if c}
    if not expected:
        return
    unknown = expected - _CAPABILITY_PROBES.keys()
    if unknown:
        pytest.exit(f"TEROK_EXPECT names unknown capabilities: {sorted(unknown)}", returncode=3)
    missing = sorted(cap for cap in expected if not _CAPABILITY_PROBES[cap]())
    if missing:
        pytest.exit(
            "matrix capability contract broken — expected but missing: " + ", ".join(missing),
            returncode=3,
        )


_hooks_available_cached = _hooks_available()

hooks_unavailable = pytest.mark.skipif(
    not _hooks_available_cached,
    reason=(
        "OCI hooks not available. "
        "Run 'terok-shield setup --user' to install, or use 'make test-matrix' for full coverage."
    ),
)
hooks_present = pytest.mark.skipif(
    _hooks_available_cached,
    reason="OCI hooks available — hookless error path not testable",
)


# -- Fixtures -------------------------------------------------


@pytest.fixture
def shield_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Provide an isolated state directory for shield operations.

    Sets ``TEROK_SHIELD_STATE_DIR`` so that CLI-based tests (which call
    ``_build_config()``) resolve paths correctly.  API-based tests should
    construct ``ShieldConfig(state_dir=...)`` explicitly.

    Yields:
        Path to the temporary state root directory.
    """
    with (
        tempfile.TemporaryDirectory() as tmp_state,
        tempfile.TemporaryDirectory() as tmp_config,
    ):
        monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp_state)
        monkeypatch.setenv("TEROK_SHIELD_CONFIG_DIR", tmp_config)
        yield Path(tmp_state)


@pytest.fixture(scope="session")
def _pull_image() -> None:
    """Pull the test image once per session (skipped if already present)."""
    if not _has("podman"):
        pytest.skip("podman not installed")
    if not _image_available():
        subprocess.run(["podman", "pull", IMAGE], check=True, timeout=120)


@pytest.fixture(scope="session")
def _verify_connectivity() -> None:
    """Verify basic internet connectivity from the host (once per session).

    Prevents false positives: if the host can't reach the internet,
    ``assert_blocked`` passes trivially (traffic is blocked by the network
    environment, not by terok-shield). Rootless podman with pasta shares
    the host's network stack, so host connectivity implies container
    pre-firewall connectivity.

    Raises ``pytest.fail()`` — not ``skip()`` — because broken host networking
    invalidates all traffic-based test results.
    """
    target_ip = ALLOWED_TARGET_IPS[0]
    try:
        s = socket.create_connection((target_ip, 53), timeout=5)
        s.close()
    except OSError as exc:
        pytest.fail(
            f"Pre-flight: cannot reach {target_ip}:53 from the host.\n"
            "Fix host internet connectivity before running integration tests.\n"
            "Traffic-based tests would produce false positives when the network "
            f"is down (assert_blocked passes trivially).\nError: {exc}"
        )


@pytest.fixture(scope="session")
def nft_in_netns(_pull_image: None, _verify_connectivity: None) -> None:
    """Verify nft works inside a container's network namespace.

    Unlike ``podman unshare nft list ruleset`` (which operates on the
    host netns and requires root), this tests the actual shield use case:
    nft inside a container-owned netns via nsenter, where the user
    namespace *does* have CAP_NET_ADMIN.
    """
    if not _has("podman") or not find_nft():
        pytest.skip("podman or nft not installed")
    name = f"{CTR_PREFIX}-nftcheck"
    _podman_rm(name)
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
        nft_path = find_nft()
        r = subprocess.run(
            ["podman", "unshare", "nsenter", "-t", pid, "-n", nft_path, "list", "ruleset"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode != 0:
            _infra_problem(f"nft not usable inside container netns: {r.stderr.strip()}")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        stderr = getattr(e, "stderr", b"") or b""
        _infra_problem(f"nft pre-check failed: {e}: {stderr.decode(errors='replace').strip()}")
    finally:
        _podman_rm(name)


@pytest.fixture
def container(_pull_image: None) -> Iterator[str]:
    """Start a disposable Alpine container, yield its name, clean up after."""
    name = f"{CTR_PREFIX}-{os.getpid()}"
    _podman_rm(name)
    try:
        subprocess.run(
            ["podman", "run", "-d", "--name", name, IMAGE, "sleep", "120"],
            check=True,
            capture_output=True,
            timeout=30,
        )
    except subprocess.CalledProcessError as e:
        # CalledProcessError hides stderr — surface the runtime's actual
        # complaint (this exact blindness cost a full matrix round).
        raise RuntimeError(
            f"podman run failed for {name}: {(e.stderr or b'').decode(errors='replace').strip()}"
        ) from e
    yield name
    _podman_rm(name)


@pytest.fixture
def container_pid(container: str) -> str:
    """Return the host PID of a running container."""
    from terok_shield.run import SubprocessRunner

    return SubprocessRunner().podman_inspect(container, "{{.State.Pid}}")


@pytest.fixture
def probe_container(_pull_image: None) -> Iterator[str]:
    """Start an Alpine container with Python and shield_probe installed."""
    name = f"{CTR_PREFIX}-probe-{os.getpid()}"
    _podman_rm(name)
    try:
        subprocess.run(
            ["podman", "run", "-d", "--name", name, IMAGE, "sleep", "120"],
            check=True,
            capture_output=True,
            timeout=30,
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
            pytest.fail(f"shield_probe.py not found at {probe_src}")
        subprocess.run(
            ["podman", "cp", str(probe_src), f"{name}:/usr/local/bin/shield_probe.py"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        yield name
    finally:
        _podman_rm(name)


def nsenter_nft(pid: str, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    """Run nft inside a container's netns via nsenter.

    Args:
        pid: Host PID of the container.
        *args: Additional nft arguments.
        stdin: Optional nft script to feed via stdin.

    Returns:
        Completed process result.
    """
    nft_path = find_nft() or "nft"
    cmd = ["podman", "unshare", "nsenter", "-t", pid, "-n", nft_path, *args]
    if stdin is not None:
        cmd.extend(["-f", "-"])
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=30)


@pytest.fixture
def shielded_container(
    _pull_image: None,
    shield_env: Path,
) -> Iterator[ShieldedContainer]:
    """Start a container with firewall applied via OCI hooks.

    Requires OCI hooks to be available — either global hooks installed
    via ``terok-shield setup``, or a podman version where per-container
    ``--hooks-dir`` persists across restart.

    1. ``Shield.pre_start()`` installs hooks, resolves DNS, returns podman args.
    2. ``podman run`` starts the container (OCI hooks apply the ruleset).
    3. Yields a `ShieldedContainer` — the container name, with the real
       podman id available via ``.id`` for the ``--container-id`` /
       ``container_id`` argument that ``Shield.down`` / ``Shield.up`` require.
    4. Cleanup: ``podman rm -f``.

    Yields:
        `ShieldedContainer` name (with ``.id``) with shield firewall applied.
    """
    if not _hooks_available_cached:
        pytest.skip(
            "OCI hooks not available. "
            "Run 'terok-shield setup --user' to install, "
            "or use 'make test-matrix' for full coverage."
        )

    from terok_shield import Shield, ShieldConfig

    name = f"{CTR_PREFIX}-api-{os.getpid()}"
    state_dir = shield_env / "containers" / name
    cfg = ShieldConfig(state_dir=state_dir)
    shield = Shield(cfg)

    _podman_rm(name)

    try:
        extra_args = shield.pre_start(name)
        cid = start_shielded_container(name, extra_args, IMAGE)
        yield ShieldedContainer(name, cid)
    finally:
        _podman_rm(name)
