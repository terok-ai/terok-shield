# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for per-container state bundle layout (state.py)."""

from collections.abc import Callable
from pathlib import Path

import pytest

from terok_shield.state import (
    BUNDLE_VERSION,
    audit_path,
    deny_path,
    ensure_state_dirs,
    hook_entrypoint,
    hook_json_path,
    hooks_dir,
    live_allowed_path,
    profile_allowed_path,
    read_denied_ips,
    read_effective_ips,
)

from ..testfs import FAKE_STATE_DIR
from ..testnet import TEST_IP1, TEST_IP2, TEST_IP3


def test_bundle_version_is_positive_int() -> None:
    """BUNDLE_VERSION is a positive integer."""
    assert isinstance(BUNDLE_VERSION, int)
    assert BUNDLE_VERSION > 0


@pytest.mark.parametrize(
    ("path_fn", "expected"),
    [
        pytest.param(hooks_dir, FAKE_STATE_DIR / "hooks", id="hooks-dir"),
        pytest.param(hook_entrypoint, FAKE_STATE_DIR / "terok-shield-hook", id="hook-entrypoint"),
        pytest.param(
            profile_allowed_path, FAKE_STATE_DIR / "profile.allowed", id="profile-allowed"
        ),
        pytest.param(live_allowed_path, FAKE_STATE_DIR / "live.allowed", id="live-allowed"),
        pytest.param(deny_path, FAKE_STATE_DIR / "deny.list", id="deny-path"),
        pytest.param(audit_path, FAKE_STATE_DIR / "audit.jsonl", id="audit-path"),
    ],
)
def test_path_derivation_functions(
    path_fn: Callable[[Path], Path],
    expected: Path,
) -> None:
    """Pure path helpers derive deterministic paths under the state dir."""
    assert path_fn(FAKE_STATE_DIR) == expected


@pytest.mark.parametrize(
    ("stage", "expected_name"),
    [
        pytest.param("createRuntime", "terok-shield-createRuntime.json", id="create-runtime"),
        pytest.param("poststop", "terok-shield-poststop.json", id="poststop"),
    ],
)
def test_hook_json_path(stage: str, expected_name: str) -> None:
    """hook_json_path() derives the per-stage OCI hook JSON filenames."""
    assert hook_json_path(FAKE_STATE_DIR, stage) == FAKE_STATE_DIR / "hooks" / expected_name


@pytest.mark.parametrize(
    "relative_state_dir",
    [
        pytest.param(Path("container-1"), id="single-level"),
        pytest.param(Path("deep") / "nested" / "state", id="nested"),
    ],
)
def test_ensure_state_dirs_creates_required_directories(
    tmp_path: Path,
    relative_state_dir: Path,
) -> None:
    """ensure_state_dirs() creates the state dir and hooks subdirectory."""
    state_dir = tmp_path / relative_state_dir
    ensure_state_dirs(state_dir)

    assert state_dir.is_dir()
    assert hooks_dir(state_dir).is_dir()


def test_ensure_state_dirs_is_idempotent(tmp_path: Path) -> None:
    """ensure_state_dirs() is safe to call repeatedly."""
    state_dir = tmp_path / "container-1"
    ensure_state_dirs(state_dir)
    ensure_state_dirs(state_dir)
    assert state_dir.is_dir()


def test_read_denied_ips_empty_when_file_missing(tmp_path: Path) -> None:
    """read_denied_ips() returns an empty set when deny.list is absent."""
    assert read_denied_ips(tmp_path) == set()


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        pytest.param(f"{TEST_IP1}\n{TEST_IP2}\n", {TEST_IP1, TEST_IP2}, id="multiple"),
        pytest.param(f"\n{TEST_IP1}\n\n", {TEST_IP1}, id="skip-blanks"),
    ],
)
def test_read_denied_ips(tmp_path: Path, content: str, expected: set[str]) -> None:
    """read_denied_ips() ignores blank lines while preserving denied entries."""
    deny_path(tmp_path).write_text(content)
    assert read_denied_ips(tmp_path) == expected


def test_read_effective_ips_subtracts_denied(tmp_path: Path) -> None:
    """Denied IPs are removed from the effective allow list."""
    profile_allowed_path(tmp_path).write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
    deny_path(tmp_path).write_text(f"{TEST_IP1}\n")
    assert read_effective_ips(tmp_path) == [TEST_IP2]


def test_read_effective_ips_without_deny_file_includes_live_entries(tmp_path: Path) -> None:
    """Without deny.list, effective IPs include both profile and live entries."""
    profile_allowed_path(tmp_path).write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
    live_allowed_path(tmp_path).write_text(f"{TEST_IP3}\n")
    assert read_effective_ips(tmp_path) == [TEST_IP1, TEST_IP2, TEST_IP3]


def test_read_effective_ips_ignores_denied_entries_not_in_allowed_set(tmp_path: Path) -> None:
    """Unmatched deny.list entries do not affect the effective allow list."""
    profile_allowed_path(tmp_path).write_text(f"{TEST_IP1}\n")
    deny_path(tmp_path).write_text(f"{TEST_IP3}\n")
    assert read_effective_ips(tmp_path) == [TEST_IP1]
