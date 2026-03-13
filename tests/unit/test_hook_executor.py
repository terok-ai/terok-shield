# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the HookExecutor class."""

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import pytest

from terok_shield import state
from terok_shield.oci_hook import HookExecutor
from terok_shield.run import ExecError

from ..testnet import RFC1918_HOST, TEST_IP1, TEST_IP2
from .helpers import write_lines


@dataclass
class HookExecutorHarness:
    """A ``HookExecutor`` plus its mock collaborators and state root."""

    executor: HookExecutor
    runner: mock.MagicMock
    audit: mock.MagicMock
    ruleset: mock.MagicMock
    state_dir: Path


HookExecutorHarnessFactory = Callable[..., HookExecutorHarness]


@pytest.fixture
def make_executor(tmp_path: Path) -> HookExecutorHarnessFactory:
    """Create a HookExecutor plus its default mock collaborators."""

    def _make_executor(
        *,
        runner: mock.MagicMock | None = None,
        audit: mock.MagicMock | None = None,
        ruleset: mock.MagicMock | None = None,
        state_dir: Path | None = None,
    ) -> HookExecutorHarness:
        runner = runner or mock.MagicMock()
        audit = audit or mock.MagicMock()
        ruleset = ruleset or mock.MagicMock()
        state_dir = state_dir or tmp_path
        return HookExecutorHarness(
            executor=HookExecutor(
                runner=runner,
                audit=audit,
                ruleset=ruleset,
                state_dir=state_dir,
            ),
            runner=runner,
            audit=audit,
            ruleset=ruleset,
            state_dir=state_dir,
        )

    return _make_executor


def _audit_details(harness: HookExecutorHarness) -> list[str]:
    """Return logged detail strings for the current harness."""
    return [call.kwargs.get("detail", "") for call in harness.audit.log_event.call_args_list]


def test_hook_executor_stores_collaborators(
    tmp_path: Path,
    make_executor: HookExecutorHarnessFactory,
) -> None:
    """Construction keeps the injected collaborators and state dir."""
    runner = mock.MagicMock()
    audit = mock.MagicMock()
    ruleset = mock.MagicMock()
    harness = make_executor(runner=runner, audit=audit, ruleset=ruleset, state_dir=tmp_path)
    assert harness.executor._runner is runner
    assert harness.executor._audit is audit
    assert harness.executor._ruleset is ruleset
    assert harness.executor._state_dir == tmp_path


@pytest.mark.parametrize(
    ("allowed_ips", "nft_side_effect", "add_elements", "expected_calls"),
    [
        pytest.param([], ["", "valid list output"], "", 2, id="no-pre-resolved-ips"),
        pytest.param(
            [TEST_IP1, TEST_IP2],
            ["", "", "valid list output"],
            f"add element allow_v4 {{ {TEST_IP1} }}",
            3,
            id="with-pre-resolved-ips",
        ),
    ],
)
def test_apply_successfully_applies_ruleset_and_verifies(
    make_executor: HookExecutorHarnessFactory,
    allowed_ips: list[str],
    nft_side_effect: list[str],
    add_elements: str,
    expected_calls: int,
) -> None:
    """apply() installs the hook ruleset, optional allow-set elements, and verifies."""
    harness = make_executor()
    if allowed_ips:
        write_lines(state.profile_allowed_path(harness.state_dir), allowed_ips)

    harness.runner.nft_via_nsenter.side_effect = nft_side_effect
    harness.ruleset.build_hook.return_value = "hook ruleset"
    harness.ruleset.verify_hook.return_value = []
    harness.ruleset.add_elements_dual.return_value = add_elements

    harness.executor.apply("test-ctr", "42")

    assert harness.runner.nft_via_nsenter.call_count == expected_calls
    details = _audit_details(harness)
    assert "ruleset applied" in details
    assert "verification passed" in details
    assert f"applied with {len(allowed_ips)} allowed IPs" in details


def test_apply_fails_closed_on_ruleset_apply_error(
    make_executor: HookExecutorHarnessFactory,
) -> None:
    """apply() short-circuits when nft rejects the hook ruleset."""
    harness = make_executor()
    harness.runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "permission denied")
    harness.ruleset.build_hook.return_value = "hook"

    with pytest.raises(RuntimeError):
        harness.executor.apply("test-ctr", "42")

    harness.runner.nft_via_nsenter.assert_called_once()
    harness.ruleset.verify_hook.assert_not_called()


def test_apply_fails_closed_on_verification_error(
    make_executor: HookExecutorHarnessFactory,
) -> None:
    """apply() raises RuntimeError when verification finds ruleset errors."""
    harness = make_executor()
    harness.runner.nft_via_nsenter.side_effect = ["", "bad output"]
    harness.ruleset.build_hook.return_value = "hook"
    harness.ruleset.verify_hook.return_value = ["policy is not drop"]

    with pytest.raises(RuntimeError, match="verification failed"):
        harness.executor.apply("test-ctr", "42")


@pytest.mark.parametrize(
    ("profile_lines", "live_lines", "deny_lines", "expected"),
    [
        pytest.param([TEST_IP1, TEST_IP2], [], [], [TEST_IP1, TEST_IP2], id="profile-only"),
        pytest.param([TEST_IP1], [TEST_IP2], [], [TEST_IP1, TEST_IP2], id="profile-and-live"),
        pytest.param([TEST_IP1], [TEST_IP1, TEST_IP2], [], [TEST_IP1, TEST_IP2], id="deduplicates"),
        pytest.param([], [], [], [], id="missing-files"),
        pytest.param(["", TEST_IP1, ""], [], [], [TEST_IP1], id="skips-blank-lines"),
        pytest.param([TEST_IP1, TEST_IP2], [], [TEST_IP1], [TEST_IP2], id="subtracts-denied"),
    ],
)
def test_read_allowed_ips_merges_allowlists(
    make_executor: HookExecutorHarnessFactory,
    profile_lines: list[str],
    live_lines: list[str],
    deny_lines: list[str],
    expected: list[str],
) -> None:
    """_read_allowed_ips() returns the effective allowlist from state files."""
    harness = make_executor()
    if profile_lines:
        write_lines(state.profile_allowed_path(harness.state_dir), profile_lines)
    if live_lines:
        write_lines(state.live_allowed_path(harness.state_dir), live_lines)
    if deny_lines:
        write_lines(state.deny_path(harness.state_dir), deny_lines)

    assert harness.executor._read_allowed_ips() == expected


def test_nft_exec_returns_runner_output(make_executor: HookExecutorHarnessFactory) -> None:
    """_nft_exec() returns the runner output on success."""
    harness = make_executor()
    harness.runner.nft_via_nsenter.return_value = "output"
    assert harness.executor._nft_exec("test-ctr", "42", "list", "ruleset") == "output"


@pytest.mark.parametrize(
    ("action", "expected_message"),
    [
        pytest.param("", "list failed", id="default-action-label"),
        pytest.param("add-elements", "add-elements failed", id="custom-action-label"),
    ],
)
def test_nft_exec_converts_exec_error_to_runtime_error(
    make_executor: HookExecutorHarnessFactory,
    action: str,
    expected_message: str,
) -> None:
    """_nft_exec() logs and re-raises runner failures as RuntimeError."""
    harness = make_executor(audit=mock.MagicMock())
    harness.runner.nft_via_nsenter.side_effect = ExecError(["nft"], 1, "fail")

    kwargs = {"stdin": "rules", "action": action} if action else {}
    args = () if action else ("list", "ruleset")
    with pytest.raises(RuntimeError, match=expected_message):
        harness.executor._nft_exec("test-ctr", "42", *args, **kwargs)
    harness.audit.log_event.assert_called()


def test_parse_oci_state_returns_container_and_pid() -> None:
    """parse_oci_state() exposes the static parser for valid OCI JSON."""
    cid, pid, annotations = HookExecutor.parse_oci_state(json.dumps({"id": "abc123", "pid": 42}))
    assert (cid, pid, annotations) == ("abc123", "42", {})


def test_parse_oci_state_rejects_invalid_json() -> None:
    """parse_oci_state() raises ValueError for malformed JSON."""
    with pytest.raises(ValueError):
        HookExecutor.parse_oci_state("not json")


def test_apply_logs_private_ranges_as_notes(make_executor: HookExecutorHarnessFactory) -> None:
    """Private-range IPs are logged as notes during apply()."""
    harness = make_executor()
    write_lines(state.profile_allowed_path(harness.state_dir), [RFC1918_HOST])

    harness.runner.nft_via_nsenter.side_effect = ["", "", "valid"]
    harness.ruleset.build_hook.return_value = "hook"
    harness.ruleset.verify_hook.return_value = []
    harness.ruleset.add_elements_dual.return_value = "add element"

    harness.executor.apply("test-ctr", "42")

    note_calls = [call for call in harness.audit.log_event.call_args_list if call.args[1] == "note"]
    assert any("private range" in call.kwargs.get("detail", "") for call in note_calls)


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(OSError("disk fail"), id="oserror"),
        pytest.param(UnicodeError("bad encoding"), id="unicodeerror"),
    ],
)
def test_apply_fails_closed_when_reading_cached_ips_fails(
    make_executor: HookExecutorHarnessFactory,
    error: Exception,
) -> None:
    """Cache read failures are converted into RuntimeError before nft verification."""
    harness = make_executor()
    harness.runner.nft_via_nsenter.return_value = ""
    harness.ruleset.build_hook.return_value = "hook"

    with mock.patch.object(harness.executor, "_read_allowed_ips", side_effect=error):
        with pytest.raises(RuntimeError):
            harness.executor.apply("test-ctr", "42")
