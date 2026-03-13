# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for subprocess helpers."""

import shutil
import subprocess
from collections.abc import Iterator
from unittest import mock

import pytest

from terok_shield.run import CommandRunner, ExecError, SubprocessRunner

from ..testfs import NFT_BINARY
from ..testnet import (
    ALIAS_DOMAIN,
    IPV6_CLOUDFLARE,
    NONEXISTENT_DOMAIN,
    TEST_DOMAIN,
    TEST_IP1,
    TEST_IP2,
)


def _completed(*, rc: int = 0, stdout: str = "", stderr: str = "") -> mock.Mock:
    """Return a completed subprocess result mock."""
    return mock.Mock(returncode=rc, stdout=stdout, stderr=stderr)


@pytest.fixture
def runner() -> SubprocessRunner:
    """Return a fresh subprocess runner."""
    return SubprocessRunner()


@pytest.fixture
def subprocess_run() -> Iterator[mock.Mock]:
    """Patch ``subprocess.run`` for the duration of a test."""
    with mock.patch("subprocess.run") as patched:
        yield patched


def test_exec_error_attributes() -> None:
    """Store command, return code, and stderr."""
    err = ExecError(["nft", "list"], 1, "permission denied")
    assert err.cmd == ["nft", "list"]
    assert err.rc == 1
    assert err.stderr == "permission denied"


def test_exec_error_message() -> None:
    """Format a human-readable error message."""
    err = ExecError(["nft"], 2, "  error  ")
    assert "rc=2" in str(err)
    assert "error" in str(err)


def test_subprocess_runner_implements_command_runner(runner: SubprocessRunner) -> None:
    """SubprocessRunner satisfies the CommandRunner protocol."""
    assert isinstance(runner, CommandRunner)


@pytest.mark.parametrize(
    ("check", "result", "expected"),
    [
        pytest.param(True, _completed(stdout="output\n"), "output\n", id="success"),
        pytest.param(
            False, _completed(rc=1, stdout="partial", stderr="err"), "partial", id="check-false"
        ),
    ],
)
def test_run_returns_stdout(
    runner: SubprocessRunner,
    subprocess_run: mock.Mock,
    *,
    check: bool,
    result: mock.Mock,
    expected: str,
) -> None:
    """run() returns stdout on success and on check=False failures."""
    subprocess_run.return_value = result
    assert runner.run(["echo", "hi"], check=check) == expected


def test_run_raises_on_failure(runner: SubprocessRunner, subprocess_run: mock.Mock) -> None:
    """run() raises ExecError on non-zero exit when check=True."""
    subprocess_run.return_value = _completed(rc=1, stderr="fail")
    with pytest.raises(ExecError):
        runner.run(["false"])


@pytest.mark.parametrize(
    ("check", "expected_rc", "expected_result"),
    [
        pytest.param(True, 127, None, id="raises"),
        pytest.param(False, None, "", id="returns-empty"),
    ],
)
def test_run_handles_missing_binary(
    runner: SubprocessRunner,
    subprocess_run: mock.Mock,
    *,
    check: bool,
    expected_rc: int | None,
    expected_result: str | None,
) -> None:
    """run() converts missing binaries into a stable ExecError or empty result."""
    subprocess_run.side_effect = FileNotFoundError("No such file")

    if check:
        with pytest.raises(ExecError) as ctx:
            runner.run(["nonexistent"], check=check, timeout=5)
        assert ctx.value.rc == expected_rc
    else:
        assert runner.run(["nonexistent"], check=check, timeout=5) == expected_result


@pytest.mark.parametrize(
    ("check", "expected_rc", "expected_result", "expected_message"),
    [
        pytest.param(True, -1, None, "timed out", id="raises"),
        pytest.param(False, None, "", None, id="returns-empty"),
    ],
)
def test_run_handles_timeout(
    runner: SubprocessRunner,
    subprocess_run: mock.Mock,
    *,
    check: bool,
    expected_rc: int | None,
    expected_result: str | None,
    expected_message: str | None,
) -> None:
    """run() converts timeouts into a stable ExecError or empty result."""
    subprocess_run.side_effect = subprocess.TimeoutExpired(["slow-cmd"], 5)

    if check:
        with pytest.raises(ExecError) as ctx:
            runner.run(["slow-cmd"], check=check, timeout=5)
        assert ctx.value.rc == expected_rc
        if expected_message is not None:
            assert expected_message in ctx.value.stderr
    else:
        assert runner.run(["slow-cmd"], check=check, timeout=5) == expected_result


@pytest.mark.parametrize(
    ("which_result", "expected"),
    [
        pytest.param(NFT_BINARY, True, id="found"),
        pytest.param(None, False, id="missing"),
    ],
)
def test_has_uses_shutil_which(
    runner: SubprocessRunner,
    monkeypatch: pytest.MonkeyPatch,
    which_result: str | None,
    expected: bool,
) -> None:
    """has() reflects whether the executable can be found."""
    monkeypatch.setattr(shutil, "which", lambda _name: which_result)
    assert runner.has("nft") is expected


@pytest.mark.parametrize(
    ("args", "stdin", "expected_cmd", "expected_input"),
    [
        pytest.param(("list", "ruleset"), None, ["nft", "list", "ruleset"], None, id="args-only"),
        pytest.param(
            ("-c",),
            "table ip test {}",
            ["nft", "-c", "-f", "-"],
            "table ip test {}",
            id="stdin-with-extra-args",
        ),
        pytest.param(
            (), "table ip test {}", ["nft", "-f", "-"], "table ip test {}", id="stdin-only"
        ),
    ],
)
def test_nft_builds_expected_command(
    runner: SubprocessRunner,
    subprocess_run: mock.Mock,
    args: tuple[str, ...],
    stdin: str | None,
    expected_cmd: list[str],
    expected_input: str | None,
) -> None:
    """nft() translates args/stdin combinations into subprocess calls."""
    subprocess_run.return_value = _completed(stdout="output")
    result = runner.nft(*args, stdin=stdin)
    assert subprocess_run.call_args[0][0] == expected_cmd
    assert subprocess_run.call_args[1]["input"] == expected_input
    assert result == "output"


def test_nft_via_nsenter_enters_container_netns(
    runner: SubprocessRunner,
    subprocess_run: mock.Mock,
) -> None:
    """nft_via_nsenter looks up the PID and enters the container namespace."""
    subprocess_run.side_effect = [
        _completed(stdout="12345\n"),
        _completed(stdout="output"),
    ]

    result = runner.nft_via_nsenter("my-ctr", "list", "ruleset")

    assert subprocess_run.call_count == 2
    assert "podman" in subprocess_run.call_args_list[0][0][0]
    nsenter_cmd = subprocess_run.call_args_list[1][0][0]
    assert "nsenter" in nsenter_cmd
    assert "12345" in nsenter_cmd
    assert result == "output"


def test_nft_via_nsenter_uses_explicit_pid(
    runner: SubprocessRunner,
    subprocess_run: mock.Mock,
) -> None:
    """nft_via_nsenter skips podman inspect when pid is provided."""
    subprocess_run.return_value = _completed(stdout="output")
    result = runner.nft_via_nsenter("my-ctr", "list", "ruleset", pid="999")
    assert subprocess_run.call_args[0][0].count("999") == 1
    assert result == "output"


def test_nft_via_nsenter_passes_stdin(
    runner: SubprocessRunner,
    subprocess_run: mock.Mock,
) -> None:
    """nft_via_nsenter forwards stdin to ``nft -f -`` inside nsenter."""
    subprocess_run.side_effect = [_completed(stdout="12345\n"), _completed()]
    runner.nft_via_nsenter("my-ctr", stdin="flush ruleset")
    nsenter_call = subprocess_run.call_args_list[1]
    assert "-f" in nsenter_call[0][0]
    assert nsenter_call[1]["input"] == "flush ruleset"


def test_podman_inspect_returns_stripped_output(
    runner: SubprocessRunner,
    subprocess_run: mock.Mock,
) -> None:
    """podman_inspect strips whitespace from inspect output."""
    subprocess_run.return_value = _completed(stdout="  12345  \n")
    result = runner.podman_inspect("my-ctr", "{{.State.Pid}}")
    assert subprocess_run.call_args[0][0] == [
        "podman",
        "inspect",
        "--format",
        "{{.State.Pid}}",
        "my-ctr",
    ]
    assert result == "12345"


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        pytest.param(
            f"{TEST_IP1}\n{TEST_IP2}\n{IPV6_CLOUDFLARE}\n",
            [TEST_IP1, TEST_IP2, IPV6_CLOUDFLARE],
            id="ipv4-and-ipv6",
        ),
        pytest.param(
            f"{ALIAS_DOMAIN}\n{TEST_IP1}\n{IPV6_CLOUDFLARE}\n",
            [TEST_IP1, IPV6_CLOUDFLARE],
            id="filters-non-ip-lines",
        ),
        pytest.param(
            f"\n{TEST_IP1}\n\n{TEST_IP2}\n\n",
            [TEST_IP1, TEST_IP2],
            id="skips-blank-lines",
        ),
    ],
)
def test_dig_all_filters_output(
    runner: SubprocessRunner,
    subprocess_run: mock.Mock,
    stdout: str,
    expected: list[str],
) -> None:
    """dig_all() keeps only parsed IP addresses from subprocess output."""
    subprocess_run.return_value = _completed(stdout=stdout)
    assert runner.dig_all(TEST_DOMAIN) == expected


def test_dig_all_returns_empty_on_failure(
    runner: SubprocessRunner,
    subprocess_run: mock.Mock,
) -> None:
    """dig_all() returns an empty list when dig fails under check=False."""
    subprocess_run.return_value = _completed(rc=1)
    assert runner.dig_all(NONEXISTENT_DOMAIN) == []


def test_dig_all_returns_empty_when_binary_missing(
    runner: SubprocessRunner,
    subprocess_run: mock.Mock,
) -> None:
    """dig_all() returns an empty list when the dig binary is unavailable."""
    subprocess_run.side_effect = FileNotFoundError("dig not found")
    assert runner.dig_all(TEST_DOMAIN) == []


def test_dig_all_uses_single_query(
    runner: SubprocessRunner,
    subprocess_run: mock.Mock,
) -> None:
    """dig_all() uses a single subprocess for both A and AAAA lookups."""
    subprocess_run.return_value = _completed(stdout=f"{TEST_IP1}\n")
    runner.dig_all(TEST_DOMAIN)
    cmd = subprocess_run.call_args[0][0]
    assert "A" in cmd
    assert "AAAA" in cmd
