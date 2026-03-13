# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the CLI entry point."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from terok_shield import ExecError, ShieldState
from terok_shield.cli import (
    _auto_detect_mode,
    _build_config,
    _build_parser,
    _load_config_file,
    _parse_loopback_ports,
    _resolve_config_root,
    _resolve_state_root,
    main,
)
from terok_shield.config import ShieldMode

from ..testfs import (
    AUDIT_FILENAME,
    CONTAINERS_DIR_NAME,
    FAKE_CONFIG_DIR,
    FAKE_STATE_DIR,
    FAKE_STATE_DIR_STR,
    FAKE_XDG_CONFIG_HOME,
    FAKE_XDG_STATE_HOME,
    FORBIDDEN_TRAVERSAL,
    NFT_BINARY,
    NONEXISTENT_DIR,
    STATE_DIR_WITH_SPACES,
    VOLUME_MOUNT_DATA,
    VOLUME_MOUNT_HOST,
)
from ..testnet import TEST_DOMAIN, TEST_IP1
from .helpers import write_jsonl

_CONTAINER = "test"
_IMAGE = "alpine:latest"


@dataclass
class CliDispatchHarness:
    """Patched CLI collaborators for commands that construct a Shield."""

    build_config: mock.MagicMock
    shield_cls: mock.MagicMock

    @property
    def shield(self) -> mock.MagicMock:
        """Return the Shield instance that main() will use."""
        return self.shield_cls.return_value


@dataclass
class CliRunHarness(CliDispatchHarness):
    """Patched CLI collaborators for the ``run`` subcommand."""

    execvp: mock.MagicMock


@pytest.fixture
def parser() -> argparse.ArgumentParser:
    """Return a fresh CLI parser."""
    return _build_parser()


@pytest.fixture
def cli_dispatch() -> Iterator[CliDispatchHarness]:
    """Patch CLI config construction and Shield wiring."""
    with (
        mock.patch("terok_shield.cli._build_config") as build_config,
        mock.patch("terok_shield.cli.Shield") as shield_cls,
    ):
        yield CliDispatchHarness(build_config=build_config, shield_cls=shield_cls)


@pytest.fixture
def cli_run() -> Iterator[CliRunHarness]:
    """Patch CLI collaborators plus ``os.execvp`` for ``run`` tests."""
    with (
        mock.patch("terok_shield.cli._build_config") as build_config,
        mock.patch("terok_shield.cli.Shield") as shield_cls,
        mock.patch("os.execvp") as execvp,
    ):
        yield CliRunHarness(build_config=build_config, shield_cls=shield_cls, execvp=execvp)


def _write_audit_entries(state_root: Path, container: str, entries: list[dict[str, str]]) -> Path:
    """Write JSONL audit entries for a specific container."""
    return write_jsonl(state_root / CONTAINERS_DIR_NAME / container / AUDIT_FILENAME, entries)


def _set_env(
    monkeypatch: pytest.MonkeyPatch,
    *,
    cleared_keys: tuple[str, ...],
    env: dict[str, str],
) -> None:
    """Clear selected environment keys, then apply test overrides."""
    for key in cleared_keys:
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)


@pytest.fixture
def force_hook_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force CLI config building to use hook mode without autodetection."""
    monkeypatch.setattr("terok_shield.cli._auto_detect_mode", lambda: ShieldMode.HOOK)


@pytest.mark.parametrize(
    ("args", "command"),
    [
        pytest.param(["status"], "status", id="status"),
        pytest.param(["rules", _CONTAINER], "rules", id="rules"),
        pytest.param(["logs"], "logs", id="logs"),
        pytest.param(["down", _CONTAINER], "down", id="down"),
        pytest.param(["up", _CONTAINER], "up", id="up"),
        pytest.param(["preview"], "preview", id="preview"),
        pytest.param(["profiles"], "profiles", id="profiles"),
    ],
)
def test_parser_recognizes_subcommands(
    parser: argparse.ArgumentParser,
    args: list[str],
    command: str,
) -> None:
    """The parser accepts each registered subcommand."""
    assert parser.parse_args(args).command == command


@pytest.mark.parametrize(
    "command",
    [
        pytest.param("prepare", id="prepare"),
        pytest.param("run", id="run"),
        pytest.param("resolve", id="resolve"),
        pytest.param("down", id="down"),
        pytest.param("up", id="up"),
    ],
)
def test_parser_requires_container(parser: argparse.ArgumentParser, command: str) -> None:
    """Container-oriented subcommands reject missing container arguments."""
    with pytest.raises(SystemExit):
        parser.parse_args([command])


@pytest.mark.parametrize(
    "command", [pytest.param("allow", id="allow"), pytest.param("deny", id="deny")]
)
def test_parser_requires_container_and_target(
    parser: argparse.ArgumentParser,
    command: str,
) -> None:
    """allow/deny require both the container and the target argument."""
    with pytest.raises(SystemExit):
        parser.parse_args([command])


def test_prepare_parser_supports_profiles(parser: argparse.ArgumentParser) -> None:
    """prepare accepts a positional container plus profile overrides."""
    parsed = parser.parse_args(["prepare", "my-ctr", "--profiles", "base", "extra"])
    assert parsed.command == "prepare"
    assert parsed.container == "my-ctr"
    assert parsed.profiles == ["base", "extra"]


def test_run_parser_supports_profiles(parser: argparse.ArgumentParser) -> None:
    """run accepts a positional container plus profile overrides."""
    parsed = parser.parse_args(["run", "my-ctr", "--profiles", "base"])
    assert parsed.command == "run"
    assert parsed.container == "my-ctr"
    assert parsed.profiles == ["base"]


def test_logs_parser_supports_optional_container_and_count(parser: argparse.ArgumentParser) -> None:
    """logs accepts optional filtering and count flags."""
    default_args = parser.parse_args(["logs"])
    filtered_args = parser.parse_args(["logs", "--container", _CONTAINER, "-n", "10"])
    assert default_args.container is None
    assert default_args.n == 50
    assert filtered_args.container == _CONTAINER
    assert filtered_args.n == 10


def test_down_parser_supports_allow_all(parser: argparse.ArgumentParser) -> None:
    """down defaults to allow_all=False and flips with --all."""
    assert not parser.parse_args(["down", "ctr"]).allow_all
    assert parser.parse_args(["down", "ctr", "--all"]).allow_all


@pytest.mark.parametrize(
    ("args", "expected_down", "expected_allow_all"),
    [
        pytest.param(["preview"], False, False, id="defaults"),
        pytest.param(["preview", "--down"], True, False, id="down"),
        pytest.param(["preview", "--down", "--all"], True, True, id="down-all"),
    ],
)
def test_preview_parser_supports_flags(
    parser: argparse.ArgumentParser,
    args: list[str],
    expected_down: bool,
    expected_allow_all: bool,
) -> None:
    """preview parses down/all flags without custom post-processing."""
    parsed = parser.parse_args(args)
    assert parsed.down is expected_down
    assert parsed.allow_all is expected_allow_all


def test_parser_supports_state_dir_flag(parser: argparse.ArgumentParser) -> None:
    """The global --state-dir option is available to all commands."""
    parsed = parser.parse_args(["--state-dir", FAKE_STATE_DIR_STR, "status"])
    assert parsed.state_dir == FAKE_STATE_DIR


@pytest.mark.parametrize(
    "argv", [pytest.param([], id="no-command"), pytest.param(["--help"], id="help")]
)
def test_main_help_paths_exit_zero(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    """main() prints help and exits 0 for help-style invocations."""
    with pytest.raises(SystemExit) as ctx:
        main(argv)
    assert ctx.value.code == 0
    assert "terok-shield" in capsys.readouterr().out


def test_main_status_dispatches_to_shield(cli_dispatch: CliDispatchHarness) -> None:
    """status constructs a Shield and calls shield.status()."""
    cli_dispatch.shield.status.return_value = {
        "mode": "hook",
        "audit_enabled": True,
        "profiles": ["dev-standard"],
    }
    main(["status"])
    cli_dispatch.shield.status.assert_called_once_with()


@pytest.mark.parametrize(
    ("argv", "profiles"),
    [
        pytest.param(["prepare", _CONTAINER], None, id="default-profiles"),
        pytest.param(
            ["prepare", _CONTAINER, "--profiles", "base", "extra"],
            ["base", "extra"],
            id="explicit-profiles",
        ),
    ],
)
def test_prepare_dispatches_and_prints_flags(
    cli_dispatch: CliDispatchHarness,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    profiles: list[str] | None,
) -> None:
    """prepare delegates to pre_start() and prints the podman flags."""
    cli_dispatch.shield.pre_start.return_value = ["--annotation", "a=b"]
    main(argv)
    cli_dispatch.shield.pre_start.assert_called_once_with(_CONTAINER, profiles)
    output = capsys.readouterr().out.strip()
    assert "--annotation" in output
    assert "--name" in output
    assert _CONTAINER in output


def test_prepare_json_output(
    cli_dispatch: CliDispatchHarness, capsys: pytest.CaptureFixture[str]
) -> None:
    """prepare --json emits a JSON array instead of shell-quoted args."""
    cli_dispatch.shield.pre_start.return_value = ["--annotation", "a=b"]
    main(["prepare", _CONTAINER, "--json"])
    output = json.loads(capsys.readouterr().out)
    assert output == ["--annotation", "a=b", "--name", _CONTAINER]


def test_prepare_output_is_shell_safe(
    cli_dispatch: CliDispatchHarness, capsys: pytest.CaptureFixture[str]
) -> None:
    """prepare quotes annotations that contain spaces."""
    annotation = f"terok.shield.state_dir={STATE_DIR_WITH_SPACES}"
    cli_dispatch.shield.pre_start.return_value = ["--annotation", annotation]
    main(["prepare", _CONTAINER])
    assert f"'{annotation}'" in capsys.readouterr().out.strip()


@pytest.mark.parametrize(
    ("argv", "profiles", "expected_tail"),
    [
        pytest.param(
            ["run", _CONTAINER, "--", _IMAGE, "sh"],
            None,
            [_IMAGE, "sh"],
            id="basic-run",
        ),
        pytest.param(
            ["run", _CONTAINER, "--profiles", "custom", "--", _IMAGE],
            ["custom"],
            [_IMAGE],
            id="run-with-profiles",
        ),
        pytest.param(
            ["run", _CONTAINER, "--", "-v", VOLUME_MOUNT_HOST, _IMAGE, "sh"],
            None,
            ["-v", VOLUME_MOUNT_HOST, _IMAGE, "sh"],
            id="split-trailing-args",
        ),
        pytest.param(
            ["run", _CONTAINER, "--", "-d", "-e", "FOO=bar", _IMAGE],
            None,
            ["-d", "-e", "FOO=bar", _IMAGE],
            id="non-managed-flags-pass-through",
        ),
        pytest.param(
            ["run", _CONTAINER, "--", "-v", VOLUME_MOUNT_DATA, "-p", "8080:80", _IMAGE],
            None,
            ["-v", VOLUME_MOUNT_DATA, "-p", "8080:80", _IMAGE],
            id="user-podman-flags",
        ),
    ],
)
def test_run_execs_podman_with_shield_flags(
    cli_run: CliRunHarness,
    argv: list[str],
    profiles: list[str] | None,
    expected_tail: list[str],
) -> None:
    """run() validates args, calls pre_start(), and execs podman run."""
    cli_run.shield.pre_start.return_value = ["--annotation", "a=b"]
    main(argv)
    cli_run.shield.pre_start.assert_called_once_with(_CONTAINER, profiles)
    cli_run.execvp.assert_called_once()
    podman_argv = cli_run.execvp.call_args.args[1]
    assert podman_argv[:3] == ["podman", "run", "--name"]
    assert _CONTAINER in podman_argv
    for item in expected_tail:
        assert item in podman_argv


@pytest.mark.parametrize(
    ("argv", "expected_code"),
    [
        pytest.param(["run", _CONTAINER, "--"], 1, id="no-image-after-separator"),
        pytest.param(["run", _CONTAINER], 1, id="no-separator-or-image"),
        pytest.param(["resolve", _CONTAINER, "--", "junk"], 2, id="separator-on-non-run"),
        pytest.param(["--", "junk"], 2, id="bare-separator"),
    ],
)
def test_run_and_separator_validation(
    cli_dispatch: CliDispatchHarness,
    argv: list[str],
    expected_code: int,
) -> None:
    """main() rejects malformed run invocations and misplaced separators."""
    with pytest.raises(SystemExit) as ctx:
        main(argv)
    assert ctx.value.code == expected_code
    cli_dispatch.shield.pre_start.assert_not_called()


@pytest.mark.parametrize(
    "flag",
    [
        pytest.param("--name", id="name"),
        pytest.param("--network", id="network"),
        pytest.param("--hooks-dir", id="hooks-dir"),
        pytest.param("--annotation", id="annotation"),
        pytest.param("--cap-add", id="cap-add"),
        pytest.param("--cap-drop", id="cap-drop"),
        pytest.param("--security-opt", id="security-opt"),
        pytest.param("--network=host", id="network-equals"),
        pytest.param("--name=other", id="name-equals"),
        pytest.param("--annotation=a=b", id="annotation-equals"),
        pytest.param("--hooks-dir=/tmp", id="hooks-dir-equals"),
        pytest.param("--cap-add=NET_ADMIN", id="cap-add-equals"),
        pytest.param("--cap-drop=ALL", id="cap-drop-equals"),
        pytest.param("--security-opt=no-new-privileges", id="security-opt-equals"),
    ],
)
def test_run_rejects_shield_managed_flags(
    cli_dispatch: CliDispatchHarness,
    flag: str,
) -> None:
    """run() rejects podman flags that terok-shield manages itself."""
    args = ["run", _CONTAINER, "--", flag, _IMAGE]
    if "=" not in flag:
        args.insert(-1, "val")
    with pytest.raises(SystemExit) as ctx:
        main(args)
    assert ctx.value.code == 1
    cli_dispatch.shield.pre_start.assert_not_called()


def test_main_uses_sys_argv_when_argv_is_none(cli_dispatch: CliDispatchHarness) -> None:
    """main(None) falls back to sys.argv[1:]."""
    cli_dispatch.shield.status.return_value = {
        "mode": "hook",
        "audit_enabled": True,
        "profiles": ["dev-standard"],
    }
    with mock.patch.object(sys, "argv", ["terok-shield", "status"]):
        main(None)
    cli_dispatch.shield.status.assert_called_once_with()


@pytest.mark.parametrize(
    ("argv", "force"),
    [
        pytest.param(["resolve", _CONTAINER], False, id="default"),
        pytest.param(["resolve", _CONTAINER, "--force"], True, id="force"),
    ],
)
def test_resolve_dispatches_force_flag(
    cli_dispatch: CliDispatchHarness,
    argv: list[str],
    force: bool,
) -> None:
    """resolve delegates to shield.resolve() with the parsed force flag."""
    cli_dispatch.shield.resolve.return_value = [TEST_IP1]
    main(argv)
    cli_dispatch.shield.resolve.assert_called_once_with(force=force)


@pytest.mark.parametrize(
    ("command", "method_name"),
    [
        pytest.param("allow", "allow", id="allow"),
        pytest.param("deny", "deny", id="deny"),
    ],
)
def test_allow_and_deny_dispatch_to_shield(
    cli_dispatch: CliDispatchHarness,
    command: str,
    method_name: str,
) -> None:
    """allow/deny dispatch to the corresponding facade methods."""
    getattr(cli_dispatch.shield, method_name).return_value = [TEST_IP1]
    main([command, _CONTAINER, TEST_IP1])
    getattr(cli_dispatch.shield, method_name).assert_called_once_with(_CONTAINER, TEST_IP1)


@pytest.mark.parametrize(
    ("argv", "method_name", "expected_call"),
    [
        pytest.param(
            ["down", _CONTAINER], "down", mock.call(_CONTAINER, allow_all=False), id="down"
        ),
        pytest.param(
            ["down", _CONTAINER, "--all"],
            "down",
            mock.call(_CONTAINER, allow_all=True),
            id="down-all",
        ),
        pytest.param(["up", _CONTAINER], "up", mock.call(_CONTAINER), id="up"),
        pytest.param(
            ["preview"],
            "preview",
            mock.call(down=False, allow_all=False),
            id="preview-default",
        ),
        pytest.param(
            ["preview", "--down"],
            "preview",
            mock.call(down=True, allow_all=False),
            id="preview-down",
        ),
        pytest.param(
            ["preview", "--down", "--all"],
            "preview",
            mock.call(down=True, allow_all=True),
            id="preview-down-all",
        ),
        pytest.param(["profiles"], "profiles_list", mock.call(), id="profiles"),
    ],
)
def test_misc_dispatch_paths(
    cli_dispatch: CliDispatchHarness,
    argv: list[str],
    method_name: str,
    expected_call: Any,
) -> None:
    """Simple CLI subcommands dispatch to the expected Shield methods."""
    if method_name == "preview":
        cli_dispatch.shield.preview.return_value = "table inet terok_shield {}"
    elif method_name == "profiles_list":
        cli_dispatch.shield.profiles_list.return_value = ["dev-standard", "dev-python"]

    main(argv)

    dispatched = getattr(cli_dispatch.shield, method_name)
    assert dispatched.call_count == 1
    assert dispatched.call_args == expected_call


def test_rules_dispatches_to_state_and_rules(cli_dispatch: CliDispatchHarness) -> None:
    """rules shows state first and then the rendered nft ruleset."""
    cli_dispatch.shield.state.return_value = ShieldState.UP
    cli_dispatch.shield.rules.return_value = "table inet terok_shield {}"
    main(["rules", _CONTAINER])
    cli_dispatch.shield.state.assert_called_once_with(_CONTAINER)
    cli_dispatch.shield.rules.assert_called_once_with(_CONTAINER)


def test_preview_requires_down_for_all() -> None:
    """preview --all without --down exits 1."""
    with pytest.raises(SystemExit) as ctx:
        main(["preview", "--all"])
    assert ctx.value.code == 1


@pytest.mark.parametrize(
    ("status", "expected_substrings"),
    [
        pytest.param(
            {"mode": "hook", "audit_enabled": True, "profiles": ["dev-standard"]},
            ["Mode:", "hook", "Audit:", "enabled"],
            id="audit-enabled",
        ),
        pytest.param(
            {"mode": "hook", "audit_enabled": False, "profiles": []},
            ["disabled", "(none)"],
            id="audit-disabled-no-profiles",
        ),
    ],
)
def test_status_output_formatting(
    cli_dispatch: CliDispatchHarness,
    capsys: pytest.CaptureFixture[str],
    status: dict[str, object],
    expected_substrings: list[str],
) -> None:
    """status output is human-readable for both enabled and disabled audit."""
    cli_dispatch.shield.status.return_value = status
    main(["status"])
    output = capsys.readouterr().out
    for text in expected_substrings:
        assert text in output


@pytest.mark.parametrize(
    ("command", "method_name"),
    [
        pytest.param("allow", "allow", id="allow"),
        pytest.param("deny", "deny", id="deny"),
    ],
)
def test_allow_and_deny_exit_1_when_nothing_changes(
    cli_dispatch: CliDispatchHarness,
    command: str,
    method_name: str,
) -> None:
    """allow/deny fail with exit code 1 when no IPs are changed."""
    getattr(cli_dispatch.shield, method_name).return_value = []
    with pytest.raises(SystemExit) as ctx:
        main([command, _CONTAINER, TEST_DOMAIN])
    assert ctx.value.code == 1


def test_rules_output_for_missing_rules(
    cli_dispatch: CliDispatchHarness,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """rules prints a friendly message when the ruleset is empty."""
    cli_dispatch.shield.state.return_value = ShieldState.INACTIVE
    cli_dispatch.shield.rules.return_value = ""
    main(["rules", _CONTAINER])
    assert "No rules found" in capsys.readouterr().out


def test_logs_without_files_reports_empty(
    state_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """logs reports when no audit files exist in the state root."""
    main(["--state-dir", str(state_root), "logs"])
    assert "No audit logs found" in capsys.readouterr().out


def test_logs_with_container_reads_single_audit_file(
    state_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """logs --container reads and prints entries from one audit file."""
    _write_audit_entries(
        state_root,
        _CONTAINER,
        [{"action": "setup", "ts": "2026-01-01T00:00:00"}],
    )
    main(["--state-dir", str(state_root), "logs", "--container", _CONTAINER])
    entry = json.loads(capsys.readouterr().out.strip())
    assert entry["action"] == "setup"


def test_logs_global_mode_merges_and_sorts(
    state_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """logs without --container merges entries across containers by timestamp."""
    _write_audit_entries(
        state_root,
        "ctr-a",
        [
            {"action": "a1", "ts": "2026-01-01T00:00:02"},
            {"action": "a2", "ts": "2026-01-01T00:00:04"},
        ],
    )
    _write_audit_entries(
        state_root,
        "ctr-b",
        [
            {"action": "b1", "ts": "2026-01-01T00:00:01"},
            {"action": "b2", "ts": "2026-01-01T00:00:03"},
        ],
    )

    main(["--state-dir", str(state_root), "logs", "-n", "3"])
    actions = [json.loads(line)["action"] for line in capsys.readouterr().out.strip().splitlines()]
    assert actions == ["a1", "b2", "a2"]


def test_logs_global_mode_ignores_containers_without_audit_files(
    state_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """logs reports no audit logs when container directories lack audit files."""
    (state_root / CONTAINERS_DIR_NAME / "empty-ctr").mkdir(parents=True)
    main(["--state-dir", str(state_root), "logs"])
    assert "No audit logs found" in capsys.readouterr().out


def test_logs_rejects_container_path_traversal(state_root: Path) -> None:
    """logs validates the optional --container value."""
    with pytest.raises(SystemExit) as ctx:
        main(["--state-dir", str(state_root), "logs", "--container", FORBIDDEN_TRAVERSAL])
    assert ctx.value.code == 1


def test_profiles_output_lists_one_profile_per_line(
    cli_dispatch: CliDispatchHarness,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """profiles prints one profile name per line."""
    cli_dispatch.shield.profiles_list.return_value = ["dev-standard", "dev-python"]
    main(["profiles"])
    assert capsys.readouterr().out.strip().splitlines() == ["dev-standard", "dev-python"]


def test_status_with_container_dispatches(cli_dispatch: CliDispatchHarness) -> None:
    """status <container> dispatches to shield.state()."""
    cli_dispatch.shield.state.return_value = ShieldState.UP
    main(["status", _CONTAINER])
    cli_dispatch.shield.state.assert_called_once_with(_CONTAINER)


def test_status_container_output(
    cli_dispatch: CliDispatchHarness,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """status <container> prints the state value, not the enum repr."""
    cli_dispatch.shield.state.return_value = ShieldState.DOWN
    main(["status", _CONTAINER])
    assert capsys.readouterr().out.strip() == "down"


@pytest.mark.parametrize(
    ("argv", "method_name", "error"),
    [
        pytest.param(["status"], "status", RuntimeError("nope"), id="runtime-error"),
        pytest.param(["allow", _CONTAINER, "bad"], "allow", ValueError("bad ip"), id="value-error"),
        pytest.param(
            ["status"],
            "status",
            ExecError(["nft", "list"], 1, "command failed"),
            id="exec-error",
        ),
        pytest.param(["rules", _CONTAINER], "rules", OSError("permission denied"), id="os-error"),
    ],
)
def test_main_dispatch_errors_exit_1(
    cli_dispatch: CliDispatchHarness,
    argv: list[str],
    method_name: str,
    error: Exception,
) -> None:
    """main() converts expected dispatch errors into exit code 1."""
    getattr(cli_dispatch.shield, method_name).side_effect = error
    with pytest.raises(SystemExit) as ctx:
        main(argv)
    assert ctx.value.code == 1


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        pytest.param({}, None, id="default"),
        pytest.param(
            {"TEROK_SHIELD_STATE_DIR": str(FAKE_STATE_DIR)}, FAKE_STATE_DIR, id="env-override"
        ),
        pytest.param(
            {"XDG_STATE_HOME": str(FAKE_XDG_STATE_HOME)},
            FAKE_XDG_STATE_HOME / "terok-shield",
            id="xdg",
        ),
        pytest.param(
            {
                "TEROK_SHIELD_STATE_DIR": str(FAKE_STATE_DIR),
                "XDG_STATE_HOME": str(FAKE_XDG_STATE_HOME),
            },
            FAKE_STATE_DIR,
            id="explicit-overrides-xdg",
        ),
    ],
)
def test_resolve_state_root(
    monkeypatch: pytest.MonkeyPatch, env: dict[str, str], expected: Path | None
) -> None:
    """_resolve_state_root() honors explicit env vars before XDG defaults."""
    _set_env(
        monkeypatch,
        cleared_keys=("TEROK_SHIELD_STATE_DIR", "XDG_STATE_HOME"),
        env=env,
    )
    root = _resolve_state_root()
    if expected is None:
        assert str(root).endswith("terok-shield")
    else:
        assert root == expected


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        pytest.param({}, None, id="default"),
        pytest.param(
            {"TEROK_SHIELD_CONFIG_DIR": str(FAKE_CONFIG_DIR)}, FAKE_CONFIG_DIR, id="env-override"
        ),
        pytest.param(
            {"XDG_CONFIG_HOME": str(FAKE_XDG_CONFIG_HOME)},
            FAKE_XDG_CONFIG_HOME / "terok-shield",
            id="xdg",
        ),
    ],
)
def test_resolve_config_root(
    monkeypatch: pytest.MonkeyPatch, env: dict[str, str], expected: Path | None
) -> None:
    """_resolve_config_root() honors explicit env vars before XDG defaults."""
    _set_env(
        monkeypatch,
        cleared_keys=("TEROK_SHIELD_CONFIG_DIR", "XDG_CONFIG_HOME"),
        env=env,
    )
    root = _resolve_config_root()
    if expected is None:
        assert str(root).endswith("terok-shield")
    else:
        assert root == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param([8080, 9090], (8080, 9090), id="valid-list"),
        pytest.param(1234, (1234,), id="single-int"),
        pytest.param([], (), id="empty-list"),
        pytest.param([True], (), id="bool-dropped"),
        pytest.param([99999], (), id="out-of-range-dropped"),
        pytest.param([8080, 0, True, 9090], (8080, 9090), id="mixed-valid-invalid"),
        pytest.param(True, (), id="bare-bool"),
        pytest.param("not-a-list", (), id="string-input"),
    ],
)
def test_parse_loopback_ports(raw: object, expected: tuple[int, ...]) -> None:
    """_parse_loopback_ports() accepts ints/lists and silently drops invalid values."""
    assert _parse_loopback_ports(raw) == expected


def test_auto_detect_mode_raises_without_nft(monkeypatch: pytest.MonkeyPatch) -> None:
    """_auto_detect_mode() fails when nft is unavailable."""
    monkeypatch.setattr("terok_shield.run.find_nft", lambda: "")
    with pytest.raises(RuntimeError):
        _auto_detect_mode()


def test_auto_detect_mode_returns_hook(monkeypatch: pytest.MonkeyPatch) -> None:
    """_auto_detect_mode() selects hook mode when nft is installed."""
    monkeypatch.setattr("terok_shield.run.find_nft", lambda: NFT_BINARY)
    assert _auto_detect_mode() == ShieldMode.HOOK


@pytest.mark.parametrize(
    "config_text",
    [
        pytest.param(": [invalid yaml\n  bad: {unclosed", id="malformed-yaml"),
        pytest.param("- just\n- a\n- list\n", id="non-dict-yaml"),
    ],
)
def test_load_config_file_returns_empty_for_invalid_inputs(
    monkeypatch: pytest.MonkeyPatch,
    config_root: Path,
    config_text: str,
) -> None:
    """_load_config_file() returns an empty mapping for malformed or non-dict YAML."""
    (config_root / "config.yml").write_text(config_text)
    monkeypatch.setenv("TEROK_SHIELD_CONFIG_DIR", str(config_root))
    assert _load_config_file() == {}


def test_build_config_uses_defaults_when_config_file_is_missing(
    force_hook_mode: None,
) -> None:
    """_build_config() falls back to defaults when config.yml is absent."""
    config = _build_config("test-ctr", state_dir_override=NONEXISTENT_DIR)
    assert config.mode == ShieldMode.HOOK
    assert config.state_dir == NONEXISTENT_DIR.resolve() / "containers" / "test-ctr"


def test_build_config_loads_yaml(
    isolated_roots: tuple[Path, Path],
    write_config: Callable[[str], Path],
) -> None:
    """_build_config() loads mode, profiles, ports, and audit settings from YAML."""
    state_root, _ = isolated_roots
    write_config(
        "mode: hook\n"
        "default_profiles: [base, dev-python]\n"
        "loopback_ports: [1234, 5678]\n"
        "audit:\n"
        "  enabled: false\n"
    )
    config = _build_config("ctr", state_dir_override=state_root)
    assert config.mode == ShieldMode.HOOK
    assert config.default_profiles == ("base", "dev-python")
    assert config.loopback_ports == (1234, 5678)
    assert not config.audit_enabled


def test_build_config_state_dir_override_and_default_container(
    force_hook_mode: None,
    state_root: Path,
) -> None:
    """_build_config() respects explicit state roots and default container names."""
    assert (
        _build_config("my-ctr", state_dir_override=state_root).state_dir
        == state_root / "containers" / "my-ctr"
    )
    assert (
        _build_config(state_dir_override=state_root).state_dir
        == state_root / "containers" / "_default"
    )


def test_build_config_rejects_unknown_mode(
    isolated_roots: tuple[Path, Path],
    write_config: Callable[[str], Path],
) -> None:
    """_build_config() rejects unknown mode strings from config.yml."""
    state_root, _ = isolated_roots
    write_config("mode: bridge\n")
    with pytest.raises(ValueError, match="Unknown shield mode"):
        _build_config("ctr", state_dir_override=state_root)


@pytest.mark.parametrize(
    ("config_text", "expected_profiles", "expected_audit_enabled"),
    [
        pytest.param(
            "default_profiles: not-a-list\n", ("dev-standard",), True, id="profiles-not-list"
        ),
        pytest.param(
            "default_profiles: [1, null]\n", ("dev-standard",), True, id="profiles-not-strings"
        ),
        pytest.param("audit: not-a-dict\n", ("dev-standard",), True, id="audit-not-dict"),
        pytest.param(
            "audit:\n  enabled: yes-please\n", ("dev-standard",), True, id="audit-enabled-not-bool"
        ),
    ],
)
def test_build_config_falls_back_for_invalid_sections(
    force_hook_mode: None,
    isolated_roots: tuple[Path, Path],
    write_config: Callable[[str], Path],
    config_text: str,
    expected_profiles: tuple[str, ...],
    expected_audit_enabled: bool,
) -> None:
    """_build_config() falls back to safe defaults for invalid config sections."""
    state_root, _ = isolated_roots
    write_config(config_text)
    config = _build_config("ctr", state_dir_override=state_root)
    assert config.default_profiles == expected_profiles
    assert config.audit_enabled is expected_audit_enabled


def test_build_config_rejects_container_path_traversal(
    force_hook_mode: None,
    state_root: Path,
) -> None:
    """_build_config() validates container names before constructing state paths."""
    with pytest.raises(ValueError):
        _build_config(FORBIDDEN_TRAVERSAL, state_dir_override=state_root)


def test_build_config_uses_resolved_state_root_when_not_overridden(
    force_hook_mode: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without --state-dir, _build_config() resolves the state root from the environment."""
    monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", str(FAKE_STATE_DIR))
    monkeypatch.setenv("TEROK_SHIELD_CONFIG_DIR", str(NONEXISTENT_DIR / "config"))
    config = _build_config("ctr")
    assert config.state_dir == FAKE_STATE_DIR / "containers" / "ctr"
