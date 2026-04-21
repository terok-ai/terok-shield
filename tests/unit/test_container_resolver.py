# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the podman-annotation based state_dir resolver."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest import mock

from terok_shield import container as resolver

_ANN_KEY = "terok.shield.state_dir"


def _fake_inspect_output(annotations: dict[str, str]) -> str:
    """Shape one ``podman inspect --format=json`` record around our annotations."""
    return json.dumps([{"Name": "/example", "Id": "abc", "Config": {"Annotations": annotations}}])


class TestResolveStateDir:
    """Happy-path and every failure branch collapses to ``None``."""

    def test_returns_annotation_path(self, tmp_path: Path) -> None:
        sd = tmp_path / "shield"
        sd.mkdir()
        with mock.patch.object(resolver.shutil, "which", return_value="/usr/bin/podman"):
            result = mock.MagicMock(returncode=0, stdout=_fake_inspect_output({_ANN_KEY: str(sd)}))
            with mock.patch.object(resolver.subprocess, "run", return_value=result):
                assert resolver.resolve_state_dir("ctr") == sd

    def test_container_name_is_passed_after_dash_dash(self, tmp_path: Path) -> None:
        """``--`` keeps podman from interpreting a hostile *container* as a flag."""
        sd = tmp_path / "shield"
        sd.mkdir()
        with mock.patch.object(resolver.shutil, "which", return_value="/usr/bin/podman"):
            result = mock.MagicMock(returncode=0, stdout=_fake_inspect_output({_ANN_KEY: str(sd)}))
            with mock.patch.object(resolver.subprocess, "run", return_value=result) as run:
                resolver.resolve_state_dir("--all")
        argv = run.call_args.args[0]
        assert "--" in argv
        assert argv.index("--all") > argv.index("--")

    def test_returns_none_when_podman_missing(self) -> None:
        with mock.patch.object(resolver.shutil, "which", return_value=None):
            assert resolver.resolve_state_dir("ctr") is None

    def test_returns_none_when_inspect_exits_nonzero(self) -> None:
        with mock.patch.object(resolver.shutil, "which", return_value="/usr/bin/podman"):
            result = mock.MagicMock(returncode=1, stdout="", stderr="no such container")
            with mock.patch.object(resolver.subprocess, "run", return_value=result):
                assert resolver.resolve_state_dir("ctr") is None

    def test_returns_none_when_inspect_times_out(self) -> None:
        with mock.patch.object(resolver.shutil, "which", return_value="/usr/bin/podman"):
            with mock.patch.object(
                resolver.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(cmd="podman", timeout=10),
            ):
                assert resolver.resolve_state_dir("ctr") is None

    def test_returns_none_when_annotation_absent(self) -> None:
        with mock.patch.object(resolver.shutil, "which", return_value="/usr/bin/podman"):
            result = mock.MagicMock(returncode=0, stdout=_fake_inspect_output({}))
            with mock.patch.object(resolver.subprocess, "run", return_value=result):
                assert resolver.resolve_state_dir("ctr") is None

    def test_returns_none_when_annotation_is_relative(self) -> None:
        with mock.patch.object(resolver.shutil, "which", return_value="/usr/bin/podman"):
            result = mock.MagicMock(
                returncode=0, stdout=_fake_inspect_output({_ANN_KEY: "relative/path"})
            )
            with mock.patch.object(resolver.subprocess, "run", return_value=result):
                assert resolver.resolve_state_dir("ctr") is None

    def test_returns_none_on_malformed_json(self) -> None:
        with mock.patch.object(resolver.shutil, "which", return_value="/usr/bin/podman"):
            result = mock.MagicMock(returncode=0, stdout="not-json")
            with mock.patch.object(resolver.subprocess, "run", return_value=result):
                assert resolver.resolve_state_dir("ctr") is None

    def test_returns_none_on_unexpected_shape(self) -> None:
        with mock.patch.object(resolver.shutil, "which", return_value="/usr/bin/podman"):
            result = mock.MagicMock(returncode=0, stdout=json.dumps({"not": "a list"}))
            with mock.patch.object(resolver.subprocess, "run", return_value=result):
                assert resolver.resolve_state_dir("ctr") is None


class TestExtractStateDir:
    """Hardening: each type-check branch of ``_extract_state_dir`` hits ``None``.

    These are the tiny shape-guards that keep the resolver robust against
    a future podman release changing its JSON contract — each deserves a
    dedicated test so coverage tracks when the guard survives a refactor.
    """

    def test_head_is_not_dict(self) -> None:
        assert resolver._extract_state_dir([["not", "a", "dict"]]) is None

    def test_config_is_not_dict(self) -> None:
        assert resolver._extract_state_dir([{"Config": "not-a-dict"}]) is None

    def test_annotations_is_not_dict(self) -> None:
        assert resolver._extract_state_dir([{"Config": {"Annotations": "not-a-dict"}}]) is None
