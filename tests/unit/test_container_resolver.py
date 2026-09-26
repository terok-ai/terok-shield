# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the podman-annotation based state_dir resolver."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest import mock

from terok_shield import container as resolver

from ..testfs import FAKE_STATE_DIR_STR

_ANN_KEY = "terok.shield.state_dir"
_VERSION_KEY = "terok.shield.version"


def _fake_inspect_output(annotations: dict[str, str]) -> str:
    """Shape one ``podman inspect --format=json`` record around our annotations."""
    return json.dumps([{"Name": "/example", "Id": "abc", "Config": {"Annotations": annotations}}])


class TestResolveStateDir:
    """Happy-path and every failure branch collapses to ``None``."""

    def test_returns_annotation_path(self, tmp_path: Path) -> None:
        sd = tmp_path / "shield"
        sd.mkdir()
        with mock.patch.object(resolver, "find_host_tool", return_value="/usr/bin/podman"):
            result = mock.MagicMock(returncode=0, stdout=_fake_inspect_output({_ANN_KEY: str(sd)}))
            with mock.patch.object(resolver.subprocess, "run", return_value=result):
                assert resolver.resolve_state_dir("ctr") == sd

    def test_container_name_is_passed_after_dash_dash(self, tmp_path: Path) -> None:
        """``--`` keeps podman from interpreting a hostile *container* as a flag."""
        sd = tmp_path / "shield"
        sd.mkdir()
        with mock.patch.object(resolver, "find_host_tool", return_value="/usr/bin/podman"):
            result = mock.MagicMock(returncode=0, stdout=_fake_inspect_output({_ANN_KEY: str(sd)}))
            with mock.patch.object(resolver.subprocess, "run", return_value=result) as run:
                resolver.resolve_state_dir("--all")
        argv = run.call_args.args[0]
        assert "--" in argv
        assert argv.index("--all") > argv.index("--")

    def test_returns_none_when_podman_missing(self) -> None:
        with mock.patch.object(resolver, "find_host_tool", return_value=None):
            assert resolver.resolve_state_dir("ctr") is None

    def test_returns_none_when_inspect_exits_nonzero(self) -> None:
        with mock.patch.object(resolver, "find_host_tool", return_value="/usr/bin/podman"):
            result = mock.MagicMock(returncode=1, stdout="", stderr="no such container")
            with mock.patch.object(resolver.subprocess, "run", return_value=result):
                assert resolver.resolve_state_dir("ctr") is None

    def test_returns_none_when_inspect_times_out(self) -> None:
        with mock.patch.object(resolver, "find_host_tool", return_value="/usr/bin/podman"):
            with mock.patch.object(
                resolver.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(cmd="podman", timeout=10),
            ):
                assert resolver.resolve_state_dir("ctr") is None

    def test_returns_none_when_annotation_absent(self) -> None:
        with mock.patch.object(resolver, "find_host_tool", return_value="/usr/bin/podman"):
            result = mock.MagicMock(returncode=0, stdout=_fake_inspect_output({}))
            with mock.patch.object(resolver.subprocess, "run", return_value=result):
                assert resolver.resolve_state_dir("ctr") is None

    def test_returns_none_when_annotation_is_relative(self) -> None:
        with mock.patch.object(resolver, "find_host_tool", return_value="/usr/bin/podman"):
            result = mock.MagicMock(
                returncode=0, stdout=_fake_inspect_output({_ANN_KEY: "relative/path"})
            )
            with mock.patch.object(resolver.subprocess, "run", return_value=result):
                assert resolver.resolve_state_dir("ctr") is None

    def test_returns_none_on_malformed_json(self) -> None:
        with mock.patch.object(resolver, "find_host_tool", return_value="/usr/bin/podman"):
            result = mock.MagicMock(returncode=0, stdout="not-json")
            with mock.patch.object(resolver.subprocess, "run", return_value=result):
                assert resolver.resolve_state_dir("ctr") is None

    def test_returns_none_on_unexpected_shape(self) -> None:
        with mock.patch.object(resolver, "find_host_tool", return_value="/usr/bin/podman"):
            result = mock.MagicMock(returncode=0, stdout=json.dumps({"not": "a list"}))
            with mock.patch.object(resolver.subprocess, "run", return_value=result):
                assert resolver.resolve_state_dir("ctr") is None

    def test_returns_none_when_resolve_raises_oserror(self) -> None:
        """An ``OSError`` out of ``Path.resolve`` (ELOOP, EACCES) collapses to ``None``.

        Exercises ``_state_dir_from`` directly, like the ``_annotations``
        shape-guard tests: the annotation value parses and is absolute, but
        the filesystem refuses to canonicalise it.
        """
        with mock.patch.object(resolver, "Path") as path_cls:
            path_cls.return_value.is_absolute.return_value = True
            path_cls.return_value.resolve.side_effect = OSError("ELOOP")
            assert resolver._state_dir_from({_ANN_KEY: FAKE_STATE_DIR_STR}) is None


class TestAnnotations:
    """Hardening: each type-check branch of ``_annotations`` hits ``None``.

    These are the tiny shape-guards that keep the resolver robust against
    a future podman release changing its JSON contract — each deserves a
    dedicated test so coverage tracks when the guard survives a refactor.
    """

    def test_head_is_not_dict(self) -> None:
        assert resolver._annotations([["not", "a", "dict"]]) is None

    def test_config_is_not_dict(self) -> None:
        assert resolver._annotations([{"Config": "not-a-dict"}]) is None

    def test_annotations_is_not_dict(self) -> None:
        assert resolver._annotations([{"Config": {"Annotations": "not-a-dict"}}]) is None


class TestResolveShieldVersion:
    """``resolve_shield_version`` reads the ``terok.shield.version`` annotation."""

    def test_returns_version_int(self) -> None:
        with mock.patch.object(resolver, "find_host_tool", return_value="/usr/bin/podman"):
            out = _fake_inspect_output({"terok.shield.version": "15"})
            with mock.patch.object(
                resolver.subprocess, "run", return_value=mock.MagicMock(returncode=0, stdout=out)
            ):
                assert resolver.resolve_shield_version("ctr") == 15

    def test_absent_container_is_none(self) -> None:
        """No podman (or no inspect record) → "cannot determine", never a crash."""
        with mock.patch.object(resolver, "find_host_tool", return_value=None):
            assert resolver.resolve_shield_version("ctr") is None

    def test_missing_annotation_is_none(self) -> None:
        with mock.patch.object(resolver, "find_host_tool", return_value="/usr/bin/podman"):
            out = _fake_inspect_output({})
            with mock.patch.object(
                resolver.subprocess, "run", return_value=mock.MagicMock(returncode=0, stdout=out)
            ):
                assert resolver.resolve_shield_version("ctr") is None

    def test_non_integer_annotation_is_none(self) -> None:
        with mock.patch.object(resolver, "find_host_tool", return_value="/usr/bin/podman"):
            out = _fake_inspect_output({"terok.shield.version": "v15"})
            with mock.patch.object(
                resolver.subprocess, "run", return_value=mock.MagicMock(returncode=0, stdout=out)
            ):
                assert resolver.resolve_shield_version("ctr") is None


class TestResolveAnnotations:
    """``resolve_annotations`` reads every shield annotation in one inspect."""

    def test_returns_both_fields_from_one_inspect(self, tmp_path: Path) -> None:
        """Both annotations present → both fields set, exactly one podman call."""
        sd = tmp_path / "shield"
        sd.mkdir()
        with mock.patch.object(resolver, "find_host_tool", return_value="/usr/bin/podman"):
            out = _fake_inspect_output({_VERSION_KEY: "15", _ANN_KEY: str(sd)})
            with mock.patch.object(
                resolver.subprocess, "run", return_value=mock.MagicMock(returncode=0, stdout=out)
            ) as run:
                ann = resolver.resolve_annotations("ctr")
        assert ann == resolver.ShieldAnnotations(version=15, state_dir=sd)
        run.assert_called_once()

    def test_fields_fail_independently(self, tmp_path: Path) -> None:
        """A defective value nulls its own field without dragging the other down."""
        sd = tmp_path / "shield"
        sd.mkdir()
        with mock.patch.object(resolver, "find_host_tool", return_value="/usr/bin/podman"):
            out = _fake_inspect_output({_VERSION_KEY: "v15", _ANN_KEY: str(sd)})
            with mock.patch.object(
                resolver.subprocess, "run", return_value=mock.MagicMock(returncode=0, stdout=out)
            ):
                ann = resolver.resolve_annotations("ctr")
        assert ann == resolver.ShieldAnnotations(version=None, state_dir=sd)

    def test_missing_annotations_are_none(self) -> None:
        with mock.patch.object(resolver, "find_host_tool", return_value="/usr/bin/podman"):
            out = _fake_inspect_output({})
            with mock.patch.object(
                resolver.subprocess, "run", return_value=mock.MagicMock(returncode=0, stdout=out)
            ):
                ann = resolver.resolve_annotations("ctr")
        assert ann == resolver.ShieldAnnotations(version=None, state_dir=None)

    def test_failed_inspect_yields_all_none(self) -> None:
        """Podman missing → the all-``None`` record, never a crash."""
        with mock.patch.object(resolver, "find_host_tool", return_value=None):
            assert resolver.resolve_annotations("ctr") == resolver.ShieldAnnotations(
                version=None, state_dir=None
            )

    def test_agrees_with_single_resolvers(self, tmp_path: Path) -> None:
        """The combined record matches what the two single resolvers report."""
        sd = tmp_path / "shield"
        sd.mkdir()
        with mock.patch.object(resolver, "find_host_tool", return_value="/usr/bin/podman"):
            out = _fake_inspect_output({_VERSION_KEY: "15", _ANN_KEY: str(sd)})
            run_result = mock.MagicMock(returncode=0, stdout=out)
            with mock.patch.object(resolver.subprocess, "run", return_value=run_result):
                ann = resolver.resolve_annotations("ctr")
                assert ann.version == resolver.resolve_shield_version("ctr")
                assert ann.state_dir == resolver.resolve_state_dir("ctr")
