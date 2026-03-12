# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for OCI hook entry point."""

import json
import unittest
import unittest.mock

from terok_shield.config import ANNOTATION_KEY, ANNOTATION_NAME_KEY, ShieldConfig
from terok_shield.oci_hook import _parse_oci_state, hook_main


def _oci_state(
    cid: str = "abc123",
    pid: int = 42,
    annotations: dict[str, str] | None = None,
) -> str:
    """Return a minimal OCI state JSON string."""
    state: dict = {"id": cid, "pid": pid}
    if annotations is not None:
        state["annotations"] = annotations
    return json.dumps(state)


class TestParseOciState(unittest.TestCase):
    """Tests for _parse_oci_state."""

    def test_valid_state(self) -> None:
        """Parse valid OCI state."""
        cid, pid, annotations = _parse_oci_state(_oci_state("mycontainer", 1234))
        self.assertEqual(cid, "mycontainer")
        self.assertEqual(pid, "1234")
        self.assertEqual(annotations, {})

    def test_with_annotations(self) -> None:
        """Parse state with annotations."""
        ann = {ANNOTATION_KEY: "dev-standard", ANNOTATION_NAME_KEY: "my-ctr"}
        _, _, annotations = _parse_oci_state(_oci_state("abc", 1, annotations=ann))
        self.assertEqual(annotations[ANNOTATION_KEY], "dev-standard")
        self.assertEqual(annotations[ANNOTATION_NAME_KEY], "my-ctr")

    def test_missing_id(self) -> None:
        """Raise ValueError for missing id."""
        with self.assertRaises(ValueError):
            _parse_oci_state(json.dumps({"pid": 42}))

    def test_missing_pid_returns_empty(self) -> None:
        """Return empty pid string when pid is absent (poststop)."""
        cid, pid, _ = _parse_oci_state(json.dumps({"id": "abc"}))
        self.assertEqual(cid, "abc")
        self.assertEqual(pid, "")

    def test_zero_pid_returns_empty(self) -> None:
        """Return empty pid string when pid is zero (poststop)."""
        cid, pid, _ = _parse_oci_state(json.dumps({"id": "abc", "pid": 0}))
        self.assertEqual(cid, "abc")
        self.assertEqual(pid, "")

    def test_invalid_json(self) -> None:
        """Raise ValueError for invalid JSON."""
        with self.assertRaises(ValueError):
            _parse_oci_state("not json")

    def test_empty_id(self) -> None:
        """Raise ValueError for empty id."""
        with self.assertRaises(ValueError):
            _parse_oci_state(json.dumps({"id": "", "pid": 42}))

    def test_non_object_json(self) -> None:
        """Raise ValueError for valid JSON that is not an object."""
        for value in ["[]", '"string"', "123", "true"]:
            with self.assertRaises(ValueError, msg=f"Should reject: {value}"):
                _parse_oci_state(value)

    def test_non_dict_annotations_ignored(self) -> None:
        """Non-dict annotations are treated as empty."""
        _, _, annotations = _parse_oci_state(
            json.dumps({"id": "abc", "pid": 1, "annotations": "not-a-dict"})
        )
        self.assertEqual(annotations, {})


class TestHookMain(unittest.TestCase):
    """Tests for hook_main entry point."""

    @unittest.mock.patch("terok_shield.oci_hook.HookExecutor")
    @unittest.mock.patch("terok_shield.oci_hook.load_shield_config")
    def test_success(self, mock_cfg: unittest.mock.Mock, mock_exec: unittest.mock.Mock) -> None:
        """Return 0 on success (hook mode createRuntime)."""
        mock_cfg.return_value = ShieldConfig(loopback_ports=(1234,))
        rc = hook_main(_oci_state("test-ctr", 42))
        self.assertEqual(rc, 0)
        mock_exec.return_value.apply.assert_called_once_with("test-ctr", "42")

    def test_invalid_json(self) -> None:
        """Return 1 on invalid OCI state."""
        rc = hook_main("not json")
        self.assertEqual(rc, 1)

    @unittest.mock.patch("terok_shield.oci_hook.HookExecutor")
    @unittest.mock.patch("terok_shield.oci_hook.load_shield_config")
    def test_runtime_error(
        self, mock_cfg: unittest.mock.Mock, mock_exec: unittest.mock.Mock
    ) -> None:
        """Return 1 on RuntimeError from executor.apply."""
        mock_cfg.return_value = ShieldConfig()
        mock_exec.return_value.apply.side_effect = RuntimeError("boom")
        rc = hook_main(_oci_state())
        self.assertEqual(rc, 1)

    def test_hook_mode_requires_pid(self) -> None:
        """Return 1 when hook mode state has no valid PID."""
        rc = hook_main(json.dumps({"id": "abc", "pid": 0}))
        self.assertEqual(rc, 1)

    def test_poststop_noop(self) -> None:
        """Poststop is a no-op returning 0 without calling HookExecutor."""
        state = _oci_state(pid=0)
        rc = hook_main(state, stage="poststop")
        self.assertEqual(rc, 0)
