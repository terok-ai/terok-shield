# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for OCI hook entry point."""

import json
import tempfile
from unittest import mock

import pytest

from terok_shield import state
from terok_shield.config import ANNOTATION_KEY, ANNOTATION_NAME_KEY
from terok_shield.oci_hook import (
    _classify_cidr,
    _classify_ips,
    _is_private_addr,
    _parse_loopback_ports,
    _parse_oci_state,
    hook_main,
)

from ..testnet import (
    BLOCKED_TARGET_IP,
    BLOCKED_TARGET_NET,
    IPV6_ULA_CIDR,
    RFC1918_CIDR_10,
    RFC1918_CIDR_192,
    RFC1918_HOST,
)


def _oci_state(
    cid: str = "abc123",
    pid: int = 42,
    annotations: dict[str, str] | None = None,
) -> str:
    """Return a minimal OCI state JSON string."""
    oci: dict = {"id": cid, "pid": pid}
    if annotations is not None:
        oci["annotations"] = annotations
    return json.dumps(oci)


def _valid_annotations(state_dir: str) -> dict[str, str]:
    """Return annotations with required fields for hook_main."""
    return {
        ANNOTATION_KEY: "dev-standard",
        ANNOTATION_NAME_KEY: "my-ctr",
        "terok.shield.state_dir": state_dir,
        "terok.shield.loopback_ports": "1234",
        "terok.shield.version": str(state.BUNDLE_VERSION),
    }


class TestClassifyCidr:
    """Tests for _classify_cidr helper."""

    def test_private_v4(self) -> None:
        """RFC1918 network is classified as private."""
        import ipaddress

        is_private, is_broad = _classify_cidr(ipaddress.ip_network(RFC1918_CIDR_10))
        assert is_private
        assert is_broad

    def test_public_v4(self) -> None:
        """Public network is not private."""
        import ipaddress

        is_private, is_broad = _classify_cidr(ipaddress.ip_network(BLOCKED_TARGET_NET))
        assert not is_private
        assert not is_broad

    def test_narrow_cidr_not_broad(self) -> None:
        """Narrow CIDR is not classified as broad."""
        import ipaddress

        _, is_broad = _classify_cidr(ipaddress.ip_network(RFC1918_CIDR_192))
        assert not is_broad

    def test_private_v6(self) -> None:
        """ULA IPv6 network is classified as private."""
        import ipaddress

        is_private, _ = _classify_cidr(ipaddress.ip_network(IPV6_ULA_CIDR))
        assert is_private


class TestIsPrivateAddr:
    """Tests for _is_private_addr helper."""

    def test_rfc1918_is_private(self) -> None:
        """RFC1918 address is private."""
        import ipaddress

        assert _is_private_addr(ipaddress.ip_address(RFC1918_HOST))

    def test_public_is_not_private(self) -> None:
        """Public address is not private."""
        import ipaddress

        assert not _is_private_addr(ipaddress.ip_address(BLOCKED_TARGET_IP))


class TestCheckPrivateRanges:
    """Tests for _classify_ips classification."""

    def test_mixed_ips(self) -> None:
        """Classifies mix of private and public IPs."""
        private, broad = _classify_ips([RFC1918_HOST, BLOCKED_TARGET_IP])
        assert RFC1918_HOST in private
        assert BLOCKED_TARGET_IP not in private
        assert broad == []

    def test_broad_cidr(self) -> None:
        """Broad CIDR is flagged."""
        private, broad = _classify_ips([RFC1918_CIDR_10])
        assert RFC1918_CIDR_10 in broad
        assert RFC1918_CIDR_10 in private

    def test_invalid_ip_skipped(self) -> None:
        """Invalid IP strings are silently skipped."""
        private, broad = _classify_ips(["not-an-ip", BLOCKED_TARGET_IP])
        assert private == []
        assert broad == []


class TestParseLoopbackPortsAnnotation:
    """Tests for _parse_loopback_ports (annotation string version)."""

    def test_valid_ports(self) -> None:
        """Comma-separated port string is parsed."""
        assert _parse_loopback_ports("8080,9090") == (8080, 9090)

    def test_empty_string(self) -> None:
        """Empty string returns empty tuple."""
        assert _parse_loopback_ports("") == ()

    def test_invalid_port_skipped(self) -> None:
        """Non-integer port values are skipped."""
        assert _parse_loopback_ports("8080,bad,9090") == (8080, 9090)

    def test_out_of_range_skipped(self) -> None:
        """Out-of-range ports are skipped."""
        assert _parse_loopback_ports("0,8080,99999") == (8080,)

    def test_whitespace_handled(self) -> None:
        """Whitespace around ports is stripped."""
        assert _parse_loopback_ports(" 8080 , 9090 ") == (8080, 9090)

    def test_trailing_comma(self) -> None:
        """Trailing comma produces no extra entry."""
        assert _parse_loopback_ports("8080,") == (8080,)


class TestParseOciState:
    """Tests for _parse_oci_state."""

    def test_valid_state(self) -> None:
        """Parse valid OCI state."""
        cid, pid, annotations = _parse_oci_state(_oci_state("mycontainer", 1234))
        assert cid == "mycontainer"
        assert pid == "1234"
        assert annotations == {}

    def test_with_annotations(self) -> None:
        """Parse state with annotations."""
        ann = {ANNOTATION_KEY: "dev-standard", ANNOTATION_NAME_KEY: "my-ctr"}
        _, _, annotations = _parse_oci_state(_oci_state("abc", 1, annotations=ann))
        assert annotations[ANNOTATION_KEY] == "dev-standard"
        assert annotations[ANNOTATION_NAME_KEY] == "my-ctr"

    def test_missing_id(self) -> None:
        """Raise ValueError for missing id."""
        with pytest.raises(ValueError):
            _parse_oci_state(json.dumps({"pid": 42}))

    def test_missing_pid_returns_empty(self) -> None:
        """Return empty pid string when pid is absent (poststop)."""
        cid, pid, _ = _parse_oci_state(json.dumps({"id": "abc"}))
        assert cid == "abc"
        assert pid == ""

    def test_zero_pid_returns_empty(self) -> None:
        """Return empty pid string when pid is zero (poststop)."""
        cid, pid, _ = _parse_oci_state(json.dumps({"id": "abc", "pid": 0}))
        assert cid == "abc"
        assert pid == ""

    def test_invalid_json(self) -> None:
        """Raise ValueError for invalid JSON."""
        with pytest.raises(ValueError):
            _parse_oci_state("not json")

    def test_empty_id(self) -> None:
        """Raise ValueError for empty id."""
        with pytest.raises(ValueError):
            _parse_oci_state(json.dumps({"id": "", "pid": 42}))

    def test_non_object_json(self) -> None:
        """Raise ValueError for valid JSON that is not an object."""
        for value in ["[]", '"string"', "123", "true"]:
            with pytest.raises(ValueError):
                _parse_oci_state(value)

    def test_non_dict_annotations_ignored(self) -> None:
        """Non-dict annotations are treated as empty."""
        _, _, annotations = _parse_oci_state(
            json.dumps({"id": "abc", "pid": 1, "annotations": "not-a-dict"})
        )
        assert annotations == {}

    def test_annotation_values_normalized_to_str(self) -> None:
        """Non-string annotation values are coerced to strings."""
        _, _, annotations = _parse_oci_state(
            json.dumps({"id": "abc", "pid": 1, "annotations": {"key": 42, "flag": True}})
        )
        assert annotations["key"] == "42"
        assert annotations["flag"] == "True"


class TestHookMain:
    """Tests for hook_main entry point."""

    @mock.patch("terok_shield.oci_hook.HookExecutor")
    def test_success(self, mock_exec: mock.Mock) -> None:
        """Return 0 on success (hook mode createRuntime)."""
        with tempfile.TemporaryDirectory() as tmp:
            ann = _valid_annotations(tmp)
            rc = hook_main(_oci_state("test-ctr", 42, annotations=ann))
            assert rc == 0
            mock_exec.return_value.apply.assert_called_once_with("test-ctr", "42")

    def test_invalid_json(self) -> None:
        """Return 1 on invalid OCI state."""
        rc = hook_main("not json")
        assert rc == 1

    @mock.patch("terok_shield.oci_hook.HookExecutor")
    def test_runtime_error(self, mock_exec: mock.Mock) -> None:
        """Return 1 on RuntimeError from executor.apply."""
        with tempfile.TemporaryDirectory() as tmp:
            ann = _valid_annotations(tmp)
            mock_exec.return_value.apply.side_effect = RuntimeError("boom")
            rc = hook_main(_oci_state(annotations=ann))
            assert rc == 1

    def test_hook_mode_requires_pid(self) -> None:
        """Return 1 when hook mode state has no valid PID."""
        rc = hook_main(json.dumps({"id": "abc", "pid": 0}))
        assert rc == 1

    def test_poststop_noop(self) -> None:
        """Poststop is a no-op returning 0 without calling HookExecutor."""
        oci = _oci_state(pid=0)
        rc = hook_main(oci, stage="poststop")
        assert rc == 0

    def test_missing_state_dir_annotation(self) -> None:
        """Return 1 when state_dir annotation is missing."""
        ann = {ANNOTATION_KEY: "dev-standard"}
        rc = hook_main(_oci_state(annotations=ann))
        assert rc == 1

    def test_version_mismatch(self) -> None:
        """Return 1 when bundle version doesn't match."""
        with tempfile.TemporaryDirectory() as tmp:
            ann = _valid_annotations(tmp)
            ann["terok.shield.version"] = "999"
            rc = hook_main(_oci_state(annotations=ann))
            assert rc == 1

    def test_invalid_version(self) -> None:
        """Return 1 when version annotation is not a valid integer."""
        with tempfile.TemporaryDirectory() as tmp:
            ann = _valid_annotations(tmp)
            ann["terok.shield.version"] = "not-a-number"
            rc = hook_main(_oci_state(annotations=ann))
            assert rc == 1

    def test_relative_state_dir_rejected(self) -> None:
        """Return 1 when state_dir annotation is a relative path."""
        ann = {
            ANNOTATION_KEY: "dev-standard",
            ANNOTATION_NAME_KEY: "my-ctr",
            "terok.shield.state_dir": "relative/path",
            "terok.shield.loopback_ports": "",
            "terok.shield.version": str(state.BUNDLE_VERSION),
        }
        rc = hook_main(_oci_state(annotations=ann))
        assert rc == 1

    @mock.patch("terok_shield.oci_hook.HookExecutor")
    @mock.patch("terok_shield.oci_hook.AuditLogger")
    def test_audit_disabled_annotation(
        self, mock_audit_cls: mock.Mock, mock_exec: mock.Mock
    ) -> None:
        """audit_enabled=false annotation is honored by hook_main."""
        with tempfile.TemporaryDirectory() as tmp:
            ann = _valid_annotations(tmp)
            ann["terok.shield.audit_enabled"] = "false"
            rc = hook_main(_oci_state(annotations=ann))
            assert rc == 0
            mock_audit_cls.assert_called_once()
            _, kwargs = mock_audit_cls.call_args
            assert not kwargs["enabled"]

    @mock.patch("terok_shield.oci_hook.HookExecutor")
    @mock.patch("terok_shield.oci_hook.AuditLogger")
    def test_malformed_audit_enabled_defaults_to_on(
        self, mock_audit_cls: mock.Mock, mock_exec: mock.Mock
    ) -> None:
        """Malformed audit_enabled value defaults to enabled (safe)."""
        with tempfile.TemporaryDirectory() as tmp:
            ann = _valid_annotations(tmp)
            ann["terok.shield.audit_enabled"] = "garbled"
            rc = hook_main(_oci_state(annotations=ann))
            assert rc == 0
            mock_audit_cls.assert_called_once()
            _, kwargs = mock_audit_cls.call_args
            assert kwargs["enabled"]
