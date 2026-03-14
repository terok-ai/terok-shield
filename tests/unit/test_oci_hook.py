# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for OCI hook entry point."""

import ipaddress
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import pytest

from terok_shield import state
from terok_shield.config import (
    ANNOTATION_AUDIT_ENABLED_KEY,
    ANNOTATION_KEY,
    ANNOTATION_LOOPBACK_PORTS_KEY,
    ANNOTATION_NAME_KEY,
    ANNOTATION_STATE_DIR_KEY,
    ANNOTATION_VERSION_KEY,
)
from terok_shield.oci_hook import (
    _classify_cidr,
    _classify_ips,
    _is_private_addr,
    _parse_loopback_ports,
    _parse_oci_state,
    hook_main,
)

from ..testfs import RELATIVE_STATE_SUBPATH
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
    oci: dict[str, object] = {"id": cid, "pid": pid}
    if annotations is not None:
        oci["annotations"] = annotations
    return json.dumps(oci)


def _valid_annotations(state_dir: Path) -> dict[str, str]:
    """Return annotations with the fields required by hook_main()."""
    return {
        ANNOTATION_KEY: "dev-standard",
        ANNOTATION_NAME_KEY: "my-ctr",
        ANNOTATION_STATE_DIR_KEY: str(state_dir),
        ANNOTATION_LOOPBACK_PORTS_KEY: "1234",
        ANNOTATION_VERSION_KEY: str(state.BUNDLE_VERSION),
    }


@dataclass
class HookMainHarness:
    """Patched collaborators used by hook_main() tests."""

    executor_cls: mock.MagicMock
    audit_cls: mock.MagicMock
    ruleset_builder_cls: mock.MagicMock

    @property
    def executor(self) -> mock.MagicMock:
        """Return the HookExecutor instance created by hook_main()."""
        return self.executor_cls.return_value


@pytest.fixture
def hook_main_harness(monkeypatch: pytest.MonkeyPatch) -> HookMainHarness:
    """Patch hook_main() collaborators that would otherwise do real work."""
    executor_cls = mock.MagicMock()
    audit_cls = mock.MagicMock()
    ruleset_builder_cls = mock.MagicMock()
    monkeypatch.setattr("terok_shield.oci_hook.HookExecutor", executor_cls)
    monkeypatch.setattr("terok_shield.oci_hook.AuditLogger", audit_cls)
    monkeypatch.setattr("terok_shield.oci_hook.RulesetBuilder", ruleset_builder_cls)
    monkeypatch.setattr("terok_shield.oci_hook.SubprocessRunner", mock.MagicMock)
    monkeypatch.setattr("terok_shield.oci_hook._read_container_dns", lambda pid: "169.254.1.1")
    return HookMainHarness(
        executor_cls=executor_cls,
        audit_cls=audit_cls,
        ruleset_builder_cls=ruleset_builder_cls,
    )


@pytest.mark.parametrize(
    ("network", "expected_private", "expected_broad"),
    [
        pytest.param(RFC1918_CIDR_10, True, True, id="private-broad-ipv4"),
        pytest.param(BLOCKED_TARGET_NET, False, False, id="public-ipv4"),
        pytest.param(RFC1918_CIDR_192, True, False, id="private-narrow-ipv4"),
        pytest.param(IPV6_ULA_CIDR, True, True, id="private-broad-ipv6"),
    ],
)
def test_classify_cidr(network: str, expected_private: bool, expected_broad: bool) -> None:
    """_classify_cidr() identifies private and broad networks."""
    assert _classify_cidr(ipaddress.ip_network(network)) == (expected_private, expected_broad)


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        pytest.param(RFC1918_HOST, True, id="private"),
        pytest.param(BLOCKED_TARGET_IP, False, id="public"),
    ],
)
def test_is_private_addr(address: str, expected: bool) -> None:
    """_is_private_addr() detects private versus public addresses."""
    assert _is_private_addr(ipaddress.ip_address(address)) is expected


@pytest.mark.parametrize(
    ("ips", "expected_private", "expected_broad"),
    [
        pytest.param([RFC1918_HOST, BLOCKED_TARGET_IP], [RFC1918_HOST], [], id="mixed-addresses"),
        pytest.param([RFC1918_CIDR_10], [RFC1918_CIDR_10], [RFC1918_CIDR_10], id="broad-cidr"),
        pytest.param(["not-an-ip", BLOCKED_TARGET_IP], [], [], id="invalid-input-skipped"),
    ],
)
def test_classify_ips(
    ips: list[str],
    expected_private: list[str],
    expected_broad: list[str],
) -> None:
    """_classify_ips() classifies private ranges and broad CIDRs for logging."""
    assert _classify_ips(ips) == (expected_private, expected_broad)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param("8080,9090", (8080, 9090), id="valid-ports"),
        pytest.param("", (), id="empty"),
        pytest.param("8080,bad,9090", (8080, 9090), id="invalid-skipped"),
        pytest.param("0,8080,99999", (8080,), id="range-checked"),
        pytest.param(" 8080 , 9090 ", (8080, 9090), id="whitespace-trimmed"),
        pytest.param("8080,", (8080,), id="trailing-comma"),
    ],
)
def test_parse_loopback_ports(raw: str, expected: tuple[int, ...]) -> None:
    """_parse_loopback_ports() parses annotation strings defensively."""
    assert _parse_loopback_ports(raw) == expected


def test_parse_oci_state_parses_valid_state() -> None:
    """_parse_oci_state() returns container id, pid, and annotations."""
    cid, pid, annotations = _parse_oci_state(_oci_state("mycontainer", 1234))
    assert (cid, pid, annotations) == ("mycontainer", "1234", {})


@pytest.mark.parametrize(
    ("stdin_data", "expected"),
    [
        pytest.param(
            _oci_state(
                "abc",
                1,
                annotations={ANNOTATION_KEY: "dev-standard", ANNOTATION_NAME_KEY: "my-ctr"},
            ),
            {ANNOTATION_KEY: "dev-standard", ANNOTATION_NAME_KEY: "my-ctr"},
            id="with-annotations",
        ),
        pytest.param(
            json.dumps({"id": "abc", "pid": 1, "annotations": "not-a-dict"}),
            {},
            id="non-dict-annotations-ignored",
        ),
        pytest.param(
            json.dumps({"id": "abc", "pid": 1, "annotations": {"key": 42, "flag": True}}),
            {"key": "42", "flag": "True"},
            id="annotation-values-normalized-to-str",
        ),
    ],
)
def test_parse_oci_state_normalizes_annotations(
    stdin_data: str,
    expected: dict[str, str],
) -> None:
    """_parse_oci_state() keeps only stringified annotation mappings."""
    _, _, annotations = _parse_oci_state(stdin_data)
    assert annotations == expected


@pytest.mark.parametrize(
    ("stdin_data", "expected_message"),
    [
        pytest.param(json.dumps({"pid": 42}), "missing id", id="missing-id"),
        pytest.param("not json", "Invalid OCI state JSON", id="invalid-json"),
        pytest.param(json.dumps({"id": "", "pid": 42}), "missing id", id="empty-id"),
        pytest.param("[]", "JSON object", id="non-object-list"),
        pytest.param('"string"', "JSON object", id="non-object-string"),
        pytest.param("123", "JSON object", id="non-object-number"),
        pytest.param("true", "JSON object", id="non-object-bool"),
    ],
)
def test_parse_oci_state_rejects_invalid_inputs(stdin_data: str, expected_message: str) -> None:
    """_parse_oci_state() rejects malformed or incomplete OCI state payloads."""
    with pytest.raises(ValueError, match=expected_message):
        _parse_oci_state(stdin_data)


@pytest.mark.parametrize(
    ("stdin_data", "expected_pid"),
    [
        pytest.param(json.dumps({"id": "abc"}), "", id="missing-pid"),
        pytest.param(json.dumps({"id": "abc", "pid": 0}), "", id="zero-pid"),
    ],
)
def test_parse_oci_state_normalizes_missing_or_zero_pid(
    stdin_data: str,
    expected_pid: str,
) -> None:
    """_parse_oci_state() returns an empty pid string for poststop-like payloads."""
    cid, pid, _ = _parse_oci_state(stdin_data)
    assert cid == "abc"
    assert pid == expected_pid


def test_hook_main_success(hook_main_harness: HookMainHarness, tmp_path: Path) -> None:
    """hook_main() returns 0 and applies the ruleset on valid createRuntime input."""
    rc = hook_main(_oci_state("test-ctr", 42, annotations=_valid_annotations(tmp_path)))
    assert rc == 0
    hook_main_harness.ruleset_builder_cls.assert_called_once_with(
        dns="169.254.1.1", loopback_ports=(1234,)
    )
    hook_main_harness.executor.apply.assert_called_once_with("test-ctr", "42")


def test_hook_main_returns_1_for_invalid_json() -> None:
    """hook_main() fails closed when OCI state is invalid JSON."""
    assert hook_main("not json") == 1


def test_hook_main_returns_1_on_executor_runtime_error(
    hook_main_harness: HookMainHarness,
    tmp_path: Path,
) -> None:
    """hook_main() returns 1 when executor.apply() fails."""
    hook_main_harness.executor.apply.side_effect = RuntimeError("boom")
    assert hook_main(_oci_state(annotations=_valid_annotations(tmp_path))) == 1


@pytest.mark.parametrize(
    ("stdin_data", "stage", "expected"),
    [
        pytest.param(
            json.dumps({"id": "abc", "pid": 0}), "createRuntime", 1, id="hook-mode-requires-pid"
        ),
        pytest.param(_oci_state(pid=0), "poststop", 0, id="poststop-noop"),
    ],
)
def test_hook_main_handles_pid_requirements(stdin_data: str, stage: str, expected: int) -> None:
    """hook_main() requires a PID only for createRuntime hooks."""
    assert hook_main(stdin_data, stage=stage) == expected


class TestReadContainerDns:
    """Tests for _read_container_dns() in oci_hook."""

    def test_reads_nameserver_from_proc(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Reads DNS from /proc/{pid}/root/etc/resolv.conf."""
        from terok_shield.oci_hook import _read_container_dns

        fake_resolv = tmp_path / "resolv.conf"
        fake_resolv.write_text("nameserver 10.0.2.3\n")

        monkeypatch.setattr(
            "terok_shield.oci_hook.Path",
            lambda _s: fake_resolv,
        )
        assert _read_container_dns("42") == "10.0.2.3"

    def test_missing_resolv_conf_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Missing resolv.conf raises RuntimeError."""
        from terok_shield.oci_hook import _read_container_dns

        monkeypatch.setattr(
            "terok_shield.oci_hook.Path",
            lambda _s: tmp_path / "nonexistent",
        )
        with pytest.raises(RuntimeError, match="Cannot read container resolv.conf"):
            _read_container_dns("42")

    def test_empty_resolv_conf_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """resolv.conf without nameserver raises RuntimeError."""
        from terok_shield.oci_hook import _read_container_dns

        fake_resolv = tmp_path / "resolv.conf"
        fake_resolv.write_text("# no nameserver\nsearch example.com\n")

        monkeypatch.setattr(
            "terok_shield.oci_hook.Path",
            lambda _s: fake_resolv,
        )
        with pytest.raises(RuntimeError, match="No nameserver found"):
            _read_container_dns("42")


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        pytest.param(lambda ann: ann.pop(ANNOTATION_STATE_DIR_KEY), 1, id="missing-state-dir"),
        pytest.param(
            lambda ann: ann.__setitem__(ANNOTATION_VERSION_KEY, "999"),
            1,
            id="version-mismatch",
        ),
        pytest.param(
            lambda ann: ann.__setitem__(ANNOTATION_VERSION_KEY, "not-a-number"),
            1,
            id="invalid-version",
        ),
        pytest.param(
            lambda ann: ann.__setitem__(ANNOTATION_STATE_DIR_KEY, RELATIVE_STATE_SUBPATH),
            1,
            id="relative-state-dir",
        ),
    ],
)
def test_hook_main_rejects_invalid_annotations(
    tmp_path: Path,
    mutate: Callable[[dict[str, str]], object],
    expected: int,
) -> None:
    """hook_main() fails closed when required annotations are missing or invalid."""
    annotations = _valid_annotations(tmp_path)
    mutate(annotations)
    assert hook_main(_oci_state(annotations=annotations)) == expected


@pytest.mark.parametrize(
    ("audit_value", "expected_enabled"),
    [
        pytest.param("false", False, id="audit-disabled"),
        pytest.param("garbled", True, id="malformed-audit-defaults-on"),
    ],
)
def test_hook_main_configures_audit_logger_from_annotation(
    hook_main_harness: HookMainHarness,
    tmp_path: Path,
    audit_value: str,
    expected_enabled: bool,
) -> None:
    """hook_main() interprets the audit_enabled annotation safely."""
    annotations = _valid_annotations(tmp_path)
    annotations[ANNOTATION_AUDIT_ENABLED_KEY] = audit_value
    assert hook_main(_oci_state(annotations=annotations)) == 0
    _, kwargs = hook_main_harness.audit_cls.call_args
    assert kwargs["enabled"] is expected_enabled
