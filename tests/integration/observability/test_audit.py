# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: audit logging (filesystem + hook audit trail)."""

import json
import tempfile
from pathlib import Path

import pytest

_NONEXISTENT_PID = "4000000"  # Well above typical PID range

from terok_shield import state
from terok_shield.audit import AuditLogger
from terok_shield.nft import RulesetBuilder
from terok_shield.oci_hook import HookExecutor
from terok_shield.run import SubprocessRunner
from tests.testnet import ALLOWED_TARGET_IPS, IPV6_CLOUDFLARE, TEST_IP1, TEST_IP2

from ..conftest import nft_missing, podman_missing

# -- Filesystem audit (no container needed) -------------------


@pytest.mark.needs_host_features
class TestAuditLive:
    """Audit logging with real temp directories."""

    def test_log_and_tail(self, tmp_path: Path) -> None:
        """Write audit events and read them back."""
        audit = AuditLogger(audit_path=state.audit_path(tmp_path))

        audit.log_event("test-ctr", "setup", detail="integration test")
        audit.log_event("test-ctr", "allowed", dest=TEST_IP1)
        audit.log_event("test-ctr", "denied", dest=TEST_IP2)

        events = list(audit.tail_log(n=10))
        assert len(events) == 3
        assert events[0]["action"] == "setup"
        assert events[1]["dest"] == TEST_IP1
        assert events[2]["action"] == "denied"

    def test_jsonl_format(self, tmp_path: Path) -> None:
        """Each line must be valid compact JSON."""
        audit_path = state.audit_path(tmp_path)
        audit = AuditLogger(audit_path=audit_path)

        audit.log_event("fmt-test", "setup")
        audit.log_event("fmt-test", "teardown")

        assert audit_path.is_file()

        for line in audit_path.read_text().splitlines():
            entry = json.loads(line)
            assert "ts" in entry
            assert "container" in entry
            assert "action" in entry
            # Compact format: no spaces after separators
            assert ", " not in line
            assert ": " not in line

    def test_tail_empty_returns_no_events(self, tmp_path: Path) -> None:
        """Tailing when no log file exists returns no events."""
        audit = AuditLogger(audit_path=state.audit_path(tmp_path))

        events = list(audit.tail_log(n=10))
        assert events == []


# -- Hook audit trail (container needed) ----------------------


def _make_executor(tmp: str) -> HookExecutor:
    """Create a HookExecutor wired to a temp directory."""
    runner = SubprocessRunner()
    audit = AuditLogger(audit_path=state.audit_path(Path(tmp)))
    ruleset = RulesetBuilder()
    return HookExecutor(
        runner=runner,
        audit=audit,
        ruleset=ruleset,
        state_dir=Path(tmp),
    )


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestApplyHookAudit:
    """Verify HookExecutor.apply produces JSONL audit entries."""

    def test_apply_hook_produces_audit_trail(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """HookExecutor.apply writes per-step JSONL audit entries."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            executor = _make_executor(tmp)
            executor.apply(container, container_pid)

            log_file = state.audit_path(Path(tmp))
            assert log_file.is_file(), "Audit log must be created"
            entries = [json.loads(line) for line in log_file.read_text().splitlines()]
            details = [e.get("detail", "") for e in entries]
            assert any("ruleset applied" in d for d in details)
            assert any("cached IPs" in d for d in details)
            assert any("verification passed" in d for d in details)
            assert any("applied with" in d for d in details)
            # All entries must have required fields
            for entry in entries:
                assert "ts" in entry
                assert "container" in entry
                assert entry["container"] == container

    def test_apply_hook_audit_with_pre_resolved_ips(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Audit entries include actual resolved IPs."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            resolved_ips = [*ALLOWED_TARGET_IPS, IPV6_CLOUDFLARE]
            state.profile_allowed_path(Path(tmp)).write_text("\n".join(resolved_ips) + "\n")

            executor = _make_executor(tmp)
            executor.apply(container, container_pid)

            log_file = state.audit_path(Path(tmp))
            entries = [json.loads(line) for line in log_file.read_text().splitlines()]
            details = [e.get("detail", "") for e in entries]
            # IPs must appear in the tagged detail lines
            assert any("[ips] cached:" in d and resolved_ips[0] in d for d in details)
            assert any("[ips] added to allow sets:" in d and resolved_ips[0] in d for d in details)

    def test_apply_hook_audit_on_failure(
        self, container: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bad PID produces an 'error' audit entry."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            executor = _make_executor(tmp)
            with pytest.raises(RuntimeError):
                executor.apply(container, _NONEXISTENT_PID)

            log_file = state.audit_path(Path(tmp))
            assert log_file.is_file(), "Audit log must be created even on failure"
            entries = [json.loads(line) for line in log_file.read_text().splitlines()]
            assert any(e.get("action") == "error" for e in entries)
