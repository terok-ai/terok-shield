# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: audit logging (filesystem + hook audit trail)."""

import json
import tempfile
from pathlib import Path

import pytest

_NONEXISTENT_PID = "4000000"  # Well above typical PID range

from terok_shield.audit import list_log_files, log_event, tail_log
from terok_shield.oci_hook import apply_hook
from tests.testnet import ALLOWED_TARGET_IPS, TEST_IP1, TEST_IP2

from ..conftest import nft_missing, podman_missing

# ── Filesystem audit (no container needed) ───────────────


@pytest.mark.needs_host_features
class TestAuditLive:
    """Audit logging with real temp directories."""

    def test_log_and_tail(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Write audit events and read them back."""
        monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", str(tmp_path))

        log_event("test-ctr", "setup", detail="integration test")
        log_event("test-ctr", "allowed", dest=TEST_IP1)
        log_event("test-ctr", "denied", dest=TEST_IP2)

        events = list(tail_log("test-ctr", n=10))
        assert len(events) == 3
        assert events[0]["action"] == "setup"
        assert events[1]["dest"] == TEST_IP1
        assert events[2]["action"] == "denied"

    def test_jsonl_format(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Each line must be valid compact JSON."""
        monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", str(tmp_path))

        log_event("fmt-test", "setup")
        log_event("fmt-test", "teardown")

        log_file = tmp_path / "logs" / "fmt-test.jsonl"
        assert log_file.is_file()

        for line in log_file.read_text().splitlines():
            entry = json.loads(line)
            assert "ts" in entry
            assert "container" in entry
            assert "action" in entry
            # Compact format: no spaces after separators
            assert ", " not in line
            assert ": " not in line

    def test_list_log_files(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """list_log_files returns container names with logs."""
        monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", str(tmp_path))

        log_event("alpha", "setup")
        log_event("bravo", "setup")

        names = list_log_files()
        assert "alpha" in names
        assert "bravo" in names

    def test_tail_empty_container(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Tailing a non-existent container returns no events."""
        monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", str(tmp_path))

        events = list(tail_log("nonexistent", n=10))
        assert events == []


# ── Hook audit trail (container needed) ──────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestApplyHookAudit:
    """Verify apply_hook produces JSONL audit entries."""

    def test_apply_hook_produces_audit_trail(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """apply_hook writes per-step JSONL audit entries."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            apply_hook(container, container_pid)

            log_file = Path(tmp) / "logs" / f"{container}.jsonl"
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
            resolved_dir = Path(tmp) / "resolved"
            resolved_dir.mkdir(parents=True)
            resolved_ips = ALLOWED_TARGET_IPS
            (resolved_dir / f"{container}.resolved").write_text("\n".join(resolved_ips) + "\n")

            apply_hook(container, container_pid)

            log_file = Path(tmp) / "logs" / f"{container}.jsonl"
            entries = [json.loads(line) for line in log_file.read_text().splitlines()]
            details = [e.get("detail", "") for e in entries]
            # IPs must appear in the tagged detail lines
            assert any("[ips] cached:" in d and resolved_ips[0] in d for d in details)
            assert any("[ips] added to allow_v4:" in d and resolved_ips[0] in d for d in details)

    def test_apply_hook_audit_on_failure(
        self, container: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bad PID produces an 'error' audit entry."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            with pytest.raises(RuntimeError):
                apply_hook(container, _NONEXISTENT_PID)

            log_file = Path(tmp) / "logs" / f"{container}.jsonl"
            assert log_file.is_file(), "Audit log must be created even on failure"
            entries = [json.loads(line) for line in log_file.read_text().splitlines()]
            assert any(e.get("action") == "error" for e in entries)
