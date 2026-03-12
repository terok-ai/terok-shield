# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: HookExecutor.apply and hook_main end-to-end."""

import json
import tempfile
from pathlib import Path

import pytest

from terok_shield.audit import AuditLogger
from terok_shield.nft import RulesetBuilder, verify_ruleset
from terok_shield.oci_hook import HookExecutor, hook_main
from terok_shield.run import SubprocessRunner
from tests.testnet import (
    ALLOWED_TARGET_HTTP,
    ALLOWED_TARGET_IPS,
    BLOCKED_TARGET_HTTP,
    GOOGLE_DNS_IP,
)

from ..conftest import nft_missing, nsenter_nft, podman_missing
from ..helpers import wget as _wget


def _make_executor(tmp: str) -> HookExecutor:
    """Create a HookExecutor wired to a temp directory."""
    runner = SubprocessRunner()
    audit = AuditLogger(logs_dir=Path(tmp) / "logs")
    ruleset = RulesetBuilder()
    return HookExecutor(
        runner=runner,
        audit=audit,
        ruleset=ruleset,
        resolved_dir=Path(tmp) / "resolved",
    )


# ── HookExecutor.apply end-to-end ────────────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestApplyHookE2E:
    """End-to-end test of the OCI hook entry point."""

    def test_apply_hook_creates_firewall(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """HookExecutor.apply applies the ruleset and passes verification."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            executor = _make_executor(tmp)
            executor.apply(container, container_pid)

            listed = nsenter_nft(container_pid, "list", "ruleset")
            assert listed.returncode == 0
            assert "terok_shield" in listed.stdout
            errors = verify_ruleset(listed.stdout)
            assert errors == [], f"Verification errors: {errors}"

    def test_apply_hook_with_pre_resolved_ips(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """HookExecutor.apply loads pre-resolved IPs from the cache file."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)

            resolved_dir = Path(tmp) / "resolved"
            resolved_dir.mkdir(parents=True)
            resolved_ips = [*ALLOWED_TARGET_IPS, GOOGLE_DNS_IP]
            (resolved_dir / f"{container}.resolved").write_text("\n".join(resolved_ips) + "\n")

            executor = _make_executor(tmp)
            executor.apply(container, container_pid)

            listed = nsenter_nft(container_pid, "list", "set", "inet", "terok_shield", "allow_v4")
            assert listed.returncode == 0
            for ip in resolved_ips:
                assert ip in listed.stdout

    def test_apply_hook_blocks_traffic(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """After HookExecutor.apply, outbound traffic is blocked."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            executor = _make_executor(tmp)
            executor.apply(container, container_pid)

        post = _wget(container, ALLOWED_TARGET_HTTP, timeout=10)
        assert post.returncode != 0, "Traffic should be blocked after apply"

    def test_apply_hook_allows_pre_resolved(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """After HookExecutor.apply with pre-resolved IPs, those IPs are reachable."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)

            resolved_dir = Path(tmp) / "resolved"
            resolved_dir.mkdir(parents=True)
            (resolved_dir / f"{container}.resolved").write_text(
                "\n".join(ALLOWED_TARGET_IPS) + "\n"
            )

            executor = _make_executor(tmp)
            executor.apply(container, container_pid)

        # Allowed IP should be reachable
        allowed = _wget(container, ALLOWED_TARGET_HTTP, timeout=10)
        assert allowed.returncode == 0, f"Pre-resolved IP should be reachable: {allowed.stderr}"

        # Non-allowed IP should still be blocked
        blocked = _wget(container, BLOCKED_TARGET_HTTP, timeout=10)
        assert blocked.returncode != 0, "Non-allowed IP should be blocked"

    def test_apply_hook_fail_closed_bad_pid(
        self, container: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """HookExecutor.apply raises RuntimeError for an invalid PID."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            executor = _make_executor(tmp)
            with pytest.raises(RuntimeError):
                executor.apply(container, "999999")

    def test_reapply_after_flush(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Flushing and re-applying produces a valid ruleset."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)

            # First apply
            executor = _make_executor(tmp)
            executor.apply(container, container_pid)
            listed = nsenter_nft(container_pid, "list", "ruleset")
            assert "terok_shield" in listed.stdout

            # Flush
            nsenter_nft(container_pid, "flush", "ruleset")
            listed = nsenter_nft(container_pid, "list", "ruleset")
            assert "terok_shield" not in listed.stdout

            # Re-apply
            executor2 = _make_executor(tmp)
            executor2.apply(container, container_pid)
            listed = nsenter_nft(container_pid, "list", "ruleset")
            assert "terok_shield" in listed.stdout
            errors = verify_ruleset(listed.stdout)
            assert errors == [], f"Re-apply verification failed: {errors}"


# ── hook_main (pure parsing — no container needed) ───────


def test_hook_main_invalid_json() -> None:
    """hook_main returns 1 for invalid OCI state."""
    rc = hook_main("not json")
    assert rc == 1


# ── hook_main end-to-end ─────────────────────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestHookMainE2E:
    """End-to-end test of hook_main (the OCI hook entry point)."""

    def test_hook_main_success(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """hook_main returns 0 on success and applies the firewall."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)

            oci_state = json.dumps({"id": container, "pid": int(container_pid)})
            rc = hook_main(oci_state)
            assert rc == 0

            listed = nsenter_nft(container_pid, "list", "ruleset")
            assert "terok_shield" in listed.stdout

    def test_hook_main_bad_pid(self, container: str, monkeypatch: pytest.MonkeyPatch) -> None:
        """hook_main returns 1 for unreachable PID."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            oci_state = json.dumps({"id": container, "pid": 999999})
            rc = hook_main(oci_state)
            assert rc == 1

    def test_hook_main_with_pre_resolved_blocks_and_allows(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Full lifecycle: OCI state → hook_main → traffic filtered."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)

            # Pre-resolve: allow Cloudflare anycast pair only
            resolved_dir = Path(tmp) / "resolved"
            resolved_dir.mkdir(parents=True)
            (resolved_dir / f"{container}.resolved").write_text(
                "\n".join(ALLOWED_TARGET_IPS) + "\n"
            )

            oci_state = json.dumps({"id": container, "pid": int(container_pid)})
            rc = hook_main(oci_state)
            assert rc == 0

        # Allowed target reachable
        allowed = _wget(container, ALLOWED_TARGET_HTTP, timeout=10)
        assert allowed.returncode == 0, "Pre-resolved IP should be reachable"

        # Non-allowed target blocked
        blocked = _wget(container, BLOCKED_TARGET_HTTP, timeout=10)
        assert blocked.returncode != 0, "Non-allowed IP should be blocked"
