# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: generate nft ruleset, apply via nsenter, verify."""

import subprocess

import pytest

from terok_shield.nft.rules import hook_ruleset, verify_ruleset

from ..conftest import nsenter_nft


def _apply(pid: str) -> None:
    """Apply hook ruleset and assert success."""
    result = nsenter_nft(pid, stdin=hook_ruleset())
    assert result.returncode == 0, f"nft apply failed: {result.stderr}"


def _list(pid: str) -> subprocess.CompletedProcess:
    """List ruleset and assert success."""
    listed = nsenter_nft(pid, "list", "ruleset")
    assert listed.returncode == 0, f"nft list failed: {listed.stderr}"
    return listed


@pytest.mark.needs_podman
@pytest.mark.usefixtures("nft_in_netns")
class TestHookApply:
    """Apply a hook-mode ruleset to a real container netns and verify."""

    def test_apply_and_list(self, container_pid: str) -> None:
        """Apply hook ruleset via nsenter and list it back."""
        _apply(container_pid)
        listed = _list(container_pid)
        assert "terok_shield" in listed.stdout

    def test_verify_applied_ruleset(self, container_pid: str) -> None:
        """Apply hook ruleset and run verify_ruleset against the output."""
        _apply(container_pid)
        listed = _list(container_pid)
        errors = verify_ruleset(listed.stdout)
        assert errors == [], f"Verification errors: {errors}"

    def test_policy_drop_enforced(self, container_pid: str) -> None:
        """Applied ruleset must contain 'policy drop'."""
        _apply(container_pid)
        listed = _list(container_pid)
        assert "policy drop" in listed.stdout

    def test_rfc1918_blocked(self, container_pid: str) -> None:
        """All RFC1918 ranges must appear in the applied ruleset."""
        from terok_shield.nft.constants import RFC1918

        _apply(container_pid)
        listed = _list(container_pid)
        for net in RFC1918:
            assert net in listed.stdout, f"RFC1918 block for {net} not found in applied ruleset"

    def test_flush_and_reapply(self, container_pid: str) -> None:
        """Flushing and reapplying the ruleset works cleanly."""
        _apply(container_pid)

        # Flush
        flush = nsenter_nft(container_pid, "flush", "ruleset")
        assert flush.returncode == 0

        # Verify empty
        listed = _list(container_pid)
        assert "terok_shield" not in listed.stdout

        # Reapply
        _apply(container_pid)
        listed = _list(container_pid)
        assert "terok_shield" in listed.stdout
