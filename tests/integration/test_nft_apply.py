# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: generate nft ruleset, apply via nsenter, verify."""

from __future__ import annotations

import pytest

from terok_shield.nft import standard_ruleset, verify_ruleset

from .conftest import nft_unusable, nsenter_nft


@pytest.mark.integration
@nft_unusable
class TestStandardApply:
    """Apply a standard-mode ruleset to a real container netns and verify."""

    def test_apply_and_list(self, container_pid: str) -> None:
        """Apply standard ruleset via nsenter and list it back."""
        ruleset = standard_ruleset()
        result = nsenter_nft(container_pid, stdin=ruleset)
        assert result.returncode == 0, f"nft apply failed: {result.stderr}"

        listed = nsenter_nft(container_pid, "list", "ruleset")
        assert listed.returncode == 0, f"nft list failed: {listed.stderr}"
        assert "terok_shield" in listed.stdout

    def test_verify_applied_ruleset(self, container_pid: str) -> None:
        """Apply standard ruleset and run verify_ruleset against the output."""
        ruleset = standard_ruleset()
        nsenter_nft(container_pid, stdin=ruleset)

        listed = nsenter_nft(container_pid, "list", "ruleset")
        errors = verify_ruleset(listed.stdout)
        assert errors == [], f"Verification errors: {errors}"

    def test_policy_drop_enforced(self, container_pid: str) -> None:
        """Applied ruleset must contain 'policy drop'."""
        ruleset = standard_ruleset()
        nsenter_nft(container_pid, stdin=ruleset)

        listed = nsenter_nft(container_pid, "list", "ruleset")
        assert "policy drop" in listed.stdout

    def test_rfc1918_blocked(self, container_pid: str) -> None:
        """All RFC1918 ranges must appear in the applied ruleset."""
        from terok_shield.nft_constants import RFC1918

        ruleset = standard_ruleset()
        nsenter_nft(container_pid, stdin=ruleset)

        listed = nsenter_nft(container_pid, "list", "ruleset")
        for net in RFC1918:
            assert net in listed.stdout, f"RFC1918 block for {net} not found in applied ruleset"

    def test_flush_and_reapply(self, container_pid: str) -> None:
        """Flushing and reapplying the ruleset works cleanly."""
        ruleset = standard_ruleset()
        nsenter_nft(container_pid, stdin=ruleset)

        # Flush
        flush = nsenter_nft(container_pid, "flush", "ruleset")
        assert flush.returncode == 0

        # Verify empty
        listed = nsenter_nft(container_pid, "list", "ruleset")
        assert "terok_shield" not in listed.stdout

        # Reapply
        result = nsenter_nft(container_pid, stdin=ruleset)
        assert result.returncode == 0

        listed = nsenter_nft(container_pid, "list", "ruleset")
        assert "terok_shield" in listed.stdout
