# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: CLI down/up/rules/preview commands with real containers."""

import pytest

from terok_shield import Shield, ShieldConfig, ShieldState
from terok_shield.cli import main
from terok_shield.nft_constants import BYPASS_LOG_PREFIX
from tests.testnet import BLOCKED_TARGET_DNS_PORT, BLOCKED_TARGET_HTTP, BLOCKED_TARGET_IP

from ..conftest import nft_missing, podman_missing
from ..helpers import assert_blocked, assert_connectable


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestBypassCLI:
    """End-to-end CLI down/up tests with a real shielded container."""

    def test_cli_down(self, shielded_container: str, capsys: pytest.CaptureFixture) -> None:
        """``main(["down", container])`` switches to bypass mode."""
        main(["down", shielded_container])
        captured = capsys.readouterr()
        assert "Shield down" in captured.out
        assert Shield(ShieldConfig()).state(shielded_container) == ShieldState.DOWN

    def test_cli_down_all(self, shielded_container: str, capsys: pytest.CaptureFixture) -> None:
        """``main(["down", container, "--all"])`` enables full bypass."""
        main(["down", shielded_container, "--all"])
        captured = capsys.readouterr()
        assert "all traffic" in captured.out
        assert Shield(ShieldConfig()).state(shielded_container) == ShieldState.DOWN_ALL

    def test_cli_up(self, shielded_container: str, capsys: pytest.CaptureFixture) -> None:
        """``main(["up", container])`` restores deny-all mode."""
        main(["down", shielded_container])
        assert Shield(ShieldConfig()).state(shielded_container) == ShieldState.DOWN

        main(["up", shielded_container])
        captured = capsys.readouterr()
        assert "Shield up" in captured.out
        assert Shield(ShieldConfig()).state(shielded_container) == ShieldState.UP

    def test_cli_down_then_traffic(self, shielded_container: str) -> None:
        """CLI down enables traffic; CLI up blocks it again."""
        assert_blocked(shielded_container, BLOCKED_TARGET_HTTP)

        main(["down", shielded_container])
        assert_connectable(shielded_container, BLOCKED_TARGET_IP, BLOCKED_TARGET_DNS_PORT)

        main(["up", shielded_container])
        assert_blocked(shielded_container, BLOCKED_TARGET_HTTP)

    def test_cli_rules_shows_state(
        self, shielded_container: str, capsys: pytest.CaptureFixture
    ) -> None:
        """``main(["rules", container])`` shows state in output."""
        main(["rules", shielded_container])
        captured = capsys.readouterr()
        assert "State: up" in captured.out

        main(["down", shielded_container])
        capsys.readouterr()  # Clear buffer

        main(["rules", shielded_container])
        captured = capsys.readouterr()
        assert "State: down" in captured.out


@pytest.mark.needs_host_features
@pytest.mark.usefixtures("shield_env")
class TestBypassPreviewCLI:
    """Verify ``terok-shield preview --down`` without a running container."""

    def test_preview_down(self, capsys: pytest.CaptureFixture) -> None:
        """``preview --down`` shows bypass ruleset with accept policy."""
        main(["preview", "--down"])
        captured = capsys.readouterr()
        assert "policy accept" in captured.out
        assert BYPASS_LOG_PREFIX in captured.out

    def test_preview_down_all(self, capsys: pytest.CaptureFixture) -> None:
        """``preview --down --all`` omits private-range rules."""
        main(["preview", "--down", "--all"])
        captured = capsys.readouterr()
        assert "policy accept" in captured.out
        assert "TEROK_SHIELD_PRIVATE" not in captured.out

    def test_preview_all_without_down_fails(self, capsys: pytest.CaptureFixture) -> None:
        """``preview --all`` without ``--down`` exits with error."""
        with pytest.raises(SystemExit) as exc_info:
            main(["preview", "--all"])
        assert exc_info.value.code == 1
