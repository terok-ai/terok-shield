# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: rules and logs inspection (API + CLI)."""

import pytest

from terok_shield.cli import main
from terok_shield.nft_constants import BYPASS_LOG_PREFIX

from ..conftest import nft_missing, podman_missing
from ..helpers import disposable_shield as _shield

# -- Public API rules -----------------------------------------


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestRulesAPI:
    """Verify ``Shield.rules()`` returns the applied ruleset."""

    def test_shield_rules_returns_ruleset(self, shielded_container: str) -> None:
        """``Shield.rules()`` returns text containing ``terok_shield``."""
        rules = _shield().rules(shielded_container)
        assert "terok_shield" in rules
        assert "allow_v4" in rules


# -- CLI rules ------------------------------------------------


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestRulesCLI:
    """Verify ``terok-shield rules`` via CLI."""

    def test_cli_rules(self, shielded_container: str, capsys: pytest.CaptureFixture) -> None:
        """``main(["rules", container])`` prints the ruleset."""
        main(["rules", shielded_container])
        captured = capsys.readouterr()
        assert "terok_shield" in captured.out

    def test_cli_rules_shows_state_up(
        self, shielded_container: str, capsys: pytest.CaptureFixture
    ) -> None:
        """``main(["rules", container])`` shows State: up for a shielded container."""
        main(["rules", shielded_container])
        captured = capsys.readouterr()
        assert "State: up" in captured.out

    def test_cli_rules_shows_state_down(
        self, shielded_container: str, capsys: pytest.CaptureFixture
    ) -> None:
        """``main(["rules", container])`` shows State: down after bypass."""
        _shield().down(shielded_container)
        main(["rules", shielded_container])
        captured = capsys.readouterr()
        assert "State: down" in captured.out


# -- Rules content in bypass mode ----------------------------


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestRulesBypassAPI:
    """Verify ``Shield.rules()`` returns correct bypass ruleset."""

    def test_rules_contain_bypass_prefix(self, shielded_container: str) -> None:
        """Bypass ruleset contains the TEROK_SHIELD_BYPASS log prefix."""
        shield = _shield()
        shield.down(shielded_container)
        rules = shield.rules(shielded_container)
        assert BYPASS_LOG_PREFIX in rules
        assert "policy accept" in rules

    def test_rules_restored_after_up(self, shielded_container: str) -> None:
        """Rules revert to deny-all after shield.up()."""
        shield = _shield()
        shield.down(shielded_container)
        assert "policy accept" in shield.rules(shielded_container)

        shield.up(shielded_container)
        rules = shield.rules(shielded_container)
        assert "policy drop" in rules
        assert BYPASS_LOG_PREFIX not in rules


# -- CLI logs -------------------------------------------------


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestLogsCLI:
    """Verify ``terok-shield logs`` via CLI."""

    def test_cli_logs(self, shielded_container: str, capsys: pytest.CaptureFixture) -> None:
        """``main(["logs", "--container", container])`` shows log entries."""
        # The shielded_container fixture logs a "setup" event via shield.pre_start
        main(["logs", "--container", shielded_container])
        captured = capsys.readouterr()
        # Audit log must have the setup entry from shield.pre_start
        assert "setup" in captured.out
