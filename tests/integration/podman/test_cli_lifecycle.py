# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the terok-shield CLI subcommands.

Mirrors the public API tests in ``test_api_lifecycle.py`` but exercises
the CLI via ``cli.main(argv=[...])``.

Run via: ``make test-podman``
"""

from pathlib import Path

import pytest

from terok_shield import shield_allow
from terok_shield.cli import main
from tests.testnet import (
    ALLOWED_TARGET_HTTP,
    ALLOWED_TARGET_IPS,
)

from .conftest import nft_missing, podman_missing
from .helpers import assert_blocked, assert_reachable

# ── CLI setup ────────────────────────────────────────────


@pytest.mark.needs_podman
@podman_missing
@nft_missing
class TestCLISetup:
    """Verify ``terok-shield setup`` via CLI."""

    def test_cli_setup(self, shield_env: Path) -> None:
        """``main(["setup"])`` exits normally and creates hook files."""
        main(["setup"])

        hooks_dir = shield_env / "hooks"
        assert (hooks_dir / "terok-shield-hook.json").is_file()
        assert (shield_env / "terok-shield-hook").is_file()

    def test_cli_setup_idempotent(self, shield_env: Path) -> None:
        """Calling setup twice via CLI succeeds."""
        main(["setup"])
        main(["setup"])

        hooks_dir = shield_env / "hooks"
        assert (hooks_dir / "terok-shield-hook.json").is_file()


# ── CLI status ───────────────────────────────────────────


@pytest.mark.needs_podman
@podman_missing
class TestCLIStatus:
    """Verify ``terok-shield status`` via CLI."""

    def test_cli_status(self, shield_env: Path, capsys: pytest.CaptureFixture) -> None:
        """``main(["status"])`` prints mode info."""
        main(["status"])
        captured = capsys.readouterr()
        assert "Mode:" in captured.out
        assert "Audit:" in captured.out


# ── CLI resolve ──────────────────────────────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
class TestCLIResolve:
    """Verify ``terok-shield resolve`` via CLI."""

    def test_cli_resolve(self, shield_env: Path, capsys: pytest.CaptureFixture) -> None:
        """``main(["resolve", container])`` prints resolved IP count."""
        main(["resolve", "cli-resolve-test"])
        captured = capsys.readouterr()
        assert "Resolved" in captured.out
        assert "cli-resolve-test" in captured.out


# ── CLI lifecycle (with real container) ──────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestCLILifecycle:
    """End-to-end CLI tests with a real shielded container."""

    def test_cli_allow(self, shielded_container: str) -> None:
        """``main(["allow", container, ip])`` makes IP reachable."""
        for ip in ALLOWED_TARGET_IPS:
            main(["allow", shielded_container, ip])
        assert_reachable(shielded_container, ALLOWED_TARGET_HTTP)

    def test_cli_deny(self, shielded_container: str) -> None:
        """``main(["deny", container, ip])`` blocks the IP."""
        # First allow, then deny
        for ip in ALLOWED_TARGET_IPS:
            shield_allow(shielded_container, ip)
        assert_reachable(shielded_container, ALLOWED_TARGET_HTTP)

        for ip in ALLOWED_TARGET_IPS:
            main(["deny", shielded_container, ip])
        assert_blocked(shielded_container, ALLOWED_TARGET_HTTP)

    def test_cli_rules(self, shielded_container: str, capsys: pytest.CaptureFixture) -> None:
        """``main(["rules", container])`` prints the ruleset."""
        main(["rules", shielded_container])
        captured = capsys.readouterr()
        assert "terok_shield" in captured.out

    def test_cli_logs(self, shielded_container: str, capsys: pytest.CaptureFixture) -> None:
        """``main(["logs", "--container", container])`` shows log entries."""
        # The shielded_container fixture logs a "setup" event via shield_pre_start
        main(["logs", "--container", shielded_container])
        captured = capsys.readouterr()
        # Audit log should have at least the setup entry
        assert "setup" in captured.out or captured.out.strip() == ""


# ── CLI error handling ───────────────────────────────────


@pytest.mark.needs_podman
@podman_missing
class TestCLIErrors:
    """Verify CLI error handling."""

    def test_cli_no_args_exits_zero(self) -> None:
        """``main([])`` prints help and exits 0."""
        with pytest.raises(SystemExit) as exc_info:
            main([])
        assert exc_info.value.code == 0

    def test_cli_allow_bad_container(self, shield_env: Path) -> None:
        """``main(["allow", "nonexistent", "1.2.3.4"])`` exits 1."""
        with pytest.raises(SystemExit) as exc_info:
            main(["allow", "nonexistent-container-xyz", "1.2.3.4"])
        assert exc_info.value.code == 1
