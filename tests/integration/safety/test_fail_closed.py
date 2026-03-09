# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: fail-closed error paths."""

import uuid
from pathlib import Path

import pytest

from terok_shield.cli import main
from tests.testnet import TEST_IP1

from ..conftest import podman_missing


@pytest.mark.needs_podman
@podman_missing
class TestCLIErrors:
    """Verify CLI error handling that requires podman."""

    def test_cli_allow_bad_container(self, shield_env: Path) -> None:
        """Allowing on a nonexistent container exits 1."""
        bogus = f"nonexistent-{uuid.uuid4().hex[:12]}"
        with pytest.raises(SystemExit) as exc_info:
            main(["allow", bogus, TEST_IP1])
        assert exc_info.value.code == 1
