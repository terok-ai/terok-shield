# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for all integration test tiers."""

import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def shield_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Provide an isolated state directory for shield operations.

    Sets ``TEROK_SHIELD_STATE_DIR`` to a temporary directory so that hooks,
    resolved caches, and logs do not touch the real system.

    Yields:
        Path to the temporary state directory.
    """
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
        yield Path(tmp)
