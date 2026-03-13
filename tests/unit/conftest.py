# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for unit tests."""

from collections.abc import Callable
from pathlib import Path

import pytest

from terok_shield.config import ShieldConfig


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    """Return an isolated state directory path for a unit test."""
    return tmp_path


@pytest.fixture
def make_config(state_dir: Path) -> Callable[..., ShieldConfig]:
    """Build ``ShieldConfig`` objects rooted in the test's temp state directory."""

    def _make_config(**kwargs: object) -> ShieldConfig:
        return ShieldConfig(state_dir=state_dir, **kwargs)

    return _make_config
