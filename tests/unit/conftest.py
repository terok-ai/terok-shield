# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for unit tests."""

from collections.abc import Callable
from pathlib import Path
from typing import TypedDict, Unpack

import pytest

from terok_shield.config import ShieldConfig, ShieldMode

from ..testfs import CONFIG_FILENAME, CONFIG_ROOT_NAME, STATE_ROOT_NAME


class _ShieldConfigKwargs(TypedDict, total=False):
    """Optional ``ShieldConfig`` kwargs accepted by ``make_config``."""

    mode: ShieldMode
    default_profiles: tuple[str, ...]
    loopback_ports: tuple[int, ...]
    audit_enabled: bool
    profiles_dir: Path | None


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    """Return an isolated state directory path for a unit test."""
    return tmp_path


@pytest.fixture
def state_root(tmp_path: Path) -> Path:
    """Return a dedicated state root directory for CLI-style tests."""
    root = tmp_path / STATE_ROOT_NAME
    root.mkdir()
    return root


@pytest.fixture
def config_root(tmp_path: Path) -> Path:
    """Return a dedicated config root directory for CLI-style tests."""
    root = tmp_path / CONFIG_ROOT_NAME
    root.mkdir()
    return root


@pytest.fixture
def isolated_roots(
    monkeypatch: pytest.MonkeyPatch,
    state_root: Path,
    config_root: Path,
) -> tuple[Path, Path]:
    """Point CLI env resolution at isolated per-test config and state roots."""
    monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", str(state_root))
    monkeypatch.setenv("TEROK_SHIELD_CONFIG_DIR", str(config_root))
    return state_root, config_root


@pytest.fixture
def write_config(config_root: Path) -> Callable[[str], Path]:
    """Write ``config.yml`` under the isolated config root and return its path."""

    def _write_config(text: str) -> Path:
        config_file = config_root / CONFIG_FILENAME
        config_file.write_text(text)
        return config_file

    return _write_config


@pytest.fixture
def make_config(state_dir: Path) -> Callable[..., ShieldConfig]:
    """Build ``ShieldConfig`` objects rooted in the test's temp state directory."""

    def _make_config(**kwargs: Unpack[_ShieldConfigKwargs]) -> ShieldConfig:
        return ShieldConfig(state_dir=state_dir, **kwargs)

    return _make_config
