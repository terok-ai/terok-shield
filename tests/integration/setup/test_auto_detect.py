# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: config auto-detect with real podman."""

import pytest

from terok_shield.config import ShieldMode, _auto_detect_mode

from ..conftest import podman_missing


@pytest.mark.needs_podman
@podman_missing
class TestAutoDetect:
    """Test _auto_detect_mode with real podman."""

    def test_returns_valid_mode(self) -> None:
        """Auto-detect must return a valid ShieldMode."""
        mode = _auto_detect_mode()
        assert isinstance(mode, ShieldMode)

    def test_at_least_hook_with_nft(self, nft_in_netns: None) -> None:
        """If nft works in a container netns, auto-detect returns at least HOOK."""
        mode = _auto_detect_mode()
        assert mode in (ShieldMode.HOOK, ShieldMode.BRIDGE)
