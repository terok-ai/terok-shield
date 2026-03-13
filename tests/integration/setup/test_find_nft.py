# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: nft binary discovery on real systems."""

import os

import pytest

from terok_shield.run import find_nft

from ..conftest import nft_missing


@pytest.mark.needs_host_features
@nft_missing
class TestFindNft:
    """Verify find_nft() discovers the real nft binary."""

    def test_returns_absolute_path(self) -> None:
        """find_nft() returns an absolute path to the real nft binary."""
        path = find_nft()
        assert path, "find_nft() returned empty on a system with nft installed"
        assert os.path.isabs(path)

    def test_returned_path_is_executable(self) -> None:
        """The path returned by find_nft() points to an executable file."""
        path = find_nft()
        assert os.path.isfile(path)
        assert os.access(path, os.X_OK)

    def test_result_is_stable(self) -> None:
        """Repeated calls return the same path."""
        assert find_nft() == find_nft()
