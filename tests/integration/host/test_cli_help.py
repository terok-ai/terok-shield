# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""CLI help smoke test — no podman or internet needed."""

import pytest

from terok_shield.cli import main


@pytest.mark.needs_host_features
class TestCLIHelp:
    """Verify CLI entrypoint basics."""

    def test_cli_no_args_exits_zero(self) -> None:
        """``main([])`` prints help and exits 0."""
        with pytest.raises(SystemExit) as exc_info:
            main([])
        assert exc_info.value.code == 0
