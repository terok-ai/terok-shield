# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Regression guard: ``python -m terok_shield.cli`` is launchable.

[`simple_clearance`][terok_shield.simple_clearance] spawns the verdict
subprocess via ``[sys.executable, "-m", "terok_shield.cli", action, ...]``
with [`child_process_env`][terok_shield.subprocess_env.child_process_env]
threading the parent's ``sys.path``.  If the ``__main__`` module ever
disappears (or never lands), every operator allow / deny in the
terminal-fallback flow silently regresses to ``! verdict failed``.
The launch shape verified here mirrors that call site exactly.
"""

from __future__ import annotations

import subprocess
import sys

from terok_shield.subprocess_env import child_process_env


def test_cli_module_runs_via_dash_m() -> None:
    """``python -m terok_shield.cli --help`` exits 0 and prints usage text."""
    result = subprocess.run(  # nosec B603 — fixed argv, no shell
        [sys.executable, "-m", "terok_shield.cli", "--help"],
        capture_output=True,
        env=child_process_env(),
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, (
        f"`python -m terok_shield.cli --help` failed (rc={result.returncode}): "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "usage" in result.stdout.lower()
