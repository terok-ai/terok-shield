# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Host-wide filesystem paths and filenames for terok-shield artifacts.

Per-container state paths live in [`terok_shield.state`][terok_shield.state].  This
module is the single source of truth for artifacts shared across
containers or installed into host-wide locations:

- the NFLOG reader script's canonical install path (XDG data home);
- the hook entrypoint filename used both under the user's
  ``containers/oci/hooks.d/`` and inside each per-container
  ``state_dir``.

The reader-script path is computed in two places: ``reader_script_path()``
in this module, and its stdlib-only mirror ``_reader_script_path()`` in
``resources/reader_hook.py`` — that file cannot import from this package
at runtime, so the computation is inlined there verbatim.  When either
definition changes, the other must be updated by hand; the synced pair
is the contract.
"""

from __future__ import annotations

import os
from pathlib import Path

HOOK_ENTRYPOINT_NAME = "terok-shield-hook"
"""Canonical filename of the shield OCI hook entrypoint script.

Used (a) under ``~/.local/share/containers/oci/hooks.d/`` for user-wide
installation and (b) under each per-container ``state_dir`` after
``Shield.pre_start()`` materialises it.  Keeping both sites consuming
the same constant means renaming the entrypoint is a single edit.
"""


def reader_script_path() -> Path:
    """Return the on-disk path where the NFLOG reader script is installed.

    Respects ``XDG_DATA_HOME`` when set, otherwise falls back to the
    POSIX default ``~/.local/share``.  Mirrors the stdlib-only
    ``_reader_script_path()`` inlined in ``resources/reader_hook.py``.
    """
    data_home = os.environ.get("XDG_DATA_HOME") or f"{os.environ.get('HOME', '')}/.local/share"
    return Path(data_home) / "terok" / "shield" / "nflog-reader.py"
