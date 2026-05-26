# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Host-wide filesystem paths and filenames for terok-shield artifacts.

Per-container state paths live in [`terok_shield.state`][terok_shield.state].  This
module is the single source of truth for artifacts shared across
containers or installed into host-wide locations:

- the NFLOG reader script's canonical install path (under
  ``paths.root`` via [`namespace_state_dir`][terok_util.paths.namespace_state_dir]);
- the hook entrypoint filename used both under the user's
  ``containers/oci/hooks.d/`` and inside each per-container
  ``state_dir``.

The reader-script path is computed once in this module.  The
``resources/reader_hook.py`` script cannot import from terok_shield
at runtime (it runs under ``/usr/bin/python3`` outside any venv); the
installer rewrites that script's ``_READER_SCRIPT_PATH`` placeholder
with the resolved path at install time, so the on-disk hook always
points at wherever ``reader_script_path()`` resolved when ``terok-shield
setup`` ran.
"""

from __future__ import annotations

from pathlib import Path

from terok_util.paths import namespace_state_dir

HOOK_ENTRYPOINT_NAME = "terok-shield-hook"
"""Canonical filename of the shield OCI hook entrypoint script.

Used (a) under ``~/.local/share/containers/oci/hooks.d/`` for user-wide
installation and (b) under each per-container ``state_dir`` after
``Shield.pre_start()`` materialises it.  Keeping both sites consuming
the same constant means renaming the entrypoint is a single edit.
"""


def reader_script_path() -> Path:
    """Return the on-disk path where the NFLOG reader script is installed.

    Honours the operator's ``paths.root`` config via
    [`namespace_state_dir`][terok_util.paths.namespace_state_dir] —
    when ``config.yml`` sets ``paths.root: /virt/terok/state`` the
    script lands at ``/virt/terok/state/shield/nflog-reader.py``;
    without that override it falls back to the platform-default XDG
    data dir.
    """
    return namespace_state_dir("shield") / "nflog-reader.py"
