# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Installer for the standalone NFLOG reader resource.

Copies ``terok_shield/resources/nflog_reader.py`` out of the installed
package to the canonical on-disk location, where the OCI bridge hook
can execute it with ``/usr/bin/python3``.  The destination survives
terok-shield reinstalls (the OCI hook references it by absolute path
regardless of the package's virtual-environment location).
"""

from importlib import resources as importlib_resources
from pathlib import Path

from ..paths import reader_script_path

_READER_PACKAGE = "terok_shield.resources"
_READER_RESOURCE = "nflog_reader.py"


def install_reader_resource(dest: Path | None = None) -> Path:
    """Copy the NFLOG reader script to *dest* and make it executable.

    Overwrites any existing file so re-running after a terok-shield
    upgrade always picks up the latest reader code.

    Args:
        dest: Destination path for the reader script.  Defaults to
            [`reader_script_path`][terok_shield.hooks.reader_install.reader_script_path] — the canonical XDG-aware
            location that the OCI bridge hook looks for.  Parents are
            created on demand.

    Returns:
        The absolute path where the reader was actually installed.
    """
    if dest is None:
        dest = reader_script_path()
    # Normalise before touching disk so the Returns-absolute contract holds
    # even when a caller hands in ``Path("~/share/…")`` or ``Path("./x")``.
    dest = dest.expanduser().resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    source = importlib_resources.files(_READER_PACKAGE).joinpath(_READER_RESOURCE)
    dest.write_bytes(source.read_bytes())
    dest.chmod(0o755)
    return dest
