# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""AST-based tests for OCI-hook resource import isolation.

The three resource files installed alongside each terok-shield hook
pair must use only stdlib modules (plus the shared ``_oci_state``
sibling, for the role scripts).  They run as standalone OCI hooks
inside the container runtime's namespace via ``/usr/bin/python3``,
outside any virtualenv — a ``terok_shield`` import would simply fail.

This file stays intentionally small and explicit because it guards the
import boundary of the hook scripts.  Abstraction would obscure the
allowed dependency surface; auditors should be able to read the
allowed-set line by line.
"""

import ast
from pathlib import Path

_RESOURCES = Path(__file__).parents[2] / "src" / "terok_shield" / "resources"

_STDLIB = {
    "__future__",
    "contextlib",
    "json",
    "os",
    "pathlib",
    "pwd",
    "shutil",
    "signal",
    "stat",
    "subprocess",
    "sys",
    "time",
}

#: Sibling module the role scripts may import via the ``sys.path[0]``
#: convention.  Audited separately by ``TestOciStateBallastImportIsolation``.
_BALLAST_NAME = "_oci_state"


def _check_imports(source: str, *, allow_ballast: bool, file_label: str) -> None:
    """Walk *source* and assert every import resolves to ``_STDLIB``.

    When *allow_ballast* is True, ``import _oci_state`` and ``from
    _oci_state import …`` are also permitted — that's the role-script
    contract.
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if allow_ballast and top == _BALLAST_NAME:
                    continue
                assert top in _STDLIB, f"{file_label} imports non-stdlib module: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                rel = "." * node.level + (node.module or "")
                raise AssertionError(
                    f"{file_label} has relative import: {rel} (must be stdlib-only)"
                )
            if node.module:
                top = node.module.split(".")[0]
                if allow_ballast and top == _BALLAST_NAME:
                    continue
                assert top in _STDLIB, f"{file_label} imports non-stdlib module: {node.module}"


class TestOciStateBallastImportIsolation:
    """``_oci_state.py`` is stdlib-only — no third-party or terok_shield imports.

    The role scripts both depend on this module at runtime; if it grew
    a non-stdlib import, every shielded container start would fail.
    """

    def test_oci_state_has_only_stdlib_imports(self) -> None:
        """Verify ``_oci_state.py`` imports only stdlib modules."""
        source = (_RESOURCES / "_oci_state.py").read_text()
        _check_imports(source, allow_ballast=False, file_label="_oci_state.py")


class TestNftHookImportIsolation:
    """``nft_hook.py`` is stdlib + ``_oci_state`` only."""

    def test_nft_hook_has_only_allowed_imports(self) -> None:
        """Verify ``nft_hook.py`` imports only stdlib + the ballast sibling."""
        source = (_RESOURCES / "nft_hook.py").read_text()
        _check_imports(source, allow_ballast=True, file_label="nft_hook.py")


class TestReaderHookImportIsolation:
    """``reader_hook.py`` is stdlib + ``_oci_state`` only."""

    def test_reader_hook_has_only_allowed_imports(self) -> None:
        """Verify ``reader_hook.py`` imports only stdlib + the ballast sibling."""
        source = (_RESOURCES / "reader_hook.py").read_text()
        _check_imports(source, allow_ballast=True, file_label="reader_hook.py")
