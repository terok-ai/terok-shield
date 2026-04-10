# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""AST-based tests for hook_entrypoint.py import isolation.

This file stays intentionally small and explicit because it guards the
import boundary of the OCI hook script.  hook_entrypoint.py runs as a
standalone OCI hook inside the container runtime's namespace — it must
use only stdlib modules and no terok_shield imports.  We avoid
abstraction here so the allowed dependency surface can be reviewed
line by line.
"""

import ast
from pathlib import Path


class TestHookEntrypointImportIsolation:
    """hook_entrypoint.py is stdlib-only -- no third-party or terok_shield imports."""

    def test_hook_entrypoint_has_only_stdlib_imports(self) -> None:
        """Verify hook_entrypoint.py imports only stdlib modules."""
        # Keep the source path inline here so auditors can review the exact
        # security-boundary file target without indirection.
        source = (
            Path(__file__).parents[2] / "src" / "terok_shield" / "resources" / "hook_entrypoint.py"
        ).read_text()
        tree = ast.parse(source)
        stdlib = {
            "json",
            "os",
            "pathlib",
            "pwd",
            "shutil",
            "signal",
            "subprocess",
            "sys",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    assert top in stdlib, (
                        f"hook_entrypoint.py imports non-stdlib module: {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.level > 0:
                    rel = "." * node.level + (node.module or "")
                    raise AssertionError(
                        f"hook_entrypoint.py has relative import: {rel} "
                        "(must be stdlib-only, no terok_shield imports)"
                    )
                if node.module:
                    top = node.module.split(".")[0]
                    assert top in stdlib, (
                        f"hook_entrypoint.py imports non-stdlib module: {node.module}"
                    )
