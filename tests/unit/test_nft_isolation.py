# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""AST-based tests for nft.py import isolation.

This file stays intentionally small and explicit because it guards the import
boundary of the auditable security module. We avoid abstraction here so the
allowed dependency surface can be reviewed line by line.
"""

import ast
from pathlib import Path


class TestNftImportIsolation:
    """nft.py is the auditable security boundary -- no third-party imports."""

    def test_nft_has_only_allowed_imports(self) -> None:
        """Verify nft.py imports only stdlib and nft_constants."""
        # Keep the source path inline here so auditors can review the exact
        # security-boundary file target without indirection.
        source = (
            Path(__file__).parents[2] / "src" / "terok_shield" / "nft" / "rules.py"
        ).read_text()
        tree = ast.parse(source)
        stdlib = {"ipaddress", "re", "textwrap"}
        # nft_constants.py is the only non-stdlib import allowed (literals-only module)
        allowed_relative = {"constants"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    assert top in stdlib, f"nft.py imports non-stdlib module: {alias.name}"
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.level > 0:
                    # Relative import — must be from allowed set
                    mod = node.module.split(".")[0]
                    assert mod in allowed_relative, (
                        f"nft.py has disallowed relative import: .{node.module}"
                    )
                else:
                    top = node.module.split(".")[0]
                    assert top in stdlib, f"nft.py imports non-stdlib module: {node.module}"
