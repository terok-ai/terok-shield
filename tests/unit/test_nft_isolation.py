# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""AST-based test: nft.py must only import stdlib modules."""

import ast
import unittest
from pathlib import Path


class TestNftImportIsolation(unittest.TestCase):
    """nft.py is the auditable security boundary -- no third-party imports."""

    def test_nft_has_only_allowed_imports(self) -> None:
        """Verify nft.py imports only stdlib and nft_constants."""
        source = (Path(__file__).parents[2] / "src" / "terok_shield" / "nft.py").read_text()
        tree = ast.parse(source)
        stdlib = {"ipaddress", "re", "textwrap", "__future__"}
        # nft_constants.py is the only non-stdlib import allowed (literals-only module)
        allowed_relative = {"nft_constants"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    self.assertIn(
                        top,
                        stdlib,
                        f"nft.py imports non-stdlib module: {alias.name}",
                    )
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.level > 0:
                    # Relative import — must be from allowed set
                    mod = node.module.split(".")[0]
                    self.assertIn(
                        mod,
                        allowed_relative,
                        f"nft.py has disallowed relative import: .{node.module}",
                    )
                else:
                    top = node.module.split(".")[0]
                    self.assertIn(
                        top,
                        stdlib,
                        f"nft.py imports non-stdlib module: {node.module}",
                    )
