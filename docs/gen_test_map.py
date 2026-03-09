# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Generate the integration test map page for MkDocs.

Runs during ``mkdocs build`` via the mkdocs-gen-files plugin.
Delegates to ``docs/test_map.py`` for the actual collection and
Markdown generation.
"""

import sys
from pathlib import Path

import mkdocs_gen_files

# Make docs/ importable (runpy.run_path does not add it)
sys.path.insert(0, str(Path(__file__).parent))

import test_map  # noqa: E402

report = test_map.generate_test_map()
with mkdocs_gen_files.open("test_map.md", "w") as f:
    f.write(report)
