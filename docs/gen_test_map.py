# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Generate the integration test map page for MkDocs.

Runs during ``mkdocs build`` via the mkdocs-gen-files plugin.
Delegates to ``docs/test_map.py`` for the actual collection and
Markdown generation.
"""

import mkdocs_gen_files
import test_map

report = test_map.generate_test_map()
with mkdocs_gen_files.open("TEST_MAP.md", "w") as f:
    f.write(report)
