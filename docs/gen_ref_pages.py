# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Generate the code reference pages and navigation."""

from pathlib import Path

import mkdocs_gen_files
from mkdocs_terok.ref_pages import RefPagesConfig, generate_ref_pages

nav = mkdocs_gen_files.Nav()
config = RefPagesConfig(src_dir=Path(__file__).parent.parent / "src")


def write_file(path: str, content: str) -> None:
    """Write a generated file via mkdocs-gen-files."""
    with mkdocs_gen_files.open(path, "w") as f:
        f.write(content)


entries = generate_ref_pages(
    config, write_file=write_file, set_edit_path=mkdocs_gen_files.set_edit_path
)
for parts, doc_path in entries:
    nav[parts] = str(Path(doc_path).relative_to(config.output_prefix))

with mkdocs_gen_files.open("reference/SUMMARY.md", "w") as f:
    f.writelines(nav.build_literate_nav())
