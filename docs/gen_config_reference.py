# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Generate config reference from the ShieldFileConfig Pydantic model.

Runs during ``mkdocs build`` via mkdocs-gen-files.  The Pydantic model
is the single source of truth -- if a field exists in the schema, it
appears in the docs automatically.
"""

from __future__ import annotations

import io

import mkdocs_gen_files
from mkdocs_terok.config_reference import render_model_tables, render_yaml_example

from terok_shield.config_file import ShieldFileConfig


def _generate() -> str:
    buf = io.StringIO()
    buf.write("# Config Reference\n\n")
    buf.write(
        "Auto-generated from the "
        "[`ShieldFileConfig`][terok_shield.config_file.ShieldFileConfig] model.  "
        "Unknown keys are rejected at load time (`extra='forbid'`).\n\n"
    )

    buf.write(render_model_tables(ShieldFileConfig))

    buf.write("## Example\n\n")
    buf.write('```yaml title="config.yml"\n')
    buf.write(render_yaml_example(ShieldFileConfig))
    buf.write("```\n")

    return buf.getvalue()


with mkdocs_gen_files.open("config-reference.md", "w") as f:
    f.write(_generate())
