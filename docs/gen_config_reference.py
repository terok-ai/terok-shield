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

from terok_shield.config import ShieldFileConfig

_FIELD_DOCS: dict[str, str] = {
    "mode": "Firewall mode. ``auto`` selects the best available; ``hook`` forces OCI hook mode.",
    "default_profiles": "Allowlist profiles applied when no explicit list is given.",
    "loopback_ports": "TCP ports forwarded to host loopback via pasta ``-T``.",
    "audit.enabled": "Write per-container JSONL audit logs.",
}


def _generate() -> str:
    buf = io.StringIO()
    buf.write("# Config Reference\n\n")
    buf.write(
        "Auto-generated from the "
        "[`ShieldFileConfig`][terok_shield.config.ShieldFileConfig] model.  "
        "Unknown keys are rejected at load time (`extra='forbid'`).\n\n"
    )

    buf.write(render_model_tables(ShieldFileConfig, field_docs=_FIELD_DOCS))

    buf.write("## Example\n\n")
    buf.write('```yaml title="config.yml"\n')
    buf.write(render_yaml_example(ShieldFileConfig, field_docs=_FIELD_DOCS))
    buf.write("```\n")

    return buf.getvalue()


with mkdocs_gen_files.open("config-reference.md", "w") as f:
    f.write(_generate())
