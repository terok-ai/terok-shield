# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Generate a narrative overview page from module and class docstrings.

Runs during ``mkdocs build`` via mkdocs-gen-files.  Walks the source tree
in tach layer order (common → core → support → cli), extracts module and
class docstrings via AST (no imports), and renders them as a single page.

The result is a table-of-contents-with-docstrings: if the first lines
of each module and class read as a coherent story, the codebase is
following the Narrative Code manifesto.
"""

from __future__ import annotations

import ast
import io
from pathlib import Path

import mkdocs_gen_files

_SRC = Path("src/terok_shield")

# Layer order from tach.toml — bottom-up, foundation first.
_LAYERS: list[tuple[str, list[Path]]] = [
    (
        "Common",
        [
            _SRC / "common" / "config.py",
            _SRC / "common" / "validation.py",
            _SRC / "common" / "util.py",
            _SRC / "common" / "podman_info.py",
        ],
    ),
    (
        "Core",
        [
            _SRC / "core" / "nft_constants.py",
            _SRC / "core" / "nft.py",
            _SRC / "core" / "state.py",
            _SRC / "core" / "run.py",
            _SRC / "core" / "dns.py",
            _SRC / "core" / "dnsmasq.py",
            _SRC / "core" / "hook_install.py",
            _SRC / "core" / "mode_hook.py",
        ],
    ),
    (
        "Library",
        [
            _SRC / "lib" / "audit.py",
            _SRC / "lib" / "profiles.py",
            _SRC / "lib" / "watchers" / "_event.py",
            _SRC / "lib" / "watchers" / "dns_log.py",
            _SRC / "lib" / "watchers" / "audit_log.py",
            _SRC / "lib" / "watchers" / "nflog.py",
            _SRC / "lib" / "watchers" / "domain_cache.py",
            _SRC / "lib" / "dbus_bridge.py",
        ],
    ),
    (
        "CLI",
        [
            _SRC / "cli" / "registry.py",
            _SRC / "cli" / "main.py",
            _SRC / "cli" / "interactive.py",
            _SRC / "cli" / "dbus_bridge.py",
        ],
    ),
]


def _module_label(path: Path) -> str:
    """Derive a dotted module label from a file path."""
    rel = path.relative_to(_SRC)
    parts = list(rel.with_suffix("").parts)
    return "terok_shield." + ".".join(parts)


def _extract(path: Path) -> tuple[str, list[tuple[str, str]]]:
    """Extract module docstring and class docstrings via AST.

    Returns (module_doc, [(class_name, class_doc), ...]).
    """
    try:
        tree = ast.parse(path.read_text())
    except SyntaxError:
        return ("", [])

    module_doc = ast.get_docstring(tree) or ""

    classes: list[tuple[str, str]] = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ClassDef):
            doc = ast.get_docstring(node) or ""
            classes.append((node.name, doc))

    return (module_doc, classes)


def _render(out: io.StringIO) -> None:
    """Render the narrative overview to a StringIO buffer."""
    out.write("# Narrative Overview\n\n")
    out.write(
        "Module and class docstrings in layer order.  If these read as a\n"
        "coherent story top-to-bottom, the codebase is telling its own spec.\n\n"
        "*Generated from source docstrings during build.*\n\n"
    )

    for layer_name, paths in _LAYERS:
        out.write(f"---\n\n## {layer_name}\n\n")

        for path in paths:
            if not path.is_file():
                continue
            label = _module_label(path)
            module_doc, classes = _extract(path)
            if not module_doc and not classes:
                continue

            out.write(f"### `{label}`\n\n")
            if module_doc:
                out.write(f"{module_doc}\n\n")

            for cls_name, cls_doc in classes:
                if not cls_doc:
                    continue
                first_line = cls_doc.split("\n", 1)[0]
                rest = cls_doc.split("\n", 1)[1].strip() if "\n" in cls_doc else ""
                out.write(f"**{cls_name}** — {first_line}\n")
                if rest:
                    # Indent continuation as a blockquote for scannability.
                    for line in rest.splitlines():
                        out.write(f"> {line}\n" if line.strip() else ">\n")
                out.write("\n")


buf = io.StringIO()
_render(buf)
with mkdocs_gen_files.open("narrative-overview.md", "w") as f:
    f.write(buf.getvalue())
