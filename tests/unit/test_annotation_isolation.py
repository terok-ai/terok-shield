# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""A ``TYPE_CHECKING`` name in a live annotation must be quoted.

Python 3.14 evaluates annotations lazily (PEP 649), so a name imported only
under ``if TYPE_CHECKING:`` can sit unquoted in a signature and never raise on a
3.14 developer box.  On 3.12 — the floor this package supports, and what CI runs
— the same line raises ``NameError`` the moment the module is imported.  The
gap is invisible to every test that passes locally, which is exactly why it is
worth an AST check rather than a review habit.

Modules carrying ``from __future__ import annotations`` are exempt: there every
annotation is a string already.
"""

import ast
from pathlib import Path

import pytest

_PACKAGE = Path(__file__).parents[2] / "src" / "terok_shield"


def _type_checking_names(tree: ast.Module) -> set[str]:
    """Names this module binds only inside ``if TYPE_CHECKING:``."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        guarded = (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
            isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
        )
        if not guarded:
            continue
        for imported in ast.walk(node):
            if isinstance(imported, ast.ImportFrom | ast.Import):
                names.update(alias.asname or alias.name.split(".")[0] for alias in imported.names)
    return names


def _live_annotations(tree: ast.Module) -> list[tuple[int, ast.expr]]:
    """Annotations evaluated at import time, with the line they sit on.

    A string annotation is already deferred, so only expressions are returned.
    """
    live: list[tuple[int, ast.expr]] = []
    for node in ast.walk(tree):
        annotations: list[ast.expr | None] = []
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            args = node.args
            annotations = [node.returns, *(a.annotation for a in args.args)]
            annotations += [a.annotation for a in args.kwonlyargs]
            annotations += [a.annotation for a in args.posonlyargs]
        elif isinstance(node, ast.AnnAssign):
            annotations = [node.annotation]
        live += [
            (annotation.lineno, annotation)
            for annotation in annotations
            if annotation is not None and not isinstance(annotation, ast.Constant)
        ]
    return live


@pytest.mark.parametrize(
    "source_file",
    sorted(_PACKAGE.rglob("*.py")),
    ids=lambda path: str(path.relative_to(_PACKAGE)),
)
def test_type_checking_names_are_not_evaluated_at_import(source_file: Path) -> None:
    """No module evaluates a ``TYPE_CHECKING``-only name while it is being imported."""
    tree = ast.parse(source_file.read_text())
    if any(isinstance(node, ast.ImportFrom) and node.module == "__future__" for node in tree.body):
        return

    deferred = _type_checking_names(tree)
    if not deferred:
        return

    offenders = [
        (lineno, name.id)
        for lineno, annotation in _live_annotations(tree)
        for name in ast.walk(annotation)
        if isinstance(name, ast.Name) and name.id in deferred
    ]

    assert not offenders, (
        f"{source_file.relative_to(_PACKAGE)} evaluates TYPE_CHECKING-only names at import "
        f"time: {offenders}. Quote the annotation, or add `from __future__ import annotations`."
    )
