# SPDX-FileCopyrightText: 2026 terok contributors
# SPDX-License-Identifier: Apache-2.0

"""Generate a code quality report page for MkDocs.

Runs during ``mkdocs build`` via the mkdocs-gen-files plugin.
Executes complexipy, vulture, and docstr-coverage, then assembles
the results into a single Markdown page.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import mkdocs_gen_files

ROOT = Path(__file__).parent.parent
SRC = ROOT / "src" / "terok_shield"
COMPLEXITY_THRESHOLD = 15
_VENV_BIN = Path(sys.executable).parent


def _run(
    *cmd: str, cwd: Path = ROOT, timeout_seconds: float = 120.0
) -> subprocess.CompletedProcess[str]:
    """Run a command and return the result (never raises on failure)."""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="timed out")
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr=str(exc))


def _nbsp_num(n: int) -> str:
    """Format an integer with non-breaking spaces as thousand separators."""
    s = f"{n:,}"
    return s.replace(",", "\u00a0")


_EMPTY_TOTALS: dict[str, int] = {"lines": 0, "code": 0, "comment": 0, "blank": 0, "files": 0}


def _scc_totals(path: Path) -> dict[str, int]:
    """Run scc on *path* and return aggregated totals across all languages."""
    result = _run("scc", "--format", "json", "--no-cocomo", str(path))
    if result.returncode != 0 or not result.stdout.strip():
        return dict(_EMPTY_TOTALS)
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return dict(_EMPTY_TOTALS)
    totals = dict(_EMPTY_TOTALS)
    for lang in data:
        if lang.get("Name", "") in ("Total", "SUM"):
            continue
        totals["lines"] += lang.get("Lines", 0)
        totals["code"] += lang.get("Code", 0)
        totals["comment"] += lang.get("Comment", 0)
        totals["blank"] += lang.get("Blank", 0)
        totals["files"] += lang.get("Count", 0)
    return totals


def _section_loc() -> str:
    """Generate lines-of-code statistics using scc."""
    import shutil

    if not shutil.which("scc"):
        return "!!! warning\n    `scc` not found — skipping LoC report.\n"

    n = _nbsp_num
    src_totals = _scc_totals(SRC)
    tests_totals = _scc_totals(ROOT / "tests")

    comment_ratio = (
        f"{src_totals['comment'] / src_totals['code'] * 100:.0f}%" if src_totals["code"] else "—"
    )
    test_ratio = f"{tests_totals['code'] / src_totals['code']:.1%}" if src_totals["code"] else "—"

    return (
        f"| | Files | Code | Comment | Blank | Total |\n"
        f"|---|---:|---:|---:|---:|---:|\n"
        f"| Source | {src_totals['files']} | {n(src_totals['code'])} | {n(src_totals['comment'])} | {n(src_totals['blank'])} | {n(src_totals['lines'])} |\n"
        f"| Tests | {tests_totals['files']} | {n(tests_totals['code'])} | {n(tests_totals['comment'])} | {n(tests_totals['blank'])} | {n(tests_totals['lines'])} |\n"
        f"\n"
        f"- **Comment/code ratio:** {comment_ratio}\n"
        f"- **Test/source ratio:** {test_ratio}\n"
    )


def _section_complexity() -> str:
    """Generate cognitive complexity section from complexipy."""
    run_result = _run(str(_VENV_BIN / "complexipy"), str(SRC), "--ignore-complexity")
    if run_result.returncode != 0:
        output = (run_result.stdout + run_result.stderr).strip()
        return f"!!! warning\n    complexipy failed.\n\n```\n{output}\n```\n"

    cache_dir = ROOT / ".complexipy_cache"
    cache_files = sorted(cache_dir.glob("*.json")) if cache_dir.is_dir() else []
    if not cache_files:
        return "!!! warning\n    complexipy cache not found.\n"

    latest_cache = max(cache_files, key=lambda p: p.stat().st_mtime)
    try:
        data = json.loads(latest_cache.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return "!!! warning\n    complexipy cache is invalid JSON.\n"

    functions = [
        f
        for f in data.get("functions", [])
        if isinstance(f, dict) and isinstance(f.get("complexity"), (int, float))
    ]
    if not functions:
        return "No functions found.\n"

    functions.sort(key=lambda f: f["complexity"], reverse=True)
    total = len(functions)
    over = [f for f in functions if f["complexity"] > COMPLEXITY_THRESHOLD]
    pct = (total - len(over)) / total * 100 if total else 0

    lines = [
        f"- **Functions analyzed:** {total}\n",
        f"- **Within threshold ({COMPLEXITY_THRESHOLD}):** {pct:.0f}% ({total - len(over)}/{total})\n\n",
    ]

    if over:
        lines.append(f"**{len(over)} functions exceeding threshold:**\n\n")
        lines.append("| Complexity | Function | File |\n|---:|---|---|\n")
        for f in over:
            lines.append(f"| {f['complexity']} | `{f['function_name']}` | `{f['path']}` |\n")
    else:
        lines.append(f"All functions within threshold of {COMPLEXITY_THRESHOLD}.\n")

    return "".join(lines)


def _section_dead_code() -> str:
    """Generate dead code section from vulture."""
    result = _run(
        sys.executable,
        "-m",
        "vulture",
        str(SRC),
        str(ROOT / "vulture_whitelist.py"),
        "--min-confidence",
        "80",
    )
    output = (result.stdout + result.stderr).strip()
    if not output:
        return "No dead code found at 80% confidence threshold.\n"

    lines = ["| Confidence | Location | Issue |\n", "|---:|---|---|\n"]
    parsed = 0
    for line in output.splitlines():
        if "% confidence)" in line:
            parts = line.rsplit("(", 1)
            location_msg = parts[0].strip()
            confidence = parts[1].rstrip(")").strip()
            loc_parts = location_msg.split(": ", 1)
            location = loc_parts[0] if loc_parts else location_msg
            message = loc_parts[1] if len(loc_parts) > 1 else ""
            lines.append(f"| {confidence} | `{location}` | {message} |\n")
            parsed += 1
    if parsed == 0 and result.returncode != 0:
        return f"!!! warning\n    vulture failed.\n\n```text\n{output}\n```\n"
    return "".join(lines)


def _section_docstring_coverage() -> str:
    """Generate docstring coverage section."""
    result = _run(str(_VENV_BIN / "docstr-coverage"), str(SRC), "--fail-under=0")
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0:
        return f"!!! warning\n    docstr-coverage failed.\n\n```text\n{output}\n```\n"
    summary = []
    for line in output.splitlines():
        if any(kw in line for kw in ("Needed:", "Total coverage:", "Grade:")):
            summary.append(f"- {line.strip()}\n")
    return "".join(summary) if summary else f"```text\n{output}\n```\n"


def generate_report() -> str:
    """Assemble the full quality report."""
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return "".join(
        [
            "# Code Quality Report\n\n",
            f"*Generated: {now}*\n\n---\n\n",
            "## Lines of Code\n\n",
            _section_loc(),
            "\n## Cognitive Complexity\n\n",
            f"Threshold: **{COMPLEXITY_THRESHOLD}**\n\n",
            _section_complexity(),
            "\n## Dead Code Analysis\n\n",
            _section_dead_code(),
            "\n## Docstring Coverage\n\n",
            _section_docstring_coverage(),
            "\n---\n\n*Generated by scc, complexipy, vulture, and docstr-coverage.*\n",
        ]
    )


report = generate_report()
with mkdocs_gen_files.open("quality-report.md", "w") as f:
    f.write(report)
