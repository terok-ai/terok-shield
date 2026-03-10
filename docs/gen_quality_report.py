# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Generate a code quality report page for MkDocs.

Runs during ``mkdocs build`` via the mkdocs-gen-files plugin.
Executes complexipy, vulture, tach, and docstr-coverage, embeds Codecov
coverage data, then assembles the results into a single Markdown page
with a Mermaid dependency diagram.
"""

import json
import subprocess
import sys
import tomllib
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


def _scc_file_totals(path: Path) -> dict[str, int]:
    """Run scc on a single file and return its totals."""
    result = _run("scc", "--format", "json", "--no-cocomo", str(path))
    if result.returncode != 0 or not result.stdout.strip():
        return dict(_EMPTY_TOTALS)
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return dict(_EMPTY_TOTALS)
    for lang in data:
        if lang.get("Name", "") in ("Total", "SUM"):
            continue
        return {
            "lines": lang.get("Lines", 0),
            "code": lang.get("Code", 0),
            "comment": lang.get("Comment", 0),
            "blank": lang.get("Blank", 0),
            "files": 1,
        }
    return dict(_EMPTY_TOTALS)


def _walk_source_tree(base: Path, lines: list[str], prefix: str = "") -> None:
    """Recursively collect LoC table rows for files and subdirs under *base*."""
    n = _nbsp_num
    entries = sorted(base.iterdir(), key=lambda p: (p.is_file(), p.name))
    for entry in entries:
        if entry.name == "__pycache__":
            continue
        if entry.is_dir():
            t = _scc_totals(entry)
            if t["code"] == 0 and t["lines"] == 0:
                continue
            label = f"{prefix}{entry.name}/"
            lines.append(
                f"| `{label}` | {t['files']} | {n(t['code'])} | {n(t['comment'])} | {n(t['blank'])} |\n"
            )
            _walk_source_tree(entry, lines, label)
        elif entry.suffix == ".py":
            t = _scc_file_totals(entry)
            if t["code"] == 0:
                continue
            lines.append(
                f"| `{prefix}{entry.name}` | — | {n(t['code'])} | {n(t['comment'])} | {n(t['blank'])} |\n"
            )


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

    lines = [
        "| | Files | Code | Comment | Blank | Total |\n",
        "|---|---:|---:|---:|---:|---:|\n",
        f"| Source | {src_totals['files']} | {n(src_totals['code'])} | {n(src_totals['comment'])} | {n(src_totals['blank'])} | {n(src_totals['lines'])} |\n",
        f"| Tests | {tests_totals['files']} | {n(tests_totals['code'])} | {n(tests_totals['comment'])} | {n(tests_totals['blank'])} | {n(tests_totals['lines'])} |\n",
        "\n",
        f"- **Comment/code ratio:** {comment_ratio}\n",
        f"- **Test/source ratio:** {test_ratio}\n",
        "\n",
    ]

    detail_lines: list[str] = []
    _walk_source_tree(SRC, detail_lines)

    lines.append('??? info "Source by module (click to expand)"\n\n')
    lines.append("    | Module | Files | Code | Comment | Blank |\n")
    lines.append("    |---|---:|---:|---:|---:|\n")
    for dl in detail_lines:
        lines.append(f"    {dl}")
    lines.append("\n")

    return "".join(lines)


def _load_tach_toml() -> tuple[str, dict, list[dict]] | None:
    """Load and parse tach.toml, returning (raw_text, parsed_data, modules) or None."""
    tach_path = ROOT / "tach.toml"
    if not tach_path.is_file():
        return None
    raw = tach_path.read_text(encoding="utf-8")
    try:
        data = tomllib.loads(raw)
    except Exception:
        return None
    modules = data.get("modules", [])
    return (raw, data, modules)


def _section_dependency_diagram() -> str:
    """Generate module dependency diagram from tach."""
    result = _run(sys.executable, "-m", "tach", "show", "--mermaid", "-o", "-")
    if result.returncode != 0:
        output = (result.stdout + result.stderr).strip() or "no output"
        return (
            f"!!! warning\n    tach show failed (exit {result.returncode}).\n\n```\n{output}\n```\n"
        )
    output = result.stdout.strip()
    if not output:
        return "!!! warning\n    tach show --mermaid produced no output.\n"
    # Render the mermaid graph directly (small enough to skip coarsening)
    return f"```mermaid\n{output}\n```\n"


def _section_boundary_check() -> str:
    """Run tach check and report results."""
    loaded = _load_tach_toml()
    mod_count = 0
    dep_count = 0
    if loaded:
        _raw, _data, modules = loaded
        mod_count = len(modules)
        dep_count = sum(len(m.get("depends_on", [])) for m in modules)

    result = _run(sys.executable, "-m", "tach", "check")
    output = (result.stdout + result.stderr).strip()
    if result.returncode == 0:
        stats = f"{mod_count} modules, {dep_count} dependency edges — " if mod_count else ""
        return f"{stats}all boundaries validated.\n"
    return f"```\n{output}\n```\n"


def _section_dependency_report() -> str:
    """Generate a module dependency summary table from tach.toml."""
    loaded = _load_tach_toml()
    if not loaded:
        return "!!! warning\n    `tach.toml` not found or unparseable — skipping module summary.\n"
    raw, _data, modules = loaded
    if not modules:
        return "No modules defined in `tach.toml`.\n"

    # Extract comments above each [[modules]] block as descriptions.
    descriptions: list[str] = []
    raw_lines = raw.splitlines()
    for i, line in enumerate(raw_lines):
        if line.strip() == "[[modules]]":
            desc = (
                raw_lines[i - 1].lstrip("# ").strip()
                if i > 0 and raw_lines[i - 1].startswith("#")
                else ""
            )
            descriptions.append(desc)

    lines = [
        f'??? info "{len(modules)} modules (click to expand)"\n\n',
        "    | Module | Deps | Description |\n",
        "    |---|---:|---|\n",
    ]
    for idx, mod in enumerate(modules):
        path = mod.get("path", "?")
        deps = len(mod.get("depends_on", []))
        desc = descriptions[idx] if idx < len(descriptions) else ""
        lines.append(f"    | `{path}` | {deps} | {desc} |\n")
    lines.append("\n")
    return "".join(lines)


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
    scores = [int(f["complexity"]) for f in functions]
    over = [f for f in functions if f["complexity"] > COMPLEXITY_THRESHOLD]
    max_c = scores[0] if scores else 0
    avg_c = sum(scores) / total if total else 0
    sorted_scores = sorted(scores)
    if total % 2 == 1:
        median_c = sorted_scores[total // 2]
    else:
        median_c = (sorted_scores[total // 2 - 1] + sorted_scores[total // 2]) / 2 if total else 0
    pct = (total - len(over)) / total * 100 if total else 0

    lines = [
        f"- **Functions analyzed:** {total}\n",
        f"- **Median complexity:** {median_c} · **Average:** {avg_c:.1f} · **Max:** {max_c}\n",
        f"- **Within threshold ({COMPLEXITY_THRESHOLD}):** {pct:.0f}%"
        f" ({total - len(over)}/{total})\n",
        "\n",
    ]

    # Histogram with bins of 3, capped at 26+.
    buckets = [(0, 3), (4, 6), (7, 9), (10, 12), (13, 15), (16, 18), (19, 21), (22, 25), (26, 999)]
    bar_max = 30
    bucket_counts = []
    for lo, hi in buckets:
        count = sum(1 for s in scores if lo <= s <= hi)
        bucket_counts.append((lo, hi, count))

    peak = max(c for _, _, c in bucket_counts) if bucket_counts else 1

    lines.append("```\n")
    for lo, hi, count in bucket_counts:
        if count == 0 and lo > max(scores, default=0):
            continue
        label = f"{lo:>3d}–{hi:>3d}" if hi < 999 else f"{lo:>3d}+   "
        bar_len = round(count / peak * bar_max) if peak else 0
        bar = "█" * bar_len
        pct_bin = count / total * 100 if total else 0
        marker = " ◄ threshold" if lo <= COMPLEXITY_THRESHOLD <= hi else ""
        lines.append(f"  {label} │ {bar:<{bar_max}} {count:>3d} ({pct_bin:4.1f}%){marker}\n")
    lines.append("```\n\n")

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


_CODECOV_REPO = "terok-ai/terok-shield"
_CODECOV_TOKEN = "D74Q7lvnIF"
_TREEMAP_LOCAL = ROOT / "docs" / "assets" / "coverage_treemap.svg"


def _section_test_coverage() -> str:
    """Generate test coverage section with Codecov badge and treemap."""
    base = f"https://codecov.io/gh/{_CODECOV_REPO}"

    if _TREEMAP_LOCAL.is_file():
        svg = _TREEMAP_LOCAL.read_text(encoding="utf-8")
        # Write the SVG as a sibling of quality_report/index.html so the
        # relative reference is just the filename — no ../ gymnastics.
        with mkdocs_gen_files.open("quality_report/coverage_treemap.svg", "w") as f:
            f.write(svg)
        src = "coverage_treemap.svg"
    else:
        src = f"{base}/graphs/tree.svg?token={_CODECOV_TOKEN}"
    # <object> loads the SVG as its own document — no markdown mangling,
    # and native <title> tooltips work on hover.
    treemap = f'<object id="codecov-treemap-img" type="image/svg+xml" data="{src}"></object>\n\n'

    return (
        f"Coverage is collected from unit tests in CI and uploaded to "
        f"[Codecov]({base}).\n\n"
        "### Coverage Treemap\n\n"
        + treemap
        + "Each rectangle represents a source file. Size is proportional to the "
        "number of lines; colour shows the coverage percentage (green = high, "
        "red = low).\n"
    )


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
            "\n## Architecture\n\n",
            "### Module Dependency Graph\n\n",
            _section_dependency_diagram(),
            "\n### Module Boundaries\n\n",
            _section_boundary_check(),
            "\n### Module Summary\n\n",
            _section_dependency_report(),
            "\n## Test Coverage\n\n",
            _section_test_coverage(),
            "\n## Cognitive Complexity\n\n",
            f"Threshold: **{COMPLEXITY_THRESHOLD}**\n\n",
            _section_complexity(),
            "\n## Dead Code Analysis\n\n",
            _section_dead_code(),
            "\n## Docstring Coverage\n\n",
            _section_docstring_coverage(),
            "\n---\n\n*Generated by scc, Codecov, complexipy, vulture, tach, and docstr-coverage.*\n",
        ]
    )


report = generate_report()
with mkdocs_gen_files.open("quality_report.md", "w") as f:
    f.write(report)
