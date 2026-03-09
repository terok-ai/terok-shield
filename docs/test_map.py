#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Generate a Markdown test map from pytest collection.

Runs ``pytest --collect-only -qq`` on ``tests/integration/`` and groups
the collected test IDs by directory, producing a Markdown table.

Can be used standalone (``python docs/test_map.py``) or as a mkdocs
gen-files script (imported by ``docs/gen_test_map.py``).
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INTEGRATION_DIR = ROOT / "tests" / "integration"
_VENV_BIN = Path(sys.executable).parent

_DIR_ORDER = [
    "setup",
    "launch",
    "blocking",
    "allow_deny",
    "dns",
    "observability",
    "safety",
    "cli",
]


def collect_tests() -> list[str]:
    """Run pytest --collect-only and return the list of test node IDs.

    Raises:
        RuntimeError: If pytest collection fails (non-zero exit code).
    """
    result = subprocess.run(
        [
            str(_VENV_BIN / "pytest"),
            "--collect-only",
            "-qq",
            "-p",
            "no:tach",
            str(INTEGRATION_DIR),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=60,
    )
    if result.returncode != 0:
        msg = (result.stdout + result.stderr).strip()
        raise RuntimeError(f"pytest collection failed (exit {result.returncode}):\n{msg}")
    lines = result.stdout.strip().splitlines()
    # Filter to actual test IDs (contain ::)
    return [line.strip() for line in lines if "::" in line]


def _extract_markers(test_file: Path) -> dict[str, list[str]]:
    """Extract pytest markers from a test file, keyed by class or module.

    Buffers decorators until the next ``class`` declaration so markers
    above a class are correctly assigned to that class, not the previous one.

    Returns a mapping of ``ClassName`` (or ``_module``) to a list of
    marker names found on that scope.
    """
    markers: dict[str, list[str]] = defaultdict(list)
    current_class = "_module"
    pending: list[str] = []
    if not test_file.is_file():
        return markers
    for line in test_file.read_text().splitlines():
        marker_match = re.match(r"^@pytest\.mark\.(\w+)", line.strip())
        if marker_match:
            pending.append(marker_match.group(1))
            continue
        class_match = re.match(r"^class (\w+)", line)
        if class_match:
            current_class = class_match.group(1)
            markers[current_class].extend(pending)
            pending.clear()
        elif pending and not line.strip().startswith("@"):
            # Non-decorator, non-class line: flush pending to current scope
            markers[current_class].extend(pending)
            pending.clear()
    # Flush any remaining pending markers
    if pending:
        markers[current_class].extend(pending)
    return markers


def _ci_tier(env_markers: set[str]) -> str:
    """Derive the CI tier from a set of environment markers.

    Returns the most restrictive tier (podman > network > host).
    """
    if "needs_podman" in env_markers:
        return "podman"
    if "needs_internet" in env_markers:
        return "network"
    return "host"


def _group_by_directory(test_ids: list[str]) -> dict[str, list[str]]:
    """Group test IDs by their integration test subdirectory."""
    groups: dict[str, list[str]] = defaultdict(list)
    for tid in test_ids:
        file_path = tid.split("::")[0]
        rel = file_path.replace("tests/integration/", "")
        subdir = rel.split("/")[0] if "/" in rel else "(root)"
        groups[subdir].append(tid)
    return groups


def _sorted_dirs(groups: dict[str, list[str]]) -> list[str]:
    """Return directory names in canonical order, unknown dirs appended alphabetically."""
    known = [d for d in _DIR_ORDER if d in groups]
    return known + sorted(d for d in groups if d not in _DIR_ORDER)


def _dir_description(subdir: str) -> str:
    """Read the README.md description for a test subdirectory."""
    readme = INTEGRATION_DIR / subdir / "README.md"
    if not readme.is_file():
        return ""
    lines = readme.read_text().strip().splitlines()
    desc_lines = [ln.strip() for ln in lines[1:] if ln.strip()]
    return " ".join(desc_lines)


def _test_row(tid: str, marker_cache: dict[str, dict[str, list[str]]]) -> str:
    """Format a single test ID as a Markdown table row."""
    parts = tid.split("::")
    file_path = parts[0]
    class_name = parts[1] if len(parts) > 2 else ""
    test_name = parts[-1]

    if file_path not in marker_cache:
        marker_cache[file_path] = _extract_markers(ROOT / file_path)
    file_markers = marker_cache[file_path]

    all_markers = set(file_markers.get("_module", []))
    if class_name:
        all_markers.update(file_markers.get(class_name, []))
    env_markers = sorted(m for m in all_markers if m.startswith("needs_"))
    marker_str = ", ".join(f"`{m}`" for m in env_markers) if env_markers else ""
    tier = _ci_tier(all_markers)
    return f"| `{test_name}` | `{class_name}` | {tier} | {marker_str} |"


def _dir_section(subdir: str, tids: list[str]) -> list[str]:
    """Generate the Markdown section for one test directory."""
    lines = [f"## `{subdir}/`\n\n"]
    desc = _dir_description(subdir)
    if desc:
        lines.append(f"{desc}\n\n")
    lines.append("| Test | Class | CI Tier | Markers |\n")
    lines.append("|---|---|---|---|\n")
    marker_cache: dict[str, dict[str, list[str]]] = {}
    for tid in sorted(tids):
        lines.append(_test_row(tid, marker_cache) + "\n")
    lines.append("\n")
    return lines


def generate_test_map(test_ids: list[str] | None = None) -> str:
    """Generate a Markdown test map grouped by directory.

    Args:
        test_ids: Optional pre-collected test IDs. If ``None``, runs
            ``pytest --collect-only`` to collect them.

    Returns:
        Markdown string with the test map.
    """
    if test_ids is None:
        test_ids = collect_tests()

    groups = _group_by_directory(test_ids)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Integration Test Map\n\n",
        f"*Generated: {now}*\n\n",
        f"**{len(test_ids)} tests** across **{len(groups)} directories**\n\n",
    ]
    for subdir in _sorted_dirs(groups):
        lines.extend(_dir_section(subdir, groups[subdir]))
    return "".join(lines)


if __name__ == "__main__":
    output = generate_test_map()
    docs_dir = ROOT / "docs"
    if docs_dir.is_dir():
        out_path = docs_dir / "test_map.md"
        out_path.write_text(output, encoding="utf-8")
        print(f"Wrote {out_path}")
    else:
        print(output)
