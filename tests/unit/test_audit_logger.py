# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the AuditLogger class."""

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from terok_shield import state
from terok_shield.audit import AuditLogger

from ..testfs import NONEXISTENT_DIR, TEST_SUBDIR_NAME
from ..testnet import TEST_IP1
from .helpers import write_jsonl


def _read_entry(path: Path) -> dict[str, str]:
    """Read a single JSONL entry from *path*."""
    return json.loads(path.read_text().strip())


@pytest.fixture
def make_logger(tmp_path: Path) -> Callable[..., AuditLogger]:
    """Create an AuditLogger rooted under the test temp directory."""

    def _make_logger(*, audit_path: Path | None = None, enabled: bool = True) -> AuditLogger:
        return AuditLogger(audit_path=audit_path or state.audit_path(tmp_path), enabled=enabled)

    return _make_logger


@pytest.mark.parametrize(
    "enabled", [pytest.param(False, id="disabled"), pytest.param(True, id="default-enabled")]
)
def test_audit_logger_init(make_logger: Callable[..., AuditLogger], enabled: bool) -> None:
    """Construction preserves the enabled flag."""
    logger = make_logger(enabled=enabled)
    assert logger.enabled is enabled


def test_audit_logger_enabled_toggle(make_logger: Callable[..., AuditLogger]) -> None:
    """The enabled property can be toggled after construction."""
    logger = make_logger(enabled=True)
    logger.enabled = False
    assert not logger.enabled
    logger.enabled = True
    assert logger.enabled


def test_log_event_writes_jsonl(make_logger: Callable[..., AuditLogger], tmp_path: Path) -> None:
    """log_event() appends a JSONL audit record."""
    path = state.audit_path(tmp_path)
    logger = make_logger(audit_path=path)
    logger.log_event("test-ctr", "setup", detail="test")
    entry = _read_entry(path)
    assert entry["container"] == "test-ctr"
    assert entry["action"] == "setup"
    assert entry["detail"] == "test"
    assert "ts" in entry


def test_log_event_omits_missing_optional_fields(
    make_logger: Callable[..., AuditLogger], tmp_path: Path
) -> None:
    """Optional event fields are only included when provided."""
    path = state.audit_path(tmp_path)
    logger = make_logger(audit_path=path)
    logger.log_event("test-ctr", "denied", dest=TEST_IP1)
    entry = _read_entry(path)
    assert entry["dest"] == TEST_IP1
    assert "detail" not in entry


def test_log_event_skips_writes_when_disabled(
    make_logger: Callable[..., AuditLogger], tmp_path: Path
) -> None:
    """Disabled loggers do not create or append log files."""
    path = state.audit_path(tmp_path)
    make_logger(audit_path=path, enabled=False).log_event("test-ctr", "setup", detail="test")
    assert not path.exists()


def test_log_event_ignores_write_errors(
    monkeypatch: pytest.MonkeyPatch,
    make_logger: Callable[..., AuditLogger],
    tmp_path: Path,
) -> None:
    """Write failures are swallowed to avoid breaking protected workloads."""

    def _fail_open(_self: Path, *args: object, **kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(Path, "open", _fail_open)
    make_logger(audit_path=state.audit_path(tmp_path)).log_event("test-ctr", "setup")


def test_log_event_appends_multiple_events(
    make_logger: Callable[..., AuditLogger], tmp_path: Path
) -> None:
    """Multiple events append to the same file."""
    path = state.audit_path(tmp_path)
    logger = make_logger(audit_path=path)
    logger.log_event("test-ctr", "setup")
    logger.log_event("test-ctr", "allowed", dest=TEST_IP1)
    assert len(path.read_text().strip().splitlines()) == 2


def test_log_event_creates_parent_dirs(
    make_logger: Callable[..., AuditLogger], tmp_path: Path
) -> None:
    """log_event() creates missing parent directories as needed."""
    path = state.audit_path(tmp_path / TEST_SUBDIR_NAME)
    make_logger(audit_path=path).log_event("test-ctr", "setup")
    assert path.exists()


@pytest.mark.parametrize(
    ("entries", "n", "expected_actions"),
    [
        pytest.param(
            [{"action": f"event-{index}"} for index in range(5)],
            3,
            ["event-2", "event-3", "event-4"],
            id="last-n",
        ),
        pytest.param(
            ['{"action":"good"}', "not-json", '{"action":"also-good"}'],
            50,
            ["good", "also-good"],
            id="skips-corrupt-lines",
        ),
        pytest.param([{"action": "a"}], 0, [], id="n-zero"),
    ],
)
def test_tail_log_reads_recent_entries(
    make_logger: Callable[..., AuditLogger],
    tmp_path: Path,
    entries: list[dict[str, str] | str],
    n: int,
    expected_actions: list[str],
) -> None:
    """tail_log() returns recent valid JSON entries in order."""
    path = write_jsonl(state.audit_path(tmp_path), entries)
    result = list(make_logger(audit_path=path).tail_log(n=n))
    assert [entry["action"] for entry in result] == expected_actions


def test_tail_log_returns_empty_for_missing_file() -> None:
    """tail_log() yields nothing when the audit file does not exist."""
    assert list(AuditLogger(audit_path=state.audit_path(NONEXISTENT_DIR)).tail_log()) == []
