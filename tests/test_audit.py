from __future__ import annotations

import json
from pathlib import Path

from permission_guard import AuditEntry, AuditLog


def entry(**overrides) -> AuditEntry:
    base = dict(
        timestamp="2026-01-01T00:00:00+00:00",
        action="read_file",
        target="a.txt",
        decision="allow",
        reason="test",
        approver="policy",
        result="ok",
    )
    base.update(overrides)
    return AuditEntry(**base)


def test_append_writes_one_json_line(tmp_path: Path):
    log = AuditLog(tmp_path / "log.jsonl")
    log.append(entry())
    lines = (tmp_path / "log.jsonl").read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["action"] == "read_file"


def test_append_is_append_only(tmp_path: Path):
    log = AuditLog(tmp_path / "log.jsonl")
    log.append(entry(target="first"))
    log.append(entry(target="second"))
    targets = [e.target for e in log.read_all()]
    assert targets == ["first", "second"]


def test_read_all_round_trips_every_field(tmp_path: Path):
    log = AuditLog(tmp_path / "log.jsonl")
    original = entry(decision="deny", approver="user", reason="user declined")
    log.append(original)
    assert log.read_all() == [original]


def test_read_missing_file_returns_empty(tmp_path: Path):
    assert AuditLog(tmp_path / "missing.jsonl").read_all() == []


def test_creates_parent_directories(tmp_path: Path):
    log = AuditLog(tmp_path / "deep" / "dir" / "log.jsonl")
    log.append(entry())
    assert (tmp_path / "deep" / "dir" / "log.jsonl").exists()


def test_format_table_contains_columns_and_rows(tmp_path: Path):
    log = AuditLog(tmp_path / "log.jsonl")
    log.append(entry(action="run_command", target="rm -rf /", decision="deny", reason="dangerous"))
    table = log.format_table()
    for col in ("timestamp", "action", "target", "decision", "approver", "reason"):
        assert col in table
    assert "rm -rf /" in table
    assert "dangerous" in table


def test_format_table_empty(tmp_path: Path):
    assert "empty" in AuditLog(tmp_path / "log.jsonl").format_table()
