from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from permission_guard import AuditEntry, AuditError, AuditLog
from permission_guard.__main__ import main as cli_main
from permission_guard.audit import GENESIS_HASH


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


def lines(path: Path) -> list[str]:
    return path.read_text().splitlines()


def write_lines(path: Path, new_lines: list[str]) -> None:
    path.write_text("\n".join(new_lines) + "\n")


@pytest.fixture
def log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "log.jsonl")


# ---------------------------------------------------------------- basics


def test_append_writes_one_json_line(log: AuditLog):
    log.append(entry())
    written = lines(log.path)
    assert len(written) == 1
    assert json.loads(written[0])["action"] == "read_file"


def test_append_is_append_only(log: AuditLog):
    log.append(entry(target="first"))
    log.append(entry(target="second"))
    assert [e.target for e in log.read_all()] == ["first", "second"]


def test_append_returns_sealed_entry_that_round_trips(log: AuditLog):
    sealed = log.append(entry(decision="deny", approver="user", reason="user declined"))
    assert sealed.hash and sealed.prev_hash == GENESIS_HASH
    assert log.read_all() == [sealed]


def test_read_missing_file_returns_empty(tmp_path: Path):
    assert AuditLog(tmp_path / "missing.jsonl").read_all() == []


def test_creates_parent_directories(tmp_path: Path):
    log = AuditLog(tmp_path / "deep" / "dir" / "log.jsonl")
    log.append(entry())
    assert (tmp_path / "deep" / "dir" / "log.jsonl").exists()


def test_log_file_is_private(log: AuditLog):
    log.append(entry())
    assert (log.path.stat().st_mode & 0o077) == 0


def test_format_table_contains_columns_and_rows(log: AuditLog):
    log.append(entry(action="run_command", target="rm -rf /", decision="deny", reason="dangerous", result="blocked"))
    table = log.format_table()
    for col in ("timestamp", "action", "target", "decision", "approver", "result", "reason"):
        assert col in table
    assert "rm -rf /" in table
    assert "blocked" in table


def test_format_table_truncates_long_cells(log: AuditLog):
    log.append(entry(reason="y" * 500))
    assert max(len(line) for line in log.format_table().splitlines()) < 300


def test_format_table_empty(log: AuditLog):
    assert "empty" in log.format_table()


# ---------------------------------------------------------------- hash chain


def test_chain_links_entries(log: AuditLog):
    first = log.append(entry(target="1"))
    second = log.append(entry(target="2"))
    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.hash
    assert log.last_hash() == second.hash


def test_verify_accepts_intact_log(log: AuditLog):
    for i in range(5):
        log.append(entry(target=str(i)))
    result = log.verify()
    assert result.ok and result.entries == 5
    assert "OK" in str(result)


def test_verify_empty_or_missing_log_is_ok(tmp_path: Path):
    assert AuditLog(tmp_path / "nothing.jsonl").verify().ok
    assert AuditLog(tmp_path / "nothing.jsonl").last_hash() == GENESIS_HASH


def test_verify_detects_modified_entry(log: AuditLog):
    for i in range(3):
        log.append(entry(target=str(i)))
    rows = lines(log.path)
    tampered = json.loads(rows[1])
    tampered["decision"] = "allow" if tampered["decision"] == "deny" else "deny"
    tampered["target"] = "changed"
    rows[1] = json.dumps(tampered)
    write_lines(log.path, rows)
    result = log.verify()
    assert not result.ok and result.line == 2
    assert "modified" in result.error


def test_verify_detects_removed_entry(log: AuditLog):
    for i in range(4):
        log.append(entry(target=str(i)))
    rows = lines(log.path)
    del rows[1]
    write_lines(log.path, rows)
    result = log.verify()
    assert not result.ok and result.line == 2
    assert "chain broken" in result.error


def test_verify_detects_reordered_entries(log: AuditLog):
    for i in range(3):
        log.append(entry(target=str(i)))
    rows = lines(log.path)
    rows[1], rows[2] = rows[2], rows[1]
    write_lines(log.path, rows)
    assert not log.verify().ok


def test_verify_detects_inserted_forged_entry(log: AuditLog):
    for i in range(3):
        log.append(entry(target=str(i)))
    rows = lines(log.path)
    forged = json.loads(rows[0])
    forged["target"] = "forged"
    rows.insert(1, json.dumps(forged))
    write_lines(log.path, rows)
    assert not log.verify().ok


def test_verify_detects_forged_hash_without_recomputing_chain(log: AuditLog):
    log.append(entry(target="a"))
    log.append(entry(target="b"))
    rows = lines(log.path)
    first = json.loads(rows[0])
    first["reason"] = "rewritten"
    rows[0] = json.dumps(first)  # hash field left stale
    write_lines(log.path, rows)
    assert not log.verify().ok


def test_verify_reports_malformed_line(log: AuditLog):
    log.append(entry())
    with log.path.open("a") as fh:
        fh.write("not json\n")
    result = log.verify()
    assert not result.ok and "malformed" in result.error and result.line == 2


def test_anchored_last_hash_reveals_tail_truncation(log: AuditLog):
    log.append(entry(target="a"))
    anchor = log.append(entry(target="b")).hash
    rows = lines(log.path)
    write_lines(log.path, rows[:1])  # attacker drops the newest entry
    assert log.verify().ok  # the chain alone cannot see it ...
    assert log.last_hash() != anchor  # ... but an externally stored anchor can


def test_append_refuses_to_extend_a_corrupt_tail(log: AuditLog):
    log.append(entry())
    with log.path.open("a") as fh:
        fh.write("garbage\n")
    with pytest.raises(AuditError):
        log.append(entry())


def test_append_refuses_after_partial_write(log: AuditLog):
    log.append(entry())
    with log.path.open("a") as fh:
        fh.write('{"partial": ')  # crash mid-line, no newline
    with pytest.raises(AuditError):
        log.append(entry())


def test_append_with_very_large_entries_still_chains(log: AuditLog):
    log.append(entry(reason="x" * 200_000))
    log.append(entry(reason="y" * 200_000))
    log.append(entry())
    result = log.verify()
    assert result.ok and result.entries == 3


def test_concurrent_appends_keep_the_chain_intact(log: AuditLog):
    def work(i: int) -> None:
        for j in range(15):
            log.append(entry(target=f"{i}-{j}"))

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(work, range(4)))
    result = log.verify()
    assert result.ok and result.entries == 60


def test_append_fails_with_audit_error_when_path_is_unwritable(tmp_path: Path):
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file")
    with pytest.raises((AuditError, OSError, NotADirectoryError)):
        AuditLog(blocker / "log.jsonl").append(entry())


def test_sealing_does_not_mutate_the_original_entry(log: AuditLog):
    original = entry()
    log.append(original)
    assert original.hash == "" and original.prev_hash == ""


# ---------------------------------------------------------------- verify CLI


def test_cli_verify_ok_and_failure(log: AuditLog, capsys):
    log.append(entry())
    assert cli_main(["verify", str(log.path)]) == 0
    assert "OK" in capsys.readouterr().out

    rows = lines(log.path)
    row = json.loads(rows[0])
    row["target"] = "tampered"
    write_lines(log.path, [json.dumps(row)])
    assert cli_main(["verify", str(log.path)]) == 1
    assert "FAILED" in capsys.readouterr().out
