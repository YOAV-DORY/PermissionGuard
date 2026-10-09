"""End-to-end middleware tests: policy -> approval -> execution -> audit."""

from __future__ import annotations

from pathlib import Path

from permission_guard import ActionRequest, AuditLog, AutoApprover, Decision
from permission_guard.approval import CliApprover

REQUIRED_FIELDS = {"timestamp", "action", "target", "decision", "reason", "approver", "result"}


def last_entry(audit: AuditLog):
    entries = audit.read_all()
    assert entries, "expected at least one audit entry"
    return entries[-1]


def test_allowed_read_executes_and_logs_policy_approver(make_guard, audit):
    guard = make_guard()
    result = guard.handle("read_file", "hello.txt")
    assert result.decision is Decision.ALLOW
    assert result.executed is True
    assert result.output == "hello world\n"

    entry = last_entry(audit)
    assert entry.decision == "allow"
    assert entry.approver == "policy"
    assert entry.result == "ok"


def test_ask_then_approve_executes_and_logs_user_approver(make_guard, audit, sandbox: Path):
    approver = AutoApprover(approve=True)
    guard = make_guard(approver=approver)
    result = guard.handle("delete_file", "hello.txt")

    assert result.executed is True
    assert not (sandbox / "hello.txt").exists()
    assert approver.calls == [ActionRequest("delete_file", "hello.txt")]

    entry = last_entry(audit)
    assert entry.decision == "allow"
    assert entry.approver == "user"
    assert "user approved" in entry.reason


def test_ask_then_decline_does_not_execute(make_guard, audit, sandbox: Path):
    guard = make_guard(approver=AutoApprover(approve=False))
    result = guard.handle("delete_file", "hello.txt")

    assert result.decision is Decision.DENY
    assert result.executed is False
    assert (sandbox / "hello.txt").exists()

    entry = last_entry(audit)
    assert entry.decision == "deny"
    assert entry.approver == "user"
    assert "user declined" in entry.reason
    assert entry.result == "blocked"


def test_session_approval_is_recorded_as_session(make_guard, audit):
    approver = CliApprover(input_fn=lambda _: "s", output_fn=lambda _: None)
    guard = make_guard(approver=approver)
    guard.handle("write_file", "a.txt", content="1")
    guard.handle("write_file", "a.txt", content="2")
    approvers = [e.approver for e in audit.read_all()]
    assert approvers == ["session", "session"]


def test_denied_command_never_reaches_tool(make_guard, audit):
    calls: list[str] = []

    def spy_run_command(sandbox_root, target, **params):
        calls.append(target)
        return "should not happen"

    guard = make_guard(tools={"run_command": spy_run_command})
    result = guard.handle("run_command", "rm -rf /")

    assert result.decision is Decision.DENY
    assert result.executed is False
    assert calls == []

    entry = last_entry(audit)
    assert entry.decision == "deny"
    assert entry.approver == "policy"
    assert "dangerous command" in entry.reason


def test_approver_not_consulted_for_deny_or_allow(make_guard):
    approver = AutoApprover(approve=True)
    guard = make_guard(approver=approver)
    guard.handle("read_file", "hello.txt")      # allow
    guard.handle("read_file", "../etc/passwd")  # deny
    assert approver.calls == []


def test_path_traversal_is_blocked_and_audited(make_guard, audit):
    result = guard_result = make_guard().handle("read_file", "../../etc/passwd")
    assert result.executed is False
    entry = last_entry(audit)
    assert entry.decision == "deny"
    assert "escapes sandbox" in entry.reason


def test_tool_error_is_audited_not_raised(make_guard, audit):
    guard = make_guard()
    result = guard.handle("read_file", "missing.txt")
    assert result.executed is True
    assert "FileNotFoundError" in result.error
    entry = last_entry(audit)
    assert entry.result.startswith("error:")


def test_every_audit_entry_has_required_fields(make_guard, audit):
    guard = make_guard(approver=AutoApprover(approve=True))
    guard.handle("read_file", "hello.txt")
    guard.handle("delete_file", "hello.txt")
    guard.handle("run_command", "rm -rf /")

    entries = audit.read_all()
    assert len(entries) == 3
    for e in entries:
        data = e.to_dict()
        assert set(data) == REQUIRED_FIELDS
        assert all(data[f] != "" for f in REQUIRED_FIELDS - {"result"}), data
        assert data["timestamp"].endswith("+00:00")


def test_demo_sequence(make_guard, audit, sandbox: Path):
    """Mirror demo.py: read succeeds, delete approved, rm -rf denied."""
    guard = make_guard(approver=AutoApprover(approve=True))
    decisions = [
        guard.handle("read_file", "hello.txt").decision,
        guard.handle("delete_file", "hello.txt").decision,
        guard.handle("run_command", "rm -rf /").decision,
    ]
    assert decisions == [Decision.ALLOW, Decision.ALLOW, Decision.DENY]
    assert not (sandbox / "hello.txt").exists()
    assert [e.approver for e in audit.read_all()] == ["policy", "user", "policy"]
