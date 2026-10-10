"""End-to-end middleware tests: policy -> approval -> audit -> execution -> audit."""

from __future__ import annotations

from pathlib import Path

from permission_guard import ActionRequest, AuditError, AuditLog, AutoApprover, Decision, Limits
from permission_guard.approval import CliApprover

REQUIRED_FIELDS = {
    "timestamp",
    "action",
    "target",
    "decision",
    "reason",
    "approver",
    "result",
    "prev_hash",
    "hash",
}


def results(audit: AuditLog) -> list[str]:
    return [e.result for e in audit.read_all()]


def last_entry(audit: AuditLog):
    entries = audit.read_all()
    assert entries, "expected at least one audit entry"
    return entries[-1]


# ---------------------------------------------------------------- the three outcomes


def test_allowed_read_executes_and_logs_decision_then_outcome(make_guard, audit):
    guard = make_guard()
    result = guard.handle("read_file", "hello.txt")
    assert result.decision is Decision.ALLOW
    assert result.executed is True
    assert result.output == "hello world\n"

    decision_row, outcome_row = audit.read_all()
    assert (decision_row.decision, decision_row.approver, decision_row.result) == ("allow", "policy", "authorized")
    assert (outcome_row.decision, outcome_row.approver, outcome_row.result) == ("allow", "policy", "ok")


def test_ask_then_approve_executes_and_logs_user_approver(make_guard, audit, sandbox: Path):
    approver = AutoApprover(approve=True)
    guard = make_guard(approver=approver)
    result = guard.handle("delete_file", "hello.txt")

    assert result.executed is True
    assert not (sandbox / "hello.txt").exists()
    assert approver.calls == [ActionRequest("delete_file", "hello.txt")]

    entries = audit.read_all()
    assert [e.approver for e in entries] == ["user", "user"]
    assert "user approved" in entries[0].reason
    assert results(audit) == ["authorized", "ok"]


def test_ask_then_decline_does_not_execute(make_guard, audit, sandbox: Path):
    guard = make_guard(approver=AutoApprover(approve=False))
    result = guard.handle("delete_file", "hello.txt")

    assert result.decision is Decision.DENY
    assert result.executed is False
    assert (sandbox / "hello.txt").exists()

    entries = audit.read_all()
    assert len(entries) == 1
    entry = entries[0]
    assert (entry.decision, entry.approver, entry.result) == ("deny", "user", "blocked")
    assert "user declined" in entry.reason


def test_session_approval_is_recorded_as_session(make_guard, audit):
    approver = CliApprover(input_fn=lambda _: "s", output_fn=lambda _: None)
    guard = make_guard(approver=approver)
    guard.handle("write_file", "a.txt", content="1")
    guard.handle("write_file", "a.txt", content="2")
    assert [e.approver for e in audit.read_all()] == ["session"] * 4


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
    assert (entry.decision, entry.approver, entry.result) == ("deny", "policy", "blocked")
    assert "dangerous command" in entry.reason


def test_approver_not_consulted_for_deny_or_allow(make_guard):
    approver = AutoApprover(approve=True)
    guard = make_guard(approver=approver)
    guard.handle("read_file", "hello.txt")      # allow
    guard.handle("read_file", "../etc/passwd")  # deny
    assert approver.calls == []


def test_path_traversal_is_blocked_and_audited(make_guard, audit):
    result = make_guard().handle("read_file", "../../etc/passwd")
    assert result.executed is False
    entry = last_entry(audit)
    assert entry.decision == "deny"
    assert "escapes sandbox" in entry.reason


def test_approver_sees_details_of_what_it_approves(make_guard, sandbox: Path):
    approver = AutoApprover(approve=True)
    make_guard(approver=approver).handle("write_file", "new.txt", content="secret plan")
    details = approver.details[0]
    assert details["resolved_path"] == str((sandbox / "new.txt").resolve())
    assert "secret plan" in details["content_preview"]


# ---------------------------------------------------------------- failures are audited, not raised


def test_tool_error_is_audited_not_raised(make_guard, audit):
    result = make_guard().handle("read_file", "missing.txt")
    assert result.executed is True
    assert "FileNotFoundError" in result.error
    assert results(audit)[0] == "authorized"
    assert results(audit)[1].startswith("error:")


def test_assistant_cannot_override_limits_through_params(make_guard, policy):
    seen: dict = {}

    def spy(sandbox_root, target, **kwargs):
        seen.update(kwargs)
        return "ok"

    guard = make_guard(tools={"read_file": spy})
    guard.handle("read_file", "hello.txt", limits=Limits(max_read_bytes=10**12), extra="kept")
    assert seen["limits"] is policy.limits
    assert seen["extra"] == "kept"


def test_oversized_write_is_denied_before_approval(make_guard, policy):
    approver = AutoApprover(approve=True)
    guard = make_guard(approver=approver)
    result = guard.handle("write_file", "big.txt", content="x" * (policy.limits.max_write_bytes + 1))
    assert result.executed is False
    assert approver.calls == []


# ---------------------------------------------------------------- fail closed


class BrokenAudit:
    """An audit log whose disk is full."""

    def append(self, entry):
        raise AuditError("disk full")


def test_no_audit_no_action(make_guard, policy, sandbox: Path):
    from permission_guard import PermissionGuard

    guard = PermissionGuard(policy, BrokenAudit(), AutoApprover(approve=True), sandbox_root=sandbox)  # type: ignore[arg-type]
    result = guard.handle("delete_file", "hello.txt")
    assert result.executed is False
    assert result.decision is Decision.DENY
    assert "audit log unavailable" in result.reason
    assert "disk full" in result.error
    assert (sandbox / "hello.txt").exists()


def test_read_is_also_blocked_when_audit_is_down(policy, sandbox: Path):
    from permission_guard import PermissionGuard

    guard = PermissionGuard(policy, BrokenAudit(), AutoApprover(), sandbox_root=sandbox)  # type: ignore[arg-type]
    assert guard.handle("read_file", "hello.txt").executed is False


def test_denials_still_return_when_audit_is_down(policy, sandbox: Path):
    from permission_guard import PermissionGuard

    guard = PermissionGuard(policy, BrokenAudit(), AutoApprover(), sandbox_root=sandbox)  # type: ignore[arg-type]
    result = guard.handle("run_command", "rm -rf /")
    assert result.executed is False
    assert "audit write failed" in result.error


def test_policy_crash_means_deny(make_guard, policy, audit, monkeypatch):
    def boom(request):
        raise RuntimeError("bug in policy")

    monkeypatch.setattr(policy, "evaluate", boom)
    called: list[str] = []
    guard = make_guard(tools={"read_file": lambda *a, **k: called.append("ran") or "x"})
    result = guard.handle("read_file", "hello.txt")
    assert result.decision is Decision.DENY
    assert result.executed is False
    assert called == []
    assert "policy error" in last_entry(audit).reason


def test_approver_crash_means_deny(make_guard, audit, sandbox: Path):
    class CrashingApprover:
        def ask(self, request, reason, details=None):
            raise RuntimeError("terminal exploded")

    guard = make_guard(approver=CrashingApprover())
    result = guard.handle("delete_file", "hello.txt")
    assert result.executed is False
    assert (sandbox / "hello.txt").exists()
    assert "approval error" in last_entry(audit).reason


def test_unregistered_tool_is_denied(make_guard, audit):
    guard = make_guard(tools={})
    result = guard.handle("read_file", "hello.txt")
    assert result.executed is False
    assert "no tool registered" in last_entry(audit).reason


# ---------------------------------------------------------------- audit integrity


def test_every_audit_entry_has_required_fields(make_guard, audit):
    guard = make_guard(approver=AutoApprover(approve=True))
    guard.handle("read_file", "hello.txt")
    guard.handle("delete_file", "hello.txt")
    guard.handle("run_command", "rm -rf /")

    entries = audit.read_all()
    assert len(entries) == 5  # read x2, delete x2, denied command x1
    for e in entries:
        data = e.to_dict()
        assert set(data) == REQUIRED_FIELDS
        assert all(data[f] != "" for f in REQUIRED_FIELDS), data
        assert data["timestamp"].endswith("+00:00")


def test_audit_chain_is_valid_after_guard_activity(make_guard, audit):
    guard = make_guard(approver=AutoApprover(approve=True))
    guard.handle("read_file", "hello.txt")
    guard.handle("write_file", "x.txt", content="1")
    guard.handle("run_command", "sudo ls")
    guard.handle("read_file", "../nope")
    assert audit.verify().ok


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
    assert [e.approver for e in audit.read_all()] == ["policy", "policy", "user", "user", "policy"]
