"""The middleware: policy check -> approval -> audit -> execution -> audit.

``PermissionGuard.handle(action, target, **params)`` is the shape an MCP server
would call for each incoming tool request; ``execute`` takes a full
``ActionRequest`` for callers that already have one.

Fail-closed rules enforced here:

* if the policy engine raises, the request is denied;
* if the approver raises, the request is denied;
* the decision is written to the audit log *before* the tool runs; if that write
  fails, the tool does not run;
* tool errors are caught and recorded, never raised to the assistant.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .approval import ApprovalProvider
from .audit import AuditLog
from .models import ActionRequest, AuditEntry, Decision, GuardResult, PolicyResult
from .policy import PolicyEngine
from .tools import TOOLS, ToolFn


class PermissionGuard:
    def __init__(
        self,
        policy: PolicyEngine,
        audit: AuditLog,
        approver: ApprovalProvider,
        sandbox_root: str | Path | None = None,
        tools: dict[str, ToolFn] | None = None,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.approver = approver
        self.sandbox_root = Path(sandbox_root).resolve() if sandbox_root else policy.sandbox_root
        self.tools = tools if tools is not None else TOOLS

    # ------------------------------------------------------------------ public API

    def handle(self, action: str, target: str, **params: Any) -> GuardResult:
        return self.execute(ActionRequest(action=action, target=target, params=params))

    def execute(self, request: ActionRequest) -> GuardResult:
        try:
            verdict = self.policy.evaluate(request)
        except Exception as exc:  # noqa: BLE001 - a broken policy must never become "allow"
            verdict = PolicyResult(Decision.DENY, f"policy error: {type(exc).__name__}: {exc}", "policy-error")

        if verdict.decision is Decision.DENY:
            return self._deny(request, verdict.reason, approver="policy")

        if verdict.decision is Decision.ALLOW:
            return self._authorize_and_run(request, verdict.reason, approver="policy")

        # Decision.ASK
        try:
            response = self.approver.ask(request, verdict.reason, verdict.details)
        except Exception as exc:  # noqa: BLE001 - an approver that crashes means "no"
            return self._deny(request, f"approval error: {type(exc).__name__}: {exc}", approver="policy")

        if not response.approved:
            return self._deny(request, f"user declined ({verdict.reason})", approver=response.approver)
        return self._authorize_and_run(request, f"user approved ({verdict.reason})", approver=response.approver)

    # ------------------------------------------------------------------ internals

    def _deny(self, request: ActionRequest, reason: str, approver: str) -> GuardResult:
        error = self._record(request, Decision.DENY, reason, approver, result="blocked")
        return GuardResult(Decision.DENY, executed=False, reason=reason, error=error)

    def _authorize_and_run(self, request: ActionRequest, reason: str, approver: str) -> GuardResult:
        tool = self.tools.get(request.action)
        if tool is None:
            return self._deny(request, f"no tool registered for '{request.action}'", approver="policy")

        # Write-ahead: the decision is on disk before anything happens. No audit, no action.
        audit_error = self._record(request, Decision.ALLOW, reason, approver, result="authorized")
        if audit_error:
            return GuardResult(
                Decision.DENY,
                executed=False,
                reason="audit log unavailable; action not executed",
                error=audit_error,
            )

        # The assistant must not be able to override limits through params.
        params = {k: v for k, v in request.params.items() if k != "limits"}
        try:
            output = tool(self.sandbox_root, request.target, limits=self.policy.limits, **params)
        except Exception as exc:  # noqa: BLE001 - any tool failure must be audited, not raised
            error = f"{type(exc).__name__}: {exc}"
            note = self._record(
                request, Decision.ALLOW, "execution failed", approver, result=f"error: {error}"
            )
            return GuardResult(Decision.ALLOW, executed=True, reason=reason, error=error + (f" | {note}" if note else ""))

        note = self._record(request, Decision.ALLOW, "execution completed", approver, result="ok")
        return GuardResult(Decision.ALLOW, executed=True, reason=reason, output=output, error=note)

    def _record(
        self, request: ActionRequest, decision: Decision, reason: str, approver: str, result: str
    ) -> str:
        """Append one audit entry. Returns an error string, or "" on success."""
        try:
            self.audit.append(
                AuditEntry(
                    timestamp=AuditEntry.now(),
                    action=request.action,
                    target=request.target,
                    decision=decision.value,
                    reason=reason,
                    approver=approver,
                    result=result,
                )
            )
        except Exception as exc:  # noqa: BLE001 - AuditError or any I/O problem
            return f"audit write failed: {type(exc).__name__}: {exc}"
        return ""
