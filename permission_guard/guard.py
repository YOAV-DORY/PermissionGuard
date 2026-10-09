"""The middleware: policy check -> approval -> execution -> audit.

``PermissionGuard.handle(action, target, **params)`` is the shape an MCP server
would call for each incoming tool request; ``execute`` takes a full
``ActionRequest`` for callers that already have one.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .approval import ApprovalProvider
from .audit import AuditLog
from .models import ActionRequest, AuditEntry, Decision, GuardResult
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
        verdict = self.policy.evaluate(request)

        if verdict.decision is Decision.DENY:
            self._log(request, Decision.DENY, verdict.reason, approver="policy", result="blocked")
            return GuardResult(Decision.DENY, executed=False, reason=verdict.reason)

        if verdict.decision is Decision.ALLOW:
            return self._run(request, Decision.ALLOW, verdict.reason, approver="policy")

        # Decision.ASK
        response = self.approver.ask(request, verdict.reason)
        if not response.approved:
            reason = f"user declined ({verdict.reason})"
            self._log(request, Decision.DENY, reason, approver=response.approver, result="blocked")
            return GuardResult(Decision.DENY, executed=False, reason=reason)

        reason = f"user approved ({verdict.reason})"
        return self._run(request, Decision.ALLOW, reason, approver=response.approver)

    # ------------------------------------------------------------------ internals

    def _run(self, request: ActionRequest, decision: Decision, reason: str, approver: str) -> GuardResult:
        tool = self.tools.get(request.action)
        if tool is None:
            error = f"no tool registered for '{request.action}'"
            self._log(request, Decision.DENY, error, approver="policy", result="error")
            return GuardResult(Decision.DENY, executed=False, reason=error, error=error)

        try:
            output = tool(self.sandbox_root, request.target, **request.params)
        except Exception as exc:  # noqa: BLE001 - any tool failure must be audited, not raised
            error = f"{type(exc).__name__}: {exc}"
            self._log(request, decision, reason, approver=approver, result=f"error: {error}")
            return GuardResult(decision, executed=True, reason=reason, error=error)

        self._log(request, decision, reason, approver=approver, result="ok")
        return GuardResult(decision, executed=True, reason=reason, output=output)

    def _log(self, request: ActionRequest, decision: Decision, reason: str, approver: str, result: str) -> None:
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
