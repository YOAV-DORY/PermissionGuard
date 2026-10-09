"""Approval flow: how an ``ask`` decision gets resolved.

``ApprovalProvider`` is a small protocol so the guard does not care whether the
answer comes from a terminal prompt, a test double, or (later) an MCP client.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from .models import ActionRequest

Scope = str  # "once" | "session" | "denied"


@dataclass(frozen=True)
class ApprovalResponse:
    approved: bool
    scope: Scope

    @property
    def approver(self) -> str:
        """Value recorded in the audit log's ``approver`` column."""
        if not self.approved:
            return "user"
        return "session" if self.scope == "session" else "user"


class ApprovalProvider(Protocol):
    def ask(self, request: ActionRequest, reason: str) -> ApprovalResponse: ...


class CliApprover:
    """Interactive y / n / s prompt on the command line.

    ``s`` approves the request and remembers (action, target) for the rest of
    the session, so identical requests are not prompted again.
    ``input_fn`` and ``output_fn`` are injectable for testing.
    """

    PROMPT = "  Approve? [y]es / [n]o / [s]ession (approve for rest of session): "

    def __init__(
        self,
        input_fn: Callable[[str], str] = input,
        output_fn: Callable[[str], None] = print,
    ) -> None:
        self._input = input_fn
        self._output = output_fn
        self.session_grants: set[tuple[str, str]] = set()

    def ask(self, request: ActionRequest, reason: str) -> ApprovalResponse:
        key = (request.action, request.target)
        if key in self.session_grants:
            self._output(f"[approval] {request.action} {request.target!r} auto-approved (session grant)")
            return ApprovalResponse(approved=True, scope="session")

        self._output("")
        self._output("[approval] The assistant wants to perform an action that needs your approval:")
        self._output(f"  action : {request.action}")
        self._output(f"  target : {request.target}")
        if request.params:
            self._output(f"  params : {request.params}")
        self._output(f"  reason : {reason}")

        while True:
            answer = self._input(self.PROMPT).strip().lower()
            if answer in ("y", "yes"):
                return ApprovalResponse(approved=True, scope="once")
            if answer in ("n", "no", ""):
                return ApprovalResponse(approved=False, scope="denied")
            if answer in ("s", "session"):
                self.session_grants.add(key)
                return ApprovalResponse(approved=True, scope="session")
            self._output("  Please answer y, n, or s.")


class AutoApprover:
    """Non-interactive provider that always answers the same way. Useful for demos and tests."""

    def __init__(self, approve: bool = True, scope: Scope = "once") -> None:
        self._approve = approve
        self._scope = scope if approve else "denied"
        self.calls: list[ActionRequest] = []

    def ask(self, request: ActionRequest, reason: str) -> ApprovalResponse:
        self.calls.append(request)
        return ApprovalResponse(approved=self._approve, scope=self._scope)
