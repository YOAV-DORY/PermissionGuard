"""Approval flow: how an ``ask`` decision gets resolved.

``ApprovalProvider`` is a small protocol so the guard does not care whether the
answer comes from a terminal prompt, a test double, or (later) an MCP client.

The ``details`` argument carries facts the human needs to decide safely (the
resolved path, the parsed argv, a preview of the content to be written) so the
prompt never asks for approval of something the human cannot see.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol

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


def describe_request(
    request: ActionRequest, reason: str, details: dict[str, Any] | None = None
) -> list[tuple[str, Any]]:
    """The facts a human needs to approve safely, as (label, value) rows."""
    rows: list[tuple[str, Any]] = [("action", request.action), ("target", request.target)]
    rows.extend((details or {}).items())
    if request.params:
        rows.append(("params", request.params))
    rows.append(("reason", reason))
    return rows


def format_rows(rows: list[tuple[str, Any]]) -> list[str]:
    width = max(len(name) for name, _ in rows)
    return [f"  {name:<{width}} : {value}" for name, value in rows]


class ApprovalUnavailable(Exception):
    """No human can be asked right now (for example the MCP client cannot show prompts).

    Raised from an approver, the guard turns it into a denial that is attributed to the
    system, not to a user decision.
    """


class ApprovalProvider(Protocol):
    def ask(self, request: ActionRequest, reason: str, details: dict[str, Any] | None = None) -> ApprovalResponse: ...


class CliApprover:
    """Interactive y / n / s prompt on the command line.

    ``s`` approves the request and remembers (action, target) for the rest of
    the session, so identical requests are not prompted again. Closed input
    (EOF) counts as "no". ``input_fn`` and ``output_fn`` are injectable for tests.
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

    def ask(self, request: ActionRequest, reason: str, details: dict[str, Any] | None = None) -> ApprovalResponse:
        key = (request.action, request.target)
        if key in self.session_grants:
            self._output(f"[approval] {request.action} {request.target!r} auto-approved (session grant)")
            return ApprovalResponse(approved=True, scope="session")

        self._output("")
        self._output("[approval] The assistant wants to perform an action that needs your approval:")
        for line in format_rows(describe_request(request, reason, details)):
            self._output(line)

        while True:
            try:
                answer = self._input(self.PROMPT).strip().lower()
            except EOFError:
                self._output("  (no input available - denying)")
                return ApprovalResponse(approved=False, scope="denied")
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
        self.details: list[dict[str, Any]] = []

    def ask(self, request: ActionRequest, reason: str, details: dict[str, Any] | None = None) -> ApprovalResponse:
        self.calls.append(request)
        self.details.append(dict(details or {}))
        return ApprovalResponse(approved=self._approve, scope=self._scope)
