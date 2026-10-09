"""PermissionGuard as an MCP server (stdio).

Any MCP client can use the four guarded tools (``read_file``, ``write_file``,
``delete_file``, ``run_command``). Every call goes through the same
``PermissionGuard`` as everywhere else: policy, optional human approval, audit log.

Approval uses MCP elicitation, so the question is shown by the MCP *client* (the
app the human is looking at), not on the server's terminal (a stdio server has no
terminal; stdin and stdout carry the protocol). It is built on the SDK's
``Resolve`` / ``Elicit`` mechanism, which works on both protocol generations:

* a resolver runs *before* the tool body: it asks the policy whether this call needs
  approval and, if so, returns an ``Elicit`` marker for the SDK to put to the human;
* the tool body then runs the guard with the human's answer already in hand
  (``ResolvedApprover``), so the guard never blocks waiting on a person.

Fail closed: no elicitation support in the client, prompts disabled, an unreadable
answer, or an approval that does not match the call all end in "denied".

IMPORTANT: this server only governs calls made *through it*. A client that also has
its own shell or file tools is not restricted by them; disable those for real
enforcement.

Do not ``print`` in this module: on stdio, stdout is the protocol channel.

Note: no ``from __future__ import annotations`` here. The SDK inspects the
``Annotated[..., Resolve(fn)]`` parameter annotations, which must be real objects.
"""

import argparse
import contextvars
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

import anyio.to_thread
from mcp.server.mcpserver import (
    AcceptedElicitation,
    Context,
    Elicit,
    ElicitationResult,
    MCPServer,
    Resolve,
)
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from .approval import ApprovalResponse, ApprovalUnavailable, describe_request, format_rows
from .assistant import execute_tool_call
from .audit import AuditLog
from .guard import PermissionGuard
from .models import ActionRequest, Decision
from .policy import PolicyEngine

logger = logging.getLogger("permission_guard.mcp")

PROJECT_ROOT = Path(__file__).resolve().parent.parent

APPROVE_ONCE = "approve once"
APPROVE_SESSION = "approve for this session"
DENY = "deny"

INSTRUCTIONS = (
    "Guarded file and command tools. Paths are relative to a sandbox directory; anything outside it is "
    "refused. Commands run without a shell (one program per call, no pipes or redirects). Some calls "
    "need the user's approval and may be declined. If a call is blocked, do not try to work around it: "
    "tell the user what was blocked and why."
)


class ApprovalForm(BaseModel):
    """What the human is asked. Only the three listed answers are accepted."""

    decision: Literal["deny", "approve once", "approve for this session"] = Field(
        default=DENY,
        title="Your decision",
        description="Approve this one action, approve identical actions for the rest of this session, or deny it.",
    )


@dataclass(frozen=True)
class Resolution:
    """The outcome of the pre-tool approval step for one call."""

    status: str  # "not_asked" | "approved" | "denied" | "unavailable"
    scope: str = "once"  # "once" | "session"
    note: str = ""


class ResolvedApprover:
    """Hands the guard an approval that was already collected before the tool body ran.

    The resolution is carried in a ``ContextVar`` so concurrent tool calls never see each
    other's answers. If the guard asks for something the pre-step did not ask about (the
    world changed in between), the answer is "no".
    """

    def __init__(self) -> None:
        self._current: contextvars.ContextVar[Resolution | None] = contextvars.ContextVar("pg_resolution", default=None)

    def bind(self, resolution: Resolution) -> contextvars.Token:
        return self._current.set(resolution)

    def reset(self, token: contextvars.Token) -> None:
        self._current.reset(token)

    def ask(self, request: ActionRequest, reason: str, details: dict[str, Any] | None = None) -> ApprovalResponse:
        resolution = self._current.get()
        if resolution is None or resolution.status == "not_asked":
            raise ApprovalUnavailable("this action needed approval but approval was not requested; refusing")
        if resolution.status == "unavailable":
            raise ApprovalUnavailable(resolution.note)
        if resolution.status == "approved":
            return ApprovalResponse(approved=True, scope=resolution.scope)
        return ApprovalResponse(approved=False, scope="denied")


def _approval_message(request: ActionRequest, reason: str, details: dict[str, Any]) -> str:
    lines = ["PermissionGuard needs your approval for an action the assistant requested:", ""]
    lines += format_rows(describe_request(request, reason, details))
    return "\n".join(lines)


def _can_elicit(ctx: Context) -> bool:
    """True if the client declared form elicitation (a bare ``elicitation: {}`` counts)."""
    capabilities = ctx.client_capabilities
    elicitation = capabilities.elicitation if capabilities is not None else None
    return elicitation is not None and (elicitation.form is not None or elicitation.url is None)


def _session_key(ctx: Context) -> str:
    return str(getattr(ctx.request_context, "session_id", None) or "default")


def build_server(
    guard_factory, *, approval_mode: Literal["elicit", "deny"] = "elicit", name: str = "permission-guard"
) -> MCPServer:
    """Create the MCP server. ``guard_factory(approver)`` must return a PermissionGuard using that approver."""
    approver = ResolvedApprover()
    guard: PermissionGuard = guard_factory(approver)
    grants: set[tuple[str, str, str]] = set()  # (session, action, target) approved "for this session"
    server = MCPServer(name, instructions=INSTRUCTIONS)

    # ---------------------------------------------------------------- step 1: resolver (before the tool body)

    def decide(ctx: Context, request: ActionRequest) -> "Elicit[ApprovalForm] | Resolution":
        try:
            verdict = guard.policy.evaluate(request)
        except Exception:  # noqa: BLE001 - the guard re-evaluates and fails closed; nothing to ask about
            return Resolution("not_asked")
        if verdict.decision is not Decision.ASK:
            return Resolution("not_asked")  # allow or deny: the guard decides, no human involved
        if approval_mode == "deny":
            return Resolution("unavailable", note="approval prompts are disabled on this server (--approval deny)")
        if (_session_key(ctx), request.action, request.target) in grants:
            return Resolution("approved", scope="session")
        if not _can_elicit(ctx):
            return Resolution("unavailable", note="the MCP client does not support approval prompts (elicitation)")
        return Elicit(_approval_message(request, verdict.reason, verdict.details), ApprovalForm)

    def resolve_read(ctx: Context, path: str) -> "Elicit[ApprovalForm] | Resolution":
        return decide(ctx, ActionRequest("read_file", path))

    def resolve_write(ctx: Context, path: str, content: str) -> "Elicit[ApprovalForm] | Resolution":
        return decide(ctx, ActionRequest("write_file", path, {"content": content}))

    def resolve_delete(ctx: Context, path: str) -> "Elicit[ApprovalForm] | Resolution":
        return decide(ctx, ActionRequest("delete_file", path))

    def resolve_command(ctx: Context, command: str) -> "Elicit[ApprovalForm] | Resolution":
        return decide(ctx, ActionRequest("run_command", command))

    # ---------------------------------------------------------------- step 2: the tool body

    def to_resolution(outcome: ElicitationResult[ApprovalForm]) -> Resolution:
        if not isinstance(outcome, AcceptedElicitation):
            return Resolution("denied")  # declined or cancelled
        data = outcome.data
        if isinstance(data, Resolution):
            return data
        if isinstance(data, ApprovalForm):
            if data.decision == APPROVE_ONCE:
                return Resolution("approved", scope="once")
            if data.decision == APPROVE_SESSION:
                return Resolution("approved", scope="session")
        return Resolution("denied")

    async def run(ctx: Context, action: str, tool_input: dict[str, Any], outcome: ElicitationResult[ApprovalForm]) -> str:
        resolution = to_resolution(outcome)
        target = tool_input.get("path") or tool_input.get("command") or ""
        if resolution.status == "approved" and resolution.scope == "session":
            grants.add((_session_key(ctx), action, target))

        token = approver.bind(resolution)
        try:
            # The guard is synchronous (file and subprocess work), so run it off the event loop.
            text, is_error, _blocked, _executed = await anyio.to_thread.run_sync(
                lambda: execute_tool_call(guard, action, tool_input)
            )
        finally:
            approver.reset(token)
        if is_error:
            raise ToolError(text)
        return text

    read_only = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)
    writes = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False)
    destructive = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False)
    commands = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=True)

    @server.tool(annotations=read_only)
    async def read_file(
        path: str, ctx: Context, approval: Annotated[ElicitationResult[ApprovalForm], Resolve(resolve_read)]
    ) -> str:
        """Read a UTF-8 text file from the sandbox. `path` is relative to the sandbox directory."""
        return await run(ctx, "read_file", {"path": path}, approval)

    @server.tool(annotations=writes)
    async def write_file(
        path: str,
        content: str,
        ctx: Context,
        approval: Annotated[ElicitationResult[ApprovalForm], Resolve(resolve_write)],
    ) -> str:
        """Create or overwrite a text file in the sandbox. Usually needs the user's approval."""
        return await run(ctx, "write_file", {"path": path, "content": content}, approval)

    @server.tool(annotations=destructive)
    async def delete_file(
        path: str, ctx: Context, approval: Annotated[ElicitationResult[ApprovalForm], Resolve(resolve_delete)]
    ) -> str:
        """Delete a file from the sandbox. Always needs the user's approval."""
        return await run(ctx, "delete_file", {"path": path}, approval)

    @server.tool(annotations=commands)
    async def run_command(
        command: str, ctx: Context, approval: Annotated[ElicitationResult[ApprovalForm], Resolve(resolve_command)]
    ) -> str:
        """Run one allowlisted program (no shell, no pipes or redirects) in the sandbox. Needs the user's approval."""
        return await run(ctx, "run_command", {"command": command}, approval)

    return server


def build_default_server(
    policy_file: Path, sandbox: Path, audit_file: Path, approval_mode: Literal["elicit", "deny"] = "elicit"
) -> MCPServer:
    sandbox.mkdir(parents=True, exist_ok=True)
    policy = PolicyEngine.from_yaml(policy_file, sandbox_root=sandbox)
    audit = AuditLog(audit_file)

    def factory(approver: ResolvedApprover) -> PermissionGuard:
        return PermissionGuard(policy=policy, audit=audit, approver=approver)

    return build_server(factory, approval_mode=approval_mode)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m permission_guard.mcp_server",
        description="Run PermissionGuard as an MCP server on stdio.",
    )
    parser.add_argument("--policy", type=Path, default=PROJECT_ROOT / "policies" / "default.yaml")
    parser.add_argument("--sandbox", type=Path, default=PROJECT_ROOT / "sandbox", help="the only directory the tools may touch")
    parser.add_argument("--audit-file", type=Path, default=PROJECT_ROOT / "audit.log.jsonl")
    parser.add_argument(
        "--approval",
        choices=["elicit", "deny"],
        default="elicit",
        help="elicit: ask the human through the MCP client (default); deny: never ask, so anything that needs approval is refused",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(name)s: %(message)s")
    try:
        server = build_default_server(args.policy.resolve(), args.sandbox.resolve(), args.audit_file.resolve(), args.approval)
    except Exception as exc:  # noqa: BLE001 - a bad policy must stop the server with a readable message
        print(f"permission-guard: cannot start: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    logger.info("policy=%s sandbox=%s audit=%s approval=%s", args.policy, args.sandbox.resolve(), args.audit_file, args.approval)
    server.run("stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
