"""A tool-using assistant loop wired through PermissionGuard.

The assistant (an LLM) never touches a tool directly. Every ``tool_use`` it emits
becomes ``guard.handle(...)``; the guard's verdict is sent back as the
``tool_result``. The loop depends only on a tiny protocol (``LLM.create``) and on
duck-typed content blocks (``.type``, ``.text``, ``.id``, ``.name``, ``.input``),
so it works with the Anthropic SDK, with the offline simulation in
``simulated.py``, and with test doubles.

File contents and command output are returned to the model as tool results. They
are *untrusted data*: this is the channel a prompt-injection attack arrives on,
and exactly why the guard sits between the model and the tools.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from .guard import PermissionGuard
from .models import Decision

MAX_TURNS = 10
MAX_TOOL_RESULT_CHARS = 20_000

SYSTEM_PROMPT = (
    "You are a helpful file assistant. You work inside a sandbox directory using the "
    "provided tools. Paths are relative to the sandbox. Commands run without a shell, "
    "one program per call (no pipes, redirects or chaining). Some actions need human "
    "approval and may be declined; if an action is blocked, do not try to work around "
    "it - tell the user what happened."
)

# Tool schemas shown to the model. Property names are model-friendly; the executor
# below maps them onto the guard's (action, target, params) shape.
TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "read_file",
        "description": "Read a text file from the sandbox and return its contents.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path relative to the sandbox"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "write_file",
        "description": "Create or overwrite a text file in the sandbox. Requires human approval.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to the sandbox"},
                "content": {"type": "string", "description": "Full new contents of the file"},
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
    },
    {
        "name": "delete_file",
        "description": "Delete a file from the sandbox. Requires human approval.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path relative to the sandbox"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "run_command",
        "description": "Run one program (no shell) with the sandbox as working directory. Requires human approval.",
        "input_schema": {
            "type": "object",
            "properties": {"command": {"type": "string", "description": "Program and arguments, e.g. 'ls -la'"}},
            "required": ["command"],
            "additionalProperties": False,
        },
    },
]

# tool name -> (name of the field that holds the guard "target", other fields passed as params)
_TOOL_FIELDS: dict[str, tuple[str, tuple[str, ...]]] = {
    "read_file": ("path", ()),
    "write_file": ("path", ("content",)),
    "delete_file": ("path", ()),
    "run_command": ("command", ()),
}


class LLM(Protocol):
    def create(self, *, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Any:
        """Return a response with ``.content`` (blocks) and ``.stop_reason``."""


@dataclass
class AgentEvent:
    """Something that happened during a run, for live display."""

    kind: str  # "user" | "tool_call" | "tool_result" | "assistant_text" | "stopped"
    text: str = ""
    tool: str = ""
    tool_input: dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    executed: bool = False


@dataclass
class AgentRun:
    final_text: str
    stop_reason: str
    turns: int
    tool_calls: int
    blocked: int
    messages: list[dict[str, Any]]


def _clip(text: str) -> str:
    if len(text) <= MAX_TOOL_RESULT_CHARS:
        return text
    return text[:MAX_TOOL_RESULT_CHARS] + f"\n[truncated: {len(text) - MAX_TOOL_RESULT_CHARS} more characters]"


def describe_call(name: str, tool_input: dict[str, Any]) -> str:
    """Short human-readable form, e.g. ``read_file('report.txt')``."""
    key = _TOOL_FIELDS.get(name, ("", ()))[0]
    value = tool_input.get(key, "?") if isinstance(tool_input, dict) else "?"
    return f"{name}({value!r})"


def execute_tool_call(guard: PermissionGuard, name: str, tool_input: Any) -> tuple[str, bool, bool, bool]:
    """Run one tool call through the guard.

    Returns ``(text_for_model, is_error, blocked, executed)``.
    """
    if name not in _TOOL_FIELDS:
        return f"Unknown tool '{name}'.", True, False, False
    if not isinstance(tool_input, dict):
        return "Tool input must be a JSON object.", True, False, False

    target_key, param_keys = _TOOL_FIELDS[name]
    target = tool_input.get(target_key)
    if not isinstance(target, str) or not target:
        return f"Missing required string field '{target_key}'.", True, False, False
    params: dict[str, Any] = {}
    for key in param_keys:
        if key not in tool_input:
            return f"Missing required field '{key}'.", True, False, False
        params[key] = tool_input[key]

    result = guard.handle(name, target, **params)
    if result.decision is Decision.DENY and not result.executed:
        return f"Blocked by PermissionGuard: {result.reason}", True, True, False
    if result.error:
        return f"The tool failed: {result.error}", True, False, True
    return _clip(result.output or "(done, no output)"), False, False, True


def run_agent(
    llm: LLM,
    guard: PermissionGuard,
    user_prompt: str,
    *,
    system: str = SYSTEM_PROMPT,
    tools: list[dict[str, Any]] | None = None,
    max_turns: int = MAX_TURNS,
    on_event: Callable[[AgentEvent], None] | None = None,
) -> AgentRun:
    """Drive the model until it stops asking for tools, routing every call through the guard."""
    emit = on_event or (lambda event: None)
    tools = tools if tools is not None else TOOL_DEFINITIONS
    messages: list[dict[str, Any]] = [{"role": "user", "content": user_prompt}]
    emit(AgentEvent("user", user_prompt))

    tool_calls = blocked = 0
    final_text = ""
    stop_reason = "max_turns"
    turns = 0

    for turns in range(1, max_turns + 1):
        response = llm.create(system=system, messages=messages, tools=tools)
        stop_reason = response.stop_reason or "end_turn"

        text = "".join(getattr(b, "text", "") for b in response.content if b.type == "text").strip()
        if text:
            final_text = text
            emit(AgentEvent("assistant_text", text))

        if stop_reason != "tool_use":
            break

        # Echo the assistant turn back unchanged (the API requires thinking blocks to be preserved).
        messages.append({"role": "assistant", "content": response.content})

        results: list[dict[str, Any]] = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            tool_calls += 1
            emit(AgentEvent("tool_call", tool=block.name, tool_input=block.input))
            content, is_error, was_blocked, executed = execute_tool_call(guard, block.name, block.input)
            blocked += was_blocked
            emit(AgentEvent("tool_result", content, tool=block.name, blocked=was_blocked, executed=executed))
            results.append(
                {"type": "tool_result", "tool_use_id": block.id, "content": content, **({"is_error": True} if is_error else {})}
            )
        if not results:  # stop_reason said tool_use but there was nothing to run; do not send an empty user turn
            messages.pop()
            stop_reason = "end_turn"
            break
        # All results of one assistant turn go back in a single user message.
        messages.append({"role": "user", "content": results})
    else:
        stop_reason = "max_turns"

    emit(AgentEvent("stopped", stop_reason))
    return AgentRun(final_text, stop_reason, turns, tool_calls, blocked, messages)
