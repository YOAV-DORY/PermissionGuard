"""The assistant loop: every tool call goes through the guard, nothing else does."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from permission_guard import AutoApprover
from permission_guard.assistant import (
    MAX_TOOL_RESULT_CHARS,
    TOOL_DEFINITIONS,
    describe_call,
    execute_tool_call,
    run_agent,
)


@dataclass
class Block:
    type: str
    text: str = ""
    id: str = ""
    name: str = ""
    input: dict[str, Any] = field(default_factory=dict)


@dataclass
class Response:
    content: list[Block]
    stop_reason: str


def tool_use(id: str, name: str, **tool_input: Any) -> Block:
    return Block("tool_use", id=id, name=name, input=tool_input)


class ScriptedLLM:
    """Plays back prepared responses and records every request it receives."""

    def __init__(self, *responses: Response) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, Any]] = []

    def create(self, *, system, messages, tools):
        self.requests.append({"system": system, "messages": [dict(m) for m in messages], "tools": tools})
        return self.responses.pop(0)


def done(text: str = "done") -> Response:
    return Response([Block("text", text=text)], "end_turn")


# ---------------------------------------------------------------- tool definitions


def test_tool_definitions_cover_every_guarded_action():
    assert {t["name"] for t in TOOL_DEFINITIONS} == {"read_file", "write_file", "delete_file", "run_command"}
    for tool in TOOL_DEFINITIONS:
        assert tool["input_schema"]["additionalProperties"] is False
        assert set(tool["input_schema"]["required"]) <= set(tool["input_schema"]["properties"])


def test_describe_call():
    assert describe_call("read_file", {"path": "a.txt"}) == "read_file('a.txt')"
    assert describe_call("run_command", {"command": "ls -la"}) == "run_command('ls -la')"


# ---------------------------------------------------------------- execute_tool_call


def test_allowed_read_returns_file_content(make_guard):
    text, is_error, blocked, executed = execute_tool_call(make_guard(), "read_file", {"path": "hello.txt"})
    assert (text, is_error, blocked, executed) == ("hello world\n", False, False, True)


def test_policy_denial_is_reported_as_blocked_error(make_guard):
    text, is_error, blocked, executed = execute_tool_call(make_guard(), "read_file", {"path": "../secret"})
    assert is_error and blocked and not executed
    assert text.startswith("Blocked by PermissionGuard:")


def test_declined_approval_is_reported_as_blocked(make_guard, sandbox: Path):
    guard = make_guard(approver=AutoApprover(approve=False))
    text, is_error, blocked, executed = execute_tool_call(guard, "delete_file", {"path": "hello.txt"})
    assert is_error and blocked and not executed and "user declined" in text
    assert (sandbox / "hello.txt").exists()


def test_tool_failure_is_an_error_but_not_blocked(make_guard):
    text, is_error, blocked, executed = execute_tool_call(make_guard(), "read_file", {"path": "missing.txt"})
    assert is_error and not blocked and executed
    assert "FileNotFoundError" in text


def test_write_passes_content_through(make_guard, sandbox: Path):
    text, is_error, *_ = execute_tool_call(make_guard(), "write_file", {"path": "n.txt", "content": "hi"})
    assert not is_error
    assert (sandbox / "n.txt").read_text() == "hi"


@pytest.mark.parametrize(
    "name, tool_input",
    [
        ("read_file", {}),
        ("read_file", {"path": ""}),
        ("read_file", {"path": 5}),
        ("write_file", {"path": "a.txt"}),
        ("run_command", {"cmd": "ls"}),
        ("read_file", ["hello.txt"]),
        ("format_disk", {"path": "x"}),
    ],
)
def test_malformed_calls_never_reach_the_guard(make_guard, audit, name, tool_input):
    text, is_error, blocked, executed = execute_tool_call(make_guard(), name, tool_input)
    assert is_error and not executed
    assert audit.read_all() == []


def test_long_results_are_truncated(make_guard, sandbox: Path):
    (sandbox / "long.txt").write_text("x" * (MAX_TOOL_RESULT_CHARS + 500))
    text, *_ = execute_tool_call(make_guard(), "read_file", {"path": "long.txt"})
    assert len(text) < MAX_TOOL_RESULT_CHARS + 100
    assert "truncated" in text


# ---------------------------------------------------------------- the loop


def test_plain_answer_without_tools(make_guard):
    llm = ScriptedLLM(done("hello"))
    run = run_agent(llm, make_guard(), "hi")
    assert (run.final_text, run.stop_reason, run.tool_calls, run.turns) == ("hello", "end_turn", 0, 1)
    assert llm.requests[0]["tools"] == TOOL_DEFINITIONS


def test_tool_roundtrip_feeds_the_result_back(make_guard):
    llm = ScriptedLLM(Response([tool_use("t1", "read_file", path="hello.txt")], "tool_use"), done("it says hello"))
    run = run_agent(llm, make_guard(), "read hello.txt")

    assert run.final_text == "it says hello" and run.tool_calls == 1 and run.blocked == 0
    second = llm.requests[1]["messages"]
    assert [m["role"] for m in second] == ["user", "assistant", "user"]
    assert second[1]["content"][0].id == "t1"  # assistant turn echoed back unchanged
    assert second[2]["content"] == [{"type": "tool_result", "tool_use_id": "t1", "content": "hello world\n"}]


def test_parallel_tool_calls_return_all_results_in_one_user_message(make_guard):
    llm = ScriptedLLM(
        Response(
            [tool_use("a", "read_file", path="hello.txt"), tool_use("b", "read_file", path="../nope")],
            "tool_use",
        ),
        done(),
    )
    run = run_agent(llm, make_guard(), "go")
    results = llm.requests[1]["messages"][2]["content"]
    assert [r["tool_use_id"] for r in results] == ["a", "b"]
    assert "is_error" not in results[0]
    assert results[1]["is_error"] is True and "Blocked" in results[1]["content"]
    assert run.blocked == 1 and run.tool_calls == 2


def test_assistant_turn_with_thinking_blocks_is_echoed_untouched(make_guard):
    thinking = Block("thinking")
    llm = ScriptedLLM(Response([thinking, tool_use("t", "read_file", path="hello.txt")], "tool_use"), done())
    run_agent(llm, make_guard(), "go")
    echoed = llm.requests[1]["messages"][1]["content"]
    assert echoed[0] is thinking


def test_refusal_stops_the_loop(make_guard):
    llm = ScriptedLLM(Response([Block("text", text="I can't help with that.")], "refusal"))
    run = run_agent(llm, make_guard(), "go")
    assert run.stop_reason == "refusal" and run.tool_calls == 0


def test_max_tokens_stops_the_loop(make_guard):
    run = run_agent(ScriptedLLM(Response([Block("text", text="cut off")], "max_tokens")), make_guard(), "go")
    assert run.stop_reason == "max_tokens" and run.final_text == "cut off"


def test_runaway_assistant_is_capped(make_guard):
    endless = [Response([tool_use(f"t{i}", "read_file", path="hello.txt")], "tool_use") for i in range(20)]
    run = run_agent(ScriptedLLM(*endless), make_guard(), "go", max_turns=3)
    assert run.stop_reason == "max_turns" and run.turns == 3 and run.tool_calls == 3


def test_tool_use_stop_reason_without_tool_blocks_does_not_send_an_empty_turn(make_guard):
    llm = ScriptedLLM(Response([Block("text", text="hmm")], "tool_use"))
    run = run_agent(llm, make_guard(), "go")
    assert run.stop_reason == "end_turn"
    assert all(m["role"] != "user" or m["content"] for m in run.messages)


def test_events_are_emitted_in_order(make_guard):
    events = []
    llm = ScriptedLLM(Response([tool_use("t", "read_file", path="hello.txt")], "tool_use"), done("ok"))
    run_agent(llm, make_guard(), "go", on_event=events.append)
    assert [e.kind for e in events] == ["user", "tool_call", "tool_result", "assistant_text", "stopped"]
    assert events[2].executed and not events[2].blocked
