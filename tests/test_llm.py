"""AnthropicLLM through the REAL Anthropic SDK, with the network replaced by a mock transport.

This checks everything on our side of the wire: the request the SDK builds from our
arguments, and how the SDK parses a response and serialises it again when we echo the
assistant turn back. It cannot check what the live API would answer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

anthropic = pytest.importorskip("anthropic")
httpx2 = pytest.importorskip("httpx2")

from permission_guard import AuditLog, AutoApprover, PermissionGuard, PolicyEngine
from permission_guard.assistant import TOOL_DEFINITIONS, run_agent
from permission_guard.llm import DEFAULT_MODEL, FALLBACK_BETA, AnthropicLLM
from tests.conftest import DEFAULT_POLICY


def message(content: list[dict], stop_reason: str, model: str = DEFAULT_MODEL) -> dict:
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }


def client_with(responses: list[dict], seen: list[httpx2.Request]):
    queue = list(responses)

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(200, json=queue.pop(0))

    return anthropic.Anthropic(
        api_key="sk-ant-test-not-real",
        max_retries=0,
        http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(handler)),
    )


@pytest.fixture
def guard(tmp_path: Path) -> PermissionGuard:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / "hello.txt").write_text("hello world\n")
    return PermissionGuard(
        PolicyEngine.from_yaml(DEFAULT_POLICY, sandbox_root=sandbox), AuditLog(tmp_path / "a.jsonl"), AutoApprover()
    )


def test_default_model_is_opus_5_5():
    assert DEFAULT_MODEL == "claude-opus-5-5"


def test_request_shape(guard):
    seen: list[httpx2.Request] = []
    client = client_with([message([{"type": "text", "text": "hi"}], "end_turn")], seen)
    run_agent(AnthropicLLM(client=client, effort="low"), guard, "say hi")

    request = seen[0]
    body = json.loads(request.content)
    assert request.url.path == "/v1/messages"
    assert FALLBACK_BETA in request.headers["anthropic-beta"]
    assert body["model"] == "claude-opus-5-5"
    assert body["fallbacks"] == "default"
    assert body["output_config"] == {"effort": "low"}
    assert body["max_tokens"] == 16_000
    assert [t["name"] for t in body["tools"]] == [t["name"] for t in TOOL_DEFINITIONS]
    assert body["messages"] == [{"role": "user", "content": "say hi"}]
    assert "system" in body and "thinking" not in body and "tool_choice" not in body  # no forced tool use, thinking left to the model


def test_models_without_fallback_support_use_the_plain_endpoint(guard):
    seen: list[httpx2.Request] = []
    client = client_with([message([{"type": "text", "text": "hi"}], "end_turn", "claude-haiku-5-5")], seen)
    run_agent(AnthropicLLM("claude-haiku-5-5", client=client), guard, "hi")
    body = json.loads(seen[0].content)
    assert "fallbacks" not in body and "anthropic-beta" not in seen[0].headers


def test_full_tool_loop_through_the_sdk(guard):
    seen: list[httpx2.Request] = []
    first = message(
        [
            {"type": "thinking", "thinking": "", "signature": "sig-abc"},
            {"type": "text", "text": "Reading it."},
            {"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {"path": "hello.txt"}},
            {"type": "tool_use", "id": "toolu_2", "name": "read_file", "input": {"path": "../../etc/passwd"}},
        ],
        "tool_use",
    )
    final = message([{"type": "text", "text": "It says hello."}], "end_turn")
    client = client_with([first, final], seen)

    run = run_agent(AnthropicLLM(client=client), guard, "read hello.txt")

    assert run.final_text == "It says hello." and run.tool_calls == 2 and run.blocked == 1
    second = json.loads(seen[1].content)["messages"]
    assert [m["role"] for m in second] == ["user", "assistant", "user"]

    echoed = second[1]["content"]
    assert echoed[0]["type"] == "thinking" and echoed[0]["signature"] == "sig-abc"  # thinking block preserved verbatim
    assert [b["type"] for b in echoed] == ["thinking", "text", "tool_use", "tool_use"]

    results = second[2]["content"]
    assert results[0] == {"type": "tool_result", "tool_use_id": "toolu_1", "content": "hello world\n"}
    assert results[1]["tool_use_id"] == "toolu_2" and results[1]["is_error"] is True
    assert "Blocked by PermissionGuard" in results[1]["content"]


def test_refusal_stop_reason_ends_the_run(guard):
    client = client_with([message([{"type": "text", "text": "I can't help with that."}], "refusal")], [])
    run = run_agent(AnthropicLLM(client=client), guard, "do something bad")
    assert run.stop_reason == "refusal" and run.tool_calls == 0


def test_api_errors_propagate_as_sdk_exceptions(guard):
    def handler(request):
        return httpx2.Response(401, json={"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}})

    client = anthropic.Anthropic(
        api_key="sk-ant-bad", max_retries=0, http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(handler))
    )
    with pytest.raises(anthropic.AuthenticationError):
        run_agent(AnthropicLLM(client=client), guard, "hi")
