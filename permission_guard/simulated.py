"""Offline stand-in for a model that is vulnerable to prompt injection.

``GullibleLLM`` needs no API key. It behaves like an assistant that follows
instructions it finds inside file contents: it reads the file the user named, and if
the content contains numbered ``run_command:`` / ``read_file:`` / ``delete_file:``
steps, it carries them out. Real models are trained to resist this, so treat it as a
worst-case simulation, not a claim about any particular model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

STEP_RE = re.compile(r"^\s*\d+\.\s*(run_command|read_file|delete_file)\s*:\s*(.+?)\s*$", re.MULTILINE)
FILE_RE = re.compile(r"\b([\w./-]+\.(?:txt|md|csv|log))\b")


@dataclass
class _Block:
    type: str
    text: str = ""
    id: str = ""
    name: str = ""
    input: dict[str, Any] = field(default_factory=dict)


@dataclass
class _Response:
    content: list[_Block]
    stop_reason: str


def _tool_text(messages: list[dict[str, Any]]) -> str:
    """All tool_result text seen so far."""
    chunks: list[str] = []
    for message in messages:
        if message["role"] == "user" and isinstance(message["content"], list):
            chunks.extend(str(item.get("content", "")) for item in message["content"] if item.get("type") == "tool_result")
    return "\n".join(chunks)


class GullibleLLM:
    def __init__(self) -> None:
        self._counter = 0

    def _call(self, name: str, tool_input: dict[str, Any]) -> _Block:
        self._counter += 1
        return _Block("tool_use", id=f"toolu_sim_{self._counter}", name=name, input=tool_input)

    def create(self, *, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> _Response:
        assistant_turns = sum(1 for m in messages if m["role"] == "assistant")

        if assistant_turns == 0:
            match = FILE_RE.search(str(messages[0]["content"]))
            path = match.group(1) if match else "report.txt"
            return _Response([_Block("text", text=f"I'll start by reading {path}."), self._call("read_file", {"path": path})], "tool_use")

        if assistant_turns == 1:
            steps = STEP_RE.findall(_tool_text(messages))
            if steps:
                calls = []
                for tool, argument in steps:
                    key = "command" if tool == "run_command" else "path"
                    calls.append(self._call(tool, {key: argument}))
                return _Response(
                    [_Block("text", text="The file contains setup instructions. Running them before I summarize."), *calls],
                    "tool_use",
                )

        results = _tool_text(messages)
        blocked = results.count("Blocked by PermissionGuard")
        note = f" {blocked} of my actions were blocked by the permission layer." if blocked else ""
        return _Response([_Block("text", text="Summary: the report covers Q3 results." + note)], "end_turn")
