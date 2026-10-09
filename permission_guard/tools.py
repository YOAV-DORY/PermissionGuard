"""Wrapped filesystem and shell operations.

Every tool takes ``sandbox_root`` as its first argument and resolves the target
against it. The policy engine has already verified the path stays inside the
sandbox, but the tools re-check as a second line of defence.

Each function has a plain signature and a docstring so it can later be exposed
directly as an MCP tool (e.g. via FastMCP's ``@mcp.tool()`` decorator).
"""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from typing import Any, Callable

DEFAULT_TIMEOUT_SECONDS = 10


class SandboxViolation(Exception):
    """Raised when a tool is asked to touch a path outside the sandbox."""


def resolve_in_sandbox(sandbox_root: Path, target: str) -> Path:
    """Resolve ``target`` relative to the sandbox and refuse anything that escapes it."""
    root = sandbox_root.resolve()
    candidate = (root / target).resolve()
    if not candidate.is_relative_to(root):
        raise SandboxViolation(f"path escapes sandbox: {target}")
    return candidate


def read_file(sandbox_root: Path, target: str, **_: Any) -> str:
    """Read a UTF-8 text file inside the sandbox and return its contents."""
    path = resolve_in_sandbox(sandbox_root, target)
    return path.read_text(encoding="utf-8")


def write_file(sandbox_root: Path, target: str, content: str = "", **_: Any) -> str:
    """Write ``content`` to a text file inside the sandbox, creating parent dirs."""
    path = resolve_in_sandbox(sandbox_root, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return f"wrote {len(content)} bytes to {target}"


def delete_file(sandbox_root: Path, target: str, **_: Any) -> str:
    """Delete a single file inside the sandbox."""
    path = resolve_in_sandbox(sandbox_root, target)
    if not path.is_file():
        raise FileNotFoundError(f"not a file: {target}")
    path.unlink()
    return f"deleted {target}"


def run_command(
    sandbox_root: Path,
    target: str,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    **_: Any,
) -> str:
    """Run a shell command with the sandbox as working directory.

    The command is split with ``shlex`` and executed without ``shell=True``, so
    shell metacharacters (pipes, redirects) are passed to the program as literal
    arguments rather than interpreted by a shell.
    """
    argv = shlex.split(target)
    if not argv:
        raise ValueError("empty command")
    proc = subprocess.run(
        argv,
        cwd=sandbox_root,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    output = proc.stdout
    if proc.returncode != 0:
        output += f"\n[exit {proc.returncode}] {proc.stderr}"
    return output.strip()


ToolFn = Callable[..., str]

TOOLS: dict[str, ToolFn] = {
    "read_file": read_file,
    "write_file": write_file,
    "delete_file": delete_file,
    "run_command": run_command,
}
