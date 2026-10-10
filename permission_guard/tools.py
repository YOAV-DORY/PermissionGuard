"""Wrapped filesystem and shell operations.

Every tool takes ``sandbox_root`` as its first argument and touches files only
through ``openat``-style calls that never follow symlinks:

* the sandbox root is opened once and every path component is opened relative to
  the previous directory descriptor with ``O_NOFOLLOW``;
* so even if a symlink is swapped in *after* the policy checked the path (a
  time-of-check/time-of-use race), the open fails instead of escaping.

``run_command`` runs without a shell, with a scrubbed environment, a timeout and
an output cap. Each function has a plain signature and docstring so it can later
be exposed directly as an MCP tool.
"""

from __future__ import annotations

import errno
import os
import posixpath
import selectors
import shlex
import signal
import stat
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .models import Limits


class SandboxViolation(Exception):
    """Raised when a tool is asked to touch a path outside the sandbox."""


class LimitExceeded(Exception):
    """Raised when a size limit would be exceeded."""


class NotARegularFile(Exception):
    """Raised when a file operation targets a directory, device, FIFO or symlink."""


# ---------------------------------------------------------------- path handling


def _split_target(target: str) -> list[str]:
    """Lexically normalise a sandbox-relative path into components, refusing escapes."""
    if not isinstance(target, str) or not target:
        raise ValueError("empty path")
    if "\x00" in target:
        raise SandboxViolation("NUL byte in path")
    if posixpath.isabs(target):
        raise SandboxViolation(f"absolute path not allowed: {target}")
    norm = posixpath.normpath(target)
    if norm == ".":
        raise ValueError("path refers to the sandbox directory itself")
    if norm == ".." or norm.startswith("../"):
        raise SandboxViolation(f"path escapes sandbox: {target}")
    return norm.split("/")


def _open_parent(root: Path, parts: list[str], create: bool) -> int:
    """Open the directory containing ``parts[-1]`` without following any symlink."""
    dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                try:
                    nxt = os.open(part, flags, dir_fd=dirfd)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(part, 0o755, dir_fd=dirfd)
                    nxt = os.open(part, flags, dir_fd=dirfd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise SandboxViolation(f"symlink or non-directory in path: {part}") from exc
                raise
            os.close(dirfd)
            dirfd = nxt
        return dirfd
    except BaseException:
        os.close(dirfd)
        raise


def _open_file(root: Path, target: str, flags: int, create_parents: bool = False) -> int:
    parts = _split_target(target)
    dirfd = _open_parent(root.resolve(), parts, create_parents)
    try:
        return os.open(parts[-1], flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o644, dir_fd=dirfd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise SandboxViolation(f"symlink not allowed: {target}") from exc
        raise
    finally:
        os.close(dirfd)


def _require_regular(fd: int, target: str) -> None:
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise NotARegularFile(f"not a regular file: {target}")


# ---------------------------------------------------------------- file tools


def read_file(sandbox_root: Path, target: str, *, limits: Limits | None = None, **_: Any) -> str:
    """Read a UTF-8 text file inside the sandbox and return its contents."""
    limits = limits or Limits()
    fd = _open_file(sandbox_root, target, os.O_RDONLY)
    _require_regular(fd, target)
    with os.fdopen(fd, "rb") as fh:
        data = fh.read(limits.max_read_bytes + 1)
    if len(data) > limits.max_read_bytes:
        raise LimitExceeded(f"file is larger than {limits.max_read_bytes} bytes: {target}")
    return data.decode("utf-8", errors="replace")


def write_file(
    sandbox_root: Path, target: str, content: str = "", *, limits: Limits | None = None, **_: Any
) -> str:
    """Write ``content`` to a text file inside the sandbox, creating parent dirs."""
    limits = limits or Limits()
    if not isinstance(content, str):
        raise TypeError("content must be a string")
    data = content.encode("utf-8")
    if len(data) > limits.max_write_bytes:
        raise LimitExceeded(f"content is larger than {limits.max_write_bytes} bytes")

    fd = _open_file(sandbox_root, target, os.O_WRONLY | os.O_CREAT, create_parents=True)
    _require_regular(fd, target)
    with os.fdopen(fd, "wb") as fh:
        fh.truncate(0)
        fh.write(data)
    return f"wrote {len(data)} bytes to {target}"


def delete_file(sandbox_root: Path, target: str, *, limits: Limits | None = None, **_: Any) -> str:
    """Delete a single regular file inside the sandbox (never a directory or symlink)."""
    parts = _split_target(target)
    dirfd = _open_parent(sandbox_root.resolve(), parts, create=False)
    try:
        st = os.stat(parts[-1], dir_fd=dirfd, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode):
            raise NotARegularFile(f"not a regular file: {target}")
        os.unlink(parts[-1], dir_fd=dirfd)
    finally:
        os.close(dirfd)
    return f"deleted {target}"


# ---------------------------------------------------------------- command tool


def _safe_env(sandbox_root: Path) -> dict[str, str]:
    """Environment for child processes: no inherited secrets, only absolute PATH entries."""
    path_entries = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p.startswith("/")]
    return {
        "PATH": os.pathsep.join(path_entries) or "/usr/bin:/bin",
        "HOME": str(sandbox_root),
        "LANG": "C.UTF-8",
    }


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def run_command(sandbox_root: Path, target: str, *, limits: Limits | None = None, **_: Any) -> str:
    """Run one program with the sandbox as working directory and return its output.

    The command is split with ``shlex`` and executed without a shell, so pipes and
    redirects are passed to the program as literal arguments. The child gets a
    scrubbed environment, no stdin, its own process group, a wall-clock timeout and
    a cap on captured output (stdout and stderr are merged).
    """
    limits = limits or Limits()
    argv = shlex.split(target)
    if not argv:
        raise ValueError("empty command")

    proc = subprocess.Popen(
        argv,
        cwd=sandbox_root,
        env=_safe_env(sandbox_root),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )

    deadline = time.monotonic() + limits.command_timeout_seconds
    chunks: list[bytes] = []
    total = 0
    truncated = False
    timed_out = False

    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            if not selector.select(min(remaining, 0.25)):
                continue
            chunk = os.read(proc.stdout.fileno(), 65_536)
            if not chunk:
                break  # EOF: child closed its output
            room = limits.max_output_bytes - total
            chunks.append(chunk[:room])
            total += min(len(chunk), room)
            if len(chunk) > room:
                truncated = True
                break
    finally:
        selector.close()
        if timed_out or truncated or proc.poll() is None:
            _kill_group(proc)
        proc.stdout.close()
        returncode = proc.wait()

    if timed_out:
        raise TimeoutError(f"command timed out after {limits.command_timeout_seconds}s")

    output = b"".join(chunks).decode("utf-8", errors="replace").rstrip()
    if truncated:
        output += f"\n[output truncated at {limits.max_output_bytes} bytes]"
    if returncode != 0 and not truncated:
        output += f"\n[exit {returncode}]"
    return output.strip()


ToolFn = Callable[..., str]

TOOLS: dict[str, ToolFn] = {
    "read_file": read_file,
    "write_file": write_file,
    "delete_file": delete_file,
    "run_command": run_command,
}
