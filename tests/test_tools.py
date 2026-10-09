from __future__ import annotations

from pathlib import Path

import pytest

from permission_guard.tools import (
    SandboxViolation,
    delete_file,
    read_file,
    run_command,
    write_file,
)


def test_read_file(sandbox: Path):
    assert read_file(sandbox, "hello.txt") == "hello world\n"


def test_write_then_read(sandbox: Path):
    msg = write_file(sandbox, "new/file.txt", content="abc")
    assert "3 bytes" in msg
    assert read_file(sandbox, "new/file.txt") == "abc"


def test_delete_file(sandbox: Path):
    delete_file(sandbox, "hello.txt")
    assert not (sandbox / "hello.txt").exists()


def test_delete_missing_file_raises(sandbox: Path):
    with pytest.raises(FileNotFoundError):
        delete_file(sandbox, "nope.txt")


def test_delete_directory_refused(sandbox: Path):
    with pytest.raises(FileNotFoundError):
        delete_file(sandbox, "sub")


@pytest.mark.parametrize("fn", [read_file, write_file, delete_file])
def test_tools_refuse_paths_outside_sandbox(sandbox: Path, fn):
    with pytest.raises(SandboxViolation):
        fn(sandbox, "../escape.txt")


def test_run_command_captures_stdout(sandbox: Path):
    assert run_command(sandbox, "echo hello") == "hello"


def test_run_command_runs_in_sandbox(sandbox: Path):
    out = run_command(sandbox, "ls")
    assert "hello.txt" in out


def test_run_command_reports_nonzero_exit(sandbox: Path):
    out = run_command(sandbox, "ls does-not-exist")
    assert "[exit" in out


def test_run_command_does_not_use_a_shell(sandbox: Path):
    # Without shell=True the pipe is a literal argument, so nothing is chained.
    out = run_command(sandbox, "echo a | echo b")
    assert out == "a | echo b"


def test_run_command_empty_raises(sandbox: Path):
    with pytest.raises(ValueError):
        run_command(sandbox, "   ")
