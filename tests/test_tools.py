from __future__ import annotations

import os
import shlex
import sys
import time
from pathlib import Path

import pytest

from permission_guard import Limits
from permission_guard.tools import (
    LimitExceeded,
    NotARegularFile,
    SandboxViolation,
    _safe_env,
    delete_file,
    read_file,
    run_command,
    write_file,
)

# ---------------------------------------------------------------- basic file operations


def test_read_file(sandbox: Path):
    assert read_file(sandbox, "hello.txt") == "hello world\n"


def test_write_then_read(sandbox: Path):
    msg = write_file(sandbox, "new/file.txt", content="abc")
    assert "3 bytes" in msg
    assert read_file(sandbox, "new/file.txt") == "abc"


def test_write_overwrites_existing_file(sandbox: Path):
    write_file(sandbox, "hello.txt", content="x")
    assert read_file(sandbox, "hello.txt") == "x"


def test_delete_file(sandbox: Path):
    delete_file(sandbox, "hello.txt")
    assert not (sandbox / "hello.txt").exists()


def test_delete_missing_file_raises(sandbox: Path):
    with pytest.raises(FileNotFoundError):
        delete_file(sandbox, "nope.txt")


def test_delete_directory_refused(sandbox: Path):
    with pytest.raises(NotARegularFile):
        delete_file(sandbox, "sub")
    assert (sandbox / "sub").is_dir()


@pytest.mark.parametrize("fn", [read_file, write_file, delete_file])
@pytest.mark.parametrize("target", ["../escape.txt", "/etc/passwd", "a/../../x", "..", "x\x00y"])
def test_tools_refuse_paths_outside_sandbox(sandbox: Path, fn, target):
    with pytest.raises(SandboxViolation):
        fn(sandbox, target)


def test_dot_dot_inside_sandbox_is_normalised(sandbox: Path):
    assert read_file(sandbox, "sub/../hello.txt") == "hello world\n"


# ---------------------------------------------------------------- symlinks (TOCTOU defence)


def test_read_refuses_symlink_to_outside_file(sandbox: Path, tmp_path: Path):
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret")
    (sandbox / "link").symlink_to(secret)
    with pytest.raises(SandboxViolation):
        read_file(sandbox, "link")


def test_read_refuses_symlinked_directory_component(sandbox: Path, tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("top secret")
    (sandbox / "swapped").symlink_to(outside)
    with pytest.raises(SandboxViolation):
        read_file(sandbox, "swapped/secret.txt")


def test_write_refuses_to_create_through_symlinked_directory(sandbox: Path, tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (sandbox / "swapped").symlink_to(outside)
    with pytest.raises(SandboxViolation):
        write_file(sandbox, "swapped/new.txt", content="x")
    assert not (outside / "new.txt").exists()


def test_write_refuses_symlink_target_and_leaves_victim_untouched(sandbox: Path, tmp_path: Path):
    victim = tmp_path / "victim.txt"
    victim.write_text("original")
    (sandbox / "link").symlink_to(victim)
    with pytest.raises(SandboxViolation):
        write_file(sandbox, "link", content="overwritten")
    assert victim.read_text() == "original"


def test_delete_refuses_symlink_component(sandbox: Path, tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.txt"
    victim.write_text("keep me")
    (sandbox / "swapped").symlink_to(outside)
    with pytest.raises(SandboxViolation):
        delete_file(sandbox, "swapped/victim.txt")
    assert victim.exists()


def test_delete_does_not_follow_final_symlink(sandbox: Path, tmp_path: Path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    (sandbox / "link").symlink_to(victim)
    with pytest.raises(NotARegularFile):
        delete_file(sandbox, "link")
    assert victim.exists()


def test_read_refuses_fifo_without_blocking(sandbox: Path):
    os.mkfifo(sandbox / "pipe")
    with pytest.raises(NotARegularFile):
        read_file(sandbox, "pipe")


# ---------------------------------------------------------------- limits


def test_read_over_limit_raises(sandbox: Path):
    (sandbox / "big.txt").write_text("x" * 100)
    with pytest.raises(LimitExceeded):
        read_file(sandbox, "big.txt", limits=Limits(max_read_bytes=10))


def test_read_exactly_at_limit_is_fine(sandbox: Path):
    (sandbox / "edge.txt").write_text("x" * 10)
    assert read_file(sandbox, "edge.txt", limits=Limits(max_read_bytes=10)) == "x" * 10


def test_write_over_limit_raises_and_creates_nothing(sandbox: Path):
    with pytest.raises(LimitExceeded):
        write_file(sandbox, "big.txt", content="x" * 100, limits=Limits(max_write_bytes=10))
    assert not (sandbox / "big.txt").exists()


def test_write_rejects_non_string_content(sandbox: Path):
    with pytest.raises(TypeError):
        write_file(sandbox, "a.txt", content=b"bytes")  # type: ignore[arg-type]


# ---------------------------------------------------------------- run_command


def test_run_command_captures_stdout(sandbox: Path):
    assert run_command(sandbox, "echo hello") == "hello"


def test_run_command_runs_in_sandbox(sandbox: Path):
    assert "hello.txt" in run_command(sandbox, "ls")


def test_run_command_reports_nonzero_exit(sandbox: Path):
    out = run_command(sandbox, "ls does-not-exist")
    assert "[exit" in out


def test_run_command_does_not_use_a_shell(sandbox: Path):
    # Without a shell the pipe is a literal argument, so nothing is chained.
    assert run_command(sandbox, "echo a | echo b") == "a | echo b"


def test_run_command_does_not_expand_variables_or_globs(sandbox: Path):
    assert run_command(sandbox, "echo $HOME '*' ~") == "$HOME * ~"


def test_run_command_empty_raises(sandbox: Path):
    with pytest.raises(ValueError):
        run_command(sandbox, "   ")


def test_run_command_does_not_leak_environment_secrets(sandbox: Path, monkeypatch):
    monkeypatch.setenv("PG_TEST_SECRET", "hunter2")
    out = run_command(sandbox, "printenv")
    assert "hunter2" not in out
    assert "PG_TEST_SECRET" not in out


def test_run_command_stdin_is_closed(sandbox: Path):
    # 'cat' with no args reads stdin; with /dev/null it returns immediately.
    assert run_command(sandbox, "cat", limits=Limits(command_timeout_seconds=3)) == ""


def test_run_command_output_is_capped(sandbox: Path):
    command = f"{shlex.quote(sys.executable)} -c \"print('x' * 5000)\""
    out = run_command(sandbox, command, limits=Limits(max_output_bytes=100))
    assert "[output truncated" in out
    assert out.count("x") == 100


def test_run_command_times_out_and_kills_the_process(sandbox: Path):
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        run_command(sandbox, "sleep 30", limits=Limits(command_timeout_seconds=1))
    assert time.monotonic() - started < 10


def test_run_command_kills_child_processes_on_timeout(sandbox: Path):
    marker = sandbox / "marker.txt"
    script = f"import time, pathlib; time.sleep(2); pathlib.Path({str(marker)!r}).write_text('survived')"
    path = sandbox / "child.py"
    path.write_text(script)
    with pytest.raises(TimeoutError):
        run_command(sandbox, f"{shlex.quote(sys.executable)} child.py", limits=Limits(command_timeout_seconds=1))
    time.sleep(2.5)
    assert not marker.exists()


def test_safe_env_keeps_only_absolute_path_entries(monkeypatch, sandbox: Path):
    monkeypatch.setenv("PATH", f"relative/bin:{os.pathsep}/usr/bin::.:/bin")
    env = _safe_env(sandbox)
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["HOME"] == str(sandbox)
    assert set(env) == {"PATH", "HOME", "LANG"}
