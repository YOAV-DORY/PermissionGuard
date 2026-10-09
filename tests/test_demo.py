"""Smoke test: the demo script runs end to end in every mode."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from tests.conftest import PROJECT_ROOT


def run_demo(tmp_path: Path, *args: str, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "demo.py"), "--sandbox", str(tmp_path / "sb"), "--audit-file", str(tmp_path / "audit.jsonl"), *args],
        cwd=PROJECT_ROOT,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_demo_auto_approve(tmp_path: Path):
    proc = run_demo(tmp_path, "--auto-approve")
    assert proc.returncode == 0, proc.stderr
    assert "read_file('notes.txt')" in proc.stdout
    assert "ALLOW / EXECUTED: user approved" in proc.stdout
    assert "DENY / BLOCKED: dangerous command" in proc.stdout
    assert "Integrity check: OK" in proc.stdout
    assert not (tmp_path / "sb" / "notes.txt").exists()


def test_demo_auto_deny_keeps_the_file(tmp_path: Path):
    proc = run_demo(tmp_path, "--auto-deny")
    assert proc.returncode == 0, proc.stderr
    assert "user declined" in proc.stdout
    assert (tmp_path / "sb" / "notes.txt").exists()


def test_demo_interactive_yes(tmp_path: Path):
    proc = run_demo(tmp_path, stdin="y\n")
    assert proc.returncode == 0, proc.stderr
    assert "Approve?" in proc.stdout
    assert not (tmp_path / "sb" / "notes.txt").exists()


def test_demo_interactive_no_input_denies(tmp_path: Path):
    proc = run_demo(tmp_path, stdin="")
    assert proc.returncode == 0, proc.stderr
    assert (tmp_path / "sb" / "notes.txt").exists()
