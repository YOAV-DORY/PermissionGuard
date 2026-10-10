"""The path inspector used for command arguments: answers the way the kernel would."""

from __future__ import annotations

from pathlib import Path

import pytest

from permission_guard.paths import first_symlink, inspect_argument_path


@pytest.fixture
def root(tmp_path: Path) -> Path:
    root = (tmp_path / "sandbox").resolve()
    (root / "sub").mkdir(parents=True)
    (root / "hello.txt").write_text("hi")
    (root / "sub" / "nested.txt").write_text("hi")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    (root / "file_link").symlink_to(outside / "secret.txt")
    (root / "dir_link").symlink_to(outside)
    (root / "inner_link").symlink_to(root / "hello.txt")  # points INSIDE, still refused
    return root


@pytest.mark.parametrize(
    "value",
    ["hello.txt", "sub/nested.txt", "sub/../hello.txt", "./hello.txt", "sub//nested.txt", "missing.txt", "sub/missing/deeper", "word", ".", "sub/.."],
)
def test_ordinary_paths_and_plain_words_pass(root, value):
    assert inspect_argument_path(root, value) is None


@pytest.mark.parametrize(
    "value, kind",
    [
        ("file_link", "symlink"),
        ("./file_link", "symlink"),
        ("sub/../file_link", "symlink"),
        ("dir_link", "symlink"),
        ("dir_link/secret.txt", "symlink"),
        ("dir_link/../hello.txt", "symlink"),  # the kernel would resolve '..' inside the linked directory
        ("inner_link", "symlink"),
        ("..", "outside"),
        ("../x", "outside"),
        ("sub/../../x", "outside"),
        ("/etc/passwd", "outside"),
        ("a\x00b", "outside"),
    ],
)
def test_escapes_and_symlinks_are_refused(root, value, kind):
    problem = inspect_argument_path(root, value)
    assert problem is not None and problem[0] == kind


def test_first_symlink(root):
    assert first_symlink(root, "hello.txt") is None
    assert first_symlink(root, "dir_link/secret.txt") == "dir_link"
    assert first_symlink(root, "new/file.txt") is None
