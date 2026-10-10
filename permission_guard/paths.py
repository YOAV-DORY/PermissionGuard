"""Path inspection shared by the policy and the command analyser.

Two questions are answered the way the *kernel* would answer them, because a command is
executed by a real program, not by our symlink-safe tool wrappers:

* does a sandbox-relative path stay inside the sandbox?
* does it pass through (or end at) a symlink?

Symlinks are never followed: a path that touches one is refused, even if it happens to
point back inside the sandbox.
"""

from __future__ import annotations

from pathlib import Path


def first_symlink(root: Path, normalized: str) -> str | None:
    """Name of the first component of an already-normalised relative path that is a symlink."""
    current = root
    for part in normalized.split("/"):
        current = current / part
        if current.is_symlink():
            return part
        if not current.exists():
            break  # components that do not exist yet cannot be symlinks
    return None


def inspect_argument_path(root: Path, value: str) -> tuple[str, str] | None:
    """Check one command argument as a sandbox-relative path.

    Returns ``None`` if the path stays inside ``root`` and never touches a symlink, otherwise
    ``(kind, component)`` with kind ``"outside"`` or ``"symlink"``.

    ``root`` must already be resolved. The raw string is walked component by component
    *without* normalising it first: a program hands it to the kernel as written, so
    ``link/../x`` really does go through ``link``. A ``..`` is only trusted after every
    earlier component was confirmed not to be a symlink (then the lexical parent is the real
    parent).
    """
    if "\x00" in value or value.startswith("/"):
        return ("outside", value)

    current = root
    for part in value.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            current = current.parent
            if not current.is_relative_to(root):
                return ("outside", part)
            continue
        current = current / part
        if current.is_symlink():
            return ("symlink", part)
        if not current.exists():
            break  # nothing further can resolve; the program will just get "not found"

    try:
        resolved = (root / value).resolve()
    except (OSError, RuntimeError):
        return ("outside", value)
    if not resolved.is_relative_to(root):
        return ("outside", value)
    return None
