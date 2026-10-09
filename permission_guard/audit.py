"""Append-only, hash-chained audit log stored as JSON Lines.

The class exposes no update or delete methods. Each entry stores the SHA-256 of
the previous entry (``prev_hash``) and its own hash (``hash``), so editing,
removing, inserting or reordering any line in the middle of the file is
detected by ``verify()``.

Limit: someone who can rewrite the whole file can recompute the whole chain, and
removing lines from the very end cannot be detected from the file alone. To catch
that, record ``last_hash()`` somewhere the attacker cannot write (see THREAT_MODEL.md).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

try:  # fcntl is POSIX-only; without it we simply skip cross-process locking.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

from .models import AuditEntry

GENESIS_HASH = "0" * 64
COLUMNS = ("timestamp", "action", "target", "decision", "approver", "result", "reason")
MAX_CELL_WIDTH = 72
_TAIL_CHUNK = 64 * 1024


class AuditError(Exception):
    """The audit log cannot be written safely (corrupt, unreadable, disk error)."""


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    entries: int
    error: str = ""
    line: int | None = None

    def __str__(self) -> str:
        if self.ok:
            return f"OK: {self.entries} entries, hash chain intact"
        where = f" (line {self.line})" if self.line else ""
        return f"FAILED{where}: {self.error}"


def _payload(entry: AuditEntry) -> dict[str, Any]:
    """The part of an entry covered by its hash: everything except ``hash`` itself."""
    data = entry.to_dict()
    data.pop("hash", None)
    data.pop("prev_hash", None)
    return data


def compute_hash(prev_hash: str, entry: AuditEntry) -> str:
    canonical = json.dumps(_payload(entry), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev_hash + "\n" + canonical).encode("utf-8")).hexdigest()


def _truncate(text: str) -> str:
    return text if len(text) <= MAX_CELL_WIDTH else text[: MAX_CELL_WIDTH - 1] + "…"


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ writing

    def append(self, entry: AuditEntry) -> AuditEntry:
        """Seal ``entry`` into the chain, write it, and return the sealed copy.

        Raises AuditError if the file cannot be written or its tail is corrupt.
        Callers (the guard) treat that as "do not execute the action".
        """
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
        except OSError as exc:
            raise AuditError(f"cannot open audit log: {exc}") from exc

        with os.fdopen(fd, "a+b") as fh:
            try:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                prev_hash = self._tail_hash(fh)
                sealed = replace(entry, prev_hash=prev_hash, hash="")
                sealed = replace(sealed, hash=compute_hash(prev_hash, sealed))
                line = json.dumps(sealed.to_dict(), ensure_ascii=False) + "\n"
                fh.write(line.encode("utf-8"))
                fh.flush()
                os.fsync(fh.fileno())
            except AuditError:
                raise
            except OSError as exc:
                raise AuditError(f"cannot write audit log: {exc}") from exc
        return sealed

    def _tail_hash(self, fh) -> str:
        """Return the hash of the last entry, reading only the end of the file."""
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        if size == 0:
            return GENESIS_HASH

        chunk = _TAIL_CHUNK
        while True:
            start = max(0, size - chunk)
            fh.seek(start)
            data = fh.read(size - start)
            if not data.endswith(b"\n"):
                raise AuditError("audit log does not end with a newline (partial write?); run verify")
            lines = data.splitlines()
            if start > 0:
                lines = lines[1:]  # first line of the chunk may be cut in half
            lines = [ln for ln in lines if ln.strip()]
            if lines or start == 0:
                break
            chunk *= 2

        if not lines:
            return GENESIS_HASH
        try:
            last = json.loads(lines[-1])
            tail_hash = last["hash"]
        except (ValueError, KeyError, TypeError) as exc:
            raise AuditError("last audit entry is malformed; run verify") from exc
        if not isinstance(tail_hash, str) or not tail_hash:
            raise AuditError("last audit entry has no hash; run verify")
        return tail_hash

    # ------------------------------------------------------------------ reading

    def read_all(self) -> list[AuditEntry]:
        if not self.path.exists():
            return []
        entries: list[AuditEntry] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if raw:
                    entries.append(AuditEntry.from_dict(json.loads(raw)))
        return entries

    def last_hash(self) -> str:
        """Hash of the newest entry. Anchor this externally to detect tail truncation."""
        if not self.path.exists():
            return GENESIS_HASH
        with self.path.open("rb") as fh:
            return self._tail_hash(fh)

    def verify(self) -> VerifyResult:
        """Check the whole chain. Never raises on a damaged file; reports it instead."""
        if not self.path.exists():
            return VerifyResult(ok=True, entries=0)

        prev_hash = GENESIS_HASH
        count = 0
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, start=1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    entry = AuditEntry.from_dict(json.loads(raw))
                except (ValueError, TypeError):
                    return VerifyResult(False, count, "malformed entry", lineno)
                if entry.prev_hash != prev_hash:
                    return VerifyResult(False, count, "chain broken: an entry was removed, inserted or reordered", lineno)
                if compute_hash(prev_hash, entry) != entry.hash:
                    return VerifyResult(False, count, "entry was modified after it was written", lineno)
                prev_hash = entry.hash
                count += 1
        return VerifyResult(ok=True, entries=count)

    def format_table(self) -> str:
        """Render the log as a readable fixed-width table."""
        entries = self.read_all()
        if not entries:
            return "(audit log is empty)"

        rows = [[_truncate(str(getattr(e, col))) for col in COLUMNS] for e in entries]
        widths = [max(len(col), *(len(r[i]) for r in rows)) for i, col in enumerate(COLUMNS)]

        def fmt(cells: list[str]) -> str:
            return " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells)).rstrip()

        header = fmt(list(COLUMNS))
        sep = "-+-".join("-" * w for w in widths)
        return "\n".join([header, sep, *(fmt(r) for r in rows)])
