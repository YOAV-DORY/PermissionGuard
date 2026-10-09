"""Append-only audit log stored as JSON Lines.

The class deliberately exposes no update or delete methods. The file is opened in
append mode for every write so that a crash between writes never truncates history.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import AuditEntry

COLUMNS = ("timestamp", "action", "target", "decision", "approver", "reason")


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, entry: AuditEntry) -> None:
        line = json.dumps(entry.to_dict(), ensure_ascii=False)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()

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

    def format_table(self) -> str:
        """Render the log as a readable fixed-width table."""
        entries = self.read_all()
        if not entries:
            return "(audit log is empty)"

        rows = [[str(getattr(e, col)) for col in COLUMNS] for e in entries]
        widths = [max(len(col), *(len(r[i]) for r in rows)) for i, col in enumerate(COLUMNS)]

        def fmt(cells: list[str]) -> str:
            return " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells))

        header = fmt(list(COLUMNS))
        sep = "-+-".join("-" * w for w in widths)
        return "\n".join([header, sep, *(fmt(r) for r in rows)])
