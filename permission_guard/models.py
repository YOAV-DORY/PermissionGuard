"""Data models shared across the package."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class Decision(str, Enum):
    """Outcome of a policy check."""

    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


@dataclass(frozen=True)
class Limits:
    """Resource limits enforced by the policy (pre-checks) and the tools (hard stops)."""

    max_read_bytes: int = 1_048_576
    max_write_bytes: int = 1_048_576
    max_output_bytes: int = 65_536
    command_timeout_seconds: int = 10
    max_command_length: int = 4_096


@dataclass(frozen=True)
class ActionRequest:
    """A single action the assistant wants to perform.

    ``action`` is the tool name (read_file, write_file, delete_file, run_command).
    ``target`` is the path or command string. Extra arguments go in ``params``.
    """

    action: str
    target: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyResult:
    """What the policy engine decided and why.

    ``details`` carries facts the approval prompt should show to a human
    (resolved path, parsed argv, content preview). It is not part of equality.
    """

    decision: Decision
    reason: str
    rule_id: str
    details: dict[str, Any] = field(default_factory=dict, compare=False)


@dataclass
class AuditEntry:
    """One line in the audit log.

    ``prev_hash`` and ``hash`` form a hash chain filled in by ``AuditLog.append``;
    callers leave them empty. ``content_sha256`` is covered by that chain.
    """

    timestamp: str
    action: str
    target: str
    decision: str
    reason: str
    approver: str
    result: str = ""
    prev_hash: str = ""
    hash: str = ""
    content_sha256: str = ""  # write_file only: SHA-256 (hex) of the UTF-8 content that was requested

    @staticmethod
    def now() -> str:
        return datetime.now(UTC).isoformat(timespec="seconds")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if not data["content_sha256"]:
            del data["content_sha256"]  # absent on every non-write entry, and on logs written before the field existed
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEntry:
        return cls(**data)


@dataclass
class GuardResult:
    """Returned to the caller (the assistant) after the guard processes a request."""

    decision: Decision
    executed: bool
    reason: str
    output: str = ""
    error: str = ""
