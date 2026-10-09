"""Data models shared across the package."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Decision(str, Enum):
    """Outcome of a policy check."""

    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


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
    """What the policy engine decided and why."""

    decision: Decision
    reason: str
    rule_id: str


@dataclass
class AuditEntry:
    """One line in the audit log. Every field is required for traceability."""

    timestamp: str
    action: str
    target: str
    decision: str
    reason: str
    approver: str
    result: str = ""

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditEntry":
        return cls(**data)


@dataclass
class GuardResult:
    """Returned to the caller (the assistant) after the guard processes a request."""

    decision: Decision
    executed: bool
    reason: str
    output: str = ""
    error: str = ""
