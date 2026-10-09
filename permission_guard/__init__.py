"""PermissionGuard: a policy-enforcing middleware between an AI assistant and computer tools.

Public API:
    PermissionGuard  - the middleware entry point
    PolicyEngine     - decides allow / deny / ask per action
    AuditLog         - append-only JSONL log of every decision
    CliApprover      - interactive command-line approval flow
"""

from .approval import AutoApprover, CliApprover
from .audit import AuditLog
from .guard import PermissionGuard
from .models import ActionRequest, AuditEntry, Decision, GuardResult, PolicyResult
from .policy import PolicyEngine

__all__ = [
    "ActionRequest",
    "AuditEntry",
    "AuditLog",
    "AutoApprover",
    "CliApprover",
    "Decision",
    "GuardResult",
    "PermissionGuard",
    "PolicyEngine",
    "PolicyResult",
]
