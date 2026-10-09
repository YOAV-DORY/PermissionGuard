"""PermissionGuard: a policy-enforcing middleware between an AI assistant and computer tools.

Public API:
    PermissionGuard  - the middleware entry point
    PolicyEngine     - decides allow / deny / ask per action
    AuditLog         - append-only, hash-chained JSONL log of every decision
    CliApprover      - interactive command-line approval flow
"""

from .approval import AutoApprover, CliApprover
from .audit import AuditError, AuditLog, VerifyResult
from .guard import PermissionGuard
from .models import ActionRequest, AuditEntry, Decision, GuardResult, Limits, PolicyResult
from .policy import PolicyConfigError, PolicyEngine

__all__ = [
    "ActionRequest",
    "AuditEntry",
    "AuditError",
    "AuditLog",
    "AutoApprover",
    "CliApprover",
    "Decision",
    "GuardResult",
    "Limits",
    "PermissionGuard",
    "PolicyConfigError",
    "PolicyEngine",
    "PolicyResult",
    "VerifyResult",
]
