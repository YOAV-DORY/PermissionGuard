from __future__ import annotations

from pathlib import Path

import pytest

from permission_guard import AuditLog, AutoApprover, PermissionGuard, PolicyEngine

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = PROJECT_ROOT / "policies" / "default.yaml"


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    root = tmp_path / "sandbox"
    root.mkdir()
    (root / "hello.txt").write_text("hello world\n", encoding="utf-8")
    (root / "sub").mkdir()
    (root / "sub" / "nested.txt").write_text("nested\n", encoding="utf-8")
    return root


@pytest.fixture
def policy(sandbox: Path) -> PolicyEngine:
    return PolicyEngine.from_yaml(DEFAULT_POLICY, sandbox_root=sandbox)


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture
def make_guard(policy: PolicyEngine, audit: AuditLog, sandbox: Path):
    """Factory so tests can choose the approver."""

    def _make(approver=None, tools=None) -> PermissionGuard:
        return PermissionGuard(
            policy=policy,
            audit=audit,
            approver=approver or AutoApprover(approve=True),
            sandbox_root=sandbox,
            tools=tools,
        )

    return _make
