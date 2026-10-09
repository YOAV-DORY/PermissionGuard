"""Policy engine: maps an ActionRequest to allow / deny / ask.

Rules live in a YAML file so behaviour can be changed without touching code.
The engine performs no side effects besides path resolution.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .models import ActionRequest, Decision, PolicyResult

PATH_ACTIONS = ("read_file", "write_file", "delete_file")
COMMAND_ACTION = "run_command"


@dataclass(frozen=True)
class DangerousCommandRule:
    rule_id: str
    pattern: re.Pattern[str]
    reason: str


class PolicyEngine:
    def __init__(self, config: dict[str, Any], sandbox_root: str | Path) -> None:
        self.config = config
        self.sandbox_root = Path(sandbox_root).resolve()
        self.actions: dict[str, dict[str, str]] = config.get("actions", {})
        self.dangerous_commands = [
            DangerousCommandRule(
                rule_id=str(rule.get("id", f"dangerous-{i}")),
                pattern=re.compile(rule["pattern"]),
                reason=str(rule.get("reason", "dangerous command")),
            )
            for i, rule in enumerate(config.get("dangerous_commands", []))
        ]

    @classmethod
    def from_yaml(cls, path: str | Path, sandbox_root: str | Path | None = None) -> "PolicyEngine":
        """Load a policy file. ``sandbox_root`` overrides the value in the file."""
        path = Path(path)
        with path.open("r", encoding="utf-8") as fh:
            config = yaml.safe_load(fh) or {}
        if sandbox_root is None:
            # Relative sandbox_root in the file is interpreted relative to the policy file's project.
            sandbox_root = path.parent.parent / config.get("sandbox_root", "./sandbox")
        return cls(config, sandbox_root)

    # ------------------------------------------------------------------ evaluation

    def evaluate(self, request: ActionRequest) -> PolicyResult:
        if request.action in PATH_ACTIONS:
            return self._evaluate_path_action(request)
        if request.action == COMMAND_ACTION:
            return self._evaluate_command(request)
        return PolicyResult(Decision.DENY, f"unknown action '{request.action}'", "unknown-action")

    def _evaluate_path_action(self, request: ActionRequest) -> PolicyResult:
        target = request.target
        if not target:
            return PolicyResult(Decision.DENY, "empty path", "empty-path")

        if Path(target).is_absolute():
            return PolicyResult(Decision.DENY, f"absolute paths are not allowed: {target}", "absolute-path")

        # resolve() collapses '..' segments and follows symlinks, so a traversal
        # attempt like 'a/../../etc/passwd' ends up outside the sandbox root.
        resolved = (self.sandbox_root / target).resolve()
        if not resolved.is_relative_to(self.sandbox_root):
            return PolicyResult(
                Decision.DENY,
                f"path escapes sandbox ({self.sandbox_root.name}/): {target}",
                "outside-sandbox",
            )

        verdict = self.actions.get(request.action, {}).get("inside_sandbox", "deny")
        decision = Decision(verdict)
        return PolicyResult(
            decision,
            f"{request.action} inside sandbox is '{verdict}' by policy",
            f"{request.action}-inside-sandbox",
        )

    def _evaluate_command(self, request: ActionRequest) -> PolicyResult:
        command = request.target.strip()
        if not command:
            return PolicyResult(Decision.DENY, "empty command", "empty-command")

        for rule in self.dangerous_commands:
            if rule.pattern.search(command):
                return PolicyResult(
                    Decision.DENY,
                    f"dangerous command ({rule.reason})",
                    rule.rule_id,
                )

        verdict = self.actions.get(COMMAND_ACTION, {}).get("default", "ask")
        return PolicyResult(
            Decision(verdict),
            f"command is '{verdict}' by default policy",
            "run_command-default",
        )
