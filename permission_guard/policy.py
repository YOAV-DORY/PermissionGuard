"""Policy engine: maps an ActionRequest to allow / deny / ask.

Rules live in a YAML file so behaviour can be changed without touching code.
The engine fails closed: an invalid policy file refuses to load, an unknown
action is denied, and a path that cannot be proven to be inside the sandbox is
denied.
"""

from __future__ import annotations

import posixpath
from dataclasses import fields
from pathlib import Path
from typing import Any

import yaml

from .commands import CommandPolicy
from .models import ActionRequest, Decision, Limits, PolicyResult
from .paths import first_symlink

PATH_ACTIONS = ("read_file", "write_file", "delete_file")
COMMAND_ACTION = "run_command"

VERDICTS = {d.value for d in Decision}
TOP_LEVEL_KEYS = {"sandbox_root", "actions", "limits", "commands"}
COMMAND_KEYS = {
    "unknown_program",
    "allowed_programs",
    "subcommands",
    "downloaders",
    "shells",
    "allowed_url_schemes",
    "system_paths",
    "denied_programs",
    "forbidden_options",
}
PREVIEW_CHARS = 200


class PolicyConfigError(ValueError):
    """The policy file is malformed. The engine refuses to start with it."""


# ---------------------------------------------------------------- validation


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyConfigError(message)


def _check_str_list(value: Any, where: str) -> None:
    _require(isinstance(value, list) and all(isinstance(v, str) for v in value), f"{where} must be a list of strings")


def _check_rules(rules: Any, where: str, required: dict[str, str], optional_lists: tuple[str, ...]) -> None:
    _require(isinstance(rules, list), f"{where} must be a list")
    for i, rule in enumerate(rules):
        label = f"{where}[{i}]"
        _require(isinstance(rule, dict), f"{label} must be a mapping")
        for key, kind in required.items():
            _require(key in rule, f"{label} is missing '{key}'")
            if kind == "str":
                _require(isinstance(rule[key], str) and rule[key], f"{label}.{key} must be a non-empty string")
            else:
                _check_str_list(rule[key], f"{label}.{key}")
        for key in optional_lists:
            if key in rule:
                _check_str_list(rule[key], f"{label}.{key}")
        unknown = set(rule) - set(required) - set(optional_lists)
        _require(not unknown, f"{label} has unknown keys: {sorted(unknown)}")


def validate_config(config: Any) -> None:
    """Raise PolicyConfigError unless ``config`` is a well-formed policy."""
    _require(isinstance(config, dict), "policy must be a YAML mapping")
    unknown = set(config) - TOP_LEVEL_KEYS
    _require(not unknown, f"unknown top-level keys: {sorted(unknown)}")

    actions = config.get("actions", {})
    _require(isinstance(actions, dict), "'actions' must be a mapping")
    for name, rule in actions.items():
        _require(name in (*PATH_ACTIONS, COMMAND_ACTION), f"unknown action '{name}' in 'actions'")
        _require(isinstance(rule, dict), f"actions.{name} must be a mapping")
        key = "default" if name == COMMAND_ACTION else "inside_sandbox"
        _require(set(rule) <= {key}, f"actions.{name} may only contain '{key}'")
        if key in rule:
            _require(rule[key] in VERDICTS, f"actions.{name}.{key} must be one of {sorted(VERDICTS)}")

    limits = config.get("limits", {})
    _require(isinstance(limits, dict), "'limits' must be a mapping")
    valid_limits = {f.name for f in fields(Limits)}
    _require(set(limits) <= valid_limits, f"unknown limits: {sorted(set(limits) - valid_limits)}")
    for key, value in limits.items():
        _require(
            isinstance(value, int) and not isinstance(value, bool) and value > 0,
            f"limits.{key} must be a positive integer",
        )

    commands = config.get("commands", {})
    _require(isinstance(commands, dict), "'commands' must be a mapping")
    _require(set(commands) <= COMMAND_KEYS, f"unknown keys in 'commands': {sorted(set(commands) - COMMAND_KEYS)}")
    if "unknown_program" in commands:
        _require(
            commands["unknown_program"] in ("deny", "ask"),
            "commands.unknown_program must be 'deny' or 'ask'",
        )
    for key in ("allowed_programs", "downloaders", "shells", "allowed_url_schemes", "system_paths"):
        if key in commands:
            _check_str_list(commands[key], f"commands.{key}")
    if "subcommands" in commands:
        subs = commands["subcommands"]
        _require(isinstance(subs, dict), "commands.subcommands must be a mapping")
        for prog, allowed in subs.items():
            _check_str_list(allowed, f"commands.subcommands.{prog}")
    if "denied_programs" in commands:
        _check_rules(
            commands["denied_programs"], "commands.denied_programs", {"id": "str", "reason": "str", "names": "list"}, ()
        )
    if "forbidden_options" in commands:
        _check_rules(
            commands["forbidden_options"],
            "commands.forbidden_options",
            {"id": "str", "reason": "str", "programs": "list"},
            ("short", "long"),
        )


def _preview(text: str) -> str:
    if len(text) <= PREVIEW_CHARS:
        return repr(text)
    return repr(text[:PREVIEW_CHARS]) + f" ... (+{len(text) - PREVIEW_CHARS} more characters)"


# ---------------------------------------------------------------- engine


class PolicyEngine:
    def __init__(self, config: dict[str, Any], sandbox_root: str | Path) -> None:
        validate_config(config)
        self.config = config
        self.sandbox_root = Path(sandbox_root).resolve()
        self.actions: dict[str, dict[str, str]] = config.get("actions", {})
        self.limits = Limits(**config.get("limits", {}))
        run_verdict = Decision(self.actions.get(COMMAND_ACTION, {}).get("default", "deny"))
        self.commands = CommandPolicy(config.get("commands", {}), self.sandbox_root, run_verdict, self.limits)

    @classmethod
    def from_yaml(cls, path: str | Path, sandbox_root: str | Path | None = None) -> PolicyEngine:
        """Load a policy file. ``sandbox_root`` overrides the value in the file."""
        path = Path(path)
        try:
            with path.open("r", encoding="utf-8") as fh:
                config = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise PolicyConfigError(f"{path}: invalid YAML: {exc}") from exc
        if config is None:
            raise PolicyConfigError(f"{path}: policy file is empty")
        validate_config(config)
        if sandbox_root is None:
            # A relative sandbox_root in the file is relative to the project (the policy dir's parent).
            sandbox_root = path.parent.parent / config.get("sandbox_root", "./sandbox")
        return cls(config, sandbox_root)

    # ------------------------------------------------------------------ evaluation

    def evaluate(self, request: ActionRequest) -> PolicyResult:
        if request.action in PATH_ACTIONS:
            return self._evaluate_path_action(request)
        if request.action == COMMAND_ACTION:
            if not isinstance(request.target, str):
                return PolicyResult(Decision.DENY, "command must be a string", "invalid-params")
            return self.commands.evaluate(request.target)
        return PolicyResult(Decision.DENY, f"unknown action '{request.action}'", "unknown-action")

    def _evaluate_path_action(self, request: ActionRequest) -> PolicyResult:
        target = request.target
        if not isinstance(target, str) or not target:
            return PolicyResult(Decision.DENY, "empty path", "empty-path")
        if "\x00" in target:
            return PolicyResult(Decision.DENY, "path contains a NUL byte", "invalid-path")
        if posixpath.isabs(target):
            return PolicyResult(Decision.DENY, f"absolute paths are not allowed: {target}", "absolute-path")

        # Lexical check first: 'a/../../x' normalises to '../x'.
        norm = posixpath.normpath(target)
        if norm == ".":
            return PolicyResult(Decision.DENY, "path refers to the sandbox directory itself", "empty-path")
        outside = PolicyResult(
            Decision.DENY, f"path escapes sandbox ({self.sandbox_root.name}/): {target}", "outside-sandbox"
        )
        if norm == ".." or norm.startswith("../"):
            return outside

        # Then resolve for real: a symlink that points outside ends up outside here.
        try:
            resolved = (self.sandbox_root / norm).resolve()
        except (OSError, RuntimeError):
            return PolicyResult(Decision.DENY, f"cannot resolve path: {target}", "unresolvable-path")
        if not resolved.is_relative_to(self.sandbox_root):
            return outside

        link = first_symlink(self.sandbox_root, norm)
        if link:
            return PolicyResult(Decision.DENY, f"symlinks are not allowed in paths: {link}", "symlink-in-path")

        details: dict[str, Any] = {"resolved_path": str(resolved)}
        if request.action == "write_file":
            content = request.params.get("content", "")
            if not isinstance(content, str):
                return PolicyResult(Decision.DENY, "write_file content must be a string", "invalid-params")
            try:
                size = len(content.encode("utf-8"))
            except UnicodeEncodeError:
                return PolicyResult(Decision.DENY, "write_file content is not valid text", "invalid-params")
            if size > self.limits.max_write_bytes:
                return PolicyResult(
                    Decision.DENY,
                    f"content is {size} bytes; limit is {self.limits.max_write_bytes}",
                    "write-too-large",
                )
            details.update(bytes=size, overwrites_existing=resolved.exists(), content_preview=_preview(content))

        verdict = self.actions.get(request.action, {}).get("inside_sandbox", "deny")
        return PolicyResult(
            Decision(verdict),
            f"{request.action} inside sandbox is '{verdict}' by policy",
            f"{request.action}-inside-sandbox",
            details,
        )
