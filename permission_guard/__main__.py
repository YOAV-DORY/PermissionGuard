"""Command-line tools.

    python -m permission_guard check "rm -rf /"           what would the policy say? (nothing is executed)
    python -m permission_guard check --action read_file ../../etc/passwd
    python -m permission_guard verify audit.log.jsonl      has the audit log been tampered with?
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import AuditLog
from .models import ActionRequest, Decision
from .policy import PolicyConfigError, PolicyEngine

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ACTIONS = ("run_command", "read_file", "write_file", "delete_file")


def cmd_verify(args: argparse.Namespace) -> int:
    log = AuditLog(args.logfile)
    result = log.verify()
    print(result)
    if result.ok and result.entries:
        print(f"last hash: {log.last_hash()}")
    return 0 if result.ok else 1


def cmd_check(args: argparse.Namespace) -> int:
    """Dry run: evaluate one request against the policy. Never executes anything, never writes the audit log."""
    try:
        engine = PolicyEngine.from_yaml(args.policy, sandbox_root=args.sandbox)
    except (PolicyConfigError, OSError) as exc:
        print(f"cannot load policy: {exc}", file=sys.stderr)
        return 2

    params = {"content": args.content} if args.action == "write_file" else {}
    result = engine.evaluate(ActionRequest(args.action, args.target, params))

    if args.json:
        print(
            json.dumps(
                {
                    "decision": result.decision.value,
                    "rule": result.rule_id,
                    "reason": result.reason,
                    "details": result.details,
                },
                indent=2,
                default=str,
            )
        )
    else:
        print(f"{result.decision.value.upper():<5}  {result.rule_id}")
        print(f"       {result.reason}")
        if "argv" in result.details:
            print(f"       parsed as: {result.details['argv']}")
        if "resolved_path" in result.details:
            print(f"       resolves to: {result.details['resolved_path']}")
        if result.decision is Decision.ASK:
            print("       (a human would be asked before this runs)")
    return 1 if result.decision is Decision.DENY else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="permission_guard")
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="check the hash chain of an audit log")
    verify.add_argument("logfile", nargs="?", default="audit.log.jsonl")
    verify.set_defaults(func=cmd_verify)

    check = sub.add_parser(
        "check",
        help="dry run: show what the policy decides for a command or path (exit code 1 on deny)",
        description="Evaluate one request against the policy without executing it.",
    )
    check.add_argument("target", help="the command line, or a sandbox-relative path with --action")
    check.add_argument("--action", choices=ACTIONS, default="run_command")
    check.add_argument("--content", default="", help="file content, for --action write_file")
    check.add_argument("--policy", type=Path, default=PROJECT_ROOT / "policies" / "default.yaml")
    check.add_argument("--sandbox", type=Path, default=PROJECT_ROOT / "sandbox")
    check.add_argument("--json", action="store_true", help="machine-readable output")
    check.set_defaults(func=cmd_check)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
