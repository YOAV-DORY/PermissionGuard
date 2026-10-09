#!/usr/bin/env python3
"""End-to-end demonstration of PermissionGuard.

Simulates an AI assistant that tries three actions in order:
  1. read a file inside ./sandbox            -> allowed automatically
  2. delete that file                        -> requires approval
  3. run ``rm -rf /``                        -> denied automatically

No real AI provider is involved; the "assistant" is a scripted list of requests.

Usage:
    python demo.py                 # interactive approval prompt
    python demo.py --auto-approve  # answer "yes" to every prompt (CI / non-interactive)
    python demo.py --auto-deny     # answer "no" to every prompt
"""

from __future__ import annotations

import argparse
from pathlib import Path

from permission_guard import (
    ActionRequest,
    AuditLog,
    AutoApprover,
    CliApprover,
    PermissionGuard,
    PolicyEngine,
)

PROJECT_ROOT = Path(__file__).resolve().parent
POLICY_FILE = PROJECT_ROOT / "policies" / "default.yaml"
SANDBOX = PROJECT_ROOT / "sandbox"
AUDIT_FILE = PROJECT_ROOT / "audit.log.jsonl"
SAMPLE_FILE = "notes.txt"
SAMPLE_CONTENT = "Shopping list:\n- milk\n- eggs\n- bread\n"


def simulated_assistant_actions() -> list[ActionRequest]:
    """The scripted 'assistant'. Replace with a real LLM tool-call loop later."""
    return [
        ActionRequest("read_file", SAMPLE_FILE),
        ActionRequest("delete_file", SAMPLE_FILE),
        ActionRequest("run_command", "rm -rf /"),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--auto-approve", action="store_true", help="approve every prompt without asking")
    mode.add_argument("--auto-deny", action="store_true", help="deny every prompt without asking")
    parser.add_argument("--keep-log", action="store_true", help="append to the existing audit log instead of starting fresh")
    args = parser.parse_args()

    # Fresh state for a repeatable demo.
    SANDBOX.mkdir(exist_ok=True)
    (SANDBOX / SAMPLE_FILE).write_text(SAMPLE_CONTENT, encoding="utf-8")
    if not args.keep_log and AUDIT_FILE.exists():
        AUDIT_FILE.unlink()

    if args.auto_approve:
        approver = AutoApprover(approve=True)
    elif args.auto_deny:
        approver = AutoApprover(approve=False)
    else:
        approver = CliApprover()

    guard = PermissionGuard(
        policy=PolicyEngine.from_yaml(POLICY_FILE, sandbox_root=SANDBOX),
        audit=AuditLog(AUDIT_FILE),
        approver=approver,
    )

    print("=" * 72)
    print("PermissionGuard demo - simulated assistant session")
    print(f"sandbox : {SANDBOX}")
    print(f"policy  : {POLICY_FILE.relative_to(PROJECT_ROOT)}")
    print("=" * 72)

    for i, request in enumerate(simulated_assistant_actions(), start=1):
        print(f"\n[{i}] assistant requests: {request.action}({request.target!r})")
        result = guard.execute(request)
        status = "EXECUTED" if result.executed else "BLOCKED"
        print(f"    -> {result.decision.value.upper()} / {status}: {result.reason}")
        if result.output:
            indented = "\n".join("       " + line for line in result.output.splitlines())
            print(f"    output:\n{indented}")
        if result.error:
            print(f"    error: {result.error}")

    print("\n" + "=" * 72)
    print(f"Audit log ({AUDIT_FILE.relative_to(PROJECT_ROOT)})")
    print("=" * 72)
    print(guard.audit.format_table())


if __name__ == "__main__":
    main()
