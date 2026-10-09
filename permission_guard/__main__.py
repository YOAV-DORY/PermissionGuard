"""Tiny command-line entry point: ``python -m permission_guard verify [LOGFILE]``."""

from __future__ import annotations

import argparse
import sys

from .audit import AuditLog


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="permission_guard")
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="check the hash chain of an audit log")
    verify.add_argument("logfile", nargs="?", default="audit.log.jsonl")
    args = parser.parse_args(argv)

    if args.command == "verify":
        log = AuditLog(args.logfile)
        result = log.verify()
        print(result)
        if result.ok and result.entries:
            print(f"last hash: {log.last_hash()}")
        return 0 if result.ok else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
