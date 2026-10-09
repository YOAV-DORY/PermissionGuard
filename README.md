# PermissionGuard

A permission middleware that sits between an AI assistant and the tools it wants to use.
Every requested action (read a file, write a file, delete a file, run a command) is
checked against a policy, escalated to a human when the policy says so, executed only
if permitted, and recorded in a tamper-evident audit log.

The AI assistant is simulated in this version. The design is intentionally shaped so the
guard can later be exposed as an [MCP](https://modelcontextprotocol.io/) server.

> Security posture and its honest limits are written down in [THREAT_MODEL.md](THREAT_MODEL.md).
> The test suite includes a red-team file that attacks the guard, and lists the attacks
> that still work as `xfail` tests.

## Architecture

```
                         +---------------------------------------------+
  +---------------+      |               PermissionGuard               |      +-----------------+
  | AI assistant  | ---> |  guard.py                                   | ---> | tools.py        |
  | (simulated)   |      |                                             |      |  read_file      |
  +---------------+      |   1. policy.evaluate(request)               |      |  write_file     |
        ^                |        |                                    |      |  delete_file    |
        |                |        v                                    |      |  run_command    |
        |                |   +---------+   allow  -> 3. audit, run     |      |  (no symlinks,  |
        |                |   | policy  |-- deny   -> audit, block      |      |   no shell,     |
        |                |   |  .py    |   ask    -> 2. approval       |      |   limits)       |
        |                |   +---------+              |                |      +-----------------+
        |                |    commands.py             v                |
        |                |    policies/        +-------------+         |      +-----------------+
        |                |    default.yaml     | approval.py | <-------|------|  human (CLI)    |
        |                |                     +-------------+         |      +-----------------+
        |                |                                             |
        |                |   decision is written BEFORE the tool runs  |      +-----------------+
        |                |   outcome is written AFTER                  | ---> | audit.py        |
        +--------------- |   4. GuardResult (decision, output, error)  |      |  hash-chained   |
                         +---------------------------------------------+      |  JSONL, append  |
                                                                              +-----------------+
```

Flow for one request:

1. `PolicyEngine.evaluate()` returns `allow`, `deny`, or `ask` with a reason and rule id.
   Any exception in the policy counts as `deny`.
2. `ask` is handed to the `ApprovalProvider` (a CLI prompt by default). The prompt shows
   the resolved path, the parsed argv, or a preview of the content to be written.
   A crash or closed stdin counts as "no".
3. For anything that will run, the decision is appended to the audit log **first**. If that
   write fails, the tool does not run. After the tool finishes, an outcome row is appended.
4. Denied requests are logged and never reach a tool.

## Project layout

```
permission_guard/
  models.py      ActionRequest, Decision, Limits, PolicyResult, AuditEntry, GuardResult
  policy.py      PolicyEngine: file rules, config validation, resource limits
  commands.py    run_command analysis: parser, allowlist, option and path-argument rules
  tools.py       read_file, write_file, delete_file, run_command (symlink-proof, limited)
  approval.py    ApprovalProvider protocol, CliApprover (y/n/session), AutoApprover
  audit.py       AuditLog: append-only, hash-chained JSONL + verify + readable table
  guard.py       PermissionGuard: the middleware
  __main__.py    `python -m permission_guard verify` for audit logs
policies/default.yaml   the default policy
demo.py                 end-to-end demonstration with a simulated assistant
THREAT_MODEL.md         what is defended, what is not
tests/                  pytest suite incl. red-team attacks and documented limitations
sandbox/                the only directory the tools may touch
```

## Setup

Python 3.11 is required. On macOS with Homebrew:

```bash
brew install python@3.11
```

Then, from the project root:

```bash
/opt/homebrew/opt/python@3.11/bin/python3.11 -m venv .venv
```

```bash
.venv/bin/pip install -r requirements.txt
```

(On other platforms replace the interpreter path with whatever `python3.11` resolves to.
macOS and Linux are supported; Windows is not.)

## Run

Interactive demo (you will be asked to approve the delete):

```bash
.venv/bin/python demo.py
```

Non-interactive variants:

```bash
.venv/bin/python demo.py --auto-approve
```

```bash
.venv/bin/python demo.py --auto-deny
```

Tests:

```bash
.venv/bin/pytest -v
```

Verify an audit log has not been edited:

```bash
.venv/bin/python -m permission_guard verify audit.log.jsonl
```

## Default policy

Defined in [`policies/default.yaml`](policies/default.yaml). The policy **fails closed**:
anything it does not mention is denied, and a policy file with a typo or bad value refuses
to load.

| Action | Target | Decision |
|---|---|---|
| `read_file` | inside `./sandbox` | allow |
| `write_file` | inside `./sandbox` (content up to 1 MiB) | ask |
| `delete_file` | inside `./sandbox` | ask |
| any file action | outside `./sandbox`: `..` traversal, absolute path, symlink out | deny |
| any file action | path that passes through any symlink | deny |
| `run_command` | dangerous: recursive `rm`, `sudo`/`su`, `curl ... \| sh`, writes to system paths, shells, wrappers (`env`, `xargs`, ...), `dd`/`mkfs`, `chmod`, `ln` | deny |
| `run_command` | needs a shell: `\|`, `;`, `&&`, `>`, `$(...)`, backticks, newlines | deny |
| `run_command` | program not on the allowlist | deny (set `unknown_program: ask` to ask instead) |
| `run_command` | allowlisted program whose arguments stay inside the sandbox | ask |
| `run_command` | a path-like argument outside the sandbox, or a non-http(s) URL | deny |
| unknown action | - | deny |

Note on "every other command requires approval": the first version asked for every command
that was not dangerous. That makes safety depend on a regex list catching every bad
command, so this version is allowlist-first. One line in the YAML (`unknown_program: ask`)
restores the old behaviour.

## Sample run

Output of `printf 'y\n' | .venv/bin/python demo.py`:

```
[1] assistant requests: read_file('notes.txt')
    -> ALLOW / EXECUTED: read_file inside sandbox is 'allow' by policy
    output:
       Shopping list:
       - milk
       - eggs
       - bread

[2] assistant requests: delete_file('notes.txt')

[approval] The assistant wants to perform an action that needs your approval:
  action        : delete_file
  target        : notes.txt
  resolved_path : ./sandbox/notes.txt
  reason        : delete_file inside sandbox is 'ask' by policy
  Approve? [y]es / [n]o / [s]ession (approve for rest of session): y
    -> ALLOW / EXECUTED: user approved (delete_file inside sandbox is 'ask' by policy)
    output:
       deleted notes.txt

[3] assistant requests: run_command('rm -rf /')
    -> DENY / BLOCKED: dangerous command (recursive delete)

========================================================================
Audit log (audit.log.jsonl)
========================================================================
timestamp                 | action      | target    | decision | approver | result     | reason
--------------------------+-------------+-----------+----------+----------+------------+--------------------------------------------------------------
2026-10-09T14:27:09+00:00 | read_file   | notes.txt | allow    | policy   | authorized | read_file inside sandbox is 'allow' by policy
2026-10-09T14:27:09+00:00 | read_file   | notes.txt | allow    | policy   | ok         | execution completed
2026-10-09T14:27:09+00:00 | delete_file | notes.txt | allow    | user     | authorized | user approved (delete_file inside sandbox is 'ask' by policy)
2026-10-09T14:27:09+00:00 | delete_file | notes.txt | allow    | user     | ok         | execution completed
2026-10-09T14:27:09+00:00 | run_command | rm -rf /  | deny     | policy   | blocked    | dangerous command (recursive delete)

Integrity check: OK: 5 entries, hash chain intact
```

Two of the raw lines in `audit.log.jsonl` behind that table (hashes shortened):

```json
{"timestamp": "2026-10-09T14:27:09+00:00", "action": "delete_file", "target": "notes.txt", "decision": "allow", "reason": "user approved (delete_file inside sandbox is 'ask' by policy)", "approver": "user", "result": "authorized", "prev_hash": "afbeb27a71ab...", "hash": "91ba78d0333d..."}
{"timestamp": "2026-10-09T14:27:09+00:00", "action": "run_command", "target": "rm -rf /", "decision": "deny", "reason": "dangerous command (recursive delete)", "approver": "policy", "result": "blocked", "prev_hash": "054c5d49a547...", "hash": "b024b1becf6d..."}
```

Every executed action produces two rows: `authorized` (written before the tool runs) and
`ok` or `error: ...` (written after). Denied actions produce one `blocked` row.
`approver` is `policy` for automatic decisions, `user` for a one-off human answer, and
`session` when the human chose "approve for the rest of this session".

## Using the guard from code

```python
from permission_guard import AuditLog, CliApprover, PermissionGuard, PolicyEngine

guard = PermissionGuard(
    policy=PolicyEngine.from_yaml("policies/default.yaml"),
    audit=AuditLog("audit.log.jsonl"),
    approver=CliApprover(),
)

result = guard.handle("read_file", "notes.txt")
print(result.decision, result.executed, result.output)
```

`guard.handle(action, target, **params)` is the single entry point an MCP server (or any
other transport) would call per tool request.

## Design decisions and tradeoffs

**Allowlist-first for commands, argv not regex.** The command string is parsed the way a
shell would split it, the program name is normalised (case-folded, quotes and escapes
removed, path-qualified programs refused), and the program is judged against an allowlist,
a denylist, and per-program option rules. `r''m -rf /`, `\rm`, `RM`, `/bin/rm`, `env rm`
and `sh -c 'rm ...'` all end in a denial. Tradeoff: a smaller set of usable commands, and
the allowlist needs maintenance. Unknown things are denied, not guessed at.

**No shell, and anything that needs one is denied.** `run_command` executes argv directly,
so `|`, `;` and `>` would be passed to the program as literal arguments, which would be
silently different from what the assistant meant. The policy rejects them up front with a
clear reason so the assistant can retry with one simple command.

**Path arguments are policed too.** `cat /etc/passwd` and `cp x ../../y` fail on the
argument, not on the program name. This also covers `--opt=/path`, glued `-o/path`, and
URL schemes (`file://` is denied).

**Symlinks are refused rather than followed.** The policy rejects any symlink in a path
and the tools open each component with `O_NOFOLLOW` relative to a directory descriptor, so
a symlink swapped in after the policy check (a TOCTOU race) makes the open fail instead
of escaping. Tradeoff: legitimate symlinks inside the sandbox do not work.

**Fail closed.** Bad policy file, policy exception, approver exception, closed stdin,
audit write failure, unregistered tool: all of them end in "denied" or "not executed".

**Write-ahead audit.** The decision is on disk before the tool runs; an action cannot
happen without a record. Tradeoff: two rows per executed action, and a full disk stops
the guard.

**Hash-chained JSONL.** Each entry carries the hash of the previous one, so editing,
deleting, inserting or reordering lines is detected by `verify`. It is tamper evidence,
not tamper proof: someone who can rewrite the whole file can recompute the chain, and
dropped tail entries are only visible if you saved `last_hash()` elsewhere. Details in
[THREAT_MODEL.md](THREAT_MODEL.md).

**Approval shows what you are approving.** Resolved absolute path, parsed argv, and a
content preview for writes, so "yes" is informed. `ask` is resolved by an injectable
`ApprovalProvider`: `CliApprover` for terminals, `AutoApprover` for tests, and later an
MCP-based approver, without changing the guard.

**Session grants are keyed by `(action, target)`.** "Approve for this session" covers
only the identical request. Broader grants widen the blast radius, so v1 keeps it narrow.

**Policy in YAML, evaluation in code, validated on load.** The YAML holds data (verdicts,
program lists, limits, reasons); the order of checks is fixed in code. Unknown keys are
errors, so a typo cannot silently weaken the policy.

**Honest limits.** Allowed interpreters can still run arbitrary scripts after approval,
network programs can exfiltrate, and this is a policy-level sandbox, not an OS jail.
These are listed, each with an `xfail` test, in [THREAT_MODEL.md](THREAT_MODEL.md).

**MCP readiness.** Tools are plain functions, the guard has a transport-agnostic
`handle()`, and approval is pluggable. Wrapping this in a FastMCP server means registering
one tool per action that forwards to `guard.handle()`. One caveat for later: an MCP stdio
server cannot prompt on stdin, so approval must go through MCP elicitation or another channel.

## Future work

- Connect a real LLM tool-calling loop in place of the scripted assistant, with a
  prompt-injection demo.
- Expose the guard as an MCP server and use MCP elicitation for approval.
- Sign audit entries with a key held elsewhere to close the full-rewrite gap.
- CI, a demo recording, and a `permission-guard check "<command>"` dry-run command.
- Per-policy glob rules, rate limits, and expiring session grants.
