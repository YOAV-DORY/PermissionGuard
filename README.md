# PermissionGuard

A permission middleware that sits between an AI assistant and the tools it wants to use.
Every requested action (read a file, write a file, delete a file, run a command) is
checked against a policy, optionally escalated to a human for approval, executed only
if permitted, and recorded in an append-only audit log.

The AI assistant is simulated in this version. The design is intentionally shaped so the
guard can later be exposed as an [MCP](https://modelcontextprotocol.io/) server.

## Architecture

```
                         +---------------------------------------------+
  +---------------+      |               PermissionGuard               |      +-----------------+
  | AI assistant  | ---> |  guard.py                                   | ---> | tools.py        |
  | (simulated)   |      |                                             |      |  read_file      |
  +---------------+      |   1. policy.evaluate(request)               |      |  write_file     |
        ^                |        |                                    |      |  delete_file    |
        |                |        v                                    |      |  run_command    |
        |                |   +---------+   allow  -> execute           |      +-----------------+
        |                |   | policy  |-- deny   -> block             |
        |                |   |  .py    |   ask    -> 2. approval       |      +-----------------+
        |                |   +---------+              |                | ---> | audit.py        |
        |                |    policies/               v                |      |  audit.log.jsonl|
        |                |    default.yaml     +-------------+         |      |  (append-only)  |
        |                |                     | approval.py | <-------|------|  human (CLI)    |
        |                |                     +-------------+         |      +-----------------+
        |                |   3. every decision -> audit.append(entry)  |
        +--------------- |   4. GuardResult (decision, output, error)  |
                         +---------------------------------------------+
```

Flow for one request:

1. `PolicyEngine.evaluate()` returns `allow`, `deny`, or `ask` with a reason and rule id.
2. `deny` is logged and blocked. `allow` is executed. `ask` is handed to the
   `ApprovalProvider` (a CLI prompt by default) and executed only on approval.
3. Whatever happens, one line is appended to the audit log with timestamp, action,
   target, decision, reason, approver and result.

## Project layout

```
permission_guard/
  models.py      ActionRequest, Decision, PolicyResult, AuditEntry, GuardResult
  policy.py      PolicyEngine: YAML rules -> allow / deny / ask
  tools.py       read_file, write_file, delete_file, run_command (sandbox-bound)
  approval.py    ApprovalProvider protocol, CliApprover (y/n/session), AutoApprover
  audit.py       AuditLog: append-only JSONL + readable table
  guard.py       PermissionGuard: the middleware
policies/default.yaml   the default policy
demo.py                 end-to-end demonstration with a simulated assistant
tests/                  pytest suite (every policy rule + approval flow)
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

(On other platforms replace the interpreter path with whatever `python3.11` resolves to.)

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

## Default policy

Defined in [`policies/default.yaml`](policies/default.yaml).

| Action        | Target                              | Decision |
|---------------|-------------------------------------|----------|
| `read_file`   | inside `./sandbox`                  | allow    |
| `write_file`  | inside `./sandbox`                  | ask      |
| `delete_file` | inside `./sandbox`                  | ask      |
| any file op   | outside `./sandbox` (incl. `..`, absolute paths, symlinks out) | deny |
| `run_command` | matches a dangerous pattern (`rm -rf`, `sudo`, `curl ... \| sh`, writes to `/etc`, `/usr`, ..., `dd of=/dev/`, `mkfs`) | deny |
| `run_command` | anything else                       | ask      |
| unknown action | -                                  | deny     |

Dangerous commands are a list of regexes in the YAML, each with an `id` and a
human-readable `reason` that ends up in the audit log.

## Sample audit log

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
  action : delete_file
  target : notes.txt
  reason : delete_file inside sandbox is 'ask' by policy
  Approve? [y]es / [n]o / [s]ession (approve for rest of session): y
    -> ALLOW / EXECUTED: user approved (delete_file inside sandbox is 'ask' by policy)
    output:
       deleted notes.txt

[3] assistant requests: run_command('rm -rf /')
    -> DENY / BLOCKED: dangerous command (recursive force delete)

========================================================================
Audit log (audit.log.jsonl)
========================================================================
timestamp                 | action      | target    | decision | approver | reason
--------------------------+-------------+-----------+----------+----------+--------------------------------------------------------------
2026-09-20T12:16:43+00:00 | read_file   | notes.txt | allow    | policy   | read_file inside sandbox is 'allow' by policy
2026-09-20T12:16:43+00:00 | delete_file | notes.txt | allow    | user     | user approved (delete_file inside sandbox is 'ask' by policy)
2026-09-20T12:16:43+00:00 | run_command | rm -rf /  | deny     | policy   | dangerous command (recursive force delete)
```

The raw `audit.log.jsonl` behind that table:

```json
{"timestamp": "2026-09-20T12:16:43+00:00", "action": "read_file", "target": "notes.txt", "decision": "allow", "reason": "read_file inside sandbox is 'allow' by policy", "approver": "policy", "result": "ok"}
{"timestamp": "2026-09-20T12:16:43+00:00", "action": "delete_file", "target": "notes.txt", "decision": "allow", "reason": "user approved (delete_file inside sandbox is 'ask' by policy)", "approver": "user", "result": "ok"}
{"timestamp": "2026-09-20T12:16:43+00:00", "action": "run_command", "target": "rm -rf /", "decision": "deny", "reason": "dangerous command (recursive force delete)", "approver": "policy", "result": "blocked"}
```

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

**Path containment by resolution, not string prefix.** Targets are resolved with
`Path.resolve()` against the sandbox root and checked with `is_relative_to()`. This
collapses `..` segments and follows symlinks, so `sub/../../etc/passwd` and a symlink
pointing outside the sandbox are both denied. Absolute paths are rejected outright, even
when they point inside the sandbox, to keep the contract simple: targets are always
sandbox-relative. Tradeoff: `resolve()` touches the filesystem (for symlinks), so the
policy engine is not 100% pure. A TOCTOU race between check and use is still possible;
the tools re-check containment as a second layer.

**Regex denylist for commands.** Simple, transparent, and editable without code changes.
It is also easy to bypass (`r''m -rf`, base64, `$(...)`, aliases). That is acceptable
here because the denylist is a first filter, not the security boundary: every command
that is not denied still requires human approval, and commands run without a shell.

**No `shell=True`.** `run_command` splits the string with `shlex` and passes argv
directly. Pipes and redirects become literal arguments, so `curl x | sh` cannot actually
chain even if a regex misses it. Tradeoff: legitimate shell features do not work; a
later version could opt in per policy.

**Append-only JSONL audit.** One JSON object per line, opened in append mode per write,
flushed immediately. Survives crashes, greps well, streams into any log pipeline, and
needs no database. Tradeoff: no integrity protection. A malicious local process could
edit the file; hash-chaining entries or shipping them to a remote sink is future work.

**`ask` is resolved by an injectable `ApprovalProvider`.** The guard only knows the
protocol `ask(request, reason) -> ApprovalResponse`. `CliApprover` prompts on the
terminal, `AutoApprover` answers deterministically for tests and CI, and an MCP
elicitation-based approver can be dropped in later without touching the guard.

**Session grants are keyed by `(action, target)`.** "Approve for this session" only
covers the identical request. Broader grants (any delete, any command) are convenient but
widen the blast radius; this version keeps the conservative default.

**Policy in YAML, evaluation in code.** The YAML holds data (verdicts, patterns, reasons);
the evaluation order (path containment first, then denylist, then defaults) is fixed in
`policy.py`. This keeps policies readable and avoids inventing a rule DSL for a v1.

**Default deny.** Unknown actions, empty targets and unregistered tools are all denied
and logged rather than raising, so a misbehaving assistant cannot crash the middleware
into an unlogged state.

**MCP readiness.** Tools are plain functions with docstrings and keyword args, the guard
has a transport-agnostic `handle()` method, and approval is pluggable. Wrapping this in a
FastMCP server means registering one `@mcp.tool()` per action that forwards to
`guard.handle()` and returns `GuardResult` fields.

## Future work

- Expose the guard as an MCP server and use MCP elicitation for approval.
- Connect a real LLM tool-calling loop in place of the scripted assistant.
- Hash-chain the audit log for tamper evidence.
- Per-policy option to allow a real shell for `run_command`, with a stricter denylist.
- Broader session grants (per action or per directory) with explicit expiry.
