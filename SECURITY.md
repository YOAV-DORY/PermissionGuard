# Security policy

PermissionGuard is a security-focused project, but it is a learning and portfolio project:
it has **not** been independently audited and is not a substitute for OS-level isolation
(containers, VMs, seccomp). Read [THREAT_MODEL.md](THREAT_MODEL.md) for what it defends, what it
does not, and the known limitations (each one has a strict `xfail` test).

## Reporting a vulnerability

Found a way to get a denied action through, escape the sandbox, forge or hide an audit entry, or
approve something without a human? That is exactly the kind of report this project wants.

- Preferred: GitHub's **private vulnerability reporting** (repository **Security** tab, **Report a
  vulnerability**), so a fix can land before details are public.
- For something that is clearly already listed under "Known limitations" in the threat model, or
  that is a hardening idea rather than a bypass, a normal public issue is fine.

A good report includes the policy file, the exact request (command string or path), what the guard
decided, and what you expected. `python -m permission_guard check "<command>"` prints the decision
for a command without running anything, which makes reports easy to reproduce.

## Supported versions

Only the latest commit on `main`.
