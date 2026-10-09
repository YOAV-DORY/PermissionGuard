#!/usr/bin/env python3
"""Generate the animated terminal recordings used in the README.

Each recording runs a real demo script (answering its approval prompt through stdin),
takes its actual output, and renders it as a self-contained animated SVG using only CSS
animations, so it plays inside a GitHub README with no external tools or JavaScript.

Usage:
    python scripts/make_demo_svg.py                           # writes docs/demo.svg and docs/injection.svg
    python scripts/make_demo_svg.py --which injection         # just one of them
    python scripts/make_demo_svg.py --which demo --output x.svg
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Preset:
    script: str
    answer: str          # what the "human" types at the approval prompt
    output: Path
    title: str
    alt: str


PRESETS = {
    "demo": Preset(
        "demo.py", "y", ROOT / "docs" / "demo.svg",
        "PermissionGuard - simulated assistant session",
        "Terminal recording of the PermissionGuard demo: a read is allowed, a delete asks for approval, rm -rf / is denied.",
    ),
    "injection": Preset(
        "demo_injection.py", "n", ROOT / "docs" / "injection.svg",
        "PermissionGuard - prompt injection demo",
        "Terminal recording: an assistant reads a poisoned file and tries to run curl | sh and read an SSH key; the guard blocks both and the human declines the delete.",
    ),
}

FONT_SIZE = 13
CHAR_WIDTH = 7.9
LINE_HEIGHT = 19
PAD_X = 20
TITLE_BAR = 38
PAD_BOTTOM = 18
END_PAUSE = 5.0

PROMPT_TAIL = "(approve for rest of session): "

STYLE = """
  .bg { fill: #0d1117; }
  .bar { fill: #161b22; }
  .t { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "DejaVu Sans Mono", monospace;
       font-size: %(fs)spx; white-space: pre; }
  .title { fill: #8b949e; font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; font-size: 12px; }
  .c-text { fill: #c9d1d9; }
  .c-dim { fill: #6e7681; }
  .c-green { fill: #3fb950; }
  .c-red { fill: #f85149; font-weight: bold; }
  .c-yellow { fill: #d29922; }
  .c-blue { fill: #79c0ff; }
  .c-white { fill: #f0f6fc; font-weight: bold; }
  .l { opacity: 0; }
  @media (prefers-reduced-motion: reduce) { .l { animation: none !important; opacity: 1; } .a { display: none; } }
"""


@dataclass
class Line:
    segments: list[tuple[str, str]]  # (text, css class)
    show: float                       # seconds after loop start
    hide: float | None = None         # seconds, None = stays until the loop restarts
    replaced: bool = False            # True for the "before typing" prompt line
    share_row: bool = False           # True when drawn on the same row as the previous line

    @property
    def length(self) -> int:
        return sum(len(text) for text, _ in self.segments)


# ---------------------------------------------------------------- capturing the real demo


def run_demo(preset: Preset) -> list[str]:
    """Run the real demo script and return the session lines (without banner and audit table)."""
    with tempfile.TemporaryDirectory() as tmp:
        sandbox = Path(tmp) / "sandbox"
        proc = subprocess.run(
            [sys.executable, str(ROOT / preset.script), "--sandbox", str(sandbox), "--audit-file", str(Path(tmp) / "audit.jsonl")],
            input=preset.answer + "\n",
            capture_output=True,
            text=True,
            cwd=ROOT,
            timeout=60,
            check=True,
        )
        out = proc.stdout.replace(str(sandbox.resolve()), "./sandbox").replace(str(sandbox), "./sandbox")

    lines = out.splitlines()
    first = next(i for i, ln in enumerate(lines) if ln.startswith(("user>", "[1]")))
    last = next(i for i, ln in enumerate(lines) if ln.startswith("Audit log"))
    session = lines[first : last - 1]  # drop the "=====" line above "Audit log"
    while session and not session[-1].strip():
        session.pop()
    integrity = next(ln for ln in lines if ln.startswith("Integrity check"))
    result = [ln for ln in lines if ln.startswith("Result:")]
    return session + ["", integrity] + ([""] + result if result else [])


# ---------------------------------------------------------------- styling


def style_line(line: str, in_approval: bool) -> list[tuple[str, str]]:
    if line.startswith("$ "):
        return [("$ ", "c-green"), (line[2:], "c-white")]
    if line.startswith("user> "):
        return [("user> ", "c-green"), (line[6:], "c-white")]
    if line.startswith("assistant> "):
        return [("assistant> ", "c-blue"), (line[11:], "c-text")]
    if line.startswith("Result:"):
        return [(line, "c-green")]
    match = re.match(r"^(\[\d\] assistant requests: )(.*)$", line)
    if match:
        return [(match.group(1), "c-blue"), (match.group(2), "c-white")]
    match = re.match(r"^(\s*)(-> ALLOW / EXECUTED:)(.*)$", line)
    if match:
        return [(match.group(1), "c-text"), (match.group(2), "c-green"), (match.group(3), "c-text")]
    match = re.match(r"^(\s*)(-> DENY / BLOCKED:)(.*)$", line)
    if match:
        return [(match.group(1), "c-text"), (match.group(2), "c-red"), (match.group(3), "c-text")]
    if line.startswith("Integrity check: OK"):
        return [(line, "c-green")]
    if in_approval:
        return [(line, "c-yellow")]
    if line.startswith("    output:") or line.startswith("       "):
        return [(line, "c-dim")]
    return [(line, "c-text")]


def build_lines(session: list[str], command: str, answer: str) -> list[Line]:
    """Turn the captured session into timed lines, with a typed command and a typed answer."""
    out: list[Line] = []
    t = 0.4

    out.append(Line([("$ ", "c-green"), (command, "c-white")], show=t))
    t += 1.0

    in_approval = False
    for raw in session:
        if "Approve?" in raw and PROMPT_TAIL in raw:
            head, _, tail = raw.partition(PROMPT_TAIL)
            prompt = head + PROMPT_TAIL
            waiting = Line(style_line(prompt, True), show=t, replaced=True)
            t += 1.8  # the human thinks
            waiting.hide = t
            out.append(waiting)
            out.append(Line([(prompt, "c-yellow"), (answer, "c-white")], show=t, share_row=True))
            t += 0.6
            in_approval = False
            if tail.strip():
                out.append(Line(style_line(tail, False), show=t))
                t += 0.45
            continue

        if raw.startswith("[approval]"):
            in_approval = True
            t += 0.5
        if re.match(r"^\[\d\] assistant requests:", raw) or raw.startswith(("assistant> ", "Result:")):
            t += 0.7

        if raw.strip():
            out.append(Line(style_line(raw, in_approval), show=t))
            t += 0.38
        else:
            t += 0.15
    return out


# ---------------------------------------------------------------- rendering


def render_svg(lines: list[Line], title: str, alt: str) -> str:
    total = max((ln.show for ln in lines), default=0) + END_PAUSE
    max_chars = max(ln.length for ln in lines)
    width = int(max_chars * CHAR_WIDTH * 1.06 + PAD_X * 2)
    rows: list[int] = []
    for ln in lines:
        rows.append(rows[-1] if ln.share_row else (rows[-1] + 1 if rows else 0))
    height = TITLE_BAR + (rows[-1] + 1) * LINE_HEIGHT + PAD_BOTTOM

    css = [STYLE % {"fs": FONT_SIZE}]
    body: list[str] = []
    for i, (ln, row) in enumerate(zip(lines, rows)):
        p_show = ln.show / total * 100
        keyframes = f"0%,{p_show:.3f}%{{opacity:0}}{p_show + 0.01:.3f}%"
        if ln.hide is not None:
            p_hide = ln.hide / total * 100
            keyframes += f",{p_hide:.3f}%{{opacity:1}}{p_hide + 0.01:.3f}%,100%{{opacity:0}}"
        else:
            keyframes += ",99.5%{opacity:1}100%{opacity:0}"
        css.append(f"  @keyframes k{i} {{{keyframes}}}")
        css.append(f"  .k{i} {{ animation: k{i} {total:.2f}s linear infinite; }}")

        y = TITLE_BAR + (row + 1) * LINE_HEIGHT - 5
        spans = "".join(f'<tspan class="{cls}">{escape(text)}</tspan>' for text, cls in ln.segments)
        classes = f"t l k{i}" + (" a" if ln.replaced else "")
        body.append(f'<text x="{PAD_X}" y="{y}" class="{classes}" xml:space="preserve">{spans}</text>')

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
        f'role="img" aria-label="{escape(alt, {chr(34): "&quot;"})}">\n'
        f"<style>{chr(10).join(css)}\n</style>\n"
        f'<rect class="bg" width="{width}" height="{height}" rx="10"/>\n'
        f'<path class="bar" d="M0 10a10 10 0 0 1 10-10h{width - 20}a10 10 0 0 1 10 10v{TITLE_BAR - 10}H0z"/>\n'
        f'<circle cx="20" cy="19" r="6" fill="#ff5f56"/><circle cx="40" cy="19" r="6" fill="#ffbd2e"/><circle cx="60" cy="19" r="6" fill="#27c93f"/>\n'
        f'<text x="{width // 2}" y="23" text-anchor="middle" class="title">{escape(title)}</text>\n'
        + "\n".join(body)
        + "\n</svg>\n"
    )


def generate(name: str, output: Path | None = None) -> Path:
    preset = PRESETS[name]
    svg = render_svg(build_lines(run_demo(preset), f"python {preset.script}", preset.answer), preset.title, preset.alt)
    target = output or preset.output
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(svg, encoding="utf-8")
    print(f"wrote {target} ({len(svg) // 1024} KiB)")
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--which", choices=[*PRESETS, "all"], default="all")
    parser.add_argument("--output", type=Path, help="output path (only with a single --which)")
    args = parser.parse_args()
    if args.output and args.which == "all":
        parser.error("--output needs --which demo|injection")
    for name in PRESETS if args.which == "all" else [args.which]:
        generate(name, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
