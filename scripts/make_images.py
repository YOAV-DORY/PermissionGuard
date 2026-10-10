#!/usr/bin/env python3
"""Generate the PNG images used for the GitHub social preview and for posts.

Uses a locally installed Chrome/Chromium in headless mode, so the result renders exactly like a
browser (and like GitHub). Not part of CI, because it needs a browser; the PNGs are committed.

    python scripts/make_images.py
        docs/images/social-preview.png   1280x640, the repository's social preview card
        docs/images/injection.png        terminal recording of the prompt-injection demo, final frame, 2x
        docs/images/demo.png             terminal recording of the basic demo, final frame, 2x
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_demo_svg

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "images"

CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome",
    "chromium",
    "chromium-browser",
]

CARD_HTML = """<!doctype html><meta charset="utf-8">
<style>
  * { box-sizing: border-box; }
  html, body { margin: 0; width: 1280px; height: 640px; }
  body {
    position: relative; overflow: hidden; color: #f0f6fc;
    font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
    background: radial-gradient(900px 560px at 72% 48%, #1a2433 0%, #0d1117 68%);
  }
  .left { position: absolute; left: 64px; top: 0; bottom: 0; width: 500px; display: flex; flex-direction: column; justify-content: center; }
  h1 { font-size: 58px; line-height: 1.02; margin: 0 0 18px; letter-spacing: -1.2px; }
  .tag { font-size: 28px; color: #9fb3c8; margin: 0 0 30px; line-height: 1.3; }
  .sub { font-size: 21px; color: #6e7f91; line-height: 1.45; margin: 0; max-width: 440px; }
  .foot { position: absolute; left: 64px; bottom: 38px; font-size: 19px; color: #6e7681; }

  /* traffic light */
  .pole { position: absolute; left: 636px; top: 520px; width: 28px; height: 140px; background: linear-gradient(90deg, #1b2230, #2a3446 45%, #1b2230); border-radius: 4px; }
  .housing {
    position: absolute; left: 596px; top: 56px; width: 108px; height: 480px; border-radius: 34px;
    background: linear-gradient(160deg, #222c3c, #131a26); border: 3px solid #2f3b50;
    box-shadow: 0 24px 60px rgba(0,0,0,.55), inset 0 2px 0 rgba(255,255,255,.06);
  }
  .lamp { position: absolute; left: 14px; width: 74px; height: 74px; border-radius: 50%; }
  .lamp::after { content: ""; position: absolute; left: 14px; top: 9px; width: 26px; height: 15px; border-radius: 50%; background: rgba(255,255,255,.35); transform: rotate(-25deg); }
  .l-red    { top: 28px;  background: radial-gradient(circle at 50% 40%, #ff7b72, #f85149 60%, #c4302b); box-shadow: 0 0 34px 8px rgba(248,81,73,.55); }
  .l-yellow { top: 202px; background: radial-gradient(circle at 50% 40%, #f2cc60, #d29922 60%, #a67618); box-shadow: 0 0 34px 8px rgba(210,153,34,.5); }
  .l-green  { top: 376px; background: radial-gradient(circle at 50% 40%, #56d364, #3fb950 60%, #2a8a3c); box-shadow: 0 0 34px 8px rgba(63,185,80,.5); }

  .row { position: absolute; left: 748px; width: 486px; height: 150px; display: flex; flex-direction: column; justify-content: center; }
  .r1 { top: 76px; } .r2 { top: 250px; } .r3 { top: 424px; }
  .verdict { font-size: 15px; font-weight: 800; letter-spacing: 3px; margin: 0 0 5px; }
  .what { font-size: 25px; font-weight: 700; margin: 0 0 12px; }
  .red .verdict { color: #ff7b72; } .yellow .verdict { color: #f2cc60; } .green .verdict { color: #56d364; }
  .pills { display: flex; flex-wrap: wrap; gap: 7px; }
  .pills span {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 16px;
    padding: 5px 10px; border-radius: 8px; background: rgba(255,255,255,.06); border: 1px solid rgba(255,255,255,.1); color: #dbe5ee;
  }
  .red .pills span { border-color: rgba(248,81,73,.45); } .yellow .pills span { border-color: rgba(210,153,34,.45); } .green .pills span { border-color: rgba(63,185,80,.45); }
</style>

<div class="left">
  <h1>PermissionGuard</h1>
  <p class="tag">A permission layer for AI assistants</p>
  <p class="sub">Every action an AI takes is allowed, sent to a human, or denied. All of it goes into a tamper-evident log.</p>
</div>

<div class="pole"></div>
<div class="housing">
  <div class="lamp l-red"></div>
  <div class="lamp l-yellow"></div>
  <div class="lamp l-green"></div>
</div>

<div class="row r1 red">
  <p class="verdict">DENY</p>
  <p class="what">Blocked by policy</p>
  <div class="pills"><span>rm -rf /</span><span>curl ... | sh</span><span>../../.ssh/id_rsa</span></div>
</div>
<div class="row r2 yellow">
  <p class="verdict">ASK</p>
  <p class="what">A human decides</p>
  <div class="pills"><span>delete_file</span><span>write_file</span><span>run_command</span></div>
</div>
<div class="row r3 green">
  <p class="verdict">ALLOW</p>
  <p class="what">Safe and in the sandbox</p>
  <div class="pills"><span>read_file report.txt</span></div>
</div>

<div class="foot">github.com/YOAV-DORY/PermissionGuard &nbsp;·&nbsp; Python 3.11</div>
"""


def find_chrome() -> str:
    for candidate in CHROME_CANDIDATES:
        path = shutil.which(candidate) or (candidate if Path(candidate).exists() else None)
        if path:
            return path
    sys.exit("No Chrome/Chromium found. Install Google Chrome to regenerate the PNGs.")


def screenshot(chrome: str, html: Path, out: Path, width: int, height: int, scale: int, transparent: bool = False) -> None:
    cmd = [
        chrome,
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        f"--window-size={width},{height}",
        f"--force-device-scale-factor={scale}",
        f"--screenshot={out}",
    ]
    if transparent:
        cmd.append("--default-background-color=00000000")
    cmd.append(html.as_uri())
    subprocess.run(cmd, check=True, capture_output=True, timeout=120)


def svg_size(svg: Path) -> tuple[int, int]:
    head = svg.read_text(encoding="utf-8")[:400]
    match = re.search(r'width="(\d+)" height="(\d+)"', head)
    assert match, "SVG has no explicit size"
    return int(match.group(1)), int(match.group(2))


def main() -> int:
    chrome = find_chrome()
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        svgs = {name: make_demo_svg.generate(name, tmp / f"{name}.svg", static=True) for name in make_demo_svg.PRESETS}

        for name, svg in svgs.items():
            width, height = svg_size(svg)
            page = tmp / f"{name}.html"
            page.write_text(
                f'<!doctype html><meta charset="utf-8"><body style="margin:0;background:transparent">'
                f'<img src="{svg.as_uri()}" style="display:block">',
                encoding="utf-8",
            )
            screenshot(chrome, page, OUT / f"{name}.png", width, height, scale=2, transparent=True)

        card = tmp / "card.html"
        card.write_text(CARD_HTML, encoding="utf-8")
        screenshot(chrome, card, OUT / "social-preview.png", 1280, 640, scale=1)

    for png in sorted(OUT.glob("*.png")):
        print(f"wrote {png.relative_to(ROOT)} ({png.stat().st_size // 1024} KiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
