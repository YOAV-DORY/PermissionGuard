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
    background: radial-gradient(1200px 600px at 85% 20%, #1b2a41 0%, #0d1117 60%);
    color: #f0f6fc; font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
    display: flex; align-items: center; padding: 0 56px; gap: 40px; overflow: hidden;
  }
  .left { width: 470px; flex: none; }
  h1 { font-size: 58px; line-height: 1.05; margin: 0 0 14px; letter-spacing: -1px; }
  .tag { font-size: 25px; color: #9fb3c8; margin: 0 0 34px; line-height: 1.3; }
  ul { list-style: none; padding: 0; margin: 0; font-size: 21px; line-height: 1.35; }
  li { margin: 0 0 14px; padding-left: 30px; position: relative; color: #dbe5ee; }
  li::before { content: ""; position: absolute; left: 0; top: 8px; width: 12px; height: 12px; border-radius: 50%; background: #3fb950; }
  li.r::before { background: #f85149; } li.y::before { background: #d29922; }
  .foot { position: absolute; left: 56px; bottom: 34px; font-size: 18px; color: #6e7681; }
  .term { flex: none; width: 700px; filter: drop-shadow(0 18px 40px rgba(0,0,0,.55)); }
  .term img { width: 700px; display: block; }
</style>
<div class="left">
  <h1>PermissionGuard</h1>
  <p class="tag">A permission layer for AI assistants</p>
  <ul>
    <li>allow, deny, or ask a human for every action</li>
    <li class="r">limits what a prompt-injected assistant can do</li>
    <li class="y">tamper-evident audit log, MCP server</li>
  </ul>
</div>
<div class="term"><img src="__SVG__"></div>
<div class="foot">github.com/YOAV-DORY/PermissionGuard &nbsp;·&nbsp; Python 3.11 &nbsp;·&nbsp; MIT</div>
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
        card.write_text(CARD_HTML.replace("__SVG__", svgs["injection"].as_uri()), encoding="utf-8")
        screenshot(chrome, card, OUT / "social-preview.png", 1280, 640, scale=1)

    for png in sorted(OUT.glob("*.png")):
        print(f"wrote {png.relative_to(ROOT)} ({png.stat().st_size // 1024} KiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
