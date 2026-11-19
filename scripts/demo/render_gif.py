"""Renders the README demo GIF from a recorded transcript (a developer tool, not part of hn).

    python scripts/demo/render_gif.py [--transcript scripts/demo/transcript.json] [--out docs/demo.gif]

The transcript is what a real `hn` run printed (see record.ts). This only draws it as a terminal: it types the
person's side, reveals output line by line, pauses on each approval card, and adds a caption naming what is shown.
Nothing on screen is invented here. It needs Pillow and a monospace font (Consolas, DejaVu Sans Mono or Courier New).
"""

from __future__ import annotations

import argparse
import json
import re
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]

BG = (14, 17, 22)
BAR = (28, 33, 40)
FG = (230, 237, 243)
DIM = (139, 148, 158)
GREEN = (63, 185, 80)
AMBER = (240, 180, 60)
CYAN = (88, 166, 255)
RED = (248, 81, 73)
CAPTION_BG = (22, 27, 34)

COLS, ROWS, FONT_SIZE = 94, 25, 16
PAD, BAR_H, CAPTION_H = 14, 34, 34
FONT_CANDIDATES = [
    "C:/Windows/Fonts/consola.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
    "C:/Windows/Fonts/cour.ttf",
]

CAPTIONS = [
    ("A task, in a box hn has verified", GREEN),
    ("An approval card: you see the exact change before it happens", AMBER),
    ("A refused escape: a path outside the project is blocked", RED),
    ("From inside the box, the host's file is out of reach", RED),
    ("Your changes come back to your project when you leave the box", GREEN),
]


def load_font(size: int) -> ImageFont.FreeTypeFont:
    for candidate in FONT_CANDIDATES:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size)
    raise SystemExit("No monospace font found; install DejaVu Sans Mono or use Windows or macOS.")


def colour(line: str) -> tuple[int, int, int]:
    if line.startswith("Sandboxed:"):
        return GREEN
    if line.startswith("\u258c"):
        return AMBER
    if re.search(r"Blocked:|Access is denied", line):
        return RED
    if re.search(r"\bok: ", line):
        return GREEN
    if re.match(r"\[[a-z_]+\]$", line):
        return CYAN
    if line.startswith(("[done]", "context ~", "[dream]", "mode safe")):
        return DIM
    return FG


class Screen:
    """The terminal's lines, as (text, colour) rows, wrapped to the width."""

    def __init__(self) -> None:
        self.rows: list[tuple[str, tuple[int, int, int]]] = []
        self.current = ""

    def _wrap(self, text: str) -> list[str]:
        return textwrap.wrap(text, COLS, replace_whitespace=False, drop_whitespace=False, break_long_words=True) or [""]

    def feed(self, text: str) -> None:
        self.current += text.replace("\r", "")

    def newline(self) -> None:
        for part in self._wrap(self.current):
            self.rows.append((part, colour(self.current)))
        self.current = ""

    def visible(self) -> list[tuple[str, tuple[int, int, int]]]:
        live = [(part, colour(self.current)) for part in self._wrap(self.current)] if self.current != "" else []
        return (self.rows + live)[-ROWS:]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transcript", default=str(ROOT / "scripts" / "demo" / "transcript.json"))
    parser.add_argument("--out", default=str(ROOT / "docs" / "demo.gif"))
    args = parser.parse_args()
    events = json.loads(Path(args.transcript).read_text(encoding="utf-8"))["events"]

    font = load_font(FONT_SIZE)
    cw = int(round(font.getlength("M")))
    ch = FONT_SIZE + 5
    width = COLS * cw + 2 * PAD
    height = BAR_H + ROWS * ch + 2 * PAD + CAPTION_H
    screen = Screen()
    frames: list[tuple[Image.Image, int]] = []
    caption = 0

    def draw() -> Image.Image:
        image = Image.new("RGB", (width, height), BG)
        d = ImageDraw.Draw(image)
        d.rectangle([0, 0, width, BAR_H], fill=BAR)
        for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([14 + i * 22, 11, 26 + i * 22, 23], fill=c)
        title = "hn  \u00b7  recorded from a real run  \u00b7  the model is scripted, everything else is real"
        d.text((width // 2 - int(font.getlength(title) // 2) + 30, 8), title, font=font, fill=DIM)
        y = BAR_H + PAD
        rows = screen.visible()
        for text, rgb in rows:
            d.text((PAD, y), text, font=font, fill=rgb)
            y += ch
        if rows:
            cx = PAD + len(rows[-1][0]) * cw
            cy = BAR_H + PAD + (len(rows) - 1) * ch
            d.rectangle([cx, cy + 2, cx + cw - 2, cy + ch - 3], fill=(200, 208, 216))
        text, rgb = CAPTIONS[caption]
        d.rectangle([0, height - CAPTION_H, width, height], fill=CAPTION_BG)
        d.rectangle([0, height - CAPTION_H, 5, height], fill=rgb)
        d.text((PAD + 6, height - CAPTION_H + 8), text, font=font, fill=rgb)
        return image

    def snap(ms: int) -> None:
        frames.append((draw(), ms))

    snap(1200)
    seen = 0
    for event in events:
        if event["kind"] == "in":
            line = event["text"]
            if seen == 0:
                caption = 0
            elif seen in (1, 2):
                caption = 1
            elif line.startswith("now show me"):
                caption = 2
            elif line.startswith("try it"):
                caption = 3
            elif line == "/exit":
                caption = 4
            seen += 1
            snap(900 if line in ("y", "/exit") else 500)
            for letter in line:
                screen.feed(letter)
                snap(55)
            snap(350)
            screen.newline()
            snap(250)
            continue
        for piece in re.split(r"(\n)", event["text"]):
            if piece == "\n":
                screen.newline()
                snap(130)
            elif piece != "":
                screen.feed(piece)
                snap(60)
                if piece.rstrip().endswith(("Allow? [y]es once, [s]ession, [N]o:", "Allow? [y]es once, [N]o:")):
                    snap(1500)
    snap(3500)

    # One shared palette keeps the file small and the colours steady.
    picks = frames[:: max(1, len(frames) // 8)][:8]
    sample = Image.new("RGB", (width, height * len(picks)))
    for index, (frame, _) in enumerate(picks):
        sample.paste(frame, (0, index * height))
    palette = sample.quantize(colors=48, method=Image.Quantize.MEDIANCUT)
    packed = [frame.quantize(palette=palette, dither=Image.Dither.NONE) for frame, _ in frames]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    packed[0].save(out, save_all=True, append_images=packed[1:], duration=[ms for _, ms in frames], loop=0, optimize=True, disposal=1)
    print(f"Wrote {out} ({out.stat().st_size // 1024} KB, {len(frames)} frames, {sum(ms for _, ms in frames) / 1000:.1f} s)")


if __name__ == "__main__":
    main()
