#!/usr/bin/env python3
"""Verify a QEMU screendump against GUI_SPECIFICATION.md §4 (layout) and §5 (palette).

`dev-tools/qemu_check.py --vga std --screendump target/gui.ppm` captures the emulated screen;
this script reads that PPM, checks that the framebuffer really holds the display server's
windows, rules and palette - in the rectangles the serial log claims - and writes a PNG
next to it so the frame can be eyeballed in any viewer.

Glyph shapes are not OCR'd: `gui test` proves glyph coverage through the aperture, this
proves the pixels on screen are the specified colours in the specified rectangles.

    python dev-tools/verify_gui.py --ppm target/gui.ppm --png target/gui.png
"""

from __future__ import annotations

import argparse
import os
import struct
import sys

# Palette from GUI_SPECIFICATION.md §5 (canvas.rs mirrors it as u32 0x00RRGGBB).
BG = (3, 7, 18)
PANEL = (15, 23, 42)
BORDER = (99, 102, 241)
TEXT = (248, 250, 252)
TEXT_DIM = (148, 163, 184)
DANGER = (239, 68, 68)
SECURE = (16, 185, 129)
CHROME = (27, 36, 56)

PALETTE = {
    "bg": BG,
    "panel": PANEL,
    "border": BORDER,
    "text": TEXT,
    "dim": TEXT_DIM,
    "danger": DANGER,
    "secure": SECURE,
    "chrome": CHROME,
}

# Layout constants the display server uses (src/gui/mod.rs).
TOP_BAR_HEIGHT = 30
FOOTER_HEIGHT = 22
CHROME_HEIGHT = 20
PADDING = 6

# Window rectangles from the boot log ("[GUI]   win1 KELLER SHELL pid=1 rect=626x704+8+36").
WINDOWS = [
    ("KELLER SHELL", 8, 36, 626, 704, "shell"),
    ("KELLER VAULT", 644, 36, 372, 366, "vault"),
    ("SUBSYSTEMS", 644, 410, 372, 330, "subsystems"),
]


def read_ppm(path: str) -> tuple[int, int, list[tuple[int, int, int]]]:
    with open(path, "rb") as handle:
        blob = handle.read()
    if not blob.startswith(b"P6"):
        raise SystemExit(f"{path}: not a binary PPM (P6)")
    fields: list[int] = []
    index = 2
    while len(fields) < 3:
        while index < len(blob) and blob[index : index + 1].isspace():
            index += 1
        if index < len(blob) and blob[index : index + 1] == b"#":
            while index < len(blob) and blob[index : index + 1] != b"\n":
                index += 1
            continue
        start = index
        while index < len(blob) and not blob[index : index + 1].isspace():
            index += 1
        fields.append(int(blob[start:index]))
    index += 1  # single whitespace byte after maxval
    width, height, maxval = fields
    if maxval != 255:
        raise SystemExit(f"{path}: maxval {maxval} is not 8-bit")
    expected = width * height * 3
    pixels_blob = blob[index : index + expected]
    if len(pixels_blob) != expected:
        raise SystemExit(f"{path}: truncated pixel data")
    pixels = list(struct.iter_unpack("BBB", pixels_blob))
    return width, height, pixels


def at(pixels, width, x: int, y: int) -> tuple[int, int, int]:
    return pixels[y * width + x]


def near(actual: tuple[int, int, int], expected: tuple[int, int, int], slack: int = 8) -> bool:
    return all(abs(a - b) <= slack for a, b in zip(actual, expected))


def save_png(path: str, width: int, height: int, pixels) -> bool:
    """Writes a PNG next to the capture. Returns False when PIL is unavailable."""
    try:
        from PIL import Image
    except ImportError:
        print("verify_gui: PIL unavailable, skipping PNG", file=sys.stderr)
        return False
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    image = Image.new("RGB", (width, height))
    image.putdata(pixels)
    image.save(path)
    print(f"verify_gui: wrote {path}")
    return True


def report(checks) -> int:
    failures = 0
    for name, ok, detail in checks:
        if not ok:
            failures += 1
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))
    print(f"verify_gui: {len(checks) - failures} passed, {failures} failed")
    return 1 if failures else 0


def run_wiped(args, width: int, height: int, pixels, checks, check) -> int:
    """Panic-path mode.

    After the shell's `panic` command the scrub hook has zeroed the framebuffer through the
    aperture, so the very last frame the emulator can capture must be black: a screen still
    showing the tiles would mean the wipe never reached the adapter.
    """
    check("mode", (width, height) == (args.width, args.height), f"{width}x{height}")
    non_black = 0
    painted = 0
    for pixel in pixels:
        if pixel != (0, 0, 0):
            non_black += 1
            if pixel in PALETTE.values():
                painted += 1
    check("wiped:all-zero", non_black == 0, f"{non_black} non-black px of {len(pixels)}")
    check("wiped:no-palette", painted == 0, f"{painted} palette px survived the wipe")
    save_png(args.png, width, height, pixels)
    return report(checks)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ppm", default="target/gui.ppm")
    parser.add_argument("--png", default="target/gui.png")
    parser.add_argument(
        "--html",
        default=None,
        help="also write a self-contained page (base64 PNG) for the Preview tab",
    )
    parser.add_argument(
        "--wiped",
        action="store_true",
        help="panic-path check: the frame must be black (framebuffer scrubbed by the hook)",
    )
    parser.add_argument(
        "--cursor",
        default=None,
        help="x,y the top bar claims for the software cursor; checks the arrow is really there",
    )
    parser.add_argument("--width", type=int, default=1024)
    parser.add_argument("--height", type=int, default=768)
    args = parser.parse_args()

    width, height, pixels = read_ppm(args.ppm)
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, bool(ok), detail))

    if args.wiped:
        return run_wiped(args, width, height, pixels, checks, check)

    check(
        "mode",
        (width, height) == (args.width, args.height),
        f"{width}x{height} (expected {args.width}x{args.height})",
    )

    # 1. Palette coverage: every specified colour has to appear on screen.
    counts = {name: 0 for name in PALETTE}
    for pixel in pixels:
        for name, color in PALETTE.items():
            if pixel == color:
                counts[name] += 1
                break
    for name, count in counts.items():
        check(f"palette:{name}", count > 0, f"{count} px")

    # 2. Top status bar and its border rule.
    check("topbar:panel", at(pixels, width, width // 2, 0) == PANEL, f"{at(pixels, width, width // 2, 0)}")
    check(
        "topbar:ink",
        any(at(pixels, width, x, 12) != PANEL for x in range(8, 200)),
        "status text occupies the bar",
    )
    rule_ok = all(at(pixels, width, x, TOP_BAR_HEIGHT - 1) == BORDER for x in range(0, width, 37))
    check("topbar:border-rule", rule_ok, f"rows {TOP_BAR_HEIGHT - 2}..{TOP_BAR_HEIGHT - 1}")

    # 3. Footer rule.
    footer_y = height - FOOTER_HEIGHT
    check(
        "footer:border-rule",
        all(at(pixels, width, x, footer_y) == BORDER for x in range(0, width, 37)),
        f"row {footer_y}",
    )
    check("footer:panel", at(pixels, width, width // 2, height - 2) == PANEL, "panel strip")

    # 4. Background shows between the windows.
    check("background:bg", at(pixels, width, 0, TOP_BAR_HEIGHT + 2) == BG, f"{BG}")

    # 5. Each window: border outline on all four edges, chrome strip, and interior ink.
    for title, x, y, w, h, role in WINDOWS:
        edges_ok = (
            at(pixels, width, x, y) == BORDER
            and at(pixels, width, x + w - 1, y) == BORDER
            and at(pixels, width, x, y + h - 1) == BORDER
            and at(pixels, width, x + w - 1, y + h - 1) == BORDER
        )
        check(f"window:{role}:frame", edges_ok, f"{w}x{h}+{x}+{y}")

        # Chrome strip: sample just inside the frame, away from the title and the pid/cap text.
        chrome_x = x + w // 2
        check(
            f"window:{role}:chrome",
            at(pixels, width, chrome_x, y + 2) == CHROME,
            f"title strip at y={y + 2}",
        )

        ink = 0
        interior = 0
        for row in range(y + CHROME_HEIGHT + 2, y + h - 4):
            for column in range(x + 4, x + w - 4):
                pixel = at(pixels, width, column, row)
                interior += 1
                if pixel in (TEXT, TEXT_DIM, DANGER, SECURE):
                    ink += 1
        check(f"window:{role}:ink", ink > 200, f"{ink} lit px of {interior} interior px")

    # 6. The console tile actually mirrors the kernel log (the boot log alone is ~40 lines).
    #    Ink is counted per 16-row text cell, not per pixel row: a cell's top rows are blank
    #    because the baked font sits on a baseline (see dev-tools/make_font.py).
    _, cx, cy, cw, ch, _ = WINDOWS[0]
    bands_with_ink = 0
    for band in range(cy + CHROME_HEIGHT + 2, cy + ch - 4, 16):
        lit = sum(
            1
            for row in range(band, min(band + 16, cy + ch - 4))
            for column in range(cx + 8, cx + cw - 8)
            if at(pixels, width, column, row) in (TEXT, TEXT_DIM)
        )
        if lit >= 8:
            bands_with_ink += 1
    check("shell:log-lines", bands_with_ink >= 12, f"{bands_with_ink} text cells carry log lines")

    # 7. The vault tile carries the danger-coloured panic affordance.
    _, vx, vy, vw, vh, _ = WINDOWS[1]
    danger_px = sum(
        1
        for row in range(vy, vy + vh)
        for column in range(vx, vx + vw)
        if at(pixels, width, column, row) == DANGER
    )
    check("vault:panic-affordance", danger_px > 40, f"{danger_px} danger px")

    # 8. The focused window title is drawn in the secure colour.
    secure_px = sum(
        1
        for row in range(cy, cy + CHROME_HEIGHT)
        for column in range(cx, cx + cw)
        if at(pixels, width, column, row) == SECURE
    )
    check("shell:focus-colour", secure_px > 20, f"{secure_px} secure px in the title strip")

    # 9. Software cursor: the arrow is `TEXT` white with a `BG` outline, 9x14, and its tip
    #    is the top-left pixel. Checked where the kernel says it is, not where we hope.
    if args.cursor:
        cursor_x, cursor_y = (int(value) for value in args.cursor.split(","))
        width_css, height_css = 9, 14
        tip_ok = at(pixels, width, cursor_x, cursor_y) == TEXT
        lit = sum(
            1
            for row in range(cursor_y, min(cursor_y + height_css, height))
            for column in range(cursor_x, min(cursor_x + width_css, width))
            if at(pixels, width, column, row) == TEXT
        )
        outline = sum(
            1
            for row in range(cursor_y, min(cursor_y + height_css, height))
            for column in range(cursor_x, min(cursor_x + width_css, width))
            if at(pixels, width, column, row) == BG
        )
        check("cursor:tip", tip_ok, f"({cursor_x},{cursor_y}) is TEXT")
        check("cursor:lit", lit >= 20, f"{lit} lit pixels in the arrow")
        check("cursor:outline", outline >= 10, f"{outline} outline pixels")

    # 10. Write the PNG so the frame can be looked at without a PPM viewer.
    if save_png(args.png, width, height, pixels) and args.html:
        import base64
        import io

        from PIL import Image

        image = Image.new("RGB", (width, height))
        image.putdata(pixels)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
        rows = "".join(
            f"<tr><td>{name}</td><td class='{'ok' if ok else 'bad'}'>"
            f"{'PASS' if ok else 'FAIL'}</td><td>{detail}</td></tr>"
            for name, ok, detail in checks
        )
        page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>KELLER-OS framebuffer capture</title>
<style>
 body {{ background:#030712; color:#f8fafc; font:14px/1.5 ui-monospace,Consolas,monospace; margin:24px; }}
 h1 {{ font-size:16px; color:#6366f1; letter-spacing:.08em; text-transform:uppercase; }}
 img {{ width:100%; max-width:{width}px; image-rendering:pixelated; border:1px solid #6366f1; display:block; }}
 table {{ border-collapse:collapse; margin-top:18px; max-width:{width}px; width:100%; }}
 td {{ border-top:1px solid #0f172a; padding:3px 8px; vertical-align:top; }}
 td:first-child {{ color:#94a3b8; }}
 .ok {{ color:#10b981; }} .bad {{ color:#ef4444; }}
 p {{ color:#94a3b8; max-width:{width}px; }}
</style></head><body>
<h1>QEMU -vga std screendump &mdash; {width}x{height}x32</h1>
<p>Captured by <code>dev-tools/qemu_check.py --screendump</code> after booting the kernel and
running <code>status</code>, <code>input</code>, <code>input test</code>, <code>gui</code>,
<code>gui test</code>, <code>selftest</code> and <code>net</code> over the serial console, then
injecting pointer motion, two left clicks and a typed command through the emulated PS/2
controller. Top bar = vault/mesh/entropy state plus the focus holder and cursor position, left
tile = kernel log mirror, right tiles = vault (with the red
<code>[PANIC: ZERO VAULT &amp; HALT]</code> affordance) and subsystems.</p>
<img alt="KELLER-OS framebuffer" src="data:image/png;base64,{encoded}">
<table>{rows}</table>
</body></html>
"""
        with open(args.html, "w", encoding="utf-8") as handle:
            handle.write(page)
        print(f"verify_gui: wrote {args.html}")

    return report(checks)


if __name__ == "__main__":
    raise SystemExit(main())
