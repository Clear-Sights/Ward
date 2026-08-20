#!/usr/bin/env python3
"""Render Ward's short Reddit demo video with Pillow and the bundled ffmpeg."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugin"
if str(PLUGIN) not in sys.path:
    # The package moved under plugin/; the event payloads below still describe ROOT, because
    # they stand for a user's working tree rather than for this repository's layout.
    sys.path.insert(0, str(PLUGIN))

from ward.checks import CHECKS, evaluate  # noqa: E402


WIDTH, HEIGHT, FPS = 1280, 800, 30
FFMPEG = Path(
    "/usr/local/lib/python3.11/dist-packages/imageio_ffmpeg/binaries/"
    "ffmpeg-linux-x86_64-v7.0.2"
)
OUTPUT = ROOT / "docs" / "demo.mp4"

PAGE = "#f6f8fa"
WHITE = "#ffffff"
BORDER = "#d0d7de"
BAR = "#eaeef2"
INK = "#1f2328"
MUTED = "#59636e"
PROMPT = "#1a7f37"
RED = "#cf222e"
CHIP_BG = "#fff1f0"
HERO_BLUE = "#0969da"
TAGLINE_BLUE = "#d8e6f7"
PILL_BLUE = "#0550ae"

MONO_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SANS_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
SANS_BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

MONO_24 = ImageFont.truetype(MONO_PATH, 24)
MONO_21 = ImageFont.truetype(MONO_PATH, 21)
MONO_18 = ImageFont.truetype(MONO_PATH, 18)
MONO_BOLD_24 = ImageFont.truetype(MONO_BOLD_PATH, 24)
SANS_18 = ImageFont.truetype(SANS_PATH, 18)
SANS_BOLD_18 = ImageFont.truetype(SANS_BOLD_PATH, 18)
SANS_BOLD_62 = ImageFont.truetype(SANS_BOLD_PATH, 62)
SANS_31 = ImageFont.truetype(SANS_PATH, 31)
MONO_22 = ImageFont.truetype(MONO_PATH, 22)


@dataclass(frozen=True)
class Scene:
    command: str
    result: str
    hold_seconds: float
    denied: bool


def event(tool_name: str, file_path: str, introduced: str) -> dict:
    tool_input = {"file_path": str(ROOT / file_path)}
    if tool_name == "Write":
        tool_input["content"] = introduced
    else:
        tool_input.update({"old_string": "pass", "new_string": introduced})
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "cwd": str(ROOT),
    }


def real_denial(tool_name: str, file_path: str, introduced: str) -> str:
    fired = evaluate(event(tool_name, file_path, introduced))
    if fired is None:
        raise RuntimeError(f"Ward unexpectedly allowed demo input: {introduced}")
    check_id, message = fired
    return f"{check_id}: {message}"


SCENES = (
    Scene(
        "Write app.py: requests.get(url, verify=False)",
        real_denial("Write", "app.py", "requests.get(url, verify=False)\n"),
        3.2,
        True,
    ),
    Scene(
        'Edit auth.py: jwt.decode(tok, algorithms=["none"])',
        real_denial("Edit", "auth.py", 'jwt.decode(tok, algorithms=["none"])'),
        3.2,
        True,
    ),
    Scene(
        "Edit app.py: a = a + 1",
        "{}  · no opinion — Ward only speaks for its 11 rows.",
        2.0,
        False,
    ),
)


def wrap_pixels(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.FreeTypeFont, width: int) -> list[str]:
    lines: list[str] = []
    for paragraph in text.splitlines() or [""]:
        words = paragraph.split()
        if not words:
            lines.append("")
            continue
        current = words[0]
        for word in words[1:]:
            trial = f"{current} {word}"
            if draw.textlength(trial, font=font) <= width:
                current = trial
            else:
                lines.append(current)
                current = word
        lines.append(current)
    return lines


def terminal_base() -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (WIDTH, HEIGHT), PAGE)
    draw = ImageDraw.Draw(image)
    card = (50, 62, 1230, 738)
    draw.rounded_rectangle(card, radius=18, fill=WHITE, outline=BORDER, width=2)
    draw.rounded_rectangle((50, 62, 1230, 130), radius=18, fill=BAR)
    draw.rectangle((50, 108, 1230, 130), fill=BAR)
    for x, color in ((82, "#ff5f57"), (112, "#febc2e"), (142, "#28c840")):
        draw.ellipse((x - 9, 87, x + 9, 105), fill=color)
    title = "ward · PreToolUse"
    title_w = draw.textlength(title, font=MONO_18)
    draw.text(((WIDTH - title_w) / 2, 82), title, fill=MUTED, font=MONO_18)
    return image, draw


def render_scene(scene: Scene, typed_chars: int, show_result: bool) -> Image.Image:
    image, draw = terminal_base()
    draw.text((82, 175), "$", fill=PROMPT, font=MONO_BOLD_24)
    draw.text((116, 175), scene.command[:typed_chars], fill=INK, font=MONO_24)
    if typed_chars < len(scene.command):
        cursor_x = 116 + draw.textlength(scene.command[:typed_chars], font=MONO_24)
        draw.rectangle((cursor_x + 2, 179, cursor_x + 5, 203), fill=MUTED)
    if not show_result:
        return image

    if scene.denied:
        draw.rounded_rectangle((82, 238, 174, 274), radius=18, fill=CHIP_BG, outline=RED, width=2)
        label_w = draw.textlength("DENY", font=SANS_BOLD_18)
        draw.text((128 - label_w / 2, 244), "DENY", fill=RED, font=SANS_BOLD_18)
        draw.text((196, 245), "permissionDecisionReason · exact evaluate() output", fill=MUTED, font=MONO_18)
        lines = wrap_pixels(draw, scene.result, MONO_21, 1088)
        y = 311
        for line in lines:
            draw.text((82, y), line, fill=INK, font=MONO_21)
            y += 34
        draw.text((82, 690), "process exit 0 · the host reads the deny decision", fill=MUTED, font=MONO_18)
    else:
        draw.line((82, 243, 1198, 243), fill=BAR, width=2)
        draw.text((82, 282), scene.result, fill=MUTED, font=MONO_21)
    return image


def shield(draw: ImageDraw.ImageDraw, cx: int, cy: int) -> None:
    points = [(cx, cy - 76), (cx + 68, cy - 49), (cx + 57, cy + 30), (cx, cy + 82), (cx - 57, cy + 30), (cx - 68, cy - 49)]
    draw.polygon(points, fill=WHITE)
    inner = [(cx, cy - 57), (cx + 48, cy - 38), (cx + 40, cy + 18), (cx, cy + 57), (cx - 40, cy + 18), (cx - 48, cy - 38)]
    draw.polygon(inner, fill=HERO_BLUE)
    draw.line((cx - 24, cy, cx - 6, cy + 20, cx + 31, cy - 24), fill=WHITE, width=10, joint="curve")


def render_end_card() -> Image.Image:
    image = Image.new("RGB", (WIDTH, HEIGHT), HERO_BLUE)
    draw = ImageDraw.Draw(image)
    shield(draw, 640, 213)
    ward_w = draw.textlength("WARD", font=SANS_BOLD_62)
    draw.text(((WIDTH - ward_w) / 2, 326), "WARD", fill=WHITE, font=SANS_BOLD_62)
    tagline = "nothing outright bad happens"
    tag_w = draw.textlength(tagline, font=SANS_31)
    draw.text(((WIDTH - tag_w) / 2, 430), tagline, fill=TAGLINE_BLUE, font=SANS_31)
    url = "github.com/Clear-Sights/Ward"
    url_w = draw.textlength(url, font=MONO_22)
    draw.rounded_rectangle(((WIDTH - url_w) / 2 - 22, 520, (WIDTH + url_w) / 2 + 22, 572), radius=26, fill=PILL_BLUE)
    draw.text(((WIDTH - url_w) / 2, 533), url, fill=WHITE, font=MONO_22)
    return image


def write_frames(proc: subprocess.Popen[bytes], image: Image.Image, count: int) -> None:
    raw = image.tobytes()
    assert proc.stdin is not None
    for _ in range(count):
        proc.stdin.write(raw)


def main() -> int:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    command = [
        str(FFMPEG), "-y", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{WIDTH}x{HEIGHT}",
        "-r", str(FPS), "-i", "-", "-an", "-c:v", "libx264", "-preset", "medium", "-crf", "18",
        "-pix_fmt", "yuv420p", "-movflags", "+faststart", str(OUTPUT),
    ]
    print("COMMAND:", " ".join(command))
    proc = subprocess.Popen(command, stdin=subprocess.PIPE)
    for index, scene in enumerate(SCENES):
        for chars in range(1, len(scene.command) + 1):
            write_frames(proc, render_scene(scene, chars, False), 1)
        write_frames(proc, render_scene(scene, len(scene.command), False), round(0.3 * FPS))
        write_frames(proc, render_scene(scene, len(scene.command), True), round(scene.hold_seconds * FPS))
        if index < len(SCENES) - 1:
            write_frames(proc, render_scene(SCENES[index + 1], 0, False), round(0.2 * FPS))
    write_frames(proc, render_end_card(), round(1.5 * FPS))
    assert proc.stdin is not None
    proc.stdin.close()
    exit_code = proc.wait()
    print(f"EXIT_CODE={exit_code}")
    if exit_code != 0:
        return exit_code
    print(f"Rendered {OUTPUT}")
    print(f"Ward rows at render time: {len(CHECKS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
