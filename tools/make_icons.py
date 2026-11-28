"""
Draw the application's icon set (device types, navigation, status badges).

Run from the repository root whenever an icon changes::

    pip install pillow
    python tools/make_icons.py

The app itself only loads the PNGs this writes to ``weftscan/assets/icons``;
Pillow is a design-time tool, not a runtime dependency.

All glyphs are drawn on a 64-unit grid with one stroke weight, rendered at
8x and downsampled, so every size is anti-aliased and the set reads as one
family.
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parents[1] / "weftscan" / "assets" / "icons"
GRID = 64
OVERSAMPLE = 8
CANVAS = GRID * OVERSAMPLE

INK = (32, 32, 32, 255)          # #202020  line colour (black)
ACCENT = (0, 99, 177, 255)         # #0063B1  brand accent (blue)
ACCENT_TINT = (221, 235, 247, 255)
WHITE = (255, 255, 255, 255)

ROW_SIZES = (16, 20, 24, 32)
HEADER_SIZES = (32, 40, 48, 64)
BADGE_SIZES = (8, 10, 12, 16)


class Pen:
    """Drawing helpers in 64-unit grid coordinates."""

    def __init__(self, stroke: float = 4.0, colour=INK) -> None:
        self.image = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
        self.draw = ImageDraw.Draw(self.image)
        self.width = int(stroke * OVERSAMPLE)
        self.colour = colour

    @staticmethod
    def _xy(*values: float) -> list[float]:
        return [v * OVERSAMPLE for v in values]

    def rect(self, x0, y0, x1, y1, r=3, fill=None, colour=None):
        self.draw.rounded_rectangle(self._xy(x0, y0, x1, y1), radius=r * OVERSAMPLE,
                                    outline=colour or self.colour, width=self.width, fill=fill)

    def fill_rect(self, x0, y0, x1, y1, r=1, colour=None):
        self.draw.rounded_rectangle(self._xy(x0, y0, x1, y1), radius=r * OVERSAMPLE,
                                    fill=colour or self.colour)

    def line(self, *points, colour=None, width=None):
        coords = self._xy(*[c for point in points for c in point])
        self.draw.line(coords, fill=colour or self.colour, width=width or self.width,
                       joint="curve")
        radius = (width or self.width) / 2
        for x, y in (points[0], points[-1]):
            cx, cy = x * OVERSAMPLE, y * OVERSAMPLE
            self.draw.ellipse((cx - radius, cy - radius, cx + radius, cy + radius),
                              fill=colour or self.colour)

    def circle(self, cx, cy, r, fill=None, colour=None):
        self.draw.ellipse(self._xy(cx - r, cy - r, cx + r, cy + r),
                          outline=colour or self.colour, width=self.width, fill=fill)

    def dot(self, cx, cy, r=2.4, colour=None):
        self.draw.ellipse(self._xy(cx - r, cy - r, cx + r, cy + r), fill=colour or self.colour)

    def arc(self, cx, cy, r, start, end, colour=None):
        self.draw.arc(self._xy(cx - r, cy - r, cx + r, cy + r), start, end,
                      fill=colour or self.colour, width=self.width)

    def polygon(self, points, fill=None, colour=None):
        coords = self._xy(*[c for point in points for c in point])
        self.draw.polygon(coords, fill=fill, outline=colour or self.colour,
                          width=self.width)

    def text(self, x, y, value, size=34, colour=None):
        try:
            font = ImageFont.truetype("segoeuib.ttf", size * OVERSAMPLE)
        except OSError:
            font = ImageFont.load_default()
        self.draw.text((x * OVERSAMPLE, y * OVERSAMPLE), value, font=font,
                       fill=colour or self.colour, anchor="mm")


# --------------------------------------------------------------------------- #
# Device glyphs
# --------------------------------------------------------------------------- #
def computer(p: Pen, accent: bool = False):
    p.rect(7, 10, 57, 43, r=4, fill=ACCENT_TINT if accent else None)
    p.line((32, 44), (32, 51))
    p.line((21, 53), (43, 53))
    if accent:
        p.line((22, 27), (29, 33), (42, 20), colour=ACCENT)


def laptop(p: Pen):
    p.rect(13, 13, 51, 40, r=3)
    p.line((5, 49), (59, 49))
    p.line((5, 49), (9, 53), (55, 53), (59, 49))


def server(p: Pen):
    for top in (7, 25, 43):
        p.rect(11, top, 53, top + 14, r=3)
        p.dot(45, top + 7)
        p.line((19, top + 7), (31, top + 7))


def router(p: Pen):
    p.rect(7, 34, 57, 52, r=5)
    p.line((19, 34), (15, 13))
    p.line((45, 34), (49, 13))
    p.dot(18, 43)
    p.dot(27, 43)
    p.line((37, 43), (48, 43))


def access_point(p: Pen):
    p.rect(9, 40, 55, 52, r=6)
    p.dot(32, 46)
    p.arc(32, 32, 10, 220, 320)
    p.arc(32, 32, 19, 220, 320)


def phone(p: Pen):
    p.rect(19, 5, 45, 59, r=7)
    p.line((28, 12), (36, 12))
    p.dot(32, 51, r=2.6)


def tablet(p: Pen):
    p.rect(11, 7, 53, 57, r=6)
    p.dot(32, 50, r=2.6)


def printer(p: Pen):
    p.rect(19, 7, 45, 22, r=2)
    p.rect(7, 22, 57, 45, r=5)
    p.rect(19, 37, 45, 57, r=2, fill=WHITE)
    p.dot(48, 30)
    p.line((25, 44), (39, 44))
    p.line((25, 50), (35, 50))


def camera(p: Pen):
    p.rect(5, 14, 45, 34, r=9)
    p.circle(14, 24, 4)
    p.line((28, 34), (31, 45), (51, 45))
    p.line((53, 36), (53, 54))


def tv(p: Pen):
    p.rect(4, 10, 60, 45, r=3)
    p.line((20, 53), (44, 53))
    p.line((32, 45), (32, 53))


def media(p: Pen):
    p.rect(7, 20, 57, 46, r=8)
    p.polygon([(27, 26), (27, 40), (39, 33)], fill=INK)


def speaker(p: Pen):
    p.rect(15, 5, 49, 59, r=8)
    p.circle(32, 38, 9)
    p.dot(32, 38, r=2.2)
    p.dot(32, 17, r=3.2)


def console(p: Pen):
    p.rect(5, 18, 59, 47, r=14)
    p.line((16, 32), (26, 32))
    p.line((21, 27), (21, 37))
    p.dot(42, 29, r=2.8)
    p.dot(48, 35, r=2.8)


def storage(p: Pen):
    p.rect(13, 5, 51, 59, r=4)
    for top in (14, 31):
        p.rect(19, top, 45, top + 11, r=2)
        p.dot(40, top + 5.5, r=2)
    p.dot(32, 51)


def smart_home(p: Pen):
    p.line((7, 31), (32, 9), (57, 31))
    p.line((14, 26), (14, 55), (50, 55), (50, 26))
    p.arc(32, 44, 6, 180, 360)
    p.arc(32, 44, 13, 200, 340)
    p.dot(32, 46, r=2.6)


def network(p: Pen):
    p.rect(5, 22, 59, 42, r=4)
    for x in (14, 23, 32, 41):
        p.fill_rect(x - 3, 29, x + 3, 35, r=1)
    p.dot(51, 32)


def unknown(p: Pen):
    p.rect(9, 9, 55, 55, r=10)
    p.text(32, 31, "?", size=30)


def this_computer(p: Pen):
    computer(p, accent=True)


DEVICES = {
    "computer": computer, "laptop": laptop, "server": server, "router": router,
    "access_point": access_point, "phone": phone, "tablet": tablet, "printer": printer,
    "camera": camera, "tv": tv, "media": media, "speaker": speaker, "console": console,
    "storage": storage, "smart_home": smart_home, "network": network, "unknown": unknown,
    "this_computer": this_computer,
}


# --------------------------------------------------------------------------- #
# Interface glyphs
# --------------------------------------------------------------------------- #
def nav_devices(p: Pen):
    p.rect(7, 9, 57, 39, r=4)
    p.line((24, 47), (40, 47))
    p.line((32, 39), (32, 47))
    p.line((15, 55), (49, 55))


def nav_favorites(p: Pen):
    points = []
    for i in range(10):
        angle = math.pi / 2 + i * math.pi / 5
        radius = 26 if i % 2 == 0 else 11
        points.append((32 + radius * math.cos(angle), 34 - radius * math.sin(angle)))
    p.polygon(points)


def nav_tools(p: Pen):
    p.line((12, 52), (34, 30))
    p.arc(42, 22, 11, 0, 270)
    p.line((42, 11), (42, 22), (53, 22))


def nav_monitor(p: Pen):
    p.line((5, 34), (18, 34), (24, 18), (34, 50), (41, 28), (46, 34), (59, 34))


def tool_scan(p: Pen):
    p.polygon([(19, 12), (19, 52), (51, 32)], fill=ACCENT, colour=ACCENT)


def tool_stop(p: Pen):
    p.fill_rect(16, 16, 48, 48, r=4, colour=INK)


def tool_options(p: Pen):
    for y, knob in ((16, 40), (32, 20), (48, 34)):
        p.line((8, y), (56, y))
        p.circle(knob, y, 5, fill=WHITE)


def tool_export(p: Pen):
    p.line((32, 8), (32, 38))
    p.line((20, 27), (32, 39), (44, 27))
    p.line((10, 42), (10, 54), (54, 54), (54, 42))


def tool_report(p: Pen):
    p.line((14, 6), (40, 6), (52, 18), (52, 58), (14, 58), (14, 6))
    for y in (28, 37, 46):
        p.line((22, y), (44, y))


def folder(p: Pen):
    p.line((7, 15), (24, 15), (30, 21), (57, 21), (57, 51), (7, 51), (7, 15))


def service(p: Pen):
    p.rect(14, 14, 50, 50, r=6)
    p.line((24, 32), (40, 32))


INTERFACE = {
    "folder": folder, "service": service,
    "nav_devices": nav_devices, "nav_favorites": nav_favorites, "nav_tools": nav_tools,
    "nav_monitor": nav_monitor, "scan": tool_scan, "stop": tool_stop,
    "options": tool_options, "export": tool_export, "report": tool_report,
}


# --------------------------------------------------------------------------- #
# Status badges (drawn into the corner of a device icon at runtime)
# --------------------------------------------------------------------------- #
BADGES = {
    "online": (16, 124, 16, 255),
    "new": (0, 0, 0, 255),
    "risk": (216, 94, 0, 255),
    "danger": (196, 43, 28, 255),
    "favorite": (242, 169, 0, 255),
}


def badge(colour, star: bool = False) -> Image.Image:
    image = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    if star:
        points = []
        for i in range(10):
            angle = math.pi / 2 + i * math.pi / 5
            radius = (CANVAS / 2 - 4) if i % 2 == 0 else CANVAS / 5
            points.append((CANVAS / 2 + radius * math.cos(angle),
                           CANVAS / 2 + 18 - radius * math.sin(angle)))
        draw.polygon(points, fill=colour, outline=WHITE, width=OVERSAMPLE * 5)
    else:
        ring = OVERSAMPLE * 7
        draw.ellipse((ring // 2, ring // 2, CANVAS - ring // 2, CANVAS - ring // 2),
                     fill=colour, outline=WHITE, width=ring)
    return image


def app_mark() -> Image.Image:
    """Application icon: an address grid with some addresses in use.

    It echoes the address map in the main window, where every cell is one IP
    of the scanned range and filled cells are devices that answered.
    """
    image = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    unit = CANVAS / GRID
    draw.rounded_rectangle((2 * unit, 2 * unit, 62 * unit, 62 * unit), radius=13 * unit,
                           fill=ACCENT)
    used = {(0, 0), (1, 0), (3, 0), (1, 1), (2, 1), (0, 2), (2, 2), (3, 2), (1, 3), (3, 3)}
    for row in range(4):
        for column in range(4):
            x0 = (12 + column * 10.5) * unit
            y0 = (12 + row * 10.5) * unit
            box = (x0, y0, x0 + 8 * unit, y0 + 8 * unit)
            if (column, row) in used:
                draw.rounded_rectangle(box, radius=1.6 * unit, fill=WHITE)
            else:
                draw.rounded_rectangle(box, radius=1.6 * unit, outline=(255, 255, 255, 150),
                                       width=int(1.6 * unit))
    return image


def save(image: Image.Image, name: str, sizes) -> None:
    for size in sizes:
        image.resize((size, size), Image.LANCZOS).save(OUT / f"{name}_{size}.png")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.png"):
        old.unlink()
    for name, glyph in DEVICES.items():
        pen = Pen()
        glyph(pen)
        save(pen.image, name, ROW_SIZES + HEADER_SIZES)
    for name, glyph in INTERFACE.items():
        pen = Pen()
        glyph(pen)
        save(pen.image, name, ROW_SIZES)
    for name, colour in BADGES.items():
        save(badge(colour, star=name == "favorite"), f"badge_{name}", BADGE_SIZES)
    mark = app_mark()
    assets = OUT.parent
    mark.resize((64, 64), Image.LANCZOS).save(assets / "icon.png")
    mark.resize((256, 256), Image.LANCZOS).save(
        assets / "icon.ico", sizes=[(16, 16), (20, 20), (24, 24), (32, 32), (48, 48), (64, 64),
                                     (256, 256)])
    save(mark, "app", (16, 20, 24, 32, 48))
    sheet = Image.new("RGBA", (8 + 56 * 9, 8 + 56 * 4), WHITE)
    names = list(DEVICES) + list(INTERFACE)
    for index, name in enumerate(names):
        tile = Image.open(OUT / f"{name}_{48 if name in DEVICES else 32}.png")
        sheet.alpha_composite(tile, (8 + (index % 9) * 56, 8 + (index // 9) * 56))
    sheet.save(OUT.parent / "icon_sheet.png")
    print(f"Wrote {len(list(OUT.glob('*.png')))} icons to {OUT}")


if __name__ == "__main__":
    main()
