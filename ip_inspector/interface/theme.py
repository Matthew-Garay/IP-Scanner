"""Native look for IP Inspector: ttk styles, colours and small drawn icons.

The window uses the operating system's own controls (the ``vista`` ttk
theme on Windows) instead of custom-drawn widgets, so buttons, tabs, combo
boxes and scroll bars look and behave like every other Windows utility.

Icons are drawn pixel by pixel into ``tk.PhotoImage`` objects at start-up:
no image files to ship, nothing to license, and they scale with the font.
"""

from __future__ import annotations

import sys
import tkinter as tk
from dataclasses import dataclass
from tkinter import font as tkfont
from tkinter import ttk


@dataclass(frozen=True)
class Palette:
    """The few colours the native theme does not provide."""

    text: str = "#1F1F1F"
    text_muted: str = "#6D6D6D"
    row_alt: str = "#F5F7FA"
    grid: str = "#E3E3E3"
    selection: str = "#CCE4F7"
    link: str = "#0066CC"
    online: str = "#2E9E3E"
    new: str = "#1F6FD1"
    warning: str = "#D97B00"
    danger: str = "#C62828"
    favorite: str = "#E0A800"
    offline: str = "#A0A0A0"
    console_bg: str = "#FFFFFF"
    header_bg: str = "#F0F0F0"


PALETTE = Palette()

#: Screen scale factor (1.0 at 96 DPI, 1.25 at 120 DPI...), set by
#: :func:`setup_style`. Treeview column widths and row heights are plain
#: pixels and do not follow the font size, so they go through :func:`px`.
SCALE = 1.0


def px(value: float) -> int:
    """Scale a 96-DPI pixel size to the current screen."""
    return int(round(value * SCALE))

UI_FONT = ("Segoe UI", 9)
UI_FONT_BOLD = ("Segoe UI", 9, "bold")
TITLE_FONT = ("Segoe UI", 11, "bold")
MONO_FONT = ("Consolas", 10)


def current() -> Palette:
    return PALETTE


def setup_style(root: tk.Misc) -> ttk.Style:
    """Pick the native theme and add the handful of custom styles we need."""
    global SCALE
    try:
        SCALE = max(1.0, root.winfo_fpixels("1i") / 96.0)
    except tk.TclError:
        SCALE = 1.0
    style = ttk.Style(root)
    for name in ("vista", "winnative", "clam"):
        if name in style.theme_names():
            style.theme_use(name)
            break
    default = tkfont.nametofont("TkDefaultFont")
    default.configure(family=UI_FONT[0], size=UI_FONT[1])
    for named in ("TkTextFont", "TkMenuFont", "TkHeadingFont"):
        try:
            tkfont.nametofont(named).configure(family=UI_FONT[0], size=UI_FONT[1])
        except tk.TclError:
            pass
    root.option_add("*Font", default)

    pal = PALETTE
    style.configure("Treeview", rowheight=px(22), font=UI_FONT)
    style.configure("Treeview.Heading", font=UI_FONT)
    style.configure("Results.Treeview", rowheight=px(22))
    style.map("Results.Treeview",
              background=[("selected", pal.selection)],
              foreground=[("selected", pal.text)])
    style.configure("Props.Treeview", rowheight=px(20))
    style.map("Props.Treeview",
              background=[("selected", pal.selection)],
              foreground=[("selected", pal.text)])
    style.configure("Status.TLabel", padding=(6, 1))
    style.configure("Muted.TLabel", foreground=pal.text_muted)
    style.configure("Warn.TLabel", foreground=pal.warning)
    style.configure("Title.TLabel", font=TITLE_FONT)
    style.configure("Toolbar.TButton", padding=(6, 2))
    style.configure("Toolbar.TFrame")
    return style


# --------------------------------------------------------------------------- #
# Icons
# --------------------------------------------------------------------------- #
def _blank(size: int) -> tk.PhotoImage:
    return tk.PhotoImage(width=size, height=size)


def _hex_mix(colour: str, towards: str, ratio: float) -> str:
    a = [int(colour[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(towards[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * ratio):02x}" for x, y in zip(a, b))


def dot(colour: str, size: int = 14, radius: float = 4.6) -> tk.PhotoImage:
    """A small shaded disc, used as the status icon of a table row."""
    image = _blank(size)
    centre = (size - 1) / 2
    edge = _hex_mix(colour, "#000000", 0.25)
    light = _hex_mix(colour, "#FFFFFF", 0.35)
    for y in range(size):
        row = []
        for x in range(size):
            distance = ((x - centre) ** 2 + (y - centre) ** 2) ** 0.5
            if distance <= radius - 1:
                row.append(light if (x + y) < size - 3 else colour)
            elif distance <= radius:
                row.append(edge)
            else:
                row.append(None)
        for x, pixel in enumerate(row):
            if pixel:
                image.put(pixel, (x, y))
    return image


def star(colour: str, size: int = 14) -> tk.PhotoImage:
    """Five-pointed star for favourites (point-in-polygon rasterised)."""
    import math

    image = _blank(size)
    centre, outer, inner = (size - 1) / 2, size / 2 - 0.5, size / 5
    points = []
    for i in range(10):
        angle = math.pi / 2 + i * math.pi / 5
        radius = outer if i % 2 == 0 else inner
        points.append((centre + radius * math.cos(angle), centre - radius * math.sin(angle)))

    def inside(px: float, py: float) -> bool:
        result = False
        j = len(points) - 1
        for i, (xi, yi) in enumerate(points):
            xj, yj = points[j]
            if (yi > py) != (yj > py) and px < (xj - xi) * (py - yi) / (yj - yi) + xi:
                result = not result
            j = i
        return result

    edge = _hex_mix(colour, "#000000", 0.3)
    for y in range(size):
        for x in range(size):
            if inside(x + 0.5, y + 0.5):
                border = not all(inside(x + 0.5 + dx, y + 0.5 + dy)
                                 for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)))
                image.put(edge if border else colour, (x, y))
    return image


def play(colour: str = "#2E9E3E", size: int = 16) -> tk.PhotoImage:
    """Right-pointing triangle for the Scan button."""
    image = _blank(size)
    top, bottom, left = 2, size - 3, 4
    height = bottom - top
    for y in range(top, bottom + 1):
        reach = left + int((height / 2 - abs(y - top - height / 2)) * 1.6)
        for x in range(left, reach + 1):
            image.put(colour, (x, y))
    return image


def square(colour: str = "#C62828", size: int = 16) -> tk.PhotoImage:
    """Filled square for the Stop button."""
    image = _blank(size)
    image.put(colour, to=(4, 4, size - 4, size - 4))
    return image


def folder(size: int = 14) -> tk.PhotoImage:
    """Folder glyph for shared-folder rows."""
    image = _blank(size)
    body, edge = "#F2C14E", "#B8862B"
    image.put(edge, to=(1, 3, 6, 5))
    image.put(edge, to=(1, 4, size - 1, size - 2))
    image.put(body, to=(2, 5, size - 2, size - 3))
    return image


def service(size: int = 14) -> tk.PhotoImage:
    """Small grey square for service (port) rows."""
    image = _blank(size)
    image.put("#7A869A", to=(4, 4, size - 4, size - 4))
    image.put("#AEB7C4", to=(5, 5, size - 5, size - 5))
    return image


class Icons:
    """All icons, created once per root window (PhotoImage needs a root)."""

    def __init__(self) -> None:
        pal = PALETTE
        self.online = dot(pal.online)
        self.new = dot(pal.new)
        self.risk = dot(pal.warning)
        self.danger = dot(pal.danger)
        self.offline = dot(pal.offline)
        self.favorite = star(pal.favorite)
        self.scan = play()
        self.stop = square()
        self.folder = folder()
        self.service = service()


def enable_dpi_awareness() -> None:
    """Crisp text on high-DPI Windows screens (call before creating the root)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass
