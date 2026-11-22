"""Visual system of IP Scanner: colour tokens, ttk styles and icons.

Design notes
------------
* Neutral surfaces (white work areas on a light grey chrome) with hairline
  borders, so the data is what stands out.
* One accent, a deep teal, used only for the primary action, the current
  navigation item, selection and the address map. Status colours appear
  only where they carry meaning (online, new, needs attention).
* Segoe UI throughout: the Windows system face, at a small type scale
  (9 / 10 / 13 pt) with weight, not size, carrying hierarchy.

Icons are PNGs drawn by ``tools/make_icons.py``. Each table row shows the
device-type glyph with a small status badge composited onto its corner at
runtime, so 18 glyphs x 5 states need no extra files.
"""

from __future__ import annotations

import sys
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import font as tkfont
from tkinter import ttk


@dataclass(frozen=True)
class Palette:
    ink: str = "#1D2833"           # primary text
    ink_2: str = "#55626F"         # secondary text
    ink_3: str = "#8792A0"         # tertiary text, placeholders
    paper: str = "#FFFFFF"         # work surfaces
    chrome: str = "#F2F4F6"        # window background, rails, bars
    hairline: str = "#D9DEE3"      # borders and dividers
    hover: str = "#E8ECEF"
    accent: str = "#0B6E79"        # teal: primary action, selection, map
    accent_hover: str = "#095A63"
    accent_soft: str = "#DCEFF1"   # selected row, current nav item
    accent_muted: str = "#8FBFC4"
    ok: str = "#2F9E44"
    warn: str = "#E8590C"
    danger: str = "#C92A2A"
    new: str = "#1971C2"
    row_alt: str = "#FAFBFC"
    empty_cell: str = "#E6EAEE"

    # Aliases kept for older call sites.
    @property
    def text(self) -> str:
        return self.ink

    @property
    def text_muted(self) -> str:
        return self.ink_3

    @property
    def selection(self) -> str:
        return self.accent_soft

    @property
    def link(self) -> str:
        return self.accent

    @property
    def warning(self) -> str:
        return self.warn

    @property
    def header_bg(self) -> str:
        return self.chrome

    @property
    def console_bg(self) -> str:
        return self.paper


PALETTE = Palette()

UI_FONT = ("Segoe UI", 9)
UI_FONT_BOLD = ("Segoe UI Semibold", 9)
BODY_FONT = ("Segoe UI", 10)
TITLE_FONT = ("Segoe UI Semibold", 13)
SUBTITLE_FONT = ("Segoe UI Semibold", 10)
MONO_FONT = ("Consolas", 10)

#: Screen scale factor (1.0 at 96 DPI, 1.25 at 120 DPI...), set by
#: :func:`setup_style`. Treeview column widths and row heights are plain
#: pixels and do not follow the font size, so they go through :func:`px`.
SCALE = 1.0

ICON_DIR = Path(__file__).resolve().parents[1] / "assets" / "icons"


def px(value: float) -> int:
    """Scale a 96-DPI pixel size to the current screen."""
    return int(round(value * SCALE))


def current() -> Palette:
    return PALETTE


def setup_style(root: tk.Misc) -> ttk.Style:
    """Flat styles on top of ttk's 'clam' engine, which accepts custom colours."""
    global SCALE
    try:
        SCALE = max(1.0, root.winfo_fpixels("1i") / 96.0)
    except tk.TclError:
        SCALE = 1.0
    p = PALETTE
    style = ttk.Style(root)
    style.theme_use("clam")

    for named in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
        try:
            tkfont.nametofont(named).configure(family=UI_FONT[0], size=UI_FONT[1])
        except tk.TclError:
            pass
    # Only classic Tk widgets read fonts from the option database. A global
    # "*Font" would also set the -font option of every ttk label and silently
    # override the style (all headings rendered at body size).
    for widget in ("Menu", "Text", "Listbox", "Label", "Entry"):
        root.option_add(f"*{widget}.font", tkfont.nametofont("TkDefaultFont"))
    root.option_add("*TCombobox*Listbox.background", p.paper)
    root.option_add("*TCombobox*Listbox.selectBackground", p.accent_soft)
    root.option_add("*TCombobox*Listbox.selectForeground", p.ink)
    root.option_add("*Menu.background", p.paper)
    root.option_add("*Menu.activeBackground", p.accent_soft)
    root.option_add("*Menu.activeForeground", p.ink)
    root.option_add("*Menu.relief", "flat")
    root.configure(background=p.chrome)
    root.option_add("*Toplevel.background", p.paper)

    style.configure(".", background=p.chrome, foreground=p.ink, bordercolor=p.hairline,
                    lightcolor=p.paper, darkcolor=p.hairline, troughcolor=p.chrome,
                    focuscolor=p.accent, selectbackground=p.accent_soft,
                    selectforeground=p.ink, insertcolor=p.ink, font=UI_FONT)
    style.configure("TFrame", background=p.paper)
    style.configure("Chrome.TFrame", background=p.chrome)
    style.configure("Paper.TFrame", background=p.paper)
    style.configure("Rule.TFrame", background=p.hairline)
    style.configure("TLabel", background=p.paper, foreground=p.ink)
    style.configure("Paper.TLabel", background=p.paper)
    style.configure("Muted.TLabel", background=p.paper, foreground=p.ink_3)
    style.configure("PaperMuted.TLabel", background=p.paper, foreground=p.ink_3)
    style.configure("Secondary.TLabel", background=p.paper, foreground=p.ink_2)
    style.configure("Warn.TLabel", background=p.paper, foreground=p.danger)
    style.configure("PaperWarn.TLabel", background=p.paper, foreground=p.danger)
    style.configure("Title.TLabel", background=p.paper, font=TITLE_FONT)
    style.configure("Subtitle.TLabel", background=p.paper, font=SUBTITLE_FONT)
    style.configure("Brand.TLabel", background=p.paper, font=("Segoe UI Semibold", 11))
    style.configure("Status.TLabel", background=p.chrome, foreground=p.ink_2,
                    padding=(px(8), px(3)))

    style.configure("TButton", background=p.paper, foreground=p.ink, bordercolor="#C5CCD3",
                    lightcolor=p.paper, darkcolor=p.paper, relief="solid", borderwidth=1,
                    padding=(px(10), px(4)), focusthickness=1, focuscolor=p.accent_muted)
    style.map("TButton",
              background=[("disabled", p.paper), ("pressed", p.hover), ("active", p.hover)],
              foreground=[("disabled", p.ink_3)],
              bordercolor=[("disabled", p.hairline), ("focus", p.accent), ("active", "#AEB7C1")])
    # ttk buttons default to at least 11 characters wide; small ones size to text.
    style.configure("Small.TButton", padding=(px(8), px(2)), width=-4)
    style.configure("Accent.TButton", background=p.accent, foreground="#FFFFFF",
                    bordercolor=p.accent, lightcolor=p.accent, darkcolor=p.accent,
                    font=UI_FONT_BOLD)
    style.map("Accent.TButton",
              background=[("disabled", p.accent_muted), ("pressed", p.accent_hover),
                          ("active", p.accent_hover)],
              foreground=[("disabled", "#FFFFFF")],
              bordercolor=[("disabled", p.accent_muted)])
    style.configure("Toolbutton", background=p.paper, relief="flat", padding=(px(6), px(4)),
                    borderwidth=0)
    style.map("Toolbutton", background=[("active", p.hover), ("selected", p.accent_soft)])

    for widget in ("TEntry", "TCombobox"):
        style.configure(widget, fieldbackground=p.paper, background=p.paper,
                        bordercolor=p.hairline, lightcolor=p.paper, darkcolor=p.paper,
                        arrowcolor=p.ink_2, padding=(px(5), px(3)))
        style.map(widget,
                  bordercolor=[("focus", p.accent)], lightcolor=[("focus", p.accent)],
                  fieldbackground=[("disabled", p.chrome), ("readonly", p.paper)],
                  foreground=[("disabled", p.ink_3)])
    style.configure("TCheckbutton", background=p.paper, foreground=p.ink,
                    indicatorbackground=p.paper, indicatorforeground=p.paper,
                    indicatormargin=(0, 0, px(6), 0), indicatorsize=px(13),
                    upperbordercolor=p.ink_3, lowerbordercolor=p.ink_3)
    style.map("TCheckbutton",
              indicatorbackground=[("selected", p.accent), ("active", p.hover)],
              indicatorforeground=[("selected", p.accent)],
              upperbordercolor=[("selected", p.accent)],
              lowerbordercolor=[("selected", p.accent)],
              background=[("active", p.paper)])
    style.configure("Chrome.TCheckbutton", background=p.chrome)
    style.map("Chrome.TCheckbutton", background=[("active", p.chrome)])

    style.configure("Treeview", background=p.paper, fieldbackground=p.paper,
                    foreground=p.ink, rowheight=px(26), borderwidth=0, relief="flat",
                    font=UI_FONT)
    style.map("Treeview", background=[("selected", p.accent_soft)],
              foreground=[("selected", p.ink)])
    style.configure("Treeview.Heading", background=p.paper, foreground=p.ink_2,
                    font=UI_FONT, relief="flat", borderwidth=1, bordercolor=p.hairline,
                    lightcolor=p.paper, darkcolor=p.hairline, padding=(px(6), px(5)))
    style.map("Treeview.Heading", background=[("active", p.chrome)])
    style.configure("Results.Treeview", rowheight=px(28))
    style.configure("Props.Treeview", rowheight=px(22))
    style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

    style.configure("TScrollbar", background=p.chrome, troughcolor=p.paper,
                    bordercolor=p.paper, lightcolor=p.chrome, darkcolor=p.chrome,
                    arrowcolor=p.ink_3, gripcount=0, arrowsize=px(11))
    style.map("TScrollbar", background=[("active", p.hairline)])
    style.configure("TPanedwindow", background=p.hairline)
    style.configure("Sash", sashthickness=px(5), background=p.chrome, gripcount=0)
    style.configure("Accent.Horizontal.TProgressbar", background=p.accent,
                    troughcolor=p.hairline, bordercolor=p.hairline, lightcolor=p.accent,
                    darkcolor=p.accent, thickness=px(4))
    style.configure("TSeparator", background=p.hairline)
    style.configure("TNotebook", background=p.paper, borderwidth=0)
    style.configure("TNotebook.Tab", background=p.chrome, padding=(px(10), px(4)))
    style.map("TNotebook.Tab", background=[("selected", p.paper)])
    return style


# --------------------------------------------------------------------------- #
# Icons
# --------------------------------------------------------------------------- #
def _pick_size(base: int, available: tuple[int, ...]) -> int:
    wanted = px(base)
    return min(available, key=lambda size: (abs(size - wanted), -size))


class Icons:
    """Loads the PNG icon set (needs a Tk root) and builds row icons."""

    ROW_SIZES = (16, 20, 24, 32)
    HEADER_SIZES = (32, 40, 48, 64)
    BADGE_SIZES = (8, 10, 12, 16)
    BADGES = ("online", "new", "risk", "danger", "favorite")

    def __init__(self, folder: Path | None = None) -> None:
        self._folder = folder or ICON_DIR
        self._cache: dict[tuple, tk.PhotoImage] = {}
        self.row_size = _pick_size(20, self.ROW_SIZES)
        self.ui_size = _pick_size(16, self.ROW_SIZES)
        self.header_size = _pick_size(40, self.HEADER_SIZES)
        self.badge_size = _pick_size(9, self.BADGE_SIZES)
        # Names used by the rest of the window.
        self.scan = self.ui("scan")
        self.stop = self.ui("stop")
        self.folder = self.ui("folder")
        self.service = self.ui("service")
        self.options = self.ui("options")
        self.export = self.ui("export")
        self.report = self.ui("report")
        self.online = self.device("unknown", "online")
        self.danger = self.device("unknown", "danger")
        self.offline = self.device("unknown")

    def _file(self, name: str, size: int) -> tk.PhotoImage:
        key = ("file", name, size)
        if key not in self._cache:
            path = self._folder / f"{name}_{size}.png"
            try:
                self._cache[key] = tk.PhotoImage(file=str(path))
            except tk.TclError:
                self._cache[key] = tk.PhotoImage(width=size, height=size)
        return self._cache[key]

    def ui(self, name: str, size: int | None = None) -> tk.PhotoImage:
        return self._file(name, size or self.ui_size)

    def header(self, category: str) -> tk.PhotoImage:
        return self._file(category or "unknown", self.header_size)

    def device(self, category: str, badge: str = "") -> tk.PhotoImage:
        """Device glyph with an optional status badge in its bottom-right corner."""
        category = category or "unknown"
        key = ("device", category, badge)
        if key in self._cache:
            return self._cache[key]
        glyph = self._file(category, self.row_size)
        if not badge:
            self._cache[key] = glyph
            return glyph
        size = self.row_size
        image = tk.PhotoImage(width=size, height=size)
        image.tk.call(image, "copy", glyph)
        mark = self._file(f"badge_{badge}", self.badge_size)
        offset = size - self.badge_size
        image.tk.call(image, "copy", mark, "-to", offset, offset,
                      "-compositingrule", "overlay")
        self._cache[key] = image
        return image


def enable_dpi_awareness() -> None:
    """Crisp text on high-DPI Windows screens (call before creating the root)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass
