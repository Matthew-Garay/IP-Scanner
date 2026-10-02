"""Corporate colour palette and result table for IP Inspector.

The palette follows a restrained industrial scheme: one corporate blue for
actions and selection, a near-white (light) or slate (dark) background --
never pure black, which fatigues the eye -- and semantic colours reserved
strictly for device state.

The results table is a grid of lightweight per-row frames rather than a
``ttk.Treeview``. A Treeview cannot host a chart in a cell, and the tables
here carry status *dots* plus a latency sparkline, so a few rows of composed
widgets are cheaper than fighting the widget. Rows are appended during a
scan and rebuilt only on sort or filter, so a full /24 sweep stays fast.
"""

from __future__ import annotations

from dataclasses import dataclass
import tkinter as tk

import customtkinter as ctk


@dataclass(frozen=True)
class Palette:
    """Resolved colours for one appearance mode."""

    primary: str
    primary_hover: str
    primary_active: str
    #: Deeper accent held back for the one call to action on screen, so the
    #: primary blue can stay on secondary affordances without diluting it.
    accent: str
    accent_hover: str
    accent_text: str
    background: str
    surface: str
    #: Slightly offset surface: group strips, hover plates, quiet panels.
    surface_alt: str
    hover: str
    text_primary: str
    text_secondary: str
    #: Caption grey. Held above 4.5:1 on the surfaces it is drawn on: labels
    #: such as column heads and field captions carry meaning.
    text_muted: str
    header_bg: str
    header_text: str
    row_even: str
    row_odd: str
    #: Hairline between table rows and panels: structure without borders.
    grid_line: str
    selection: str
    selection_text: str
    border: str
    #: Field fill. Deliberately *not* the panel colour: an input that matches
    #: the panel behind it reads as text printed on the window.
    field: str
    #: Field border, held at 3:1 or better against both the panel and the
    #: field fill (WCAG 1.4.11, non-text contrast).
    field_border: str
    field_focus: str
    #: Small status/context chip.
    chip: str
    chip_text: str
    #: Kept for the plain ``input_bg`` readers; same as ``field``.
    input_bg: str
    online: str
    vpn: str
    warning: str
    #: State codes, kept separate from the brand so "green = reachable" never
    #: competes with "blue = you can click this".
    state_ok: str
    state_warn: str
    state_off: str
    state_idle: str


#: Corporate light scheme. The page is a clear grey-blue and every panel,
#: field and card is white, so an input always reads as something you can
#: type in. Status colours are dark enough to carry text on white.
LIGHT = Palette(
    primary="#005FA3",
    primary_hover="#00508C",
    primary_active="#004578",
    accent="#0B4F8A",
    accent_hover="#093F6E",
    accent_text="#FFFFFF",
    background="#E9EDF2",
    surface="#FFFFFF",
    surface_alt="#F4F6F9",
    hover="#E3EAF2",
    text_primary="#1B2430",
    text_secondary="#4A5568",
    text_muted="#64707F",
    header_bg="#1F4E79",
    header_text="#FFFFFF",
    row_even="#FFFFFF",
    row_odd="#F5F8FB",
    grid_line="#DFE5EC",
    selection="#CFE4F7",
    selection_text="#123A5C",
    border="#C3CCD8",
    field="#FFFFFF",
    field_border="#7C8797",
    field_focus="#005FA3",
    chip="#EDF1F6",
    chip_text="#35414F",
    input_bg="#FFFFFF",
    online="#157F3D",
    vpn="#B25E09",
    warning="#C0392B",
    state_ok="#157F3D",
    state_warn="#B25E09",
    state_off="#C0392B",
    state_idle="#6B7684",
)

#: Dark scheme: slate rather than pure black, with the page darker than the
#: panels and the panels darker than the fields, so the same layering the
#: light scheme uses still reads top-down.
DARK = Palette(
    primary="#2E86C8",
    primary_hover="#3D99DE",
    primary_active="#256EAC",
    accent="#4DA3E8",
    accent_hover="#63B6F2",
    accent_text="#0B1621",
    background="#16181C",
    surface="#21252B",
    surface_alt="#1B1E23",
    hover="#2C3138",
    text_primary="#E8EAED",
    text_secondary="#B9C0C9",
    text_muted="#96A0AC",
    header_bg="#1B3A56",
    header_text="#FFFFFF",
    row_even="#21252B",
    row_odd="#1D2126",
    grid_line="#313740",
    selection="#24507D",
    selection_text="#FFFFFF",
    border="#3A414A",
    field="#14171A",
    field_border="#4C5661",
    field_focus="#4DA3E8",
    chip="#262B32",
    chip_text="#C6CDD6",
    input_bg="#14171A",
    online="#3FB950",
    vpn="#D29922",
    warning="#F85149",
    state_ok="#3FB950",
    state_warn="#D29922",
    state_off="#F85149",
    state_idle="#8B949E",
)


#: Appearance mode mirror. CustomTkinter does not expose a reliable
#: public getter across versions, so we record it ourselves.
_MODE: str = "light"


def set_mode(mode: str) -> None:
    """Record the active appearance mode and notify the live widgets."""
    global _MODE
    _MODE = "dark" if str(mode).lower() == "dark" else "light"
    for widget in (*_TABLES, *_SPARKLINES):
        try:
            widget.refresh()
        except Exception:  # noqa: BLE001 - a dead widget must not break the switch
            pass


def is_dark() -> bool:
    """True when the application is in dark appearance mode."""
    return _MODE == "dark"


#: Live tables, so a mode switch can restyle them without a rebuild.
_TABLES: list["ResultTable"] = []

#: Live sparklines, restyled for the same reason.
_SPARKLINES: list["Sparkline"] = []

#: Live device-type icons, restyled for the same reason.
_ICONS: list["TypeIcon"] = []

#: Ceiling of a table sparkline in milliseconds. Fixed, so the row of a quiet
#: host and the row of a struggling one can be compared side by side.
SPARKLINE_SCALE_MS = 120.0

#: Window a table sparkline keeps, matching the monitor's history depth.
SPARKLINE_CAPACITY = 60


#: Semantic aliases used for the status dot, independent of the scheme.
def online() -> str:
    """Green used for reachable devices."""
    return current().online


def vpn() -> str:
    """Amber used when a VPN or a risky exposure is detected."""
    return current().vpn


def warning() -> str:
    """Red used for critical findings and offline devices."""
    return current().warning


def current() -> Palette:
    """Return the palette matching the active appearance mode."""
    return DARK if is_dark() else LIGHT


# ---------------------------------------------------------------------------
# Small widget factories
# ---------------------------------------------------------------------------

def font(size: int = 13, weight: str = "normal") -> ctk.CTkFont:
    return ctk.CTkFont(size=size, weight=weight)


def primary_button(master, text: str, command, width: int = 132,
                   height: int = 34) -> ctk.CTkButton:
    """Main call-to-action button."""
    p = current()
    return ctk.CTkButton(
        master, text=text, command=command, width=width, height=height,
        corner_radius=6,
        fg_color=p.primary, hover_color=p.primary_hover,
        text_color="#FFFFFF", font=font(13, "bold"),
    )


def secondary_button(master, text: str, command, width: int = 100,
                     height: int = 34) -> ctk.CTkButton:
    """Outlined secondary action."""
    p = current()
    return ctk.CTkButton(
        master, text=text, command=command, width=width, height=height,
        corner_radius=6,
        fg_color="transparent", hover_color=p.selection,
        border_width=1, border_color=p.primary,
        text_color=p.primary, font=font(13),
    )


def field(master, placeholder: str, **kwargs) -> ctk.CTkEntry:
    """Styled single-line input."""
    p = current()
    return ctk.CTkEntry(
        master, placeholder_text=placeholder, height=34, corner_radius=6,
        fg_color=p.input_bg, border_color=p.border, text_color=p.text_primary,
        placeholder_text_color=p.text_secondary, font=font(13), **kwargs,
    )


def caption(master, text: str) -> ctk.CTkLabel:
    """Small uppercase caption above an input."""
    p = current()
    return ctk.CTkLabel(
        master, text=text.upper(), font=font(10, "bold"), text_color=p.text_secondary,
    )


def progress_bar(master, width: int = 320, height: int = 6):
    """Thin progress bar for the status bar: no visual noise, no modal."""
    p = current()
    return ctk.CTkProgressBar(
        master, width=width, height=height, corner_radius=3,
        progress_color=p.primary, fg_color=p.border,
    )


def panel(master) -> ctk.CTkFrame:
    """Grouped surface with a subtle border."""
    p = current()
    return ctk.CTkFrame(
        master, fg_color=p.surface, corner_radius=8, border_width=1,
        border_color=p.border,
    )


def _mix(colour: str, towards: str, ratio: float) -> str:
    """Blend two ``#rrggbb`` colours; ``ratio`` is the share of the second."""
    def channels(value: str) -> tuple[int, int, int]:
        value = value.lstrip("#")
        return tuple(int(value[i : i + 2], 16) for i in (0, 2, 4))  # type: ignore[return-value]

    first, second = channels(colour), channels(towards)
    blended = [round(a + (b - a) * ratio) for a, b in zip(first, second)]
    return "#" + "".join(f"{value:02X}" for value in blended)


class Sparkline(ctk.CTkFrame):
    """
    Mini latency chart: a filled line that breaks where packets were lost.

    CustomTkinter ships no chart, so the drawing is a plain ``tk.Canvas``
    wrapped in a themed frame. A sample of ``None`` is a lost probe: the line
    is cut and a red tick marks the gap, which is what makes an intermittent
    link obvious at a glance.

    The vertical scale auto-fits the window unless ``scale_ms`` fixes it, and
    the table cells fix it so two hosts can be compared row against row.
    """

    def __init__(
        self,
        master,
        width: int = 110,
        height: int = 22,
        capacity: int = 60,
        fast_ms: float = 25.0,
        slow_ms: float = 90.0,
        scale_ms: float = 0.0,
        axis: bool = False,
    ) -> None:
        super().__init__(master, width=width, height=height,
                         fg_color="transparent", corner_radius=3, border_width=0)
        self._samples: list[float | None] = []
        self._capacity = max(2, capacity)
        self._fast, self._slow, self._scale = fast_ms, slow_ms, scale_ms
        self._axis = axis
        #: True once a table row has imposed its stripe colour on us.
        self._striped = False
        # Sits on the panel colour so an unfinished window reads as empty
        # space rather than as a broken widget; table cells override it with
        # the stripe they are drawn on.
        self._background = current().surface

        self.grid_propagate(False)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self._canvas = tk.Canvas(
            self, width=width, height=height, highlightthickness=0, bd=0,
            background=self._background,
        )
        self._canvas.grid(row=0, column=0, sticky="nsew")
        self.bind("<Configure>", self._redraw)
        _SPARKLINES.append(self)

    def destroy(self) -> None:
        """Stop tracking this widget so the registry cannot grow forever."""
        try:
            _SPARKLINES.remove(self)
        except ValueError:
            pass
        super().destroy()

    # -- data ------------------------------------------------------------
    def set_samples(self, samples, scale_ms: float | None = None) -> None:
        """Plot a window of round trips, ``None`` meaning a lost packet."""
        self._samples = list(samples)[-self._capacity :]
        if scale_ms is not None:
            self._scale = scale_ms
        self._redraw()

    def clear(self) -> None:
        """Empty the graph without forgetting its scale."""
        self.set_samples([])

    def set_background(self, colour: str) -> None:
        """Blend the plot into its parent, used by the striped table rows."""
        self._striped = True
        if colour == self._background:
            return
        self._background = colour
        self._canvas.configure(background=colour)
        self._redraw()

    def refresh(self) -> None:
        """Re-draw after an appearance mode change."""
        if not self._striped:
            self._background = current().surface
            self._canvas.configure(background=self._background)
        self._redraw()
    # -- drawing ---------------------------------------------------------
    def _ceiling(self) -> float:
        """Top of the scale: a fixed one when given, otherwise the data."""
        highest = [value for value in self._samples if value is not None]
        auto = max(highest) * 1.2 if highest else self._slow
        return max(self._scale, auto, 1.0)

    def _colour(self) -> str:
        """Green while the average is quick, amber when it drags, red past slow."""
        pal = current()
        values = [value for value in self._samples if value is not None]
        if not values:
            return pal.text_secondary
        average = sum(values) / len(values)
        if average <= self._fast:
            return pal.online
        return pal.vpn if average <= self._slow else pal.warning

    def _redraw(self, _event=None) -> None:
        canvas = self._canvas
        canvas.delete("all")
        # A tab that has never been shown reports a size of one pixel, so the
        # requested size stands in until the first <Configure> arrives.
        width = canvas.winfo_width() or canvas.winfo_reqwidth()
        height = canvas.winfo_height() or canvas.winfo_reqheight()
        if width < 20 or height < 12:
            return

        pal = current()
        ceiling = self._ceiling()
        top, bottom = 6.0, height - (16 if self._axis else 3.0)

        def y_of(value: float) -> float:
            return bottom - (bottom - top) * min(max(value, 0.0) / ceiling, 1.0)

        # Threshold guides: what a quick hop and a slow one look like.
        for level in (self._fast, self._slow):
            if 0 < level < ceiling:
                guide = y_of(level)
                canvas.create_line(0, guide, width, guide, fill=pal.border, dash=(2, 4))
        if self._axis:
            canvas.create_text(
                4, height - 7, anchor="w", text=f"{ceiling:.0f} ms",
                fill=pal.text_secondary, font=("Segoe UI", 8),
            )
        if not self._samples:
            return

        # A fixed step keeps the graph an honest time axis: it fills from the
        # left and stops at the newest sample instead of stretching to fit.
        step = width / (self._capacity - 1)
        colour = self._colour()
        segments: list[list[tuple[float, float]]] = []
        run: list[tuple[float, float]] = []
        for index, value in enumerate(self._samples):
            x = index * step
            if value is None:
                if len(run) > 1:
                    segments.append(run)
                run = []
                # A lost packet: a dashed red bar over the whole plot, so the
                # eye reads "nothing came back here" rather than a real spike.
                canvas.create_line(x, top, x, bottom, fill=pal.warning,
                                   width=2, dash=(2, 2))
                continue
            run.append((x, y_of(value)))
        if len(run) > 1:
            segments.append(run)

        tint = _mix(colour, self._background, 0.80)
        for points in segments:
            flat = [value for point in points for value in point]
            canvas.create_line(flat, fill=colour, width=2, capstyle="round")
            # Close the area under the line, back along the baseline.
            canvas.create_polygon(
                flat + [points[-1][0], bottom, points[0][0], bottom],
                fill=tint, outline="",
            )
        if len(run) == 1:
            # A single answer still deserves a dot.
            x, y = run[0]
            canvas.create_oval(x - 2, y - 2, x + 2, y + 2, fill=colour, outline="")


# ---------------------------------------------------------------------------
# Device-type icon
# ---------------------------------------------------------------------------


#: How each device class is drawn, as a key into the drawing routines below.
#: The old approach used BMP glyphs (a filled square for every desktop, a
#: striped square for every server), which told an operator nothing: three
#: different machines drew the same mark. Vector shapes are recognisable at
#: this size and cannot go missing on a machine whose fonts lack a symbol.
TYPE_ICON_KINDS: dict[str, str] = {
    "Router": "router",
    "Network Device": "switch",
    "IP Camera": "camera",
    "Printer": "printer",
    "Windows PC": "desktop",
    "Mac / Apple": "desktop",
    "Apple Device": "mobile",
    "Mobile / Tablet": "mobile",
    "Linux Server": "server",
    "Server": "server",
    "Raspberry Pi": "board",
    "IoT Device": "board",
}

#: Used for anything the classifier could not place.
UNKNOWN_ICON_KIND = "unknown"


def icon_kind(device_type: str) -> str:
    """Drawing routine for a device class, never empty."""
    return TYPE_ICON_KINDS.get(device_type, UNKNOWN_ICON_KIND)


class TypeIcon(ctk.CTkFrame):
    """
    A small pictogram of the device class, drawn rather than typeset.

    Every glyph approach was a compromise: a BMP symbol renders only where the
    font carries it, and the symbols that do carry are so close together that a
    desktop, a server and a switch all read as the same box. Drawing the shape
    on a canvas makes the mark explicit and immune to the installed fonts,
    which is the same reason :class:`Sparkline` paints itself.
    """

    def _ink(self) -> str:
        """Colour the pictogram is drawn in."""
        return current().text_secondary

    def __init__(self, master, width: int = 20, height: int = 20,
                 kind: str = UNKNOWN_ICON_KIND) -> None:
        super().__init__(master, width=width, height=height,
                         fg_color="transparent", corner_radius=0, border_width=0)
        self._kind = kind
        self._striped = False
        self._background = current().surface

        self.grid_propagate(False)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self._canvas = tk.Canvas(
            self, width=width, height=height, highlightthickness=0, bd=0,
            background=self._background,
        )
        self._canvas.grid(row=0, column=0, sticky="nsew")
        self.bind("<Configure>", lambda _e: self._redraw())
        # Drawn up front from the requested size. <Configure> only arrives once
        # the row has been laid out, and a table built before the window is
        # first shown would otherwise hold a row of blank cells until the
        # operator resizes something.
        self.bind("<Map>", lambda _e: self._redraw())
        self.after_idle(self._redraw)
        _ICONS.append(self)
        self._redraw()

    def destroy(self) -> None:
        """Stop tracking this widget so the registry cannot grow forever."""
        try:
            _ICONS.remove(self)
        except ValueError:
            pass
        super().destroy()

    def set_kind(self, kind: str) -> None:
        """Switch the pictogram to another device class."""
        if kind != self._kind:
            self._kind = kind
            self._redraw()

    def set_background(self, colour: str) -> None:
        """Blend the icon into its parent, used by the striped table rows."""
        self._striped = True
        if colour == self._background:
            return
        self._background = colour
        self._canvas.configure(background=colour)
        self._redraw()

    def refresh(self) -> None:
        """Re-draw after an appearance mode change."""
        if not self._striped:
            self._background = current().surface
            self._canvas.configure(background=self._background)
        self._redraw()

    def _redraw(self) -> None:
        canvas = self._canvas
        canvas.delete("all")
        # A widget that has not been laid out yet reports a real size of one
        # pixel, so the requested size stands in until <Configure> arrives. A
        # canvas left at one pixel would draw nothing at all, which is how an
        # icon silently becomes a blank cell in a table built before the
        # window is first shown.
        w = canvas.winfo_width()
        h = canvas.winfo_height()
        if w < 8 or h < 8:
            w, h = canvas.winfo_reqwidth(), canvas.winfo_reqheight()
        if w < 8 or h < 8:
            return
        painter = getattr(self, "_draw_" + self._kind, self._draw_unknown)
        painter(canvas, w, h, self._ink())

    def _box(self, w, h, pad_x=2, pad_y=2):
        """Inset rectangle every routine draws inside, so shapes keep their
        proportions whatever the row height is."""
        s = min(w, h)
        x0, y0 = (w - s) / 2 + pad_x, (h - s) / 2 + pad_y
        return x0, y0, x0 + s - pad_x - 1, y0 + s - pad_y - 1

    # -- the pictograms --------------------------------------------------
    def _draw_router(self, canvas, w, h, ink) -> None:
        """A box with a crossing arrow: the thing traffic goes through."""
        x0, y0, x1, y1 = self._box(w, h, 2, 3)
        canvas.create_rectangle(x0, y0, x1, y1, outline=ink, width=2)
        mid = (y0 + y1) / 2
        canvas.create_line(x0 + 2, mid, x1 - 4, mid, fill=ink, width=2)
        canvas.create_polygon(
            (x1 - 2, mid, x1 - 6, mid - 3.5, x1 - 6, mid + 3.5), fill=ink, outline=""
        )
        canvas.create_line(mid, y0 + 2, mid, y1 - 2, fill=ink, width=1, dash=(2, 2))

    def _draw_switch(self, canvas, w, h, ink) -> None:
        """A chassis with a row of ports and a link light."""
        x0, y0, x1, y1 = self._box(w, h, 2, 3)
        canvas.create_rectangle(x0, y0, x1, y1, outline=ink, width=2)
        step = (x1 - x0 - 5) / 4
        for index in range(4):
            px = x0 + 3 + index * step
            canvas.create_rectangle(px, y1 - 5.5, px + step - 2, y1 - 2.5,
                                    outline=ink, fill="")
        canvas.create_oval(x1 - 5, y0 + 2, x1 - 3, y0 + 4, fill=ink, outline="")

    def _draw_camera(self, canvas, w, h, ink) -> None:
        """A lens: a body with a big circle pointing out of it."""
        s = min(w, h)
        cx, cy = w / 2, h / 2
        r = s / 2 - 3
        canvas.create_rectangle(cx - r, cy - r * 0.78, cx + r * 0.45, cy + r * 0.78,
                                outline=ink, width=2)
        canvas.create_oval(cx - r * 0.5, cy - r * 0.72, cx + r * 0.7, cy + r * 0.72,
                           outline=ink, width=2)
        canvas.create_line(cx + r * 0.45, cy - r * 0.45, cx + r * 0.9, cy - r * 0.85,
                           fill=ink, width=2)

    def _draw_printer(self, canvas, w, h, ink) -> None:
        """Paper coming out of a printer."""
        s = min(w, h)
        x0, y0 = (w - s) / 2 + 2, (h - s) / 2 + 1
        x1, y1 = x0 + s - 5, y0 + s - 3
        canvas.create_rectangle(x0, y0 + 4, x1, y1 - 4, outline=ink, width=2)
        canvas.create_rectangle(x0 + 3, y0 - 1, x1 - 3, y0 + 5,
                                outline=ink, fill="", width=2)
        canvas.create_oval(x1 - 4, y1 - 7.5, x1 - 2.5, y1 - 6, fill=ink, outline="")

    def _draw_desktop(self, canvas, w, h, ink) -> None:
        """A monitor on a stand: any workstation."""
        x0, y0, x1, y1 = self._box(w, h, 2, 1)
        base = min(w, h) / 2 - 1
        canvas.create_rectangle(x0, y0, x1, base, outline=ink, width=2)
        mid = (x0 + x1) / 2
        canvas.create_line(mid, base, mid, base + 3, fill=ink, width=2)
        canvas.create_line(x0 + 3, base + 3, x1 - 3, base + 3, fill=ink, width=2)

    def _draw_server(self, canvas, w, h, ink) -> None:
        """A rack: stacked units with a status light each."""
        x0, y0, x1, y1 = self._box(w, h, 2, 2)
        canvas.create_rectangle(x0, y0, x1, y1, outline=ink, width=2)
        unit = (y1 - y0) / 3
        for index in range(3):
            top = y0 + index * unit
            if index:
                canvas.create_line(x0, top, x1, top, fill=ink)
            canvas.create_oval(x0 + 2, top + unit / 2 - 1.2, x0 + 4.4,
                               top + unit / 2 + 1.2, fill=ink, outline="")

    def _draw_board(self, canvas, w, h, ink) -> None:
        """A single-board computer: a board with a chip and pin rows."""
        x0, y0, x1, y1 = self._box(w, h, 2, 2)
        canvas.create_rectangle(x0, y0, x1, y1, outline=ink, width=2)
        canvas.create_rectangle(x0 + 3.5, y0 + 3.5, x1 - 3.5, y1 - 3.5, outline=ink)
        for edge in (x0, x1):
            canvas.create_line(edge, y0 + 1, edge, y1 - 1, fill=ink, dash=(2, 2))

    def _draw_mobile(self, canvas, w, h, ink) -> None:
        """A slab with a home dot: a phone or a tablet."""
        s = min(w, h)
        x0, y0 = (w - s) / 2 + 3, (h - s) / 2 + 1
        x1, y1 = x0 + s - 7, y0 + s - 3
        canvas.create_rectangle(x0, y0, x1, y1, outline=ink, width=2)
        mid = (x0 + x1) / 2
        canvas.create_oval(mid - 1.3, y1 - 4, mid + 1.3, y1 - 1.4, fill=ink, outline="")

    def _draw_unknown(self, canvas, w, h, ink) -> None:
        """A dashed box: recognised as a device, but not classified."""
        x0, y0, x1, y1 = self._box(w, h, 2, 2)
        canvas.create_rectangle(x0, y0, x1, y1, outline=ink, dash=(2, 2))
        canvas.create_line(x0 + 3, (y0 + y1) / 2, x1 - 3, (y0 + y1) / 2,
                           fill=ink, width=2)


# ---------------------------------------------------------------------------
# Result table
# ---------------------------------------------------------------------------




class ResultTable(ctk.CTkFrame):
    """
    Dense results grid built from lightweight per-row frames.

    A ttk.Treeview cannot colour a single cell nor host a chart, and the
    brief asks for status *dots* and a latency sparkline, so rows are
    composed widgets. Rows are appended during a scan and rebuilt only on
    sort/filter, which keeps a /24 sweep fast.

    ``sparkline`` names the column index that holds a :class:`Sparkline`
    instead of a label; ``rebuild`` then feeds it the samples for that row.
    """

    #: Height of a data row, in pixels. Generous on purpose: this is a reading
    #: surface, not a status strip, and a technician scanning a page of hosts
    #: should be able to take a row in at a glance. The cost is one more row
    #: off the viewport, which is far cheaper than squinting at 10px text.
    ROW_HEIGHT = 34

    #: Font sizes, in points. The body is one step above the 9pt header so a
    #: row reads as data rather than as chrome.
    HEADER_FONT_SIZE = 10
    ROW_FONT_SIZE = 12
    #: Leading for cells, as a share of the font size. Native Windows already
    #: spaces these faces well, so this is close to neutral.
    ROW_FONT_PADDING = 4

    def __init__(self, master, columns, on_sort=None, on_select=None,
                 sparkline=None, dot=None, icon=None, icons=None):
        super().__init__(master, fg_color="transparent", corner_radius=4)
        # columns: (label, width, anchor, mono, align)
        self._columns = columns
        self._on_sort = on_sort
        self._on_select = on_select
        self._sparkline = sparkline
        #: Column whose text is painted with the row's status colour.
        self._dot = dot
        #: Column holding a :class:`TypeIcon` instead of a label, and the
        #: mapping that tells each key which pictogram to draw.
        self._icon = icon
        # An empty dict is falsy, so ``icons or {}`` would quietly swap in a
        # different mapping and every row would fall back to the unknown
        # pictogram. The caller's dict is kept by reference instead.
        self._icons = {} if icons is None else icons
        self._rows: dict[str, tuple] = {}
        self._order: list[str] = []
        self._selected: str | None = None
        self._build()
        _TABLES.append(self)
        self.refresh()

    def destroy(self) -> None:
        """Stop tracking this widget so the registry cannot grow forever."""
        try:
            _TABLES.remove(self)
        except ValueError:
            pass
        super().destroy()

    # -- construction ----------------------------------------------------
    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        self._header = header

        for index, spec in enumerate(self._columns):
            label, width, anchor, _mono, _align = spec
            # Weight proportional to the column's own width, so the spare room
            # in a wide window is shared in proportion instead of all landing on
            # the last column. The declared width stays as the minimum, which
            # keeps a narrow window from crushing a column below what its
            # caption needs.
            header.grid_columnconfigure(index, minsize=width, weight=width)
            # Each heading lives in a fixed-width holder that refuses to grow. A
            # button sizes its column to whatever its caption needs, and
            # "STATUS" needs more than the 20px this column is allowed, so the
            # header ended up wider than the rows below it and every value sat
            # to the left of the heading it belonged to.
            holder = ctk.CTkFrame(
                header, width=width, height=26, fg_color="transparent",
                corner_radius=0,
            )
            holder.grid(row=0, column=index, sticky="ew")
            holder.grid_propagate(False)
            button = ctk.CTkButton(
                holder, text=label.upper(), width=width, height=26,
                corner_radius=3, fg_color="transparent", hover_color=None,
                text_color=("gray35", "gray62"),
                font=("Segoe UI", self.HEADER_FONT_SIZE, "bold"), anchor=anchor,
                command=(lambda i: self._on_sort(i)) if self._on_sort else None,
            )
            button.grid(row=0, column=0, sticky="ew")

        # The scrollable body gives 16px to its scrollbar and the header does
        # not, so the two grids were laid out on different widths and every
        # column drifted as the window grew. A spacer of the scrollbar's own
        # width reserves that gutter in the header, so the columns underneath
        # land exactly where their headings are.
        self._scrollbar_gutter = ctk.CTkFrame(
            header, width=0, height=26, fg_color="transparent", corner_radius=0,
        )
        self._scrollbar_gutter.grid(
            row=0, column=len(self._columns), sticky="nsew")
        header.grid_columnconfigure(len(self._columns), weight=0)

        self._body = ctk.CTkScrollableFrame(
            self, fg_color="transparent", corner_radius=0,
            scrollbar_button_color=("gray70", "gray35"),
        )
        self._body.grid(row=1, column=0, sticky="nsew")
        # The body holds one row per entry, not the data cells themselves, so
        # only its first column is real; the rest of the width belongs to
        # that row, which hands its trailing slack to its last column exactly
        # as the header does. Reserving minsizes here instead would squeeze
        # the rows and slide every cell out of place.
        self._body.grid_columnconfigure(0, weight=1)
        self._sync_gutter()
        self.bind("<Configure>", self._on_resize)

    def _sync_gutter(self) -> None:
        """Match the header's gutter to the scrollbar's real width."""
        scrollbar = getattr(self._body, "_scrollbar", None)
        if scrollbar is None or self._scrollbar_gutter is None:
            return
        try:
            width = scrollbar.winfo_reqwidth() or 16
        except Exception:  # noqa: BLE001 - a body not yet built is not fatal
            return
        self._scrollbar_gutter.configure(width=width)

    def _on_resize(self, _event=None) -> None:
        """Keep the header and the body on the same width after a resize."""
        self._sync_gutter()

    # -- styling ---------------------------------------------------------
    def refresh(self) -> None:
        """Re-apply palette colours to header and existing rows."""
        pal = current()
        for index in range(len(self._columns)):
            # The caption now sits on a button inside a fixed-width holder, so
            # the widget that carries the colour is one level down.
            holder = self._header.grid_slaves(row=0, column=index)[0]
            for button in holder.grid_slaves(row=0, column=0):
                button.configure(text_color=pal.text_secondary)
        self._restyle_all()

    def _restyle_all(self) -> None:
        for position, key in enumerate(self._order):
            self._style_row(self._rows[key][0], position, key == self._selected)

    def _style_row(self, row, position: int, selected: bool) -> None:
        pal = current()
        if selected:
            background = pal.selection
            border = pal.primary
        else:
            background = pal.row_even if position % 2 == 0 else pal.row_odd
            border = background
        row.configure(fg_color=background, border_color=border)
        # A canvas cannot inherit its parent's colour, so the chart cells are
        # told which stripe they are sitting on.
        for widget in row.winfo_children():
            blend = getattr(widget, "set_background", None)
            if blend is not None:
                blend(background)

    # -- data ------------------------------------------------------------
    def rebuild(self, rows, sparklines: dict | None = None) -> None:
        """
        Replace all rows. ``rows`` is a list of (key, cells, dot_colour).

        ``sparklines`` maps a key to the round trips that belong in that
        row's chart cell; it is ignored when the table has no such column.
        """
        self.clear()
        for position, (key, cells, dot) in enumerate(rows):
            self._insert(position, key, cells, dot,
                         (sparklines or {}).get(key) if self._sparkline is not None else None)

    def _insert(self, position: int, key: str, cells, dot, samples=None) -> None:
        """
        Add one row. ``dot`` is the status colour for the row, applied to
        the text of the column declared as the dot column.
        """
        pal = current()
        row = ctk.CTkFrame(
            self._body, fg_color="transparent", height=self.ROW_HEIGHT,
            corner_radius=3, border_width=1,
        )
        row.grid(row=position, column=0, sticky="ew", pady=0)
        # Every row reserves exactly the widths the header reserved, with the
        # same proportional weighting. Without this each row sized its own
        # columns from its own text, so a long hostname stretched the columns
        # beside it and every value drifted left of the header it belonged to.
        for index, spec in enumerate(self._columns):
            row.grid_columnconfigure(index, minsize=spec[1], weight=spec[1])
        row.grid_propagate(False)
        row.bind("<Button-1>", lambda _e, k=key: self._select(k))

        widgets = []
        for index, spec in enumerate(self._columns):
            _label, width, anchor, mono, _align = spec
            value = cells[index] if index < len(cells) else ""
            if index == self._sparkline:
                widget = Sparkline(
                    row, width=width - 4, height=self.ROW_HEIGHT - 6,
                    capacity=SPARKLINE_CAPACITY, scale_ms=SPARKLINE_SCALE_MS,
                )
                widget.set_samples(samples or [])
                widget.grid(row=0, column=index, sticky="ew", padx=2)
            elif index == self._icon:
                widget = TypeIcon(
                    row, width=width - 2, height=self.ROW_HEIGHT - 8,
                    kind=self._icons.get(key, UNKNOWN_ICON_KIND),
                )
                widget.grid(row=0, column=index, sticky="ew", padx=2)
            elif index == self._dot:
                # Cell widths are the column width minus the padding on both
                # sides, so a row grid lands exactly on the header grid. The
                # label is centred inside that width: the status dot belongs
                # under its heading, not against the left edge of the column.
                widget = ctk.CTkLabel(
                    row, text=value, width=width - 4, height=self.ROW_HEIGHT - 4,
                    anchor="center",
                    text_color=dot or (pal.online if value else pal.text_secondary),
                    font=("Segoe UI", self.ROW_FONT_SIZE, "bold"),
                )
                widget.grid(row=0, column=index, sticky="ew", padx=2)
            else:
                family = "Consolas" if mono else "Segoe UI"
                # Native Tk labels clip a 12pt face against a 34px row unless
                # they are told how much leading to leave around it, so the
                # padding is scaled with the font rather than left to chance.
                widget = ctk.CTkLabel(
                    row, text=value, width=width - 4, height=self.ROW_HEIGHT - 4,
                    anchor=anchor, text_color=pal.text_primary,
                    font=(family, self.ROW_FONT_SIZE),
                    padx=self.ROW_FONT_PADDING,
                    # Without this a long hostname or port list spills over the
                    # next column instead of ending at its own edge. The value
                    # is refreshed from the real width on <Configure>, so the
                    # wrap follows a column that grew with the window.
                    wraplength=width - 4 - 2 * self.ROW_FONT_PADDING,
                )
                widget.grid(row=0, column=index, sticky="ew", padx=2)
                widget.bind("<Configure>", self._rewrap, add="+")
            widgets.append(widget)

        self._rows[key] = (row, widgets, dot)
        # Insert at the visual position so a single-row rebuild keeps the
        # sort order; sequential rebuilds pass 0..n so this equals append.
        if position >= len(self._order):
            self._order.append(key)
        else:
            self._order.insert(position, key)
        self._style_row(row, position, key == self._selected)

    @staticmethod
    def _rewrap(event) -> None:
        """Keep a cell's wrap length on its real width.

        Columns now grow with the window, so a wrap length fixed at build time
        would let a long value wrap far too early and leave the rest of a
        widened column empty.
        """
        widget = event.widget
        real = widget.winfo_width()
        if real > 8:
            try:
                widget.configure(
                    wraplength=max(8, real - 2 * ResultTable.ROW_FONT_PADDING)
                )
            except Exception:  # noqa: BLE001 - a dead cell is not fatal
                pass

    def has_key(self, key: str) -> bool:
        """True when a row for ``key`` already exists in the table."""
        return key in self._rows

    def append_row(self, key: str, cells, dot, samples=None) -> None:
        """Append one row at the end without touching existing rows."""
        self._insert(len(self._order), key, cells, dot, samples)

    def update_row(self, key: str, cells, dot) -> None:
        """Update cell texts in place; creates the row if it went missing."""
        entry = self._rows.get(key)
        if not entry:
            self.append_row(key, cells, dot)
            return
        _row, widgets, _old_dot = entry
        for index, widget in enumerate(widgets):
            value = cells[index] if index < len(cells) else ""
            if isinstance(widget, TypeIcon):
                # The pictogram is keyed by row, not by cell text, so it needs
                # its own refresh path rather than the label one.
                widget.set_kind(self._icons.get(key, UNKNOWN_ICON_KIND))
            elif isinstance(widget, ctk.CTkLabel):
                try:
                    if widget.cget("text") != value:
                        widget.configure(text=value)
                except Exception:  # noqa: BLE001 - a stale row is rebuilt
                    self._insert_fallback(key, cells, dot)
                    return
                if index == self._dot and dot:
                    try:
                        widget.configure(text_color=dot)
                    except Exception:  # noqa: BLE001 - colour is cosmetic
                        pass
        self._rows[key] = (_row, widgets, dot)

    def _insert_fallback(self, key: str, cells, dot) -> None:
        """Rebuild a single row when an in-place update failed."""
        try:
            position = self._order.index(key)
        except ValueError:
            position = len(self._order)
        old = self._rows.pop(key, None)
        if old is not None:
            try:
                old[0].destroy()
            except Exception:  # noqa: BLE001 - the row may already be gone
                pass
            try:
                self._order.remove(key)
            except ValueError:
                pass
        self._insert(position, key, cells, dot)

    def clear(self) -> None:
        for row, _widgets, _dot in self._rows.values():
            row.destroy()
        self._rows.clear()
        self._order.clear()
        self._selected = None

    def row_count(self) -> int:
        return len(self._order)

    def keys(self) -> list[str]:
        return list(self._order)

    def key_at(self, y: int) -> str | None:
        """
        Row key under a pointer y given in the body's coordinate space.

        Rows are compared by their real screen position rather than by a
        canvas offset, so the answer stays right while the body is scrolled.
        This is what the right-click menu uses to act on the row under the
        cursor rather than on whatever happens to be selected.
        """
        pointer = self._body.winfo_rooty() + y
        for key in self._order:
            row = self._rows[key][0]
            top, height = row.winfo_rooty(), row.winfo_height()
            if height > 0 and top <= pointer < top + height:
                return key
        return None

    # -- selection -------------------------------------------------------
    def _select(self, key: str) -> None:
        if self._selected and self._selected in self._rows:
            previous = self._rows[self._selected][0]
            position = self._order.index(self._selected)
            self._style_row(previous, position, False)
        self._selected = key
        if key in self._rows:
            position = self._order.index(key)
            self._style_row(self._rows[key][0], position, True)
        if self._on_select:
            self._on_select(key)

    def select_key(self, key: str) -> None:
        self._select(key)

    def selected_key(self) -> str | None:
        return self._selected

    def bind_context_menu(self, callback) -> None:
        self._body.bind("<Button-3>", callback)
