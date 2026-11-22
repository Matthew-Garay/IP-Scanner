"""Colour palettes of IP Inspector.

Two palettes, light and dark, in a neutral "network tool" style: greys and
whites for surfaces, one strong colour for the Scan button and semantic
colours reserved for state (green reachable, amber warning, red down).

CustomTkinter widgets take ``(light, dark)`` pairs built from these and
switch by themselves; native ttk/tk widgets are restyled from
:func:`current` when the mode changes.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Palette:
    """Resolved colours for one appearance mode."""

    #: Brand / action colour used for the Scan button and selected row.
    primary: str
    primary_hover: str
    primary_active: str
    #: Secondary action colour (secondary buttons, subtle accents).
    accent: str
    accent_hover: str
    accent_text: str
    #: Window page colour behind panels.
    background: str
    #: Panel / card background.
    surface: str
    #: Slightly offset surface for group strips and hover plates.
    surface_alt: str
    hover: str
    text_primary: str
    text_secondary: str
    text_muted: str
    header_bg: str
    header_text: str
    row_even: str
    row_odd: str
    grid_line: str
    selection: str
    selection_text: str
    border: str
    field: str
    field_border: str
    field_focus: str
    chip: str
    chip_text: str
    input_bg: str
    online: str
    vpn: str
    warning: str
    state_ok: str
    state_warn: str
    state_off: str
    state_idle: str


#: Light scheme -- Advanced IP Scanner style.
#: Neutral industrial greys, white panels, strong blue/green Scan button.
LIGHT = Palette(
    primary="#0078D4",
    primary_hover="#0063B9",
    primary_active="#004C8F",
    accent="#2E7D32",
    accent_hover="#1B5E20",
    accent_text="#FFFFFF",
    background="#F2F2F2",
    surface="#FFFFFF",
    surface_alt="#EDEDED",
    hover="#D9D9D9",
    text_primary="#323130",
    text_secondary="#605E5C",
    text_muted="#8A8886",
    header_bg="#F2F2F2",
    header_text="#323130",
    row_even="#FFFFFF",
    row_odd="#F7F7F7",
    grid_line="#D0D0D0",
    selection="#E2EFFF",
    selection_text="#323130",
    border="#C8C8C8",
    field="#FFFFFF",
    field_border="#A6A6A6",
    field_focus="#0078D4",
    chip="#EDEDED",
    chip_text="#323130",
    input_bg="#FFFFFF",
    online="#2E7D32",
    vpn="#F57C00",
    warning="#D32F2F",
    state_ok="#2E7D32",
    state_warn="#F57C00",
    state_off="#D32F2F",
    state_idle="#9E9E9E",
)

#: Dark scheme: slate rather than pure black.
DARK = Palette(
    primary="#0A84FF",
    primary_hover="#0060DF",
    primary_active="#004C9E",
    accent="#30D158",
    accent_hover="#2CB248",
    accent_text="#000000",
    background="#1E1E1E",
    surface="#252525",
    surface_alt="#2D2D2D",
    hover="#383838",
    text_primary="#FFFFFF",
    text_secondary="#C9C9C9",
    text_muted="#858585",
    header_bg="#252525",
    header_text="#FFFFFF",
    row_even="#252525",
    row_odd="#2D2D2D",
    grid_line="#3E3E3E",
    selection="#2A4D8F",
    selection_text="#FFFFFF",
    border="#4A4A4A",
    field="#323232",
    field_border="#6E6E6E",
    field_focus="#0A84FF",
    chip="#383838",
    chip_text="#FFFFFF",
    input_bg="#323232",
    online="#30D158",
    vpn="#FF9F0A",
    warning="#FF453A",
    state_ok="#30D158",
    state_warn="#FF9F0A",
    state_off="#FF453A",
    state_idle="#8E8E8E",
)


#: Appearance mode mirror. CustomTkinter does not expose a reliable
#: public getter across versions, so we record it ourselves.
_MODE: str = "light"


def set_mode(mode: str) -> None:
    """Record the active appearance mode ("light", "dark" or CustomTkinter's names)."""
    global _MODE
    _MODE = "dark" if str(mode).lower() == "dark" else "light"


def is_dark() -> bool:
    """True when the application is in dark appearance mode."""
    return _MODE == "dark"


def current() -> Palette:
    """Return the palette matching the active appearance mode."""
    return DARK if is_dark() else LIGHT
