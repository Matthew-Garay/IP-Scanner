"""IT report generation in PDF and HTML.

The production dependency set is deliberately four packages, so no PDF
library is used here. A PDF is a text-based container format and the
standard 14 fonts (Helvetica, Courier) are expected to exist on the
reader, which means a correct report can be produced with the standard
library alone: no font embedding, no external binaries.

Both formats are generated from the same normalised dataset so the HTML
and the PDF always agree.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .. import i18n
from ..core.models import Device

# ---------------------------------------------------------------------------
# PDF primitives
# ---------------------------------------------------------------------------

#: A4 in PostScript points.
PAGE_WIDTH = 595
PAGE_HEIGHT = 842
MARGIN_X = 42
MARGIN_TOP = 56

#: Escape sequences must be removed from any literal we emit.
_ESCAPES = {"\\": r"\\", "(": r"\(", ")": r"\)", "\r": " "}


def _grayscale(colour: tuple[float, ...]) -> float:
    """
    Collapse an RGB triple to the single gray value PDF text needs.

    Text operators use ``g`` (gray), not ``rg`` (RGB); using the standard
    luminance weights keeps dark text dark and muted text muted.
    """
    if not colour:
        return 0.0
    # A bare float is already a gray level (1.0 == white on the cover band).
    if len(colour) == 1:
        return max(0.0, min(1.0, colour[0]))
    r, g, b = (max(0.0, min(1.0, c)) for c in colour[:3])
    return 0.299 * r + 0.587 * g + 0.114 * b


def _escape(text: str) -> str:
    """Escape a string for a PDF literal, dropping non WinAnsi characters."""
    out = []
    for char in str(text):
        if char in _ESCAPES:
            out.append(_ESCAPES[char])
        elif ord(char) < 256:
            out.append(char)
        elif char == "\t":
            out.append("    ")
    return "".join(out)


#: Font keys exposed to the layout code.
HELVETICA = "F1"
HELVETICA_BOLD = "F2"
COURIER = "F3"
COURIER_BOLD = "F4"


@dataclass
class _Page:
    """A single content stream plus the drawing state it accumulated."""

    ops: list[str] = field(default_factory=list)
    font: str = HELVETICA
    size: float = 10.0
    x: float = MARGIN_X
    y: float = PAGE_HEIGHT - MARGIN_TOP


class PdfWriter:
    """
    Minimal PDF writer: text, filled rectangles and horizontal rules.

    Only the operators needed for a tabular report are implemented, and
    byte offsets for the cross-reference table are tracked as objects are
    emitted, which is the part hand-rolled writers usually get wrong.
    """

    def __init__(self) -> None:
        self._pages: list[_Page] = []
        self._current: _Page | None = None

    # -- pages -----------------------------------------------------------
    def new_page(self) -> _Page:
        page = _Page()
        self._pages.append(page)
        self._current = page
        return page

    @property
    def page_count(self) -> int:
        return len(self._pages)

    def remaining(self, used: float) -> float:
        """Vertical space left on the current page."""
        if self._current is None:
            return 0.0
        return MARGIN_TOP - used

    # -- drawing ---------------------------------------------------------
    def text(self, x: float, y: float, value: str, font: str = HELVETICA,
             size: float = 10.0, *colour: float) -> None:
        """Draw one line of text. ``colour`` is an optional RGB triple."""
        if self._current is None:
            self.new_page()
        assert self._current is not None
        gray = _grayscale(colour)
        self._current.ops.append(
            f"BT /{font} {size:g} Tf {gray:g} g "
            f"1 0 0 1 {x:.2f} {y:.2f} Tm ({_escape(value)}) Tj ET"
        )

    def rect(self, x: float, y: float, width: float, height: float,
             r: float = 0.0, g: float = 0.0, b: float = 0.0) -> None:
        """Fill a rectangle (used for header bands and zebra rows)."""
        if self._current is None:
            self.new_page()
        assert self._current is not None
        self._current.ops.append(
            f"{r:g} {g:g} {b:g} rg {x:.2f} {y:.2f} {width:.2f} {height:.2f} re f"
        )

    def rule(self, x: float, y: float, width: float,
             *colour: float, thickness: float = 0.6) -> None:
        """Draw a horizontal rule; ``colour`` may be an RGB triple."""
        if self._current is None:
            self.new_page()
        assert self._current is not None
        gray = _grayscale(colour) if colour else 0.75
        self._current.ops.append(
            f"{gray:g} G {thickness:g} w {x:.2f} {y:.2f} m "
            f"{x + width:.2f} {y:.2f} l S"
        )

    # -- serialisation ---------------------------------------------------
    def render(self) -> bytes:
        """Serialise the document into a valid PDF byte string."""
        if not self._pages:
            self.new_page()

        objects: list[bytes] = []

        def add(payload: bytes) -> int:
            objects.append(payload)
            return len(objects)          # 1-based object number

        font_ids = {
            HELVETICA: add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"),
            HELVETICA_BOLD: add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"),
            COURIER: add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>"),
            COURIER_BOLD: add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold /Encoding /WinAnsiEncoding >>"),
        }
        fonts = " ".join(f"/{key} {value} 0 R" for key, value in font_ids.items())

        catalog_id = add(b"")            # placeholder, patched below
        pages_id = add(b"")

        page_ids: list[int] = []
        for page in self._pages:
            stream = ("\n".join(page.ops)).encode("latin-1", "replace")
            content_id = add(
                b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n"
                + stream + b"\nendstream"
            )
            page_ids.append(add(
                b"<< /Type /Page /Parent " + str(pages_id).encode()
                + b" 0 R /MediaBox [0 0 " + str(PAGE_WIDTH).encode()
                + b" " + str(PAGE_HEIGHT).encode()
                + b"] /Resources << /Font << " + fonts.encode()
                + b" >> >> /Contents " + str(content_id).encode() + b" 0 R >>"
            ))

        kids = b" ".join(f"{pid} 0 R".encode() for pid in page_ids)
        objects[pages_id - 1] = (
            b"<< /Type /Pages /Kids [" + kids + b"] /Count "
            + str(len(page_ids)).encode() + b" >>"
        )
        objects[catalog_id - 1] = (
            b"<< /Type /Catalog /Pages " + str(pages_id).encode() + b" 0 R >>"
        )

        # Cross-reference table with byte offsets measured on the real output.
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for number, payload in enumerate(objects, start=1):
            offsets.append(len(out))
            out += f"{number} 0 obj\n".encode() + payload + b"\nendobj\n"

        xref_at = len(out)
        count = len(objects) + 1
        out += f"xref\n0 {count}\n".encode()
        out += b"0000000000 65535 f \n"
        for offset in offsets[1:]:
            out += f"{offset:010d} 00000 n \n".encode()
        out += (
            b"trailer\n<< /Size " + str(count).encode()
            + b" /Root " + str(catalog_id).encode() + b" 0 R >>\n"
            + b"startxref\n" + str(xref_at).encode() + b"\n%%EOF\n"
        )
        return bytes(out)

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.render())
        return target
# ---------------------------------------------------------------------------
# Report layout
# ---------------------------------------------------------------------------

#: Brand colour reused from the application theme.
BRAND = (0.00, 0.48, 0.80)
BRAND_DARK = (0.12, 0.42, 0.58)
ZEBRA = (0.97, 0.98, 0.98)
RULE = (0.80, 0.83, 0.86)
INK = (0.20, 0.20, 0.20)
INK_SOFT = (0.42, 0.45, 0.48)

#: Table geometry: (header, width, alignment, monospace).
_DEVICE_COLUMNS = (
    ("IP", 88, "l", True),
    ("Estado", 52, "c", False),
    ("Nombre", 104, "l", False),
    ("MAC", 104, "l", True),
    ("Fabricante", 104, "l", False),
    ("Tipo", 84, "l", False),
    ("Puertos", 44, "r", True),
)


def _fit(value: str, width: int, mono: bool) -> str:
    """Truncate to the column width, in approximate glyph units."""
    # Courier is fixed at 0.6 em, Helvetica averages near 0.5 em.
    capacity = int(width / (6.6 if mono else 5.4))
    text = str(value or "")
    return text if len(text) <= capacity else text[: max(0, capacity - 1)] + "\u2026"


def _hex_to_rgb(value: str) -> tuple[float, float, float]:
    """Convert '#RRGGBB' into the 0-1 float triple PDF expects."""
    value = value.lstrip("#")
    return tuple(int(value[i: i + 2], 16) / 255 for i in (0, 2, 4))  # type: ignore[return-value]


def build_pdf(
    devices: list[Device],
    path: str | Path,
    *,
    target_range: str = "",
    inventory_changes: list | None = None,
    vpn_summary: str = "",
) -> Path:
    """
    Render a corporate network inventory report to PDF.

    Layout: cover band, KPI strip, device table with zebra rows and
    repeated headers on every page, then an optional inventory
    (unauthorised device) section.
    """
    from ..interface.theme import current

    pal = current()
    brand = _hex_to_rgb(pal.primary)
    ink = _hex_to_rgb(pal.text_primary)
    soft = _hex_to_rgb(pal.text_secondary)
    zebra = _hex_to_rgb(pal.row_odd)

    now = datetime.now()
    writer = PdfWriter()
    writer.new_page()
    y = PAGE_HEIGHT - MARGIN_TOP

    # -- cover band ------------------------------------------------------
    writer.rect(0, PAGE_HEIGHT - 92, PAGE_WIDTH, 92, *brand)
    writer.text(MARGIN_X, PAGE_HEIGHT - 44, "IP Inspector", HELVETICA_BOLD, 22, 1.0)
    writer.text(MARGIN_X, PAGE_HEIGHT - 64,
                i18n.t("report.subtitle"), HELVETICA, 10, 1.0)
    writer.text(MARGIN_X, PAGE_HEIGHT - 80,
                now.strftime("%Y-%m-%d %H:%M"), HELVETICA, 9, 1.0)

    # -- metadata -------------------------------------------------------
    y = PAGE_HEIGHT - 120
    if target_range:
        writer.text(MARGIN_X, y, f"{i18n.t('report.range')}: {target_range}",
                    COURIER, 9, *soft)
        y -= 14
    if vpn_summary:
        writer.text(MARGIN_X, y, f"{i18n.t('report.vpn')}: {vpn_summary}",
                    HELVETICA, 9, *soft)
        y -= 14

    # -- KPI strip ------------------------------------------------------
    y -= 12
    with_ports = sum(1 for d in devices if d.open_ports)
    vpn_devices = sum(1 for d in devices if d.is_vpn_active)
    new_devices = sum(1 for d in devices if d.is_new_device)
    tiles = (
        (len(devices), i18n.t("kpi.devices")),
        (with_ports, i18n.t("kpi.ports")),
        (vpn_devices, i18n.t("kpi.vpn")),
        (new_devices, i18n.t("kpi.risk")),
    )
    tile_width = (PAGE_WIDTH - MARGIN_X * 2) / len(tiles)
    for index, (value, caption) in enumerate(tiles):
        tx = MARGIN_X + index * tile_width
        writer.rect(tx, y - 30, tile_width - 6, 34, *zebra)
        writer.text(tx + 8, y - 12, str(value), HELVETICA_BOLD, 15, *ink)
        writer.text(tx + 8, y - 24, caption.upper(), HELVETICA, 7, *soft)

    # -- device table ---------------------------------------------------
    y -= 52
    writer.text(MARGIN_X, y, i18n.t("report.inventory"), HELVETICA_BOLD, 12, *ink)
    y -= 8
    y = _draw_table(writer, devices, y, brand, zebra, ink, soft)

    # -- inventory drift -------------------------------------------------
    changes = inventory_changes or []
    if changes:
        y -= 18
        if y < MARGIN_TOP + 140:
            writer.new_page()
            y = PAGE_HEIGHT - MARGIN_TOP
        writer.text(MARGIN_X, y, i18n.t("report.changes"), HELVETICA_BOLD, 12, *ink)
        y -= 16
        y = _draw_changes(writer, changes, y, brand, zebra, ink, soft)

    # -- footer on every page --------------------------------------------
    for page in writer._pages:
        writer._current = page
        writer.rule(MARGIN_X, MARGIN_TOP - 18, PAGE_WIDTH - MARGIN_X * 2, *RULE)
        writer.text(MARGIN_X, MARGIN_TOP - 30,
                    f"IP Inspector - {now:%Y-%m-%d %H:%M}", HELVETICA, 7, *soft)

    return writer.save(path)


def _table_x(column: int, total: int) -> float:
    width = PAGE_WIDTH - MARGIN_X * 2
    used = sum(c[1] for c in _DEVICE_COLUMNS[:column])
    return MARGIN_X + used * width / total


def _draw_table(writer, devices, y, brand, zebra, ink, soft) -> float:
    """Draw the device table, repeating the header after each page break."""
    total = sum(c[1] for c in _DEVICE_COLUMNS)
    width = PAGE_WIDTH - MARGIN_X * 2
    row_height = 15

    def header(at: float) -> float:
        writer.rect(MARGIN_X, at - 12, width, row_height, *brand)
        for index, (title, col_width, align, mono) in enumerate(_DEVICE_COLUMNS):
            font = COURIER_BOLD if mono else HELVETICA_BOLD
            x = _table_x(index, total)
            if align == "r":
                writer.text(x + col_width * width / total - 5, at - 6,
                            title.upper(), font, 7, 1.0)
            elif align == "c":
                writer.text(x + col_width * width / total / 2 - 12, at - 6,
                            title.upper(), font, 7, 1.0)
            else:
                writer.text(x + 4, at - 6, title.upper(), font, 7, 1.0)
        return at - row_height

    y = header(y)

    for position, device in enumerate(devices):
        if y < MARGIN_TOP + 24:
            writer.new_page()
            y = header(PAGE_HEIGHT - MARGIN_TOP)
            position = position  # keep zebra tied to the global position

        if position % 2 == 0:
            writer.rect(MARGIN_X, y - 12, width, row_height, *zebra)

        cells = (
            device.ip_address,
            i18n.t("state.online") if device.is_alive else i18n.t("state.offline"),
            device.hostname or "-",
            device.mac_address or "-",
            device.vendor or "-",
            device.device_type,
            ", ".join(str(p.number) for p in device.open_ports if p.is_open) or "-",
        )
        for index, value in enumerate(cells):
            title, col_width, align, mono = _DEVICE_COLUMNS[index]
            font = COURIER if mono else HELVETICA
            glyphs = _fit(value, col_width * width / total, mono)
            x = _table_x(index, total)
            if align == "r":
                writer.text(x + col_width * width / total - 5, y - 6, glyphs, font, 8)
            elif align == "c":
                writer.text(x + col_width * width / total / 2 - 12, y - 6,
                            glyphs, font, 8)
            else:
                writer.text(x + 4, y - 6, glyphs, font, 8)
        y -= row_height

    writer.rule(MARGIN_X, y + 4, width, *RULE)
    return y

#: Inventory drift columns: (header, width, alignment).
_CHANGE_COLUMNS = (
    ("Cambio", 62, "l"),
    ("MAC", 92, "l"),
    ("IP", 78, "l"),
    ("Detalle", 210, "l"),
)

_SEVERITY_RGB = {
    "critical": (0.85, 0.20, 0.20),
    "high": (0.90, 0.32, 0.12),
    "medium": (0.90, 0.49, 0.13),
    "low": (0.45, 0.60, 0.70),
    "info": (0.55, 0.58, 0.60),
}


def _draw_changes(writer, changes, y, brand, zebra, ink, soft) -> float:
    """Draw the unauthorised / drift section."""
    total = sum(c[1] for c in _CHANGE_COLUMNS)
    width = PAGE_WIDTH - MARGIN_X * 2
    row_height = 15

    def header(at: float) -> float:
        writer.rect(MARGIN_X, at - 12, width, row_height, *brand)
        offset = MARGIN_X
        for title, col_width, _align in _CHANGE_COLUMNS:
            writer.text(offset + 4, at - 6, title.upper(), HELVETICA_BOLD, 7, 1.0)
            offset += col_width * width / total
        return at - row_height

    y = header(y)
    for position, change in enumerate(changes):
        if y < MARGIN_TOP + 24:
            writer.new_page()
            y = header(PAGE_HEIGHT - MARGIN_TOP)
        if position % 2 == 0:
            writer.rect(MARGIN_X, y - 12, width, row_height, *zebra)

        rgb = _SEVERITY_RGB.get(change.severity, soft)
        cells = (
            change.kind.upper(),
            change.mac or "-",
            change.ip or "-",
            change.detail,
        )
        offset = MARGIN_X
        for index, value in enumerate(cells):
            title, col_width, _align = _CHANGE_COLUMNS[index]
            font = COURIER if index in (1, 2) else HELVETICA
            colour = rgb if index == 0 else ink
            writer.text(offset + 4, y - 6,
                        _fit(value, col_width * width / total, index in (1, 2)),
                        font, 8, *colour)
            offset += col_width * width / total
        y -= row_height
    return y


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<title>IP Inspector - {title}</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ margin: 0; padding: 28px 32px; background: {bg};
         font-family: "Segoe UI", Arial, sans-serif; color: {fg}; font-size: 13px; }}
  h1 {{ font-size: 22px; margin: 0 0 2px; }}
  .sub {{ color: {muted}; font-size: 12px; margin-bottom: 18px; }}
  .kpis {{ display: flex; gap: 10px; margin-bottom: 22px; }}
  .kpi {{ flex: 1; background: {surface}; border: 1px solid {border};
          border-radius: 6px; padding: 12px 14px; }}
  .kpi b {{ display: block; font-size: 22px; }}
  .kpi span {{ font-size: 10px; letter-spacing: .06em; color: {muted}; }}
  h2 {{ font-size: 15px; margin: 22px 0 8px; }}
  table {{ width: 100%; border-collapse: collapse; background: {surface};
           border: 1px solid {border}; border-radius: 6px; overflow: hidden; }}
  thead th {{ background: {primary}; color: #fff; font-size: 10px;
              letter-spacing: .05em; text-align: left; padding: 8px 10px; }}
  tbody td {{ padding: 6px 10px; border-top: 1px solid {border}; }}
  tbody tr:nth-child(even) {{ background: {zebra}; }}
  td.mono {{ font-family: Consolas, "Courier New", monospace; font-size: 12px; }}
  .online {{ color: {online}; font-weight: 600; }}
  .offline {{ color: {muted}; }}
  .vpn {{ color: {vpn}; font-weight: 600; }}
  .new {{ color: {vpn}; }}
  @media print {{ body {{ padding: 0; }} .kpis, table {{ break-inside: avoid; }} }}
</style>
</head>
<body>
<h1>IP Inspector</h1>
<div class="sub">{subtitle} &middot; {generated}{range}{vpn_line}</div>
<div class="kpis">{kpis}</div>
<h2>{inventory_title}</h2>
<table>
<thead><tr><th>IP</th><th>Status</th><th>Hostname</th><th>MAC</th>
<th>Vendor</th><th>Model</th><th>Type</th><th>VPN</th><th>Ports</th></tr></thead>
<tbody>{device_rows}</tbody>
</table>
{changes_block}
</body>
</html>
"""


def build_html(
    devices: list[Device],
    path: str | Path,
    *,
    target_range: str = "",
    inventory_changes: list | None = None,
    vpn_summary: str = "",
) -> Path:
    """Render the same inventory as a self-contained, print-ready HTML file."""
    from ..interface.theme import current

    pal = current()
    now = datetime.now()

    def esc(value: object) -> str:
        return (
            str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        )

    rows = []
    for device in devices:
        state = "online" if device.is_alive else "offline"
        ports = ", ".join(str(p.number) for p in device.open_ports if p.is_open)
        rows.append(
            "<tr>"
            f'<td class="mono">{esc(device.ip_address)}</td>'
            f'<td class="{state}">{esc(i18n.t("state.online" if device.is_alive else "state.offline"))}</td>'
            f"<td>{esc(device.hostname or '-')}</td>"
            f'<td class="mono">{esc(device.mac_address or "-")}</td>'
            f"<td>{esc(device.vendor or '-')}</td>"
            f"<td>{esc(device.model or '-')}</td>"
            f"<td>{esc(i18n.device_type_label(device.device_type))}</td>"
            f'<td class="vpn">{esc(i18n.t("value.vpn") if device.is_vpn_active else "")}</td>'
            f'<td class="mono">{esc(ports or "-")}</td>'
            "</tr>"
        )

    with_ports = sum(1 for d in devices if d.open_ports)
    vpn_devices = sum(1 for d in devices if d.is_vpn_active)
    new_devices = sum(1 for d in devices if d.is_new_device)
    kpis = "".join(
        f'<div class="kpi"><b>{value}</b><span>{esc(caption)}</span></div>'
        for value, caption in (
            (len(devices), i18n.t("kpi.devices")),
            (with_ports, i18n.t("kpi.ports")),
            (vpn_devices, i18n.t("kpi.vpn")),
            (new_devices, i18n.t("kpi.risk")),
        )
    )

    changes_block = ""
    changes = inventory_changes or []
    if changes:
        change_rows = "".join(
            "<tr>"
            f'<td style="color:{_css_severity(c.severity)};font-weight:600">'
            f"{esc(c.kind.upper())}</td>"
            f'<td class="mono">{esc(c.mac or "-")}</td>'
            f'<td class="mono">{esc(c.ip or "-")}</td>'
            f"<td>{esc(c.detail)}</td>"
            f"<td>{esc(c.vendor or '-')}</td>"
            "</tr>"
            for c in changes
        )
        changes_block = (
            f"<h2>{esc(i18n.t('report.changes'))}</h2><table><thead><tr>"
            f"<th>{esc(i18n.t('inv.new'))}</th><th>{esc(i18n.t('inv.mac'))}</th>"
            f"<th>{esc(i18n.t('col.ip'))}</th><th>{esc(i18n.t('inv.detail'))}</th>"
            f"<th>{esc(i18n.t('inv.vendorcol'))}</th></tr></thead>"
            f"<tbody>{change_rows}</tbody></table>"
        )

    document = _HTML_TEMPLATE.format(
        lang=i18n.get_language(),
        title=esc(i18n.t("report.inventory")),
        subtitle=esc(i18n.t("report.subtitle")),
        generated=now.strftime("%Y-%m-%d %H:%M"),
        range=f" &middot; {esc(i18n.t('report.range'))}: "
              f"<span class=\"mono\">{esc(target_range)}</span>" if target_range else "",
        vpn_line=f" &middot; {esc(i18n.t('report.vpn'))}: {esc(vpn_summary)}"
                 if vpn_summary else "",
        kpis=kpis,
        inventory_title=esc(i18n.t("report.inventory")),
        device_rows="".join(rows) or "<tr><td colspan=9>-</td></tr>",
        changes_block=changes_block,
        bg=pal.background, surface=pal.surface, fg=pal.text_primary,
        muted=pal.text_secondary, border=pal.border, primary=pal.header_bg,
        zebra=pal.row_odd, online=pal.online, vpn=pal.vpn,
    )

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(document, encoding="utf-8")
    return target


def _css_severity(severity: str) -> str:
    return {"critical": "#d93025", "high": "#e8590c", "medium": "#e67700",
            "low": "#4c6ef5", "info": "#868e96"}.get(severity, "#868e96")


def build_report(
    devices: list[Device],
    path: str | Path,
    fmt: str = "pdf",
    **kwargs,
) -> Path:
    """Dispatch to the PDF or HTML writer based on ``fmt``."""
    builder = build_pdf if fmt.lower() == "pdf" else build_html
    return builder(devices, path, **kwargs)