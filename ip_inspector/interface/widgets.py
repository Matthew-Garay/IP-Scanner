"""Reusable widgets of the main window: the results table and the detail panel.

Nothing here knows about scanning; both widgets only render
:class:`~ip_inspector.core.models.Device` records handed to them.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

from .. import i18n
from ..core.models import KNOWN_SERVICES, Device
from . import theme

#: Columns of the results tree-view: (heading, width, anchor)
TREE_COLUMNS: tuple[tuple[str, int, str], ...] = (
    ("Name", 180, "w"),
    ("IP", 115, "w"),
    ("Vendor", 180, "w"),
    ("MAC", 135, "w"),
    ("Type", 110, "w"),
    ("OS", 90, "w"),
    ("Risk", 50, "center"),
    ("Open ports", 200, "w"),
)
COL_IP = 1
COL_RISK = 6
COL_PORTS = 7

MONO_FONT = ("Consolas", 10)


def c(name: str) -> tuple[str, str]:
    """(light, dark) colour pair, so CustomTkinter follows the mode by itself."""
    return getattr(theme.LIGHT, name), getattr(theme.DARK, name)


def ip_key(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (999,)


def open_ports(device: Device) -> list:
    """Open ports only: ``Device.open_ports`` also holds closed/filtered ones."""
    return sorted((p for p in device.open_ports if p.is_open), key=lambda p: p.number)


def risk_label(score: int) -> str:
    if score >= 70:
        return "High"
    if score >= 40:
        return "Med"
    if score > 0:
        return "Low"
    return "-"


def device_key(device: Device) -> str:
    """Stable identity of a device across scans: its MAC, else its IP."""
    return device.mac_address or device.ip_address


def device_row(device: Device, alias: str = "") -> tuple[str, ...]:
    """Cell values of a device row, in :data:`TREE_COLUMNS` order."""
    return (
        alias or device.hostname or "-",
        device.ip_address,
        device.vendor or device.model or "-",
        device.mac_address or "-",
        i18n.device_type_label(device.device_type) if device.device_type else "-",
        device.os_name or "-",
        risk_label(device.risk_score),
        device.ports_compact(),
    )


def matches_filter(device: Device, text: str, alias: str = "") -> bool:
    """True when the quick filter text appears in any visible field."""
    if not text:
        return True
    text = text.lower()
    haystack = " ".join((alias,
        device.ip_address, device.hostname or "", device.mac_address or "",
        device.vendor or "", device.model or "", device.device_type or "",
        device.os_name or "", device.ports_compact(),
    )).lower()
    return text in haystack


def style_treeview(style: ttk.Style, name: str, pal) -> None:
    """Apply the palette to a ttk.Treeview style (ttk ignores CustomTkinter)."""
    style.configure(
        f"{name}.Treeview", background=pal.surface, foreground=pal.text_primary,
        fieldbackground=pal.surface, rowheight=26, font=("Segoe UI", 10),
        borderwidth=0, relief="flat",
    )
    style.configure(
        f"{name}.Treeview.Heading", background=pal.header_bg,
        foreground=pal.header_text, font=("Segoe UI", 9, "bold"),
        relief="flat", borderwidth=0,
    )
    style.map(f"{name}.Treeview",
              background=[("selected", pal.selection)],
              foreground=[("selected", pal.selection_text)])
    style.map(f"{name}.Treeview.Heading", background=[("active", pal.hover)])


# --------------------------------------------------------------------------- #
# Device tree
# --------------------------------------------------------------------------- #
class DeviceTree(ctk.CTkFrame):
    """Tree-view table: one row per device, expandable to show open services.

    Rows are updated in place (``upsert_device``), so selection and expanded
    rows survive the stream of updates a scan produces.
    """

    def __init__(self, master, on_select=None, on_open_device=None, on_context=None):
        super().__init__(master, fg_color="transparent")
        self._on_select = on_select
        self._on_open_device = on_open_device
        self._on_context = on_context
        self._devices: dict[str, Device] = {}
        self._favorites: set[str] = set()
        self._new: set[str] = set()
        #: ip -> custom name typed by the user.
        self._aliases: dict[str, str] = {}
        self._filter = ""
        self._only_open = False
        self._sort_col = COL_IP
        self._sort_reverse = False
        self._build()
        self.apply_palette(theme.current())

    # -- construction ------------------------------------------------------- #
    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._style = ttk.Style(self)
        try:
            self._style.theme_use("clam")
        except tk.TclError:
            pass

        cols = [f"c{i}" for i in range(len(TREE_COLUMNS))]
        self._tree = ttk.Treeview(self, columns=cols, show="tree headings",
                                  style="AIS.Treeview", selectmode="browse")
        self._tree.heading("#0", text="", anchor="w")
        self._tree.column("#0", width=58, minwidth=58, stretch=False, anchor="w")
        for i, (label, width, anchor) in enumerate(TREE_COLUMNS):
            self._tree.heading(cols[i], text=label, anchor="w",
                               command=lambda k=i: self.sort_by(k))
            self._tree.column(cols[i], width=width, minwidth=40, anchor=anchor,
                              stretch=i not in (COL_RISK,))

        vsb = ttk.Scrollbar(self, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        self._tree.bind("<<TreeviewSelect>>", self._on_select_event)
        self._tree.bind("<Double-1>", self._on_double_click)
        self._tree.bind("<Button-3>", self._on_right_click)

    def apply_palette(self, pal) -> None:
        style_treeview(self._style, "AIS", pal)
        self._tree.tag_configure("dev", foreground=pal.text_primary)
        self._tree.tag_configure("fav", foreground=pal.primary)
        self._tree.tag_configure("new", foreground=pal.accent)
        self._tree.tag_configure("risk", foreground=pal.state_warn)
        self._tree.tag_configure("svc", foreground=pal.text_secondary)

    # -- public API ---------------------------------------------------------- #
    def clear(self) -> None:
        self._tree.delete(*self._tree.get_children())
        self._devices.clear()
        self._new.clear()

    def row_count(self) -> int:
        return len(self._tree.get_children())

    def visible_ips(self) -> list[str]:
        return [iid.removeprefix("dev:") for iid in self._tree.get_children()]

    def row_values(self, ip: str) -> tuple[str, ...]:
        return tuple(self._tree.item(self._iid(ip), "values"))

    def set_filter(self, text: str, only_open: bool | None = None) -> None:
        self._filter = text.strip().lower()
        if only_open is not None:
            self._only_open = only_open
        self._rebuild()

    def set_marks(self, favorites: set[str], new: set[str] | None = None,
                  aliases: dict[str, str] | None = None) -> None:
        self._favorites = set(favorites)
        if new is not None:
            self._new = set(new)
        if aliases is not None:
            self._aliases = dict(aliases)
        for ip, device in self._devices.items():
            if self._tree.exists(self._iid(ip)):
                self.upsert_device(device)

    def set_alias(self, ip: str, name: str) -> None:
        """Remember a custom name for one row (applied on its next update)."""
        if name:
            self._aliases[ip] = name
        else:
            self._aliases.pop(ip, None)

    def upsert_device(self, device: Device) -> None:
        """Add or update a single device row without touching the others."""
        ip = device.ip_address
        self._devices[ip] = device
        iid = self._iid(ip)
        exists = self._tree.exists(iid)
        if not self._visible(device):
            if exists:
                self._tree.delete(iid)
            return
        if ip in self._favorites:
            tags, text = ("fav",), "★"
        elif ip in self._new:
            tags, text = ("new",), "● NEW"
        elif device.risk_score >= 40:
            tags, text = ("risk",), "●"
        else:
            tags, text = ("dev",), "●"
        values = device_row(device, self._aliases.get(ip, ""))
        if exists:
            self._tree.item(iid, text=text, values=values, tags=tags)
        else:
            self._tree.insert("", self._insert_index(device), iid=iid, text=text,
                              values=values, tags=tags)
        self._fill_services(device)

    def select(self, ip: str) -> None:
        iid = self._iid(ip)
        if self._tree.exists(iid):
            self._tree.selection_set(iid)
            self._tree.see(iid)

    def get_selected_ip(self) -> str | None:
        sel = self._tree.selection()
        if not sel:
            return None
        iid = sel[0]
        parent = self._tree.parent(iid)          # a service child -> its device
        return (parent or iid).removeprefix("dev:")

    def expand_all(self, expanded: bool = True) -> None:
        for iid in self._tree.get_children():
            self._tree.item(iid, open=expanded)

    # -- internals ----------------------------------------------------------- #
    @staticmethod
    def _iid(ip: str) -> str:
        return f"dev:{ip}"

    def _visible(self, device: Device) -> bool:
        if self._only_open and not open_ports(device):
            return False
        return matches_filter(device, self._filter, self._aliases.get(device.ip_address, ""))

    def _sort_key(self, device: Device):
        if self._sort_col == COL_IP:
            return (ip_key(device.ip_address),)
        if self._sort_col == COL_PORTS:
            return (len(open_ports(device)), ip_key(device.ip_address))
        if self._sort_col == COL_RISK:
            return (device.risk_score, ip_key(device.ip_address))
        value = device_row(device, self._aliases.get(device.ip_address, ""))[self._sort_col]
        return (value == "-", value.lower(), ip_key(device.ip_address))

    def _insert_index(self, device: Device) -> int | str:
        """Position that keeps the current sort order (no full repaint)."""
        key = self._sort_key(device)
        for index, iid in enumerate(self._tree.get_children()):
            other = self._devices.get(iid.removeprefix("dev:"))
            if other is None:
                continue
            other_key = self._sort_key(other)
            if (other_key < key) if self._sort_reverse else (other_key > key):
                return index
        return "end"

    def _fill_services(self, device: Device) -> None:
        """Children rows: one per open service, shown when the row is expanded."""
        iid = self._iid(device.ip_address)
        children = self._tree.get_children(iid)
        ports = open_ports(device)
        if len(children) == len(ports):
            return
        self._tree.delete(*children)
        for port in ports:
            name = port.service or KNOWN_SERVICES.get(port.number, "unknown")
            detail = port.version or port.banner or ""
            values = (f"{port.number}/tcp  {name}", "", detail[:80], "", "", "", "", "")
            self._tree.insert(iid, "end", text="", values=values, tags=("svc",))

    def _rebuild(self) -> None:
        selected = self.get_selected_ip()
        opened = {iid for iid in self._tree.get_children() if self._tree.item(iid, "open")}
        self._tree.delete(*self._tree.get_children())
        ordered = sorted(self._devices.values(), key=self._sort_key,
                         reverse=self._sort_reverse)
        for device in ordered:
            self.upsert_device(device)
            iid = self._iid(device.ip_address)
            if iid in opened and self._tree.exists(iid):
                self._tree.item(iid, open=True)
        if selected:
            self.select(selected)

    def sort_by(self, idx: int) -> None:
        if self._sort_col == idx:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col, self._sort_reverse = idx, False
        for i, (label, *_rest) in enumerate(TREE_COLUMNS):
            arrow = (" ▼" if self._sort_reverse else " ▲") if i == idx else ""
            self._tree.heading(f"c{i}", text=label + arrow)
        self._rebuild()

    def _on_select_event(self, _event) -> None:
        ip = self.get_selected_ip()
        if ip and self._on_select:
            self._on_select(ip)

    def _on_double_click(self, event) -> None:
        if self._tree.identify_region(event.x, event.y) == "heading":
            return
        ip = self.get_selected_ip()
        if ip and self._on_open_device:
            self._on_open_device(ip)

    def _on_right_click(self, event) -> None:
        iid = self._tree.identify_row(event.y)
        if not iid:
            return
        self._tree.selection_set(iid)
        ip = self.get_selected_ip()
        if ip and self._on_context:
            self._on_context(ip, event.x_root, event.y_root)


# --------------------------------------------------------------------------- #
# Collapsible detail panel
# --------------------------------------------------------------------------- #
class DetailPanel(ctk.CTkFrame):
    """Right-hand panel showing full details for the selected device."""

    def __init__(self, master, width: int = 340):
        super().__init__(master, fg_color="transparent", width=width)
        self._expanded = True
        self._device: Device | None = None
        self._label_info: dict = {}
        self._row_widgets: list = []
        self._build(width)
        self._render()

    @property
    def device(self) -> Device | None:
        return self._device

    @property
    def expanded(self) -> bool:
        return self._expanded

    def _build(self, width: int) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color=c("surface_alt"), corner_radius=0)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 1))
        header.grid_columnconfigure(1, weight=1)

        self._toggle_btn = ctk.CTkButton(
            header, text="▶", width=26, height=26, fg_color="transparent",
            hover_color=c("hover"), text_color=c("text_secondary"),
            font=("Segoe UI", 12, "bold"), command=self.toggle,
        )
        self._toggle_btn.grid(row=0, column=0, padx=6, pady=6)
        self._title = ctk.CTkLabel(header, text="Device details",
                                   font=("Segoe UI", 11, "bold"),
                                   text_color=c("text_primary"))
        self._title.grid(row=0, column=1, padx=8, sticky="w")

        self._scroll = ctk.CTkScrollableFrame(self, fg_color=c("surface"), width=width - 20)
        self._scroll.grid(row=1, column=0, sticky="nsew")
        self._scroll.grid_columnconfigure(0, weight=1)

        self._fields = ctk.CTkFrame(self._scroll, fg_color="transparent")
        self._fields.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        self._fields.grid_columnconfigure(1, weight=1)

    def toggle(self) -> None:
        self._expanded = not self._expanded
        self._toggle_btn.configure(text="▶" if self._expanded else "◀")
        if self._expanded:
            self._scroll.grid()
            self._title.grid()
        else:
            self._scroll.grid_remove()
            self._title.grid_remove()

    def set_device(self, device: Device | None, label: dict | None = None) -> None:
        """Show a device; ``label`` carries the user's custom name and note."""
        self._device = device
        self._label_info = label or {}
        self._render()

    def _label(self, text, row, col=0, bold=False, color="text_primary", **grid):
        widget = ctk.CTkLabel(
            self._fields, text=text, anchor="w", justify="left", wraplength=200,
            height=18, font=("Segoe UI", 10, "bold" if bold else "normal"),
            text_color=c(color),
        )
        widget.grid(row=row, column=col, sticky="nw", **grid)
        self._row_widgets.append(widget)
        return widget

    def _section(self, title: str, row: int) -> None:
        sep = ctk.CTkFrame(self._fields, height=1, fg_color=c("grid_line"))
        sep.grid(row=row, column=0, columnspan=2, sticky="new", pady=(10, 0))
        self._row_widgets.append(sep)
        self._label(title, row, bold=True, color="primary", columnspan=2, pady=(16, 4))

    def _render(self) -> None:
        for widget in self._row_widgets:
            widget.destroy()
        self._row_widgets.clear()

        dev = self._device
        if dev is None:
            self._label("Select a device to see its details.", 0,
                        color="text_muted", columnspan=2, pady=8)
            return

        fields = []
        if self._label_info.get("name"):
            fields.append(("Custom name", self._label_info["name"]))
        if self._label_info.get("note"):
            fields.append(("Note", self._label_info["note"]))
        fields += [
            ("IP", dev.ip_address),
            ("Hostname", dev.hostname or "—"),
            ("Vendor", dev.vendor or "—"),
            ("Model", dev.model or "—"),
            ("MAC", dev.mac_address or "—"),
            ("Type", i18n.device_type_label(dev.device_type)),
            ("OS guess", dev.os_name or "—"),
            ("TTL", dev.ttl_label),
            ("Latency (ms)", dev.latency_label),
            ("Found via", dev.discovery_method or "—"),
            ("VPN subnet", "yes" if dev.is_vpn_active else "no"),
            ("Risk score", f"{dev.risk_score}/100  ({risk_label(dev.risk_score)})"),
        ]
        row = 0
        for name, value in fields:
            self._label(name + ":", row, bold=True, color="text_secondary",
                        padx=(0, 8), pady=2)
            self._label(value, row, col=1, pady=2)
            row += 1

        ports = open_ports(dev)
        self._section(f"Open services ({len(ports)})", row)
        row += 1
        if not ports:
            self._label("None found", row, color="text_muted", columnspan=2)
            row += 1
        for port in ports:
            name = port.service or KNOWN_SERVICES.get(port.number, "unknown")
            self._label(f"{port.number}/tcp", row, color="text_secondary", padx=(8, 8))
            self._label(f"{name}  {port.version or port.banner[:60]}".strip(), row, col=1)
            row += 1

        if dev.findings:
            self._section(f"Security findings ({len(dev.findings)})", row)
            row += 1
            for finding in dev.findings:
                color = {"critical": "state_off", "high": "state_off",
                         "medium": "state_warn"}.get(finding.severity, "text_secondary")
                title = (i18n.t(finding.title_key, **finding.params)
                         if finding.title_key else finding.title)
                detail = (i18n.t(finding.detail_key, **finding.params)
                          if finding.detail_key else finding.detail)
                self._label(finding.severity.upper(), row, color=color, bold=True,
                            padx=(8, 8), pady=(2, 0))
                self._label(f"{title}\n{detail}", row, col=1, pady=(2, 6))
                row += 1
