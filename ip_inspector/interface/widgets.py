"""Reusable widgets of the main window, built on native ttk controls.

* :class:`DeviceTree`    - the results grid: one row per device, expandable
                           to its open services and shared folders.
* :class:`PropertyPanel` - a two-column property grid for the selected device.
* :class:`CheckBox`, :class:`Notebook` - thin ttk wrappers with the small API
  the window uses (``get``/``select`` and ``set(tab_name)``).

Nothing here knows about scanning; the widgets only render
:class:`~ip_inspector.core.models.Device` records handed to them.
"""

from __future__ import annotations

import textwrap
import tkinter as tk
from tkinter import ttk
from typing import Callable

from .. import i18n
from ..core.models import KNOWN_SERVICES, Device
from . import theme

#: Columns of the results grid: (heading, width, anchor)
TREE_COLUMNS: tuple[tuple[str, int, str], ...] = (
    ("Name", 170, "w"),
    ("IP", 110, "w"),
    ("Manufacturer", 190, "w"),
    ("MAC address", 125, "w"),
    ("Type", 105, "w"),
    ("OS", 85, "w"),
    ("Risk", 64, "w"),
    ("Open ports", 190, "w"),
)
COL_NAME = 0
COL_IP = 1
COL_RISK = 6
COL_PORTS = 7

MONO_FONT = theme.MONO_FONT


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #
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
        return "Medium"
    if score > 0:
        return "Low"
    return ""


def device_key(device: Device) -> str:
    """Stable identity of a device across scans: its MAC, else its IP."""
    return device.mac_address or device.ip_address


def device_row(device: Device, alias: str = "") -> tuple[str, ...]:
    """Cell values of a device row, in :data:`TREE_COLUMNS` order."""
    ports = device.ports_compact()
    return (
        alias or device.hostname or device.ip_address,
        device.ip_address,
        device.vendor or device.model or "",
        device.mac_address or "",
        i18n.device_type_label(device.device_type) if device.device_type else "",
        device.os_name or "",
        risk_label(device.risk_score),
        "" if ports == "-" else ports,
    )


def matches_filter(device: Device, text: str, alias: str = "") -> bool:
    """True when the quick filter text appears in any visible field."""
    if not text:
        return True
    text = text.lower()
    haystack = " ".join((
        alias, device.ip_address, device.hostname or "", device.mac_address or "",
        device.vendor or "", device.model or "", device.device_type or "",
        device.os_name or "", device.ports_compact(),
    )).lower()
    return text in haystack


# --------------------------------------------------------------------------- #
# Small ttk wrappers
# --------------------------------------------------------------------------- #
class CheckBox(ttk.Checkbutton):
    """ttk.Checkbutton with ``get()``/``select()``/``deselect()``."""

    def __init__(self, master, text: str = "", command=None, value: bool = False):
        self._var = tk.BooleanVar(master, value=value)
        super().__init__(master, text=text, variable=self._var, command=command)

    def get(self) -> bool:
        return bool(self._var.get())

    def select(self) -> None:
        self._var.set(True)

    def deselect(self) -> None:
        self._var.set(False)


class Notebook(ttk.Notebook):
    """ttk.Notebook addressed by tab title: ``add_tab(name)`` and ``set(name)``."""

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self._tabs: dict[str, ttk.Frame] = {}

    def add_tab(self, name: str) -> ttk.Frame:
        frame = ttk.Frame(self, padding=(4, 4))
        self.add(frame, text=f"  {name}  ")
        self._tabs[name] = frame
        return frame

    def set(self, name: str) -> None:
        self.select(self._tabs[name])

    def get(self) -> str:
        current = self.select()
        for name, frame in self._tabs.items():
            if str(frame) == current:
                return name
        return ""


def scrolled(parent, widget_factory: Callable, horizontal: bool = False):
    """Place a widget with scroll bars in a frame; returns (frame, widget)."""
    frame = ttk.Frame(parent)
    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(0, weight=1)
    widget = widget_factory(frame)
    widget.grid(row=0, column=0, sticky="nsew")
    vsb = ttk.Scrollbar(frame, orient="vertical", command=widget.yview)
    vsb.grid(row=0, column=1, sticky="ns")
    widget.configure(yscrollcommand=vsb.set)
    if horizontal:
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=widget.xview)
        hsb.grid(row=1, column=0, sticky="ew")
        widget.configure(xscrollcommand=hsb.set)
    return frame, widget


# --------------------------------------------------------------------------- #
# Results grid
# --------------------------------------------------------------------------- #
class DeviceTree(ttk.Frame):
    """Results grid: one row per device, expandable to services and shares.

    Rows are updated in place (``upsert_device``), so selection and expanded
    rows survive the stream of updates a scan produces.
    """

    def __init__(self, master, icons: theme.Icons, on_select=None, on_open_device=None,
                 on_context=None, on_expand=None, on_open_share=None):
        super().__init__(master)
        self._icons = icons
        self._on_select = on_select
        self._on_open_device = on_open_device
        self._on_context = on_context
        self._on_expand = on_expand
        self._on_open_share = on_open_share
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

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        cols = [f"c{i}" for i in range(len(TREE_COLUMNS))]
        self._tree = ttk.Treeview(self, columns=cols, show="tree headings",
                                  style="Results.Treeview", selectmode="extended")
        self._tree.heading("#0", text="", anchor="w")
        self._tree.column("#0", width=theme.px(46), minwidth=theme.px(40), stretch=False)
        for i, (label, width, anchor) in enumerate(TREE_COLUMNS):
            self._tree.heading(cols[i], text=label, anchor="w",
                               command=lambda k=i: self.sort_by(k))
            self._tree.column(cols[i], width=theme.px(width), minwidth=theme.px(40),
                              anchor=anchor,
                              stretch=i in (COL_NAME, COL_PORTS))
        vsb = ttk.Scrollbar(self, orient="vertical", command=self._tree.yview)
        hsb = ttk.Scrollbar(self, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        pal = theme.PALETTE
        self._tree.tag_configure("odd", background=pal.row_alt)
        self._tree.tag_configure("even", background="#FFFFFF")
        self._tree.tag_configure("child", foreground=pal.text_muted)
        self._tree.tag_configure("share", foreground=pal.link)

        self._tree.bind("<<TreeviewSelect>>", self._on_select_event)
        self._tree.bind("<<TreeviewOpen>>", self._on_open_event)
        self._tree.bind("<Double-1>", self._on_double_click)
        self._tree.bind("<Return>", self._on_double_click)
        self._tree.bind("<Button-3>", self._on_right_click)
        self._tree.bind("<Control-a>", lambda _e: self._tree.selection_set(
            self._tree.get_children()))

    # -- public API ---------------------------------------------------------- #
    def focus_table(self) -> None:
        self._tree.focus_set()

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
                self._restripe()
            return
        icons = self._icons
        if ip in self._favorites:
            image = icons.favorite
        elif ip in self._new:
            image = icons.new
        elif device.risk_score >= 70:
            image = icons.danger
        elif device.risk_score >= 40:
            image = icons.risk
        else:
            image = icons.online
        label = ""
        values = device_row(device, self._aliases.get(ip, ""))
        if exists:
            self._tree.item(iid, text=label, image=image, values=values)
        else:
            self._tree.insert("", self._insert_index(device), iid=iid, text=label,
                              image=image, values=values)
            self._restripe()
        self._fill_services(device)

    def add_shares(self, ip: str, shares: list[tuple[str, str, str]]) -> None:
        """Show a device's shared folders as child rows."""
        iid = self._iid(ip)
        if not self._tree.exists(iid):
            return
        for child in self._tree.get_children(iid):
            if child.startswith("share:"):
                self._tree.delete(child)
        for name, kind, comment in shares:
            values = (f"\\\\{ip}\\{name}", "", f"{kind}  {comment}".strip(), "", "", "", "", "")
            self._tree.insert(iid, "end", iid=f"share:{ip}:{name}", text="",
                              image=self._icons.folder, values=values, tags=("share",))
        self._tree.item(iid, open=True)

    def select(self, ip: str) -> None:
        iid = self._iid(ip)
        if self._tree.exists(iid):
            self._tree.selection_set(iid)
            self._tree.focus(iid)
            self._tree.see(iid)

    def get_selected_ip(self) -> str | None:
        ips = self.get_selected_ips()
        return ips[0] if ips else None

    def get_selected_ips(self) -> list[str]:
        """Selected devices (a selected child row counts as its device)."""
        result: list[str] = []
        for iid in self._tree.selection():
            parent = self._tree.parent(iid)
            ip = (parent or iid).removeprefix("dev:")
            if ip not in result:
                result.append(ip)
        return result

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

    def _restripe(self) -> None:
        for index, iid in enumerate(self._tree.get_children()):
            self._tree.item(iid, tags=("odd" if index % 2 else "even",))

    def _sort_key(self, device: Device):
        if self._sort_col == COL_IP:
            return (ip_key(device.ip_address),)
        if self._sort_col == COL_PORTS:
            return (len(open_ports(device)), ip_key(device.ip_address))
        if self._sort_col == COL_RISK:
            return (device.risk_score, ip_key(device.ip_address))
        value = device_row(device, self._aliases.get(device.ip_address, ""))[self._sort_col]
        return (value == "", value.lower(), ip_key(device.ip_address))

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
        """Child rows: one per open service (shares are added separately)."""
        iid = self._iid(device.ip_address)
        services = [c for c in self._tree.get_children(iid) if c.startswith("svc:")]
        ports = open_ports(device)
        if len(services) == len(ports):
            return
        self._tree.delete(*services)
        for index, port in enumerate(ports):
            name = port.service or KNOWN_SERVICES.get(port.number, "unknown")
            detail = port.version or port.banner or ""
            values = (f"{name} ({port.number}/tcp)", "", detail[:90], "", "", "", "", "")
            self._tree.insert(iid, index, iid=f"svc:{device.ip_address}:{port.number}",
                              text="", image=self._icons.service, values=values,
                              tags=("child",))

    def _rebuild(self) -> None:
        selected = self.get_selected_ips()
        opened = {iid for iid in self._tree.get_children() if self._tree.item(iid, "open")}
        shares = {iid: [self._tree.item(c, "values") for c in self._tree.get_children(iid)
                        if c.startswith("share:")]
                  for iid in self._tree.get_children()}
        self._tree.delete(*self._tree.get_children())
        ordered = sorted(self._devices.values(), key=self._sort_key,
                         reverse=self._sort_reverse)
        for device in ordered:
            self.upsert_device(device)
            iid = self._iid(device.ip_address)
            if not self._tree.exists(iid):
                continue
            for values in shares.get(iid, []):
                name = str(values[0]).rsplit("\\", 1)[-1]
                self._tree.insert(iid, "end", iid=f"share:{device.ip_address}:{name}",
                                  text="", image=self._icons.folder, values=values,
                                  tags=("share",))
            if iid in opened:
                self._tree.item(iid, open=True)
        self._restripe()
        keep = [self._iid(ip) for ip in selected if self._tree.exists(self._iid(ip))]
        if keep:
            self._tree.selection_set(keep)

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

    def _on_open_event(self, _event) -> None:
        iid = self._tree.focus()
        if iid.startswith("dev:") and self._on_expand:
            self._on_expand(iid.removeprefix("dev:"))

    def _on_double_click(self, event) -> str | None:
        if str(event.type) == "ButtonPress" and \
                self._tree.identify_region(event.x, event.y) in ("heading", "separator"):
            return None
        iid = self._tree.focus()
        if iid.startswith("share:") and self._on_open_share:
            _prefix, ip, name = iid.split(":", 2)
            self._on_open_share(ip, name)
            return "break"
        ip = self.get_selected_ip()
        if ip and self._on_open_device:
            self._on_open_device(ip)
        return "break"

    def _on_right_click(self, event) -> None:
        iid = self._tree.identify_row(event.y)
        if not iid:
            return
        if iid not in self._tree.selection():
            self._tree.selection_set(iid)
        self._tree.focus(iid)
        parent = self._tree.parent(iid)
        ip = (parent or iid).removeprefix("dev:")
        if self._on_context:
            self._on_context(ip, event.x_root, event.y_root)


# --------------------------------------------------------------------------- #
# Property grid
# --------------------------------------------------------------------------- #
class PropertyPanel(ttk.Frame):
    """Two-column property grid (Property | Value) for the selected device."""

    WRAP = 48

    def __init__(self, master):
        super().__init__(master)
        self._device: Device | None = None
        self._label_info: dict = {}
        self._build()
        self._render()

    @property
    def device(self) -> Device | None:
        return self._device

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self._title = ttk.Label(self, text="Properties", style="Title.TLabel",
                                padding=(4, 2, 4, 4))
        self._title.grid(row=0, column=0, sticky="w")
        frame, self._grid = scrolled(self, lambda parent: ttk.Treeview(
            parent, columns=("value",), show="tree headings", style="Props.Treeview",
            selectmode="browse"))
        frame.grid(row=1, column=0, sticky="nsew")
        self._grid.heading("#0", text="Property", anchor="w")
        self._grid.heading("value", text="Value", anchor="w")
        self._grid.column("#0", width=theme.px(128), minwidth=theme.px(80), stretch=False)
        self._grid.column("value", width=theme.px(230), minwidth=theme.px(100), stretch=True)
        pal = theme.PALETTE
        self._grid.tag_configure("group", font=theme.UI_FONT_BOLD, background=pal.header_bg)
        self._grid.tag_configure("critical", foreground=pal.danger)
        self._grid.tag_configure("high", foreground=pal.danger)
        self._grid.tag_configure("medium", foreground=pal.warning)
        self._grid.tag_configure("muted", foreground=pal.text_muted)
        self._grid.bind("<Double-1>", self._copy_value)
        self._grid.bind("<Control-c>", self._copy_value)

    def set_device(self, device: Device | None, label: dict | None = None) -> None:
        """Show a device; ``label`` carries the user's custom name and note."""
        self._device = device
        self._label_info = label or {}
        self._render()

    def value_of(self, prop: str) -> str:
        """Value shown for a property, '' when absent (used by tests)."""
        for group in self._grid.get_children():
            for row in self._grid.get_children(group):
                if self._grid.item(row, "text") == prop:
                    return str(self._grid.item(row, "values")[0])
        return ""

    def _group(self, title: str) -> str:
        return self._grid.insert("", "end", text=title, values=("",), open=True,
                                 tags=("group",))

    def _row(self, parent: str, prop: str, value: str, tag: str = "") -> str:
        lines = textwrap.wrap(str(value), self.WRAP) or [""]
        tags = (tag,) if tag else ()
        row = self._grid.insert(parent, "end", text=prop, values=(lines[0],), tags=tags)
        for extra in lines[1:]:
            self._grid.insert(parent, "end", text="", values=(extra,), tags=tags)
        return row

    def _render(self) -> None:
        self._grid.delete(*self._grid.get_children())
        dev = self._device
        if dev is None:
            self._title.configure(text="Properties")
            self._grid.insert("", "end", text="No device selected", values=("",),
                              tags=("muted",))
            return
        self._title.configure(text=self._label_info.get("name") or dev.hostname
                              or dev.ip_address)
        general = self._group("General")
        if self._label_info.get("name"):
            self._row(general, "Custom name", self._label_info["name"])
        for prop, value in (
            ("IP address", dev.ip_address),
            ("Host name", dev.hostname),
            ("MAC address", dev.mac_address or ""),
            ("Manufacturer", dev.vendor),
            ("Model", dev.model),
            ("Device type", i18n.device_type_label(dev.device_type)),
            ("Operating system", dev.os_name),
            ("TTL", dev.ttl_label if dev.ttl else ""),
            ("Response (ms)", dev.latency_label if dev.response_time_ms else ""),
            ("Found via", dev.discovery_method),
            ("VPN subnet", "Yes" if dev.is_vpn_active else "No"),
        ):
            if value:
                self._row(general, prop, value)
        if self._label_info.get("note"):
            self._row(self._group("Note"), "Note", self._label_info["note"])

        ports = open_ports(dev)
        services = self._group(f"Services ({len(ports)})")
        if not ports:
            self._row(services, "", "No open ports found", "muted")
        for port in ports:
            name = port.service or KNOWN_SERVICES.get(port.number, "unknown")
            detail = port.version or port.banner[:80]
            self._row(services, f"{port.number}/tcp", f"{name}  {detail}".strip())

        security = self._group(f"Security — risk {dev.risk_score}")
        if not dev.findings:
            self._row(security, "", "No findings", "muted")
        for finding in dev.findings:
            title = (i18n.t(finding.title_key, **finding.params)
                     if finding.title_key else finding.title)
            detail = (i18n.t(finding.detail_key, **finding.params)
                      if finding.detail_key else finding.detail)
            row = self._row(security, finding.severity.capitalize(), title, finding.severity)
            for extra in textwrap.wrap(detail, self.WRAP):
                self._grid.insert(row, "end", text="", values=(extra,), tags=("muted",))

    def _copy_value(self, _event=None) -> None:
        iid = self._grid.focus()
        if not iid:
            return
        values = self._grid.item(iid, "values")
        if values and values[0]:
            self.clipboard_clear()
            self.clipboard_append(str(values[0]))
