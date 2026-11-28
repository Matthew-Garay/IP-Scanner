"""Reusable widgets of the main window.

* :class:`DeviceTree`   - results grid: one row per device with a type icon,
                          expandable to its open services and shared folders.
* :class:`AddressMap`   - one cell per address of the scanned range; filled
                          cells are devices that answered.
* :class:`DetailsPanel` - header (icon, name, type) and a property grid for
                          the selected device.
* :class:`ViewStack`    - left navigation rail switching between views.
* :class:`CheckBox`     - ttk.Checkbutton with ``get``/``select``/``deselect``.

Nothing here knows about scanning; the widgets only render
:class:`~weftscan.core.models.Device` records handed to them.
"""

from __future__ import annotations

import ipaddress
import textwrap
import tkinter as tk
from tkinter import ttk
from typing import Callable

from .. import i18n
from ..core.devicetype import category_name
from ..core.models import KNOWN_SERVICES, Device
from . import theme

#: Columns of the results grid: (heading, width, anchor)
TREE_COLUMNS: tuple[tuple[str, int, str], ...] = (
    ("Name", 200, "w"),
    ("IP address", 112, "w"),
    ("Type", 118, "w"),
    ("Manufacturer", 190, "w"),
    ("MAC address", 128, "w"),
    ("Open ports", 180, "w"),
    ("Risk", 72, "w"),
)
COL_NAME = 0
COL_IP = 1
COL_TYPE = 2
COL_PORTS = 5
COL_RISK = 6

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


def device_type_text(device: Device) -> str:
    if device.category:
        return category_name(device.category)
    return i18n.device_type_label(device.device_type) if device.device_type else ""


def manufacturer_text(device: Device) -> str:
    if device.vendor:
        return device.vendor
    if device.details.get("MAC address type", "").startswith("Randomized"):
        return "Private MAC address"
    return device.model or ""


def announced_model(device: Device) -> str:
    """The model a device announced itself as (UPnP/mDNS), if any."""
    if device.details.get("UPnP device") or device.details.get("Announced services"):
        return device.model
    return ""


def device_row(device: Device, alias: str = "") -> tuple[str, ...]:
    """Cell values of a device row, in :data:`TREE_COLUMNS` order."""
    ports = device.ports_compact()
    return (
        alias or device.hostname or announced_model(device) or device.ip_address,
        device.ip_address,
        device_type_text(device),
        manufacturer_text(device),
        device.mac_address or "",
        "" if ports == "-" else ports,
        risk_label(device.risk_score),
    )


def matches_filter(device: Device, text: str, alias: str = "") -> bool:
    """True when the quick filter text appears in any visible field."""
    if not text:
        return True
    text = text.lower()
    haystack = " ".join((
        alias, device.ip_address, device.hostname or "", device.mac_address or "",
        device.vendor or "", device.model or "", device.device_type or "",
        device_type_text(device), device.os_name or "", device.ports_compact(),
    )).lower()
    return text in haystack


def status_badge(device: Device, favorite: bool = False, new: bool = False) -> str:
    if favorite:
        return "favorite"
    if new:
        return "new"
    if device.risk_score >= 70:
        return "danger"
    if device.risk_score >= 40:
        return "risk"
    return "online"


# --------------------------------------------------------------------------- #
# Small wrappers
# --------------------------------------------------------------------------- #
class CheckBox(ttk.Checkbutton):
    """ttk.Checkbutton with ``get()``/``select()``/``deselect()``."""

    def __init__(self, master, text: str = "", command=None, value: bool = False,
                 style: str = "TCheckbutton"):
        self._var = tk.BooleanVar(master, value=value)
        super().__init__(master, text=text, variable=self._var, command=command, style=style)

    def get(self) -> bool:
        return bool(self._var.get())

    def select(self) -> None:
        self._var.set(True)

    def deselect(self) -> None:
        self._var.set(False)


def scrolled(parent, widget_factory: Callable, horizontal: bool = False):
    """Place a widget with scroll bars in a frame; returns (frame, widget)."""
    frame = ttk.Frame(parent, style="Paper.TFrame")
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


def text_box(parent, **options) -> tk.Text:
    pal = theme.PALETTE
    defaults = dict(font=theme.MONO_FONT, relief="flat", borderwidth=0, padx=10, pady=8,
                    background=pal.paper, foreground=pal.ink, highlightthickness=1,
                    highlightbackground=pal.hairline, highlightcolor=pal.hairline,
                    selectbackground=pal.accent_soft, selectforeground=pal.ink,
                    insertbackground=pal.ink)
    defaults.update(options)
    return tk.Text(parent, **defaults)


# --------------------------------------------------------------------------- #
# Navigation rail
# --------------------------------------------------------------------------- #
class ViewStack:
    """A left navigation rail plus a stack of views, addressed by name."""

    def __init__(self, rail_parent, view_parent, icons: theme.Icons):
        pal = theme.PALETTE
        self._icons = icons
        self.rail = tk.Frame(rail_parent, background=pal.chrome, width=theme.px(170))
        self._views_parent = view_parent
        self._views: dict[str, ttk.Frame] = {}
        self._items: dict[str, tuple[tk.Frame, tk.Frame, tk.Label]] = {}
        self._current = ""
        self._listeners: list[Callable[[str], None]] = []
        tk.Frame(self.rail, background=pal.chrome, height=theme.px(8)).pack(fill="x")

    def add_tab(self, name: str, icon: str = "") -> ttk.Frame:
        pal = theme.PALETTE
        view = ttk.Frame(self._views_parent, style="Paper.TFrame")
        view.grid(row=0, column=0, sticky="nsew")
        self._views[name] = view

        item = tk.Frame(self.rail, background=pal.chrome, cursor="hand2")
        item.pack(fill="x", padx=(0, theme.px(8)), pady=1)
        marker = tk.Frame(item, background=pal.chrome, width=theme.px(3))
        marker.pack(side="left", fill="y")
        label = tk.Label(item, text=f"  {name}", anchor="w", background=pal.chrome,
                         foreground=pal.ink_2, font=theme.BODY_FONT,
                         image=self._icons.ui(icon) if icon else "", compound="left",
                         padx=theme.px(10), pady=theme.px(7))
        label.pack(side="left", fill="x", expand=True)
        for widget in (item, label):
            widget.bind("<Button-1>", lambda _e, n=name: self.set(n))
            widget.bind("<Enter>", lambda _e, n=name: self._hover(n, True))
            widget.bind("<Leave>", lambda _e, n=name: self._hover(n, False))
        self._items[name] = (item, marker, label)
        if not self._current:
            self.set(name)
        return view

    def _hover(self, name: str, inside: bool) -> None:
        if name == self._current:
            return
        pal = theme.PALETTE
        item, marker, label = self._items[name]
        colour = pal.hover if inside else pal.chrome
        for widget in (item, marker, label):
            widget.configure(background=colour)

    def set(self, name: str) -> None:
        pal = theme.PALETTE
        self._current = name
        for other, (item, marker, label) in self._items.items():
            selected = other == name
            background = pal.accent_soft if selected else pal.chrome
            item.configure(background=background)
            label.configure(background=background,
                            foreground=pal.ink if selected else pal.ink_2,
                            font=theme.SUBTITLE_FONT if selected else theme.BODY_FONT)
            marker.configure(background=pal.accent if selected else background)
        self._views[name].tkraise()
        for listener in self._listeners:
            listener(name)

    def get(self) -> str:
        return self._current

    def on_change(self, callback: Callable[[str], None]) -> None:
        self._listeners.append(callback)


# --------------------------------------------------------------------------- #
# Address map
# --------------------------------------------------------------------------- #
class AddressMap(tk.Canvas):
    """One cell per address in the scanned range, like a patch panel.

    Filled cells are devices that answered; their colour follows the row's
    status. Hovering shows the address, clicking selects the device.
    """

    MAX_CELLS = 1024
    PER_ROW = 128

    def __init__(self, master, on_select: Callable[[str], None] | None = None,
                 on_hover: Callable[[str], None] | None = None):
        pal = theme.PALETTE
        super().__init__(master, height=theme.px(22), background=pal.paper,
                         highlightthickness=0, borderwidth=0)
        self._on_select = on_select
        self._on_hover = on_hover
        self._addresses: list[str] = []
        self._states: dict[str, str] = {}
        self._labels: dict[str, str] = {}
        self._selected = ""
        self._cells: dict[str, int] = {}
        self.bind("<Configure>", lambda _e: self._draw())
        self.bind("<Motion>", self._motion)
        self.bind("<Leave>", lambda _e: self._on_hover and self._on_hover(""))
        self.bind("<Button-1>", self._click)

    @property
    def visible(self) -> bool:
        return 0 < len(self._addresses) <= self.MAX_CELLS

    def set_range(self, addresses: list[str]) -> None:
        self._addresses = list(addresses) if len(addresses) <= self.MAX_CELLS else []
        self._states.clear()
        self._labels.clear()
        self._selected = ""
        self._draw()

    def set_device(self, ip: str, state: str, label: str = "") -> None:
        self._states[ip] = state
        self._labels[ip] = label
        cell = self._cells.get(ip)
        if cell is not None:
            self.itemconfigure(cell, fill=self._colour(ip))
        elif ip in self._addresses:
            self._draw()

    def select(self, ip: str) -> None:
        previous, self._selected = self._selected, ip
        for address in (previous, ip):
            cell = self._cells.get(address)
            if cell is not None:
                self.itemconfigure(cell, outline=self._outline(address),
                                   width=2 if address == ip else 1)

    def _colour(self, ip: str) -> str:
        pal = theme.PALETTE
        return {
            "online": pal.accent, "new": pal.ink, "risk": pal.warn, "danger": pal.danger,
            "favorite": pal.accent,
        }.get(self._states.get(ip, ""), pal.empty_cell)

    def _outline(self, ip: str) -> str:
        return theme.PALETTE.ink if ip == self._selected else self._colour(ip)

    def _layout(self) -> tuple[int, int, float, float]:
        count = len(self._addresses)
        per_row = min(count, self.PER_ROW) or 1
        rows = (count + per_row - 1) // per_row
        width = max(1, self.winfo_width())
        cell = width / per_row
        height = theme.px(9) if rows > 1 else theme.px(16)
        return per_row, rows, cell, height

    def _draw(self) -> None:
        self.delete("all")
        self._cells.clear()
        if not self.visible:
            self.configure(height=1)
            return
        per_row, rows, cell, height = self._layout()
        gap = 1 if cell < 6 else 2
        self.configure(height=int(rows * (height + 2)))
        for index, ip in enumerate(self._addresses):
            row, column = divmod(index, per_row)
            x0 = column * cell
            y0 = row * (height + 2)
            self._cells[ip] = self.create_rectangle(
                x0, y0, x0 + max(1.0, cell - gap), y0 + height,
                fill=self._colour(ip), outline=self._outline(ip),
                width=2 if ip == self._selected else 1)

    def _address_at(self, x: float, y: float) -> str:
        if not self.visible:
            return ""
        per_row, _rows, cell, height = self._layout()
        column, row = int(x // cell), int(y // (height + 2))
        index = row * per_row + column
        if 0 <= column < per_row and 0 <= index < len(self._addresses):
            return self._addresses[index]
        return ""

    def _motion(self, event) -> None:
        ip = self._address_at(event.x, event.y)
        if self._on_hover:
            label = self._labels.get(ip, "")
            self._on_hover(f"{ip}   {label}".strip() if ip in self._states else
                           (f"{ip}   no answer" if ip else ""))
        self.configure(cursor="hand2" if ip in self._states else "")

    def _click(self, event) -> None:
        ip = self._address_at(event.x, event.y)
        if ip in self._states and self._on_select:
            self._on_select(ip)


def range_addresses(text: str) -> list[str]:
    """Addresses of a typed range for the map (empty when too large)."""
    from ..core.utils import plan_targets

    plan = plan_targets(text)
    if plan.is_empty or plan.total > AddressMap.MAX_CELLS:
        return []
    addresses = plan.addresses()
    addresses.sort(key=lambda ip: int(ipaddress.ip_address(ip)))
    return addresses


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
        super().__init__(master, style="Paper.TFrame")
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
        self._tree.column("#0", width=theme.px(52), minwidth=theme.px(44), stretch=False)
        for i, (label, width, anchor) in enumerate(TREE_COLUMNS):
            self._tree.heading(cols[i], text=label, anchor="w",
                               command=lambda k=i: self.sort_by(k))
            self._tree.column(cols[i], width=theme.px(width), minwidth=theme.px(40),
                              anchor=anchor, stretch=i in (COL_NAME, COL_PORTS))
        vsb = ttk.Scrollbar(self, orient="vertical", command=self._tree.yview)
        hsb = ttk.Scrollbar(self, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        pal = theme.PALETTE
        self._tree.tag_configure("odd", background=pal.row_alt)
        self._tree.tag_configure("even", background=pal.paper)
        self._tree.tag_configure("child", foreground=pal.ink_2)
        self._tree.tag_configure("share", foreground=pal.accent)

        self._empty = ttk.Label(self._tree, text="", style="PaperMuted.TLabel",
                                justify="center")
        self._empty_text = ""

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
        self._update_empty()

    def row_count(self) -> int:
        return len(self._tree.get_children())

    def visible_ips(self) -> list[str]:
        return [iid.removeprefix("dev:") for iid in self._tree.get_children()]

    def row_values(self, ip: str) -> tuple[str, ...]:
        return tuple(self._tree.item(self._iid(ip), "values"))

    def badge_of(self, ip: str) -> str:
        device = self._devices.get(ip)
        if device is None:
            return ""
        return status_badge(device, ip in self._favorites, ip in self._new)

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
        image = self._icons.device(device.category, self.badge_of(ip))
        values = device_row(device, self._aliases.get(ip, ""))
        if exists:
            self._tree.item(iid, image=image, values=values)
            self._tag(iid)
        else:
            self._tree.insert("", self._insert_index(device), iid=iid, text="",
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
            values = (f"\\\\{ip}\\{name}", "", "Shared folder" if kind.lower().startswith(
                ("disk", "disco")) else kind, comment, "", "", "")
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

    def _tag(self, iid: str, index: int | None = None) -> None:
        if index is None:
            index = self._tree.index(iid)
        self._tree.item(iid, tags=("odd" if index % 2 else "even",))

    def _restripe(self) -> None:
        for index, iid in enumerate(self._tree.get_children()):
            self._tag(iid, index)
        self._update_empty()

    def set_empty_message(self, text: str) -> None:
        """Text shown in the middle of the grid while it has no rows."""
        self._empty_text = text
        self._update_empty()

    def _update_empty(self) -> None:
        if self._tree.get_children() or not self._empty_text:
            self._empty.place_forget()
            return
        message = self._empty_text
        if self._devices and (self._filter or self._only_open):
            message = "No devices match the current search or filter."
        self._empty.configure(text=message)
        self._empty.place(relx=0.5, rely=0.4, anchor="center")

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
            name = port.service or KNOWN_SERVICES.get(port.number, "Unknown service")
            detail = port.version or port.banner or ""
            values = (name, f"{port.number}/tcp", "Service", detail[:90], "", "", "")
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
            arrow = (" ▾" if self._sort_reverse else " ▴") if i == idx else ""
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
# Details panel
# --------------------------------------------------------------------------- #
class DetailsPanel(ttk.Frame):
    """Header with the device's icon and name, quick actions and a property grid."""

    WRAP = 46

    def __init__(self, master, icons: theme.Icons, actions: dict[str, Callable[[], None]]
                 | None = None):
        super().__init__(master, style="Paper.TFrame", padding=(theme.px(14), theme.px(12),
                                                                 theme.px(8), theme.px(8)))
        self._icons = icons
        self._actions = actions or {}
        self._device: Device | None = None
        self._label_info: dict = {}
        self._build()
        self._render()

    @property
    def device(self) -> Device | None:
        return self._device

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        header = ttk.Frame(self, style="Paper.TFrame")
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)
        self._icon = ttk.Label(header, style="Paper.TLabel")
        self._icon.grid(row=0, column=0, rowspan=2, padx=(0, theme.px(10)))
        self._title = ttk.Label(header, style="Subtitle.TLabel", text="")
        self._title.grid(row=0, column=1, sticky="sw")
        self._subtitle = ttk.Label(header, style="Secondary.TLabel", text="")
        self._subtitle.grid(row=1, column=1, sticky="nw")

        self._buttons = ttk.Frame(self, style="Paper.TFrame")
        self._buttons.grid(row=1, column=0, sticky="w", pady=(theme.px(10), theme.px(8)))
        self._action_buttons: list[ttk.Button] = []
        for label, key in (("Open", "open"), ("Rename", "rename"), ("Rescan", "rescan")):
            button = ttk.Button(self._buttons, text=label, style="Small.TButton",
                                command=lambda k=key: self._actions.get(k, lambda: None)())
            button.pack(side="left", padx=(0, theme.px(6)))
            self._action_buttons.append(button)

        frame, self._grid = scrolled(self, lambda parent: ttk.Treeview(
            parent, columns=("value",), show="tree", style="Props.Treeview",
            selectmode="browse"))
        frame.grid(row=2, column=0, sticky="nsew")
        self._grid.column("#0", width=theme.px(122), minwidth=theme.px(80), stretch=False)
        self._grid.column("value", width=theme.px(220), minwidth=theme.px(100), stretch=True)
        pal = theme.PALETTE
        self._grid.tag_configure("group", font=theme.UI_FONT_BOLD, foreground=pal.ink)
        self._grid.tag_configure("prop", foreground=pal.ink_2)
        self._grid.tag_configure("critical", foreground=pal.danger)
        self._grid.tag_configure("high", foreground=pal.danger)
        self._grid.tag_configure("medium", foreground=pal.warn)
        self._grid.tag_configure("muted", foreground=pal.ink_3)
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
                if self._grid.item(row, "text").strip() == prop:
                    return str(self._grid.item(row, "values")[0])
        return ""

    def _group(self, title: str) -> str:
        return self._grid.insert("", "end", text=title, values=("",), open=True,
                                 tags=("group",))

    def _row(self, parent: str, prop: str, value: str, tag: str = "prop") -> str:
        lines = textwrap.wrap(str(value), self.WRAP) or [""]
        row = self._grid.insert(parent, "end", text=prop, values=(lines[0],), tags=(tag,))
        for extra in lines[1:]:
            self._grid.insert(parent, "end", text="", values=(extra,), tags=(tag,))
        return row

    def _render(self) -> None:
        self._grid.delete(*self._grid.get_children())
        dev = self._device
        state = "disabled" if dev is None else "normal"
        for button in self._action_buttons:
            button.configure(state=state)
        if dev is None:
            self._icon.configure(image=self._icons.header("unknown"))
            self._title.configure(text="No device selected")
            self._subtitle.configure(text="Select a device to see its details.")
            return

        name = self._label_info.get("name") or dev.hostname or dev.ip_address
        self._icon.configure(image=self._icons.header(dev.category))
        self._title.configure(text=name)
        subtitle = [device_type_text(dev) or "Unknown device", dev.ip_address]
        self._subtitle.configure(text=",  ".join(part for part in subtitle if part))

        general = self._group("Device")
        if self._label_info.get("name") and dev.hostname:
            self._row(general, "Host name", dev.hostname)
        for prop, value in (
            ("IP address", dev.ip_address),
            ("MAC address", dev.mac_address or ""),
            ("Manufacturer", manufacturer_text(dev)),
            ("Model", dev.model),
            ("Type", device_type_text(dev)),
            ("Operating system", dev.os_name),
            ("Role", dev.details.get("Role", "")
             if dev.details.get("Role") != device_type_text(dev) else ""),
            ("Response time", f"{dev.latency_label} ms" if dev.response_time_ms else ""),
            ("TTL", dev.ttl_label if dev.ttl else ""),
            ("Found by", dev.discovery_method),
        ):
            if value:
                self._row(general, prop, value)
        if self._label_info.get("note"):
            self._row(general, "Note", self._label_info["note"])

        announced = {k: v for k, v in dev.details.items() if k != "Role"}
        if announced:
            group = self._group("Announced by the device")
            for prop, value in announced.items():
                self._row(group, prop, value)

        ports = open_ports(dev)
        services = self._group(f"Services ({len(ports)})")
        if not ports:
            self._row(services, "", "No open ports found", "muted")
        for port in ports:
            name = port.service or KNOWN_SERVICES.get(port.number, "Unknown service")
            detail = port.version or port.banner[:80]
            self._row(services, f"{port.number}/tcp", f"{name}  {detail}".strip())

        risk = risk_label(dev.risk_score)
        security = self._group("Security")
        self._row(security, "Risk", f"{risk} ({dev.risk_score} of 100)" if risk else "None found",
                  "prop" if risk else "muted")
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


# Backwards-compatible name.
PropertyPanel = DetailsPanel
