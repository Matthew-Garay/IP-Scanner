"""
CustomTkinter user interface for IP Inspector â€” Advanced IP Scanner style.

Layout (top to bottom, left to right):

* Native menu bar:  Archivo | Vista | ConfiguraciÃ³n | Ayuda
* Toolbar:          Explorar (Play) | Pausa | Detener | red
* Control row:      Rango IP (label + entry)  â”€â”€â”  Filtro rÃ¡pido (entry + borrar)
* Tab view:         [ Lista de resultados ] | [ Favoritos ]
* Main area:        Tree-view table (Estado, Nombre, IP, Fabricante, MAC, Puertos)
                      + collapsible Detalle panel on the right
* Status bar:       mÃ©tricas en tiempo real (activo / inactivo / desconocido)

Threading model
---------------
Every long operation runs on a worker thread that pushes results onto a
``queue.Queue``. The main thread drains it with ``after()`` â€” the only safe
way to update tkinter from another thread and keeps the window responsive
during a full sweep.

This module is the only one allowed to know about widgets. Presentation
lives in :mod:`ip_inspector.interface.theme`; this module owns behaviour
and layout.
"""

from __future__ import annotations

import csv
import json
import logging
import queue
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from .. import i18n
from ..actions.menu import best_web_port, open_remote_desktop, open_web, wake_device
from ..core.models import (
    Device,
    KNOWN_SERVICES,
    Port,
    ScannerEvent,
    ScanRequest,
)
from ..core.network import NetworkScanner
from ..core.utils import (
    MAX_TARGETS,
    default_gateway,
    list_adapters,
    local_network_hint,
    lookup_vendor,
    plan_targets,
)
from . import theme
from .fasttable import FastTable

logger = logging.getLogger(__name__)

APP_NAME = "IP Inspector"
APP_AUTHOR = "Matthew Garay"

WINDOW_SIZE = (1366, 900)
WINDOW_MINIMUM = (1024, 700)
POLL_INTERVAL_MS = 120

#: Columns of the results tree-view: (i18n key, width, anchor)
TREE_COLUMNS: tuple[tuple[str, int, str], ...] = (
    ("col.status",   52,  "center"),
    ("col.name",     170, "w"),
    ("col.ip",       140, "w"),
    ("col.vendor",   160, "w"),
    ("col.mac",      150, "w"),
    ("col.ports",    300, "w"),
)

#: Sub-columns shown under an expanded device (services / ports).


# --------------------------------------------------------------------------- #
# Device tree â€” table with expandable services (Advanced IP Scanner style)
# --------------------------------------------------------------------------- #
class DeviceTree(ctk.CTkFrame):
    """Tree-view table: one row per device, expandable to show open services.

    Uses a native ``ttk.Treeview`` so expand/collapse and per-row icons work
    exactly like a desktop tree table. Styled through ``ttk.Style`` to blend
    with the CustomTkinter palette.
    """

    def __init__(self, master, on_select=None, on_open_device=None):
        super().__init__(master, fg_color="transparent")
        self._on_select = on_select
        self._on_open_device = on_open_device
        self._devices: dict[str, Device] = {}
        self._device_item: dict[str, str] = {}   # ip -> tree iid
        self._service_items: dict[str, list[str]] = {}  # ip -> [service iids]
        self._sorted_ips: list[str] = []
        self._build()
        self._apply_palette(theme.current())

    # -- construction ------------------------------------------------------- #
    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        pal = theme.current()
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "AIS.Treeview",
            background=pal.surface,
            foreground=pal.text_primary,
            fieldbackground=pal.surface,
            rowheight=26,
            font=("Segoe UI", 10),
            borderwidth=0,
            relief="flat",
        )
        style.configure(
            "AIS.Treeview.Heading",
            background=pal.header_bg,
            foreground=pal.header_text,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            borderwidth=0,
        )
        style.map(
            "AIS.Treeview",
            background=[("selected", pal.selection)],
            foreground=[("selected", pal.selection_text)],
        )

        cols = [f"c{i}" for i in range(len(TREE_COLUMNS))]
        self._tree = ttk.Treeview(
            self, columns=cols, show="tree headings",
            style="AIS.Treeview", selectmode="browse",
        )
        self._tree.heading("#0", text="", anchor="w")
        self._tree.column("#0", width=24, minwidth=24, stretch=False, anchor="center")
        for i, (label, width, anchor) in enumerate(TREE_COLUMNS):
            self._tree.heading(cols[i], text=str(label).upper(),
                               command=lambda k=i: self._sort(k))
            self._tree.column(cols[i], width=width, minwidth=60,
                              anchor={"w": "w", "center": "center"}.get(anchor, "w"),
                              stretch=True)

        vsb = ttk.Scrollbar(self, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        self._tree.bind("<<TreeviewOpen>>", self._on_item_open)
        self._tree.bind("<<TreeviewSelect>>", self._on_select_event)
        self._tree.bind("<Double-1>", self._on_double_click)
        # Mouse-wheel forwarding inside CTkTabview / CTkFrame containers.
        self._tree.bind("<MouseWheel>", self._on_mouse_wheel)
        self._tree.bind("<Button-4>", self._on_scroll_up)
        self._tree.bind("<Button-5>", self._on_scroll_down)

    # -- public API ---------------------------------------------------------- #
    def clear(self) -> None:
        self._tree.delete(*self._tree.get_children())
        self._devices.clear()
        self._device_item.clear()
        self._service_items.clear()
        self._sorted_ips = []

    def set_devices(self, devices: dict[str, Device]) -> None:
        """Replace the whole device set and repaint the tree."""
        self._devices = dict(devices)
        self._rebuild()

    def upsert_device(self, device: Device) -> None:
        """Add or update a single device row (called mid-scan)."""
        ip = device.ip_address
        self._devices[ip] = device
        if ip in self._device_item:
            self._refresh_row(ip)
        else:
            self._insert_device(ip)

    def get_selected_ip(self) -> str | None:
        sel = self._tree.selection()
        if not sel:
            return None
        iid = sel[0]
        # The iid may be a service child; walk up to the device parent.
        parent = self._tree.parent(iid)
        if parent:
            iid = parent
        for ip, item in self._device_item.items():
            if item == iid:
                return ip
        return None

    # -- internals ----------------------------------------------------------- #
    def _rebuild(self) -> None:
        self._tree.delete(*self._tree.get_children())
        self._device_item.clear()
        self._service_items.clear()
        self._sorted_ips = sorted(self._devices, key=lambda ip: tuple(int(o) for o in ip.split(".")))
        for ip in self._sorted_ips:
            self._insert_device(ip)

    def _insert_device(self, ip: str) -> None:
        dev = self._devices[ip]
        status = "Online" if dev.is_alive else "Offline"
        values = (
            status,
            dev.hostname or "-",
            dev.ip_address,
            dev.vendor_label,
            dev.mac_address or "-",
            dev.ports_summary or "-",
        )
        tag = "st_ok" if dev.is_alive else "st_off"
        # The tree column (#0) holds the expand arrow + status dot glyph.
        text = "â— " if dev.is_alive else "â—‹ "
        iid = self._tree.insert("", "end", iid=f"dev:{ip}", text=text,
                                values=values, open=False, tags=(tag,))
        self._device_item[ip] = iid
        # Placeholder child so the expand arrow shows until first open.
        self._tree.insert(iid, "end", text="")
        self._service_items[ip] = []

    def _refresh_row(self, ip: str) -> None:
        dev = self._devices[ip]
        status = "Online" if dev.is_alive else "Offline"
        values = (
            status,
            dev.hostname or "-",
            dev.ip_address,
            dev.vendor_label,
            dev.mac_address or "-",
            dev.ports_summary or "-",
        )
        tag = "st_ok" if dev.is_alive else "st_off"
        text = "â— " if dev.is_alive else "â—‹ "
        iid = self._device_item[ip]
        self._tree.item(iid, text=text, values=values, tags=(tag,))

    def _fill_services(self, ip: str) -> None:
        """Insert (or replace) service children under a device row."""
        dev = self._devices.get(ip)
        if not dev:
            return
        iid = self._device_item.get(ip)
        if not iid:
            return
        # Remove old service children + placeholder.
        for child in self._tree.get_children(iid):
            self._tree.delete(child)
        items: list[str] = []
        for port in sorted(dev.open_ports, key=lambda p: p.number):
            if not port.is_open:
                continue
            name = KNOWN_SERVICES.get(port.number, port.service or "Desconocido")
            values = (str(port.number), name, "Abierto", port.banner or "-")
            child = self._tree.insert(iid, "end", text="â–¸", values=values,
                                      tags=("svc_open",))
            items.append(child)
        self._service_items[ip] = items
        # Auto-expand so the user immediately sees the services.
        self._tree.item(iid, open=True)

    def _sort(self, idx: int) -> None:
        # Keep the current IP order for now; a full sorter can be wired here.
        pass

    def _on_select_event(self, event) -> None:
        ip = self.get_selected_ip()
        if ip and self._on_select:
            self._on_select(ip)

    def _on_double_click(self, event) -> None:
        ip = self.get_selected_ip()
        if ip and self._on_open_device:
            self._on_open_device(ip)

    def _on_mouse_wheel(self, event):
        self._tree.yview_scroll(int(-1 * (event.delta / 120)), "units")
        return "break"

    def _on_scroll_up(self, event):
        self._tree.yview_scroll(-1, "units")
        return "break"

    def _on_scroll_down(self, event):
        self._tree.yview_scroll(1, "units")
        return "break"

    def _on_item_open(self, event) -> None:
        iid = self._tree.focus()
        if not iid:
            return
        parent = self._tree.parent(iid)
        if not parent:
            return  # top-level device was just opened
        # A service child was opened; nothing to do here.
        return

    def _apply_palette(self, pal) -> None:
        try:
            self._tree.tag_configure("st_ok", foreground=pal.state_ok)
            self._tree.tag_configure("st_off", foreground=pal.state_off)
            self._tree.tag_configure("st_unk", foreground=pal.text_muted)
            self._tree.tag_configure("svc_open", foreground=pal.state_ok)
            self._tree.tag_configure("svc_closed", foreground=pal.text_muted)
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Collapsible detail panel
# --------------------------------------------------------------------------- #
class DetailPanel(ctk.CTkFrame):
    """Right-hand panel showing full details for the selected device.

    Can be collapsed to a slim handle so the table gets the whole window.
    """

    def __init__(self, master, collapsed_width: int = 46, expanded_width: int = 380):
        super().__init__(master, fg_color="transparent")
        self._collapsed_width = collapsed_width
        self._expanded_width = expanded_width
        self._expanded = True
        self._device: Device | None = None
        self._build()
        self.expand()

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        pal = theme.current()
        self._header = ctk.CTkFrame(self, fg_color=pal.surface_alt, corner_radius=0)
        self._header.grid(row=0, column=0, sticky="ew", pady=(0, 1))
        self._header.grid_columnconfigure(1, weight=1)

        self._toggle_btn = ctk.CTkButton(
            self._header, text="â—€", width=26, height=26,
            fg_color="transparent", hover_color=pal.hover,
            text_color=pal.text_secondary, font=("Segoe UI", 12, "bold"),
            command=self.toggle,
        )
        self._toggle_btn.grid(row=0, column=0, padx=6, pady=6)

        self._title = ctk.CTkLabel(
            self._header, text="Detalle del dispositivo",
            font=("Segoe UI", 11, "bold"), text_color=pal.text_primary,
        )
        self._title.grid(row=0, column=1, padx=8, sticky="w")

        self._scroll = ctk.CTkScrollableFrame(self, fg_color=pal.surface)
        self._scroll.grid(row=1, column=0, sticky="nsew")
        self._scroll.grid_columnconfigure(0, weight=1)

        self._fields_frame = ctk.CTkFrame(self._scroll, fg_color="transparent")
        self._fields_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        self._fields_frame.grid_columnconfigure(1, weight=1)

        self._row_widgets: list[ctk.CTkBaseClass] = []

    def toggle(self) -> None:
        self._expanded = not self._expanded
        width = self._expanded_width if self._expanded else self._collapsed_width
        self.configure(width=width)
        self._toggle_btn.configure(text="â–¶" if not self._expanded else "â—€")
        if self._expanded:
            self._scroll.grid()
        else:
            self._scroll.grid_remove()
        self.update_idletasks()

    def _render(self) -> None:
        for w in self._row_widgets:
            w.destroy()
        self._row_widgets.clear()

        pal = theme.current()
        if not self._device:
            row = ctk.CTkLabel(
                self._fields_frame, text="Selecciona un dispositivo para ver el detalle.",
                text_color=pal.text_muted, font=("Segoe UI", 10),
            )
            row.grid(row=0, column=0, columnspan=2, sticky="w", pady=8)
            self._row_widgets.append(row)
            return

        dev = self._device
        fields: list[tuple[str, str]] = [
            ("IP", dev.ip_address),
            ("Estado", "Activo" if dev.is_alive else "Inactivo"),
            ("Nombre", dev.hostname or "â€”"),
            ("Fabricante", dev.vendor_label),
            ("Modelo", dev.model_label),
            ("DirecciÃ³n MAC", dev.mac_address or "â€”"),
            ("Tipo", dev.device_type),
            ("Sistema operativo", dev.os_name or "â€”"),
            ("TTL", dev.ttl_label),
            ("Latencia", dev.latency_label),
            ("MÃ©todo de descubrimiento", dev.discovery_method or "â€”"),
            ("Puertos abiertos", dev.ports_compact()),
            ("Riesgo", str(dev.risk_score)),
        ]

        for r, (label, value) in enumerate(fields):
            lab = ctk.CTkLabel(
                self._fields_frame, text=label + ":",
                font=("Segoe UI", 10, "bold"), text_color=pal.text_secondary,
                anchor="w", width=150,
            )
            lab.grid(row=r, column=0, sticky="w", padx=(0, 8), pady=3)
            val = ctk.CTkLabel(
                self._fields_frame, text=value,
                font=("Segoe UI", 10), text_color=pal.text_primary,
                anchor="w",
            )
            val.grid(row=r, column=1, sticky="ew", pady=3)
            self._row_widgets.extend([lab, val])

        # Services sub-section
        if dev.open_ports:
            r = len(fields)
            sep = ctk.CTkFrame(self._fields_frame, height=1, fg_color=pal.grid_line)
            sep.grid(row=r, column=0, columnspan=2, sticky="ew", pady=(10, 6))
            self._row_widgets.append(sep)

            svc_title = ctk.CTkLabel(
                self._fields_frame, text="Servicios detectados",
                font=("Segoe UI", 10, "bold"), text_color=pal.primary,
                anchor="w",
            )
            svc_title.grid(row=r + 1, column=0, columnspan=2, sticky="w", pady=(0, 4))
            self._row_widgets.append(svc_title)

            for s, port in enumerate(sorted(dev.open_ports, key=lambda p: p.number)):
                if not port.is_open:
                    continue
                rr = r + 2 + s
                name = KNOWN_SERVICES.get(port.number, port.service or "Desconocido")
                p_lab = ctk.CTkLabel(
                    self._fields_frame, text=f"Puerto {port.number}:",
                    font=("Segoe UI", 10), text_color=pal.text_secondary,
                    anchor="w", width=150,
                )
                p_lab.grid(row=rr, column=0, sticky="w", padx=(20, 8), pady=2)
                p_val = ctk.CTkLabel(
                    self._fields_frame,
                    text=f"{name} â€” {port.banner or '-'}",
                    font=("Segoe UI", 10), text_color=pal.text_primary,
                    anchor="w",
                )
                p_val.grid(row=rr, column=1, sticky="ew", pady=2)
                self._row_widgets.extend([p_lab, p_val])
        self.update_idletasks()

    def expand(self) -> None:
        if not self._expanded:
            self.toggle()

    def collapse(self) -> None:
        if self._expanded:
            self.toggle()

    def set_device(self, device: Device | None) -> None:
        self._device = device
        self._render()

# --------------------------------------------------------------------------- #
# Main application window
# --------------------------------------------------------------------------- #
class IPInspectorApp(ctk.CTk):
    """Main window: Advanced IP Scanner look-alike."""

    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self._centre_on_screen(WINDOW_SIZE, WINDOW_MINIMUM)
        self.minsize(*WINDOW_MINIMUM)

        i18n.initialize()
        theme.set_mode(ctk.get_appearance_mode())

        self._scanner = NetworkScanner(event_queue=queue.Queue())
        self._devices: dict[str, Device] = {}
        self._favorites: set[str] = set()

        self._scanning = False
        self._scan_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._paint_job: str | None = None
        self._last_paint = 0.0
        self._detail_panel_visible = True

        # UI references (set in _build_layout)
        self._menu_bar: tk.Menu | None = None
        self._range_entry: ctk.CTkEntry | None = None
        self._filter_entry: ctk.CTkEntry | None = None
        self._filter_clear_btn: ctk.CTkButton | None = None
        self._scan_btn: ctk.CTkButton | None = None
        self._pause_btn: ctk.CTkButton | None = None
        self._stop_btn: ctk.CTkButton | None = None
        self._status_label: ctk.CTkLabel | None = None
        self._active_label: ctk.CTkLabel | None = None
        self._inactive_label: ctk.CTkLabel | None = None
        self._unknown_label: ctk.CTkLabel | None = None
        self._tree: DeviceTree | None = None
        self._detail: DetailPanel | None = None
        self._tabview: ctk.CTkTabview | None = None
        self._results_tab: str | None = None
        self._favs_tab: str | None = None
        self._favs_list = None
        self._time_label: ctk.CTkLabel | None = None

        self._build_menu_bar()
        self._build_layout()
        self._start_queue_poll()

    # -- window helpers ------------------------------------------------------- #
    def _centre_on_screen(self, size, minimum):
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        # Clamp the desired size to the screen but never below the minimum.
        w = max(min(size[0], sw), minimum[0])
        h = max(min(size[1], sh), minimum[1])
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    # -- menu bar ------------------------------------------------------------- #
    def _build_menu_bar(self) -> None:
        self._menu_bar = tk.Menu(self)
        self.config(menu=self._menu_bar)

        m_file = tk.Menu(self._menu_bar, tearoff=0)
        m_file.add_command(label="Escanear redâ€¦", command=self._on_scan_click)
        m_file.add_separator()
        m_file.add_command(label="Exportar listaâ€¦", command=self._export_csv)
        m_file.add_separator()
        m_file.add_command(label="Salir", command=self.quit)
        self._menu_bar.add_cascade(label="Archivo", menu=m_file)

        m_view = tk.Menu(self._menu_bar, tearoff=0)
        m_view.add_command(label="Panel de detalle", command=self._toggle_detail)
        m_view.add_separator()
        m_view.add_command(label="Modo claro", command=lambda: theme.set_mode("light"))
        m_view.add_command(label="Modo oscuro", command=lambda: theme.set_mode("dark"))
        m_view.add_command(label="Sistema", command=lambda: theme.set_mode("system"))
        self._menu_bar.add_cascade(label="Vista", menu=m_view)

        m_cfg = tk.Menu(self._menu_bar, tearoff=0)
        m_cfg.add_command(label="Preferenciasâ€¦", command=self._open_prefs)
        m_cfg.add_command(label="Adaptadores de redâ€¦", command=self._show_adapters)
        self._menu_bar.add_cascade(label="ConfiguraciÃ³n", menu=m_cfg)

        m_help = tk.Menu(self._menu_bar, tearoff=0)
        m_help.add_command(label="Acerca de IP Inspector", command=self._show_about)
        m_help.add_command(label="Ayuda", command=self._show_help)
        self._menu_bar.add_cascade(label="Ayuda", menu=m_help)

    # -- layout --------------------------------------------------------------- #
    def _build_layout(self) -> None:
        pal = theme.current()
        self.configure(fg_color=pal.background)

        # Root: row 0 = header block (toolbar + control), row 1 = tabs+content, row 2 = status
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ========== Header block ===========================================
        header = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 4))
        header.grid_columnconfigure(1, weight=1)

        # --- Toolbar ---
        toolbar = ctk.CTkFrame(header, fg_color=pal.surface, corner_radius=8, height=44)
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        toolbar.grid_propagate(False)
        toolbar.grid_columnconfigure(2, weight=1)

        self._scan_btn = ctk.CTkButton(
            toolbar, text="â–¶  Explorar", width=120, height=32,
            fg_color=pal.accent, hover_color=pal.accent_hover,
            text_color=pal.accent_text, font=("Segoe UI", 11, "bold"),
            command=self._on_scan_click,
        )
        self._scan_btn.grid(row=0, column=0, padx=10, pady=6)

        self._pause_btn = ctk.CTkButton(
            toolbar, text="â¸  Pausa", width=86, height=32,
            fg_color="transparent", hover_color=pal.hover,
            text_color=pal.text_primary, font=("Segoe UI", 10),
            command=self._on_pause_click, state="disabled",
        )
        self._pause_btn.grid(row=0, column=1, padx=(0, 6), pady=6)

        self._stop_btn = ctk.CTkButton(
            toolbar, text="â¹  Detener", width=90, height=32,
            fg_color="transparent", hover_color=pal.hover,
            text_color=pal.text_primary, font=("Segoe UI", 10),
            command=self._on_stop_click, state="disabled",
        )
        self._stop_btn.grid(row=0, column=2, padx=(0, 10), pady=6)

        # --- Network + filter row ---
        ctrl = ctk.CTkFrame(header, fg_color="transparent", corner_radius=0, height=34)
        ctrl.grid(row=1, column=0, sticky="ew")
        ctrl.grid_columnconfigure(0, weight=1)
        ctrl.grid_columnconfigure(1, weight=0)
        ctrl.grid_columnconfigure(2, weight=0)
        ctrl.grid_columnconfigure(3, weight=1)

        range_lbl = ctk.CTkLabel(
            ctrl, text="Rango IP:", font=("Segoe UI", 10, "bold"),
            text_color=pal.text_secondary,
        )
        range_lbl.grid(row=0, column=0, padx=(0, 6), sticky="e")

        self._range_entry = ctk.CTkEntry(
            ctrl, placeholder_text="Ej. 192.168.1.1-100 o 192.168.1.0/24",
            width=260, height=30,
        )
        self._range_entry.grid(row=0, column=1, padx=(0, 10), sticky="w")
        self._range_entry.bind("<Return>", lambda _e: self._on_scan_click())

        filter_lbl = ctk.CTkLabel(
            ctrl, text="Buscar:", font=("Segoe UI", 10, "bold"),
            text_color=pal.text_secondary,
        )
        filter_lbl.grid(row=0, column=2, padx=(10, 6), sticky="e")

        self._filter_entry = ctk.CTkEntry(
            ctrl, placeholder_text="Filtrar por IP, nombre o MACâ€¦",
            width=220, height=30,
        )
        self._filter_entry.grid(row=0, column=3, padx=(0, 6), sticky="w")
        self._filter_entry.bind("<KeyRelease>", self._on_filter_change)

        self._filter_clear_btn = ctk.CTkButton(
            ctrl, text="Ã—", width=28, height=30,
            fg_color="transparent", hover_color=pal.hover,
            text_color=pal.text_muted, font=("Segoe UI", 14, "bold"),
            command=self._clear_filter,
        )
        self._filter_clear_btn.grid(row=0, column=4, padx=(0, 0), sticky="w")

        # ========== Tab view ================================================
        self._tabview = ctk.CTkTabview(self, fg_color=pal.surface)
        self._tabview.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 4))
        self._tabview._segmented_button.configure(font=("Segoe UI", 10, "bold"))

        self._results_tab = self._tabview.add("Lista de resultados")
        self._favs_tab = self._tabview.add("Favoritos")

        # --- Results tab: tree + detail panel ---
        self._results_tab.grid_columnconfigure(0, weight=1)
        self._results_tab.grid_columnconfigure(1, weight=0)
        self._results_tab.grid_rowconfigure(0, weight=1)

        self._tree = DeviceTree(
            self._results_tab, on_select=self._on_device_selected,
            on_open_device=self._open_device_web,
        )
        self._tree.grid(row=0, column=0, sticky="nsew", padx=(6, 0), pady=6)

        self._detail = DetailPanel(self._results_tab)
        self._detail.grid(row=0, column=1, sticky="nsew", padx=(4, 6), pady=6)

        # --- Favorites tab: simple list ---
        self._favs_tab.grid_columnconfigure(0, weight=1)
        self._favs_tab.grid_rowconfigure(0, weight=1)
        self._favs_list = tk.Listbox(
            self._favs_tab, bg=pal.surface, fg=pal.text_primary,
            selectbackground=pal.selection, selectforeground=pal.selection_text,
            borderwidth=0, highlightthickness=0, font=("Segoe UI", 10),
            activestyle="none",
        )
        self._favs_list.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)
        self._favs_list.bind("<Double-1>", self._on_fav_double_click)

        # ========== Status bar ==============================================
        status = ctk.CTkFrame(self, fg_color=pal.surface, corner_radius=0, height=26)
        status.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 8))
        status.grid_propagate(False)
        status.grid_columnconfigure(4, weight=1)

        self._status_label = ctk.CTkLabel(
            status, text="Listo", font=("Segoe UI", 9),
            text_color=pal.text_secondary, anchor="w",
        )
        self._status_label.grid(row=0, column=0, padx=10, sticky="w")

        self._active_label = ctk.CTkLabel(
            status, text="â— 0 activo", font=("Segoe UI", 9),
            text_color=pal.state_ok, anchor="w",
        )
        self._active_label.grid(row=0, column=1, padx=10, sticky="w")

        self._inactive_label = ctk.CTkLabel(
            status, text="â—‹ 0 inactivo", font=("Segoe UI", 9),
            text_color=pal.state_off, anchor="w",
        )
        self._inactive_label.grid(row=0, column=2, padx=10, sticky="w")

        self._unknown_label = ctk.CTkLabel(
            status, text="? 0 desconocido", font=("Segoe UI", 9),
            text_color=pal.text_muted, anchor="w",
        )
        self._unknown_label.grid(row=0, column=3, padx=10, sticky="w")

        self._time_label = ctk.CTkLabel(
            status, text="", font=("Segoe UI", 9),
            text_color=pal.text_muted, anchor="e",
        )
        self._time_label.grid(row=0, column=4, padx=10, sticky="e")

    # -- scanning ------------------------------------------------------------- #
    def _on_scan_click(self) -> None:
        if self._scanning:
            return
        rng = (self._range_entry.get() if self._range_entry else "").strip()
        if not rng:
            hint = local_network_hint()
            self._range_entry.insert(0, hint or "192.168.1.1-100")
            rng = self._range_entry.get().strip()
        self._start_scan(rng)

    def _start_scan(self, target_range: str) -> None:
        self._stop_event.clear()
        self._scanning = True
        self._scan_btn.configure(state="disabled")
        self._pause_btn.configure(state="normal")
        self._stop_btn.configure(state="normal")
        self._status_label.configure(text="Escaneandoâ€¦")

        req = ScanRequest(target_range=target_range)
        self._scan_thread = threading.Thread(
            target=self._run_scan, args=(req,), daemon=True,
        )
        self._scan_thread.start()

    def _run_scan(self, req: ScanRequest) -> None:
        try:
            self._scanner.scan(req, self._stop_event)
        except Exception as exc:  # noqa: BLE001
            logger.exception("scan failed")
            self._queue_put(ScannerEvent(phase="error", message=str(exc), is_error=True))

    def _queue_put(self, event: ScannerEvent) -> None:
        try:
            self._scanner.event_queue.put_nowait(event)
        except Exception:
            pass

    def _on_pause_click(self) -> None:
        # Pausa lÃ³gica: el escÃ¡ner respeta el evento de parada; aquÃ­ simplemente
        # cambiamos el estado visual. Una pausa real requiere soporte en el
        # worker; por ahora usamos "detener" como pausa segura.
        self._on_stop_click()

    def _on_stop_click(self) -> None:
        if not self._scanning:
            return
        self._stop_event.set()
        self._scanning = False
        self._scan_btn.configure(state="normal")
        self._pause_btn.configure(state="disabled")
        self._stop_btn.configure(state="disabled")
        self._status_label.configure(text="Detenido por el usuario")

    def _start_queue_poll(self) -> None:
        self._poll_queue()
        self._tick_clock()

    def _poll_queue(self) -> None:
        try:
            while True:
                ev: ScannerEvent = self._scanner.event_queue.get_nowait()
                self._handle_event(ev)
        except queue.Empty:
            pass
        except Exception:  # noqa: BLE001
            logger.exception("queue drain failed")
        self._paint_job = self.after(POLL_INTERVAL_MS, self._poll_queue)

    def _tick_clock(self) -> None:
        now = datetime.now().strftime("%H:%M:%S")
        if self._time_label:
            self._time_label.configure(text=now)
        self.after(1000, self._tick_clock)

    def _handle_event(self, ev: ScannerEvent) -> None:
        phase = ev.phase
        if phase == "device" and ev.device:
            self._on_device_event(ev.device)
        elif phase == "progress":
            self._status_label.configure(text=ev.message or "Escaneandoâ€¦")
        elif phase == "done":
            self._scan_finished()
        elif phase == "error" or ev.is_error:
            self._scan_error(ev.message or "Error de escaneo")
        elif phase == "cleared":
            self._tree.clear()
            self._status_label.configure(text="Listo")

    def _on_device_event(self, device: Device) -> None:
        self._devices[device.ip_address] = device
        # Throttle repaints so a /23 sweep stays fluid.
        import time
        now = time.time()
        if now - self._last_paint > 0.25:
            self._last_paint = now
            self._refresh_tree()
        else:
            if self._paint_job is None:
                self._paint_job = self.after(50, self._refresh_tree)

    def _refresh_tree(self) -> None:
        self._paint_job = None
        # Apply filter
        flt = (self._filter_entry.get() if self._filter_entry else "").strip().lower()
        if flt:
            shown = {ip: d for ip, d in self._devices.items()
                     if flt in ip.lower() or flt in (d.hostname or "").lower()
                     or flt in (d.mac_address or "").lower()
                     or flt in (d.vendor or "").lower()}
        else:
            shown = self._devices
        self._tree.set_devices(shown)
        self._update_status_bar()
        # Refresh detail panel if its device is still present.
        if self._detail and self._detail._device:
            ip = self._detail._device.ip_address
            if ip in self._devices:
                self._detail.set_device(self._devices[ip])

    def _update_status_bar(self) -> None:
        active = sum(1 for d in self._devices.values() if d.is_alive)
        inactive = sum(1 for d in self._devices.values() if not d.is_alive)
        unknown = len(self._devices) - active - inactive
        total = len(self._devices)
        if self._active_label:
            self._active_label.configure(text=f"â— {active} activo")
        if self._inactive_label:
            self._inactive_label.configure(text=f"â—‹ {inactive} inactivo")
        if self._unknown_label:
            self._unknown_label.configure(text=f"? {unknown} desconocido")
        if self._status_label and not self._scanning:
            self._status_label.configure(
                text=f"{total} dispositivo{'s' if total != 1 else ''}")

    # -- device selection / detail ------------------------------------------ #
    def _on_device_selected(self, ip: str) -> None:
        dev = self._devices.get(ip)
        if dev:
            self._detail.set_device(dev)
        # Fill services under the row once so they are visible.
        if self._tree:
            self._tree._fill_services(ip)

    def _open_device_web(self, ip: str) -> None:
        dev = self._devices.get(ip)
        if not dev:
            return
        port = best_web_port(dev)
        if port:
            open_web(dev.ip_address, port)
        else:
            messagebox.showinfo(
                "Sin puerto web",
                f"El dispositivo {ip} no tiene ningÃºn puerto web detectado.",
            )

    def _toggle_detail(self) -> None:
        if self._detail:
            self._detail.toggle()
            self._detail_panel_visible = self._detail._expanded

    # -- filter --------------------------------------------------------------- #
    def _on_filter_change(self, _event=None) -> None:
        # Debounce lightly: repaint on next poll cycle.
        self._refresh_tree()

    def _clear_filter(self) -> None:
        if self._filter_entry:
            self._filter_entry.delete(0, tk.END)
        self._refresh_tree()

    # -- favorites ------------------------------------------------------------ #
    def _on_fav_double_click(self, event) -> None:
        sel = self._favs_list.curselection()
        if not sel:
            return
        ip = self._favs_list.get(sel[0])
        if self._tree:
            self._tree._tree.selection_set(f"dev:{ip}")
            self._tree._tree.see(f"dev:{ip}")
            self._on_device_selected(ip)

    def _scan_finished(self) -> None:
        self._scanning = False
        self._scan_btn.configure(state="normal")
        self._pause_btn.configure(state="disabled")
        self._stop_btn.configure(state="disabled")
        self._refresh_tree()
        self._status_label.configure(text="Terminado")

    def _scan_error(self, message: str) -> None:
        self._scanning = False
        self._scan_btn.configure(state="normal")
        self._pause_btn.configure(state="disabled")
        self._stop_btn.configure(state="disabled")
        self._status_label.configure(text="Error")
        messagebox.showerror("Error de escaneo", message)

    # -- actions / menu ------------------------------------------------------- #
    def _export_csv(self) -> None:
        if not self._devices:
            messagebox.showwarning("Sin datos", "No hay dispositivos para exportar.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            title="Exportar lista de dispositivos",
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["Estado", "Nombre", "IP", "Fabricante", "DirecciÃ³n MAC", "Puertos"])
                for d in self._devices.values():
                    w.writerow([
                        "Activo" if d.is_alive else "Inactivo",
                        d.hostname or "-",
                        d.ip_address,
                        d.vendor_label,
                        d.mac_address or "-",
                        d.ports_compact(),
                    ])
            messagebox.showinfo("Exportado", f"Lista guardada en {path}")
        except Exception as exc:  # noqa: BLE001
            logger.exception("export failed")
            messagebox.showerror("Error", str(exc))

    def _open_prefs(self) -> None:
        messagebox.showinfo("Preferencias", "Las preferencias se abren aquÃ­ en la prÃ³xima versiÃ³n.")

    def _show_adapters(self) -> None:
        try:
            adapters = list_adapters()
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Error", str(exc))
            return
        lines = [f"{a.name} â€” {a.address} ({a.network})" for a in adapters]
        messagebox.showinfo("Adaptadores de red", "\n".join(lines) or "No se encontraron adaptadores.")

    def _show_about(self) -> None:
        messagebox.showinfo(
            "Acerca de",
            f"{APP_NAME}\nPor {APP_AUTHOR}\nEstilo Advanced IP Scanner\nCustomTkinter",
        )

    def _show_help(self) -> None:
        messagebox.showinfo(
            "Ayuda",
            "1. Escribe un rango IP (ej. 192.168.1.1-100 o 192.168.1.0/24).\n"
            "2. Pulsa Explorar (â–¶).\n"
            "3. Espera a Â«TerminadoÂ» (un /23 puede tardar ~60 s).\n"
            "4. Expande un dispositivo para ver sus servicios.\n"
            "5. Usa el panel Detalle para ver la ficha completa.",
        )

    # -- lifecycle ------------------------------------------------------------ #
    def destroy(self) -> None:
        self._stop_event.set()
        self._scanning = False
        super().destroy()



def launch() -> None:
    """Create the main window and start the tkinter event loop."""
    app = IPInspectorApp()
    app.mainloop()


if __name__ == "__main__":
    launch()