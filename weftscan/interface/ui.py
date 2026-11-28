"""
Main window of WeftScan, built on native Windows controls (ttk).

Layout
------
* Menu bar:   File · Edit · View · Actions · Tools · Settings · Help
* Toolbar:    Scan / Stop, address range (with history), adapter, profile,
              Options, Search
* Options:    collapsible strip (F8): ports, timeout, threads, name
              resolution, model identification, auto-rescan, open-ports filter
* Tabs:       Results (grid + property panel) · Favorites · Tools · Monitor
* Status bar: message · summary · progress · privilege mode

Threading model
---------------
Every long operation runs on a worker thread that pushes results onto a
``queue.Queue``. The main thread drains it with ``after()`` — the only safe
way to update tkinter from another thread. The scan worker always finishes
by posting :data:`WORKER_DONE`, even when the engine raises, so the buttons
can never stay stuck in the "scanning" state. Other workers (shared-folder
lookups) hand callables to :meth:`ScannerApp._call_soon`.

Event contract
--------------
The phase names below are the ones :class:`NetworkScanner` emits;
``tests/test_ui.py`` pins this contract.
"""

from __future__ import annotations

import ctypes
import ipaddress
import logging
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from .. import i18n
from ..actions.exporter import export as export_devices
from ..actions.exporter import load_json
from ..actions.menu import (
    best_web_port,
    open_ftp,
    open_remote_desktop,
    open_web,
    remote_power,
    wake_device,
)
from ..analysis.exposure import exposure_findings, exposure_score
from ..core.models import Device, ScannerEvent
from ..core.network import NetworkScanner
from ..core.utils import (
    default_gateway,
    is_elevated,
    list_adapters,
    local_network_hint,
    plan_targets,
)
from ..nettools import tools as nettools
from ..nettools.profiles import CUSTOM, PROFILES, get_profile, parse_ports
from . import theme
from .monitor_tab import MonitorTab
from .settings import Settings
from .tools_tab import ToolsTab
from .widgets import (
    TREE_COLUMNS,
    AddressMap,
    CheckBox,
    DetailsPanel,
    DeviceTree,
    ViewStack,
    device_key,
    device_row,
    ip_key,
    matches_filter,
    open_ports,
    range_addresses,
    scrolled,
)

logger = logging.getLogger(__name__)

__all__ = [
    "APP_NAME", "APP_AUTHOR", "ScannerApp", "launch",
    "TREE_COLUMNS", "device_row", "matches_filter",
]

APP_NAME = "WeftScan"
APP_AUTHOR = "Matthew Garay"
APP_VERSION = "2.1"

WINDOW_SIZE = (1280, 760)
WINDOW_MINIMUM = (900, 520)
POLL_INTERVAL_MS = 100
#: How often the window checks whether the computer moved to another network.
NETWORK_CHECK_MS = 15000

#: Events processed per poll, so a burst never freezes the window.
MAX_EVENTS_PER_POLL = 400

#: Phases emitted by :class:`NetworkScanner` (see ``core/network.py``).
PHASE_DEVICE = "Device"
PHASE_FINISHED = "Finished"
PHASE_CANCELLED = "Cancelled"
PHASE_ERROR = "Error"
PROGRESS_PHASES = ("Discovery", "Ports", "Models", "Fingerprint")

#: Posted by the UI's own worker wrapper once the scan thread has exited.
WORKER_DONE = "_worker_done"

PHASE_TEXT = {
    "Discovery": "Discovering hosts",
    "Ports": "Scanning ports",
    "Models": "Identifying devices",
    "Fingerprint": "Fingerprinting operating systems",
}

TIMEOUTS = ("0.2", "0.3", "0.5", "1.0", "2.0")
THREADS = ("100", "250", "500", "1000", "1500", "2000")
AUTO_ADAPTER = "Automatic"
#: Auto-rescan choices shown in the options strip -> minutes (0 = off).
AUTO_RESCAN = {"Off": 0, "5 min": 5, "15 min": 15, "30 min": 30, "60 min": 60}

TAB_SCANNER = "Devices"
TAB_FAVORITES = "Favorites"
TAB_TOOLS = "Tools"
TAB_MONITOR = "Monitor"

SMB_PORTS = {139, 445}
WINDOWS_PORTS = {135, 139, 445, 3389}


class ScannerApp(tk.Tk):
    """Main window."""

    def __init__(self, settings: Settings | None = None) -> None:
        super().__init__()
        self.withdraw()
        self.title(APP_NAME)
        self.settings = settings if settings is not None else Settings.load()
        i18n.initialize()
        i18n.set_language("en")
        theme.setup_style(self)
        self.icons = theme.Icons()
        self._set_window_icon()
        self._restore_geometry()
        self.minsize(*WINDOW_MINIMUM)

        self._events: queue.Queue[ScannerEvent] = queue.Queue()
        self._calls: queue.Queue[Callable[[], None]] = queue.Queue()
        self._scanner = NetworkScanner(event_queue=self._events)
        self._devices: dict[str, Device] = {}
        self._new_devices: set[str] = set()
        self._elevated = is_elevated()
        self._adapters = [a for a in self._safe_adapters() if a.is_scannable]

        self._scanning = False
        self._scan_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._scan_started = 0.0
        self._last_range = ""
        self._last_profile = ""
        self._partial = False
        self._outcome = ""
        self._after_jobs: list[str] = []
        self._options_visible = False
        #: Devices of the previous scan of this range that did not answer now.
        self._gone: list[dict] = []
        self._auto_job: str | None = None
        self._auto_due = 0.0
        self._auto_run = False
        #: Shared-folder lookups already done (or running) per IP.
        self._shares_requested: set[str] = set()
        #: Range detected from this computer's own network, and whether the
        #: range box still shows it (typing a range turns auto mode off).
        self._detected_range = ""
        self._range_is_auto = True
        self._detecting = False

        self._build_menu_bar()
        self._build_layout()
        self._load_options()
        self._refresh_favorites()
        self._update_summary()
        self._tree.set_empty_message(
            "No results yet.\nPress Scan (F5) to look for devices on your network.")
        self._set_status("Ready")
        self._schedule(POLL_INTERVAL_MS, self._poll_queue)
        self._detect_network()
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.deiconify()
        if self.settings.window_zoomed:
            try:
                self.state("zoomed")
            except tk.TclError:
                pass

    # ------------------------------------------------------------------ #
    # Window helpers
    # ------------------------------------------------------------------ #
    def _restore_geometry(self) -> None:
        geometry = self.settings.window_geometry
        if geometry:
            try:
                size, _, position = geometry.partition("+")
                width, height = (int(v) for v in size.split("x"))
                x, y = (int(v) for v in position.split("+"))
                sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
                if 0 <= x < sw - 100 and 0 <= y < sh - 100 and width >= WINDOW_MINIMUM[0]:
                    self.geometry(geometry)
                    return
            except ValueError:
                pass
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w = max(min(theme.px(WINDOW_SIZE[0]), sw - 40), WINDOW_MINIMUM[0])
        h = max(min(theme.px(WINDOW_SIZE[1]), sh - 80), WINDOW_MINIMUM[1])
        self.geometry(f"{w}x{h}+{max(0, (sw - w) // 2)}+{max(0, (sh - h) // 3)}")

    def _set_window_icon(self) -> None:
        here = Path(__file__).resolve().parents[1]
        for folder in (here / "assets", Path(getattr(sys, "_MEIPASS", here)) / "assets"):
            icon = folder / "icon.png"
            if icon.is_file():
                try:
                    self._icon_image = tk.PhotoImage(file=str(icon))
                    self.iconphoto(True, self._icon_image)
                except tk.TclError:
                    pass
                return

    def _schedule(self, ms: int, callback) -> None:
        self._after_jobs.append(self.after(ms, callback))
        if len(self._after_jobs) > 32:
            self._after_jobs = self._after_jobs[-8:]

    def _call_soon(self, callback: Callable[[], None]) -> None:
        """Run ``callback`` on the UI thread (safe to call from any thread)."""
        self._calls.put(callback)

    @staticmethod
    def _safe_adapters():
        try:
            return list_adapters()
        except Exception:  # noqa: BLE001 - adapters are a convenience
            logger.warning("Could not list adapters", exc_info=True)
            return []

    def _set_status(self, text: str) -> None:
        self._status_label.configure(text=text)

    # ------------------------------------------------------------------ #
    # Menu bar
    # ------------------------------------------------------------------ #
    def _build_menu_bar(self) -> None:
        bar = tk.Menu(self)
        self.config(menu=bar)

        m_file = tk.Menu(bar, tearoff=0)
        m_file.add_command(label="Scan", accelerator="F5", command=self._on_scan_click)
        m_file.add_command(label="Stop", accelerator="Esc", command=self._on_stop_click)
        m_file.add_separator()
        m_file.add_command(label="Open results…", accelerator="Ctrl+O",
                           command=self._open_results)
        m_file.add_command(label="Save results as…", accelerator="Ctrl+S",
                           command=self._export)
        m_file.add_command(label="Security report…", accelerator="Ctrl+P",
                           command=self._report)
        m_file.add_separator()
        m_file.add_command(label="Exit", command=self.destroy)
        bar.add_cascade(label="File", menu=m_file)

        m_edit = tk.Menu(bar, tearoff=0)
        m_edit.add_command(label="Copy", accelerator="Ctrl+C", command=self._copy_selected)
        m_edit.add_command(label="Select all", accelerator="Ctrl+A", command=self._select_all)
        m_edit.add_separator()
        m_edit.add_command(label="Find…", accelerator="Ctrl+F", command=self._focus_filter)
        m_edit.add_command(label="Rename…", accelerator="F2", command=self._rename_selected)
        bar.add_cascade(label="Edit", menu=m_edit)

        m_view = tk.Menu(bar, tearoff=0)
        self._props_var = tk.BooleanVar(self, value=self.settings.show_properties)
        m_view.add_checkbutton(label="Details panel", accelerator="F9",
                               variable=self._props_var, command=self._apply_props_visibility)
        self._options_var = tk.BooleanVar(self, value=False)
        m_view.add_checkbutton(label="Scan options", accelerator="F8",
                               variable=self._options_var,
                               command=lambda: self._toggle_options(self._options_var.get()))
        self._view_menu = m_view
        m_view.add_separator()
        m_view.add_command(label="Expand all", command=lambda: self._tree.expand_all(True))
        m_view.add_command(label="Collapse all", command=lambda: self._tree.expand_all(False))
        m_view.add_separator()
        m_view.add_command(label="Changes since last scan…", accelerator="Ctrl+D",
                           command=self._show_changes)
        bar.add_cascade(label="View", menu=m_view)

        self._actions_menu = tk.Menu(bar, tearoff=0, postcommand=self._fill_actions_menu)
        bar.add_cascade(label="Actions", menu=self._actions_menu)

        m_tools = tk.Menu(bar, tearoff=0)
        for label, tool, values in (
            ("Ping default gateway", "Ping", lambda: {"host": default_gateway()}),
            ("Traceroute to the Internet", "Traceroute", lambda: {"host": "8.8.8.8"}),
            ("ARP table", "ARP table", dict),
            ("Network adapters", "Network adapters", dict),
            ("Listening ports on this PC", "Listening ports", dict),
        ):
            m_tools.add_command(label=label,
                                command=lambda t=tool, v=values: self._open_tool(t, v(), run=True))
        m_tools.add_separator()
        m_tools.add_command(label="All tools", accelerator="Ctrl+T",
                            command=lambda: self._tabview.set(TAB_TOOLS))
        m_tools.add_command(label="Monitor", accelerator="Ctrl+M",
                            command=lambda: self._tabview.set(TAB_MONITOR))
        bar.add_cascade(label="Tools", menu=m_tools)

        m_cfg = tk.Menu(bar, tearoff=0)
        m_cfg.add_command(label="Detect my network range", command=self._use_local_network)
        m_cfg.add_command(label="Clear address history", command=self._clear_history)
        m_cfg.add_command(label="Forget known devices", command=self._forget_known)
        if sys.platform == "win32" and not self._elevated:
            m_cfg.add_separator()
            m_cfg.add_command(label="Restart as administrator", command=self._restart_elevated)
        bar.add_cascade(label="Settings", menu=m_cfg)

        m_help = tk.Menu(bar, tearoff=0)
        m_help.add_command(label="Quick guide", accelerator="F1", command=self._show_help)
        m_help.add_command(label=f"About {APP_NAME}", command=self._show_about)
        bar.add_cascade(label="Help", menu=m_help)

        for key, action in (
            ("<F5>", self._on_scan_click), ("<Escape>", self._on_stop_click),
            ("<Control-s>", self._export), ("<Control-p>", self._report),
            ("<Control-o>", self._open_results),
            ("<Control-r>", self._rescan_selected), ("<F1>", self._show_help),
            ("<F8>", lambda: self._toggle_options(not self._options_visible)),
            ("<F9>", self._toggle_detail),
            ("<Control-f>", self._focus_filter),
            ("<Control-d>", self._show_changes),
            ("<F2>", self._rename_selected),
            ("<Control-t>", lambda: self._tabview.set(TAB_TOOLS)),
            ("<Control-m>", lambda: self._tabview.set(TAB_MONITOR)),
        ):
            self.bind(key, lambda _e, a=action: a())

        self._context = tk.Menu(self, tearoff=0)

    # ------------------------------------------------------------------ #
    # Device menus (context menu and the Actions menu share one builder)
    # ------------------------------------------------------------------ #
    def _fill_actions_menu(self) -> None:
        menu = self._actions_menu
        menu.delete(0, tk.END)
        ips = self._tree.get_selected_ips()
        if not ips:
            menu.add_command(label="Select a device first", state="disabled")
            return
        self._fill_device_menu(menu, ips)

    def _show_context(self, ip: str, x: int, y: int) -> None:
        ips = self._tree.get_selected_ips() or [ip]
        if ip not in ips:
            ips = [ip]
        self._context.delete(0, tk.END)
        self._fill_device_menu(self._context, ips)
        try:
            self._context.tk_popup(x, y)
        finally:
            self._context.grab_release()

    def _fill_device_menu(self, menu: tk.Menu, ips: list[str]) -> None:
        """Commands for one device, or bulk commands for several."""
        devices = [self._devices[ip] for ip in ips if ip in self._devices]
        if not devices:
            return
        if len(devices) > 1:
            count = len(devices)
            menu.add_command(label=f"Rescan {count} devices",
                             command=lambda: self._rescan_hosts([d.ip_address for d in devices]))
            menu.add_command(label=f"Wake-on-LAN ({count})",
                             command=lambda: [self._wake(d.ip_address) for d in devices])
            menu.add_command(label=f"Add {count} to monitor",
                             command=lambda: [self._monitor_host(d.ip_address) for d in devices])
            menu.add_command(label=f"Add {count} to favorites",
                             command=lambda: self._add_favorites([d.ip_address for d in devices]))
            menu.add_separator()
            menu.add_command(label=f"Copy {count} rows", accelerator="Ctrl+C",
                             command=self._copy_selected)
            menu.add_command(label="Copy IP addresses",
                             command=lambda: self._copy("\n".join(d.ip_address for d in devices)))
            return

        dev = devices[0]
        ip = dev.ip_address
        ports = {p.number for p in open_ports(dev)}
        web = best_web_port(dev)

        def state(enabled: bool) -> str:
            return "normal" if enabled else "disabled"

        m_open = tk.Menu(menu, tearoff=0)
        m_open.add_command(label="HTTP", state=state(bool(ports & {80, 8000, 8080, 5000})),
                           command=lambda: open_web(ip, next(p for p in (80, 8080, 8000, 5000)
                                                            if p in ports)))
        m_open.add_command(label="HTTPS", state=state(bool(ports & {443, 8443})),
                           command=lambda: open_web(ip, 443 if 443 in ports else 8443))
        m_open.add_command(label="FTP", state=state(21 in ports), command=lambda: open_ftp(ip))
        m_open.add_separator()
        m_open.add_command(label="Remote Desktop (RDP)", state=state(3389 in ports),
                           command=lambda: self._open_rdp(ip))
        m_open.add_command(label="SSH", state=state(22 in ports),
                           command=lambda: self._open_ssh(ip))
        m_open.add_command(label="Shared folders", state=state(bool(ports & SMB_PORTS)),
                           command=lambda: self._open_shares(ip))
        menu.add_command(label="Open", accelerator="Enter", state=state(bool(web)),
                         command=lambda: self._open_device_web(ip))
        menu.add_cascade(label="Open with", menu=m_open)
        menu.add_separator()

        menu.add_command(label="Rescan", accelerator="Ctrl+R",
                         command=lambda: self._rescan_host(ip))
        menu.add_command(label="Scan its subnet (/24)", command=lambda: self._scan_subnet(ip))
        m_tools = tk.Menu(menu, tearoff=0)
        m_tools.add_command(label="Ping", command=lambda: self._open_tool(
            "Ping", {"host": ip}, run=True))
        m_tools.add_command(label="Traceroute", command=lambda: self._open_tool(
            "Traceroute", {"host": ip}, run=True))
        m_tools.add_command(label="All ports (1-65535)", command=lambda: self._open_tool(
            "Port check", {"host": ip, "ports": "1-65535", "timeout": "0.3"}, run=True))
        m_tools.add_command(label="Shared folders", state=state(bool(ports & SMB_PORTS)),
                            command=lambda: self._open_tool(
                                "Shared folders", {"host": ip}, run=True))
        m_tools.add_command(label="TLS certificate", state=state(bool(ports & {443, 8443})),
                            command=lambda: self._open_tool(
                                "TLS certificate",
                                {"host": ip, "port": "443" if 443 in ports else "8443"},
                                run=True))
        m_tools.add_command(label="HTTP security headers", state=state(bool(web)),
                            command=lambda: self._open_tool(
                                "HTTP headers",
                                {"url": f"{'https' if web in (443, 8443) else 'http'}://{ip}"
                                        + ("" if web in (80, 443) else f":{web}")},
                                run=True))
        menu.add_cascade(label="Tools", menu=m_tools)
        menu.add_command(label="Add to monitor", command=lambda: self._monitor_host(ip))

        m_power = tk.Menu(menu, tearoff=0)
        windows = sys.platform == "win32" and bool(ports & WINDOWS_PORTS)
        m_power.add_command(label="Wake-on-LAN", state=state(bool(dev.mac_address)),
                            command=lambda: self._wake(ip))
        m_power.add_separator()
        m_power.add_command(label="Shut down…", state=state(windows),
                            command=lambda: self._power(ip, "shutdown"))
        m_power.add_command(label="Restart…", state=state(windows),
                            command=lambda: self._power(ip, "restart"))
        m_power.add_command(label="Cancel shutdown", state=state(windows),
                            command=lambda: self._power(ip, "abort"))
        menu.add_cascade(label="Power", menu=m_power)
        menu.add_separator()

        menu.add_command(label="Rename…", accelerator="F2", command=lambda: self._edit_label(ip))
        menu.add_command(label="Remove from favorites" if ip in self._favorites
                         else "Add to favorites", command=lambda: self._toggle_favorite(ip))
        m_copy = tk.Menu(menu, tearoff=0)
        m_copy.add_command(label="Row", accelerator="Ctrl+C", command=self._copy_selected)
        m_copy.add_command(label="IP address", command=lambda: self._copy(ip))
        m_copy.add_command(label="MAC address", state=state(bool(dev.mac_address)),
                           command=lambda: self._copy(dev.mac_address or ""))
        m_copy.add_command(label="Name", command=lambda: self._copy(
            device_row(dev, self._label_for(dev).get("name", ""))[0]))
        menu.add_cascade(label="Copy", menu=m_copy)

    # ------------------------------------------------------------------ #
    # Layout
    # ------------------------------------------------------------------ #
    def _build_layout(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
        self._build_toolbar()
        ttk.Frame(self, style="Rule.TFrame", height=1).grid(row=1, column=0, sticky="ew")
        self._build_options()

        body = ttk.Frame(self)
        body.grid(row=3, column=0, sticky="nsew")
        body.columnconfigure(2, weight=1)
        body.rowconfigure(0, weight=1)
        views = ttk.Frame(body, style="Paper.TFrame")
        views.grid(row=0, column=2, sticky="nsew")
        views.columnconfigure(0, weight=1)
        views.rowconfigure(0, weight=1)
        self._tabview = ViewStack(body, views, self.icons)
        self._tabview.rail.grid(row=0, column=0, sticky="ns")
        ttk.Frame(body, style="Rule.TFrame", width=1).grid(row=0, column=1, sticky="ns")

        devices_view = self._tabview.add_tab(TAB_SCANNER, "nav_devices")
        favs_view = self._tabview.add_tab(TAB_FAVORITES, "nav_favorites")
        tools_view = self._tabview.add_tab(TAB_TOOLS, "nav_tools")
        monitor_view = self._tabview.add_tab(TAB_MONITOR, "nav_monitor")
        self._tabview.set(TAB_SCANNER)

        self._build_devices_view(devices_view)
        self._build_favorites_tab(favs_view)

        pad = theme.px(16)
        self._tools = ToolsTab(tools_view, on_status=self._set_status)
        self._tools.pack(fill="both", expand=True, padx=pad, pady=(pad, theme.px(10)))
        self._monitor = MonitorTab(monitor_view, self.icons, on_status=self._set_status)
        self._monitor.pack(fill="both", expand=True, padx=pad, pady=(pad, theme.px(10)))

        ttk.Frame(self, style="Rule.TFrame", height=1).grid(row=4, column=0, sticky="ew")
        self._build_status_bar()

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self, style="Paper.TFrame", padding=(theme.px(12), theme.px(8)))
        bar.grid(row=0, column=0, sticky="ew")

        ttk.Label(bar, image=self.icons.ui("app", self.icons.row_size), style="Paper.TLabel"
                  ).pack(side="left")
        ttk.Label(bar, text=APP_NAME, style="Brand.TLabel").pack(side="left",
                                                                 padx=(theme.px(8), 0))
        ttk.Frame(bar, style="Rule.TFrame", width=1).pack(side="left", fill="y",
                                                          padx=theme.px(14))

        # Packed before the left-hand controls so it keeps its room when the
        # window is narrow; the combo boxes shrink instead.
        self._filter_entry = ttk.Entry(bar, width=16)
        self._filter_entry.pack(side="right")
        self._filter_entry.bind("<KeyRelease>", lambda _e: self._apply_filter())
        self._filter_entry.bind("<Escape>", lambda _e: self._clear_filter())
        ttk.Label(bar, text="Search", style="Secondary.TLabel").pack(
            side="right", padx=(theme.px(12), theme.px(6)))

        self._scan_btn = ttk.Button(bar, text="Scan", style="Accent.TButton",
                                    command=self._on_scan_click, width=9)
        self._scan_btn.pack(side="left")
        self._stop_btn = ttk.Button(bar, text="Stop", command=self._on_stop_click,
                                    state="disabled", width=7)
        self._stop_btn.pack(side="left", padx=(theme.px(6), theme.px(14)))

        ttk.Label(bar, text="Range", style="Secondary.TLabel").pack(side="left")
        self._range_entry = ttk.Combobox(bar, width=19, values=self.settings.range_history)
        self._range_entry.pack(side="left", padx=(theme.px(6), theme.px(6)))
        self._range_entry.bind("<Return>", lambda _e: self._on_scan_click())
        self._range_entry.bind("<KeyRelease>", self._on_range_typed)
        self._range_entry.bind("<<ComboboxSelected>>", lambda _e: self._on_range_typed())
        self._range_info = ttk.Label(bar, text="", width=21, style="PaperMuted.TLabel")
        self._range_info.pack(side="left")

        ttk.Label(bar, text="Profile", style="Secondary.TLabel").pack(side="left",
                                                                      padx=(theme.px(6), 0))
        self._profile_menu = ttk.Combobox(bar, values=[p.name for p in PROFILES], width=15,
                                          state="readonly")
        self._profile_menu.pack(side="left", padx=(theme.px(6), theme.px(6)))
        self._profile_menu.bind("<<ComboboxSelected>>", lambda _e: self._on_profile_change())
        self._options_btn = ttk.Button(bar, text="Options", image=self.icons.options,
                                       compound="left",
                                       command=lambda: self._toggle_options(
                                           not self._options_visible))
        self._options_btn.pack(side="left")

    def _build_options(self) -> None:
        pad = theme.px(12)
        self._options_frame = ttk.Frame(self, style="Paper.TFrame",
                                        padding=(pad, theme.px(4), pad, theme.px(10)))
        self._options_frame.grid(row=2, column=0, sticky="ew")
        row = ttk.Frame(self._options_frame, style="Paper.TFrame")
        row.pack(fill="x")

        def caption(text: str, first: bool = False) -> None:
            ttk.Label(row, text=text, style="Secondary.TLabel").pack(
                side="left", padx=(0 if first else theme.px(14), theme.px(6)))

        caption("Adapter", first=True)
        adapter_names = [AUTO_ADAPTER] + [f"{a.name} ({a.sweep_range})" for a in self._adapters]
        self._adapter_menu = ttk.Combobox(row, values=adapter_names, width=26, state="readonly")
        self._adapter_menu.set(AUTO_ADAPTER)
        self._adapter_menu.pack(side="left")
        self._adapter_menu.bind("<<ComboboxSelected>>",
                                lambda _e: self._on_adapter_change(self._adapter_menu.get()))
        caption("Ports")
        self._ports_entry = ttk.Entry(row, width=30)
        self._ports_entry.pack(side="left")
        self._ports_entry.bind("<KeyRelease>", lambda _e: self._preview_range())
        caption("Timeout (s)")
        self._timeout_menu = ttk.Combobox(row, values=list(TIMEOUTS), width=5, state="readonly")
        self._timeout_menu.pack(side="left")
        caption("Threads")
        self._threads_menu = ttk.Combobox(row, values=list(THREADS), width=6, state="readonly")
        self._threads_menu.pack(side="left")
        caption("Rescan every")
        self._auto_menu = ttk.Combobox(row, values=list(AUTO_RESCAN), width=7, state="readonly")
        self._auto_menu.pack(side="left")
        self._auto_menu.bind("<<ComboboxSelected>>", lambda _e: self._on_auto_change())

        row2 = ttk.Frame(self._options_frame, style="Paper.TFrame")
        row2.pack(fill="x", pady=(theme.px(8), 0))
        self._resolve_chk = CheckBox(row2, text="Resolve host names")
        self._resolve_chk.pack(side="left")
        self._identify_chk = CheckBox(row2, text="Identify device models")
        self._identify_chk.pack(side="left", padx=(theme.px(18), 0))
        self._profile_info = ttk.Label(row2, text="", style="PaperMuted.TLabel")
        self._profile_info.pack(side="left", padx=(theme.px(18), 0))
        self._options_frame.grid_remove()

    def _build_devices_view(self, view) -> None:
        pad = theme.px(16)
        view.columnconfigure(0, weight=1)
        view.rowconfigure(3, weight=1)

        header = ttk.Frame(view, style="Paper.TFrame", padding=(pad, pad, pad, 0))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="Devices", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        self._summary_label = ttk.Label(header, text="", style="Secondary.TLabel")
        self._summary_label.grid(row=1, column=0, sticky="w", pady=(theme.px(2), 0))
        actions = ttk.Frame(header, style="Paper.TFrame")
        actions.grid(row=0, column=1, rowspan=2, sticky="e")
        self._only_open_chk = CheckBox(actions, text="Only hosts with open ports",
                                       command=self._apply_filter)
        self._only_open_chk.pack(side="left", padx=(0, theme.px(14)))
        self._export_btn = ttk.Button(actions, text="Export", image=self.icons.export,
                                      compound="left", command=self._export)
        self._export_btn.pack(side="left")
        self._report_btn = ttk.Button(actions, text="Report", image=self.icons.report,
                                      compound="left", command=self._report)
        self._report_btn.pack(side="left", padx=(theme.px(6), 0))

        mapping = ttk.Frame(view, style="Paper.TFrame", padding=(pad, theme.px(14), pad, 0))
        mapping.grid(row=1, column=0, sticky="ew")
        mapping.columnconfigure(0, weight=1)
        self._map = AddressMap(mapping, on_select=self._select_from_map,
                               on_hover=self._map_hover)
        self._map.grid(row=0, column=0, sticky="ew")
        self._map_caption = ttk.Label(mapping, text="", style="PaperMuted.TLabel")
        self._map_caption.grid(row=1, column=0, sticky="w", pady=(theme.px(4), 0))

        ttk.Frame(view, style="Paper.TFrame", height=theme.px(10)).grid(row=2, column=0)
        self._paned = ttk.Panedwindow(view, orient="horizontal")
        self._paned.grid(row=3, column=0, sticky="nsew", padx=(pad, 0))
        self._tree = DeviceTree(self._paned, self.icons,
                                on_select=self._on_device_selected,
                                on_open_device=self._open_device_web,
                                on_context=self._show_context,
                                on_expand=self._on_device_expand,
                                on_open_share=self._open_share)
        self._paned.add(self._tree, weight=3)
        self._detail = DetailsPanel(self._paned, self.icons, actions={
            "open": lambda: self._detail.device and self._open_device_web(
                self._detail.device.ip_address),
            "rename": lambda: self._detail.device and self._edit_label(
                self._detail.device.ip_address),
            "rescan": lambda: self._detail.device and self._rescan_host(
                self._detail.device.ip_address),
        })
        if self.settings.show_properties:
            self._paned.add(self._detail, weight=1)
            self.after(250, self._place_sash)
        self._tree.bind_all("<Control-c>", self._on_ctrl_c, add="+")

    def _build_favorites_tab(self, view) -> None:
        pad = theme.px(16)
        view.columnconfigure(0, weight=1)
        view.rowconfigure(2, weight=1)
        ttk.Label(view, text="Favorites", style="Title.TLabel").grid(
            row=0, column=0, sticky="w", padx=pad, pady=(pad, 0))
        ttk.Label(view, text="Pin devices you check often. Right-click a device and choose "
                             "Add to favorites; double-click a favorite to find it.",
                  style="Secondary.TLabel").grid(row=1, column=0, sticky="w", padx=pad,
                                                 pady=(theme.px(2), theme.px(12)))
        frame, self._favs_list = scrolled(view, lambda parent: ttk.Treeview(
            parent, columns=("name", "ip", "type", "state"), show="tree headings",
            style="Results.Treeview", selectmode="browse"))
        frame.grid(row=2, column=0, sticky="nsew", padx=pad, pady=(0, pad))
        self._favs_list.column("#0", width=theme.px(44), stretch=False)
        for column, heading, width in (("name", "Name", 220), ("ip", "IP address", 120),
                                       ("type", "Type", 130), ("state", "Status", 220)):
            self._favs_list.heading(column, text=heading, anchor="w")
            self._favs_list.column(column, width=theme.px(width), anchor="w")
        self._favs_list.tag_configure("away", foreground=theme.PALETTE.ink_3)
        self._favs_list.bind("<Double-1>", self._on_fav_double_click)
        self._favs_list.bind("<Return>", self._on_fav_double_click)
        self._favs_list.bind("<Delete>", self._on_fav_delete)

    def _build_status_bar(self) -> None:
        status = ttk.Frame(self, style="Chrome.TFrame", padding=(theme.px(4), 0))
        status.grid(row=5, column=0, sticky="ew")
        status.columnconfigure(0, weight=1)
        self._status_label = ttk.Label(status, text="", style="Status.TLabel")
        self._status_label.grid(row=0, column=0, sticky="ew")
        self._progress = ttk.Progressbar(status, length=theme.px(180), mode="determinate",
                                         style="Accent.Horizontal.TProgressbar")
        self._progress.grid(row=0, column=1, padx=(theme.px(8), theme.px(8)))
        self._progress.grid_remove()
        self._priv_label = ttk.Label(
            status, style="Status.TLabel",
            text="Administrator" if self._elevated
            else "Limited mode: run as administrator for complete results")
        self._priv_label.grid(row=0, column=2, sticky="e")

    def _place_sash(self) -> None:
        """Start the details panel at a readable width."""
        try:
            self.update_idletasks()
            width = self._paned.winfo_width()
            if width > theme.px(700) and len(self._paned.panes()) > 1:
                self._paned.sashpos(0, width - theme.px(380))
        except tk.TclError:
            pass

    def _apply_props_visibility(self) -> None:
        show = self._props_var.get()
        panes = self._paned.panes()
        if show and str(self._detail) not in panes:
            self._paned.add(self._detail, weight=1)
            self.after(250, self._place_sash)
        elif not show and str(self._detail) in panes:
            self._paned.forget(self._detail)
        self.settings.show_properties = show

    # -- address map ------------------------------------------------------- #
    def _reset_map(self, target: str) -> None:
        addresses = range_addresses(target) if target else []
        self._map.set_range(addresses)
        if self._map.visible:
            self._map.grid()
            self._map_caption.grid()
            self._map_caption.configure(
                text=f"Address map of {target}: one cell per address. Click a "
                     f"filled cell to select that device.")
        else:
            self._map.grid_remove()
            self._map_caption.grid_remove()

    def _map_device(self, device: Device) -> None:
        name = self._label_for(device).get("name") or device.hostname or ""
        self._map.set_device(device.ip_address, self._tree.badge_of(device.ip_address)
                             or "online", name)

    def _refresh_map_states(self) -> None:
        for device in self._devices.values():
            self._map_device(device)

    def _map_hover(self, text: str) -> None:
        if text:
            self._map_caption.configure(text=text)
        elif self._map.visible:
            self._map_caption.configure(
                text="Address map: one cell per address. Click a filled cell to "
                     "select that device.")

    def _select_from_map(self, ip: str) -> None:
        if self._tree.row_count() and ip not in self._tree.visible_ips():
            self._clear_filter()
        self._tree.select(ip)
        self._on_device_selected(ip)

    # ------------------------------------------------------------------ #
    # Options
    # ------------------------------------------------------------------ #
    def _load_options(self) -> None:
        s = self.settings
        self._profile_menu.set(get_profile(s.profile).name)
        self._timeout_menu.set(f"{s.timeout:.1f}" if f"{s.timeout:.1f}" in TIMEOUTS else "0.5")
        self._threads_menu.set(str(s.threads) if str(s.threads) in THREADS else "1000")
        (self._resolve_chk.select if s.resolve_hostnames else self._resolve_chk.deselect)()
        (self._identify_chk.select if s.identify_models else self._identify_chk.deselect)()
        (self._only_open_chk.select if s.only_open else self._only_open_chk.deselect)()
        self._auto_menu.set(next((k for k, v in AUTO_RESCAN.items() if v == s.auto_rescan), "Off"))
        self._tree.set_marks(self._favorites)
        self._tree.set_filter("", only_open=s.only_open)
        # The real range arrives from _detect_network a moment later; until
        # then show the last one used so the box is never empty.
        if s.last_range:
            self._range_entry.set(s.last_range)
        self._on_profile_change(initial=True)

    def _save_options(self) -> None:
        s = self.settings
        s.profile = get_profile(self._profile_menu.get()).key
        if s.profile == CUSTOM.key:
            s.custom_ports = self._ports_entry.get().strip() or s.custom_ports
        s.timeout = float(self._timeout_menu.get())
        s.threads = int(self._threads_menu.get())
        s.resolve_hostnames = bool(self._resolve_chk.get())
        s.identify_models = bool(self._identify_chk.get())
        s.only_open = bool(self._only_open_chk.get())
        s.auto_rescan = AUTO_RESCAN.get(self._auto_menu.get(), 0)
        s.last_range = self._range_entry.get().strip()
        s.remember_range(s.last_range)
        self._range_entry.configure(values=s.range_history)
        s.save()

    def _on_profile_change(self, initial: bool = False) -> None:
        profile = get_profile(self._profile_menu.get())
        self._ports_entry.configure(state="normal")
        self._ports_entry.delete(0, tk.END)
        if profile is CUSTOM:
            self._ports_entry.insert(0, self.settings.custom_ports)
        else:
            self._ports_entry.insert(0, profile.ports_label())
            self._ports_entry.configure(state="disabled")
            if not initial:
                self._timeout_menu.set(f"{profile.port_timeout:.1f}"
                                       if f"{profile.port_timeout:.1f}" in TIMEOUTS else "0.5")
        if profile is CUSTOM and not self._options_visible:
            self._toggle_options(True)
        self._preview_range()

    def _toggle_options(self, show: bool) -> None:
        self._options_visible = show
        self._options_var.set(show)
        if show:
            self._options_frame.grid()
        else:
            self._options_frame.grid_remove()

    def _on_adapter_change(self, choice: str) -> None:
        for adapter in self._adapters:
            if choice.startswith(adapter.name + " ("):
                self._range_entry.set(adapter.sweep_range)
                break
        self._on_range_typed()

    def _selected_interface(self) -> str:
        choice = self._adapter_menu.get()
        for adapter in self._adapters:
            if choice.startswith(adapter.name + " ("):
                return adapter.name
        return ""

    def _current_ports(self) -> tuple[int, ...]:
        profile = get_profile(self._profile_menu.get())
        if profile is CUSTOM:
            return parse_ports(self._ports_entry.get())
        return profile.ports

    def _preview_range(self) -> None:
        text = self._range_entry.get().strip()
        profile = get_profile(self._profile_menu.get())
        if profile is CUSTOM:
            try:
                info = f"{len(self._current_ports())} ports"
            except ValueError:
                info = "Invalid port list"
        else:
            info = profile.description
        self._profile_info.configure(text=info)
        if not text:
            self._range_info.configure(text="")
            return
        plan = plan_targets(text)
        if plan.is_empty:
            self._range_info.configure(text="Invalid range", style="Warn.TLabel")
        else:
            note = " (capped)" if plan.truncated else (
                " (detected)" if self._range_is_auto and text == self._detected_range else "")
            self._range_info.configure(text=f"{plan.total} addresses{note}",
                                       style="PaperMuted.TLabel")

    # -- automatic network range ------------------------------------------ #
    def _detect_network(self) -> None:
        """Work out this computer's network in the background, then repeat."""
        if not self._detecting:
            self._detecting = True

            def work() -> None:
                try:
                    detected = local_network_hint()
                except Exception:  # noqa: BLE001 - detection is a convenience
                    detected = ""
                self._call_soon(lambda: self._on_network_detected(detected))

            threading.Thread(target=work, name="detect-network", daemon=True).start()
        self._schedule(NETWORK_CHECK_MS, self._detect_network)

    def _on_network_detected(self, detected: str) -> None:
        self._detecting = False
        if not detected:
            return
        changed = bool(self._detected_range) and detected != self._detected_range
        self._detected_range = detected
        if not self._range_is_auto or self._scanning:
            return
        if self._range_entry.get().strip() != detected:
            self._range_entry.set(detected)
            if changed:
                self._set_status(f"Network changed. The range is now {detected}.")
        self._preview_range()

    def _on_range_typed(self, _event=None) -> None:
        """Typing or picking a range takes over from automatic detection."""
        text = self._range_entry.get().strip()
        self._range_is_auto = not text or text == self._detected_range
        self._preview_range()

    def _use_local_network(self) -> None:
        hint = local_network_hint()
        if not hint:
            messagebox.showwarning(APP_NAME, "No active local network was found.", parent=self)
            return
        self._range_entry.set(hint)
        self._detected_range = hint
        self._range_is_auto = True
        self._adapter_menu.set(AUTO_ADAPTER)
        self._preview_range()

    def _clear_history(self) -> None:
        self.settings.range_history = []
        self.settings.save()
        self._range_entry.configure(values=[])
        self._set_status("Address history cleared")

    # ------------------------------------------------------------------ #
    # Scanning
    # ------------------------------------------------------------------ #
    def _build_request(self, target: str):
        profile = get_profile(self._profile_menu.get())
        ports = self._current_ports()
        return profile.to_request(
            target,
            ports=ports,
            port_timeout=float(self._timeout_menu.get()),
            concurrency=int(self._threads_menu.get()),
            resolve_hostnames=bool(self._resolve_chk.get()),
            identify_models=bool(self._identify_chk.get()) and profile.identify_models,
            interface=self._selected_interface(),
        )

    def _on_scan_click(self) -> None:
        if self._scanning:
            return
        target = self._range_entry.get().strip()
        if not target:
            self._use_local_network()
            target = self._range_entry.get().strip()
            if not target:
                return
        plan = plan_targets(target)
        if plan.is_empty:
            problems = ", ".join(plan.problems) or target
            messagebox.showerror(
                APP_NAME, f"Invalid IP range: {problems}\n\n"
                          "Examples: 192.168.1.0/24, 192.168.1.1-100, 10.0.0.5", parent=self)
            return
        try:
            request = self._build_request(target)
        except ValueError as exc:
            messagebox.showerror(APP_NAME, f"Invalid port list: {exc}", parent=self)
            return
        self._save_options()
        self._cancel_auto()
        self._auto_run = False
        self._tabview.set(TAB_SCANNER)
        self._start_scan(request, clear=True)

    def _start_scan(self, request, clear: bool) -> None:
        while True:                                 # drop leftovers of a past run
            try:
                self._events.get_nowait()
            except queue.Empty:
                break
        if clear:
            self._devices.clear()
            self._new_devices.clear()
            self._gone = []
            self._shares_requested.clear()
            self._tree.clear()
            self._detail.set_device(None)
            self._reset_map(request.target_range)
        self._partial = not clear
        self._stop_event = threading.Event()
        self._scanning = True
        self._outcome = ""
        self._last_range = request.target_range
        self._last_profile = get_profile(request.profile).name
        self._scan_started = time.monotonic()
        self._set_buttons(scanning=True)
        self._set_status(f"Scanning {request.target_range}…")
        self._tree.set_empty_message("Looking for devices…")
        self._progress.grid()
        self._progress.configure(mode="indeterminate")
        self._progress.start(12)
        self._update_summary()
        self._scan_thread = threading.Thread(
            target=self._run_scan, args=(request, self._stop_event),
            name="scan-worker", daemon=True,
        )
        self._scan_thread.start()

    def _run_scan(self, request, stop_event: threading.Event) -> None:
        """Worker thread body: never touches tkinter."""
        try:
            devices = self._scanner.scan(request, stop_event)
            for device in devices:
                # Offline heuristics only: no extra traffic, just the ports found.
                device.findings = exposure_findings(device)
                device.risk_score = exposure_score(device)
                self._events.put(ScannerEvent(PHASE_DEVICE, device=device))
        except Exception as exc:  # noqa: BLE001 - surface any engine failure
            logger.exception("scan failed")
            self._events.put(ScannerEvent(PHASE_ERROR, str(exc), is_error=True))
        finally:
            self._events.put(ScannerEvent(WORKER_DONE))

    def _on_stop_click(self) -> None:
        if not self._scanning or self._stop_event.is_set():
            return
        self._stop_event.set()
        self._stop_btn.configure(state="disabled")
        self._set_status("Stopping…")

    def _set_buttons(self, scanning: bool) -> None:
        for widget in (self._scan_btn, self._range_entry):
            widget.configure(state="disabled" if scanning else "normal")
        for widget in (self._profile_menu, self._adapter_menu, self._timeout_menu,
                       self._threads_menu):
            widget.configure(state="disabled" if scanning else "readonly")
        self._stop_btn.configure(state="normal" if scanning else "disabled")

    def _poll_queue(self) -> None:
        try:
            for _ in range(MAX_EVENTS_PER_POLL):
                try:
                    event = self._events.get_nowait()
                except queue.Empty:
                    break
                self._handle_event(event)
            while True:
                try:
                    callback = self._calls.get_nowait()
                except queue.Empty:
                    break
                callback()
        except Exception:  # noqa: BLE001 - the poll loop must never die
            logger.exception("queue drain failed")
        self._schedule(POLL_INTERVAL_MS, self._poll_queue)

    def _handle_event(self, ev: ScannerEvent) -> None:
        phase = ev.phase
        if phase == PHASE_DEVICE and ev.device is not None:
            self._on_device_event(ev.device)
        elif phase in PROGRESS_PHASES:
            self._on_progress(ev)
        elif phase == PHASE_FINISHED:
            self._outcome = "Finished"
        elif phase == PHASE_CANCELLED:
            self._outcome = "Stopped"
        elif phase == PHASE_ERROR or ev.is_error:
            self._outcome = "Error"
            messagebox.showerror("Scan error", ev.message or "Unknown error", parent=self)
        elif phase == WORKER_DONE:
            self._scan_finished()

    def _on_progress(self, ev: ScannerEvent) -> None:
        if self._stop_event.is_set():
            return
        text = PHASE_TEXT.get(ev.phase, ev.phase)
        if ev.phase == "Ports" and ev.total:
            if str(self._progress.cget("mode")) != "determinate":
                self._progress.stop()
                self._progress.configure(mode="determinate", maximum=100)
            percent = ev.completed * 100 // ev.total
            self._progress.configure(value=percent)
            text += f" ({percent}%)"
        elif str(self._progress.cget("mode")) != "indeterminate":
            self._progress.configure(mode="indeterminate")
            self._progress.start(12)
        self._set_status(text + "…")

    def _on_device_event(self, device: Device) -> None:
        self._devices[device.ip_address] = device
        self._tree.set_alias(device.ip_address, self._label_for(device).get("name", ""))
        self._tree.upsert_device(device)
        self._map_device(device)
        self._update_summary()
        current = self._detail.device
        if current is not None and current.ip_address == device.ip_address:
            self._detail.set_device(device, self._label_for(device))

    def _scan_finished(self) -> None:
        self._scanning = False
        self._progress.stop()
        self._progress.grid_remove()
        self._tree.set_empty_message(
            "No devices answered.\nCheck the range, try the Full profile, or run as "
            "administrator." if self._outcome == "Finished" else
            "No results yet.\nPress Scan (F5) to look for devices on your network.")
        self._set_buttons(scanning=False)
        if get_profile(self._profile_menu.get()) is not CUSTOM:
            self._ports_entry.configure(state="disabled")
        elapsed = time.monotonic() - self._scan_started
        complete = self._outcome == "Finished" and not self._partial
        if complete:
            self._mark_new_devices()
            self._track_changes()
        total = len(self._devices)
        verb = {"Finished": "Scan finished", "Stopped": "Scan stopped",
                "Error": "Scan failed"}.get(self._outcome, "Scan finished")
        status = (f"{verb}: {total} device{'s' if total != 1 else ''} "
                  f"found in {elapsed:.1f} s")
        self._update_summary()
        self._refresh_favorites()
        changes = len(self._new_devices) + len(self._gone)
        if self._auto_run and complete and changes:
            status = (f"Changes detected: {len(self._new_devices)} new, "
                      f"{len(self._gone)} gone (Ctrl+D) — " + status)
            self.title(f"{APP_NAME} — changes detected")
            self.bell()
            self.after(300, self.bell)
        if complete and AUTO_RESCAN.get(self._auto_menu.get(), 0):
            self._schedule_auto()
            status += f"; next scan at {datetime.fromtimestamp(self._auto_due):%H:%M}"
        self._set_status(status)

    def _mark_new_devices(self) -> None:
        """Flag devices never seen in an earlier scan (by MAC, else IP)."""
        known = self.settings.known_devices
        first_scan = not known
        today = datetime.now().strftime("%Y-%m-%d %H:%M")
        new: set[str] = set()
        for ip, device in self._devices.items():
            key = device.mac_address or ip
            if key not in known:
                known[key] = today
                if not first_scan:
                    new.add(ip)
        self._new_devices = new
        self._tree.set_marks(self._favorites, new, self._aliases())
        self._refresh_map_states()
        self.settings.save()

    def _track_changes(self) -> None:
        """Compare with the previous complete scan of the same range."""
        s = self.settings
        current = {device_key(d): {"ip": ip, "name": d.hostname or d.vendor or ""}
                   for ip, d in self._devices.items()}
        if s.last_scan_range == self._last_range:
            self._gone = [dict(info, key=key) for key, info in s.last_scan.items()
                          if key not in current]
        else:
            self._gone = []
        s.last_scan, s.last_scan_range = current, self._last_range
        s.save()

    def _update_summary(self) -> None:
        total = len(self._devices)
        if not total:
            self._summary_label.configure(
                text="Press Scan to find the devices on your network." if not self._scanning
                else "Looking for devices…")
            return
        where = f" on {self._last_range}" if self._last_range else ""
        parts = [f"{total} device{'s' if total != 1 else ''}{where}"]
        with_ports = sum(1 for d in self._devices.values() if open_ports(d))
        details = [f"{with_ports} with open ports"]
        risky = sum(1 for d in self._devices.values() if d.risk_score >= 40)
        if risky:
            details.append(f"{risky} need{'s' if risky == 1 else ''} attention")
        if self._new_devices:
            details.append(f"{len(self._new_devices)} new")
        if self._gone:
            details.append(f"{len(self._gone)} no longer answering")
        shown = self._tree.row_count()
        if shown != total:
            details.append(f"{shown} shown")
        self._summary_label.configure(text=f"{parts[0]}. " + ", ".join(details).capitalize()
                                      + ".")

    def _rescan_host(self, ip: str) -> None:
        self._rescan_hosts([ip])

    def _rescan_hosts(self, ips: list[str]) -> None:
        if self._scanning or not ips:
            return
        try:
            request = self._build_request(",".join(ips))
        except ValueError as exc:
            messagebox.showerror(APP_NAME, f"Invalid port list: {exc}", parent=self)
            return
        self._start_scan(request, clear=False)

    def _rescan_selected(self) -> None:
        ips = self._tree.get_selected_ips()
        if ips:
            self._rescan_hosts(ips)
        else:
            self._set_status("Select a device to rescan it")

    def _scan_subnet(self, ip: str) -> None:
        if self._scanning:
            return
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
        self._range_entry.set(str(network))
        self._on_range_typed()
        self._on_scan_click()

    # ------------------------------------------------------------------ #
    # Changes dialog, names and notes
    # ------------------------------------------------------------------ #
    def _show_changes(self) -> None:
        """Dialog listing what appeared and disappeared since the last scan."""
        self.title(APP_NAME)
        rows: list[tuple[str, str, str, str]] = []
        for ip in sorted(self._new_devices, key=ip_key):
            dev = self._devices.get(ip)
            name = (self._label_for(dev).get("name") or dev.hostname or dev.vendor) if dev else ""
            rows.append(("New", ip, (dev.mac_address if dev else "") or "", name or ""))
        for info in sorted(self._gone, key=lambda i: ip_key(i["ip"])):
            label = self.settings.device_labels.get(info["key"], {}).get("name") or info["name"]
            mac = info["key"] if info["key"] != info["ip"] else ""
            rows.append(("Gone", info["ip"], mac, label))

        window = tk.Toplevel(self)
        window.title("Changes since last scan")
        window.geometry("560x320")
        window.transient(self)
        frame = ttk.Frame(window, padding=8)
        frame.pack(fill="both", expand=True)
        if not self._devices:
            text = ("Run a complete scan first. Changes are measured against the previous "
                    "complete scan of the same range.")
        else:
            text = (f"{len(self._new_devices)} new device(s) and {len(self._gone)} device(s) "
                    f"that no longer answer, compared with the previous scan of "
                    f"{self._last_range}.")
        ttk.Label(frame, text=text, wraplength=530).pack(anchor="w", pady=(0, 6))
        tree = ttk.Treeview(frame, columns=("change", "ip", "mac", "name"), show="headings",
                            height=8)
        for column, heading, width in (("change", "Change", 70), ("ip", "IP", 110),
                                       ("mac", "MAC address", 130), ("name", "Name", 200)):
            tree.heading(column, text=heading, anchor="w")
            tree.column(column, width=width, anchor="w")
        tree.tag_configure("Gone", foreground=theme.PALETTE.danger)
        tree.tag_configure("New", foreground=theme.PALETTE.new)
        for row in rows:
            tree.insert("", "end", values=row, tags=(row[0],))
        tree.pack(fill="both", expand=True)
        ttk.Button(frame, text="Close", command=window.destroy).pack(anchor="e", pady=(8, 0))
        window.bind("<Escape>", lambda _e: window.destroy())
        window.after(50, window.focus_force)
        self._changes_window = window

    def _label_for(self, device: Device | None) -> dict:
        if device is None:
            return {}
        return self.settings.device_labels.get(device_key(device), {})

    def _aliases(self) -> dict[str, str]:
        return {ip: self._label_for(d).get("name", "") for ip, d in self._devices.items()
                if self._label_for(d).get("name")}

    def _rename_selected(self) -> None:
        ip = self._tree.get_selected_ip()
        if ip:
            self._edit_label(ip)

    def _edit_label(self, ip: str) -> None:
        """Small dialog to give a device a custom name and a note."""
        device = self._devices.get(ip)
        if device is None:
            return
        current = self._label_for(device)
        window = tk.Toplevel(self)
        window.title("Rename device")
        window.resizable(False, False)
        window.transient(self)
        frame = ttk.Frame(window, padding=12)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text=f"{ip}    {device.mac_address or ''}    "
                              f"{device.hostname or device.vendor or ''}",
                  style="Muted.TLabel").grid(row=0, column=0, columnspan=2, sticky="w",
                                             pady=(0, 8))
        ttk.Label(frame, text="Name:").grid(row=1, column=0, sticky="w", padx=(0, 8))
        name = ttk.Entry(frame, width=40)
        name.grid(row=1, column=1, sticky="ew", pady=2)
        name.insert(0, current.get("name", ""))
        ttk.Label(frame, text="Note:").grid(row=2, column=0, sticky="w", padx=(0, 8))
        note = ttk.Entry(frame, width=40)
        note.grid(row=2, column=1, sticky="ew", pady=2)
        note.insert(0, current.get("note", ""))

        def save() -> None:
            self.set_label(ip, name.get(), note.get())
            window.destroy()

        buttons = ttk.Frame(frame)
        buttons.grid(row=3, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text="OK", default="active", command=save).pack(side="left")
        ttk.Button(buttons, text="Cancel", command=window.destroy).pack(side="left", padx=(6, 0))
        window.bind("<Return>", lambda _e: save())
        window.bind("<Escape>", lambda _e: window.destroy())
        window.after(50, lambda: (window.focus_force(), name.focus_set(),
                                  name.select_range(0, tk.END)))

    def set_label(self, ip: str, name: str, note: str = "") -> None:
        """Store (or clear, when both are empty) a device's custom name and note."""
        device = self._devices.get(ip)
        if device is None:
            return
        key = device_key(device)
        name, note = name.strip(), note.strip()
        if name or note:
            self.settings.device_labels[key] = {"name": name, "note": note}
        else:
            self.settings.device_labels.pop(key, None)
        self.settings.save()
        self._tree.set_alias(ip, name)
        self._tree.upsert_device(device)
        self._map_device(device)
        if self._detail.device is not None and self._detail.device.ip_address == ip:
            self._detail.set_device(device, self._label_for(device))
        self._refresh_favorites()

    # ------------------------------------------------------------------ #
    # Automatic rescans
    # ------------------------------------------------------------------ #
    def _on_auto_change(self) -> None:
        minutes = AUTO_RESCAN.get(self._auto_menu.get(), 0)
        self.settings.auto_rescan = minutes
        self.settings.save()
        self._cancel_auto()
        if minutes and self._devices and not self._scanning:
            self._schedule_auto()
            self._set_status(f"Auto-rescan every {minutes} min; next scan at "
                             f"{datetime.fromtimestamp(self._auto_due):%H:%M}")
        elif not minutes:
            self._set_status("Auto-rescan off")

    def _schedule_auto(self) -> None:
        self._cancel_auto()
        minutes = AUTO_RESCAN.get(self._auto_menu.get(), 0)
        if minutes:
            self._auto_due = time.time() + minutes * 60
            self._auto_job = self.after(minutes * 60 * 1000, self._auto_scan)

    def _cancel_auto(self) -> None:
        if self._auto_job is not None:
            try:
                self.after_cancel(self._auto_job)
            except (tk.TclError, ValueError):
                pass
            self._auto_job = None

    def _auto_scan(self) -> None:
        self._auto_job = None
        if self._scanning:
            self._schedule_auto()
            return
        target = self._last_range or self._range_entry.get().strip()
        try:
            request = self._build_request(target)
        except ValueError:
            return
        self._auto_run = True
        self._start_scan(request, clear=True)

    # ------------------------------------------------------------------ #
    # Device actions
    # ------------------------------------------------------------------ #
    @property
    def _favorites(self) -> set[str]:
        return set(self.settings.favorites)

    def _on_device_selected(self, ip: str) -> None:
        device = self._devices.get(ip)
        self._detail.set_device(device, self._label_for(device))
        self._map.select(ip)

    def _on_device_expand(self, ip: str) -> None:
        """List shared folders the first time a Windows host is expanded."""
        dev = self._devices.get(ip)
        if dev is None or ip in self._shares_requested or sys.platform != "win32":
            return
        if not {p.number for p in open_ports(dev)} & SMB_PORTS:
            return
        self._shares_requested.add(ip)
        self._set_status(f"Reading shared folders of {ip}…")

        def work() -> None:
            result = nettools.list_shares(ip)
            shares = result.data or []
            self._call_soon(lambda: self._show_shares(ip, shares, result.error))

        threading.Thread(target=work, name="shares", daemon=True).start()

    def _show_shares(self, ip: str, shares: list, error: str) -> None:
        self._tree.add_shares(ip, shares)
        if shares:
            self._set_status(f"{ip} shares {len(shares)} folder(s)")
        else:
            self._set_status(f"{ip}: no shared folders" + (f" ({error})" if error else ""))

    def _open_share(self, ip: str, name: str) -> None:
        if sys.platform == "win32":
            try:
                os.startfile(f"\\\\{ip}\\{name}")  # noqa: S606 - opens Explorer
            except OSError as exc:
                messagebox.showerror(APP_NAME, str(exc), parent=self)

    def _open_tool(self, name: str, values: dict, run: bool = False) -> None:
        self._tabview.set(TAB_TOOLS)
        if run:
            self._tools.run_tool(name, values)
        else:
            self._tools.select_tool(name, values)

    def _monitor_host(self, ip: str) -> None:
        dev = self._devices.get(ip)
        label = (self._label_for(dev).get("name") or dev.hostname) if dev else ""
        self._monitor.add_host(ip, label=label or ip, category=dev.category if dev else "")
        self._tabview.set(TAB_MONITOR)

    def _open_device_web(self, ip: str) -> None:
        dev = self._devices.get(ip)
        if not dev:
            return
        port = best_web_port(dev)
        if port:
            open_web(dev.ip_address, port)
        elif {p.number for p in open_ports(dev)} & SMB_PORTS:
            self._open_shares(ip)
        else:
            self._set_status(f"{ip} has no web page or shared folders to open")

    def _open_rdp(self, ip: str) -> None:
        ok, message = open_remote_desktop(ip)
        if not ok:
            messagebox.showerror(APP_NAME, message, parent=self)

    def _open_ssh(self, ip: str) -> None:
        try:
            if sys.platform == "win32":
                subprocess.Popen(["cmd", "/c", "start", "SSH", "ssh", ip])
            else:
                subprocess.Popen(["x-terminal-emulator", "-e", "ssh", ip])
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"Could not start ssh: {exc}", parent=self)

    def _open_shares(self, ip: str) -> None:
        if sys.platform == "win32":
            try:
                os.startfile(f"\\\\{ip}")  # noqa: S606 - opens Explorer on the share list
            except OSError as exc:
                messagebox.showerror(APP_NAME, str(exc), parent=self)
        else:
            messagebox.showinfo(APP_NAME, f"Open smb://{ip} in your file manager.", parent=self)

    def _wake(self, ip: str) -> None:
        dev = self._devices.get(ip)
        if not dev:
            return
        ok, message = wake_device(dev)
        if ok:
            self._set_status(f"Wake-on-LAN packet sent to {message}")
        else:
            messagebox.showerror("Wake-on-LAN", message, parent=self)

    def _power(self, ip: str, action: str) -> None:
        dev = self._devices.get(ip)
        name = (self._label_for(dev).get("name") or dev.hostname) if dev else ""
        target = f"{name} ({ip})" if name else ip
        if action != "abort":
            verb = "shut down" if action == "shutdown" else "restart"
            if not messagebox.askyesno(
                    "Confirm", f"Ask {target} to {verb} in 30 seconds?\n\n"
                               "The remote computer must allow it and you need administrator "
                               "rights on it. Its user sees a warning and can be told to "
                               "save their work.", icon="warning", parent=self):
                return
        ok, message = remote_power(ip, action)
        if ok:
            self._set_status(message)
        else:
            messagebox.showerror(APP_NAME, message, parent=self)

    def _copy(self, text: str) -> None:
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status(f"Copied to clipboard: {text.splitlines()[0][:60]}")

    def _copy_selected(self) -> None:
        """Selected rows as tab-separated text (pastes into Excel)."""
        ips = self._tree.get_selected_ips()
        if not ips:
            return
        header = "\t".join(label for label, *_rest in TREE_COLUMNS)
        rows = [header] + ["\t".join(device_row(self._devices[ip],
                                                self._label_for(self._devices[ip]).get("name", "")))
                           for ip in ips if ip in self._devices]
        self._copy("\n".join(rows))
        self._set_status(f"Copied {len(rows) - 1} row(s)")

    def _on_ctrl_c(self, event) -> None:
        if event.widget is self._tree._tree:
            self._copy_selected()

    def _select_all(self) -> None:
        self._tabview.set(TAB_SCANNER)
        self._tree._tree.selection_set(self._tree._tree.get_children())

    def _toggle_detail(self) -> None:
        self._props_var.set(not self._props_var.get())
        self._apply_props_visibility()

    # -- filter ---------------------------------------------------------- #
    def _apply_filter(self) -> None:
        self._tree.set_filter(self._filter_entry.get(),
                              only_open=bool(self._only_open_chk.get()))
        self._update_summary()

    def _clear_filter(self) -> None:
        self._filter_entry.delete(0, tk.END)
        self._apply_filter()

    def _focus_filter(self) -> None:
        self._tabview.set(TAB_SCANNER)
        self._filter_entry.focus_set()
        self._filter_entry.select_range(0, tk.END)

    # -- favorites ------------------------------------------------------- #
    def _toggle_favorite(self, ip: str) -> None:
        favorites = self._favorites ^ {ip}
        self.settings.favorites = sorted(favorites, key=ip_key)
        self.settings.save()
        self._tree.set_marks(favorites)
        self._refresh_map_states()
        self._refresh_favorites()

    def _add_favorites(self, ips: list[str]) -> None:
        favorites = self._favorites | set(ips)
        self.settings.favorites = sorted(favorites, key=ip_key)
        self.settings.save()
        self._tree.set_marks(favorites)
        self._refresh_map_states()
        self._refresh_favorites()

    def _refresh_favorites(self) -> None:
        self._favs_list.delete(*self._favs_list.get_children())
        for ip in self.settings.favorites:
            dev = self._devices.get(ip)
            if dev:
                name = self._label_for(dev).get("name") or dev.hostname or ip
                ports = dev.ports_compact()
                state = "Online" + (f", ports {ports}" if ports != "-" else "")
                self._favs_list.insert("", "end", iid=ip, image=self.icons.device(dev.category),
                                       values=(name, ip, device_row(dev)[2], state))
            else:
                self._favs_list.insert("", "end", iid=ip, image=self.icons.device("unknown"),
                                       values=(ip, ip, "", "Not found in the current results"),
                                       tags=("away",))

    def _on_fav_double_click(self, _event=None) -> None:
        selection = self._favs_list.selection()
        if not selection:
            return
        ip = selection[0]
        self._tabview.set(TAB_SCANNER)
        if ip in self._devices:
            self._select_from_map(ip)
        else:
            self._range_entry.set(ip)
            self._on_range_typed()
            self._set_status(f"{ip} is not in the current results. Press Scan to check it.")

    def _on_fav_delete(self, _event=None) -> None:
        selection = self._favs_list.selection()
        if selection:
            self._toggle_favorite(selection[0])

    def _forget_known(self) -> None:
        if messagebox.askyesno(APP_NAME, "Forget every known device?\n\n"
                                         "The next scan becomes the new baseline for the "
                                         "\"new device\" markers.", parent=self):
            self.settings.known_devices = {}
            self.settings.save()
            self._new_devices.clear()
            self._tree.set_marks(self._favorites, set())
            self._refresh_map_states()
            self._update_summary()

    # -- files ----------------------------------------------------------- #
    def _require_devices(self) -> bool:
        if not self._devices:
            messagebox.showwarning(APP_NAME, "There are no results yet. Run a scan first.",
                                   parent=self)
            return False
        return True

    def _sorted_devices(self) -> list[Device]:
        return sorted(self._devices.values(), key=lambda d: ip_key(d.ip_address))

    def _export(self) -> None:
        if self._scanning or not self._require_devices():
            return
        path = filedialog.asksaveasfilename(
            parent=self, title="Save results as", defaultextension=".csv",
            filetypes=[("CSV (Excel)", "*.csv"), ("JSON (can be reopened)", "*.json")],
            initialfile=f"weftscan_{datetime.now():%Y%m%d_%H%M}",
        )
        if not path:
            return
        try:
            written = export_devices(self._sorted_devices(), path,
                                     extra={"range": self._last_range,
                                            "profile": self._last_profile})
        except Exception as exc:  # noqa: BLE001
            logger.exception("export failed")
            messagebox.showerror(APP_NAME, f"Could not save the results:\n{exc}", parent=self)
            return
        self._set_status(f"Saved {len(self._devices)} devices to {written}")

    def _open_results(self) -> None:
        if self._scanning:
            return
        path = filedialog.askopenfilename(
            parent=self, title="Open results", filetypes=[("WeftScan results", "*.json")])
        if path:
            self.load_results(path)

    def load_results(self, path: str) -> bool:
        """Replace the table with devices saved earlier as JSON."""
        try:
            devices, session = load_json(path)
        except ValueError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self)
            return False
        self._devices.clear()
        self._new_devices.clear()
        self._gone = []
        self._shares_requested.clear()
        self._tree.clear()
        self._detail.set_device(None)
        self._last_range = str(session.get("range", ""))
        self._reset_map(self._last_range)
        if self._last_range:
            self._range_entry.set(self._last_range)
            self._on_range_typed()
        for device in devices:
            self._on_device_event(device)
        if self._last_range:
            self._range_entry.set(self._last_range)
            self._preview_range()
        self._tabview.set(TAB_SCANNER)
        when = str(session.get("generated", "")).replace("T", " ")
        self._set_status(f"Opened {Path(path).name}: {len(devices)} devices"
                         + (f" (saved {when})" if when else ""))
        self._update_summary()
        self._refresh_favorites()
        return True

    def _report(self) -> None:
        if self._scanning or not self._require_devices():
            return
        path = filedialog.asksaveasfilename(
            parent=self, title="Security report", defaultextension=".html",
            filetypes=[("HTML", "*.html"), ("PDF", "*.pdf")],
            initialfile=f"network_report_{datetime.now():%Y%m%d_%H%M}",
        )
        if not path:
            return
        from ..analysis.report import build_report

        fmt = "pdf" if path.lower().endswith(".pdf") else "html"
        try:
            written = build_report(self._sorted_devices(), path, fmt=fmt)
        except Exception as exc:  # noqa: BLE001
            logger.exception("report failed")
            messagebox.showerror(APP_NAME, f"Could not build the report:\n{exc}", parent=self)
            return
        self._set_status(f"Report saved to {written}")
        if messagebox.askyesno(APP_NAME, f"Report saved to:\n{written}\n\nOpen it now?",
                               parent=self):
            try:
                os.startfile(str(written))  # noqa: S606
            except (OSError, AttributeError):
                pass

    # ------------------------------------------------------------------ #
    # Dialogs and system
    # ------------------------------------------------------------------ #
    def _restart_elevated(self) -> None:
        """Relaunch through UAC so the ARP sweep and ICMP get raw sockets."""
        if getattr(sys, "frozen", False):
            program, params = sys.executable, ""
        else:
            program = sys.executable
            params = "-m weftscan.main"
        cwd = str(Path(__file__).resolve().parents[2])
        try:
            code = ctypes.windll.shell32.ShellExecuteW(None, "runas", program, params, cwd, 1)
        except (AttributeError, OSError) as exc:
            messagebox.showerror(APP_NAME, f"Could not restart: {exc}", parent=self)
            return
        if code > 32:
            self.destroy()

    def _show_about(self) -> None:
        messagebox.showinfo(
            f"About {APP_NAME}",
            f"{APP_NAME} {APP_VERSION}\n{APP_AUTHOR}\n\n"
            "Network scanner for local networks: finds devices, open ports and "
            "shared folders, and includes diagnostic tools and a host monitor.\n\n"
            "Only scan networks you own or are allowed to test.", parent=self)

    def _show_help(self) -> None:
        messagebox.showinfo(
            "Quick guide",
            "Scanning\n"
            "  Type a range (192.168.1.0/24, 192.168.1.1-100, 10.0.0.5) or pick an "
            "adapter, choose a profile and press Scan (F5). Esc stops.\n\n"
            "Results\n"
            "  Click a device to see its properties. Expand it to list its services and "
            "shared folders. Double-click or Enter opens its web page or shares. "
            "Right-click for Open with, Tools, Power and Copy.\n\n"
            "Markers\n"
            "  Blue: new device. Orange/red: security findings. Star: favorite.\n\n"
            "Keyboard\n"
            "  F5 Scan, Esc Stop, Ctrl+R Rescan, F2 Rename, Ctrl+C Copy rows, "
            "Ctrl+F Search, Ctrl+D Changes, F8 Options, F9 Properties, "
            "Ctrl+O Open results, Ctrl+S Save results, Ctrl+P Report.\n\n"
            "Command line\n"
            "  python -m weftscan 192.168.1.0/24 -p quick", parent=self)

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def _save_geometry(self) -> None:
        try:
            zoomed = self.state() == "zoomed"
            if not zoomed:
                self.settings.window_geometry = self.geometry()
            self.settings.window_zoomed = zoomed
            self.settings.save()
        except tk.TclError:
            pass

    def destroy(self) -> None:
        self._stop_event.set()
        self._cancel_auto()
        self._save_geometry()
        try:
            self._monitor.shutdown()
        except Exception:  # noqa: BLE001
            pass
        for job in self._after_jobs:
            try:
                self.after_cancel(job)
            except (tk.TclError, ValueError):
                pass
        super().destroy()


def launch() -> None:
    """Create the main window and start the tkinter event loop."""
    theme.enable_dpi_awareness()
    app = ScannerApp()
    app.mainloop()


if __name__ == "__main__":
    launch()
