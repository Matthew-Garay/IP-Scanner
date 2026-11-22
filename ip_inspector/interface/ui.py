"""
Main window of IP Inspector.

Tabs
----
* **Scanner**   - range, adapter and profile pickers, scan options, the
                  results table and the device detail panel.
* **Favorites** - devices you pinned, remembered between sessions.
* **Tools**     - standalone diagnostics (see :mod:`.tools_tab`).
* **Monitor**   - continuous reachability checks (see :mod:`.monitor_tab`).

Threading model
---------------
Every long operation runs on a worker thread that pushes results onto a
``queue.Queue``. The main thread drains it with ``after()`` — the only safe
way to update tkinter from another thread.

The scan worker always finishes by posting :data:`WORKER_DONE`, even when the
engine raises, so the buttons can never stay stuck in the "scanning" state.

Event contract
--------------
The phase names below are the ones :class:`NetworkScanner` emits;
``tests/test_ui.py`` pins this contract.
"""

from __future__ import annotations

import ctypes
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
from tkinter import filedialog, messagebox

import customtkinter as ctk

from .. import i18n
from ..actions.exporter import export as export_devices
from ..actions.menu import best_web_port, open_remote_desktop, open_web, wake_device
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
from ..nettools.profiles import CUSTOM, PROFILES, get_profile, parse_ports
from . import theme
from .monitor_tab import MonitorTab
from .settings import Settings
from .tools_tab import ToolsTab
from .widgets import (
    TREE_COLUMNS,
    DetailPanel,
    DeviceTree,
    c,
    device_key,
    device_row,
    ip_key,
    matches_filter,
    open_ports,
)

logger = logging.getLogger(__name__)

__all__ = [
    "APP_NAME", "APP_AUTHOR", "IPInspectorApp", "launch",
    "TREE_COLUMNS", "device_row", "matches_filter",
]

APP_NAME = "IP Inspector"
APP_AUTHOR = "Matthew Garay"
APP_VERSION = "2.0"

WINDOW_SIZE = (1440, 880)
WINDOW_MINIMUM = (1100, 660)
POLL_INTERVAL_MS = 100

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
AUTO_ADAPTER = "Auto (default route)"
#: Auto-rescan choices shown in the options row -> minutes (0 = off).
AUTO_RESCAN = {"Off": 0, "5 min": 5, "15 min": 15, "30 min": 30, "60 min": 60}

TAB_SCANNER = "Scanner"
TAB_FAVORITES = "Favorites"
TAB_TOOLS = "Tools"
TAB_MONITOR = "Monitor"


class IPInspectorApp(ctk.CTk):
    """Main window."""

    def __init__(self, settings: Settings | None = None) -> None:
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self._centre_on_screen(WINDOW_SIZE, WINDOW_MINIMUM)
        self.minsize(*WINDOW_MINIMUM)

        self.settings = settings if settings is not None else Settings.load()
        i18n.initialize()
        i18n.set_language("en")
        if self.settings.appearance in ("light", "dark"):
            ctk.set_appearance_mode(self.settings.appearance)
        theme.set_mode(ctk.get_appearance_mode())

        self._events: queue.Queue[ScannerEvent] = queue.Queue()
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

        self._build_menu_bar()
        self._build_layout()
        self._load_options()
        self._refresh_favorites()
        self._set_status("Ready. Press Scan (F5) to explore the network.")
        self._schedule(POLL_INTERVAL_MS, self._poll_queue)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    # ------------------------------------------------------------------ #
    # Window helpers
    # ------------------------------------------------------------------ #
    def _centre_on_screen(self, size, minimum):
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w = max(min(size[0], sw - 40), minimum[0])
        h = max(min(size[1], sh - 80), minimum[1])
        self.geometry(f"{w}x{h}+{max(0, (sw - w) // 2)}+{max(0, (sh - h) // 3)}")

    def _schedule(self, ms: int, callback) -> None:
        self._after_jobs.append(self.after(ms, callback))
        if len(self._after_jobs) > 32:
            self._after_jobs = self._after_jobs[-8:]

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
    # Menu bar and context menu
    # ------------------------------------------------------------------ #
    def _build_menu_bar(self) -> None:
        bar = tk.Menu(self)
        self.config(menu=bar)

        m_file = tk.Menu(bar, tearoff=0)
        m_file.add_command(label="Scan", accelerator="F5", command=self._on_scan_click)
        m_file.add_command(label="Stop", accelerator="Esc", command=self._on_stop_click)
        m_file.add_command(label="Rescan selected device", accelerator="Ctrl+R",
                           command=self._rescan_selected)
        m_file.add_separator()
        m_file.add_command(label="Export results (CSV / JSON)…", accelerator="Ctrl+S",
                           command=self._export)
        m_file.add_command(label="Security report (HTML / PDF)…", accelerator="Ctrl+P",
                           command=self._report)
        m_file.add_separator()
        m_file.add_command(label="Exit", command=self.destroy)
        bar.add_cascade(label="File", menu=m_file)

        m_view = tk.Menu(bar, tearoff=0)
        m_view.add_command(label="Details panel", accelerator="F9", command=self._toggle_detail)
        m_view.add_command(label="Scan options", accelerator="F8", command=self._toggle_options)
        m_view.add_command(label="Expand all services", command=lambda: self._tree.expand_all(True))
        m_view.add_command(label="Collapse all", command=lambda: self._tree.expand_all(False))
        m_view.add_command(label="Changes since last scan…", accelerator="Ctrl+D",
                           command=self._show_changes)
        m_view.add_separator()
        m_view.add_command(label="Light theme", command=lambda: self._set_appearance("light"))
        m_view.add_command(label="Dark theme", command=lambda: self._set_appearance("dark"))
        m_view.add_command(label="System theme", command=lambda: self._set_appearance("system"))
        bar.add_cascade(label="View", menu=m_view)

        m_tools = tk.Menu(bar, tearoff=0)
        for label, tool, values in (
            ("Ping default gateway", "Ping", lambda: {"host": default_gateway()}),
            ("Traceroute to the Internet", "Traceroute", lambda: {"host": "8.8.8.8"}),
            ("Show ARP table", "ARP table", dict),
            ("Show network adapters", "Network adapters", dict),
            ("Listening ports on this PC", "Listening ports", dict),
        ):
            m_tools.add_command(label=label,
                                command=lambda t=tool, v=values: self._open_tool(t, v(), run=True))
        m_tools.add_separator()
        m_tools.add_command(label="All tools…", accelerator="Ctrl+T",
                            command=lambda: self._tabview.set(TAB_TOOLS))
        m_tools.add_command(label="Monitor…", accelerator="Ctrl+M",
                            command=lambda: self._tabview.set(TAB_MONITOR))
        bar.add_cascade(label="Tools", menu=m_tools)

        m_cfg = tk.Menu(bar, tearoff=0)
        m_cfg.add_command(label="Use my local network", command=self._use_local_network)
        m_cfg.add_command(label="Forget known devices (reset NEW flags)",
                          command=self._forget_known)
        if sys.platform == "win32" and not self._elevated:
            m_cfg.add_separator()
            m_cfg.add_command(label="Restart as administrator", command=self._restart_elevated)
        bar.add_cascade(label="Settings", menu=m_cfg)

        m_help = tk.Menu(bar, tearoff=0)
        m_help.add_command(label="Quick guide", accelerator="F1", command=self._show_help)
        m_help.add_command(label="About IP Inspector", command=self._show_about)
        bar.add_cascade(label="Help", menu=m_help)

        for key, action in (
            ("<F5>", self._on_scan_click), ("<Escape>", self._on_stop_click),
            ("<Control-s>", self._export), ("<Control-p>", self._report),
            ("<Control-r>", self._rescan_selected), ("<F1>", self._show_help),
            ("<F8>", self._toggle_options), ("<F9>", self._toggle_detail),
            ("<Control-f>", self._focus_filter),
            ("<Control-d>", self._show_changes),
            ("<F2>", self._rename_selected),
            ("<Control-t>", lambda: self._tabview.set(TAB_TOOLS)),
            ("<Control-m>", lambda: self._tabview.set(TAB_MONITOR)),
        ):
            self.bind(key, lambda _e, a=action: a())

        self._context_ip: str | None = None
        self._context = tk.Menu(self, tearoff=0)

    def _show_context(self, ip: str, x: int, y: int) -> None:
        """Right-click menu, rebuilt per device so it only offers what applies."""
        dev = self._devices.get(ip)
        if dev is None:
            return
        self._context_ip = ip
        menu = self._context
        menu.delete(0, tk.END)
        ports = {p.number for p in open_ports(dev)}
        web = best_web_port(dev)

        def add(label, action, enabled=True):
            menu.add_command(label=label, command=lambda: action(ip),
                             state="normal" if enabled else "disabled")

        add("Open in browser" + (f" (:{web})" if web else ""), self._open_device_web, bool(web))
        add("Remote Desktop (RDP)", self._open_rdp, 3389 in ports)
        add("SSH in a terminal", self._open_ssh, 22 in ports)
        add("Browse shared folders", self._open_shares, 445 in ports or 139 in ports)
        menu.add_separator()
        add("Rescan this device", self._rescan_host)
        add("Scan all ports (1-65535)",
            lambda i: self._open_tool("Port check", {"host": i, "ports": "1-65535",
                                                      "timeout": "0.3"}, run=True))
        add("Ping", lambda i: self._open_tool("Ping", {"host": i}, run=True))
        add("Traceroute", lambda i: self._open_tool("Traceroute", {"host": i}, run=True))
        add("TLS certificate", lambda i: self._open_tool(
            "TLS certificate", {"host": i, "port": "8443" if 8443 in ports and 443 not in ports
                                else "443"}, run=True), bool(ports & {443, 8443}))
        add("HTTP security headers", lambda i: self._open_tool(
            "HTTP headers", {"url": f"{'https' if web in (443, 8443) else 'http'}://{i}"
                             + ("" if web in (80, 443) else f":{web}")}, run=True), bool(web))
        add("Add to monitor", self._monitor_host)
        add("Rename / add note…", self._edit_label)
        menu.add_separator()
        add("Wake-on-LAN", self._wake, bool(dev.mac_address))
        add("Copy IP", lambda i: self._copy(i))
        add("Copy MAC", lambda i: self._copy(dev.mac_address or ""), bool(dev.mac_address))
        add("Copy row", lambda i: self._copy("\t".join(device_row(dev))))
        menu.add_separator()
        add("Remove from favorites" if ip in self._favorites else "Add to favorites",
            self._toggle_favorite)
        try:
            menu.tk_popup(x, y)
        finally:
            menu.grab_release()

    # ------------------------------------------------------------------ #
    # Layout
    # ------------------------------------------------------------------ #
    def _build_layout(self) -> None:
        self.configure(fg_color=c("background"))
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._tabview = ctk.CTkTabview(self, fg_color=c("surface"), anchor="nw")
        self._tabview.grid(row=0, column=0, sticky="nsew", padx=10, pady=(4, 4))
        scanner_tab = self._tabview.add(TAB_SCANNER)
        favs_tab = self._tabview.add(TAB_FAVORITES)
        tools_tab = self._tabview.add(TAB_TOOLS)
        monitor_tab = self._tabview.add(TAB_MONITOR)

        self._build_scanner_tab(scanner_tab)
        self._build_favorites_tab(favs_tab)

        tools_tab.grid_columnconfigure(0, weight=1)
        tools_tab.grid_rowconfigure(0, weight=1)
        self._tools = ToolsTab(tools_tab, on_status=self._set_status)
        self._tools.grid(row=0, column=0, sticky="nsew")

        monitor_tab.grid_columnconfigure(0, weight=1)
        monitor_tab.grid_rowconfigure(0, weight=1)
        self._monitor = MonitorTab(monitor_tab, on_status=self._set_status)
        self._monitor.grid(row=0, column=0, sticky="nsew")

        self._build_status_bar()

    def _build_scanner_tab(self, tab) -> None:
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(3, weight=1)

        # -- toolbar --------------------------------------------------------- #
        toolbar = ctk.CTkFrame(tab, fg_color=c("surface_alt"), corner_radius=8)
        toolbar.grid(row=0, column=0, sticky="ew", padx=4, pady=(4, 4))

        self._scan_btn = ctk.CTkButton(
            toolbar, text="▶  Scan", width=110, height=32,
            fg_color=c("accent"), hover_color=c("accent_hover"),
            text_color=c("accent_text"), font=("Segoe UI", 11, "bold"),
            command=self._on_scan_click,
        )
        self._scan_btn.grid(row=0, column=0, padx=(10, 6), pady=8)
        flat = dict(height=32, fg_color="transparent", hover_color=c("hover"),
                    text_color=c("text_primary"), font=("Segoe UI", 10),
                    border_width=1, border_color=c("border"))
        self._stop_btn = ctk.CTkButton(toolbar, text="■  Stop", width=80,
                                       command=self._on_stop_click, state="disabled", **flat)
        self._stop_btn.grid(row=0, column=1, padx=(0, 14), pady=8)

        def caption(text, column):
            ctk.CTkLabel(toolbar, text=text, font=("Segoe UI", 10, "bold"),
                         text_color=c("text_secondary")).grid(row=0, column=column,
                                                              padx=(0, 6))

        caption("Range:", 2)
        self._range_entry = ctk.CTkEntry(
            toolbar, placeholder_text="192.168.1.0/24, 10.0.0.1-50", width=210, height=30)
        self._range_entry.grid(row=0, column=3)
        self._range_entry.bind("<Return>", lambda _e: self._on_scan_click())
        self._range_entry.bind("<KeyRelease>", lambda _e: self._preview_range())
        self._range_info = ctk.CTkLabel(toolbar, text="", width=78, anchor="w",
                                        font=("Segoe UI", 9), text_color=c("text_muted"))
        self._range_info.grid(row=0, column=4, padx=(4, 10))

        caption("Adapter:", 5)
        adapter_names = [AUTO_ADAPTER] + [f"{a.name} · {a.sweep_range}" for a in self._adapters]
        self._adapter_menu = ctk.CTkOptionMenu(toolbar, values=adapter_names, width=200,
                                               command=self._on_adapter_change)
        self._adapter_menu.grid(row=0, column=6, padx=(0, 12))

        caption("Profile:", 7)
        self._profile_menu = ctk.CTkOptionMenu(
            toolbar, values=[p.name for p in PROFILES], width=140,
            command=lambda _v: self._on_profile_change())
        self._profile_menu.grid(row=0, column=8, padx=(0, 6))
        self._options_btn = ctk.CTkButton(toolbar, text="Options ▾", width=86,
                                          command=self._toggle_options, **flat)
        self._options_btn.grid(row=0, column=9, padx=(0, 12))

        toolbar.grid_columnconfigure(10, weight=1)
        self._export_btn = ctk.CTkButton(toolbar, text="Export", width=74,
                                         command=self._export, **flat)
        self._export_btn.grid(row=0, column=11, padx=(0, 6))
        self._report_btn = ctk.CTkButton(toolbar, text="Report", width=74,
                                         command=self._report, **flat)
        self._report_btn.grid(row=0, column=12, padx=(0, 10))

        # -- options (collapsible) ------------------------------------------- #
        self._options = ctk.CTkFrame(tab, fg_color=c("surface_alt"), corner_radius=8)
        self._options.grid(row=1, column=0, sticky="ew", padx=4, pady=(0, 4))
        opt_label = dict(font=("Segoe UI", 10, "bold"), text_color=c("text_secondary"))
        ctk.CTkLabel(self._options, text="Ports:", **opt_label).grid(
            row=0, column=0, padx=(12, 6), pady=8)
        self._ports_entry = ctk.CTkEntry(self._options, width=300, height=28,
                                         placeholder_text="22,80,443,8000-8100")
        self._ports_entry.grid(row=0, column=1, padx=(0, 4))
        self._ports_entry.bind("<KeyRelease>", lambda _e: self._preview_range())
        self._profile_info = ctk.CTkLabel(self._options, text="", font=("Segoe UI", 9),
                                          text_color=c("text_muted"), width=150, anchor="w")
        self._profile_info.grid(row=0, column=2, padx=(4, 12))
        ctk.CTkLabel(self._options, text="Timeout (s):", **opt_label).grid(row=0, column=3,
                                                                          padx=(0, 6))
        self._timeout_menu = ctk.CTkOptionMenu(self._options, values=list(TIMEOUTS), width=70)
        self._timeout_menu.grid(row=0, column=4, padx=(0, 12))
        ctk.CTkLabel(self._options, text="Threads:", **opt_label).grid(row=0, column=5,
                                                                      padx=(0, 6))
        self._threads_menu = ctk.CTkOptionMenu(self._options, values=list(THREADS), width=80)
        self._threads_menu.grid(row=0, column=6, padx=(0, 12))
        self._resolve_chk = ctk.CTkCheckBox(self._options, text="Resolve names",
                                            font=("Segoe UI", 10))
        self._resolve_chk.grid(row=0, column=7, padx=(0, 10))
        self._identify_chk = ctk.CTkCheckBox(self._options, text="Identify models",
                                             font=("Segoe UI", 10))
        self._identify_chk.grid(row=0, column=8, padx=(0, 12))
        ctk.CTkLabel(self._options, text="Auto-rescan:", **opt_label).grid(
            row=0, column=9, padx=(0, 6))
        self._auto_menu = ctk.CTkOptionMenu(self._options, values=list(AUTO_RESCAN), width=90,
                                            command=lambda _v: self._on_auto_change())
        self._auto_menu.grid(row=0, column=10, padx=(0, 12))
        self._options.grid_remove()

        # -- results header ---------------------------------------------------- #
        header = ctk.CTkFrame(tab, fg_color="transparent")
        header.grid(row=2, column=0, sticky="ew", padx=4, pady=(2, 2))
        header.grid_columnconfigure(3, weight=1)
        self._filter_entry = ctk.CTkEntry(
            header, placeholder_text="Filter: IP, name, MAC, vendor, port…  (Ctrl+F)",
            width=320, height=28)
        self._filter_entry.grid(row=0, column=0, padx=(2, 2))
        self._filter_entry.bind("<KeyRelease>", lambda _e: self._apply_filter())
        ctk.CTkButton(header, text="×", width=28, height=28, fg_color="transparent",
                      hover_color=c("hover"), text_color=c("text_muted"),
                      font=("Segoe UI", 14, "bold"),
                      command=self._clear_filter).grid(row=0, column=1, padx=(0, 10))
        self._only_open_chk = ctk.CTkCheckBox(header, text="Only hosts with open ports",
                                              font=("Segoe UI", 10),
                                              command=self._apply_filter)
        self._only_open_chk.grid(row=0, column=2)
        self._summary_label = ctk.CTkLabel(header, text="", font=("Segoe UI", 10),
                                           text_color=c("text_secondary"))
        self._summary_label.grid(row=0, column=4, padx=(0, 8), sticky="e")

        # -- results ---------------------------------------------------------- #
        body = ctk.CTkFrame(tab, fg_color="transparent")
        body.grid(row=3, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(0, weight=1)
        self._tree = DeviceTree(body, on_select=self._on_device_selected,
                                on_open_device=self._open_device_web,
                                on_context=self._show_context)
        self._tree.grid(row=0, column=0, sticky="nsew", padx=(4, 0), pady=4)
        self._detail = DetailPanel(body)
        self._detail.grid(row=0, column=1, sticky="nsew", padx=(4, 4), pady=4)

    def _build_favorites_tab(self, tab) -> None:
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(tab, text="Right-click a device in the Scanner tab → “Add to favorites”. "
                               "Double-click a favorite to jump to it.",
                     text_color=c("text_muted"), font=("Segoe UI", 10)).grid(
            row=0, column=0, sticky="w", padx=8, pady=(6, 0))
        self._favs_list = tk.Listbox(tab, borderwidth=0, highlightthickness=0,
                                     font=("Segoe UI", 11), activestyle="none")
        self._favs_list.grid(row=1, column=0, sticky="nsew", padx=6, pady=6)
        self._favs_list.bind("<Double-1>", self._on_fav_double_click)
        self._favs_list.bind("<Delete>", self._on_fav_delete)
        self._style_native(theme.current())

    def _build_status_bar(self) -> None:
        status = ctk.CTkFrame(self, fg_color=c("surface"), corner_radius=0, height=28)
        status.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 8))
        status.grid_columnconfigure(1, weight=1)
        self._status_label = ctk.CTkLabel(status, text="", font=("Segoe UI", 9),
                                          text_color=c("text_secondary"), anchor="w")
        self._status_label.grid(row=0, column=0, padx=10, sticky="w")
        self._progress = ctk.CTkProgressBar(status, height=8, width=240,
                                            progress_color=c("primary"))
        self._progress.set(0)
        self._progress.grid(row=0, column=1, padx=10, sticky="w")
        self._progress.grid_remove()
        self._priv_label = ctk.CTkLabel(
            status, font=("Segoe UI", 9),
            text=("Administrator: full ARP sweep" if self._elevated
                  else "Not elevated: limited mode (MACs from the ARP cache) — "
                       "Settings › Restart as administrator"),
            text_color=c("text_muted") if self._elevated else c("state_warn"),
        )
        self._priv_label.grid(row=0, column=2, padx=10, sticky="e")

    def _style_native(self, pal) -> None:
        self._favs_list.configure(bg=pal.surface, fg=pal.text_primary,
                                  selectbackground=pal.selection,
                                  selectforeground=pal.selection_text)
        if hasattr(self, "_tree"):
            self._tree.apply_palette(pal)
        if hasattr(self, "_monitor"):
            self._monitor.apply_palette(pal)

    def _set_appearance(self, mode: str) -> None:
        ctk.set_appearance_mode(mode)
        theme.set_mode(ctk.get_appearance_mode())
        self._style_native(theme.current())
        self.settings.appearance = mode
        self.settings.save()

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
        target = s.last_range or local_network_hint()
        if target:
            self._range_entry.insert(0, target)
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
            self._toggle_options()
        self._preview_range()

    def _toggle_options(self) -> None:
        self._options_visible = not self._options_visible
        if self._options_visible:
            self._options.grid()
            self._options_btn.configure(text="Options ▴")
        else:
            self._options.grid_remove()
            self._options_btn.configure(text="Options ▾")

    def _on_adapter_change(self, choice: str) -> None:
        for adapter in self._adapters:
            if choice.startswith(adapter.name + " ·"):
                self._range_entry.delete(0, tk.END)
                self._range_entry.insert(0, adapter.sweep_range)
                break
        self._preview_range()

    def _selected_interface(self) -> str:
        choice = self._adapter_menu.get()
        for adapter in self._adapters:
            if choice.startswith(adapter.name + " ·"):
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
        try:
            ports = len(self._current_ports()) if profile.scan_ports else 0
            port_text = f"{ports} ports" if profile.scan_ports else "no port scan"
        except ValueError:
            ports, port_text = 0, "invalid ports"
        self._profile_info.configure(text=f"{profile.description[:60]}" if profile is not CUSTOM
                                     else port_text)
        if not text:
            self._range_info.configure(text="")
            return
        plan = plan_targets(text)
        if plan.is_empty:
            self._range_info.configure(text="invalid range", text_color=c("state_off"))
        else:
            self._range_info.configure(
                text=f"{plan.total} IPs" + (" (capped)" if plan.truncated else ""),
                text_color=c("text_muted"))

    def _use_local_network(self) -> None:
        hint = local_network_hint()
        if not hint:
            messagebox.showwarning(APP_NAME, "No active local network was found.")
            return
        self._range_entry.delete(0, tk.END)
        self._range_entry.insert(0, hint)
        self._adapter_menu.set(AUTO_ADAPTER)
        self._preview_range()

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
                          "Examples: 192.168.1.0/24, 192.168.1.1-100, 10.0.0.5")
            return
        try:
            request = self._build_request(target)
        except ValueError as exc:
            messagebox.showerror(APP_NAME, f"Invalid port list: {exc}")
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
            self._tree.clear()
            self._detail.set_device(None)
        self._partial = not clear
        self._stop_event = threading.Event()
        self._scanning = True
        self._outcome = ""
        self._last_range = request.target_range
        self._last_profile = get_profile(request.profile).name
        self._scan_started = time.monotonic()
        self._set_buttons(scanning=True)
        self._set_status(f"Scanning {request.target_range} ({self._last_profile})…")
        self._progress.grid()
        self._progress.configure(mode="indeterminate")
        self._progress.start()
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
        self._set_status("Stopping… waiting for in-flight probes")

    def _set_buttons(self, scanning: bool) -> None:
        state = "disabled" if scanning else "normal"
        for widget in (self._scan_btn, self._export_btn, self._report_btn,
                       self._range_entry, self._profile_menu, self._adapter_menu,
                       self._timeout_menu, self._threads_menu):
            widget.configure(state=state)
        self._stop_btn.configure(state="normal" if scanning else "disabled")

    def _poll_queue(self) -> None:
        try:
            for _ in range(MAX_EVENTS_PER_POLL):
                try:
                    event = self._events.get_nowait()
                except queue.Empty:
                    break
                self._handle_event(event)
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
            self._outcome = "Stopped by user"
        elif phase == PHASE_ERROR or ev.is_error:
            self._outcome = "Error"
            messagebox.showerror("Scan error", ev.message or "Unknown error")
        elif phase == WORKER_DONE:
            self._scan_finished()

    def _on_progress(self, ev: ScannerEvent) -> None:
        if self._stop_event.is_set():
            return
        text = PHASE_TEXT.get(ev.phase, ev.phase)
        if ev.phase == "Ports" and ev.total:
            if self._progress.cget("mode") != "determinate":
                self._progress.stop()
                self._progress.configure(mode="determinate")
            self._progress.set(ev.completed / ev.total)
            text += f"  {ev.completed * 100 // ev.total}%  ({ev.completed:,}/{ev.total:,} probes)"
        else:
            if self._progress.cget("mode") != "indeterminate":
                self._progress.configure(mode="indeterminate")
                self._progress.start()
            if ev.message:
                text += f" — {ev.message}"
        self._set_status(text + "…")

    def _on_device_event(self, device: Device) -> None:
        self._devices[device.ip_address] = device
        self._tree.set_alias(device.ip_address, self._label_for(device).get("name", ""))
        self._tree.upsert_device(device)
        self._update_summary()
        current = self._detail.device
        if current is not None and current.ip_address == device.ip_address:
            self._detail.set_device(device, self._label_for(device))

    def _scan_finished(self) -> None:
        self._scanning = False
        self._progress.stop()
        self._progress.grid_remove()
        self._set_buttons(scanning=False)
        if get_profile(self._profile_menu.get()) is not CUSTOM:
            self._ports_entry.configure(state="disabled")
        elapsed = time.monotonic() - self._scan_started
        complete = self._outcome == "Finished" and not self._partial
        if complete:
            self._mark_new_devices()
            self._track_changes()
        total = len(self._devices)
        status = (f"{self._outcome or 'Finished'}: {total} device"
                  f"{'s' if total != 1 else ''} in {self._last_range} "
                  f"({self._last_profile}, {elapsed:.1f} s)")
        self._update_summary()
        self._refresh_favorites()
        changes = len(self._new_devices) + len(self._gone)
        if self._auto_run and complete and changes:
            status = (f"Auto-rescan found changes: {len(self._new_devices)} new, "
                      f"{len(self._gone)} gone (Ctrl+D for details) — " + status)
            self.title(f"(!) {APP_NAME} {APP_VERSION}")
            self.bell()
            self.after(300, self.bell)
        elif not self._auto_run and self._outcome != "Stopped by user":
            self.bell()
        if complete and AUTO_RESCAN.get(self._auto_menu.get(), 0):
            self._schedule_auto()
            status += f" · next scan at {datetime.fromtimestamp(self._auto_due):%H:%M}"
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

    def _show_changes(self) -> None:
        """Dialog listing what appeared and disappeared since the last scan."""
        self.title(f"{APP_NAME} {APP_VERSION}")
        lines = []
        new = sorted(self._new_devices, key=ip_key)
        lines.append(f"NEW ({len(new)}) — never seen before")
        for ip in new:
            dev = self._devices.get(ip)
            name = self._label_for(dev).get("name") or (dev.hostname or dev.vendor if dev else "")
            lines.append(f"  + {ip:<16} {dev.mac_address or '-' if dev else '-':<18} {name or ''}")
        if not new:
            lines.append("  (none)")
        lines.append("")
        lines.append(f"GONE ({len(self._gone)}) — answered the previous scan, not this one")
        for info in sorted(self._gone, key=lambda i: ip_key(i["ip"])):
            label = self.settings.device_labels.get(info["key"], {}).get("name") or info["name"]
            mac = info["key"] if info["key"] != info["ip"] else "-"
            lines.append(f"  - {info['ip']:<16} {mac:<18} {label}")
        if not self._gone:
            lines.append("  (none)")
        if not self._devices:
            lines = ["Run a complete scan first; changes are measured against the",
                     "previous complete scan of the same range."]
        self._text_dialog("Changes since last scan", "\n".join(lines))

    def _text_dialog(self, title: str, text: str) -> None:
        window = ctk.CTkToplevel(self)
        window.title(title)
        window.geometry("620x380")
        window.transient(self)
        box = ctk.CTkTextbox(window, font=("Consolas", 11))
        box.pack(fill="both", expand=True, padx=10, pady=(10, 6))
        box.insert("1.0", text)
        box.configure(state="disabled")
        ctk.CTkButton(window, text="Close", width=90, command=window.destroy).pack(pady=(0, 10))
        window.after(50, window.focus_force)

    # -- custom names and notes ------------------------------------------ #
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
        window = ctk.CTkToplevel(self)
        window.title(f"Rename {ip}")
        window.geometry("440x230")
        window.resizable(False, False)
        window.transient(self)
        window.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(window, text=f"{ip}   {device.mac_address or ''}   "
                                  f"{device.hostname or device.vendor or ''}",
                     text_color=c("text_muted")).grid(row=0, column=0, columnspan=2,
                                                      padx=14, pady=(14, 8), sticky="w")
        ctk.CTkLabel(window, text="Name:").grid(row=1, column=0, padx=(14, 8), sticky="e")
        name = ctk.CTkEntry(window, placeholder_text="e.g. Living room TV")
        name.grid(row=1, column=1, padx=(0, 14), pady=4, sticky="ew")
        name.insert(0, current.get("name", ""))
        ctk.CTkLabel(window, text="Note:").grid(row=2, column=0, padx=(14, 8), sticky="e")
        note = ctk.CTkEntry(window, placeholder_text="optional")
        note.grid(row=2, column=1, padx=(0, 14), pady=4, sticky="ew")
        note.insert(0, current.get("note", ""))

        def save() -> None:
            self.set_label(ip, name.get(), note.get())
            window.destroy()

        buttons = ctk.CTkFrame(window, fg_color="transparent")
        buttons.grid(row=3, column=0, columnspan=2, pady=16)
        ctk.CTkButton(buttons, text="Save", width=90, command=save).pack(side="left", padx=4)
        ctk.CTkButton(buttons, text="Cancel", width=90, fg_color="transparent",
                      border_width=1, text_color=c("text_primary"),
                      command=window.destroy).pack(side="left", padx=4)
        name.bind("<Return>", lambda _e: save())
        note.bind("<Return>", lambda _e: save())
        window.after(50, lambda: (window.focus_force(), name.focus_set()))

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
        if self._detail.device is not None and self._detail.device.ip_address == ip:
            self._detail.set_device(device, self._label_for(device))
        self._refresh_favorites()

    # -- automatic rescans ------------------------------------------------ #
    def _on_auto_change(self) -> None:
        minutes = AUTO_RESCAN.get(self._auto_menu.get(), 0)
        self.settings.auto_rescan = minutes
        self.settings.save()
        self._cancel_auto()
        if minutes and self._devices and not self._scanning:
            self._schedule_auto()
            self._set_status(f"Auto-rescan every {minutes} min · next scan at "
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

    def _update_summary(self) -> None:
        total = len(self._devices)
        with_ports = sum(1 for d in self._devices.values() if open_ports(d))
        risky = sum(1 for d in self._devices.values() if d.risk_score >= 40)
        parts = [f"{total} device{'s' if total != 1 else ''}",
                 f"{with_ports} with open ports"]
        if risky:
            parts.append(f"{risky} at risk")
        if self._new_devices:
            parts.append(f"{len(self._new_devices)} new")
        if self._gone:
            parts.append(f"{len(self._gone)} gone")
        shown = self._tree.row_count()
        if shown != total:
            parts.append(f"{shown} shown")
        self._summary_label.configure(text="  ·  ".join(parts) if total else "")

    def _rescan_host(self, ip: str) -> None:
        if self._scanning:
            return
        try:
            request = self._build_request(ip)
        except ValueError as exc:
            messagebox.showerror(APP_NAME, f"Invalid port list: {exc}")
            return
        self._start_scan(request, clear=False)

    def _rescan_selected(self) -> None:
        ip = self._tree.get_selected_ip()
        if ip:
            self._rescan_host(ip)
        else:
            self._set_status("Select a device to rescan it.")

    # ------------------------------------------------------------------ #
    # Device actions
    # ------------------------------------------------------------------ #
    @property
    def _favorites(self) -> set[str]:
        return set(self.settings.favorites)

    def _on_device_selected(self, ip: str) -> None:
        device = self._devices.get(ip)
        self._detail.set_device(device, self._label_for(device))

    def _open_tool(self, name: str, values: dict, run: bool = False) -> None:
        self._tabview.set(TAB_TOOLS)
        if run:
            self._tools.run_tool(name, values)
        else:
            self._tools.select_tool(name, values)

    def _monitor_host(self, ip: str) -> None:
        dev = self._devices.get(ip)
        self._monitor.add_host(ip, label=(dev.hostname if dev else "") or ip)
        self._tabview.set(TAB_MONITOR)

    def _open_device_web(self, ip: str) -> None:
        dev = self._devices.get(ip)
        if not dev:
            return
        port = best_web_port(dev)
        if port:
            open_web(dev.ip_address, port)
        else:
            self._set_status(f"{ip} has no open web port (80, 443, 8080…).")

    def _open_rdp(self, ip: str) -> None:
        ok, message = open_remote_desktop(ip)
        if not ok:
            messagebox.showerror(APP_NAME, message)

    def _open_ssh(self, ip: str) -> None:
        try:
            if sys.platform == "win32":
                subprocess.Popen(["cmd", "/c", "start", "SSH", "ssh", ip])
            else:
                subprocess.Popen(["x-terminal-emulator", "-e", "ssh", ip])
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"Could not start ssh: {exc}")

    def _open_shares(self, ip: str) -> None:
        if sys.platform == "win32":
            os.startfile(f"\\\\{ip}")  # noqa: S606 - opens Explorer on the share list
        else:
            messagebox.showinfo(APP_NAME, f"Open smb://{ip} in your file manager.")

    def _wake(self, ip: str) -> None:
        dev = self._devices.get(ip)
        if not dev:
            return
        ok, message = wake_device(dev)
        if ok:
            self._set_status(f"Wake-on-LAN packet sent to {message}")
        else:
            messagebox.showerror("Wake-on-LAN", message)

    def _copy(self, text: str) -> None:
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status(f"Copied: {text[:80]}")

    def _toggle_detail(self) -> None:
        self._detail.toggle()

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

    # -- favorites ------------------------------------------------------- #
    def _toggle_favorite(self, ip: str) -> None:
        favorites = self._favorites ^ {ip}
        self.settings.favorites = sorted(favorites, key=ip_key)
        self.settings.save()
        self._tree.set_marks(favorites)
        self._refresh_favorites()

    def _refresh_favorites(self) -> None:
        self._favs_list.delete(0, tk.END)
        for ip in self.settings.favorites:
            dev = self._devices.get(ip)
            if dev:
                name = self._label_for(dev).get("name") or dev.hostname or dev.vendor or ""
                ports = dev.ports_compact()
                line = f"●  {ip}   {name}   [{ports}]"
            else:
                line = f"○  {ip}   (not seen in the current scan)"
            self._favs_list.insert(tk.END, line)

    def _fav_ip_at(self, index: int) -> str:
        return self.settings.favorites[index]

    def _on_fav_double_click(self, _event) -> None:
        sel = self._favs_list.curselection()
        if not sel:
            return
        ip = self._fav_ip_at(sel[0])
        if ip in self._devices:
            self._tabview.set(TAB_SCANNER)
            self._tree.select(ip)
            self._on_device_selected(ip)
        else:
            self._range_entry.delete(0, tk.END)
            self._range_entry.insert(0, ip)
            self._tabview.set(TAB_SCANNER)
            self._set_status(f"{ip} is not in the current results — press Scan to probe it.")

    def _on_fav_delete(self, _event) -> None:
        sel = self._favs_list.curselection()
        if sel:
            self._toggle_favorite(self._fav_ip_at(sel[0]))

    def _forget_known(self) -> None:
        if messagebox.askyesno(APP_NAME, "Forget every known device?\n\n"
                                         "The next scan becomes the new baseline."):
            self.settings.known_devices = {}
            self.settings.save()
            self._new_devices.clear()
            self._tree.set_marks(self._favorites, set())
            self._update_summary()

    # -- export / report ------------------------------------------------- #
    def _require_devices(self) -> bool:
        if not self._devices:
            messagebox.showwarning(APP_NAME, "There are no results yet. Run a scan first.")
            return False
        return True

    def _sorted_devices(self) -> list[Device]:
        return sorted(self._devices.values(), key=lambda d: ip_key(d.ip_address))

    def _export(self) -> None:
        if self._scanning or not self._require_devices():
            return
        path = filedialog.asksaveasfilename(
            title="Export results", defaultextension=".csv",
            filetypes=[("CSV (Excel)", "*.csv"), ("JSON", "*.json")],
            initialfile=f"ip_inspector_{datetime.now():%Y%m%d_%H%M}",
        )
        if not path:
            return
        try:
            written = export_devices(self._sorted_devices(), path,
                                     extra={"range": self._last_range,
                                            "profile": self._last_profile})
        except Exception as exc:  # noqa: BLE001
            logger.exception("export failed")
            messagebox.showerror(APP_NAME, f"Export failed:\n{exc}")
            return
        self._set_status(f"Exported {len(self._devices)} devices to {written}")

    def _report(self) -> None:
        if self._scanning or not self._require_devices():
            return
        path = filedialog.asksaveasfilename(
            title="Security report", defaultextension=".html",
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
            messagebox.showerror(APP_NAME, f"Could not build the report:\n{exc}")
            return
        self._set_status(f"Report saved to {written}")
        if messagebox.askyesno(APP_NAME, f"Report saved to:\n{written}\n\nOpen it now?"):
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
            params = "-m ip_inspector.main"
        cwd = str(Path(__file__).resolve().parents[2])
        try:
            code = ctypes.windll.shell32.ShellExecuteW(None, "runas", program, params, cwd, 1)
        except (AttributeError, OSError) as exc:
            messagebox.showerror(APP_NAME, f"Could not restart: {exc}")
            return
        if code > 32:
            self.destroy()

    def _show_about(self) -> None:
        messagebox.showinfo(
            "About",
            f"{APP_NAME} {APP_VERSION}\nby {APP_AUTHOR}\n\n"
            "Network and port scanner for your local network:\n"
            "host discovery, port scanning, device identification,\n"
            "security findings, diagnostics tools and monitoring.\n\n"
            "Only scan networks you own or are authorised to test.")

    def _show_help(self) -> None:
        messagebox.showinfo(
            "Quick guide",
            "SCANNER\n"
            "• Your local range is filled in. Pick an adapter or type a range:\n"
            "  192.168.1.0/24, 192.168.1.1-100, 10.0.0.5 (comma-separated ok).\n"
            "• Profile: Quick, Standard, Full (1-1024), IoT, Ping sweep, Custom.\n"
            "• Options (F8): custom ports, timeout, threads, name resolution.\n"
            "• Click a device for details; arrow shows services; double-click\n"
            "  opens its web page; right-click for RDP, SSH, shares, ping,\n"
            "  traceroute, full port scan, TLS, monitor, Wake-on-LAN…\n"
            "• NEW marks devices never seen before. ★ marks favorites.\n"
            "• F2 or right-click › Rename gives a device your own name and note.\n"
            "• Ctrl+D lists devices that appeared or disappeared since the\n"
            "  previous scan; Options › Auto-rescan repeats it and alerts.\n\n"
            "TOOLS: ping, traceroute, port check, DNS, WHOIS, TLS, HTTP\n"
            "headers, subnet calculator, ARP table, listening ports…\n\n"
            "MONITOR: watch hosts continuously and get alerted when they drop.\n\n"
            "SHORTCUTS\n"
            "F5 scan · Esc stop · Ctrl+R rescan device · Ctrl+F filter\n"
            "Ctrl+S export · Ctrl+P report · Ctrl+T tools · Ctrl+M monitor\n"
            "Ctrl+D changes · F2 rename · F8 options · F9 details panel\n\n"
            "COMMAND LINE: python -m ip_inspector 192.168.1.0/24 -p quick")

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def destroy(self) -> None:
        self._stop_event.set()
        self._cancel_auto()
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
    app = IPInspectorApp()
    app.mainloop()


if __name__ == "__main__":
    launch()
