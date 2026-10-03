"""CustomTkinter user interface for IP Inspector.

Six tabs share one window:

* **Network Scan**   - host discovery and TCP port probing.
* **Security Audit** - TLS, HTTP posture and per-device risk scoring.
* **Tools**          - DNS, WHOIS, traceroute, subnet maths, local exposure.
* **Quick Tools**    - visual traceroute, live latency graph, subnet maths, DNS.
* **Inventory**      - devices seen so far, compared against a baseline.
* **Monitor**        - continuous reachability checks and alerts.

This is the top of the stack: it reads from every layer below and is the
only one allowed to know about widgets. Presentation lives in
:mod:`ip_inspector.interface.theme`; this module owns behaviour and layout.

Threading model
---------------
Every long operation runs on a worker thread that pushes results onto a
:class:`queue.Queue`. The main thread drains it with ``after()``, which is
the only safe way to update tkinter from another thread and keeps the
window responsive during a full sweep.
"""

from __future__ import annotations

import csv
import json
import logging
from collections import deque
from datetime import datetime
import queue
import threading
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from .. import i18n
from ..actions.menu import (
    best_web_port,
    open_remote_desktop,
    open_web,
    wake_device,
)
from ..analysis.audit import audit_device, audit_http, inspect_tls, risk_score
from ..analysis.exposure import exposure_findings, exposure_score
from ..core.models import (
    SCAN_PORTS,
    Device,
    HttpReport,
    ScanRequest,
    ScannerEvent,
    SecurityFinding,
    SubnetInfo,
    TlsReport,
    ToolResult,
    TracerouteHop,
    latency_stats,
)
from ..core.network import NetworkScanner
from ..core.ping import ping_once
from ..core.utils import (
    MAX_TARGETS,
    NetworkAdapter,
    default_gateway,
    find_adapter,
    list_adapters,
    local_network_hint,
    plan_targets,
)
from ..nettools.monitor import Monitor, MonitorEvent
from ..nettools.tools import (
    DNS_RECORD_TYPES,
    dns_lookup,
    dns_summary,
    email_security_records,
    listening_ports,
    local_exposure_report,
    ping_host,
    reverse_dns,
    split_subnet,
    subnet_details,
    subnet_info,
    traceroute,
    whois_key_fields,
    whois_lookup,
    zone_transfer,
)
from . import theme

logger = logging.getLogger(__name__)

#: Product branding shown in the window and the bottom-right footer.
APP_NAME = "IP Inspector"
APP_AUTHOR = "Matthew Garay"

#: Application logo. It ships beside the package, not beside this module, so
#: the path climbs two levels to reach ``assets/``; inside a frozen .exe the
#: files live under ``sys._MEIPASS`` instead. A missing file means "no logo"
#: rather than failing, which would hide a wrong path here.
def _logo_path() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "assets" / "logo.png"
    return Path(__file__).resolve().parent.parent / "assets" / "logo.png"


LOGO_PATH = _logo_path()
#: Height in pixels the logo is scaled to; the source is 1024x559, far too
#: large to drop into a header unscaled.
LOGO_HEIGHT = 52

#: Adapters offered as a tab in the header before the control falls back to
#: the dropdown, which lists everything but splits the header in two.
MAX_INTERFACE_TABS = 4
#: Longest an adapter name may be before its tab is trimmed.
TAB_NAME_WIDTH = 16

#: Device table layout: (i18n key, width, anchor, sort key, font style).
#: Headers are translated on every render, so a language switch takes
#: effect without rebuilding the module.
#: Device table layout.
#: (i18n key, width px, anchor, monospace, sort key)
#: ``monospace`` is mandatory on the technical columns: addresses, MACs,
#: TTL, latency and the port list, where character alignment carries meaning.
DEVICE_COLUMNS: tuple[tuple[str, int, str, bool, str], ...] = (
    ("col.ip",        110, "w",      True,  "ip"),
    ("col.status",     20, "center", False, "status"),
    ("col.icon",       24, "center", False, "type"),
    ("col.type",       86, "w",      False, "type"),
    ("col.hostname",  100, "w",      False, "hostname"),
    ("col.mac",       114, "w",      True,  "mac"),
    ("col.vendor",     94, "w",      False, "vendor"),
    ("col.model",      94, "w",      False, "model"),
    ("col.vpn",        36, "center", False, "vpn"),
    ("col.ttl",        34, "center", True,  "ttl"),
    ("col.latency",    48, "center", True,  "latency"),
    ("col.method",     52, "center", False, "method"),
    ("col.risk",       42, "center", True,  "risk"),
    ("col.alerts",     48, "center", False, "alerts"),
    # The densest column in the grid, so it gets the widest declared box: the
    # cell is one line tall and its wrap length is fixed from this number, so
    # a narrow declaration here is what clips the service list. 200px is the
    # measured point where six open ports plus a count still fit on one line.
    ("col.ports",     200, "w",      True,  "ports"),
)

#: Index of the column that renders the coloured status dot.
STATUS_DOT_COLUMN = 1

#: Index of the column that renders the device-type pictogram. The icon leads
#: the label beside it so a row is recognisable before it is read.
TYPE_ICON_COLUMN = 2

#: Index of the column that renders the device-type icon. The icon leads the
#: row on purpose: a page of hosts is scanned by shape long before it is read
#: by name, and the glyph is the only cell that survives being 40px wide.
DEVICE_TYPE_COLUMN = 2

#: Audit table layout: (i18n key, width px, anchor, monospace, sort key).
#: The detail column is plain text; the rest stay narrow and scannable.
FINDING_COLUMNS: tuple[tuple[str, int, str, bool, str], ...] = (
    ("col.severity",  84, "center", True,  "severity"),
    ("col.finding",  240, "w",      False, "finding"),
    ("col.detail",   470, "w",      False, "detail"),
    ("col.target",   118, "w",      True,  "target"),
)


#: Monitor table layout: (i18n key, width px, anchor, monospace, sort key).
MONITOR_COLUMNS: tuple[tuple[str, int, str, bool, str], ...] = (
    ("mon.col.status",   18, "center", False, "status"),
    ("mon.col.host",    150, "w",      True,  "host"),
    ("mon.col.spark",  104, "center", False, ""),
    ("mon.col.latency",  66, "center", True,  "latency"),
    ("mon.col.avg",      62, "center", True,  "avg"),
    ("mon.col.uptime",   78, "center", True,  "uptime"),
    ("mon.col.checks",   62, "center", True,  "checks"),
    ("mon.col.since",    78, "center", False, "since"),
)

#: Inventory change table: (i18n key, width px, anchor, monospace, sort key).
INVENTORY_COLUMNS: tuple[tuple[str, int, str, bool, str], ...] = (
    ("inv.new",        78, "center", False, "kind"),
    ("inv.mac",       140, "w",      True,  "mac"),
    ("col.ip",        112, "w",      True,  "ip"),
    ("inv.detail",    330, "w",      False, "detail"),
    ("inv.vendorcol", 150, "w",      False, "vendor"),
    ("inv.typecol",   110, "w",      False, "type"),
    ("inv.firstseen", 132, "w",      False, "first_seen"),
)

#: Severity order used when sorting the findings table.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

#: Canonical severity code -> catalogue key, for the findings table.
SEVERITY_KEY_BY_CODE: dict[str, str] = {
    "critical": "sev.critical", "high": "sev.high", "medium": "sev.medium",
    "low": "sev.low", "info": "sev.info",
}

#: Sort keys shown in the sort indicator.
SORT_KEY_LABELS: dict[str, str] = {
    "ip": "col.ip", "status": "col.status", "hostname": "col.hostname",
    "mac": "col.mac", "vendor": "col.vendor", "model": "col.model",
    "type": "col.type", "vpn": "col.vpn", "ttl": "col.ttl",
    "latency": "col.latency", "method": "col.method", "risk": "col.risk",
    "alerts": "col.alerts", "ports": "col.ports",
}

#: Main-thread poll interval for the event queue, in milliseconds.
POLL_INTERVAL_MS = 120

#: Hop limits offered by the visual traceroute.
TRACE_HOP_CHOICES: tuple[int, ...] = (8, 12, 20, 30)

#: Latency scale of the traceroute bars, in milliseconds. A hop above it
#: paints a full bar, which keeps two traces visually comparable.
TRACE_SCALE_MS = 200.0

#: Latency thresholds colouring a hop bar: fast, slow, very slow.
TRACE_FAST_MS = 25.0
TRACE_SLOW_MS = 90.0

#: Width of the traceroute latency bar track, in pixels.
TRACE_BAR_WIDTH = 130

#: Cadences offered by the live latency graph, in seconds.
LATENCY_INTERVALS: tuple[float, ...] = (0.5, 1.0, 2.0, 5.0)

#: Probes kept by the live graph: two minutes at the slowest cadence, which
#: is long enough for an intermittent problem to show its shape.
LATENCY_SAMPLES = 120

#: Timeout of a single probe, in seconds. Never shorter than the cadence, so
#: a packet lost to a firewall does not make the graph run behind.
LATENCY_TIMEOUT_S = 2.0

#: Column of the monitor table that holds the mini chart.
MONITOR_SPARK_COLUMN = 2

#: Milliseconds of quiet after the last keystroke before the host count is
#: recalculated. Long enough not to redraw per character, short enough to
#: feel immediate.
TARGET_PREVIEW_DELAY_MS = 220

#: Fields of the subnet calculator, in display order.
SUBNET_FIELD_KEYS: tuple[str, ...] = (
    "sub.network", "sub.mask", "sub.wildcard", "sub.broadcast", "sub.first",
    "sub.last", "sub.total", "sub.usable", "sub.scope",
)

#: Block counts the calculator can split a network into.
SUBNET_SPLIT_CHOICES: tuple[int, ...] = (1, 2, 4, 8, 16, 32)

#: WHOIS field returned by ``tools.whois_key_fields`` -> catalogue key.
WHOIS_LABEL_KEYS: dict[str, str] = {
    "domain": "qt.whois.domain",
    "org": "qt.whois.org",
    "country": "qt.whois.country",
    "created": "qt.whois.created",
    "updated": "qt.whois.updated",
    "expires": "qt.whois.expires",
    "status": "qt.whois.status",
    "registrar": "qt.whois.registrar",
    "abuse": "qt.whois.abuse",
    "nameservers": "qt.whois.nameservers",
}

#: Tab order. Kept as catalogue keys so the visible tab can be restored
#: after a language switch rebuilds the tab view with new labels.
TAB_KEYS: tuple[str, ...] = (
    "tab.scan", "tab.audit", "tab.tools", "tab.quick", "tab.inventory", "tab.monitor",
)

#: Minimum milliseconds between full table repaints during a scan.
REPAINT_INTERVAL_MS = 400

#: New rows added per throttled paint. One row is a frame plus a label per
#: column, so appending a whole sweep's worth at once is what locked the
#: window up; spreading the new rows over the following ticks keeps the
#: window drawing and responsive while the rest arrives.
ROW_BUDGET_PER_PAINT = 40

#: Opening size of the window, and the smallest it may be dragged to.
WINDOW_SIZE = (1480, 900)
WINDOW_MINIMUM = (1180, 720)


def centred_geometry(
    screen: tuple[int, int], size: tuple[int, int], minimum: tuple[int, int]
) -> str:
    """
    Geometry string that places a window of ``size`` in the middle of ``screen``.

    The window shrinks to fit and the offset never goes negative: a 900px
    tall window on a 768px screen would hang off the bottom edge, and a
    negative coordinate is how the title bar ends up somewhere unusable.
    The minimum only applies while it still fits, so a tiny display gets the
    whole screen rather than a window too small to work in.
    """
    screen_width, screen_height = screen
    width = max(min(minimum[0], screen_width), min(size[0], screen_width))
    height = max(min(minimum[1], screen_height), min(size[1], screen_height))
    x = max(0, (screen_width - width) // 2)
    y = max(0, (screen_height - height) // 2)
    return f"{width}x{height}+{x}+{y}"

#: Sort state.
_SORT_KEYS = ("ip", "status", "hostname", "mac", "vendor", "type", "vpn", "risk", "ports")


class IPInspectorApp(ctk.CTk):
    """Main window: KPI dashboard, tabbed workspace, table and branding."""

    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self._centre_on_screen(WINDOW_SIZE, WINDOW_MINIMUM)
        self.minsize(*WINDOW_MINIMUM)

        i18n.initialize()
        theme.set_mode(ctk.get_appearance_mode())
        self._scanner = NetworkScanner(event_queue=queue.Queue())
        self._aux_queue: queue.Queue = queue.Queue()
        self.monitor = Monitor(queue.Queue())
        self._monitor_events: list[MonitorEvent] = []

        self._devices: dict[str, Device] = {}
        self._findings: list[SecurityFinding] = []

        #: Handler that paints the result of the running tool, set by
        #: :meth:`_run_tool` and reset once the worker answers.
        self._tool_handler = None

        #: Quick-tools state, kept so a language switch can repaint it.
        self._quick_inputs: dict[str, str] = {}
        self._hops: list[TracerouteHop] = []
        self._subnet_data: SubnetInfo | None = None
        self._subnet_plan: str = ""
        self._lookup_text: str = ""
        self._latency_interval = LATENCY_INTERVALS[1]

        #: Live ping graph. The worker thread owns the cadence and hands
        #: samples to the main thread through ``_aux_queue``.
        self._latency_host: str = ""
        self._latency_samples: deque[float | None] = deque(maxlen=LATENCY_SAMPLES)
        self._latency_running = False
        self._latency_stop = threading.Event()

        self._scanning = False
        self._busy = False
        #: Adapter the scan is pinned to; empty means automatic.
        self._interface_name: str = ""
        #: Pending debounce for the target host count.
        self._preview_job: str | None = None
        #: Range text carried across a toolbar rebuild.
        self._saved_range: str = ""
        #: Scaled logo, held so Tk does not collect it while in use.
        self._logo_photo: tk.PhotoImage | None = None
        #: Exactly one of the two interface controls exists at a time: tabs
        #: for an ordinary machine, the dropdown when there are too many.
        self._interface_tabs: ctk.CTkSegmentedButton | None = None
        self._interface_menu: ctk.CTkOptionMenu | None = None
        self._interface_labels: dict[str, str] = {}
        self._sort_key = "ip"
        self._sort_reverse = False
        self._filter = ""
        self._last_paint = 0.0
        self._paint_job: str | None = None
        #: Last cell contents per row key, so the throttled renderer can
        #: detect changes without asking the widgets (cget is slow).
        self._row_cache: dict[str, list[str]] = {}
        #: Maps each known device address to the pictogram its row should draw.
        #: Kept beside the devices because a row can change class as the scan
        #: enriches it (a bare host becomes a camera once ONVIF answers).
        self._icon_kinds: dict[str, str] = {}

        #: Addresses that have arrived since the last paint. The renderer
        #: walks this instead of the whole table, so the cost of a repaint
        #: tracks what changed rather than how much has been found.
        self._dirty: set[str] = set()
        #: Rows still owed a widget, because a paint hit its budget. They are
        #: carried into the next tick instead of blocking this one.
        self._pending_rows: list[Device] = []
        self._sections: list[ctk.CTkBaseClass] = []

        self.grid_columnconfigure(0, weight=1)
        # Four bands, and only the tab strip flexes: header, tabs, status strip
        # and footer are fixed-height chrome, so the table takes every pixel
        # that is left over. The window is a work surface, not a document.
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=0)
        self.grid_rowconfigure(3, weight=0)

        self._bind_shortcuts()
        self._build_header()
        self._build_tabs()
        self._build_status_bar()
        self._build_footer()
        self._prefill_inputs()
        self._set_title()

    # ------------------------------------------------------------------
    # Chrome
    # ------------------------------------------------------------------
    def _centre_on_screen(
        self, size: tuple[int, int], minimum: tuple[int, int]
    ) -> None:
        """
        Open in the middle of the screen instead of the system's corner.

        A tool that stays open for minutes is easier to come back to when it
        appears where the eye already is, and a network scanner is exactly
        that kind of tool.
        """
        self.geometry(centred_geometry(
            (self.winfo_screenwidth(), self.winfo_screenheight()),
            size, minimum,
        ))

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent")
        self._sections.append(header)
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=(16, 6))
        header.grid_columnconfigure(1, weight=1)

        brand = ctk.CTkFrame(header, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="w")
        logo = self._logo_label(brand)
        if logo is not None:
            logo.grid(row=0, column=0, rowspan=2, padx=(0, 10), sticky="w")
        names = ctk.CTkFrame(brand, fg_color="transparent")
        names.grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(
            names, text=APP_NAME, font=ctk.CTkFont(size=22, weight="bold")
        ).pack(anchor="w")
        ctk.CTkLabel(
            names,
            text=i18n.t("app.tagline"),
            font=ctk.CTkFont(size=11),
        ).pack(anchor="w")

        self._build_interface_selector(header)

        self._language_button = ctk.CTkSegmentedButton(
            header, values=["EN", "ES"], width=98, height=30,
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_language_change,
        )
        self._language_button.set(i18n.get_language().upper())
        self._language_button.grid(row=0, column=3, sticky="e", padx=(10, 0))
        self._language_button.configure(
            selected_color=theme.current().primary,
            selected_hover_color=theme.current().primary_hover,
        )

    def _logo_label(self, parent: ctk.CTkBaseClass) -> tk.Label | None:
        """
        The application logo, scaled to sit beside the name in the header.

        Loaded with Tk's own PNG reader and shown in a plain ``tk.Label``.
        ``CTkImage`` would need Pillow, which this project does not depend on,
        and a raw ``CTkLabel`` warns on every build that the image will not
        rescale on a HighDPI screen. The image is already scaled here, so
        there is nothing left for the toolkit to do.

        The scaled photo is kept on the instance: Tk holds no reference of its
        own, so without it the logo is collected and the label renders empty.
        A missing or unreadable file means no logo, never a window that fails
        to open.
        """
        if not LOGO_PATH.is_file():
            return None
        try:
            photo = tk.PhotoImage(file=str(LOGO_PATH))
            factor = max(1, round(photo.height() / LOGO_HEIGHT))
            if factor > 1:
                photo = photo.subsample(factor)
        except (tk.TclError, OSError):
            return None
        self._logo_photo = photo
        # The artwork is transparent, so the label has to be painted in
        # whatever is behind it. The window's own background is read from the
        # widget rather than from the palette: a rebuild builds the header
        # before the new appearance mode is applied, and a palette read here
        # would leave a white plate around the logo in dark mode.
        return tk.Label(parent, image=photo, bd=0, bg=self.cget("bg"))

    def _build_interface_selector(self, master: ctk.CTkBaseClass) -> None:
        """
        Pin the scan to one network adapter, as tabs in the header.

        A machine with a VPN, a hypervisor and Wi-Fi answers on several
        subnets at once, and the default interface is rarely the one the
        operator means. Selecting one also offers its own range, which is
        the quickest way to stop sweeping the wrong segment.

        The adapters become tabs rather than a dropdown: a menu boxed in the
        middle of the header cut the window in two, and the choice is one
        click either way.
        """
        self._adapters: list[NetworkAdapter] = list_adapters()
        # Only adapters that can host a sweep of their own get a tab. A
        # developer machine lists a dozen disconnected bridges and virtual
        # switches, and none of them is ever the one being asked for.
        usable = [adapter for adapter in self._adapters if adapter.is_scannable]
        if len(usable) < MAX_INTERFACE_TABS:
            self._build_interface_tabs(master, usable)
        else:
            self._build_interface_menu(master)

    def _build_interface_tabs(
        self, master: ctk.CTkBaseClass, adapters: list[NetworkAdapter]
    ) -> None:
        """One tab per usable adapter, plus automatic, in a single row."""
        self._interface_labels: dict[str, str] = {i18n.t("iface.auto.short"): ""}
        for adapter in adapters:
            label = self._tab_label(adapter)
            if label in self._interface_labels:      # two NICs, one short name
                label = f"{label} {adapter.address.rsplit('.', 1)[-1]}"
            self._interface_labels[label] = adapter.name

        self._interface_tabs = ctk.CTkSegmentedButton(
            master, values=list(self._interface_labels), height=30,
            font=ctk.CTkFont(size=11), command=self._on_interface_change,
        )
        palette = theme.current()
        self._interface_tabs.configure(
            selected_color=palette.primary,
            selected_hover_color=palette.primary_hover,
            unselected_color=palette.surface,
            unselected_hover_color=palette.selection,
            text_color=palette.text_primary,
        )
        # A language switch rebuilds the header, so the choice is reapplied
        # from the stored name rather than from the widget that is gone.
        self._interface_tabs.set(
            self._tab_label_for(self._interface_name)
            or i18n.t("iface.auto.short"))
        self._interface_tabs.grid(row=0, column=2, sticky="e", padx=(10, 0))

    def _build_interface_menu(self, master: ctk.CTkBaseClass) -> None:
        """
        Dropdown fallback for a machine with more adapters than tabs fit.

        It still lists every adapter, marked with why the unusable ones
        cannot host a sweep, which is what makes a missing entry explicable.
        """
        block = ctk.CTkFrame(master, fg_color="transparent")
        block.grid(row=0, column=2, sticky="e")
        theme.caption(block, i18n.t("iface.caption")).grid(row=0, column=0, sticky="e")

        labels = [i18n.t("iface.auto")] + [
            self._adapter_label(adapter) for adapter in self._adapters
        ]
        self._interface_menu = self._option_menu(block, labels, 300, anchor="e")
        self._interface_menu.set(self._label_for(self._interface_name) or labels[0])
        self._interface_menu.configure(command=self._on_interface_change)
        self._interface_menu.grid(row=1, column=0, sticky="e", pady=(2, 0))

    def _tab_label(self, adapter: NetworkAdapter) -> str:
        """Short name for a tab: the adapter name, trimmed to fit."""
        name = adapter.name.strip()
        if len(name) <= TAB_NAME_WIDTH:
            return name
        return name[: TAB_NAME_WIDTH - 1].rstrip() + "…"

    def _tab_label_for(self, name: str) -> str:
        """Tab label of one adapter, or "" when it is not on offer."""
        return next((label for label, adapter in self._interface_labels.items()
                     if adapter == name), "")

    def _label_for(self, name: str) -> str:
        """Dropdown label of one adapter, or an empty string when it is gone."""
        return next((self._adapter_label(a) for a in self._adapters
                     if a.name == name), "")

    def _adapter_label(self, adapter: NetworkAdapter) -> str:
        """One line for the dropdown: name, address and what it is."""
        marks = []
        if adapter.is_virtual:
            marks.append(i18n.t("iface.virtual"))
        if not adapter.is_up:
            marks.append(i18n.t("iface.down"))
        suffix = f"  [{', '.join(marks)}]" if marks else ""
        return adapter.label + suffix

    def _selected_interface(self) -> str:
        """Adapter name chosen in the dropdown, or empty for automatic."""
        return self._interface_name

    def _on_interface_change(self, _value: str = "") -> None:
        """Pin the scan to the chosen adapter and offer its own range."""
        if self._interface_tabs is not None:
            self._interface_name = self._interface_labels.get(
                self._interface_tabs.get(), "")
        else:
            chosen = self._interface_menu.get()
            self._interface_name = next(
                (a.name for a in self._adapters
                 if self._adapter_label(a) == chosen), "")

        if not self._interface_name:
            self._set_range(local_network_hint())
            return

        adapter = find_adapter(self._interface_name)
        if adapter is None:
            self._set_phase(i18n.t("iface.gone", name=self._interface_name))
            return
        if not adapter.is_scannable:
            self._set_phase(i18n.t("iface.unusable", name=adapter.name))
            return
        self._set_range(local_network_hint(self._interface_name))
        self._set_phase(i18n.t("iface.selected", name=adapter.name,
                               network=adapter.sweep_range or adapter.address))

    def _build_tabs(self) -> None:
        # The tab strip sits on row 1 and takes the whole flexible band, so the
        # table below it is the only thing that grows.
        self.grid_rowconfigure(1, weight=1)
        self._tabs = ctk.CTkTabview(self)
        self._tabs.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 6))

        for key in TAB_KEYS:
            self._tabs.add(i18n.t(key))
        for key in TAB_KEYS:
            self._build_tabs_one(key)
        self._style_tab_strip()

    def _style_tab_strip(self) -> None:
        """
        Make the tab strip recede, and reveal it on hover.

        Scanning is the job, so the five secondary destinations must not
        compete with it for attention. The strip keeps its place in the
        layout -- nothing reflows when it fades -- and returns the moment the
        pointer comes near it, so nothing is lost to a user who wants it.
        """
        palette = theme.current()
        self._tabs.configure(
            segmented_button_fg_color=palette.surface,
            segmented_button_selected_color=palette.selection,
            segmented_button_selected_hover_color=palette.selection,
            segmented_button_unselected_color=palette.surface,
            segmented_button_unselected_hover_color=palette.hover,
            text_color=palette.text_primary,
            corner_radius=4,
        )
        # The text colours of the strip live on its own segmented button, which
        # does not expose them as tabview options, so they are set on the
        # buttons themselves. Muted while idle, full contrast on hover.
        self._tab_buttons = dict(
            self._tabs._segmented_button._buttons_dict
        )
        strip = self._tabs._segmented_button
        for button in self._tab_buttons.values():
            button.configure(
                text_color=palette.text_muted,
                font=ctk.CTkFont(size=10, weight="bold"),
            )
        # The strip's own wrapper does not implement bind() on this version of
        # customtkinter, so the hover is wired to the underlying tk canvas,
        # which does. A failure here is cosmetic and must not stop the window.
        for holder in (getattr(strip, "_parent_canvas", None),
                       getattr(strip, "_canvas", None),
                       getattr(strip, "_parent_frame", None)):
            if holder is None:
                continue
            try:
                holder.bind("<Enter>", self._reveal_tabs, add="+")
                holder.bind("<Leave>", self._conceal_tabs, add="+")
                break
            except Exception:  # noqa: BLE001 - try the next candidate
                continue
        self._conceal_tabs()

    def _set_tab_text_colour(self, colour: str) -> None:
        """Tint the idle tab captions, keeping the selected one highlighted."""
        selected = None
        try:
            selected = self._tabs.get()
        except Exception:  # noqa: BLE001 - nothing selected yet
            pass
        for name, button in self._tab_buttons.items():
            try:
                button.configure(
                    text_color=theme.current().primary
                    if name == selected else colour
                )
            except Exception:  # noqa: BLE001 - a dead widget is not fatal
                pass

    def _reveal_tabs(self, _event=None) -> str:
        self._set_tab_text_colour(theme.current().text_primary)
        return "break"

    def _conceal_tabs(self, _event=None) -> str:
        self._set_tab_text_colour(theme.current().text_muted)
        return "break"

    def _build_tabs_one(self, key: str) -> None:
        """Build one tab, named by its catalogue key rather than its label."""
        tab = self._tabs.tab(i18n.t(key))
        {
            "tab.scan": self._build_scan_tab,
            "tab.audit": self._build_audit_tab,
            "tab.tools": self._build_tools_tab,
            "tab.quick": self._build_quick_tab,
            "tab.inventory": self._build_inventory_tab,
            "tab.monitor": self._build_monitor_tab,
        }[key](tab)

    def _tab_index(self) -> int:
        """Position of the visible tab, so a rebuild can restore it."""
        try:
            return [i18n.t(key) for key in TAB_KEYS].index(self._tabs.get())
        except ValueError:
            return 0

    def _select_tab(self, key: str) -> None:
        """
        Show the tab named by a catalogue key.

        ``CTkTabview.set`` forgets every other tab 100 ms later, so selecting
        one straight after a rebuild would be undone by that deferred pass;
        waiting it out keeps the last selection standing. If something else
        has already chosen a tab in the meantime, that choice wins.
        """
        name = i18n.t(key)
        untouched = {i18n.t(TAB_KEYS[0]), name}

        def apply() -> None:
            if self._tabs.get() in untouched:
                self._tabs.set(name)

        self.after(120, apply)

    # ------------------------------------------------------------------
    # Tab 1: network scan
    # ------------------------------------------------------------------
        self._sections.append(self._tabs)

    def _build_scan_tab(self, parent: ctk.CTkBaseClass) -> None:
        # Rows: 0 toolbar, 1 filter bar, 2 results table. The profile row went
        # away with the port selector: one fixed sweep replaced three modes and
        # a list to edit, so there is no longer a setting to show here.
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)

        self._build_scan_toolbar(parent)
        self._build_filter_bar(parent)

        holder = theme.panel(parent)
        holder.grid(row=2, column=0, sticky="nsew", pady=(6, 0))
        holder.grid_columnconfigure(0, weight=1)
        holder.grid_rowconfigure(0, weight=1)

        self._table = theme.ResultTable(
            holder,
            tuple((i18n.t(k), w, a, m, s) for k, w, a, m, s in DEVICE_COLUMNS),
            on_sort=self._on_sort,
            dot=STATUS_DOT_COLUMN,
            icon=TYPE_ICON_COLUMN,
            icons=self._icon_kinds,
        )
        self._table.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        self._table.bind_context_menu(self._on_context_menu)

        self._empty_hint = ctk.CTkLabel(
            self, text=i18n.t("empty.hint"), font=ctk.CTkFont(size=14),
            text_color=theme.current().text_secondary,
        )
        self._empty_hint.grid(row=1, column=0, sticky="nw", padx=20, pady=24)

    def _build_scan_toolbar(self, parent: ctk.CTkBaseClass) -> None:
        bar = ctk.CTkFrame(parent, fg_color="transparent")
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        for index, (caption_key, width, placeholder_key, attr) in enumerate((
            ("label.range", 300, "ph.range", "_range_entry"),
        )):
            block = ctk.CTkFrame(bar, fg_color="transparent")
            block.grid(row=0, column=index * 2, sticky="w", padx=(12, 6), pady=10)
            # The range is the one field the app cannot run without, so it is
            # marked as required.
            caption = i18n.t(caption_key)
            if attr == "_range_entry":
                caption = f"{caption} *"
            theme.caption(block, caption).grid(row=0, column=0, sticky="w")
            entry = ctk.CTkEntry(
                block, placeholder_text=i18n.t(placeholder_key), width=width,
                height=36, font=ctk.CTkFont(size=13),
                border_width=2,
                border_color=theme.current().field_border,
            )
            entry.grid(row=1, column=0, sticky="w", pady=(3, 0))
            setattr(self, attr, entry)

            if attr == "_range_entry":
                # The host count is shown before anything is scanned, so a
                # mistyped block is caught while it is still being typed.
                self._target_preview = ctk.CTkLabel(
                    block, text="", anchor="w", font=ctk.CTkFont(size=11),
                    text_color=theme.current().text_secondary,
                )
                self._target_preview.grid(row=2, column=0, sticky="w", pady=(2, 0))
                entry.bind("<KeyRelease>", self._schedule_target_preview)
                # Red border the moment the text cannot be scanned, so the
                # error is visible in the field rather than only in the
                # status line, which is easy to miss mid-sweep.
                entry.bind(
                    "<FocusOut>",
                    lambda _e: self._paint_field_state(self._range_entry),
                )

        actions = ctk.CTkFrame(bar, fg_color="transparent")
        actions.grid(row=0, column=2, sticky="e", padx=(6, 12))
        self._start_button = theme.primary_button(
            actions, "\u25B6  " + i18n.t("btn.start"), self._on_start_scan,
            width=150, height=38,
        )
        self._start_button.grid(row=0, column=0, padx=(0, 6))
        self._stop_button = theme.secondary_button(
            actions, "\u25A0  " + i18n.t("btn.stop"), self._on_stop_scan, 100, 38,
        )
        self._stop_button.configure(state="disabled")
        self._stop_button.grid(row=0, column=1)
        # Report and export start disabled and stay that way until a scan has
        # actually produced rows. They used to enable as soon as the scan
        # stopped, which offered the user an empty PDF whenever a sweep
        # finished with nothing found.
        self._report_button = theme.secondary_button(
            actions, i18n.t("report.pdf"), self._on_report, 120, 38,
        )
        self._report_button.configure(state="disabled")
        self._report_button.grid(row=0, column=2, padx=4)
        self._report_html_button = theme.secondary_button(
            actions, i18n.t("report.html"), self._on_report_html, 124, 38,
        )
        self._report_html_button.configure(state="disabled")
        self._report_html_button.grid(row=0, column=3, padx=4)
        # Plain data next to the printable reports: a technician filling in a
        # handover sheet wants the rows, not a paginated PDF.
        self._export_csv_button = theme.secondary_button(
            actions, i18n.t("export.csv"), lambda: self._on_export_data("csv"),
            64, 38,
        )
        self._export_csv_button.configure(state="disabled")
        self._export_csv_button.grid(row=0, column=4, padx=4)
        self._export_json_button = theme.secondary_button(
            actions, i18n.t("export.json"), lambda: self._on_export_data("json"),
            68, 38,
        )
        self._export_json_button.configure(state="disabled")
        self._export_json_button.grid(row=0, column=5, padx=4)

        # The port switch is gone along with the port field: ports are always
        # swept, so there was nothing left for it to turn off.

    def _schedule_target_preview(self, _event=None) -> None:
        """Recount the hosts once the typing settles, not on every keypress."""
        if self._preview_job:
            self.after_cancel(self._preview_job)
        self._preview_job = self.after(
            TARGET_PREVIEW_DELAY_MS, self._update_target_preview)

    def _update_target_preview(self) -> None:
        """
        Show exactly how many addresses the typed range evaluates to.

        The maths runs on the main thread but touches no socket and expands
        nothing, so it costs microseconds even for a block that would be far
        too large to scan.
        """
        self._preview_job = None
        try:
            text = self._range_entry.get()
        except tk.TclError:
            return

        plan = plan_targets(text)
        if plan.is_empty:
            if plan.problems:
                message = i18n.t("target.problem", items=", ".join(plan.problems))
            else:
                message = i18n.t("target.empty")
            colour = (theme.warning() if plan.problems
                      else theme.current().text_secondary)
        elif plan.truncated:
            message = i18n.t("target.capped", asked=f"{plan.total:,}",
                             limit=f"{MAX_TARGETS:,}")
            colour = theme.vpn()
        else:
            parts = [i18n.t("target.count", count=f"{plan.total:,}")]
            if plan.first != plan.last:
                parts.append(f"{plan.first} – {plan.last}")
            if plan.excluded:
                parts.append(i18n.t("target.excluded", count=plan.excluded))
            if plan.problems:
                # Valid chunks are still swept, so the line says what was
                # dropped instead of refusing a range that mostly parses.
                parts.append(i18n.t("target.ignoring",
                                    items=", ".join(plan.problems)))
            message = "   ·   ".join(parts)
            colour = (theme.warning() if plan.problems
                      else theme.current().text_secondary)
        self._target_preview.configure(text=message, text_color=colour)

    def _build_filter_bar(self, parent: ctk.CTkBaseClass) -> None:
        """Filter input plus the current sort indicator."""
        bar = ctk.CTkFrame(parent, fg_color="transparent")
        bar.grid(row=2, column=0, sticky="ew", pady=(0, 6))
        bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            bar, text=i18n.t("label.filter"), font=ctk.CTkFont(size=10, weight="bold")
        ).grid(row=0, column=0, padx=(4, 6), sticky="w")
        self._filter_entry = theme.field(bar, i18n.t("ph.filter"), width=320)
        self._filter_entry.grid(row=0, column=1, sticky="w")
        self._filter_entry.bind("<KeyRelease>", self._on_filter_change)

        # How many rows survived, so a filter that matched nothing is obvious
        # instead of looking like a scan that found nothing.
        self._filter_count = ctk.CTkLabel(
            bar, text="", font=ctk.CTkFont(size=11),
            text_color=theme.current().text_secondary,
        )
        self._filter_count.grid(row=0, column=2, sticky="e", padx=(10, 14))

        self._sort_label = ctk.CTkLabel(
            bar, text="", font=ctk.CTkFont(size=11)
        )
        self._sort_label.grid(row=0, column=2, sticky="e", padx=6)



    def _bind_shortcuts(self) -> None:
        """Keyboard-first ergonomics: no need to reach for the mouse."""
        self.bind("<Return>", self._shortcut_scan)
        self.bind("<KP_Enter>", self._shortcut_scan)
        self.bind("<Control-f>", self._shortcut_find)
        self.bind("<Control-F>", self._shortcut_find)
        self.bind("<Escape>", self._shortcut_stop)
        self.bind("<Control-c>", self._shortcut_copy)

    def _shortcut_scan(self, _event=None) -> str:
        """Enter anywhere: start a scan (or stop one in progress)."""
        if self._scanning:
            self._on_stop_scan()
        else:
            self._on_start_scan()
        return "break"

    def _shortcut_find(self, _event=None) -> str:
        """Ctrl+F: jump to the filter box and select its contents."""
        self._tabs.set(i18n.t("tab.scan"))
        self._filter_entry.focus_set()
        self._filter_entry.select_range(0, "end")
        return "break"

    def _shortcut_stop(self, _event=None) -> str:
        if self._scanning:
            self._on_stop_scan()
        return "break"

    def _shortcut_copy(self, _event=None) -> str:
        """Ctrl+C: copy the selected device IP."""
        key = self._table.selected_key()
        if key:
            self._copy(key)
        return "break"

    def _set_range(self, text: str) -> None:
        """Write the range field and refresh the host count beside it."""
        self._range_entry.delete(0, "end")
        if text:
            self._range_entry.insert(0, text)
        self._update_target_preview()
        self._refresh_network_caption()

    def _prefill_inputs(self) -> None:
        """Fill the range; the port list is owned by the profile."""
        # A typed range is an audit decision. A language switch rebuilds the
        # toolbar, and quietly replacing 41 chosen hosts with the local /16
        # would sweep an order of magnitude more than the operator asked for.
        self._set_range(self._saved_range or local_network_hint(self._interface_name))
        self._saved_range = ""

        # The quick-tools targets survive a language switch.
        for entry, key in (
            (self._trace_target, "trace"),
            (self._subnet_entry, "subnet"),
            (self._lookup_target, "lookup"),
        ):
            saved = (self._quick_inputs.get(key) or "").strip()
            if saved:
                entry.insert(0, saved)
        if not self._subnet_entry.get().strip():
            self._subnet_entry.insert(0, local_network_hint(self._interface_name))

    # ------------------------------------------------------------------
    # Table rendering
    # ------------------------------------------------------------------
    def _visible_devices(self) -> list[Device]:
        """Devices matching the current filter, in the current sort order."""
        devices = list(self._devices.values())

        needle = self._filter.strip().lower()
        if needle:
            def matches(device: Device) -> bool:
                haystack = " ".join(
                    (device.ip_address, device.hostname, device.mac_address or "",
                     device.vendor, device.model, device.device_type,
                     device.discovery_method, device.ports_summary)
                ).lower()
                return needle in haystack
            devices = [d for d in devices if matches(d)]

        # Stable sort twice: the second one decides, the first one only
        # breaks ties by address. Sorting by IP afterwards would silently
        # override the chosen column, which is what a single pass over a
        # stable sort avoids.
        devices.sort(key=lambda d: d.sort_key("ip"))
        devices.sort(key=lambda d: d.sort_key(self._sort_key), reverse=self._sort_reverse)
        return devices

    def _state_tags(self, device: Device) -> str:
        """Colour for the status dot: red alerts, amber attention, green fine.

        The order matters. A host with a critical or high finding is the thing
        an operator must not miss, so it takes the warning colour even when it
        is up; a host that merely has a VPN or a middling risk is amber; only
        a clean reachable host is green. An offline host used to be painted
        with the amber used for a VPN, which read as "something to think about"
        rather than "this machine is not answering".
        """
        if device.alerts_count or device.worst_severity == "critical":
            return theme.warning()
        if not device.is_alive:
            return theme.warning()
        if device.is_vpn_active or device.risk_score >= 15:
            return theme.vpn()
        return theme.online()

    def _row_values(self, device: Device) -> list[str]:
        """Cell contents in table order.

        The order must track ``DEVICE_COLUMNS`` exactly; the type icon moved
        up beside the status dot so a row is recognisable before it is read.
        """
        return [
            device.ip_address,
            "\u25CF" if device.is_alive else "\u25CB",
            # The pictogram itself is drawn by the table from the device type;
            # this cell only carries the type so the header and the export can
            # read it, and the icon column renders beside it.
            device.device_type,
            i18n.device_type_label(device.device_type),
            device.hostname or "-",
            device.mac_address or "-",
            device.vendor or i18n.t("value.unknown.vendor"),
            # model_label, not device.model: it falls back to the operating
            # system the fingerprint deduced, and the table and the export
            # must not disagree about the same device.
            device.model_label,
            (i18n.t("value.vpn") if device.is_vpn_active else "-")
            + (" *" if device.is_new_device else ""),
            device.ttl_label,
            device.latency_label,
            device.discovery_method or "-",
            str(device.risk_score) if device.risk_score else "-",
            str(device.alerts_count) if device.alerts_count else "-",
            device.ports_compact() if device.open_port_count else "-",
        ]

    def _render_table(self, force: bool = False) -> None:
        """
        Repaint the results table.

        While a scan runs, repaints are throttled to REPAINT_INTERVAL_MS and
        only pending rows are synced; a full rebuild only happens on sort,
        filter or completion.
        """
        import time

        if self._scanning and not force:
            now = time.monotonic() * 1000
            if (now - self._last_paint) < REPAINT_INTERVAL_MS:
                # Defer: the pending rows stay in _devices and will be
                # synced on the next event that passes the throttle, or on
                # the scheduled repaint below.
                if self._paint_job is None:
                    wait = max(
                        1,
                        int(REPAINT_INTERVAL_MS - (now - self._last_paint)),
                    )
                    self._paint_job = self.after(wait, self._paint_deferred)
                return
            self._last_paint = now
            self._sync_pending_rows()
            return

        now = time.monotonic() * 1000
        if not force and (now - self._last_paint) < REPAINT_INTERVAL_MS:
            return
        self._last_paint = now

        # A rebuild redraws every row, so anything queued is now redundant.
        self._pending_rows.clear()
        self._dirty.clear()

        devices = self._visible_devices()
        # Updated in place: the table holds a reference to this exact dict, so
        # rebinding it here would leave every row drawing the fallback shape.
        self._icon_kinds.clear()
        self._icon_kinds.update(
            {d.ip_address: theme.icon_kind(d.device_type) for d in devices}
        )
        self._table.rebuild(
            [(d.ip_address, self._row_values(d), self._state_tags(d)) for d in devices]
        )
        self._row_cache = {
            device.ip_address: self._row_values(device) for device in devices
        }
        self._toggle_empty_hint(len(devices))
        self._update_sort_label(len(devices))

    def _paint_deferred(self) -> None:
        """Flush a throttled repaint scheduled while a scan was running."""
        self._paint_job = None
        if self._scanning or self._pending_rows:
            # Rows left over by an earlier budget must drain whether or not the
            # scan is still running: stopping here would strand them invisible
            # while the table claimed to be complete.
            import time

            self._last_paint = time.monotonic() * 1000
            self._sync_pending_rows()

    def _sync_pending_rows(self) -> None:
        """Sync only new/changed rows without rebuilding the whole table.

        Building a row is the expensive part of this app: it is a frame plus
        one label per column, so a sweep that finds a thousand hosts is tens
        of thousands of widgets. Two rules keep that off the critical path:

        * only the addresses flagged in ``_dirty`` are recomputed, because a
          repaint that walks every row costs the same whether one host was
          discovered or all of them were;
        * new rows are added under ``ROW_BUDGET_PER_PAINT``, and whatever does
          not fit is queued in ``_pending_rows`` for the next tick.

        The window therefore stays responsive on a large sweep and the rows
        keep arriving, a few dozen per paint, instead of the interface
        blocking for seconds at a time.
        """
        if not self._devices:
            return

        # Anything deferred by an earlier paint goes first, and newly flagged
        # devices join the queue behind it. The queue holds addresses, not
        # Device objects: a device that is still waiting for its widget may be
        # enriched (a hostname, then open ports) in the meantime, and the row
        # must show the latest state rather than the snapshot that queued it.
        queue: list[str] = []
        seen: set[str] = set()
        for device in self._pending_rows:
            key = device.ip_address
            if key in self._devices and key not in seen:
                seen.add(key)
                queue.append(key)
        for key in self._dirty:
            if key in self._devices and key not in seen:
                seen.add(key)
                queue.append(key)

        # New rows are appended in the order they were found, but the table is
        # meant to read in sort order. Sorting the queue (a list, so cheap) is
        # what keeps a burst of arrivals from landing in the table backwards.
        queue.sort(key=lambda key: self._devices[key].sort_key(self._sort_key),
                   reverse=self._sort_reverse)

        budget = ROW_BUDGET_PER_PAINT
        added = 0
        for index, key in enumerate(queue):
            if added >= budget:
                # Out of budget: keep the rest queued, for the next tick.
                self._pending_rows = [self._devices[k] for k in queue[index:]]
                self._dirty.clear()
                self._toggle_empty_hint(self._table.row_count())
                self._update_sort_label(self._table.row_count())
                self._schedule_next_paint()
                return
            device = self._devices.get(key)
            if device is None or not self._passes_filter(device):
                continue
            cells = self._row_values(device)
            dot = self._state_tags(device)
            # The pictogram is keyed by row, so the table needs to be told which
            # shape this address draws before the row is created or updated.
            self._icon_kinds[key] = theme.icon_kind(device.device_type)
            if self._table.has_key(key):
                if self._row_cache.get(key) != cells:
                    self._table.update_row(key, cells, dot)
                    self._row_cache[key] = list(cells)
            else:
                self._table.append_row(key, cells, dot)
                self._row_cache[key] = list(cells)
                added += 1

        self._pending_rows = []
        self._dirty.clear()
        self._toggle_empty_hint(self._table.row_count())
        self._update_sort_label(self._table.row_count())
        self._schedule_next_paint()

    def _schedule_next_paint(self) -> None:
        """Keep painting while rows are still queued, without stacking jobs."""
        if not self._pending_rows or self._paint_job is not None:
            return
        self._paint_job = self.after(1, self._paint_deferred)

    def _passes_filter(self, device: Device) -> bool:
        """Whether one device satisfies the filter box.

        Split out of :meth:`_visible_devices` so an incremental paint can test
        a single row instead of rebuilding and re-sorting the whole list.
        """
        needle = self._filter.strip().lower()
        if not needle:
            return True
        haystack = " ".join(
            (device.ip_address, device.hostname, device.mac_address or "",
             device.vendor, device.model, device.device_type,
             device.discovery_method, device.ports_summary)
        ).lower()
        return needle in haystack

    def _toggle_empty_hint(self, count: int) -> None:
        """Show the placeholder only while the table is empty."""
        if count == 0:
            if self._empty_hint is None or not self._empty_hint.winfo_exists():
                self._empty_hint = ctk.CTkLabel(
                    self, text=i18n.t("empty.hint"), font=ctk.CTkFont(size=14),
                    text_color=theme.current().text_secondary,
                )
                self._empty_hint.grid(row=1, column=0, sticky="nw", padx=20, pady=24)
        elif self._empty_hint is not None and self._empty_hint.winfo_exists():
            self._empty_hint.destroy()
            self._empty_hint = None

    def _update_sort_label(self, count: int) -> None:
        arrow = "▼" if self._sort_reverse else "▲"
        label = SORT_KEY_LABELS.get(self._sort_key, self._sort_key)
        self._sort_label.configure(
            text=i18n.t("status.shown", count=count)
            + "   ·   "
            + i18n.t("status.sorted", column=i18n.t(label), arrow=arrow)
        )

        # While a filter is active, say how many of the discovered hosts
        # survived it. "3 of 128" explains an almost empty table at a glance,
        # and an empty one says the text matched nothing rather than the scan
        # having found nothing.
        total = len(self._devices)
        self._filter_count.configure(
            text=i18n.t("status.matching", shown=count, total=total)
            if self._filter.strip() and total else ""
        )
        # The device counter is the number the operator watches, so it lives in
        # the status strip and updates on every repaint rather than only when
        # a scan finishes.
        counter = getattr(self, "_counter_label", None)
        if counter is not None:
            counter.configure(
                text=i18n.t("status.found", count=total) if total else ""
            )

    def _score_devices(self) -> None:
        """
        Assign the offline risk estimate and the exposure alerts.

        Runs after every sweep, so the Risk and Alerts columns are already
        populated when the scan finishes, with no extra probe.
        """
        for device in self._devices.values():
            device.findings = exposure_findings(device)
            device.risk_score = exposure_score(device)
    def _on_sort(self, column: int) -> None:
        if column >= len(DEVICE_COLUMNS):
            return
        key = DEVICE_COLUMNS[column][4]
        if key in ("status", "vpn"):
            key = "risk" if key == "status" else "ip"
        if key == self._sort_key:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_key = key
            self._sort_reverse = key in ("risk", "ports")
        self._render_table(force=True)

    def _on_filter_change(self, _event=None) -> None:
        self._filter = self._filter_entry.get()
        self._render_table(force=True)
    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------
    def _report_payload(self) -> dict:
        """Everything the report needs, in one place for both formats."""
        summary = ""
        try:
            from ..core.utils import vpn_report

            summary = vpn_report()["summary"]
        except Exception:  # noqa: BLE001 - a report never depends on this
            summary = ""
        return {
            "target_range": self._range_entry.get().strip(),
            "inventory_changes": self._scanner.inventory_changes,
            "vpn_summary": summary,
        }

    def _on_report(self) -> None:
        """Export the full inventory as a corporate PDF."""
        if not self._devices:
            self._set_phase(i18n.t("hint.scanfirst"))
            return
        path = filedialog.asksaveasfilename(
            title=i18n.t("report.pdf"),
            initialfile=f"informe_red_{datetime.now():%Y%m%d_%H%M}.pdf",
            defaultextension=".pdf",
            filetypes=[("PDF", "*.pdf")],
        )
        if not path:
            return
        self._export_report(path, "pdf")

    def _on_report_html(self) -> None:
        """Export the same inventory as a self-contained HTML file."""
        if not self._devices:
            self._set_phase(i18n.t("hint.scanfirst"))
            return
        path = filedialog.asksaveasfilename(
            title=i18n.t("report.html"),
            initialfile=f"informe_red_{datetime.now():%Y%m%d_%H%M}.html",
            defaultextension=".html",
            filetypes=[("HTML", "*.html")],
        )
        if not path:
            return
        self._export_report(path, "html")

    def _export_report(self, path: str, fmt: str) -> None:
        """Build the report off the UI thread and report the result."""
        devices = list(self._devices.values())
        payload = self._report_payload()

        def _work() -> None:
            from ..analysis.report import build_report

            try:
                written = build_report(devices, path, fmt, **payload)
            except Exception as exc:  # noqa: BLE001 - surface to the user
                self._scanner.event_queue.put(
                    ScannerEvent("Error", str(exc), is_error=True)
                )
                return
            self._aux_queue.put(("__tool__", ToolResult(
                name=f"Report {fmt.upper()}", ok=True,
                output=Path(written).name,
            )))

        threading.Thread(target=_work, daemon=True, name="report").start()
        self._set_phase(i18n.t("report.saved", path=Path(path).name))


    def _on_start_scan(self) -> None:
        if self._scanning:
            return
        target_range = self._range_entry.get().strip()
        if not target_range:
            self._set_phase(i18n.t("hint.range"))
            return

        # The plan is the same arithmetic the preview showed, so what the
        # operator read is exactly what the worker will sweep.
        plan = plan_targets(target_range)
        if plan.is_empty:
            self._set_phase(i18n.t(
                "target.problem",
                items=", ".join(plan.problems) or target_range))
            return
        if plan.problems:
            self._set_phase(i18n.t("target.partial",
                                   items=", ".join(plan.problems)))

        # One fixed sweep: every port in SCAN_PORTS, with the tuning that the
        # former "deep" profile used, because that is the setting the fixed
        # range implies. Ports are never skipped and never edited by hand.
        request = ScanRequest(target_range=target_range)
        request.interface = self._selected_interface()
        request.ports = SCAN_PORTS
        request.scan_ports_enabled = True
        request.port_timeout = 1.2
        request.concurrency = 250
        request.resolve_hostnames = True
        request.identify_models = True
        request.advanced_banners = True
        # "IP Camera" is the switch that makes the model phase probe ONVIF and
        # RTSP, so a sweep that leaves it out reports every camera as an
        # unidentified host. The hints are read as a membership test, so the
        # full set costs nothing.
        request.device_hints = ("IP Camera", "IoT Device", "Printer",
                                "Router", "exposure")
        request.profile = "full"
        self._clear_devices()
        self._set_scanning(True)
        self._scanner.reset()
        threading.Thread(
            target=self._scan_worker, args=(request,), daemon=True, name="scan-worker"
        ).start()
        self._drain_events()

    def _on_stop_scan(self) -> None:
        if self._scanning:
            self._scanner.stop()
            self._set_phase(i18n.t("status.stopping"))

    def _scan_worker(self, request: ScanRequest) -> None:
        """Worker-thread entry point; must never touch widgets."""
        try:
            self._scanner.run_scan(request)
        except Exception:  # noqa: BLE001 - surface failures to the UI
            logger.exception("Scan failed")
            self._scanner.event_queue.put(
                ScannerEvent("Error", "Unexpected scan error", is_error=True)
            )

    def _paint_field_state(self, entry) -> None:
        """Border the range field red while its text cannot be scanned."""
        text = entry.get().strip()
        valid = bool(text) and not plan_targets(text).is_empty
        entry.configure(
            border_color=theme.current().online if valid
            else theme.warning(),
        )

    def _set_scanning(self, scanning: bool) -> None:
        self._scanning = scanning
        self._start_button.configure(state="disabled" if scanning else "normal")
        self._stop_button.configure(state="normal" if scanning else "disabled")
        # Reports follow the data, not the clock: a finished sweep that found
        # nothing has nothing to report, and offering it an empty document is
        # worse than leaving the button greyed out.
        if scanning:
            self._set_reports_enabled(False)
        else:
            self._set_reports_enabled(bool(self._visible_devices()))

    def _set_reports_enabled(self, enabled: bool) -> None:
        """Enable the report and export actions as a single group."""
        state = "normal" if enabled else "disabled"
        for button in (self._report_button, self._report_html_button,
                       self._export_csv_button, self._export_json_button):
            button.configure(state=state)

    def _clear_devices(self) -> None:
        self._devices.clear()
        self._row_cache.clear()
        # A fresh sweep must not inherit rows the previous one had not
        # finished painting.
        self._dirty.clear()
        self._pending_rows.clear()
        self._icon_kinds.clear()
        if self._paint_job is not None:
            try:
                self.after_cancel(self._paint_job)
            except Exception:  # noqa: BLE001 - the job may already be gone
                pass
            self._paint_job = None
        self._table.rebuild([])
        self._toggle_empty_hint(0)
        self._update_sort_label(0)
        self._set_phase(i18n.t("status.scanning"))

    def _drain_events(self) -> None:
        """Consume scan events on the main thread and repaint."""
        try:
            budget = 0
            while True:
                event = self._scanner.event_queue.get_nowait()
                budget += 1
                self._handle_event(event)
                if budget >= 200:
                    # Keep the window interactive under event bursts: leave
                    # the rest for the next tick instead of blocking here.
                    break
        except queue.Empty:
            pass

        if self._scanning:
            self.after(POLL_INTERVAL_MS, self._drain_events)
        elif self._paint_job is not None:
            # A deferred paint outlived the scan; flush it right away.
            try:
                self.after_cancel(self._paint_job)
            except Exception:  # noqa: BLE001 - the job may already be gone
                pass
            self._paint_job = None
            self._render_table(force=True)

    def _handle_event(self, event: ScannerEvent) -> None:
        if event.device is not None:
            self._devices[event.device.ip_address] = event.device
            # Flagged here, not painted here: the throttled renderer decides
            # when the row actually becomes a widget.
            self._dirty.add(event.device.ip_address)
            self._render_table()

        if event.is_error:
            self._set_scanning(False)
            self._set_phase(i18n.t("status.error", message=i18n.translate_line(event.message)))
            self._render_table(force=True)
            return

        self._render_progress(event)

        if event.phase in ("Finished", "Cancelled"):
            self._set_scanning(False)
            self._score_devices()
            # Scoring fills Risk/Alerts after the sweep; the last throttled
            # paint may predate it, so force one final repaint.
            self._render_table(force=True)

    def _render_progress(self, event: ScannerEvent) -> None:
        """Move the progress bar, the phase caption and the live counters."""
        if event.total > 0:
            fraction = min(1.0, event.completed / event.total)
            self._progress_set(fraction)
            self._set_phase(
                f"{i18n.t('phase.' + event.phase.lower())}   "
                f"{i18n.translate_line(event.message)}"
            )
            # "45% · 110 of 254" answers both questions the operator has while
            # a sweep runs: is it moving, and how much is left.
            self._counter_label.configure(
                text=i18n.t("status.progress", percent=int(fraction * 100),
                            done=event.completed, total=event.total)
            )
        else:
            self._set_phase(
                f"{i18n.t('phase.' + event.phase.lower())}   "
                f"{i18n.translate_line(event.message)}".rstrip()
            )

    def _set_phase(self, text: str) -> None:
        self._phase_label.configure(text=text)

    # ------------------------------------------------------------------
    # Tab 2: security audit
    # ------------------------------------------------------------------
    def _build_audit_tab(self, parent: ctk.CTkBaseClass) -> None:
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)

        bar = ctk.CTkFrame(parent, fg_color="transparent")
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        block = ctk.CTkFrame(bar, fg_color="transparent")
        block.grid(row=0, column=0, sticky="w", padx=(10, 6), pady=7)
        theme.caption(block, i18n.t("label.target")).grid(row=0, column=0, sticky="w")
        self._audit_target = theme.field(block, i18n.t("ph.audit"), width=320)
        self._audit_target.grid(row=1, column=0, sticky="w", pady=(3, 0))

        actions = ctk.CTkFrame(bar, fg_color="transparent")
        actions.grid(row=0, column=1, sticky="e", padx=(8, 12))
        theme.primary_button(actions, i18n.t("btn.audit.target"),
                             self._on_audit_target).grid(row=0, column=0, padx=4)
        theme.secondary_button(actions, i18n.t("btn.audit.selected"),
                              self._on_audit_selected, 124).grid(row=0, column=1, padx=4)
        theme.secondary_button(actions, i18n.t("btn.audit.all"),
                              self._on_audit_all, 110).grid(row=0, column=2, padx=4)
        theme.secondary_button(actions, i18n.t("btn.audit.quick"),
                              self._on_audit_quick, 124).grid(row=0, column=3, padx=4)

        self._risk_label = ctk.CTkLabel(
            parent, text="", anchor="w", font=ctk.CTkFont(size=14, weight="bold"),
        )
        self._risk_label.grid(row=1, column=0, sticky="w", padx=6, pady=(0, 6))

        panel = theme.panel(parent)
        panel.grid(row=2, column=0, sticky="nsew")
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(0, weight=1)

        self._finding_table = theme.ResultTable(
            panel,
            tuple((i18n.t(k), w, a, m, s) for k, w, a, m, s in FINDING_COLUMNS),
            dot=0,
        )
        self._finding_table.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)

    def _build_inventory_tab(self, parent: ctk.CTkBaseClass) -> None:
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)

        bar = theme.panel(parent)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        actions = ctk.CTkFrame(bar, fg_color="transparent")
        actions.grid(row=0, column=0, sticky="w", padx=(10, 6), pady=7)
        for label, command, width in (
            (i18n.t("inv.approve"), self._on_approve, 150),
            (i18n.t("inv.forget"), self._on_forget, 150),
            (i18n.t("inv.reset"), self._on_reset_inventory, 140),
            (i18n.t("inv.export"), self._on_export_inventory, 140),
        ):
            theme.secondary_button(actions, label, command, width).grid(
                row=0, column=len(actions.grid_slaves()), padx=3
            )

        self._inventory_label = ctk.CTkLabel(
            parent, text="", anchor="w", font=ctk.CTkFont(size=12, weight="bold"),
            text_color=theme.current().text_primary,
        )
        self._inventory_label.grid(row=1, column=0, sticky="w", padx=12, pady=(0, 4))

        panel = theme.panel(parent)
        panel.grid(row=2, column=0, sticky="nsew")
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(0, weight=1)

        self._inventory_table = theme.ResultTable(
            panel,
            tuple((i18n.t(k), w, a, m, s) for k, w, a, m, s in INVENTORY_COLUMNS),
        )
        self._inventory_table.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
        self._render_inventory([])



    def _render_inventory(self, changes) -> None:
        """Paint the inventory diff, most urgent changes first."""
        rows = []
        for change in changes:
            label = {
                "new": i18n.t("inv.new"),
                "identity": i18n.t("inv.identity"),
                "vendor": i18n.t("inv.vendor"),
                "missing": i18n.t("inv.missing"),
                "returning": i18n.t("inv.returning"),
            }.get(change.kind, change.kind.upper())
            colour = {
                "identity": theme.warning(),
                "vendor": theme.vpn(),
                "new": theme.vpn(),
                "missing": theme.current().text_secondary,
                "returning": theme.current().text_secondary,
            }.get(change.kind, theme.current().text_secondary)
            rows.append((
                change.mac or change.ip,
                [
                    label,
                    change.mac or "-",
                    change.ip or "-",
                    change.detail,
                    change.vendor or "-",
                    i18n.device_type_label(change.device_type),
                    (change.first_seen or "-")[:19],
                ],
                colour,
            ))
        self._inventory_table.rebuild(rows)

        counts = {}
        for change in changes:
            counts[change.kind] = counts.get(change.kind, 0) + 1
        summary = i18n.t(
            "inv.summary",
            new=counts.get("new", 0),
            changed=counts.get("identity", 0) + counts.get("vendor", 0),
            missing=counts.get("missing", 0),
            total=self._scanner.inventory.__len__(),
        )
        self._inventory_label.configure(
            text=summary,
            text_color=(theme.warning() if counts.get("identity")
                        else theme.current().text_primary),
        )

    def _on_approve(self) -> None:
        """Mark the selected device as approved."""
        key = self._inventory_table.selected_key()
        if not key:
            self._set_phase(i18n.t("hint.tool"))
            return
        self._scanner.inventory.approve(key)
        self._set_phase(i18n.t("inv.approved", mac=key))

    def _on_forget(self) -> None:
        """Drop the selected device from the baseline."""
        key = self._inventory_table.selected_key()
        if not key:
            self._set_phase(i18n.t("hint.tool"))
            return
        self._scanner.inventory.forget(key)
        self._set_phase(i18n.t("inv.forgotten", mac=key))

    def _on_reset_inventory(self) -> None:
        """Clear the whole baseline after confirmation."""
        if not messagebox.askyesno(
            i18n.t("tab.inventory"), i18n.t("inv.reset.ask")
        ):
            return
        self._scanner.inventory.reset()
        self._render_inventory([])
        self._set_phase(i18n.t("inv.reset.done"))

    def _on_export_inventory(self) -> None:
        """Write the current diff to a CSV file."""
        path = filedialog.asksaveasfilename(
            title=i18n.t("inv.export"),
            initialfile="inventory_changes.csv",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")],
        )
        if not path:
            return
        changes = self._scanner.inventory_changes
        try:
            if path.lower().endswith(".json"):
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(
                        [
                            {
                                "kind": c.kind, "severity": c.severity,
                                "mac": c.mac, "ip": c.ip, "detail": c.detail,
                                "vendor": c.vendor, "type": c.device_type,
                            }
                            for c in changes
                        ],
                        handle, indent=2, ensure_ascii=False,
                    )
            else:
                with open(path, "w", newline="", encoding="utf-8-sig") as handle:
                    writer = csv.writer(handle, delimiter=";")
                    writer.writerow(["kind", "severity", "mac", "ip",
                                     "detail", "vendor", "type"])
                    for change in changes:
                        writer.writerow([
                            change.kind, change.severity, change.mac, change.ip,
                            change.detail, change.vendor, change.device_type,
                        ])
        except OSError as exc:
            messagebox.showerror(i18n.t("inv.export"), str(exc))
            return
        self._set_phase(i18n.t("inv.saved", path=Path(path).name))


    def _build_monitor_tab(self, parent: ctk.CTkBaseClass) -> None:
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)

        bar = theme.panel(parent)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        for index, (label, attr, placeholder, width) in enumerate((
            ("mon.hint", "_watch_ip", "192.168.1.1", 150),
            ("mon.label", "_watch_label", "servidor", 110),
            ("mon.port", "_watch_port", "auto", 60),
            ("mon.interval", "_watch_interval", "3", 55),
        )):
            block = ctk.CTkFrame(bar, fg_color="transparent")
            block.grid(row=0, column=index, padx=(8, 4), pady=7)
            theme.caption(block, i18n.t(label)).grid(row=0, column=0, sticky="w")
            entry = theme.field(block, placeholder, width=width)
            entry.grid(row=1, column=0, sticky="w", pady=(2, 0))
            setattr(self, attr, entry)

        actions = ctk.CTkFrame(bar, fg_color="transparent")
        actions.grid(row=0, column=5, sticky="e", padx=(6, 10))
        theme.secondary_button(actions, i18n.t("mon.add"),
                               self._on_watch_add, 96).grid(row=0, column=0, padx=3)
        self._mon_start_button = theme.secondary_button(
            actions, i18n.t("mon.start"), self._on_monitor_toggle, 132
        )
        self._mon_start_button.grid(row=0, column=1, padx=3)
        theme.secondary_button(actions, i18n.t("mon.remove"),
                               self._on_watch_remove, 84).grid(row=0, column=2, padx=3)
        theme.secondary_button(actions, i18n.t("mon.clear"),
                               self._on_monitor_clear, 110).grid(row=0, column=3, padx=3)

        self._monitor_label = ctk.CTkLabel(
            parent, text="", anchor="w", font=ctk.CTkFont(size=12, weight="bold"),
            text_color=theme.current().text_primary,
        )
        self._monitor_label.grid(row=1, column=0, sticky="w", padx=12, pady=(0, 4))

        body = ctk.CTkFrame(parent, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        holder = theme.panel(body)
        holder.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        holder.grid_columnconfigure(0, weight=1)
        holder.grid_rowconfigure(0, weight=1)
        self._monitor_table = theme.ResultTable(
            holder,
            tuple((i18n.t(k), w, a, m, s) for k, w, a, m, s in MONITOR_COLUMNS),
            sparkline=MONITOR_SPARK_COLUMN,
        )
        self._monitor_table.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)

        log_holder = theme.panel(body)
        log_holder.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        log_holder.grid_columnconfigure(0, weight=1)
        log_holder.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(
            log_holder, text=i18n.t("mon.log").upper(),
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=theme.current().text_secondary,
        ).grid(row=0, column=0, sticky="w", padx=8, pady=(6, 2))
        self._monitor_log = ctk.CTkTextbox(
            log_holder, wrap="word", font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=theme.current().background, border_width=0,
            text_color=theme.current().text_primary,
        )
        self._monitor_log.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))
        self._monitor_log.insert("1.0", i18n.t("mon.log.empty"))


    # ------------------------------------------------------------------
    # Monitor tab
    # ------------------------------------------------------------------
    def _watch(self, device: Device) -> None:
        """Pin the device currently selected in the results table."""
        self._tabs.set(i18n.t("tab.monitor"))
        self._watch_ip.delete(0, "end")
        self._watch_ip.insert(0, device.ip_address)
        self._watch_label.delete(0, "end")
        self._watch_label.insert(0, device.hostname or device.display_name())
        if device.open_ports:
            open_ports = [p.number for p in device.open_ports if p.is_open]
            self._watch_port.delete(0, "end")
            self._watch_port.insert(0, str(open_ports[0]))
        self._on_watch_add()

    def _on_watch_add(self) -> None:
        ip = self._watch_ip.get().strip()
        if not ip:
            self._set_phase(i18n.t("hint.tool"))
            return
        port_text = self._watch_port.get().strip().lower()
        try:
            port = int(port_text) if port_text and port_text != "auto" else 0
        except ValueError:
            port = 0
        try:
            interval = float(self._watch_interval.get().strip() or 3)
        except ValueError:
            interval = 3.0

        host = self.monitor.add(
            ip, self._watch_label.get().strip(), port=port,
            interval=max(1.0, interval),
        )
        if host is None:
            return
        self.monitor.start()
        self._set_phase(i18n.t("mon.added", ip=ip))
        self._mon_start_button.configure(
            text=i18n.t("mon.stop") if self.monitor.running else i18n.t("mon.start")
        )
        self._pump_monitor()

    def _on_watch_remove(self) -> None:
        key = self._monitor_table.selected_key()
        if key:
            self.monitor.remove(key)
            self._refresh_monitor()
            if not len(self.monitor):
                self.monitor.stop()
                self._mon_start_button.configure(text=i18n.t("mon.start"))

    def _on_monitor_toggle(self) -> None:
        if self.monitor.running:
            self.monitor.stop()
            self._set_phase(i18n.t("mon.stopped"))
            self._mon_start_button.configure(text=i18n.t("mon.start"))
        else:
            self.monitor.start()
            self._mon_start_button.configure(text=i18n.t("mon.stop"))
            self._pump_monitor()
        self._refresh_monitor()

    def _on_monitor_clear(self) -> None:
        self._monitor_log.delete("1.0", "end")
        self._monitor_log.insert("1.0", i18n.t("mon.log.empty"))
        self._monitor_events.clear()

    def _pump_monitor(self) -> None:
        """Drain monitor events and repaint the table on the main thread."""
        try:
            while True:
                event = self.monitor._queue.get_nowait()
                self._monitor_events.append(event)
                self._append_monitor_log(event)
        except queue.Empty:
            pass
        self._refresh_monitor()
        if self.monitor.running:
            self.after(600, self._pump_monitor)

    def _append_monitor_log(self, event: MonitorEvent) -> None:
        """Append one alert line, coloured by severity."""
        colour = {
            "alert": theme.warning(), "ok": theme.online(),
            "warn": theme.current().text_secondary,
        }.get(event.severity, theme.current().text_primary)
        tag = f"{event.severity}"
        self._monitor_log.configure(state="normal")
        self._monitor_log.insert(
            "end", f"[{event.timestamp}] {self._event_text(event)}\n", tag)
        try:
            self._monitor_log.tag_config(tag, foreground=colour)
        except Exception:  # noqa: BLE001 - tag support varies
            pass
        self._monitor_log.configure(state="disabled")
        self._monitor_log.see("end")

    def _event_text(self, event: MonitorEvent) -> str:
        """Render an alert in the active language.

        The monitor itself stays language-neutral: it emits a kind plus the
        numbers, and the wording is resolved here.
        """
        templates = {
            "added": ("{label} added to monitoring (every {interval:g}s)",
                      "{label} anadido al monitor (cada {interval:g}s)"),
            "up": ("{label} answered ({latency:.0f} ms)",
                   "{label} respondio ({latency:.0f} ms)"),
            "down": ("{label} stopped responding ({failures} failures in a row)",
                     "{label} dejo de responder ({failures} fallos seguidos)"),
            "recovered": ("{label} is back online ({latency:.0f} ms)",
                          "{label} volvio a estar en linea ({latency:.0f} ms)"),
            "removed": ("{label} removed from monitoring",
                        "{label} quitado del monitor"),
        }
        pair = templates.get(event.kind)
        if pair is None:
            return event.message
        template = pair[0] if i18n.get_language() == "en" else pair[1]
        host = self.monitor._hosts.get(event.ip)
        return template.format(
            label=event.label,
            latency=host.last_latency or 0.0 if host else 0.0,
            failures=host.failures if host else 0,
            interval=host.interval if host else 0.0,
        )

    def _refresh_monitor(self) -> None:
        """Repaint the monitored-host table from the monitor snapshot."""
        rows = []
        charts = {}
        for entry in self.monitor.snapshot():
            colour = {
                "up": theme.online(), "down": theme.warning(),
            }.get(entry["status"], theme.current().text_secondary)
            rows.append((
                entry["ip"],
                [
                    "\u25CF" if entry["status"] == "up"
                    else ("\u25CB" if entry["status"] == "down" else "\u25D0"),
                    entry["label"] or entry["ip"],
                    "",  # the sparkline cell is drawn, never written
                    f"{entry['latency']:.0f}" if entry["latency"] else "-",
                    f"{entry['avg']:.0f}" if entry["avg"] else "-",
                    f"{entry['uptime']:.0f}%",
                    str(entry["checks"]),
                    entry["since"],
                ],
                colour,
            ))
            charts[entry["ip"]] = entry["history"]
        self._monitor_table.rebuild(rows, charts)
        total = len(self.monitor)
        self._monitor_label.configure(
            text=i18n.t("mon.watching", count=total) if total else "",
        )


    def _on_audit_selected(self) -> None:
        if not self._devices:
            self._set_phase(i18n.t("hint.scanfirst.device"))
            return
        target = self._audit_target.get().strip() or next(iter(self._devices))
        self._audit_target.delete(0, "end")
        self._audit_target.insert(0, target)
        self._run_audit([target])

    def _on_audit_all(self) -> None:
        if not self._devices:
            self._set_phase(i18n.t("hint.scanfirst"))
            return
        self._run_audit(list(self._devices)[:24])

    def _on_audit_target(self) -> None:
        target = self._audit_target.get().strip()
        if not target:
            self._set_phase(i18n.t("hint.target"))
            return
        self._run_audit([target])

    def _run_audit(self, targets: list[str]) -> None:
        if self._busy:
            return
        self._busy = True
        self._render_findings([])
        threading.Thread(
            target=self._audit_worker, args=(targets,), daemon=True, name="audit-worker"
        ).start()
        self._drain_aux()

    def _audit_worker(self, targets: list[str]) -> None:
        """Worker-thread audit. Never touches widgets."""
        findings: list[SecurityFinding] = []
        for target in targets:
            findings.extend(self._audit_target_worker(target))
        self._aux_queue.put(
            ("__audit__", sorted(findings, key=lambda item: item.sort_weight))
        )

    def _audit_target_worker(self, target: str) -> list[SecurityFinding]:
        """Audit a single target, choosing the most relevant probe."""
        if target.startswith(("http://", "https://")):
            report = audit_http(target)
            return [
                SecurityFinding(severity, "HTTP headers", detail, target)
                for severity, detail in report.findings
            ]

        device = self._devices.get(target)
        if device is not None:
            return audit_device(device)

        for port in (443, 8443):
            tls = inspect_tls(target, port)
            if tls.supported:
                return [
                    SecurityFinding(
                        "high" if "EXPIRADO" in issue or "obsoleto" in issue else "info",
                        f"TLS/{port}", issue, target,
                    )
                    for issue in tls.findings
                ]

        report = audit_http(f"http://{target}")
        return [
            SecurityFinding(severity, "HTTP headers", detail, target)
            for severity, detail in report.findings
        ] or [SecurityFinding("info", "No findings", "Endpoint reachable", target)]

    def _drain_audit_result(self, payload: object) -> None:
        self._busy = False
        self._findings = payload if isinstance(payload, list) else []
        self._render_findings(self._findings)

    def _on_audit_quick(self) -> None:
        """
        Run the offline exposure heuristics over every scanned device.

        No packets leave the machine: the rules only read what the scan
        already collected, so a whole sweep is judged instantly.
        """
        if not self._devices:
            self._set_phase(i18n.t("hint.scanfirst"))
            return
        findings: list[SecurityFinding] = []
        for device in self._devices.values():
            device.findings = exposure_findings(device)
            device.risk_score = exposure_score(device)
            findings.extend(device.findings)
        self._render_findings(findings)
        self._render_table(force=True)
        self._set_phase(i18n.t("status.audit.quick", count=len(self._devices)))

    def _render_findings(self, findings: list[SecurityFinding]) -> None:
        """Paint the findings table with severity-driven row colours."""
        rows = []
        for position, finding in enumerate(sorted(
            findings, key=lambda f: SEVERITY_ORDER.index(f.severity)
            if f.severity in SEVERITY_ORDER else 9
        )):
            colour = {
                "critical": theme.warning(),
                "high": theme.warning(),
                "medium": theme.vpn(),
                "low": theme.online(),
                "info": theme.current().text_secondary,
            }.get(finding.severity, theme.current().text_secondary)
            rows.append((
                f"{finding.target}|{position}",
                [
                    i18n.severity_label(finding.severity),
                    self._finding_text(finding.title_key, finding.title, finding.params),
                    self._finding_text(finding.detail_key, finding.detail, finding.params),
                    finding.target,
                ],
                colour,
            ))
        self._finding_table.rebuild(rows)

        score = risk_score(findings)
        high = sum(1 for f in findings if f.severity in ("critical", "high"))
        self._risk_label.configure(
            text=i18n.t(
                "status.findings", count=len(findings), high=high, score=score
            ),
            text_color=(theme.current().warning if findings else
                         theme.current().text_secondary),
        )
        self._set_phase(i18n.t("status.audit.done"))

    def _finding_text(self, key: str, fallback: str, params: dict) -> str:
        """
        Localise a heuristic finding, falling back to its stored text.

        Findings are produced by the offline engine without knowing the
        active language, so the catalogue is consulted here. Anything that
        cannot be resolved renders as produced, never as a raw key.
        """
        if not key or key not in i18n.CATALOG:
            return fallback
        try:
            return i18n.t(key, **(params or {}))
        except (KeyError, IndexError, ValueError):
            return fallback

    def _tool_buttons(self) -> tuple[tuple[str, object], ...]:
        """(label, handler) pairs for the network tools, localised."""
        return (
            (i18n.t("tool.ping"), self._tool_ping),
            (i18n.t("tool.traceroute"), self._tool_traceroute),
            (i18n.t("tool.whois"), self._tool_whois),
            (i18n.t("tool.dns"), self._tool_dns),
            (i18n.t("tool.ptr"), self._tool_ptr),
            (i18n.t("tool.subnet"), self._tool_subnet),
            (i18n.t("tool.zone"), self._tool_zone),
            (i18n.t("tool.dmarc"), self._tool_dmarc),
        )

    def _local_buttons(self) -> tuple[tuple[str, object], ...]:
        """(label, handler) pairs for the local inspection tools."""
        return (
            (i18n.t("tool.exposure"), self._tool_exposure),
            (i18n.t("tool.listening"), self._tool_listening),
            (i18n.t("tool.http"), self._tool_http),
            (i18n.t("tool.tls"), self._tool_tls),
        )

    def _build_tools_tab(self, parent: ctk.CTkBaseClass) -> None:
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)

        bar = theme.panel(parent)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        block = ctk.CTkFrame(bar, fg_color="transparent")
        block.grid(row=0, column=0, sticky="w", padx=(10, 6), pady=7)
        theme.caption(block, i18n.t("label.target")).grid(row=0, column=0, sticky="w")
        self._tool_target = theme.field(block, i18n.t("ph.tool"), width=280)
        self._tool_target.grid(row=1, column=0, sticky="w", pady=(3, 0))

        self._dns_type = ctk.CTkOptionMenu(
            bar, values=list(DNS_RECORD_TYPES), width=86, height=34,
            font=ctk.CTkFont(size=12),
            fg_color=theme.current().surface,
            button_color=theme.current().primary,
            button_hover_color=theme.current().primary_hover,
            text_color=theme.current().text_primary,
            dropdown_fg_color=theme.current().surface,
            dropdown_text_color=theme.current().text_primary,
            dropdown_hover_color=theme.current().selection,
        )
        self._dns_type.grid(row=0, column=1, padx=6)

        grid = ctk.CTkFrame(bar, fg_color="transparent")
        grid.grid(row=0, column=2, sticky="e", padx=(6, 12))
        for index, (label, command) in enumerate(self._tool_buttons()):
            theme.secondary_button(grid, label, command, 92).grid(
                row=index // 4, column=index % 4, padx=3, pady=2
            )

        local_bar = ctk.CTkFrame(parent, fg_color="transparent")
        local_bar.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        local_bar.grid_columnconfigure(4, weight=1)
        for index, (label, command) in enumerate(self._local_buttons()):
            theme.secondary_button(local_bar, label, command, 138).grid(
                row=0, column=index, padx=3
            )
        theme.secondary_button(local_bar, i18n.t("btn.clear"),
                               self._clear_output, 88).grid(
            row=0, column=5, sticky="e", padx=3)

        panel = theme.panel(parent)
        panel.grid(row=2, column=0, sticky="nsew")
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(0, weight=1)
        self._tool_output = ctk.CTkTextbox(
            panel, wrap="none", font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=theme.current().background,
            border_width=0, text_color=theme.current().text_primary,
        )
        self._tool_output.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)

    def _clear_output(self) -> None:
        self._tool_output.delete("1.0", "end")

    def _append_output(self, text: str) -> None:
        self._tool_output.insert("end", text + "\n")
        self._tool_output.see("end")

    def _tool_target_value(self, required: bool = True) -> str:
        value = self._tool_target.get().strip()
        if required and not value:
            self._set_phase(i18n.t("hint.tool"))
        return value

    def _run_tool(self, function, *args, handler=None) -> None:
        """
        Execute a tool on a worker thread and paint its result.

        ``handler`` receives the :class:`ToolResult` once the worker answers.
        The console pane is the default, which is what every button on the
        Tools tab uses; the Quick Tools tab passes its own painters.
        """
        if self._busy:
            self._set_phase(i18n.t("hint.busy"))
            return
        self._busy = True
        self._tool_handler = handler
        threading.Thread(
            target=self._tool_worker, args=(function, args), daemon=True, name="tool-worker"
        ).start()
        self._drain_aux()

    def _tool_worker(self, function, args: tuple) -> None:
        try:
            result: ToolResult = function(*args)
        except Exception as exc:  # noqa: BLE001 - never kill the UI thread
            logger.exception("Tool failed")
            result = ToolResult(name="tool", ok=False, error=str(exc))
        self._aux_queue.put(("__tool__", result))

    def _drain_aux(self) -> None:
        """
        Single consumer of ``_aux_queue``, dispatching on the message kind.

        Tool results, audit results and live ping samples share one queue and
        one pump on purpose: two ``after()`` loops reading the same queue
        would race and each could swallow the other's messages.
        """
        try:
            while True:
                kind, payload = self._aux_queue.get_nowait()
                if kind == "__latency__":
                    self._append_latency(payload)
                elif kind == "__audit__":
                    self._drain_audit_result(payload)
                else:
                    self._dispatch_tool(payload)
        except queue.Empty:
            pass

        if self._busy or self._latency_running:
            self.after(POLL_INTERVAL_MS, self._drain_aux)

    def _dispatch_tool(self, result: ToolResult) -> None:
        """Hand the result to whichever handler asked for it."""
        self._busy = False
        handler, self._tool_handler = self._tool_handler, None
        (handler or self._render_tool)(result)

    def _render_tool(self, result: ToolResult) -> None:
        """Print a tool result into the console pane."""
        status = i18n.t("tool.ok") if result.ok else i18n.t("tool.error")
        elapsed = f"   {result.elapsed_ms:.0f} ms" if result.elapsed_ms else ""
        self._append_output("-" * 78)
        self._append_output(f"{'?' if result.ok else '?'} {result.name}   [{status}]{elapsed}")
        if result.error:
            self._append_output(f"    ! {result.error}")
        for line in result.lines:
            self._append_output(f"    {line}")
        self._append_output("")

    def _tool_ping(self) -> None:
        target = self._tool_target_value()
        if target:
            self._run_tool(ping_host, target, 4)

    def _tool_traceroute(self) -> None:
        target = self._tool_target_value()
        if target:
            self._run_tool(traceroute, target, 20)

    def _tool_whois(self) -> None:
        target = self._tool_target_value()
        if target:
            self._run_tool(whois_lookup, target)

    def _tool_dns(self) -> None:
        target = self._tool_target_value()
        if target:
            self._run_tool(dns_lookup, target, self._dns_type.get())

    def _tool_ptr(self) -> None:
        target = self._tool_target_value()
        if target:
            self._run_tool(reverse_dns, target)

    def _tool_subnet(self) -> None:
        target = self._tool_target_value()
        if target:
            self._run_tool(subnet_info, target)

    def _tool_zone(self) -> None:
        target = self._tool_target_value()
        if target:
            self._run_tool(zone_transfer, target)

    def _tool_dmarc(self) -> None:
        target = self._tool_target_value()
        if target:
            self._run_tool(email_security_records, target)

    def _tool_exposure(self) -> None:
        self._run_tool(local_exposure_report)

    def _tool_listening(self) -> None:
        self._run_tool(listening_ports)

    def _tool_http(self) -> None:
        target = self._tool_target_value()
        if target:
            self._render_http(audit_http(target))

    def _tool_tls(self) -> None:
        target = self._tool_target_value()
        if target:
            self._render_tls(inspect_tls(target, 443))

    # ------------------------------------------------------------------
    # Tab: quick tools (visual traceroute, CIDR calculator, DNS / WHOIS)
    # ------------------------------------------------------------------
    def _build_quick_tab(self, parent: ctk.CTkBaseClass) -> None:
        """Two columns: path and latency on the left, calculators on the right."""
        parent.grid_columnconfigure(0, weight=1, uniform="quick")
        parent.grid_columnconfigure(1, weight=1, uniform="quick")
        parent.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(parent, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew")
        left.grid_columnconfigure(0, weight=1)
        left.grid_rowconfigure(0, weight=3)
        left.grid_rowconfigure(1, weight=2)
        self._build_trace_panel(left)
        self._build_latency_panel(left)

        side = ctk.CTkFrame(parent, fg_color="transparent")
        side.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        side.grid_columnconfigure(0, weight=1)
        side.grid_rowconfigure(0, weight=3)
        side.grid_rowconfigure(1, weight=2)
        self._build_subnet_panel(side)
        self._build_lookup_panel(side)

    def _quick_panel(self, master, title: str) -> ctk.CTkFrame:
        """Titled surface shared by the three quick-tools panels."""
        panel = theme.panel(master)
        panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            panel, text=title, anchor="w",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=theme.current().text_primary,
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 2))
        return panel

    def _option_menu(self, master, values, width: int = 80, anchor: str = "w") -> ctk.CTkOptionMenu:
        """Dropdown styled like the one on the Tools tab."""
        palette = theme.current()
        return ctk.CTkOptionMenu(
            master, values=list(values), width=width, height=34,
            font=ctk.CTkFont(size=12),
            fg_color=palette.surface,
            button_color=palette.primary,
            button_hover_color=palette.primary_hover,
            text_color=palette.text_primary,
            dropdown_fg_color=palette.surface,
            dropdown_text_color=palette.text_primary,
            dropdown_hover_color=palette.selection,
            anchor=anchor,
        )

    def _textbox(self, master, **kwargs) -> ctk.CTkTextbox:
        """Read-only looking output box, matching the Tools console."""
        palette = theme.current()
        return ctk.CTkTextbox(
            master, font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=palette.background, border_width=0,
            text_color=palette.text_primary, **kwargs,
        )

    def _build_trace_panel(self, parent: ctk.CTkBaseClass) -> None:
        """Traceroute drawn as a hop list with a latency bar per router."""
        panel = self._quick_panel(parent, i18n.t("qt.trace.title"))
        panel.grid(row=0, column=0, sticky="nsew")
        panel.grid_rowconfigure(3, weight=1)

        bar = ctk.CTkFrame(panel, fg_color="transparent")
        bar.grid(row=1, column=0, sticky="ew", padx=12, pady=(6, 0))
        self._trace_target = theme.field(bar, i18n.t("ph.host"), width=210)
        self._trace_target.grid(row=0, column=0, padx=(0, 8))
        theme.caption(bar, i18n.t("qt.trace.hops")).grid(row=0, column=1, padx=(0, 4))
        self._trace_hops = self._option_menu(
            bar, [str(value) for value in TRACE_HOP_CHOICES], 54
        )
        self._trace_hops.grid(row=0, column=2, padx=(0, 8))
        theme.primary_button(
            bar, i18n.t("btn.trace"), self._quick_trace, 104
        ).grid(row=0, column=3)

        self._trace_summary = ctk.CTkLabel(
            panel, text="", anchor="w", font=ctk.CTkFont(size=11),
            text_color=theme.current().text_secondary,
        )
        self._trace_summary.grid(row=2, column=0, sticky="w", padx=12, pady=(8, 0))

        self._trace_body = ctk.CTkScrollableFrame(
            panel, fg_color="transparent", corner_radius=0, label_text="",
            scrollbar_button_color=theme.current().border,
        )
        self._trace_body.grid(row=3, column=0, sticky="nsew", padx=(6, 6), pady=(4, 0))
        self._trace_body.grid_columnconfigure(0, weight=1)

        theme.secondary_button(
            panel, i18n.t("btn.copy.path"), self._copy_trace_path, 116
        ).grid(row=4, column=0, sticky="e", padx=12, pady=(4, 10))

    def _quick_trace(self) -> None:
        """Trace the target and plot the path."""
        target = self._trace_target.get().strip()
        if not target:
            self._set_phase(i18n.t("hint.target"))
            return
        self._set_phase(i18n.t("qt.trace.running", target=target))
        self._run_tool(
            traceroute, target, int(self._trace_hops.get()),
            handler=self._render_hops,
        )

    def _render_hops(self, result: ToolResult) -> None:
        """Paint the traced path, or why the trace came back empty."""
        self._hops = result.hops
        self._paint_hops(result.hops)
        if not result.ok and not result.hops:
            self._set_phase(result.error or i18n.t("tool.error"))
        else:
            self._set_phase(i18n.t("status.ready"))

    def _paint_hops(self, hops: list[TracerouteHop]) -> None:
        """One row per hop: index, latency bar, times, address and host."""
        palette = theme.current()
        for child in self._trace_body.winfo_children():
            child.destroy()

        if not hops:
            ctk.CTkLabel(
                self._trace_body, text=i18n.t("qt.trace.empty"), anchor="w",
                font=ctk.CTkFont(size=12), text_color=palette.text_secondary,
            ).grid(row=0, column=0, sticky="w", padx=12, pady=18)
            self._trace_summary.configure(text="")
            return

        answered = [hop for hop in hops if hop.responded]
        destination = answered[-1].hop if answered else None
        for position, hop in enumerate(hops):
            row = ctk.CTkFrame(self._trace_body, fg_color="transparent")
            row.grid(row=position, column=0, sticky="ew", pady=1)
            row.grid_columnconfigure(4, weight=1)

            ctk.CTkLabel(
                row, text=f"{hop.hop:>2}", width=22, anchor="e",
                font=ctk.CTkFont(family="Consolas", size=12),
                text_color=palette.text_secondary,
            ).grid(row=0, column=0, padx=(6, 6))
            self._trace_bar(row, hop)
            ctk.CTkLabel(
                row, text=self._hop_rtt_text(hop), width=86, anchor="w",
                font=ctk.CTkFont(family="Consolas", size=12),
                text_color=palette.text_primary if hop.responded
                else palette.text_secondary,
            ).grid(row=0, column=2, padx=6)
            ctk.CTkLabel(
                row, text=hop.address, width=140, anchor="w",
                font=ctk.CTkFont(family="Consolas", size=12),
                text_color=palette.text_primary,
            ).grid(row=0, column=3, padx=6)

            is_destination = hop.hop == destination
            note = hop.hostname
            if is_destination:
                note = f"{note}  ({i18n.t('qt.trace.dest')})" if note else i18n.t("qt.trace.dest")
            ctk.CTkLabel(
                row, text=note, anchor="w", font=ctk.CTkFont(size=11),
                text_color=palette.primary if is_destination
                else palette.text_secondary,
            ).grid(row=0, column=4, sticky="w", padx=6)

        mean = sum(hop.rtt for hop in answered) / len(answered)
        self._trace_summary.configure(text=i18n.t(
            "qt.trace.summary", hops=len(hops), answered=len(answered),
            average=f"{mean:.0f}",
        ))

    def _trace_bar(self, master, hop: TracerouteHop) -> None:
        """Latency bar: full width is TRACE_SCALE_MS, empty means no reply."""
        track = ctk.CTkFrame(
            master, width=TRACE_BAR_WIDTH, height=10, corner_radius=5,
            fg_color=theme.current().border,
        )
        track.grid(row=0, column=1, padx=6)
        track.grid_propagate(False)

        rtt = hop.rtt
        if rtt is None:
            return
        fill = ctk.CTkFrame(
            track, height=10, corner_radius=5, fg_color=self._rtt_colour(rtt)
        )
        fill.place(relx=0.0, rely=0.0, relheight=1.0,
                   relwidth=min(rtt / TRACE_SCALE_MS, 1.0))

    def _rtt_colour(self, rtt: float) -> str:
        """Green for a quick hop, amber when it drags, red past the limit."""
        palette = theme.current()
        if rtt <= TRACE_FAST_MS:
            return palette.online
        return palette.vpn if rtt <= TRACE_SLOW_MS else palette.warning

    def _hop_rtt_text(self, hop: TracerouteHop) -> str:
        """Round-trip times of one hop, or the no-reply label."""
        if not hop.responded:
            return i18n.t("qt.trace.noreply")
        return " / ".join(f"{value:.0f}" for value in hop.rtts) + " ms"

    def _copy_trace_path(self) -> None:
        """Copy the traced path as tab-separated text."""
        if not self._hops:
            self._set_phase(i18n.t("qt.trace.empty"))
            return
        self._copy("\n".join(
            f"{hop.hop}\t{hop.address}\t{self._hop_rtt_text(hop)}\t{hop.hostname}"
            for hop in self._hops
        ))
        self._set_phase(i18n.t("qt.copied"))

    # ------------------------------------------------------------------
    # Quick tools: live latency graph
    # ------------------------------------------------------------------
    def _build_latency_panel(self, parent: ctk.CTkBaseClass) -> None:
        """
        Ping graph plus the numbers behind it.

        A sparkline shows the *shape* of a link - the spikes and the gaps -
        which a single "12 ms" cell can never show. The row underneath keeps
        the exact figures, and lost probes are drawn as breaks in the line
        instead of being quietly averaged away.
        """
        panel = self._quick_panel(parent, i18n.t("qt.latency.title"))
        panel.grid(row=1, column=0, sticky="nsew", pady=(6, 0))
        panel.grid_rowconfigure(2, weight=1)

        bar = ctk.CTkFrame(panel, fg_color="transparent")
        bar.grid(row=1, column=0, sticky="ew", padx=12, pady=(6, 0))
        self._latency_field = theme.field(bar, i18n.t("ph.host"), width=190)
        self._latency_field.grid(row=0, column=0, padx=(0, 8))
        self._latency_field.bind("<Return>", lambda _e: self._on_latency_toggle())
        theme.caption(bar, i18n.t("qt.latency.every")).grid(row=0, column=1, padx=(0, 4))
        self._latency_menu = self._option_menu(
            bar, [f"{value:g} s" for value in LATENCY_INTERVALS], 68
        )
        self._latency_menu.set(f"{self._latency_interval:g} s")
        self._latency_menu.grid(row=0, column=2, padx=(0, 8))
        self._latency_button = theme.primary_button(
            bar, i18n.t("qt.latency.start"), self._on_latency_toggle, 100
        )
        self._latency_button.grid(row=0, column=3)

        self._latency_chart = theme.Sparkline(
            panel, height=112, capacity=LATENCY_SAMPLES,
            fast_ms=TRACE_FAST_MS, slow_ms=TRACE_SLOW_MS, axis=True,
        )
        self._latency_chart.grid(row=2, column=0, sticky="nsew", padx=12, pady=(8, 0))

        # Stands in for the empty plot, then steps aside for the real one.
        self._latency_hint = ctk.CTkLabel(
            panel, text=i18n.t("qt.latency.idle"), font=ctk.CTkFont(size=12),
            text_color=theme.current().text_secondary,
        )
        self._latency_hint.grid(row=3, column=0, sticky="w", padx=12, pady=(2, 0))

        stats = ctk.CTkFrame(panel, fg_color="transparent")
        stats.grid(row=4, column=0, sticky="ew", padx=12, pady=(8, 10))
        keys = ("last", "min", "avg", "max", "jitter", "loss")
        stats.grid_columnconfigure(len(keys) - 1, weight=1)
        self._latency_stats: dict[str, ctk.CTkLabel] = {}
        for index, key in enumerate(keys):
            block = ctk.CTkFrame(stats, fg_color="transparent")
            block.grid(row=0, column=index, padx=(0, 16), sticky="w")
            theme.caption(block, i18n.t(f"qt.latency.{key}")).grid(row=0, column=0, sticky="w")
            value = ctk.CTkLabel(
                block, text="-", anchor="w", font=ctk.CTkFont(family="Consolas", size=13),
                text_color=theme.current().text_primary,
            )
            value.grid(row=1, column=0, sticky="w")
            self._latency_stats[key] = value

    def _interval_value(self) -> float:
        """Seconds shown in the cadence dropdown, as a number."""
        try:
            return float(str(self._latency_menu.get()).split()[0])
        except (AttributeError, ValueError, IndexError):
            return LATENCY_INTERVALS[1]

    def _on_latency_toggle(self) -> None:
        """Start the graph on the typed host, or stop the running capture."""
        if self._latency_running:
            self._stop_latency()
            return
        self._start_latency(self._latency_field.get().strip())

    def _start_latency(self, host: str) -> None:
        """Begin probing ``host`` on the cadence chosen in the dropdown."""
        host = host.strip()
        if not host:
            self._set_phase(i18n.t("hint.host"))
            return

        self._latency_samples.clear()
        self._latency_host = host
        self._latency_interval = self._interval_value()
        self._latency_stop.clear()
        self._latency_running = True
        self._latency_button.configure(text=i18n.t("qt.latency.stop"))
        self._set_phase(i18n.t(
            "qt.latency.running", host=host, interval=self._latency_interval
        ))
        threading.Thread(
            target=self._latency_worker, args=(host,), daemon=True, name="latency"
        ).start()
        self._drain_aux()

    def _stop_latency(self) -> None:
        """Ask the probe thread to finish and reset the button."""
        self._latency_running = False
        self._latency_stop.set()
        self._latency_button.configure(text=i18n.t("qt.latency.start"))
        self._set_phase(i18n.t("qt.latency.stopped"))

    def _latency_worker(self, host: str) -> None:
        """Probe one host on a fixed cadence until stopped."""
        while not self._latency_stop.is_set():
            self._aux_queue.put(("__latency__", ping_once(host, timeout=LATENCY_TIMEOUT_S)))
            self._latency_stop.wait(self._latency_interval)

    def _append_latency(self, sample: float | None) -> None:
        """Add one probe to the graph and repaint the statistics row."""
        self._latency_samples.append(sample)
        self._latency_chart.set_samples(self._latency_samples)
        self._latency_hint.grid_remove()
        self._paint_latency_stats(latency_stats(self._latency_samples))

    def _paint_latency_stats(self, stats) -> None:
        """Show last/min/avg/max/jitter in ms and the loss share in percent."""
        if not stats.sent:
            return

        def ms(value: float | None) -> str:
            return "-" if value is None else f"{value:.0f} ms"

        for key, value in (
            ("last", ms(stats.last)), ("min", ms(stats.minimum)),
            ("avg", ms(stats.average)), ("max", ms(stats.maximum)),
            ("jitter", ms(stats.jitter)), ("loss", f"{stats.loss:g} %"),
        ):
            self._latency_stats[key].configure(text=value)

        if not stats.answered:
            self._set_phase(i18n.t("qt.latency.lost", host=self._latency_host))

    def _restore_latency(self) -> None:
        """Rebuild the graph after a language switch, capture still running."""
        if self._latency_host:
            self._latency_field.delete(0, "end")
            self._latency_field.insert(0, self._latency_host)
        self._latency_menu.set(f"{self._latency_interval:g} s")
        self._latency_button.configure(text=i18n.t(
            "qt.latency.stop" if self._latency_running else "qt.latency.start"
        ))
        if self._latency_samples:
            self._latency_chart.set_samples(self._latency_samples)
            self._latency_hint.grid_remove()
            self._paint_latency_stats(latency_stats(self._latency_samples))



    def _build_subnet_panel(self, parent: ctk.CTkBaseClass) -> None:
        """CIDR calculator: every field of a block, plus an optional split."""
        panel = self._quick_panel(parent, i18n.t("qt.subnet.title"))
        panel.grid(row=0, column=0, sticky="nsew")
        panel.grid_rowconfigure(3, weight=1)

        bar = ctk.CTkFrame(panel, fg_color="transparent")
        bar.grid(row=1, column=0, sticky="ew", padx=12, pady=(6, 0))
        self._subnet_entry = theme.field(bar, i18n.t("ph.cidr"), width=160)
        self._subnet_entry.grid(row=0, column=0, padx=(0, 8))
        theme.caption(bar, i18n.t("qt.trace.split")).grid(row=0, column=1, padx=(0, 4))
        self._subnet_split = self._option_menu(
            bar, [str(value) for value in SUBNET_SPLIT_CHOICES], 54
        )
        self._subnet_split.grid(row=0, column=2, padx=(0, 8))
        theme.primary_button(
            bar, i18n.t("btn.calculate"), self._quick_subnet, 108
        ).grid(row=0, column=3)

        grid = ctk.CTkFrame(panel, fg_color="transparent")
        grid.grid(row=2, column=0, sticky="ew", padx=12, pady=(8, 0))
        self._subnet_values: list[ctk.CTkLabel] = []
        for index, key in enumerate(SUBNET_FIELD_KEYS):
            cell = ctk.CTkFrame(grid, fg_color="transparent")
            cell.grid(row=index // 2, column=index % 2, sticky="w", pady=1, padx=(0, 8))
            theme.caption(cell, i18n.t(key)).grid(row=0, column=0, sticky="w", padx=(0, 8))
            value = ctk.CTkLabel(
                cell, text="-", anchor="w", width=162,
                font=ctk.CTkFont(family="Consolas", size=12),
                text_color=theme.current().text_primary,
            )
            value.grid(row=0, column=1, sticky="w")
            self._subnet_values.append(value)

        self._plan_box = self._textbox(panel, wrap="none", height=92)
        self._plan_box.grid(row=3, column=0, sticky="nsew", padx=12, pady=(8, 12))

    def _quick_subnet(self) -> None:
        """
        Fill the calculator. Pure address arithmetic with no socket involved,
        so it runs inline instead of taking a worker thread.
        """
        cidr = self._subnet_entry.get().strip()
        if not cidr:
            self._set_phase(i18n.t("hint.tool"))
            return

        details = subnet_details(cidr)
        if not details.ok or not isinstance(details.data, SubnetInfo):
            self._paint_subnet(None, "", details.error or i18n.t("qt.subnet.invalid"))
            self._set_phase(i18n.t("qt.subnet.invalid"))
            return

        count = int(self._subnet_split.get())
        plan_lines = ""
        if count > 1:
            plan = split_subnet(cidr, count)
            plan_lines = "\n".join(plan.lines) if plan.ok else plan.error
        self._paint_subnet(details.data, plan_lines)
        self._set_phase(i18n.t("status.ready"))

    def _paint_subnet(self, info: SubnetInfo | None, plan: str,
                      error: str = "") -> None:
        """Write the calculator fields and the optional split plan."""
        if info is None:
            values = ["-"] * len(SUBNET_FIELD_KEYS)
        else:
            values = [
                f"{info.network}/{info.prefixlen}",
                info.netmask,
                info.wildcard,
                info.broadcast,
                info.first_host,
                info.last_host,
                f"{info.total_addresses:,}",
                f"{info.usable_hosts:,}",
                i18n.t("sub.private") if info.is_private else i18n.t("sub.public"),
            ]
        for label, value in zip(self._subnet_values, values):
            label.configure(text=value)

        self._subnet_data, self._subnet_plan = info, plan
        self._plan_box.delete("1.0", "end")
        if error:
            self._plan_box.insert("end", error + "\n")
        elif plan:
            self._plan_box.insert("end", plan + "\n")
        elif info is not None:
            self._plan_box.insert("end", i18n.t("qt.subnet.plan.hint") + "\n")

    def _build_lookup_panel(self, parent: ctk.CTkBaseClass) -> None:
        """Quick DNS resolution and WHOIS, sharing one output box."""
        panel = self._quick_panel(parent, i18n.t("qt.lookup.title"))
        panel.grid(row=1, column=0, sticky="nsew", pady=(6, 0))
        panel.grid_rowconfigure(2, weight=1)

        bar = ctk.CTkFrame(panel, fg_color="transparent")
        bar.grid(row=1, column=0, sticky="ew", padx=12, pady=(6, 0))
        self._lookup_target = theme.field(bar, i18n.t("ph.domain"), width=190)
        self._lookup_target.grid(row=0, column=0, padx=(0, 8))
        self._lookup_record = self._option_menu(bar, DNS_RECORD_TYPES, 68)
        self._lookup_record.grid(row=0, column=1, padx=(0, 8))
        theme.secondary_button(
            bar, i18n.t("btn.resolve"), self._quick_resolve, 86
        ).grid(row=0, column=2, padx=3)
        theme.secondary_button(
            bar, i18n.t("btn.summary"), self._quick_overview, 96
        ).grid(row=0, column=3, padx=3)
        theme.primary_button(
            bar, i18n.t("btn.whois"), self._quick_whois, 86
        ).grid(row=0, column=4, padx=3)

        self._lookup_box = self._textbox(panel, wrap="word")
        self._lookup_box.grid(row=2, column=0, sticky="nsew", padx=12, pady=(8, 12))

    def _quick_resolve(self) -> None:
        """Resolve the record type selected in the dropdown."""
        target = self._lookup_value()
        if target:
            self._run_tool(
                dns_lookup, target, self._lookup_record.get(),
                handler=self._render_lookup,
            )

    def _quick_overview(self) -> None:
        """Show the A / AAAA / NS / MX records of a domain at a glance."""
        target = self._lookup_value()
        if target:
            self._run_tool(dns_summary, target, handler=self._render_lookup)

    def _quick_whois(self) -> None:
        """Look up the owner of a domain or an IP address."""
        target = self._lookup_value()
        if target:
            self._run_tool(whois_lookup, target, handler=self._render_whois)

    def _lookup_value(self) -> str:
        """The lookup target, or empty after complaining in the status bar."""
        target = self._lookup_target.get().strip()
        if not target:
            self._set_phase(i18n.t("hint.target"))
        return target

    def _render_lookup(self, result: ToolResult) -> None:
        """Print a plain tool result in the lookup box."""
        lines = list(result.lines) or ([result.output] if result.output.strip() else [])
        if result.error:
            lines.insert(0, f"! {result.error}")
        if not lines:
            lines.append(i18n.t("qt.lookup.empty"))
        self._paint_lookup("\n".join(lines))
        self._set_phase(i18n.t("status.ready"))

    def _render_whois(self, result: ToolResult) -> None:
        """Show the key fields first, then the raw response underneath."""
        if not result.ok:
            self._paint_lookup(result.error or i18n.t("tool.error"))
            self._set_phase(result.error or i18n.t("tool.error"))
            return

        width = max(len(i18n.t(key)) for key in WHOIS_LABEL_KEYS.values())
        lines = [
            f"{i18n.t(WHOIS_LABEL_KEYS.get(key, key)):<{width}}  {value}"
            for key, value in whois_key_fields(result.output)
        ]
        if not lines:
            lines.append(i18n.t("qt.lookup.empty"))
        lines.append("")
        lines.extend(result.lines[:120])
        self._paint_lookup("\n".join(lines))
        self._set_phase(i18n.t("status.ready"))

    def _paint_lookup(self, text: str) -> None:
        """Replace the lookup box content and remember it for a rebuild."""
        self._lookup_text = text
        self._lookup_box.delete("1.0", "end")
        if text:
            self._lookup_box.insert("end", text + "\n")

    def _capture_quick_state(self) -> None:
        """Save the quick-tools inputs and results before a rebuild."""
        try:
            self._quick_inputs = {
                "trace": self._trace_target.get(),
                "subnet": self._subnet_entry.get(),
                "lookup": self._lookup_target.get(),
            }
        except (AttributeError, tk.TclError):
            self._quick_inputs = {}

    def _restore_quick_state(self) -> None:
        """Repaint the quick tools from the state captured before a rebuild."""
        try:
            if self._hops:
                self._paint_hops(self._hops)
            if self._subnet_data is not None:
                self._paint_subnet(self._subnet_data, self._subnet_plan)
            if self._lookup_text:
                self._paint_lookup(self._lookup_text)
            self._restore_latency()
        except (AttributeError, tk.TclError):
            pass


    def _render_http(self, report: HttpReport) -> None:
        self._append_output("-" * 78)
        self._append_output(f"? HTTP AUDIT   {report.url}")
        self._append_output(
            f"    status: {report.status_code}    server: {report.server or '-'}"
            f"    {report.elapsed_ms:.0f} ms"
        )
        if report.error:
            self._append_output(f"    ! {report.error}")
        for severity, detail in report.findings:
            self._append_output(f"    [{severity.upper():8}] {detail}")
        self._append_output("")

    def _render_tls(self, report: TlsReport) -> None:
        self._append_output("-" * 78)
        self._append_output(f"? TLS CERTIFICATE   {report.host}:{report.port}")
        if not report.supported:
            self._append_output(f"    ! {report.error or 'TLS not available'}")
            self._append_output("")
            return
        self._append_output(f"    protocol : {report.protocol}    cipher: {report.cipher}")
        self._append_output(f"    issuer   : {report.issuer}")
        if report.days_remaining is not None:
            self._append_output(
                f"    expires  : {report.not_after}    ({report.days_remaining} days)"
            )
        self._append_output(f"    san      : {', '.join(report.subject_alt_names[:5])}")
        for issue in report.findings:
            self._append_output(f"    * {issue}")
        self._append_output("")

    def _show_all_ports(self, device: Device) -> None:
        """
        Show every open port of a host in a window of its own.

        The grid cell is one line tall by design, so this is where the complete
        list is actually readable. It is also copyable, which is what an
        operator does with it.
        """
        top = tk.Toplevel(self)
        top.title(f"{i18n.t('ctx.ports', count=device.open_port_count)}"
                  f" - {device.ip_address}")
        top.geometry("460x420")
        top.transient(self)

        text = tk.Text(top, wrap="none", font=ctk.CTkFont(size=11),
                       borderwidth=0, highlightthickness=0)
        scroll = ctk.CTkScrollbar(top, command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        scroll.pack(side="right", fill="y", padx=(0, 10), pady=10)

        text.insert("1.0", device.ports_summary or "-")
        text.configure(state="disabled")

        ctk.CTkButton(
            top, text=i18n.t("btn.close"), width=90,
            command=top.destroy,
        ).pack(pady=(0, 10))

    def _on_context_menu(self, event) -> None:
        """Right-click actions for the device under the pointer."""
        key = self._table.key_at(event.y)
        if key is None:
            key = self._table.selected_key()
        if key is None:
            return
        device = self._devices.get(key)
        if device is None:
            return
        self._table.select_key(key)

        menu = tk.Menu(self, tearoff=0)
        web_port = best_web_port(device)
        menu.add_command(
            label=i18n.t("ctx.ping"),
            command=lambda: self._do_ping(device),
        )
        menu.add_command(
            label=i18n.t("ctx.rdp"),
            command=lambda: self._do_rdp(device),
            state="normal" if device.has_port(3389) else "disabled",
        )
        menu.add_command(
            label=i18n.t("ctx.web"),
            command=lambda: self._do_web(device, web_port),
            state="normal" if web_port else "disabled",
        )
        menu.add_command(
            label=i18n.t("ctx.wol"),
            command=lambda: self._do_wol(device),
            state="normal" if device.mac_address else "disabled",
        )
        menu.add_separator()
        # The cell only fits a few services, so the full list is one click away
        # here. Without it a host with twenty open ports looked like it had
        # four.
        if device.open_port_count:
            menu.add_command(
                label=i18n.t("ctx.ports", count=device.open_port_count),
                command=lambda: self._show_all_ports(device),
            )
        menu.add_command(label=i18n.t("ctx.copy"), command=lambda: self._copy(device.ip_address))
        menu.add_command(label=i18n.t("ctx.export"), command=lambda: self._export_row(device))
        menu.add_command(label=i18n.t("ctx.audit"), command=lambda: self._do_audit(device))
        menu.add_command(
            label=i18n.t("ctx.latency"), command=lambda: self._do_latency(device))
        menu.add_command(
            label=i18n.t("ctx.monitor"), command=lambda: self._watch(device))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _do_ping(self, device: Device) -> None:
        import subprocess

        command = (["ping", "-n", "4", device.ip_address] if sys.platform == "win32"
                   else ["ping", "-c", "4", device.ip_address])
        threading.Thread(
            target=lambda: subprocess.run(command, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)),
            daemon=True,
        ).start()
        self._set_phase(i18n.t("ctx.ping_sent", ip=device.ip_address))

    def _do_rdp(self, device: Device) -> None:
        ok, message = open_remote_desktop(device.ip_address)
        if not ok:
            messagebox.showerror(i18n.t("ctx.rdp"), message)

    def _do_web(self, device: Device, port: int | None) -> None:
        if port and not open_web(device.ip_address, port):
            messagebox.showerror(i18n.t("ctx.web"), i18n.t("hint.tool"))

    def _do_wol(self, device: Device) -> None:
        """Wake a device and say so: a silent click reads as a dead button."""
        ok, reason = wake_device(device)
        if ok:
            self._set_phase(i18n.t("wol.sent", mac=reason))
        else:
            messagebox.showerror(i18n.t("ctx.wol"), reason)

    def _do_audit(self, device: Device) -> None:
        self._tabs.set(i18n.t("tab.audit"))
        self._audit_target.delete(0, "end")
        self._audit_target.insert(0, device.ip_address)
        self._run_audit([device.ip_address])

    def _do_latency(self, device: Device) -> None:
        """Jump to the live graph with this device already being probed."""
        self._tabs.set(i18n.t("tab.quick"))
        if self._latency_running:
            self._stop_latency()
        self._start_latency(device.ip_address)

    def _export_row(self, device: Device) -> None:
        """Write a single device to a file chosen by the user."""
        path = filedialog.asksaveasfilename(
            title=i18n.t("ctx.export"),
            initialfile=f"{device.ip_address}.csv",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")],
        )
        if not path:
            return
        from ..actions.exporter import export

        try:
            written = export([device], path)
        except OSError as exc:
            messagebox.showerror(i18n.t("ctx.export"), str(exc))
            return
        self._set_phase(i18n.t("msg.exported", path=written.name))

    def _on_export_data(self, suffix: str) -> None:
        """
        Write the whole visible inventory to CSV or JSON.

        What the operator sees is what gets written: a filtered table exports
        the filtered set, which is the point of filtering by "HP" before
        handing the result to someone else.
        """
        devices = self._visible_devices()
        if not devices:
            self._set_phase(i18n.t("hint.scanfirst"))
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M")
        path = filedialog.asksaveasfilename(
            title=i18n.t(f"export.{suffix}"),
            initialfile=f"inventario_{stamp}.{suffix}",
            defaultextension=f".{suffix}",
            filetypes=[(suffix.upper(), f"*.{suffix}")],
        )
        if not path:
            return
        from ..actions.exporter import export

        try:
            written = export(devices, path, self._report_payload())
        except OSError as exc:
            messagebox.showerror(i18n.t("ctx.export"), str(exc))
            return
        self._set_phase(i18n.t("export.done", count=len(devices), path=written.name))


    def _copy(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)

    # ------------------------------------------------------------------
    # Status bar, footer and lifecycle
    # ------------------------------------------------------------------
    def _build_status_bar(self) -> None:
        """
        The status strip pinned to the bottom of the window.

        Progress is reported the way a transfer dialog reports it: how far
        along, and how many of how many. A bar with no numbers leaves the
        operator guessing whether a slow sweep is stuck or merely thorough.
        """
        bar = ctk.CTkFrame(
            self, fg_color=theme.current().surface, corner_radius=0)
        bar.grid(row=3, column=0, sticky="ew", pady=(0, 0))
        bar.grid_columnconfigure(1, weight=1)
        # A 2px rule along the top edge: the strip reads as part of the window
        # rather than as a panel dropped below the table.
        rule = ctk.CTkFrame(bar, fg_color=theme.current().grid_line,
                            height=1, corner_radius=0)
        rule.grid(row=0, column=0, columnspan=3, sticky="ew")

        self._progress, self._progress_set = theme.progress_bar(
            bar, width=1, height=2)
        self._progress.grid(row=1, column=0, columnspan=3, sticky="ew")

        inner = ctk.CTkFrame(bar, fg_color="transparent")
        inner.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(5, 5),
                   padx=16)
        inner.grid_columnconfigure(1, weight=1)
        # The signature is built into this strip rather than into a row of its
        # own, so the window ends in one fixed band instead of two that fight
        # over the same grid row.
        self._status_inner = inner

        self._phase_label = ctk.CTkLabel(
            inner, text=i18n.t("status.ready"), anchor="w",
            font=ctk.CTkFont(size=10),
            text_color=theme.current().text_secondary,
        )
        self._phase_label.grid(row=0, column=0, sticky="w")

        # Live count of what has been found, the number an operator watches.
        self._counter_label = ctk.CTkLabel(
            inner, text="", anchor="e", font=ctk.CTkFont(size=10),
            text_color=theme.current().text_secondary,
        )
        self._counter_label.grid(row=0, column=2, sticky="e")

        # The detected segment stays on screen: it is the answer to "why is
        # it scanning this range", and it survives every status message.
        self._net_label = ctk.CTkLabel(
            bar, text=self._network_caption(), anchor="e",
            font=ctk.CTkFont(size=10),
            text_color=theme.current().text_muted,
        )
        self._net_label.grid(row=0, column=3, sticky="e", padx=(0, 0))
        self._sections.append(bar)

    def _network_caption(self) -> str:
        """One line describing the segment and gateway the scan will use."""
        gateway = default_gateway(self._interface_name)
        if not gateway:
            return ""
        return i18n.t("net.gateway", gateway=gateway)

    def _refresh_network_caption(self) -> None:
        """Update the segment caption after the adapter or range changes."""
        label = getattr(self, "_net_label", None)
        if label is not None:
            label.configure(text=self._network_caption())

    def _build_footer(self) -> None:
        """
        The signature, which now lives inside the status strip.

        It used to be a row of its own below the status bar, which meant the
        two competed for the same grid row and the bar was pushed off the
        bottom edge. The strip is the natural home for it: one fixed band, and
        the table keeps every pixel that is left.
        """
        footer = getattr(self, "_status_inner", None)
        if footer is None:
            # Only during a language rebuild, before the strip exists again.
            ctk.CTkLabel(
                self, text=f"{APP_NAME}   ·   by {APP_AUTHOR}",
                font=ctk.CTkFont(size=9), anchor="e",
                text_color=theme.current().text_muted,
            ).grid(row=2, column=0, sticky="se", padx=20)
            return
        ctk.CTkLabel(
            footer, text=f"{APP_NAME}   ·   by {APP_AUTHOR}",
            font=ctk.CTkFont(size=9), anchor="e",
            text_color=theme.current().text_muted,
        ).grid(row=1, column=2, sticky="e", padx=(12, 0))

    # ------------------------------------------------------------------
    # Language switching
    # ------------------------------------------------------------------
    def _set_title(self) -> None:
        self.title(APP_NAME)

    def _on_language_change(self, value: str) -> None:
        """Switch language and rebuild every visible string in place."""
        index = self._tab_index()
        i18n.set_language(value.lower())
        self._rebuild_ui(index)

    def _rebuild_ui(self, tab: int | None = None) -> None:
        """
        Rebuild the chrome so a language change is reflected everywhere.

        Scan results live in ``self._devices``, so the inventory survives
        the rebuild; only the widgets are recreated. ``tab`` restores the tab
        the operator was looking at, which the rebuild would otherwise reset
        to the first one.
        """
        if self._scanning:
            return

        tool_output = ""
        try:
            tool_output = self._tool_output.get("1.0", "end")
        except (AttributeError, tk.TclError):
            pass
        try:
            self._saved_range = self._range_entry.get().strip()
        except (AttributeError, tk.TclError):
            self._saved_range = ""

        self._capture_quick_state()
        for section in self._sections:
            section.destroy()
        self._sections.clear()
        self._empty_hint = None

        self._build_header()
        self._build_tabs()
        if tab is not None:
            self._select_tab(TAB_KEYS[tab % len(TAB_KEYS)])
        self._build_status_bar()
        self._build_footer()
        self._prefill_inputs()
        theme.set_mode(ctk.get_appearance_mode())
        self._render_table(force=True)
        self._render_findings(self._findings)
        self._restore_quick_state()
        if tool_output.strip():
            self._tool_output.delete("1.0", "end")
            self._tool_output.insert("end", tool_output)
        self._set_phase(i18n.t("status.ready"))

    def _on_close(self) -> None:
        """Stop the running workers before destroying the window."""
        if self._scanning:
            self._scanner.stop()
        self._latency_running = False
        self._latency_stop.set()
        self.monitor.stop()
        self.destroy()


def launch() -> None:
    """Start the application. Used by :mod:`ip_inspector.main`."""
    ctk.set_appearance_mode("system")
    ctk.set_default_color_theme("blue")
    theme.set_mode(ctk.get_appearance_mode())
    window = IPInspectorApp()
    window.protocol("WM_DELETE_WINDOW", window._on_close)
    window.mainloop()
