"""The Tools tab: standalone network diagnostics with a shared console.

Each tool is declared once in :data:`TOOLS` (name, inputs, runner). The tab
builds its form from that declaration, runs the tool on a worker thread and
prints the :class:`ToolResult` into the console, so adding a tool never
touches the layout code.
"""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from dataclasses import dataclass, field
from datetime import datetime
from tkinter import filedialog, ttk
from typing import Callable

from ..core.models import ToolResult
from ..nettools import tools
from ..nettools.profiles import parse_ports
from . import theme
from .widgets import scrolled, text_box


@dataclass(frozen=True)
class Field:
    """One input of a tool form."""

    key: str
    label: str
    placeholder: str = ""
    default: str = ""
    #: When set, the input is a drop-down with these values.
    choices: tuple[str, ...] = ()


@dataclass(frozen=True)
class Tool:
    """A tool as the tab shows it."""

    name: str
    category: str
    description: str
    fields: tuple[Field, ...]
    run: Callable[[dict[str, str]], ToolResult]
    #: Tools that only read local state need no target.
    needs_input: bool = True
    extra: dict = field(default_factory=dict)


def _int(values: dict[str, str], key: str, default: int) -> int:
    try:
        return int(values.get(key, "") or default)
    except ValueError:
        raise ValueError(f"'{values.get(key)}' is not a number") from None


TOOLS: tuple[Tool, ...] = (
    # -- Connectivity ---------------------------------------------------- #
    Tool("Ping", "Connectivity", "ICMP echo: latency, packet loss and TTL.",
         (Field("host", "Host", "192.168.1.1 or example.com"),
          Field("count", "Count", "", "4", ("1", "4", "10", "20"))),
         lambda v: tools.ping_host(v["host"], _int(v, "count", 4))),
    Tool("Traceroute", "Connectivity", "Every router between you and the target.",
         (Field("host", "Host", "example.com"),
          Field("hops", "Max hops", "", "20", ("10", "20", "30"))),
         lambda v: tools.traceroute(v["host"], _int(v, "hops", 20))),
    Tool("Port check", "Connectivity",
         "TCP connect scan of one host. Ranges allowed: 22,80,443,8000-8100 or 1-65535.",
         (Field("host", "Host", "192.168.1.1"),
          Field("ports", "Ports", "22,80,443,8000-8100", "1-1024"),
          Field("timeout", "Timeout (s)", "", "0.5", ("0.3", "0.5", "1", "2"))),
         lambda v: tools.port_check(v["host"], parse_ports(v["ports"]),
                                    float(v.get("timeout") or 0.5))),
    Tool("Shared folders", "Connectivity", "Folders and printers a Windows host shares (SMB).",
         (Field("host", "Host", "192.168.1.10"),),
         lambda v: tools.list_shares(v["host"])),
    Tool("Wake-on-LAN", "Connectivity", "Send a magic packet to power on a machine.",
         (Field("mac", "MAC address", "AA:BB:CC:DD:EE:FF"),),
         lambda v: tools.wake_on_lan(v["mac"])),
    # -- DNS ------------------------------------------------------------- #
    Tool("DNS lookup", "DNS", "Resolve a name for a given record type.",
         (Field("domain", "Domain", "example.com"),
          Field("type", "Record", "", "A", tools.DNS_RECORD_TYPES)),
         lambda v: tools.dns_lookup(v["domain"], v.get("type") or "A")),
    Tool("Reverse DNS", "DNS", "PTR record of an IP address.",
         (Field("ip", "IP address", "8.8.8.8"),),
         lambda v: tools.reverse_dns(v["ip"])),
    Tool("DNS summary", "DNS", "A, AAAA, NS and MX records at a glance.",
         (Field("domain", "Domain", "example.com"),),
         lambda v: tools.dns_summary(v["domain"])),
    Tool("Mail security", "DNS", "SPF, DMARC and MX records of a domain.",
         (Field("domain", "Domain", "example.com"),),
         lambda v: tools.email_security_records(v["domain"])),
    Tool("Zone transfer", "DNS", "Try an AXFR against the domain's name servers.",
         (Field("domain", "Domain", "example.com"),),
         lambda v: tools.zone_transfer(v["domain"])),
    Tool("WHOIS", "DNS", "Registration data of a domain or IP block.",
         (Field("query", "Domain or IP", "example.com"),),
         lambda v: tools.whois_lookup(v["query"])),
    # -- Security -------------------------------------------------------- #
    Tool("TLS certificate", "Security", "Protocol, cipher, issuer and expiry.",
         (Field("host", "Host", "example.com"),
          Field("port", "Port", "", "443", ("443", "8443", "993", "995", "465"))),
         lambda v: tools.tls_check(v["host"], _int(v, "port", 443))),
    Tool("HTTP headers", "Security", "Response headers and missing security headers.",
         (Field("url", "URL", "https://example.com"),),
         lambda v: tools.http_headers(v["url"])),
    # -- Subnets --------------------------------------------------------- #
    Tool("Subnet calculator", "Subnets", "Mask, host range, broadcast and size.",
         (Field("cidr", "Network", "192.168.1.0/24"),),
         lambda v: tools.subnet_info(v["cidr"])),
    Tool("Subnet split", "Subnets", "Divide a block into equal subnets.",
         (Field("cidr", "Network", "192.168.0.0/22"),
          Field("count", "Pieces", "", "4", ("2", "4", "8", "16", "32", "64"))),
         lambda v: tools.split_subnet(v["cidr"], _int(v, "count", 4))),
    Tool("IP in network?", "Subnets", "Check whether an address is inside a block.",
         (Field("ip", "IP address", "192.168.1.50"),
          Field("cidr", "Network", "192.168.1.0/24")),
         lambda v: tools.ip_in_network(v["ip"], v["cidr"])),
    # -- This computer --------------------------------------------------- #
    Tool("Network adapters", "This computer", "Local interfaces, networks and gateway.",
         (), lambda v: tools.local_adapters(), needs_input=False),
    Tool("ARP table", "This computer", "MAC addresses this computer has learned.",
         (), lambda v: tools.arp_table(), needs_input=False),
    Tool("Listening ports", "This computer", "TCP ports open on this machine.",
         (), lambda v: tools.listening_ports(), needs_input=False),
    Tool("Local exposure", "This computer", "VPN adapters, VPN processes and proxies.",
         (), lambda v: tools.local_exposure_report(), needs_input=False),
)


def get_tool(name: str) -> Tool:
    for tool in TOOLS:
        if tool.name == name:
            return tool
    raise KeyError(name)


class ToolsTab(ttk.Frame):
    """Tool list on the left; form and console on the right."""

    POLL_MS = 120

    def __init__(self, master, on_status: Callable[[str], None] | None = None):
        super().__init__(master)
        self._on_status = on_status or (lambda _text: None)
        self._results: queue.Queue = queue.Queue()
        self._running = False
        self._tool: Tool = TOOLS[0]
        self._inputs: dict[str, ttk.Entry | ttk.Combobox] = {}
        self._build()
        self.select_tool(TOOLS[0].name)
        self._job = self.after(self.POLL_MS, self._poll)

    # -- layout -------------------------------------------------------------- #
    def _build(self) -> None:
        paned = ttk.Panedwindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True)

        left, self._list = scrolled(paned, lambda parent: ttk.Treeview(
            parent, show="tree", selectmode="browse"))
        self._list.column("#0", width=theme.px(180))
        for category in dict.fromkeys(tool.category for tool in TOOLS):
            group = self._list.insert("", "end", text=category, open=True,
                                      tags=("group",))
            for tool in TOOLS:
                if tool.category == category:
                    self._list.insert(group, "end", iid=f"tool:{tool.name}", text=tool.name)
        self._list.tag_configure("group", font=theme.UI_FONT_BOLD)
        self._list.bind("<<TreeviewSelect>>", self._on_list_select)
        paned.add(left, weight=0)

        main = ttk.Frame(paned, padding=(8, 2, 2, 2))
        main.columnconfigure(0, weight=1)
        main.rowconfigure(3, weight=1)
        paned.add(main, weight=1)

        self._title = ttk.Label(main, style="Title.TLabel")
        self._title.grid(row=0, column=0, sticky="w")
        self._description = ttk.Label(main, style="Muted.TLabel")
        self._description.grid(row=1, column=0, sticky="w", pady=(0, 6))
        self._form = ttk.Frame(main)
        self._form.grid(row=2, column=0, sticky="ew", pady=(0, 6))

        console, self._console = scrolled(main, lambda parent: text_box(parent, wrap="none", height=10),
            horizontal=True)
        console.grid(row=3, column=0, sticky="nsew")
        self._console.configure(state="disabled")

        bar = ttk.Frame(main)
        bar.grid(row=4, column=0, sticky="ew", pady=(6, 0))
        ttk.Button(bar, text="Copy", command=self._copy).pack(side="left")
        ttk.Button(bar, text="Save…", command=self._save).pack(side="left", padx=4)
        ttk.Button(bar, text="Clear", command=self.clear).pack(side="left")
        self._state_label = ttk.Label(bar, style="Muted.TLabel")
        self._state_label.pack(side="right")

    def _on_list_select(self, _event) -> None:
        selection = self._list.selection()
        if selection and selection[0].startswith("tool:"):
            name = selection[0].removeprefix("tool:")
            if name != self._tool.name:
                self.select_tool(name)

    def select_tool(self, name: str, values: dict[str, str] | None = None) -> None:
        """Show a tool's form, optionally pre-filled (used by the context menu)."""
        tool = get_tool(name)
        self._tool = tool
        iid = f"tool:{name}"
        if self._list.selection() != (iid,):
            self._list.selection_set(iid)
            self._list.see(iid)
        self._title.configure(text=tool.name)
        self._description.configure(text=tool.description)

        for child in self._form.winfo_children():
            child.destroy()
        self._inputs.clear()
        column = 0
        for spec in tool.fields:
            ttk.Label(self._form, text=spec.label + ":").grid(
                row=0, column=column, padx=(0 if column == 0 else 10, 4))
            preset = (values or {}).get(spec.key, spec.default)
            if spec.choices:
                widget = ttk.Combobox(self._form, values=list(spec.choices), width=8,
                                      state="readonly")
                widget.set(preset or spec.choices[0])
            else:
                widget = ttk.Entry(self._form, width=32 if column == 0 else 22)
                if preset:
                    widget.insert(0, preset)
                widget.bind("<Return>", lambda _e: self.run())
            widget.grid(row=0, column=column + 1)
            self._inputs[spec.key] = widget
            column += 2
        self._run_btn = ttk.Button(self._form, text="Run", command=self.run,
                                  style="Accent.TButton")
        self._run_btn.grid(row=0, column=column, padx=(12, 0))
        if self._running:
            self._run_btn.state(["disabled"])
        if tool.fields and tool.fields[0].placeholder:
            hint = ttk.Label(self._form, text=f"e.g. {tool.fields[0].placeholder}",
                             style="Muted.TLabel")
            hint.grid(row=1, column=1, sticky="w")
        first = next(iter(self._inputs.values()), None)
        if isinstance(first, ttk.Entry) and not isinstance(first, ttk.Combobox):
            first.focus_set()

    def run_tool(self, name: str, values: dict[str, str]) -> None:
        """Select a tool, fill it in and run it right away."""
        self.select_tool(name, values)
        self.run()

    # -- running ------------------------------------------------------------- #
    def run(self) -> None:
        if self._running:
            return
        tool = self._tool
        values = {key: widget.get().strip() for key, widget in self._inputs.items()}
        if tool.needs_input and tool.fields:
            first = tool.fields[0]
            if not values.get(first.key):
                self._write(f"{tool.name}: enter a value for '{first.label}'.\n\n")
                return
        self._running = True
        self._run_btn.state(["disabled"])
        self._state_label.configure(text=f"Running {tool.name}…")
        self._on_status(f"Running {tool.name}…")
        summary = "  ".join(v for v in values.values() if v)
        self._write(f"[{datetime.now():%H:%M:%S}] {tool.name}"
                    f"{'  ' + summary if summary else ''}\n")
        threading.Thread(target=self._worker, args=(tool, values),
                         name="tool-worker", daemon=True).start()

    def _worker(self, tool: Tool, values: dict[str, str]) -> None:
        started = time.perf_counter()
        try:
            result = tool.run(values)
        except Exception as exc:  # noqa: BLE001 - a tool must never kill the tab
            result = ToolResult(name=tool.name, ok=False, error=str(exc))
        self._results.put((tool, result, time.perf_counter() - started))

    def _poll(self) -> None:
        try:
            while True:
                tool, result, elapsed = self._results.get_nowait()
                self._show(tool, result, elapsed)
        except queue.Empty:
            pass
        try:
            self._job = self.after(self.POLL_MS, self._poll)
        except tk.TclError:
            pass

    def destroy(self) -> None:
        try:
            self.after_cancel(self._job)
        except (tk.TclError, ValueError):
            pass
        super().destroy()

    def _show(self, tool: Tool, result: ToolResult, elapsed: float) -> None:
        self._running = False
        try:
            self._run_btn.state(["!disabled"])
        except tk.TclError:
            pass
        body = result.output or "\n".join(result.lines)
        if body:
            self._write(body.rstrip() + "\n")
        if not result.ok or result.error:
            self._write(f"Error: {result.error or 'the tool reported a failure'}\n")
        self._write(f"Completed in {elapsed:.1f} s\n\n")
        self._state_label.configure(text=f"{tool.name}: completed in {elapsed:.1f} s")
        self._on_status(f"{tool.name} completed in {elapsed:.1f} s")

    # -- console ------------------------------------------------------------- #
    def _write(self, text: str) -> None:
        self._console.configure(state="normal")
        self._console.insert("end", text)
        self._console.see("end")
        self._console.configure(state="disabled")

    def console_text(self) -> str:
        return self._console.get("1.0", "end").strip()

    def clear(self) -> None:
        self._console.configure(state="normal")
        self._console.delete("1.0", "end")
        self._console.configure(state="disabled")

    def _copy(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self.console_text())
        self._state_label.configure(text="Output copied to the clipboard")

    def _save(self) -> None:
        text = self.console_text()
        if not text:
            self._state_label.configure(text="Nothing to save yet")
            return
        path = filedialog.asksaveasfilename(
            title="Save tool output", defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("Log", "*.log")],
            initialfile=f"ip_scanner_tools_{datetime.now():%Y%m%d_%H%M}",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text + "\n")
        except OSError as exc:
            self._state_label.configure(text=f"Could not save: {exc}")
            return
        self._state_label.configure(text=f"Saved to {path}")

    @property
    def running(self) -> bool:
        return self._running
