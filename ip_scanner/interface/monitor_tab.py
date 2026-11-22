"""The Monitor tab: keep pinging chosen hosts and alert on state changes.

The polling itself lives in :class:`ip_scanner.nettools.monitor.Monitor`,
which runs on its own thread and reports through a queue. This tab only
adds and removes hosts, refreshes the grid once a second and logs the
transitions.
"""

from __future__ import annotations

import queue
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, ttk
from typing import Callable

from ..nettools.monitor import STATUS_DOWN, STATUS_UP, Monitor
from . import theme
from .widgets import CheckBox, ip_key, scrolled, text_box

COLUMNS: tuple[tuple[str, int], ...] = (
    ("Host", 170), ("IP", 115), ("Status", 70), ("Last (ms)", 75),
    ("Avg (ms)", 75), ("Uptime", 70), ("Checks", 65), ("Lost", 55), ("Changed", 75),
)
INTERVALS = ("2", "5", "10", "30", "60")
REFRESH_MS = 1000


class MonitorTab(ttk.Frame):
    """Watch list, live statistics and an event log."""

    def __init__(self, master, icons: theme.Icons,
                 on_status: Callable[[str], None] | None = None):
        super().__init__(master)
        self._icons = icons
        self._on_status = on_status or (lambda _text: None)
        self._events: queue.Queue = queue.Queue()
        self.monitor = Monitor(self._events)
        #: ip -> device category, so rows show the same icon as the scan.
        self._categories: dict[str, str] = {}
        self._build()
        self._job = self.after(REFRESH_MS, self._refresh)

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=3)
        self.rowconfigure(5, weight=1)
        gap = theme.px(6)

        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="Monitor", style="Title.TLabel").grid(row=0, column=0,
                                                                     sticky="w")
        ttk.Label(header, text="Keep checking chosen devices and get told the moment one "
                               "stops answering.", style="Secondary.TLabel").grid(
            row=1, column=0, sticky="w", pady=(theme.px(2), 0))
        controls = ttk.Frame(header)
        controls.grid(row=0, column=1, rowspan=2, sticky="e")
        self._toggle_btn = ttk.Button(controls, text="Start monitoring", style="Accent.TButton",
                                      command=self.toggle)
        self._toggle_btn.pack(side="left")

        form = ttk.Frame(self)
        form.grid(row=1, column=0, sticky="ew", pady=(theme.px(14), theme.px(10)))

        def caption(text: str, first: bool = False) -> None:
            ttk.Label(form, text=text, style="Secondary.TLabel").pack(
                side="left", padx=(0 if first else theme.px(12), gap))

        caption("Host", first=True)
        self._host = ttk.Entry(form, width=22)
        self._host.pack(side="left")
        self._host.bind("<Return>", lambda _e: self._add_from_form())
        caption("Label")
        self._label = ttk.Entry(form, width=18)
        self._label.pack(side="left")
        caption("TCP port")
        self._port = ttk.Entry(form, width=7)
        self._port.pack(side="left")
        caption("Check every")
        self._interval = ttk.Combobox(form, values=[f"{v} s" for v in INTERVALS], width=6,
                                      state="readonly")
        self._interval.set("5 s")
        self._interval.pack(side="left")
        ttk.Button(form, text="Add host", style="Small.TButton",
                   command=self._add_from_form).pack(side="left", padx=(theme.px(12), gap))
        ttk.Button(form, text="Clear all", style="Small.TButton",
                   command=self._clear).pack(side="right")
        ttk.Button(form, text="Remove", style="Small.TButton",
                   command=self._remove_selected).pack(side="right", padx=(0, gap))

        cols = [f"m{i}" for i in range(len(COLUMNS))]
        table, self._tree = scrolled(self, lambda parent: ttk.Treeview(
            parent, columns=cols, show="tree headings", style="Results.Treeview",
            selectmode="extended"))
        table.grid(row=3, column=0, sticky="nsew")
        self._tree.column("#0", width=theme.px(40), stretch=False)
        for i, (heading, width) in enumerate(COLUMNS):
            self._tree.heading(cols[i], text=heading, anchor="w")
            self._tree.column(cols[i], width=theme.px(width), minwidth=theme.px(40), anchor="w")
        self._tree.bind("<Delete>", lambda _e: self._remove_selected())
        pal = theme.PALETTE
        self._tree.tag_configure(STATUS_DOWN, foreground=pal.danger)
        self._tree.tag_configure("unknown", foreground=pal.text_muted)

        self._empty = ttk.Label(self._tree, text="No devices watched yet. Add a host above, "
                                                  "or right-click a device in Devices and "
                                                  "choose Add to monitor.",
                                style="PaperMuted.TLabel")
        self._empty.place(relx=0.5, rely=0.45, anchor="center")

        log_header = ttk.Frame(self)
        log_header.grid(row=4, column=0, sticky="ew", pady=(theme.px(14), theme.px(4)))
        ttk.Label(log_header, text="Event log", style="Subtitle.TLabel").pack(side="left")
        self._sound = CheckBox(log_header, text="Beep when a host goes down", value=True)
        self._sound.pack(side="right")
        log, self._log = scrolled(self, lambda parent: text_box(parent, height=7))
        log.grid(row=5, column=0, sticky="nsew")
        self._log.configure(state="disabled")

    # -- actions ------------------------------------------------------------- #
    def add_host(self, ip: str, label: str = "", port: int = 0, start: bool = True,
                 category: str = "") -> None:
        """Pin a host; used by the form and by the scanner's context menu."""
        try:
            interval = float(self._interval.get().split()[0])
        except (ValueError, IndexError):
            interval = 5.0
        if category:
            self._categories[ip] = category
        host = self.monitor.add(ip, label=label, port=port, interval=interval)
        if host is None:
            return
        if start and not self.monitor.running:
            self.toggle()
        elif self.monitor.running:
            self._on_status(f"Monitoring {len(self.monitor)} "
                            f"host{'s' if len(self.monitor) != 1 else ''}")
        self._refresh_rows()

    def _add_from_form(self) -> None:
        ip = self._host.get().strip()
        if not ip:
            messagebox.showwarning("Monitor", "Type a host name or IP address to watch.",
                                   parent=self)
            return
        port_text = self._port.get().strip()
        try:
            port = int(port_text) if port_text else 0
            if not 0 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("Monitor", f"'{port_text}' is not a valid TCP port.",
                                 parent=self)
            return
        self.add_host(ip, self._label.get().strip(), port, start=False)
        self._host.delete(0, tk.END)
        self._label.delete(0, tk.END)

    def toggle(self) -> None:
        if self.monitor.running:
            self.monitor.stop()
            self._toggle_btn.configure(text="Start monitoring", style="Accent.TButton")
            self._log_line("Monitoring stopped")
            self._on_status("Monitoring stopped")
        else:
            if not len(self.monitor):
                messagebox.showinfo("Monitor", "Add at least one host first.", parent=self)
                return
            self.monitor.start()
            self._toggle_btn.configure(text="Stop monitoring", style="TButton")
            self._log_line("Monitoring started")
            self._on_status(f"Monitoring {len(self.monitor)} "
                            f"host{'s' if len(self.monitor) != 1 else ''}")

    def _remove_selected(self) -> None:
        for iid in self._tree.selection():
            self.monitor.remove(iid)
        self._refresh_rows()

    def _clear(self) -> None:
        if self.monitor.running:
            self.toggle()
        self.monitor.clear()
        self._refresh_rows()

    # -- refresh ------------------------------------------------------------- #
    def _refresh(self) -> None:
        down = False
        try:
            while True:
                event = self._events.get_nowait()
                self._log_line(event.message, event.timestamp)
                down = down or event.kind == "down"
        except queue.Empty:
            pass
        if down and self._sound.get():
            self.bell()
        self._refresh_rows()
        try:
            self._job = self.after(REFRESH_MS, self._refresh)
        except tk.TclError:
            pass

    def _refresh_rows(self) -> None:
        rows = {row["ip"]: row for row in self.monitor.snapshot()}
        for iid in self._tree.get_children():
            if iid not in rows:
                self._tree.delete(iid)
        badges = {STATUS_UP: "online", STATUS_DOWN: "danger"}
        if rows:
            self._empty.place_forget()
        else:
            self._empty.place(relx=0.5, rely=0.45, anchor="center")
        for index, ip in enumerate(sorted(rows, key=ip_key)):
            row = rows[ip]
            values = (
                row["label"], ip, row["status"].capitalize(),
                f"{row['latency']:.0f}" if row["latency"] is not None else "",
                f"{row['avg']:.0f}" if row["avg"] is not None else "",
                f"{row['uptime']:.1f}%", row["checks"], row["losses"],
                row["last_change"] or "",
            )
            image = self._icons.device(self._categories.get(ip, "unknown"),
                                       badges.get(row["status"], ""))
            if self._tree.exists(ip):
                self._tree.item(ip, values=values, image=image, tags=(row["status"],))
            else:
                self._tree.insert("", index, iid=ip, values=values, image=image,
                                  tags=(row["status"],))

    def _log_line(self, message: str, stamp: str = "") -> None:
        stamp = stamp or datetime.now().strftime("%H:%M:%S")
        self._log.configure(state="normal")
        self._log.insert("end", f"{stamp}  {message}\n")
        self._log.see("end")
        self._log.configure(state="disabled")

    def shutdown(self) -> None:
        self.monitor.stop()
        try:
            self.after_cancel(self._job)
        except (tk.TclError, ValueError):
            pass
