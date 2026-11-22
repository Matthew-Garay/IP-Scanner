"""The Monitor tab: keep pinging chosen hosts and alert on state changes.

The polling itself lives in :class:`ip_inspector.nettools.monitor.Monitor`,
which runs on its own thread and reports through a queue. This tab only
adds and removes hosts, refreshes the table once a second and logs the
transitions.
"""

from __future__ import annotations

import queue
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable

import customtkinter as ctk

from ..nettools.monitor import STATUS_DOWN, STATUS_UP, Monitor
from . import theme
from .widgets import MONO_FONT, c, ip_key, style_treeview

COLUMNS: tuple[tuple[str, int], ...] = (
    ("Host", 170), ("IP", 120), ("Status", 80), ("Last (ms)", 80),
    ("Avg (ms)", 80), ("Uptime", 80), ("Checks", 70), ("Lost", 60), ("Changed", 80),
)
INTERVALS = ("2", "5", "10", "30", "60")
REFRESH_MS = 1000


class MonitorTab(ctk.CTkFrame):
    """Watch list, live statistics and an event log."""

    def __init__(self, master, on_status: Callable[[str], None] | None = None):
        super().__init__(master, fg_color="transparent")
        self._on_status = on_status or (lambda _text: None)
        self._events: queue.Queue = queue.Queue()
        self.monitor = Monitor(self._events)
        self._build()
        self.apply_palette(theme.current())
        self._job = self.after(REFRESH_MS, self._refresh)

    # -- layout -------------------------------------------------------------- #
    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=3)
        self.grid_rowconfigure(3, weight=1)

        form = ctk.CTkFrame(self, fg_color=c("surface_alt"), corner_radius=8)
        form.grid(row=0, column=0, sticky="ew", padx=6, pady=6)

        def label(text, column):
            ctk.CTkLabel(form, text=text, font=("Segoe UI", 10, "bold"),
                         text_color=c("text_secondary")).grid(row=0, column=column,
                                                              padx=(12, 4), pady=10)

        label("Host / IP:", 0)
        self._host = ctk.CTkEntry(form, placeholder_text="192.168.1.1", width=170)
        self._host.grid(row=0, column=1)
        self._host.bind("<Return>", lambda _e: self._add_from_form())
        label("Label:", 2)
        self._label = ctk.CTkEntry(form, placeholder_text="optional", width=130)
        self._label.grid(row=0, column=3)
        label("TCP port:", 4)
        self._port = ctk.CTkEntry(form, placeholder_text="auto", width=70)
        self._port.grid(row=0, column=5)
        label("Every (s):", 6)
        self._interval = ctk.CTkOptionMenu(form, values=list(INTERVALS), width=70)
        self._interval.set("5")
        self._interval.grid(row=0, column=7)

        flat = dict(height=30, fg_color="transparent", hover_color=c("hover"),
                    text_color=c("text_primary"), border_width=1,
                    border_color=c("border"), font=("Segoe UI", 10))
        ctk.CTkButton(form, text="+ Add", width=70, command=self._add_from_form,
                      **flat).grid(row=0, column=8, padx=(12, 4))
        self._toggle_btn = ctk.CTkButton(
            form, text="▶  Start", width=100, height=30, fg_color=c("accent"),
            hover_color=c("accent_hover"), text_color=c("accent_text"),
            font=("Segoe UI", 10, "bold"), command=self.toggle)
        self._toggle_btn.grid(row=0, column=9, padx=4)
        ctk.CTkButton(form, text="Remove", width=80, command=self._remove_selected,
                      **flat).grid(row=0, column=10, padx=4)
        ctk.CTkButton(form, text="Clear all", width=80, command=self._clear,
                      **flat).grid(row=0, column=11, padx=(4, 12))

        table = ctk.CTkFrame(self, fg_color="transparent")
        table.grid(row=1, column=0, sticky="nsew", padx=6)
        table.grid_columnconfigure(0, weight=1)
        table.grid_rowconfigure(0, weight=1)
        self._style = ttk.Style(self)
        cols = [f"m{i}" for i in range(len(COLUMNS))]
        self._tree = ttk.Treeview(table, columns=cols, show="headings",
                                  style="MON.Treeview", selectmode="extended")
        for i, (heading, width) in enumerate(COLUMNS):
            self._tree.heading(cols[i], text=heading, anchor="w")
            self._tree.column(cols[i], width=width, minwidth=50, anchor="w")
        vsb = ttk.Scrollbar(table, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        self._tree.bind("<Delete>", lambda _e: self._remove_selected())

        ctk.CTkLabel(self, text="EVENT LOG", anchor="w", font=("Segoe UI", 9, "bold"),
                     text_color=c("text_muted")).grid(row=2, column=0, sticky="w",
                                                      padx=10, pady=(8, 0))
        self._log = ctk.CTkTextbox(self, font=MONO_FONT, height=120,
                                   fg_color=c("surface"), text_color=c("text_primary"))
        self._log.grid(row=3, column=0, sticky="nsew", padx=6, pady=(2, 6))
        self._log.configure(state="disabled")
        self._sound = ctk.CTkCheckBox(self, text="Beep when a host goes down",
                                      font=("Segoe UI", 10))
        self._sound.select()
        self._sound.grid(row=4, column=0, sticky="w", padx=10, pady=(0, 6))

    def apply_palette(self, pal) -> None:
        style_treeview(self._style, "MON", pal)
        self._tree.tag_configure(STATUS_UP, foreground=pal.state_ok)
        self._tree.tag_configure(STATUS_DOWN, foreground=pal.state_off)
        self._tree.tag_configure("unknown", foreground=pal.text_muted)

    # -- actions ------------------------------------------------------------- #
    def add_host(self, ip: str, label: str = "", port: int = 0, start: bool = True) -> None:
        """Pin a host; used by the form and by the scanner's context menu."""
        try:
            interval = float(self._interval.get())
        except ValueError:
            interval = 5.0
        host = self.monitor.add(ip, label=label, port=port, interval=interval)
        if host is None:
            return
        if start and not self.monitor.running:
            self.toggle()
        self._refresh_rows()

    def _add_from_form(self) -> None:
        ip = self._host.get().strip()
        if not ip:
            messagebox.showwarning("Monitor", "Type a host name or IP address to watch.")
            return
        port_text = self._port.get().strip()
        try:
            port = int(port_text) if port_text else 0
            if not 0 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("Monitor", f"'{port_text}' is not a valid TCP port.")
            return
        self.add_host(ip, self._label.get().strip(), port, start=False)
        self._host.delete(0, tk.END)
        self._label.delete(0, tk.END)

    def toggle(self) -> None:
        if self.monitor.running:
            self.monitor.stop()
            self._toggle_btn.configure(text="▶  Start")
            self._log_line("Monitoring stopped")
            self._on_status("Monitoring stopped")
        else:
            if not len(self.monitor):
                messagebox.showinfo("Monitor", "Add at least one host first.")
                return
            self.monitor.start()
            self._toggle_btn.configure(text="■  Stop")
            self._log_line(f"Monitoring {len(self.monitor)} host(s)")
            self._on_status(f"Monitoring {len(self.monitor)} host(s)")

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
        for index, ip in enumerate(sorted(rows, key=ip_key)):
            row = rows[ip]
            values = (
                row["label"], ip, row["status"],
                f"{row['latency']:.0f}" if row["latency"] is not None else "-",
                f"{row['avg']:.0f}" if row["avg"] is not None else "-",
                f"{row['uptime']:.1f}%", row["checks"], row["losses"],
                row["last_change"] or "-",
            )
            if self._tree.exists(ip):
                self._tree.item(ip, values=values, tags=(row["status"],))
            else:
                self._tree.insert("", index, iid=ip, values=values, tags=(row["status"],))

    def _log_line(self, message: str, stamp: str = "") -> None:
        from datetime import datetime

        stamp = stamp or datetime.now().strftime("%H:%M:%S")
        self._log.configure(state="normal")
        self._log.insert("end", f"[{stamp}] {message}\n")
        self._log.see("end")
        self._log.configure(state="disabled")

    def shutdown(self) -> None:
        self.monitor.stop()
        try:
            self.after_cancel(self._job)
        except (tk.TclError, ValueError):
            pass
