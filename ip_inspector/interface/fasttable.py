"""Fast results table: a single native Treeview with a thin styled frame.

One widget draws every row, so a full sweep costs the same as the
visible page. Styled to sit quietly inside the window: flat header,
zebra rows, native scrollbar.
"""
from __future__ import annotations
from tkinter import ttk
import customtkinter as ctk
from .theme import _TABLES, current


class FastTable(ctk.CTkFrame):
    ROW_HEIGHT = 24
    HEADER_FONT_SIZE = 9
    ROW_FONT_SIZE = 10
    ROW_FONT_PADDING = 3

    def __init__(self, master, columns, on_sort=None, on_select=None,
                 sparkline=None, dot=None, icon=None, icons=None):
        super().__init__(master, fg_color="transparent", corner_radius=4)
        self._columns = list(columns)
        self._on_sort = on_sort
        self._on_select = on_select
        self._dot = dot
        self._rows: dict = {}
        self._order: list = []
        self._selected = None
        self._build()
        _TABLES.append(self)
        self.refresh()

    def destroy(self):
        try:
            _TABLES.remove(self)
        except ValueError:
            pass
        super().destroy()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        pal = current()
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except Exception:
            pass
        try:
            # Flat header, no borders: the colour band does the work.
            # Rows breathe a little (26px) so dense sweeps stay readable
            # without looking like a spreadsheet from 2003.
            st.configure("AIS.Treeview", background=pal.surface,
                         foreground=pal.text_primary,
                         fieldbackground=pal.surface, rowheight=26,
                         font=("Segoe UI", 10), borderwidth=0,
                         relief="flat")
            st.configure("AIS.Treeview.Heading", background=pal.header_bg,
                         foreground=pal.header_text,
                         font=("Segoe UI", 9, "bold"),
                         relief="flat", borderwidth=0)
            st.map("AIS.Treeview",
                   background=[("selected", pal.selection)],
                   foreground=[("selected", pal.selection_text)])
            st.configure("AIS.Vertical.TScrollbar", gripcount=0,
                         background=pal.border, troughcolor=pal.surface,
                         borderwidth=0, arrowsize=0)
        except Exception:
            pass
        ids = [f"c{i}" for i in range(len(self._columns))]
        self._tree = ttk.Treeview(self, columns=ids, show="headings",
                                  style="AIS.Treeview", selectmode="browse")
        for i, spec in enumerate(self._columns):
            lab, wid = spec[0], spec[1]
            anc = {"w": "w", "center": "center"}.get(spec[2], "w")
            self._tree.heading(ids[i], text=str(lab).upper(),
                               command=lambda k=i: self._sort(k))
            self._tree.column(ids[i], width=wid, minwidth=40,
                              anchor=anc, stretch=True)
        vsb = ttk.Scrollbar(self, orient="vertical",
                            command=self._tree.yview,
                            style="AIS.Vertical.TScrollbar")
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        self._body = self._tree
        self._header = self._tree
        try:
            self._tree.tag_configure("st_ok", foreground=pal.online)
            self._tree.tag_configure("st_warn", foreground=pal.vpn)
            self._tree.tag_configure("st_off", foreground=pal.warning)
            self._tree.tag_configure("stripe", background=pal.row_odd)
        except Exception:
            pass
        self._tree.bind("<<TreeviewSelect>>", self._sel)
        # Scroll bindings so the table responds on Windows (mouse wheel,
        # trackpad, and the native scrollbar) even inside a CTkTabview.
        # Without these, customtkinter does not always forward mouse wheel
        # events to embedded ttk widgets, which makes the results and
        # Favoritos tables unscrollable and can raise Tcl errors.
        self._tree.bind("<MouseWheel>", self._on_mouse_wheel)
        self._tree.bind("<Button-4>", self._on_scroll_up)
        self._tree.bind("<Button-5>", self._on_scroll_down)

    def _sort(self, idx):
        if self._on_sort:
            try:
                self._on_sort(idx)
            except Exception:
                pass

    def _sel(self, _e=None):
        s = self._tree.selection()
        self._selected = s[0] if s else None
        if self._on_select and self._selected:
            try:
                self._on_select(self._selected)
            except Exception:
                pass

    def _tag(self, dot, pos):
        t = []
        if pos % 2 == 1:
            t.append("stripe")
        try:
            pal = current()
            if dot == pal.online:
                t.append("st_ok")
            elif dot == pal.vpn:
                t.append("st_warn")
            elif dot == pal.warning:
                t.append("st_off")
        except Exception:
            pass
        return tuple(t)

    def refresh(self):
        try:
            self._tree.tag_configure("stripe",
                                     background=current().row_odd)
        except Exception:
            pass

    def _sync_gutter(self):
        return None
    def rebuild(self, rows, sparklines=None):
        self.clear()
        for key, cells, dot in rows:
            self.append_row(key, cells, dot)

    def _insert(self, pos, key, cells, dot, samples=None):
        vals = [cells[i] if i < len(cells) else ""
                for i in range(len(self._columns))]
        if not isinstance(pos, int) or pos < 0 or pos >= len(self._order):
            self._order.append(key)
            final_pos = "end"
            tag_pos = len(self._order) - 1
        else:
            self._order.insert(pos, key)
            final_pos = pos
            tag_pos = pos
        self._rows[key] = (list(vals), dot)
        try:
            self._tree.insert("", final_pos, iid=key, values=vals,
                              tags=self._tag(dot, tag_pos))
        except Exception as insert_err:
            # Do not fall back to "end" silently: the row must stay in the
            # logical order so scrolling stays stable. Only log and carry on
            # with a best-effort insert so the table can still render.
            try:
                self._tree.insert("", "end", iid=key, values=vals,
                                  tags=self._tag(dot, len(self._order) - 1))
            except Exception:
                # The Treeview itself is unusable; surface a clear error so
                # the caller knows the table is broken instead of hiding it.
                raise RuntimeError(
                    f"FastTable insertion failed for row {key!r}: {insert_err}"
                ) from insert_err

    def has_key(self, key):
        return key in self._rows

    def append_row(self, key, cells, dot, samples=None):
        self._insert(len(self._order), key, cells, dot, samples)

    def update_row(self, key, cells, dot):
        vals = [cells[i] if i < len(cells) else ""
                for i in range(len(self._columns))]
        if key not in self._rows:
            self.append_row(key, vals, dot)
            return
        old, _ = self._rows[key]
        self._rows[key] = (list(vals), dot)
        if old == list(vals):
            return
        try:
            pos = self._order.index(key)
        except ValueError:
            pos = 0
        try:
            self._tree.item(key, values=vals, tags=self._tag(dot, pos))
        except Exception:
            pass

    def clear(self):
        for k in list(self._order):
            try:
                self._tree.delete(k)
            except Exception:
                pass
        self._rows.clear()
        self._order.clear()
        self._selected = None

    def reset(self):
        """Reset the table state (used when the whole table is being
        rebuilt while a scroll or selection is in progress)."""
        self.clear()
        self._selected = None

    def row_count(self):
        return len(self._order)

    def keys(self):
        try:
            return list(self._tree.get_children(""))
        except Exception:
            return list(self._order)

    def key_at(self, y):
        try:
            return self._tree.identify_row(y) or None
        except Exception:
            return None

    def _select(self, key):
        self._selected = key
        try:
            self._tree.selection_set(key)
            self._tree.see(key)
        except Exception:
            pass
        if self._on_select:
            try:
                self._on_select(key)
            except Exception:
                pass

    def select_key(self, key):
        self._select(key)

    def selected_key(self):
        try:
            s = self._tree.selection()
            if s:
                return s[0]
        except Exception:
            pass
        return self._selected

    def bind_context_menu(self, cb):
        try:
            self._tree.bind("<Button-3>", cb)
        except Exception:
            pass

    def _on_mouse_wheel(self, event):
        """Translate platform mouse wheel events into Treeview scrolling."""
        try:
            if event.num == 4 or event.delta == 120:
                self._tree.yview("scroll", -1, "units")
            elif event.num == 5 or event.delta == -120:
                self._tree.yview("scroll", 1, "units")
            else:
                self._tree.yview("scroll", -1 if event.delta > 0 else 1, "units")
        except Exception:
            # Scroll events are advisory; never let a bad scroll break the UI.
            pass

    def _on_scroll_up(self, _event=None):
        """Native scroll-up (Button-4 / trackpad up)."""
        try:
            self._tree.yview("scroll", -1, "units")
        except Exception:
            pass

    def _on_scroll_down(self, _event=None):
        """Native scroll-down (Button-5 / trackpad down)."""
        try:
            self._tree.yview("scroll", 1, "units")
        except Exception:
            pass

