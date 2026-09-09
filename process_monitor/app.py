from __future__ import annotations

import datetime
import queue
import threading
import tkinter as tk
from tkinter import ttk
from typing import Optional

from .collector import ProcessInfo, collect_processes
from .export import export_snapshot
from .history import ProcessHistory
from .settings import Settings

# ── colour tokens ──────────────────────────────────────────────────────────
AMBER_BG  = "#FFF3CD"
AMBER_FG  = "#7D6608"
RED_BG    = "#F8D7DA"
RED_FG    = "#721C24"
GREEN_BG  = "#D4EDDA"
GREEN_FG  = "#155724"

# ── table column definitions: (attr, header, min_width, anchor, stretch) ──
_COLS = [
    ("name",      "Process Name", 170, "w", True),
    ("pid",       "PID",           60, "e", False),
    ("cpu_pct",   "CPU %",         65, "e", False),
    ("ram_mb",    "RAM (MB)",       75, "e", False),
    ("proc_type", "Type",          110, "w", False),
    ("publisher", "Publisher",     150, "w", True),
    ("exe_path",  "Path",          220, "w", True),
]


# ── lightweight tooltip ────────────────────────────────────────────────────
class _ToolTip:
    def __init__(self, widget: tk.Widget) -> None:
        self._w = widget
        self._tw: Optional[tk.Toplevel] = None
        widget.bind("<Motion>", self._on_motion, add="+")
        widget.bind("<Leave>",  self._hide, add="+")

    def set_text(self, text: str) -> None:
        self._text = text

    def _on_motion(self, event: tk.Event) -> None:
        pass  # subclassed by Treeview tooltip

    def _hide(self, _event: tk.Event | None = None) -> None:
        if self._tw:
            self._tw.destroy()
            self._tw = None

    def _show(self, text: str, x: int, y: int) -> None:
        self._hide()
        self._tw = tw = tk.Toplevel(self._w)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x + 14}+{y + 10}")
        tk.Label(
            tw, text=text, justify="left",
            background="#fffbe6", relief="solid", borderwidth=1,
            font=("TkDefaultFont", 9), wraplength=600,
        ).pack(ipadx=5, ipady=3)


class _TreeTooltip(_ToolTip):
    """Shows the full exe path when hovering over the Path column."""

    def __init__(self, tree: ttk.Treeview, col_id: str) -> None:
        super().__init__(tree)
        self._tree = tree
        self._col_id = col_id
        tree.bind("<Motion>", self._on_motion, add="+")

    def _on_motion(self, event: tk.Event) -> None:
        region = self._tree.identify_region(event.x, event.y)
        if region != "cell":
            self._hide()
            return
        col = self._tree.identify_column(event.x)
        if col != self._col_id:
            self._hide()
            return
        iid = self._tree.identify_row(event.y)
        if not iid:
            self._hide()
            return
        col_idx = int(col.lstrip("#")) - 1
        vals = self._tree.item(iid, "values")
        if col_idx < len(vals):
            self._show(str(vals[col_idx]), event.x_root, event.y_root)


# ── detail window ──────────────────────────────────────────────────────────
class _DetailWindow(tk.Toplevel):
    def __init__(self, parent: tk.Misc, proc: ProcessInfo, history: ProcessHistory,
                 all_procs: list[ProcessInfo]) -> None:
        super().__init__(parent)
        self.title(f"{proc.name}  (PID {proc.pid})")
        self.resizable(True, True)
        self.geometry("560x500")
        self._build(proc, history, all_procs)
        self.grab_set()

    def _build(self, p: ProcessInfo, hist: ProcessHistory,
               all_procs: list[ProcessInfo]) -> None:
        outer = ttk.Frame(self, padding=16)
        outer.pack(fill="both", expand=True)

        # ── identity fields ────────────────────────────────────────────────
        def row(label: str, value: str, wrap: bool = False) -> None:
            f = ttk.Frame(outer)
            f.pack(fill="x", pady=2)
            ttk.Label(f, text=label, width=16, anchor="e",
                      foreground="#666").pack(side="left")
            lbl = ttk.Label(f, text=value, anchor="w")
            if wrap:
                lbl.configure(wraplength=380)
            lbl.pack(side="left", fill="x", expand=True, padx=(6, 0))

        row("Path:", p.exe_path, wrap=True)
        row("Publisher:", p.publisher)

        parent_name = "Unknown"
        if p.ppid:
            parent_map = {pr.pid: pr.name for pr in all_procs}
            parent_name = parent_map.get(p.ppid, "Unknown")
        row("Parent:", f"{parent_name}  (PID {p.ppid})")

        started = (datetime.datetime.fromtimestamp(p.create_time).strftime("%Y-%m-%d %H:%M:%S")
                   if p.create_time else "Unknown")
        row("Started:", started)
        row("Threads:", str(p.num_threads))
        row("Handles:", f"{p.num_handles:,}")

        # ── agent info ─────────────────────────────────────────────────────
        if p.proc_type == "Security Agent":
            ttk.Separator(outer, orient="horizontal").pack(fill="x", pady=10)
            hdr = ttk.Frame(outer)
            hdr.pack(fill="x")
            ttk.Label(hdr, text="Security Agent", font=("TkDefaultFont", 10, "bold"),
                      foreground=AMBER_FG).pack(side="left")
            if p.vendor:
                ttk.Label(hdr, text=f" — {p.vendor}", foreground="#555").pack(side="left")
            if p.agent_desc:
                ttk.Label(outer, text=p.agent_desc, wraplength=500,
                          foreground="#444", justify="left").pack(anchor="w", pady=(4, 0))

        # ── sparklines ────────────────────────────────────────────────────
        ttk.Separator(outer, orient="horizontal").pack(fill="x", pady=10)
        history_data = hist.get(p.pid)
        self._draw_sparklines(outer, history_data)

        # ── close button ──────────────────────────────────────────────────
        ttk.Button(outer, text="Close", command=self.destroy).pack(anchor="e", pady=(10, 0))

    def _draw_sparklines(self, parent: ttk.Frame,
                         entries: list) -> None:
        if not entries:
            ttk.Label(parent, text="No history yet — data appears after first refresh.",
                      foreground="#888").pack(anchor="w")
            return

        cpu_vals = [e.cpu_pct for e in entries]
        ram_vals = [e.ram_mb   for e in entries]

        for label, vals, colour in [
            ("CPU % (last 60 s)", cpu_vals, "#1a73e8"),
            ("RAM MB (last 60 s)", ram_vals, "#2e7d32"),
        ]:
            ttk.Label(parent, text=label, font=("TkDefaultFont", 9, "bold")).pack(anchor="w")
            canvas = tk.Canvas(parent, height=60, bg="#f5f5f5",
                               highlightthickness=1, highlightbackground="#ccc")
            canvas.pack(fill="x", pady=(2, 10))
            canvas.update_idletasks()
            self._plot(canvas, vals, colour)

    @staticmethod
    def _plot(canvas: tk.Canvas, values: list[float], colour: str) -> None:
        canvas.delete("all")
        w = canvas.winfo_width()
        h = canvas.winfo_height()
        if w < 4 or h < 4 or not values:
            return
        max_v = max(values) or 1.0
        n = len(values)
        pad = 4
        points: list[float] = []
        for i, v in enumerate(values):
            x = pad + (i / max(n - 1, 1)) * (w - 2 * pad)
            y = (h - pad) - (v / max_v) * (h - 2 * pad)
            points.extend([x, y])
        if len(points) >= 4:
            canvas.create_line(points, fill=colour, width=2, smooth=True)
        # axis labels
        canvas.create_text(pad, pad, anchor="nw",
                           text=f"{max_v:.0f}", fill="#999", font=("TkDefaultFont", 8))
        canvas.create_text(pad, h - pad, anchor="sw",
                           text="0", fill="#999", font=("TkDefaultFont", 8))


# ── settings dialog ────────────────────────────────────────────────────────
class _SettingsDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, settings: Settings,
                 on_save: callable) -> None:
        super().__init__(parent)
        self.title("Settings")
        self.resizable(False, False)
        self._settings = settings
        self._on_save = on_save
        self._build()
        self.grab_set()

    def _build(self) -> None:
        s = self._settings
        f = ttk.Frame(self, padding=20)
        f.pack(fill="both", expand=True)

        # refresh interval
        ttk.Label(f, text="Refresh interval:").grid(row=0, column=0, sticky="w", pady=4)
        self._interval = tk.IntVar(value=s.refresh_interval)
        for i, val in enumerate([1, 3, 5, 10]):
            ttk.Radiobutton(f, text=f"{val}s", variable=self._interval,
                            value=val).grid(row=0, column=i + 1, padx=4)

        # CPU threshold
        ttk.Label(f, text="CPU threshold (%):").grid(row=1, column=0, sticky="w", pady=4)
        self._cpu = tk.DoubleVar(value=s.cpu_threshold_pct)
        ttk.Spinbox(f, from_=5, to=90, increment=5, textvariable=self._cpu,
                    width=6).grid(row=1, column=1, sticky="w", columnspan=2)

        # RAM threshold
        ttk.Label(f, text="RAM threshold (MB):").grid(row=2, column=0, sticky="w", pady=4)
        self._ram = tk.IntVar(value=s.ram_threshold_mb)
        ttk.Spinbox(f, from_=100, to=2000, increment=100, textvariable=self._ram,
                    width=6).grid(row=2, column=1, sticky="w", columnspan=2)

        # show system processes
        ttk.Label(f, text="Show system processes:").grid(row=3, column=0, sticky="w", pady=4)
        self._show_sys = tk.BooleanVar(value=s.show_system_processes)
        ttk.Checkbutton(f, variable=self._show_sys).grid(row=3, column=1, sticky="w")

        # machine name mode
        ttk.Label(f, text="Export machine name:").grid(row=4, column=0, sticky="w", pady=4)
        self._name_mode = tk.StringVar(value=s.export_machine_name)
        mode_frame = ttk.Frame(f)
        mode_frame.grid(row=4, column=1, columnspan=4, sticky="w")
        for val, lbl in [("hostname", "Hostname"), ("custom", "Custom"), ("anonymized", "Anonymized")]:
            ttk.Radiobutton(mode_frame, text=lbl, variable=self._name_mode,
                            value=val).pack(side="left", padx=4)

        # custom label
        ttk.Label(f, text="Custom label:").grid(row=5, column=0, sticky="w", pady=4)
        self._custom = tk.StringVar(value=s.export_custom_label)
        ttk.Entry(f, textvariable=self._custom, width=22).grid(row=5, column=1,
                                                                 columnspan=3, sticky="w")

        # buttons
        btn_frame = ttk.Frame(f)
        btn_frame.grid(row=6, column=0, columnspan=5, pady=(16, 0), sticky="e")
        ttk.Button(btn_frame, text="Save", command=self._save).pack(side="right", padx=(6, 0))
        ttk.Button(btn_frame, text="Cancel", command=self.destroy).pack(side="right")

    def _save(self) -> None:
        s = self._settings
        s.refresh_interval     = self._interval.get()
        s.cpu_threshold_pct    = float(self._cpu.get())
        s.ram_threshold_mb     = int(self._ram.get())
        s.show_system_processes = self._show_sys.get()
        s.export_machine_name  = self._name_mode.get()
        s.export_custom_label  = self._custom.get()
        s.save()
        self._on_save()
        self.destroy()


# ── main application ───────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Process Monitor — Security Agent Visibility")
        self.geometry("1200x700")
        self.minsize(800, 450)

        self._settings = Settings.load()
        self._history  = ProcessHistory()
        self._queue: queue.Queue[list[ProcessInfo]] = queue.Queue()
        self._collecting = False
        self._last_procs: list[ProcessInfo] = []

        # filter state
        self._search_var    = tk.StringVar()
        self._filter_agents = tk.BooleanVar(value=False)
        self._filter_high_cpu = tk.BooleanVar(value=False)
        self._filter_high_ram = tk.BooleanVar(value=False)

        # sort state: (column attr, reverse)
        self._sort_col = "cpu_pct"
        self._sort_rev = True

        try:
            self.tk.call("tk", "scaling", 1.0)
            style = ttk.Style(self)
            style.theme_use("vista")
        except Exception:
            pass

        self._build_ui()
        self._search_var.trace_add("write", lambda *_: self._apply_filter())
        self._schedule_collect()

    # ── UI construction ────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_banner()
        self._build_filter_bar()
        self._build_table()
        self._build_bottom_bar()

    def _build_banner(self) -> None:
        self._banner_frame = tk.Frame(self, height=36)
        self._banner_frame.pack(fill="x", padx=0, pady=0)
        self._banner_label = tk.Label(
            self._banner_frame, text="Collecting process data…",
            font=("TkDefaultFont", 10, "bold"),
            bg=AMBER_BG, fg=AMBER_FG, pady=8, padx=16, anchor="w",
        )
        self._banner_label.pack(fill="both", expand=True)

    def _build_filter_bar(self) -> None:
        bar = ttk.Frame(self, padding=(8, 6))
        bar.pack(fill="x")

        ttk.Label(bar, text="Search:").pack(side="left")
        ttk.Entry(bar, textvariable=self._search_var, width=22).pack(
            side="left", padx=(4, 16))

        for text, var in [
            ("Security Agents Only", self._filter_agents),
            ("High CPU",             self._filter_high_cpu),
            ("High RAM",             self._filter_high_ram),
        ]:
            ttk.Checkbutton(bar, text=text, variable=var,
                            command=self._apply_filter).pack(side="left", padx=6)

        ttk.Button(bar, text="Clear Filters",
                   command=self._clear_filters).pack(side="left", padx=(16, 0))

    def _build_table(self) -> None:
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=8, pady=(0, 4))

        col_ids = [c[0] for c in _COLS]
        self._tree = ttk.Treeview(
            container, columns=col_ids, show="headings",
            selectmode="browse",
        )

        for attr, header, min_w, anchor, stretch in _COLS:
            self._tree.heading(attr, text=header,
                               command=lambda a=attr: self._sort_by(a))
            self._tree.column(attr, width=min_w, minwidth=40,
                              anchor=anchor, stretch=stretch)

        # colour tags
        bold_font = ("TkDefaultFont", 10, "bold")
        self._tree.tag_configure("agent",      background=AMBER_BG)
        self._tree.tag_configure("high",       background=RED_BG)
        self._tree.tag_configure("agent_high", background=RED_BG, font=bold_font)

        vsb = ttk.Scrollbar(container, orient="vertical", command=self._tree.yview)
        hsb = ttk.Scrollbar(container, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # path-column tooltip (column #7 = index 7 in the heading, displayed as "#7")
        path_col_index = f"#{col_ids.index('exe_path') + 1}"
        _TreeTooltip(self._tree, path_col_index)

        # status bar
        self._status_var = tk.StringVar(value="")
        ttk.Label(self, textvariable=self._status_var, anchor="w",
                  foreground="#666").pack(fill="x", padx=8)

    def _build_bottom_bar(self) -> None:
        bar = ttk.Frame(self, padding=(8, 6))
        bar.pack(fill="x", side="bottom")

        ttk.Button(bar, text="Export Snapshot",
                   command=self._export).pack(side="left")
        ttk.Button(bar, text="⚙ Settings",
                   command=self._open_settings).pack(side="right")

    # ── data collection ────────────────────────────────────────────────────

    def _schedule_collect(self) -> None:
        if not self._collecting:
            self._collecting = True
            threading.Thread(target=self._collect_worker, daemon=True).start()

    def _collect_worker(self) -> None:
        procs = collect_processes()
        self._queue.put(procs)
        self.after(0, self._on_collected)

    def _on_collected(self) -> None:
        try:
            procs = self._queue.get_nowait()
        except queue.Empty:
            return
        finally:
            self._collecting = False

        active_pids = {p.pid for p in procs}
        for p in procs:
            self._history.update(p.pid, p.cpu_pct, p.ram_mb)
        self._history.prune(active_pids)

        self._last_procs = procs
        self._update_banner(procs)
        self._apply_filter()

        interval_ms = self._settings.refresh_interval * 1000
        self.after(interval_ms, self._schedule_collect)

    # ── filtering & display ────────────────────────────────────────────────

    def _apply_filter(self) -> None:
        procs = self._last_procs
        search = self._search_var.get().lower().strip()
        cpu_t  = self._settings.cpu_threshold_pct
        ram_t  = self._settings.ram_threshold_mb

        if not self._settings.show_system_processes:
            procs = [p for p in procs if p.proc_type != "System"]

        if search:
            procs = [p for p in procs
                     if search in p.name.lower() or search in p.publisher.lower()]

        if self._filter_agents.get():
            procs = [p for p in procs if p.proc_type == "Security Agent"]

        if self._filter_high_cpu.get():
            procs = [p for p in procs if p.cpu_pct > cpu_t]

        if self._filter_high_ram.get():
            procs = [p for p in procs if p.ram_mb > ram_t]

        self._update_treeview(procs)
        self._status_var.set(
            f"Showing {len(procs)} of {len(self._last_procs)} processes"
        )

    def _clear_filters(self) -> None:
        self._search_var.set("")
        self._filter_agents.set(False)
        self._filter_high_cpu.set(False)
        self._filter_high_ram.set(False)
        self._apply_filter()

    def _update_treeview(self, procs: list[ProcessInfo]) -> None:
        cpu_t = self._settings.cpu_threshold_pct
        ram_t = self._settings.ram_threshold_mb

        # Sort
        key_map = {
            "name":      lambda p: p.name.lower(),
            "pid":       lambda p: p.pid,
            "cpu_pct":   lambda p: p.cpu_pct,
            "ram_mb":    lambda p: p.ram_mb,
            "proc_type": lambda p: p.proc_type,
            "publisher": lambda p: p.publisher.lower(),
            "exe_path":  lambda p: p.exe_path.lower(),
        }
        key_fn = key_map.get(self._sort_col, lambda p: p.cpu_pct)
        sorted_procs = sorted(procs, key=key_fn, reverse=self._sort_rev)

        # Save scroll and selection
        try:
            yview = self._tree.yview()[0]
        except Exception:
            yview = 0.0
        selected_iid = self._tree.focus()

        # Compute current iids in tree
        existing_iids = set(self._tree.get_children())
        new_iids = {str(p.pid) for p in sorted_procs}

        # Remove stale rows
        for iid in existing_iids - new_iids:
            self._tree.delete(iid)

        def _tag(p: ProcessInfo) -> tuple[str, ...]:
            is_agent = p.proc_type == "Security Agent"
            is_high  = p.cpu_pct > cpu_t or p.ram_mb > ram_t
            if is_agent and is_high:
                return ("agent_high",)
            if is_agent:
                return ("agent",)
            if is_high:
                return ("high",)
            return ()

        def _vals(p: ProcessInfo) -> tuple:
            path = p.exe_path
            return (
                p.name,
                p.pid,
                f"{p.cpu_pct:.1f}",
                f"{p.ram_mb:.1f}",
                p.proc_type,
                p.publisher,
                path,
            )

        # Update or insert rows in sorted order
        for idx, p in enumerate(sorted_procs):
            iid = str(p.pid)
            vals = _vals(p)
            tags = _tag(p)
            if iid in existing_iids:
                self._tree.item(iid, values=vals, tags=tags)
                self._tree.move(iid, "", idx)
            else:
                self._tree.insert("", idx, iid=iid, values=vals, tags=tags)

        # Restore scroll and selection
        self._tree.yview_moveto(yview)
        if selected_iid and self._tree.exists(selected_iid):
            self._tree.focus(selected_iid)
            self._tree.selection_set(selected_iid)

    def _sort_by(self, col: str) -> None:
        if self._sort_col == col:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col = col
            self._sort_rev = col in ("cpu_pct", "ram_mb")  # default desc for numeric
        self._apply_filter()

        # Update heading arrows
        for attr, header, *_ in _COLS:
            arrow = ""
            if attr == self._sort_col:
                arrow = " ▼" if self._sort_rev else " ▲"
            self._tree.heading(attr, text=header + arrow)

    # ── banner ─────────────────────────────────────────────────────────────

    def _update_banner(self, procs: list[ProcessInfo]) -> None:
        cpu_t = self._settings.cpu_threshold_pct
        ram_t = self._settings.ram_threshold_mb

        agents     = [p for p in procs if p.proc_type == "Security Agent"]
        high_agents = [p for p in agents if p.cpu_pct > cpu_t or p.ram_mb > ram_t]

        if high_agents:
            bg, fg = RED_BG, RED_FG
            text = (f"{len(agents)} security agent{'s' if len(agents) != 1 else ''} running"
                    f" — {len(high_agents)} with high CPU or RAM")
        elif agents:
            bg, fg = AMBER_BG, AMBER_FG
            text = (f"{len(agents)} security agent{'s' if len(agents) != 1 else ''} running"
                    " — resource usage normal")
        else:
            bg, fg = GREEN_BG, GREEN_FG
            text = "No security agents detected — resource usage normal"

        self._banner_label.config(text=text, bg=bg, fg=fg)
        self._banner_frame.config(bg=bg)

    # ── interactions ───────────────────────────────────────────────────────

    def _on_select(self, _event: tk.Event) -> None:
        iid = self._tree.focus()
        if not iid:
            return
        try:
            pid = int(iid)
        except ValueError:
            return
        proc = next((p for p in self._last_procs if p.pid == pid), None)
        if proc:
            _DetailWindow(self, proc, self._history, self._last_procs)

    def _export(self) -> None:
        export_snapshot(self._last_procs, self._settings, self)

    def _open_settings(self) -> None:
        def on_save() -> None:
            self._schedule_collect()  # restart with new interval

        _SettingsDialog(self, self._settings, on_save)
