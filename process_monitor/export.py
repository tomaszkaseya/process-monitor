from __future__ import annotations

import datetime
import html
import socket
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .collector import ProcessInfo
    from .settings import Settings


def _machine_label(settings: "Settings") -> str:
    mode = settings.export_machine_name
    if mode == "anonymized":
        return "ANONYMIZED"
    if mode == "custom" and settings.export_custom_label.strip():
        return settings.export_custom_label.strip()
    try:
        return socket.gethostname()
    except Exception:
        return "UNKNOWN"


def _it_summary(
    processes: list["ProcessInfo"],
    timestamp: str,
    machine: str,
    cpu_thresh: float,
    ram_thresh: int,
) -> str:
    agents = [p for p in processes if p.proc_type == "Security Agent"]
    high = [p for p in agents if p.cpu_pct > cpu_thresh or p.ram_mb > ram_thresh]

    if not agents:
        return (
            f"At {timestamp}, machine {machine} had no security agent processes detected. "
            "Resource usage appears normal."
        )

    parts = [
        f"At {timestamp}, machine {machine} had {len(agents)} security agent process"
        f"{'es' if len(agents) != 1 else ''} running."
    ]

    if high:
        details = []
        for p in sorted(high, key=lambda x: x.cpu_pct, reverse=True)[:3]:
            details.append(
                f"{p.name} was using {p.cpu_pct:.1f}% CPU and {p.ram_mb:.0f} MB RAM"
            )
        parts.append(" ".join(details) + (", which is unusually high." if details else "."))
    else:
        parts.append("Resource usage appears normal.")

    parts.append("Full process list attached.")
    return " ".join(parts)


def _row_class(p: "ProcessInfo", cpu_thresh: float, ram_thresh: int) -> str:
    is_agent = p.proc_type == "Security Agent"
    is_high = p.cpu_pct > cpu_thresh or p.ram_mb > ram_thresh
    if is_agent and is_high:
        return "agent-high"
    if is_agent:
        return "agent"
    if is_high:
        return "high"
    return ""


def generate_html(
    processes: list["ProcessInfo"],
    settings: "Settings",
) -> str:
    now = datetime.datetime.now()
    timestamp = now.strftime("%H:%M on %Y-%m-%d")
    machine = _machine_label(settings)
    cpu_thresh = settings.cpu_threshold_pct
    ram_thresh = settings.ram_threshold_mb

    agents = [p for p in processes if p.proc_type == "Security Agent"]
    high_agents = [p for p in agents if p.cpu_pct > cpu_thresh or p.ram_mb > ram_thresh]
    it_text = _it_summary(processes, timestamp, machine, cpu_thresh, ram_thresh)

    rows_html = ""
    for p in sorted(processes, key=lambda x: x.cpu_pct, reverse=True):
        cls = _row_class(p, cpu_thresh, ram_thresh)
        row_class = f' class="{cls}"' if cls else ""
        path_display = html.escape(p.exe_path)
        rows_html += f"""
        <tr{row_class}>
          <td>{html.escape(p.name)}</td>
          <td>{p.pid}</td>
          <td>{p.cpu_pct:.1f}</td>
          <td>{p.ram_mb:.1f}</td>
          <td>{html.escape(p.proc_type)}</td>
          <td>{html.escape(p.publisher)}</td>
          <td title="{path_display}">{path_display}</td>
        </tr>"""

    agent_count = len(agents)
    high_count = len(high_agents)
    total_count = len(processes)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Process Snapshot — {html.escape(machine)} — {now.strftime('%Y-%m-%d %H:%M')}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         margin: 0; padding: 20px; background: #f8f9fa; color: #212529; }}
  h1 {{ font-size: 1.4rem; margin: 0 0 4px; }}
  .meta {{ color: #6c757d; font-size: 0.9rem; margin-bottom: 20px; }}
  .banner {{ border-radius: 6px; padding: 12px 16px; margin-bottom: 20px;
             font-weight: 600; font-size: 1rem; }}
  .banner.green {{ background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }}
  .banner.amber {{ background: #fff3cd; color: #856404; border: 1px solid #ffeeba; }}
  .banner.red   {{ background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }}
  .it-box {{ background: #e9ecef; border-left: 4px solid #6c757d; padding: 14px 16px;
             border-radius: 4px; margin-bottom: 24px; }}
  .it-box h3 {{ margin: 0 0 8px; font-size: 0.95rem; color: #495057; }}
  .it-box p {{ margin: 0; font-size: 0.95rem; line-height: 1.5; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
           border-radius: 8px; overflow: hidden;
           box-shadow: 0 1px 3px rgba(0,0,0,.08); font-size: 0.875rem; }}
  th {{ background: #343a40; color: #fff; padding: 10px 12px; text-align: left;
        font-weight: 500; white-space: nowrap; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #dee2e6; vertical-align: middle; }}
  td[title] {{ max-width: 300px; overflow: hidden; text-overflow: ellipsis;
               white-space: nowrap; }}
  tr:last-child td {{ border-bottom: none; }}
  tr.agent td {{ background: #fff3cd; }}
  tr.high td {{ background: #f8d7da; }}
  tr.agent-high td {{ background: #f8d7da; font-weight: 700; }}
  tr:hover td {{ filter: brightness(0.96); }}
  .legend {{ display: flex; gap: 16px; margin-bottom: 12px; font-size: 0.8rem; }}
  .legend-item {{ display: flex; align-items: center; gap: 6px; }}
  .swatch {{ width: 14px; height: 14px; border-radius: 3px; display: inline-block; }}
  .swatch.amber {{ background: #fff3cd; border: 1px solid #ffc107; }}
  .swatch.red {{ background: #f8d7da; border: 1px solid #dc3545; }}
</style>
</head>
<body>
<h1>Process Snapshot</h1>
<div class="meta">
  Machine: <strong>{html.escape(machine)}</strong> &nbsp;|&nbsp;
  Captured: <strong>{html.escape(now.strftime('%Y-%m-%d %H:%M:%S'))}</strong> &nbsp;|&nbsp;
  Total processes: <strong>{total_count}</strong>
</div>

<div class="banner {'red' if high_count > 0 else 'amber' if agent_count > 0 else 'green'}">
  {agent_count} security agent{'s' if agent_count != 1 else ''} running
  {'— ' + str(high_count) + ' with high CPU or RAM' if high_count > 0 else '— resource usage normal'}
</div>

<div class="it-box">
  <h3>What to tell IT</h3>
  <p>{html.escape(it_text)}</p>
</div>

<div class="legend">
  <div class="legend-item"><span class="swatch amber"></span> Security agent</div>
  <div class="legend-item"><span class="swatch red"></span> High resource / Security agent + high resource</div>
</div>

<table>
  <thead>
    <tr>
      <th>Process Name</th>
      <th>PID</th>
      <th>CPU %</th>
      <th>RAM (MB)</th>
      <th>Type</th>
      <th>Publisher</th>
      <th>Path</th>
    </tr>
  </thead>
  <tbody>{rows_html}
  </tbody>
</table>
</body>
</html>
"""


def export_snapshot(
    processes: list["ProcessInfo"],
    settings: "Settings",
    parent: tk.Misc,
) -> None:
    import socket as _socket
    try:
        hostname = _socket.gethostname()
    except Exception:
        hostname = "host"

    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    default_name = f"process-snapshot-{hostname}-{ts}.html"

    path = filedialog.asksaveasfilename(
        parent=parent,
        defaultextension=".html",
        filetypes=[("HTML file", "*.html"), ("All files", "*.*")],
        initialfile=default_name,
        title="Save Process Snapshot",
    )
    if not path:
        return

    content = generate_html(processes, settings)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        messagebox.showinfo("Export Complete", f"Snapshot saved to:\n{path}", parent=parent)
    except OSError as exc:
        messagebox.showerror("Export Failed", str(exc), parent=parent)
