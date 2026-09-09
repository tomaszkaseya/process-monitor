# Process Monitor — Security Agent Visibility Tool

A lightweight Windows desktop app that shows all running processes with a focus on security agents (EDR, AV, DLP tools). Designed for end users who need to quickly identify whether a security agent is causing high CPU or RAM usage and capture evidence for IT support.

---

## Quick Start

```
pip install psutil pefile
python main.py
```

Python 3.10+ required. Runs as a standard user — no elevation needed.

---

## Features

### Live Dashboard
Auto-refreshes every 3 seconds (configurable). All running processes in a sortable table, sorted by CPU usage by default.

| Column | Description |
|---|---|
| Process Name | Executable name |
| PID | Process ID |
| CPU % | Current CPU usage |
| RAM (MB) | Working set memory |
| Type | Security Agent / System / User App |
| Publisher | Executable signer (from PE header) |
| Path | Full executable path (hover for full text) |

**Row highlighting:**
- **Amber** — security agent process
- **Red** — CPU > 25% or RAM > 500 MB
- **Red + bold** — security agent AND high resource

### Security Agent Detection
Automatically classifies processes from a built-in list covering:

- **CrowdStrike** — Falcon, FalconContainer, FalconUIHost
- **Microsoft** — Defender Antivirus, Defender for Endpoint (MsSense, SenseCE, SenseTVM, etc.), Defender DLP
- **SentinelOne** — SentinelAgent, SentinelServiceHost
- **Carbon Black** — cb.exe, CbDefense, CbDefenseSvc
- **Palo Alto / Cortex XDR** — cortex_agent, PanGPA, PanGPS
- **Tanium** — TaniumClient, TaniumCX
- **Trellix / FireEye** — xagt
- **Absolute** — amagent, amservice
- **Druva** — DsAgent
- **Trend Micro** — ntrtscan, tmlisten, TrendMicro*
- **Sophos** — savservice, SophosUI

Unknown processes whose path or publisher matches a known vendor are also flagged.

**Summary banner** at the top shows:
- Green — no agents detected
- Amber — agents running, resource usage normal
- Red — one or more agents with high CPU or RAM

### Filtering
- Free-text search (process name or publisher)
- Toggle filters: Security Agents Only / High CPU / High RAM
- Filters combine

### Process Detail
Click any row to open a detail panel showing:
- Full executable path
- Publisher
- Parent process (name + PID)
- Start time, thread count, handle count
- CPU % and RAM sparkline charts for the last 60 seconds
- For security agents: vendor name and description

### Export Snapshot
**Export Snapshot** button saves a self-contained `.html` file:
- Timestamp and machine name
- Summary counts (total processes, agents, high-resource)
- Full highlighted process table
- **"What to tell IT"** — auto-generated plain-English paragraph ready to paste into a support ticket

File is named `process-snapshot-<hostname>-<YYYYMMDD-HHMM>.html`.

### Settings
Gear icon (⚙) opens settings:

| Setting | Default | Options |
|---|---|---|
| Refresh interval | 3s | 1s / 3s / 5s / 10s |
| CPU threshold | 25% | 5–90% |
| RAM threshold | 500 MB | 100–2000 MB |
| Show system processes | Yes | Toggle |
| Export machine name | Hostname | Hostname / Custom label / Anonymized |

Settings are saved to `~/.process-monitor/settings.json`.

---

## Project Structure

```
process-monitor/
├── main.py                    Entry point
├── requirements.txt
└── process_monitor/
    ├── app.py                 Tkinter GUI (banner, table, detail, settings)
    ├── classifier.py          Security agent detection logic
    ├── collector.py           psutil process collection + publisher lookup
    ├── export.py              HTML snapshot generator
    ├── history.py             Rolling 60-entry per-PID CPU/RAM history
    └── settings.py            Settings dataclass with JSON persistence
```

---

## Publisher Detection

Publisher is read from the PE file header via:
1. `sigcheck.exe` (Sysinternals) if present at `C:\Sysinternals\sigcheck.exe` or `C:\Windows\Sysinternals\sigcheck.exe`
2. `pefile` Python library (included in `requirements.txt`)
3. Falls back to "Unknown" if neither is available or the file is access-restricted

Results are cached per executable path for the lifetime of the process.

---

## Permissions

Runs as a standard user. Some SYSTEM-owned processes will show "Access restricted" as their path — this is expected and handled gracefully.

---

## Packaging (future)

The code is structured to support single-executable packaging via PyInstaller:

```
pip install pyinstaller
pyinstaller --onefile --windowed main.py
```
