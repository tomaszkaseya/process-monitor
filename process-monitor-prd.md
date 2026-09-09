# Product Requirements Document
## Windows Process Monitor — Security Agent Visibility Tool

**Version:** 1.0  
**Status:** Draft  
**Prepared for:** Claude Code implementation

---

## Overview

A lightweight Python desktop application for Windows that gives end users a clear, real-time view of all running processes — with a specific focus on identifying and surfacing security agent processes that may be consuming excessive CPU or RAM. Users can monitor their machine live and export snapshots for sharing with IT or support teams.

---

## Problem Statement

Security agents (EDR, AV, DLP tools) occasionally enter states where they consume disproportionate CPU and RAM, making machines sluggish or unusable. End users have no easy way to:

- Confirm whether a security agent is the cause of their slowness
- Capture the evidence needed to report the issue to IT
- Know which specific process or agent version is responsible

The built-in Windows Task Manager shows processes but provides no context about which ones are security agents, no easy export, and no flagging of anomalous behavior.

---

## Goals

- Let users quickly see if a security agent process is hogging resources
- Provide a live, auto-refreshing view of all processes
- Allow one-click export of a snapshot for IT escalation
- Keep it simple enough for non-technical end users

---

## Non-Goals

- Remote monitoring or multi-machine views
- Killing or managing processes (read-only)
- Deep forensic analysis or kernel-level visibility
- Cross-platform support (Windows only, v1)

---

## Users

**Primary:** End users on corporate Windows machines experiencing slowness who suspect security tooling is the cause. Non-technical; want a clear answer, not raw data.

---

## Features

### 1. Live Process Dashboard

**Behavior:**
- Auto-refreshes every 3 seconds by default (configurable: 1s / 3s / 5s / 10s)
- Displays all running processes in a sortable table
- Default sort: CPU usage descending

**Columns:**

| Column | Description |
|---|---|
| Process Name | Executable name |
| PID | Process ID |
| CPU % | Current CPU usage |
| RAM (MB) | Working set memory |
| Type | "Security Agent", "System", or "User App" |
| Publisher | Verified signer of the executable (from digital signature) |
| Path | Full executable path (truncated, expandable on hover) |

**Visual treatment:**
- Security agent rows highlighted in amber
- Rows where CPU > 25% or RAM > 500 MB highlighted in red
- Both conditions together: red + bold

---

### 2. Security Agent Detection

**Behavior:**
- Automatically classifies processes against a built-in list of known security agent executable names (see below)
- Unknown processes with names or paths matching common security vendors (CrowdStrike, SentinelOne, Carbon Black, Cortex, Defender, Tanium, etc.) are also flagged
- Classification is done by process name + path + publisher, in that order of confidence

**Built-in known agent list (seed list, extensible):**

```
CSFalconService.exe, CSFalconContainer.exe       # CrowdStrike
SentinelAgent.exe, SentinelServiceHost.exe        # SentinelOne
cb.exe, CbDefense.exe, CbDefenseSvc.exe           # Carbon Black
cortex_agent.exe, pangpa.exe, pangps.exe          # Cortex XDR / Palo Alto
MsMpEng.exe, MsSense.exe, SecurityHealthService  # Microsoft Defender / MDE
TaniumClient.exe, TaniumCX.exe                    # Tanium
xagt.exe                                          # FireEye/Trellix
amagent.exe, amservice.exe                        # Absolute
DsAgent.exe                                       # Druva
TrendMicro*, ntrtscan.exe, tmlisten.exe           # Trend Micro
savservice.exe, SophosUI.exe                      # Sophos
```

**Summary banner at the top of the dashboard:**
- "X security agent(s) running — Y are high CPU"
- Color-coded: green (normal), amber (elevated), red (critical)

---

### 3. Filtering and Search

- Free-text search box filters by process name or publisher in real time
- Filter toggle buttons: "All", "Security Agents Only", "High CPU", "High RAM"
- Filters are combinable

---

### 4. Snapshot Export

**Trigger:** "Export Snapshot" button, always visible

**Output:** Single HTML file, self-contained, no external dependencies

**Contents:**
- Timestamp and machine name (hostname only, no IP or domain by default)
- Summary: total processes, security agents detected, any flagged as high-resource
- Full process table at time of export (same columns as live view)
- Highlighted rows for security agents and high-resource processes
- Section at the bottom: "What to tell IT" — a pre-filled plain-English summary the user can copy and paste, e.g.:
  > "At 14:32 on 2026-09-09, machine KA-HJ33XL3 had 3 security agent processes running. CSFalconService.exe was using 47% CPU and 812 MB RAM, which is unusually high. Full process list attached."

**File naming:** `process-snapshot-<hostname>-<YYYYMMDD-HHMM>.html`

---

### 5. Process Detail View

**Trigger:** Click any row in the table

**Shows in a side panel or modal:**
- Full executable path
- Digital signature / publisher (verified or unverified)
- Parent process (name + PID)
- CPU and RAM usage over the last 60 seconds (sparkline chart)
- Number of threads and handles
- Process start time
- For security agents: agent name, vendor, and a plain-English description of what the agent normally does

---

### 6. Settings

Accessible from a gear icon. Options:

| Setting | Default | Options |
|---|---|---|
| Refresh interval | 3 seconds | 1s, 3s, 5s, 10s |
| RAM threshold for flagging | 500 MB | 100–2000 MB |
| CPU threshold for flagging | 25% | 5–90% |
| Show system processes | Yes | Toggle |
| Machine name in export | Hostname only | Hostname / Custom label / Anonymized |

---

## Technical Notes for Implementation

- **Language:** Python 3.10+
- **Process data:** `psutil` library — use `psutil.process_iter()` with `['name', 'pid', 'cpu_percent', 'memory_info', 'exe', 'ppid', 'num_threads', 'create_time']`
- **CPU measurement:** Call `cpu_percent(interval=None)` on the second poll cycle — first call always returns 0.0
- **Publisher/signature:** Use `subprocess` + `sigcheck.exe` (Sysinternals) if available, or fall back to reading the PE header with `pefile` library; graceful fallback to "Unknown" if neither available
- **GUI framework:** `tkinter` (stdlib, no install needed) or `PySimpleGUI` for slightly cleaner look — Claude Code should pick based on what produces a cleaner result
- **Sparkline history:** Keep a rolling 60-entry deque per PID (one entry per second); clear on PID disappearance
- **Export:** Generate HTML as a Python string — no templating library needed for v1
- **Permissions:** Run as standard user; some processes (SYSTEM-owned) will have `AccessDenied` on `exe` — catch and show "Access restricted"
- **Packaging:** Single `.exe` via PyInstaller for distribution (out of scope for v1 code, but structure code to support it)

---

## Out of Scope for v1

- macOS / Linux support
- Remote or centralized monitoring
- Alerting / notifications
- Process termination
- Historical logging across sessions
- Integration with IT ticketing systems

---

## Success Criteria

- An end user can open the app, identify within 10 seconds whether a security agent is causing high CPU/RAM, and export a report to send to IT — without any training or documentation.

---

## Open Questions

1. Should the known agent list be user-editable, or managed centrally by IT via a config file?
2. Should the "What to tell IT" summary be copyable as plain text, or also offer a mailto: link?
3. Is PyInstaller packaging in scope for Claude Code to produce alongside the source?
