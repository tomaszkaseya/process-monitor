from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from typing import Optional

import psutil

from .classifier import classify

try:
    import pefile as _pefile
    _HAS_PEFILE = True
except ImportError:
    _HAS_PEFILE = False

# Cache publisher lookups keyed by executable path to avoid repeated PE reads
_publisher_cache: dict[str, str] = {}

# Candidate locations for Sysinternals sigcheck.exe
_SIGCHECK_PATHS = [
    r"C:\Sysinternals\sigcheck.exe",
    r"C:\Windows\Sysinternals\sigcheck.exe",
    r"C:\Tools\sigcheck.exe",
]


@dataclass
class ProcessInfo:
    pid: int
    name: str
    cpu_pct: float
    ram_mb: float
    proc_type: str              # "Security Agent" | "System" | "User App"
    vendor: Optional[str]
    agent_desc: Optional[str]
    publisher: str
    exe_path: str               # "Access restricted" when denied
    ppid: int
    num_threads: int
    create_time: float          # Unix timestamp
    num_handles: int = 0


def _sigcheck_exe() -> Optional[str]:
    for p in _SIGCHECK_PATHS:
        if os.path.isfile(p):
            return p
    return None


def _publisher_via_sigcheck(exe_path: str, sigcheck: str) -> Optional[str]:
    try:
        result = subprocess.run(
            [sigcheck, "-q", "-nobanner", exe_path],
            capture_output=True, text=True, timeout=4,
        )
        for line in result.stdout.splitlines():
            if "Publisher:" in line:
                return line.split("Publisher:", 1)[-1].strip() or None
    except Exception:
        pass
    return None


def _publisher_via_pefile(exe_path: str) -> Optional[str]:
    if not _HAS_PEFILE:
        return None
    try:
        pe = _pefile.PE(exe_path, fast_load=True)
        pe.parse_data_directories(
            directories=[_pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
        if hasattr(pe, "VS_VERSIONINFO"):
            for vi in pe.VS_VERSIONINFO:
                if hasattr(vi, "StringFileInfo"):
                    for sfi in vi.StringFileInfo:
                        for table in sfi.StringTable:
                            for key in (b"CompanyName", b"Publisher"):
                                if key in table.entries:
                                    val = table.entries[key]
                                    if isinstance(val, bytes):
                                        val = val.decode("utf-8", errors="replace")
                                    val = val.strip()
                                    if val:
                                        pe.close()
                                        return val
        pe.close()
    except Exception:
        pass
    return None


_sigcheck_path: Optional[str] = _sigcheck_exe()


def get_publisher(exe_path: str) -> str:
    if not exe_path or exe_path == "Access restricted":
        return "Unknown"
    if exe_path in _publisher_cache:
        return _publisher_cache[exe_path]

    pub: Optional[str] = None
    if _sigcheck_path:
        pub = _publisher_via_sigcheck(exe_path, _sigcheck_path)
    if not pub:
        pub = _publisher_via_pefile(exe_path)

    result = pub or "Unknown"
    _publisher_cache[exe_path] = result
    return result


def collect_processes() -> list[ProcessInfo]:
    """Return a snapshot of all running processes."""
    attrs = [
        "name", "pid", "cpu_percent", "memory_info",
        "exe", "ppid", "num_threads", "create_time",
    ]
    procs: list[ProcessInfo] = []

    for proc in psutil.process_iter(attrs):
        try:
            info = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        name = info.get("name") or "Unknown"
        pid = info.get("pid") or 0
        cpu_pct = round(info.get("cpu_percent") or 0.0, 1)
        mem = info.get("memory_info")
        ram_mb = round(mem.rss / (1024 * 1024), 1) if mem else 0.0
        exe = info.get("exe") or ""
        ppid = info.get("ppid") or 0
        num_threads = info.get("num_threads") or 0
        create_time = info.get("create_time") or 0.0

        try:
            num_handles = proc.num_handles()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            num_handles = 0

        exe_display = exe if exe else "Access restricted"
        publisher = get_publisher(exe_display)
        proc_type, vendor, agent_desc = classify(name, exe, publisher)

        procs.append(ProcessInfo(
            pid=pid,
            name=name,
            cpu_pct=cpu_pct,
            ram_mb=ram_mb,
            proc_type=proc_type,
            vendor=vendor,
            agent_desc=agent_desc,
            publisher=publisher,
            exe_path=exe_display,
            ppid=ppid,
            num_threads=num_threads,
            create_time=create_time,
            num_handles=num_handles,
        ))

    return procs
