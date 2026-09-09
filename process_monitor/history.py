from collections import deque
from dataclasses import dataclass
import time


@dataclass(slots=True)
class HistoryEntry:
    timestamp: float
    cpu_pct: float
    ram_mb: float


class ProcessHistory:
    """Rolling per-PID history capped at max_entries samples."""

    def __init__(self, max_entries: int = 60) -> None:
        self._max = max_entries
        self._data: dict[int, deque[HistoryEntry]] = {}

    def update(self, pid: int, cpu_pct: float, ram_mb: float) -> None:
        if pid not in self._data:
            self._data[pid] = deque(maxlen=self._max)
        self._data[pid].append(HistoryEntry(time.monotonic(), cpu_pct, ram_mb))

    def get(self, pid: int) -> list[HistoryEntry]:
        return list(self._data.get(pid, []))

    def prune(self, active_pids: set[int]) -> None:
        dead = set(self._data.keys()) - active_pids
        for pid in dead:
            del self._data[pid]
