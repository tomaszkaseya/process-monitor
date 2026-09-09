from dataclasses import dataclass, asdict
import json
from pathlib import Path

SETTINGS_FILE = Path.home() / ".process-monitor" / "settings.json"


@dataclass
class Settings:
    refresh_interval: int = 3          # seconds: 1, 3, 5, 10
    ram_threshold_mb: int = 500        # MB
    cpu_threshold_pct: float = 25.0    # percent
    show_system_processes: bool = True
    export_machine_name: str = "hostname"   # "hostname" | "custom" | "anonymized"
    export_custom_label: str = ""

    def save(self) -> None:
        SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2)

    @classmethod
    def load(cls) -> "Settings":
        if SETTINGS_FILE.exists():
            try:
                with open(SETTINGS_FILE, encoding="utf-8") as f:
                    data = json.load(f)
                valid = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
                return cls(**valid)
            except Exception:
                pass
        return cls()
