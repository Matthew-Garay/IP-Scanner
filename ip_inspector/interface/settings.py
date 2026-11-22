"""User preferences and small persistent state, stored as JSON.

Everything lives in ``~/.ip_inspector/``: a corrupt or missing file simply
means defaults, never a crash at start-up.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

logger = logging.getLogger(__name__)

DATA_DIR = Path.home() / ".ip_inspector"
SETTINGS_FILE = DATA_DIR / "settings.json"


@dataclass
class Settings:
    profile: str = "standard"
    custom_ports: str = "21,22,23,25,53,80,110,139,143,443,445,3389,8080"
    timeout: float = 0.5
    threads: int = 1000
    resolve_hostnames: bool = True
    identify_models: bool = True
    only_open: bool = False
    appearance: str = "system"
    last_range: str = ""
    favorites: list[str] = field(default_factory=list)
    #: MAC (or IP when no MAC) -> first time seen, to flag new devices.
    known_devices: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None = None) -> "Settings":
        path = path or SETTINGS_FILE
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls()
        if not isinstance(data, dict):
            return cls()
        known = {f.name for f in fields(cls)}
        settings = cls()
        for key, value in data.items():
            if key in known and isinstance(value, type(getattr(settings, key))):
                setattr(settings, key, value)
            elif key == "timeout" and isinstance(value, int):
                settings.timeout = float(value)
        return settings

    def save(self, path: Path | None = None) -> None:
        path = path or SETTINGS_FILE
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        except OSError:
            logger.warning("Could not save settings to %s", path, exc_info=True)
