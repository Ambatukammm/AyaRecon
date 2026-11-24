"""
AyaRecon — configuration and settings management.
Made by Ruel.

Settings are stored as JSON in the user's home directory so they persist
across runs and are never committed with the code. API keys live here (local
only) — they are never transmitted anywhere except the provider you configure.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

APP_DIR = Path(os.path.expanduser("~")) / ".ayarecon"
CONFIG_PATH = APP_DIR / "settings.json"
DEFAULT_DB_PATH = APP_DIR / "ayarecon.sqlite3"
WORDLIST_DIR = APP_DIR / "wordlists"

DEFAULTS: dict[str, Any] = {
    # --- Scan behaviour ---
    "tcp_timeout": 1.0,            # seconds per TCP connect attempt
    "http_timeout": 8.0,          # seconds per HTTP request
    "dns_timeout": 5.0,
    "max_threads": 50,            # worker pool size for scans
    "rate_limit_per_sec": 20,     # global cap on requests/sec for enumeration

    # --- Safety ---
    "require_active_confirmation": True,
    "enumeration_unlocked": False,   # becomes True only after permission gate
    "owned_assets": [],              # IPs/domains the user asserts they own

    # --- AI ---
    "ai_provider": "ollama",         # "ollama" | "openai" | "anthropic" | "none"
    "ollama_host": "http://localhost:11434",
    "ollama_model": "llama3",
    "cloud_api_key": "",             # optional, local only
    "cloud_model": "",

    # --- API keys for OSINT sources (all optional) ---
    "hibp_api_key": "",              # HaveIBeenPwned
    "github_token": "",              # raises GitHub search rate limits
    "nvd_api_key": "",               # NIST NVD — raises live-CVE rate limits

    # --- Paths ---
    "custom_wordlist_path": "",
}


class Config:
    """Loads, holds and persists user settings."""

    def __init__(self, path: Path = CONFIG_PATH):
        self.path = path
        self._data: dict[str, Any] = dict(DEFAULTS)
        self.load()

    def load(self) -> None:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            try:
                stored = json.loads(self.path.read_text(encoding="utf-8"))
                # Merge: keep new defaults, override with stored values.
                self._data.update({k: v for k, v in stored.items() if k in DEFAULTS})
            except (json.JSONDecodeError, OSError):
                # Corrupt config — fall back to defaults rather than crashing.
                pass

    def save(self) -> None:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._data[key] = value

    def as_dict(self) -> dict[str, Any]:
        return dict(self._data)

    # --- convenience ---
    def is_owned(self, target: str) -> bool:
        """True if the user has registered this target as something they own."""
        target = (target or "").strip().lower()
        return any(target == a.strip().lower() for a in self.get("owned_assets", []))
