"""Small persistent stores: the per-user cache (registry and OSV answers, LLM verdicts, refreshed data files) and
the per-project feedback file. Every write is atomic, every read tolerates a missing or corrupt file."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

ENABLED = os.environ.get("VIBEAUDIT_NO_CACHE", "") not in ("1", "true", "yes")


def cache_dir() -> Path:
    """VIBEAUDIT_CACHE_DIR, else the platform's user cache folder."""
    env = os.environ.get("VIBEAUDIT_CACHE_DIR")
    if env:
        return Path(env)
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "vibeaudit"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "vibeaudit"
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "vibeaudit"


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def write_atomic(path: Path, data: bytes) -> bool:
    """Write via a temporary file and rename, so readers never see half a file. False if it failed."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return True
    except OSError:
        return False


def write_json(path: Path, obj: Any) -> bool:
    return write_atomic(path, json.dumps(obj, indent=1, sort_keys=True).encode("utf-8"))


class TimedCache:
    """A JSON dict of key -> [timestamp, value] in the user cache, loaded on first use and saved by `save()`.

    ponytail: one file per cache, last writer wins between concurrent scans; it is a cache, so a lost entry
    only costs one more network request."""

    def __init__(self, name: str, ttl: float):
        self.name, self.ttl = name, ttl
        self._data: Optional[Dict[str, list]] = None
        self._dirty = False
        self._lock = threading.Lock()  # lookups run in a thread pool

    def _load(self) -> Dict[str, list]:
        with self._lock:
            if self._data is None:
                raw = read_json(cache_dir() / self.name) if ENABLED else None
                self._data = {k: v for k, v in raw.items() if isinstance(v, list) and len(v) == 2} if isinstance(raw, dict) else {}
            return self._data

    def get(self, key: str, ttl: Optional[float] = None) -> Any:
        if not ENABLED:
            return None
        hit = self._load().get(key)
        if hit is None or not isinstance(hit[0], (int, float)) or time.time() - hit[0] > (self.ttl if ttl is None else ttl):
            return None
        return hit[1]

    def put(self, key: str, value: Any) -> None:
        if ENABLED:
            self._load()[key] = [time.time(), value]
            self._dirty = True

    def save(self) -> None:
        if not (ENABLED and self._dirty and self._data is not None):
            return
        now = time.time()
        keep = {k: v for k, v in self._data.items() if now - v[0] <= self.ttl}  # drop expired entries
        if write_json(cache_dir() / self.name, keep):
            self._dirty = False
