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
from typing import Any, Dict, List, Optional

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


MAX_JSON_DEPTH = 500
MAX_JSON_FILE_BYTES = 20 * 1024 * 1024


def _json_too_deep(text: Any, limit: int = MAX_JSON_DEPTH) -> bool:
    if isinstance(text, str):
        if text.count("{") + text.count("[") <= limit:
            return False
        s = text
    elif isinstance(text, (bytes, bytearray)):
        if text.count(b"{") + text.count(b"[") <= limit:
            return False
        try:
            s = bytes(text).decode("utf-8")
        except UnicodeDecodeError:
            return False
    else:
        return False
    depth = 0
    in_str = False
    esc = False
    for ch in s:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
            if depth > limit:
                return True
        elif ch in "}]":
            if depth > 0:
                depth -= 1
    return False


def loads_json(text: Any) -> Any:
    """json.loads for untrusted text: nesting too deep for the parser (a RecursionError) is reported as the
    ValueError every caller already handles, instead of crashing the scan, the LSP or the MCP server."""
    if _json_too_deep(text):
        raise ValueError("JSON nested too deeply")
    try:
        return json.loads(text)
    except RecursionError:
        raise ValueError("JSON nested too deeply") from None


def loads_toml(text: str) -> Any:
    """tomllib.loads with the same guarantee as loads_json (TOMLDecodeError is a ValueError too)."""
    import tomllib

    try:
        return tomllib.loads(text)
    except RecursionError:
        raise ValueError("TOML nested too deeply") from None


LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


def validate_http_url(url: str, *, allow_local_http: bool = False) -> str:
    """Require an https:// URL (or http:// on loopback only when allow_local_http=True)."""
    import urllib.parse

    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string")
    parts = urllib.parse.urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not host:
        raise ValueError(f"URL {url!r} has no host")
    if scheme == "https":
        return url
    if allow_local_http and scheme == "http" and host in LOCAL_HOSTS:
        return url
    allowed = "https:// (or http:// on localhost)" if allow_local_http else "https://"
    raise ValueError(f"unsafe URL scheme {parts.scheme!r}; only {allowed} is allowed")


def read_json(path: Path, max_bytes: Optional[int] = MAX_JSON_FILE_BYTES) -> Any:
    try:
        with open(path, "rb") as fh:
            if max_bytes is not None:
                if os.fstat(fh.fileno()).st_size > max_bytes:
                    return None
                raw = fh.read(max_bytes + 1)
                if len(raw) > max_bytes:
                    return None
            else:
                raw = fh.read()
        return loads_json(raw.decode("utf-8"))
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
            try:
                os.chmod(tmp, os.stat(path).st_mode)  # mkstemp makes 0600: keep the replaced file's permissions
            except OSError:
                pass
            for attempt in range(3):
                try:
                    os.replace(tmp, path)
                    break
                except PermissionError:
                    if attempt == 2:
                        raise
                    time.sleep(0.01 * (attempt + 1))
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

    Thread-safe: dependency lookups run in a thread pool. Between processes the last writer wins; it is a
    cache, so a lost entry only costs one more network request."""

    instances: List["TimedCache"] = []

    def __init__(self, name: str, ttl: float):
        self.name, self.ttl = name, ttl
        self._data: Optional[Dict[str, list]] = None
        self._dirty = False
        self._lock = threading.Lock()
        TimedCache.instances.append(self)

    def reset(self) -> None:
        """Forget what was loaded (tests, and a long-lived process that switches cache folders)."""
        with self._lock:
            self._data, self._dirty = None, False

    def _loaded(self) -> Dict[str, list]:
        """The entries; the caller holds the lock."""
        if self._data is None:
            raw = read_json(cache_dir() / self.name) if ENABLED else None
            # a hand-edited or corrupt file may hold anything: keep only [number, value] entries
            self._data = {k: v for k, v in raw.items() if isinstance(v, list) and len(v) == 2 and isinstance(v[0], (int, float))
                          and not isinstance(v[0], bool)} if isinstance(raw, dict) else {}
        return self._data

    def get(self, key: str, ttl: Optional[float] = None) -> Any:
        if not ENABLED:
            return None
        with self._lock:
            hit = self._loaded().get(key)
        if hit is None or not isinstance(hit[0], (int, float)) or time.time() - hit[0] > (self.ttl if ttl is None else ttl):
            return None
        return hit[1]

    def put(self, key: str, value: Any) -> None:
        if ENABLED:
            with self._lock:
                self._loaded()[key] = [time.time(), value]
                self._dirty = True

    def save(self) -> None:
        if not ENABLED:
            return
        with self._lock:  # snapshot, write and clear the flag as one step, so no put is lost or half-written
            if not self._dirty or self._data is None:
                return
            now = time.time()
            keep = {k: v for k, v in self._data.items() if now - v[0] <= self.ttl}  # drop expired entries
            if write_json(cache_dir() / self.name, keep):
                self._dirty = False
