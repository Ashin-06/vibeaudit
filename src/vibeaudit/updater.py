"""Data files that age (popular-package lists, retired model ids, the threat feed) and `vibeaudit update`, which
refreshes them from the vibeaudit repository into the user cache. A refreshed file is used only if it passes
validation (the threat feed: its signature, see feed.py); otherwise the copy shipped with the package is used."""
from __future__ import annotations

import gzip
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from importlib import resources
from typing import Callable, Dict, List, Optional

from .store import cache_dir, write_atomic

DATA_URL = os.environ.get("VIBEAUDIT_DATA_URL", "https://raw.githubusercontent.com/Ashin-06/vibeaudit/main/src/vibeaudit/data/")
FEED_URL = os.environ.get("VIBEAUDIT_FEED_URL", "https://raw.githubusercontent.com/Ashin-06/vibeaudit/threat-feed/threat_feed.json")
REPO_URL = "git+https://github.com/Ashin-06/vibeaudit.git"
MAX_BYTES = 10_000_000
PACKAGE_NAME = re.compile(r"(?i)[@a-z0-9][\w.@/-]{0,213}")
MODEL_ID = re.compile(r"(?i)[a-z0-9][a-z0-9.@:_-]{1,80}\*?")


def _names(data: bytes) -> List[str]:
    return gzip.decompress(data).decode("utf-8").split()


def _valid_top(data: bytes) -> bool:
    try:
        names = _names(data)
    except (OSError, EOFError, ValueError):
        return False
    # a few real packages have odd names (npm has one called "-"), so require 99%, not every name
    return len(names) >= 1000 and sum(1 for n in names if PACKAGE_NAME.fullmatch(n)) >= 0.99 * len(names)


def model_ids(data: bytes) -> List[str]:
    return [ln.strip() for ln in data.decode("utf-8", "replace").splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def _valid_models(data: bytes) -> bool:
    ids = model_ids(data)
    return len(ids) >= 5 and all(MODEL_ID.fullmatch(i) for i in ids)


FILES: Dict[str, Callable[[bytes], bool]] = {
    "pypi_top.txt.gz": _valid_top,
    "npm_top.txt.gz": _valid_top,
    "retired_models.txt": _valid_models,
}


def data_bytes(name: str) -> bytes:
    """The refreshed copy of a data file when there is a valid one, else the packaged copy."""
    path = cache_dir() / "data" / name
    if path.is_file():  # only after `vibeaudit update`
        try:
            data = path.read_bytes()
            if FILES[name](data):
                return data
        except OSError:
            pass  # an unreadable refreshed copy falls back to the shipped one below
    return resources.files("vibeaudit").joinpath("data", name).read_bytes()


def _download(url: str) -> bytes:
    headers = {"User-Agent": "vibeaudit-update"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token and url.startswith("https://raw.githubusercontent.com/"):
        headers["Authorization"] = f"token {token}"  # needed while the repository is private
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as resp:  # noqa: S310 - fixed https URL
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("file is too large")
    return data


def forget_loaded_data() -> None:
    """Drop what was built from the data files, so a long-lived process (the MCP server) uses fresh copies."""
    from . import aiscan, bundle, deps, feed

    feed.forget()
    aiscan._RETIRED.clear()
    deps._POPULAR.clear()
    bundle._LOADED.clear()


def update_data(log: Callable[[str], None], fetch: Callable[[str], bytes] = _download) -> int:
    """Refresh every data file. Returns the number of files that could not be refreshed."""
    failed = 0
    for name, valid in FILES.items():
        try:
            data = fetch(DATA_URL + name)
        except (urllib.error.URLError, OSError, ValueError) as e:
            log(f"{name}: download failed ({e}); keeping the current copy")
            failed += 1
            continue
        if not valid(data):
            log(f"{name}: downloaded file failed validation; keeping the current copy")
            failed += 1
        elif not write_atomic(cache_dir() / "data" / name, data):
            log(f"{name}: could not write to {cache_dir() / 'data'}")
            failed += 1
        else:
            count = len(_names(data)) if name.endswith(".gz") else len(model_ids(data))
            log(f"{name}: updated ({count} entries)")
    failed += _update_feed(log, fetch)
    forget_loaded_data()
    return failed


def _update_feed(log: Callable[[str], None], fetch: Callable[[str], bytes]) -> int:
    """Install the signed threat feed if it verifies, has not expired and is not older than the installed one."""
    from . import feed

    if feed.public_key() is None:
        log(f"{feed.FEED}: this build has no feed key; using the threat data shipped with vibeaudit")
        return 0
    try:
        raw = fetch(FEED_URL)
    except (urllib.error.URLError, OSError, ValueError) as e:
        log(f"{feed.FEED}: download failed ({e}); keeping the current copy")
        return 1
    try:
        doc = feed.open_feed(raw)
        if feed.expired(doc):
            raise feed.FeedError(f"it expired on {doc['expires'][:10]}")
        current = feed.cached()
        if current is not None and doc["version"] < current["version"]:
            raise feed.FeedError("it is older than the installed feed")
    except feed.FeedError as e:
        log(f"{feed.FEED}: downloaded feed rejected ({e}); keeping the current copy")
        return 1
    if not write_atomic(cache_dir() / "data" / feed.FEED, raw):
        log(f"{feed.FEED}: could not write to {cache_dir() / 'data'}")
        return 1
    d = doc["data"]
    log(f"{feed.FEED}: updated (signed {doc['created'][:10]}, {len(d.get('slopsquatted', []))} slopsquatted names, "
        f"{len(d.get('model_sunsets', []))} model sunsets, {len(d.get('prompt_injection', []))} injection patterns)")
    return 0


def update_self(log: Callable[[str], None], run: Optional[Callable[..., int]] = None) -> int:
    """Upgrade the installed package from the repository with pip."""
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", REPO_URL]
    log("running: " + " ".join(cmd))
    return (run or (lambda c: subprocess.call(c)))(cmd)  # noqa: S603 - fixed argument list
