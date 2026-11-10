"""Data files that age (popular-package lists, retired model ids) and `vibeaudit update`, which refreshes them
from the vibeaudit repository into the user cache. A refreshed file is used only if it passes validation;
otherwise the copy shipped with the package is used."""
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
    try:
        data = (cache_dir() / "data" / name).read_bytes()
        if FILES[name](data):
            return data
    except OSError:
        pass
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
    return failed


def update_self(log: Callable[[str], None], run: Optional[Callable[..., int]] = None) -> int:
    """Upgrade the installed package from the repository with pip."""
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", REPO_URL]
    log("running: " + " ".join(cmd))
    return (run or (lambda c: subprocess.call(c)))(cmd)  # noqa: S603 - fixed argument list
