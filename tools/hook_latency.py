"""Time the pre-commit fast path (`python -m vibeaudit.hook`) on a typical commit in a benchmark repository,
next to the full `vibeaudit scan . --staged` hook.

The repository is copied into a fresh git repository, committed, and then three of its source files get a
few added lines each and are staged. Both hooks run several times; the median wall time (process start to
exit, as pre-commit sees it) is reported.

    python tools/hook_latency.py NAME [--runs 10]
"""
from __future__ import annotations

import argparse
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from benchmark import checkout_path, corpus  # noqa: E402

EDIT = {".py": "\n\ndef added_helper(x):\n    return x + 1\n", ".ts": "\n\nexport const addedValue = 1;\n",
        ".tsx": "\n\nexport const addedValue = 1;\n", ".js": "\n\nexports.addedValue = 1;\n"}


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "core.autocrlf=false", *args],
                   cwd=root, check=True, capture_output=True)


def timed(cmd, cwd: Path, runs: int) -> float:
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
    times = []
    for _ in range(runs):
        t = time.perf_counter()
        subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, stdin=subprocess.DEVNULL)
        times.append(time.perf_counter() - t)
    return statistics.median(times) * 1000


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("--runs", type=int, default=10)
    a = ap.parse_args(argv)
    repo = next(r for r in corpus() if r["name"] == a.name)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / a.name
        shutil.copytree(checkout_path(repo), root, ignore=shutil.ignore_patterns(".git"))
        git(root, "init", "-q")
        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", "base")
        files = sorted((p for p in root.rglob("*") if p.suffix in EDIT and "node_modules" not in p.parts),
                       key=lambda p: p.stat().st_size)
        picked = files[len(files) // 2:len(files) // 2 + 3]  # typical, not the largest
        for p in picked:
            with open(p, "a", encoding="utf-8", newline="") as fh:
                fh.write(EDIT[p.suffix])
        git(root, "add", *[str(p.relative_to(root)) for p in picked])
        bare = timed([sys.executable, "-c", "pass"], root, a.runs)
        fast = timed([sys.executable, "-m", "vibeaudit.hook"], root, a.runs)
        full = timed([sys.executable, "-m", "vibeaudit", "scan", ".", "--staged", "--offline", "--external", "none", "-q"],
                     root, max(3, a.runs // 3))
        print(f"{a.name}: {len(files)} source files, 3 staged ({', '.join(p.name for p in picked)})")
        print(f"python start {bare:.0f} ms; fast hook {fast:.0f} ms; full staged scan {full:.0f} ms (medians)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
