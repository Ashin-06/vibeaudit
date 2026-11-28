"""Benchmark sequential, parallel (--jobs 2, --jobs 4), and warm-cache scans on synthetic repositories."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

PY_TEMPLATE = '''import os
from flask import Blueprint, request, jsonify

bp = Blueprint("m{i}", __name__)


def helper_{i}(value):
    total = 0
    for item in range(8):
        total += item * len(str(value))
    return total


@bp.route("/items/{i}", methods=["GET"])
def list_{i}():
    q = request.args.get("q", "")
    return jsonify({{"n": helper_{i}(q), "env": os.environ.get("MODE", "dev")}})
'''
TS_TEMPLATE = '''import {{ useState }} from "react";

export function Widget{i}({{ label }}: {{ label: string }}) {{
  const [count, setCount] = useState(0);
  return <button onClick={{() => setCount(count + 1)}}>{{label}}: {{count}}</button>;
}}
'''


def _build_repo(root: Path, files: int) -> None:
    (root / "package.json").write_text('{"dependencies": {"react": "18.3.1", "vite": "5.0.0"}}\n', encoding="utf-8")
    (root / "package-lock.json").write_text("{}\n", encoding="utf-8")
    (root / "requirements.txt").write_text("flask==3.0.3\n", encoding="utf-8")
    for i in range(files):
        d = root / f"pkg{i % 40}" / f"sub{i % 5}"
        d.mkdir(parents=True, exist_ok=True)
        bucket = i % 20
        if bucket < 9:
            (d / f"mod_{i}.py").write_text(PY_TEMPLATE.format(i=i), encoding="utf-8")
        elif bucket < 18:
            (d / f"Widget_{i}.tsx").write_text(TS_TEMPLATE.format(i=i), encoding="utf-8")
        else:
            (d / f"doc_{i}.md").write_text(f"# Module {i}\n", encoding="utf-8")


def _child_resources() -> Optional[Tuple[float, float]]:
    """Return (child_max_rss_mb, child_read_mb) on Unix, or None on platforms without getrusage."""
    if sys.platform == "win32":
        return None
    import resource

    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    divisor = 1024.0 if sys.platform == "linux" else (1024.0 * 1024.0)
    rss_mb = round(usage.ru_maxrss / divisor, 2)
    read_mb = round((usage.ru_inblock * 512.0) / (1024.0 * 1024.0), 2)
    return rss_mb, read_mb


def _run_subprocess_scan(repo: Path, cache_dir: Path, jobs: int, cache: bool) -> Dict[str, Any]:
    cmd = [
        sys.executable, "-m", "vibeaudit", "scan", str(repo),
        "--offline", "--external", "none", "--jobs", str(jobs),
        "--report", "json:-", "-q",
    ]
    if not cache:
        cmd.append("--no-cache")
    env = dict(os.environ)
    env["VIBEAUDIT_CACHE_DIR"] = str(cache_dir)
    env.pop("VIBEAUDIT_NO_CACHE", None)
    before = _child_resources()
    t0 = time.perf_counter()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)  # noqa: S603 - fixed CLI benchmark invocation
    stdout, _stderr = proc.communicate()
    elapsed = time.perf_counter() - t0
    after = _child_resources()
    rss_mb: Optional[float] = None
    read_mb: Optional[float] = None
    if before is not None and after is not None:
        rss_mb = max(after[0], before[0])
        read_mb = max(0.0, round(after[1] - before[1], 2))
    payload = json.loads(stdout.decode("utf-8", "replace"))
    return {
        "jobs": jobs,
        "cache": cache,
        "cache_hit": payload["meta"]["scan_cache"]["hit"],
        "parallel_used": payload["meta"]["scan_cache"]["parallel_used"],
        "files_scanned": payload["meta"]["files_scanned"],
        "findings": len(payload["findings"]),
        "elapsed_s": round(elapsed, 3),
        "peak_rss_mb": rss_mb,
        "io_read_mb": read_mb,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark vibeaudit sequential, parallel, and cached scans.")
    parser.add_argument("--files", type=int, default=2000, help="Number of synthetic files to generate (default: 2000)")
    args = parser.parse_args()
    tmp = Path(tempfile.mkdtemp(prefix="vibeaudit_bench_"))
    try:
        repo = tmp / "repo"
        cache_dir = tmp / "cache"
        repo.mkdir()
        _build_repo(repo, args.files)
        results = [
            _run_subprocess_scan(repo, cache_dir, jobs=1, cache=False),
            _run_subprocess_scan(repo, cache_dir, jobs=2, cache=False),
            _run_subprocess_scan(repo, cache_dir, jobs=4, cache=False),
            _run_subprocess_scan(repo, cache_dir, jobs=1, cache=True),
            _run_subprocess_scan(repo, cache_dir, jobs=1, cache=True),
        ]
        print(json.dumps({"files_requested": args.files, "runs": results}, indent=2))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
