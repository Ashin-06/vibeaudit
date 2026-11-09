"""Scale test: a large generated repository must scan in bounded time and memory.

Default size suits CI (2,000 files). Set VIBEAUDIT_PERF_FILES=10000 for the full-size run.
"""
import os
import random
import time
import tracemalloc

from vibeaudit.scanner import Options, scan

FILES = int(os.environ.get("VIBEAUDIT_PERF_FILES", "2000"))
SECONDS_PER_1000_FILES = 30.0  # generous: slow CI runners, Windows file system
PEAK_MB_PER_1000_FILES = 120.0

PY = '''import os
from flask import Blueprint, request, jsonify

bp = Blueprint("m{i}", __name__)


def helper_{i}(value):
    total = 0
    for item in range(10):
        total += item * len(str(value))
    return total


@bp.route("/items/{i}", methods=["GET"])
def list_{i}():
    q = request.args.get("q", "")
    return jsonify({{"n": helper_{i}(q), "env": os.environ.get("MODE", "dev")}})
'''
TS = '''import {{ useState }} from "react";

export function Widget{i}({{ label }}: {{ label: string }}) {{
  const [count, setCount] = useState(0);
  const text = `${{label}}: ${{count}}`;
  return <button onClick={{() => setCount(count + 1)}}>{{text}}</button>;
}}

export const util{i} = (a: number, b: number) => a * b + {i};
'''
MD = "# Module {i}\n\nSome documentation with `code` and a link to https://example.com/{i}.\n"
JSON = '{{"name": "pkg{i}", "version": "1.0.{i}", "private": true}}\n'


def _build(root, n):
    rng = random.Random(42)
    (root / "package.json").write_text('{"dependencies": {"react": "18.3.1", "vite": "5.0.0"}}')
    (root / "package-lock.json").write_text("{}")
    (root / "requirements.txt").write_text("flask==3.0.3\n")
    for i in range(n):
        kind = rng.random()
        d = root / f"pkg{i % 50}" / f"sub{i % 7}"
        d.mkdir(parents=True, exist_ok=True)
        if kind < 0.4:
            (d / f"mod_{i}.py").write_text(PY.format(i=i))
        elif kind < 0.8:
            (d / f"Widget{i}.tsx").write_text(TS.format(i=i))
        elif kind < 0.9:
            (d / f"README_{i}.md").write_text(MD.format(i=i))
        else:
            (d / f"data_{i}.json").write_text(JSON.format(i=i))
    # a few real findings so the slow paths run too
    (root / "pkg0" / "vuln.py").write_text("import os\nfrom flask import request\n\n@app.post('/x')\ndef x():\n    os.system('ls ' + request.args['p'])\n")


def test_large_repository_scans_in_bounded_time_and_memory(tmp_path):
    _build(tmp_path, FILES)
    tracemalloc.start()
    start = time.perf_counter()
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    elapsed = time.perf_counter() - start
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    peak_mb = peak / 1e6
    print(f"\n{res.meta['files_scanned']} files in {elapsed:.1f}s, peak traced memory {peak_mb:.0f} MB")
    assert res.meta["files_scanned"] >= FILES
    assert res.meta["internal_errors"] == [] and res.meta["skipped"] == []
    assert ("pkg0/vuln.py", 6, "BE002") in {(f.file, f.line, f.rule_id) for f in res.findings}
    assert elapsed < SECONDS_PER_1000_FILES * FILES / 1000 + 10
    assert peak_mb < PEAK_MB_PER_1000_FILES * FILES / 1000 + 50
