"""Head-to-head on the pinned corpus: vibeaudit, Semgrep (`--config p/default`, no login) and Bandit.

    python tools/compare.py            # needs semgrep and bandit on PATH and the corpus fetched

Writes benchmark/compare.json (advisory recall, finding counts, overlap, precision on a labelled sample) and
benchmark/compare_sample.json (a seeded random sample of each tool's findings, to label). Labels go in
benchmark/compare_labels.json as {"tool|repo|file|line|rule": "tp" | "fp"}; rerun to fold them in. Runs in CI on
Linux (.github/workflows/compare.yml), where both tools install cleanly.
"""
from __future__ import annotations

import json
import random
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests"), str(ROOT / "tools")]
import benchmark as B  # noqa: E402

BENCH = ROOT / "benchmark"
SLACK = 3
SAMPLE = 50
SEED = 2026


def _rel(path: str, root: Path) -> str:
    p = Path(path)
    try:
        return p.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return p.as_posix().lstrip("./")


def semgrep(root: Path) -> List[dict]:
    out = subprocess.run(["semgrep", "scan", "--config", "p/default", "--json", "--quiet", "--metrics=off",
                          "--timeout", "20", "--max-target-bytes", "1000000", str(root)],
                         capture_output=True, text=True, encoding="utf-8", errors="replace")
    try:
        data = json.loads(out.stdout or "{}")
    except ValueError:
        data = {}
    if out.returncode not in (0, 1) or "results" not in data:
        # a scanner that cannot run must fail the comparison, not count as "found nothing"
        raise RuntimeError(f"semgrep exited {out.returncode} on {root.name}: {(out.stderr or '')[-1500:]}")
    errs = data.get("errors") or []
    if errs:
        print(f"  semgrep: {len(errs)} errors on {root.name}, first: {str(errs[0])[:300]}", flush=True)
    return [{"file": _rel(r["path"], root), "line": r["start"]["line"], "rule": r["check_id"].rsplit(".", 1)[-1],
             "message": (r.get("extra") or {}).get("message", "")[:200]} for r in data.get("results", [])]


def bandit(root: Path) -> List[dict]:
    if not any(root.rglob("*.py")):
        return []
    out = subprocess.run(["bandit", "-r", "-q", "-f", "json", "-x", "node_modules,.venv,venv,tests,test", str(root)],
                         capture_output=True, text=True, encoding="utf-8", errors="replace")
    try:
        data = json.loads(out.stdout or "{}")
    except ValueError:
        return []
    return [{"file": _rel(r["filename"], root), "line": r["line_number"], "rule": r["test_id"],
             "message": r.get("issue_text", "")[:200]} for r in data.get("results", [])]


def main() -> int:
    gt = json.loads((BENCH / "recall.json").read_text(encoding="utf-8"))["locations"]
    labels: Dict[str, str] = {}
    if (BENCH / "compare_labels.json").is_file():
        labels = json.loads((BENCH / "compare_labels.json").read_text(encoding="utf-8"))
    tools = {"vibeaudit": [], "semgrep": [], "bandit": []}
    for repo in B.corpus():
        root = B.checkout_path(repo)
        if not root.is_dir():
            continue
        print("scanning", repo["name"], flush=True)
        for f in B.scan_repo(repo):
            tools["vibeaudit"].append({"repo": repo["name"], "file": f["file"], "line": f["line"], "rule": f["rule"], "message": f["message"][:200]})
        for name, fn in (("semgrep", semgrep), ("bandit", bandit)):
            for f in fn(root):
                tools[name].append(dict(f, repo=repo["name"]))
    found_by: Dict[int, List[str]] = {i: [] for i in range(len(gt))}
    result: Dict[str, dict] = {}
    sample_out: Dict[str, List[dict]] = {}
    rnd = random.Random(SEED)
    for name, findings in tools.items():
        hits = 0
        for i, g in enumerate(gt):
            a, b = g["lines"]
            if any(f["repo"] == g["repo"] and f["file"] == g["file"] and a - SLACK <= f["line"] <= b + SLACK for f in findings):
                hits += 1
                found_by[i].append(name)
        sample = rnd.sample(findings, min(SAMPLE, len(findings))) if name != "vibeaudit" else []
        sample_out[name] = sample
        keyed = [labels.get(f"{name}|{s['repo']}|{s['file']}|{s['line']}|{s['rule']}") for s in sample]
        labelled = [k for k in keyed if k in ("tp", "fp")]
        result[name] = {"findings": len(findings), "recall": [hits, len(gt)],
                        "precision_sample": [labelled.count("tp"), len(labelled)] if len(labelled) == len(sample) and sample else None}
    overlap = sum(1 for v in found_by.values() if len(v) > 1)
    out = {
        "method": ("Each tool scans the same pinned repositories. Advisory recall counts the known vulnerable locations "
                   "(benchmark/recall.json) where the tool reports any finding within 3 lines, the same rule for every "
                   "tool (looser than vibeaudit's own recall, which needs a matching rule). Semgrep runs `--config "
                   "p/default` with no login (the community rules); Bandit runs on Python only, tests excluded. "
                   f"Precision is estimated from {SAMPLE} findings per tool drawn with a fixed seed ({SEED}) and labelled "
                   "by the rubric in benchmark/README.md; vibeaudit's precision is the full labelled count in RESULTS.md."),
        "limits": ("Semgrep's paid rules (Pro, cross-file) and Bandit plugins are not used. Seventeen advisory locations "
                   "are too few for a precise recall figure, and they are Python and JavaScript web and agent code, where "
                   "vibeaudit is strongest; Semgrep covers far more languages, and Bandit covers Python only. A sample of "
                   f"{SAMPLE} gives a precision estimate within about +-14 points at 95% confidence."),
        "tools": result, "overlap": overlap,
        "advisory_hits": {f"{g['repo']}:{g['file']}:{g['lines'][0]}": found_by[i] for i, g in enumerate(gt)},
    }
    (BENCH / "compare.json").write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    (BENCH / "compare_sample.json").write_text(json.dumps(sample_out, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
