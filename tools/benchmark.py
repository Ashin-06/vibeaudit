"""Measure vibeaudit's accuracy on a labelled corpus of real repositories and on seeded examples.

    python tools/benchmark.py fetch                  # check out every pinned repository into the cache
    python tools/benchmark.py run                    # scan, compare with the labels, print the table
    python tools/benchmark.py run --json out.json    # also write the full results
    python tools/benchmark.py check                  # CI gate: compare with benchmark/baseline.json
    python tools/benchmark.py baseline               # record the current results as the baseline
    python tools/benchmark.py review NAME            # list unlabelled findings of one repository

Corpus: benchmark/corpus.json (url, exact commit, licence). Repositories are fetched into
$VIBEAUDIT_BENCH_DIR (default: ~/.cache/vibeaudit-bench), never into this repository.
Labels: benchmark/labels/<name>.json, one entry per reviewed finding:
    {"rule": "AUTH001", "file": "app/api/x/route.ts", "line": 12, "fingerprint": "...",
     "verdict": "tp" | "fp", "reason": "one line, written after reading the code"}
A finding without a label is "needs review": it never counts as a true positive.

Precision per rule = TP / (TP + FP) over labelled findings. Seeded recall per rule = expected findings
found / expected findings, over the sample apps in tests/fixtures (and benchmark/seeded), whose expected
findings are marked with `expect: RULE` comments.

The gate (`check`) fails when a rule's precision falls below its baseline, when a labelled true positive
is no longer reported, or when seeded recall drops. Unlabelled findings count as false positives there,
so new noise cannot hide; label them (or fix the rule) to pass. A repository that cannot be fetched is
skipped and reported, never failed on: the gate checks what it could scan.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from vibeaudit.rules import RULES  # noqa: E402
from vibeaudit.scanner import Options, scan  # noqa: E402

BENCH = ROOT / "benchmark"
CORPUS = BENCH / "corpus.json"
LABELS = BENCH / "labels"
BASELINE = BENCH / "baseline.json"
SEEDED_DIRS = [ROOT / "tests" / "fixtures", BENCH / "seeded"]
MARKER = re.compile(r"expect:\s*([A-Z]+[0-9]+(?:\s*,\s*[A-Z]+[0-9]+)*)")
# rules whose result depends on the network (registry, OSV) are measured on seeded cases only
NETWORK_RULES = {"DEP001", "DEP003", "DEP004", "DEP009"}


def cache_dir() -> Path:
    return Path(os.environ.get("VIBEAUDIT_BENCH_DIR") or Path.home() / ".cache" / "vibeaudit-bench")


def corpus() -> List[dict]:
    return json.loads(CORPUS.read_text(encoding="utf-8"))["repos"]


def checkout_path(repo: dict) -> Path:
    return cache_dir() / f"{repo['name']}-{repo['commit'][:12]}"


def _git(*args: str, cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    # fixed line endings and no symlinks, so a checkout is byte-identical on every OS
    return subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "core.symlinks=false", *args],
                          cwd=str(cwd) if cwd else None, capture_output=True, text=True, timeout=600)


def fetch(repo: dict, attempts: int = 3) -> Tuple[bool, str]:
    """Check out the pinned commit (shallow). Returns (ok, message)."""
    target = checkout_path(repo)
    if (target / ".bench-ok").is_file():
        return True, "cached"
    for attempt in range(1, attempts + 1):
        tmp = Path(tempfile.mkdtemp(prefix=repo["name"] + "-", dir=str(cache_dir())))
        try:
            steps = [("init", "-q"), ("remote", "add", "origin", repo["url"]),
                     ("fetch", "-q", "--depth", "1", "origin", repo["commit"]), ("checkout", "-q", "FETCH_HEAD")]
            for step in steps:
                out = _git(*step, cwd=tmp)
                if out.returncode != 0:
                    raise RuntimeError(out.stderr.strip()[-300:] or "git failed")
            head = _git("rev-parse", "HEAD", cwd=tmp).stdout.strip()
            if head != repo["commit"]:
                raise RuntimeError(f"checked out {head}, expected {repo['commit']}")
            (tmp / ".bench-ok").write_text(head, encoding="utf-8")
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
            tmp.rename(target)
            return True, "fetched"
        except (RuntimeError, OSError, subprocess.SubprocessError) as e:
            shutil.rmtree(tmp, ignore_errors=True)
            if attempt == attempts:
                return False, f"fetch failed after {attempts} attempts: {e}"
            time.sleep(5 * attempt)
    return False, "unreachable"


def fetch_all(quiet: bool = False) -> Dict[str, str]:
    cache_dir().mkdir(parents=True, exist_ok=True)
    skipped = {}
    for repo in corpus():
        ok, msg = fetch(repo)
        if not quiet:
            print(f"{'ok  ' if ok else 'SKIP'} {repo['name']}: {msg}")
        if not ok:
            skipped[repo["name"]] = msg
    return skipped


def scan_repo(repo: dict) -> List[dict]:
    res = scan(str(checkout_path(repo)), Options(offline=True, external="none", feedback=False, cache=False,
                                                  min_severity="low", include_preview=True))
    out = [{"rule": f.rule_id, "file": f.file, "line": f.line, "fingerprint": f.fingerprint, "severity": f.severity,
            "message": f.message} for f in res.findings if f.rule_id not in NETWORK_RULES]
    return sorted(out, key=lambda x: (x["file"], x["line"], x["rule"]))


def load_labels(name: str) -> List[dict]:
    path = LABELS / f"{name}.json"
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return [x for x in data.get("findings", []) if x.get("verdict") in ("tp", "fp")]


def match(findings: List[dict], labels: List[dict]) -> Tuple[List[Tuple[dict, dict]], List[dict], List[dict]]:
    """(finding, label) pairs, findings without a label, labels whose finding is gone."""
    by_fp = {(lb["rule"], lb.get("fingerprint")): lb for lb in labels if lb.get("fingerprint")}
    by_loc = {(lb["rule"], lb["file"], lb["line"]): lb for lb in labels}
    used, pairs, unlabelled = set(), [], []
    for f in findings:
        lb = by_fp.get((f["rule"], f["fingerprint"])) or by_loc.get((f["rule"], f["file"], f["line"]))
        if lb is not None and id(lb) not in used:
            used.add(id(lb))
            pairs.append((f, lb))
        else:
            unlabelled.append(f)
    missing = [lb for lb in labels if id(lb) not in used]
    return pairs, unlabelled, missing


def seeded_recall() -> Dict[str, Dict[str, int]]:
    """Per rule: expected and found, over every sample app with expect: markers."""
    from helpers import materialize  # tests/helpers.py: fills in fake credentials at run time

    stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"expected": 0, "found": 0})
    apps = [d for base in SEEDED_DIRS if base.is_dir() for d in sorted(base.iterdir()) if d.is_dir()]
    with tempfile.TemporaryDirectory() as tmp:
        for app in apps:
            root = materialize(app.name, Path(tmp) / app.parent.name, app)
            expected = set()
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                try:
                    lines = path.read_text(encoding="utf-8").splitlines()
                except (UnicodeDecodeError, OSError):
                    continue
                rel = path.relative_to(root).as_posix()
                for n, line in enumerate(lines, 1):
                    m = MARKER.search(line)
                    if m:
                        expected.update((rel, n, r.strip()) for r in m.group(1).split(","))
            extra = (app.parent / f"{app.name}.expected")
            if extra.is_file():
                for row in extra.read_text(encoding="utf-8").splitlines():
                    row = row.strip()
                    if row and not row.startswith("#"):  # path:line:RULE, as in tests/helpers.py
                        rel, n, rule = row.rsplit(":", 2)
                        expected.add((rel, int(n), rule))
            res = scan(str(root), Options(offline=True, external="none", feedback=False, cache=False, include_preview=True))
            found = {(f.file, f.line, f.rule_id) for f in res.findings}
            for item in expected:
                stats[item[2]]["expected"] += 1
                stats[item[2]]["found"] += item in found
    return dict(stats)


def run(verbose: bool = True) -> dict:
    skipped = fetch_all(quiet=not verbose)
    per_rule: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "review": 0, "lost_tp": 0})
    by_repo: Dict[str, Dict[str, List[int]]] = defaultdict(dict)  # rule -> repo -> [tp, fp, needs review]
    repos = {}
    for repo in corpus():
        if repo["name"] in skipped:
            continue
        findings = scan_repo(repo)
        pairs, unlabelled, missing = match(findings, load_labels(repo["name"]))
        for _f, lb in pairs:
            per_rule[lb["rule"]][lb["verdict"]] += 1
            by_repo[lb["rule"]].setdefault(repo["name"], [0, 0, 0])[0 if lb["verdict"] == "tp" else 1] += 1
        for f in unlabelled:
            per_rule[f["rule"]]["review"] += 1
            by_repo[f["rule"]].setdefault(repo["name"], [0, 0, 0])[2] += 1
        lost = [lb for lb in missing if lb["verdict"] == "tp"]
        for lb in lost:
            per_rule[lb["rule"]]["lost_tp"] += 1
        repos[repo["name"]] = {"findings": len(findings), "labelled": len(pairs), "needs_review": len(unlabelled),
                               "lost_tp": [f"{lb['rule']} {lb['file']}:{lb['line']}" for lb in lost],
                               "fixed_fp": len([lb for lb in missing if lb["verdict"] == "fp"])}
    recall = seeded_recall()
    rules = {}
    for rid in sorted(RULES):
        s = per_rule.get(rid, {"tp": 0, "fp": 0, "review": 0, "lost_tp": 0})
        labelled = s["tp"] + s["fp"]
        r = recall.get(rid, {"expected": 0, "found": 0})
        rules[rid] = {
            "title": RULES[rid].title, "preview": RULES[rid].preview, "tp": s["tp"], "fp": s["fp"], "needs_review": s["review"],
            "lost_tp": s["lost_tp"],
            "precision": round(s["tp"] / labelled, 4) if labelled else None,
            # unlabelled findings counted as false positives (what the gate uses)
            "precision_pessimistic": round(s["tp"] / (labelled + s["review"]), 4) if labelled + s["review"] else None,
            "seeded_expected": r["expected"], "seeded_found": r["found"],
            "seeded_recall": round(r["found"] / r["expected"], 4) if r["expected"] else None,
            "by_repo": dict(sorted(by_repo.get(rid, {}).items())),
        }
    return {"tool": "vibeaudit benchmark", "corpus": len(corpus()), "scanned": len(repos), "skipped": skipped,
            "heldout": sorted(r["name"] for r in corpus() if r.get("split") == "heldout"),
            "repos": repos, "rules": rules}


MIN_LABELLED = 5  # fewer labelled findings than this: precision is reported as "not enough real-world data"


def _split(results: dict, rule: dict, heldout: bool) -> Tuple[int, int]:
    """(TP, FP) of one rule over the held-out repositories, or over the tuned ones."""
    names = set(results.get("heldout", []))
    rows = [v for repo, v in rule["by_repo"].items() if (repo in names) == heldout]
    return sum(v[0] for v in rows), sum(v[1] for v in rows)


def _precision(tp: int, fp: int) -> str:
    n = tp + fp
    if not n:
        return "no findings"
    return f"{tp / n:.0%} ({tp}/{n})" if n >= MIN_LABELLED else f"not enough data ({tp}/{n})"


def table(results: dict) -> str:
    rows = ["| Rule | Title | Status | Tuned precision | Held-out precision | Needs review | Seeded recall |",
            "| --- | --- | --- | --- | --- | --- | --- |"]
    for rid, r in results["rules"].items():
        tuned, held = _precision(*_split(results, r, False)), _precision(*_split(results, r, True))
        if rid in NETWORK_RULES:
            tuned = held = "network rule: not measured offline"
        rec = "n/a" if r["seeded_recall"] is None else f"{r['seeded_found']}/{r['seeded_expected']}"
        status = "preview" if r["preview"] else "stable"
        rows.append(f"| {rid} | {r['title']} | {status} | {tuned} | {held} | {r['needs_review'] or ''} | {rec} |")
    return "\n".join(rows)


def _base_precision(b: dict, scanned: set) -> Optional[float]:
    """The baseline precision over the repositories scanned now, so a repository that could not be fetched
    drops out of both sides of the comparison instead of skewing it."""
    rows = [v for repo, v in b.get("by_repo", {}).items() if repo in scanned]
    tp, fp = sum(v[0] for v in rows), sum(v[1] for v in rows)
    return tp / (tp + fp) if tp + fp else None


def check(results: dict) -> List[str]:
    """Why the gate fails (empty list: it passes)."""
    base = json.loads(BASELINE.read_text(encoding="utf-8"))
    scanned = set(results["repos"])
    problems = []
    for rid, b in base["rules"].items():
        r = results["rules"].get(rid)
        if r is None:
            problems.append(f"{rid}: rule disappeared")
            continue
        expected = _base_precision(b, scanned)
        rows = r["by_repo"].values()
        tp, other = sum(v[0] for v in rows), sum(v[1] + v[2] for v in rows)  # unlabelled count as false here
        current = tp / (tp + other) if tp + other else None
        if expected is not None and current is not None and current + 1e-9 < expected:
            problems.append(f"{rid}: precision {current:.1%} (unlabelled counted as false) is below the "
                            f"baseline {expected:.1%}; {r['needs_review']} findings need review")
        if r["lost_tp"]:
            problems.append(f"{rid}: {r['lost_tp']} labelled true positives are no longer reported")
        if b.get("seeded_recall") is not None and (r["seeded_recall"] or 0) + 1e-9 < b["seeded_recall"]:
            problems.append(f"{rid}: seeded recall {r['seeded_found']}/{r['seeded_expected']} is below the baseline "
                            f"{b['seeded_recall']:.0%}")
    return problems


def _stable_only(results: dict) -> str:
    """Stable rules are the ones that fail builds, so their precision is what a user of --fail-on sees."""
    stable = [r for r in results["rules"].values() if not r["preview"]]
    t = [sum(x) for x in zip(*(_split(results, r, False) for r in stable))]
    h = [sum(x) for x in zip(*(_split(results, r, True) for r in stable))]
    return (f"- Stable rules only (what `--fail-on` acts on): tuned {t[0] / max(1, sum(t)):.1%} ({t[0]}/{sum(t)}), "
            f"held-out {h[0] / max(1, sum(h)):.1%} ({h[0]}/{sum(h)}). Most false positives are in preview rules.")


def _without_training(results: dict) -> str:
    """Deliberately vulnerable training apps are full of true positives by design, so the precision without
    them is reported next to the overall one."""
    training = {r["name"] for r in corpus() if r.get("kind") in ("training", "known-vulnerable")}
    tp = fp = 0
    for r in results["rules"].values():
        for repo, v in r["by_repo"].items():
            if repo not in training:
                tp, fp = tp + v[0], fp + v[1]
    return (f"- Without the {len(training)} deliberately vulnerable training apps: {tp + fp} findings, {tp} true and "
            f"{fp} false ({tp / max(1, tp + fp):.1%}).")


def results_markdown(results: dict) -> str:
    rules = list(results["rules"].values())
    tuned = [sum(x) for x in zip(*(_split(results, r, False) for r in rules))]
    held = [sum(x) for x in zip(*(_split(results, r, True) for r in rules))]
    lines = [
        "# Benchmark results", "",
        "Generated by `python tools/benchmark.py baseline`; do not edit by hand. How the corpus was chosen and "
        "labelled, and how to reproduce these numbers: [README.md](README.md).", "",
        f"- Corpus: {results['scanned']} repositories pinned to exact commits ([corpus.json](corpus.json)), "
        f"{len(results['heldout'])} of them held out.",
        f"- Tuned split: {sum(tuned)} labelled findings, {tuned[0]} true and {tuned[1]} false "
        f"({tuned[0] / max(1, sum(tuned)):.1%}). Rules were fixed while looking at these findings, so this number "
        "flatters them.",
        f"- Held-out split: {sum(held)} labelled findings, {held[0]} true and {held[1]} false "
        f"({held[0] / max(1, sum(held)):.1%}). No rule is changed because of these findings; this is the number "
        "that decides whether a rule may leave preview.",
        _stable_only(results),
        _without_training(results),
        f"- Unlabelled findings: {sum(r['needs_review'] for r in rules)}.",
        f"- A precision needs at least {MIN_LABELLED} labelled findings; below that the table says `not enough data`.",
        "- Seeded recall counts the `expect:` cases in tests/fixtures and benchmark/seeded that each rule reports.", "",
        table(results), "",
    ]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("fetch")
    r = sub.add_parser("run")
    r.add_argument("--json", metavar="FILE")
    c = sub.add_parser("check")
    c.add_argument("--json", metavar="FILE")
    sub.add_parser("baseline")
    rv = sub.add_parser("review")
    rv.add_argument("name")
    a = p.parse_args(argv)
    if a.cmd == "fetch":
        skipped = fetch_all()
        print(f"{len(corpus()) - len(skipped)} of {len(corpus())} repositories available")
        return 0
    if a.cmd == "review":
        repo = next(x for x in corpus() if x["name"] == a.name)
        ok, msg = fetch(repo)
        if not ok:
            print(msg, file=sys.stderr)
            return 1
        pairs, unlabelled, missing = match(scan_repo(repo), load_labels(repo["name"]))
        print(json.dumps({"needs_review": unlabelled, "labelled_but_gone": missing}, indent=1))
        return 0
    results = run(verbose=a.cmd != "check")
    if getattr(a, "json", None):
        Path(a.json).write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    print(table(results))
    if results["skipped"]:
        print(f"\nSkipped (could not fetch, not counted): {', '.join(sorted(results['skipped']))}")
    if a.cmd == "baseline":
        if results["skipped"]:
            print("\nnot writing a baseline: some repositories could not be fetched", file=sys.stderr)
            return 1
        BASELINE.write_text(json.dumps({"rules": {
            rid: {"precision": r["precision"], "seeded_recall": r["seeded_recall"],
                  "by_repo": {repo: v[:2] for repo, v in r["by_repo"].items()}}
            for rid, r in results["rules"].items()}}, indent=1) + "\n", encoding="utf-8")
        (BENCH / "results.json").write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
        (BENCH / "RESULTS.md").write_text(results_markdown(results), encoding="utf-8", newline="\n")
        print("\nwrote benchmark/baseline.json, benchmark/results.json and benchmark/RESULTS.md")
    if a.cmd == "check":
        problems = check(results)
        if not results["scanned"]:
            print("\nNo repository could be fetched (network); the corpus part of the gate was skipped.")
        for line in problems:
            print("FAIL", line)
        if not problems:
            print(f"\nbenchmark gate passed ({results['scanned']} of {results['corpus']} repositories scanned)")
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
