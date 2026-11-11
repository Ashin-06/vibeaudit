"""Run every `vibeaudit fix` codemod over the benchmark corpus and the seeded apps, and check the result.

Each repository is copied (without .git) to a temporary folder, fixed there with `--apply`, and scanned again.
For every codemod it counts: findings fixed, findings skipped (with the reason), findings still reported after
the fix, files that no longer parse, findings introduced by the fix, and changes a second run would still make
(idempotence). The cached checkouts are never modified.

    python tools/fix_corpus.py [--json out.json] [NAME ...]
"""
from __future__ import annotations

import argparse
import ast
import json
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from benchmark import NETWORK_RULES, checkout_path, corpus  # noqa: E402
from vibeaudit import fix  # noqa: E402
from vibeaudit.files import Project  # noqa: E402
from vibeaudit.scanner import Options, scan  # noqa: E402


def options() -> Options:
    return Options(offline=True, external="none", feedback=False, cache=False, min_severity="low", include_preview=True)


def findings(root: Path):
    return [f for f in scan(str(root), options()).findings if f.rule_id not in NETWORK_RULES]


def parses(path: Path) -> bool:
    text = path.read_bytes().decode("utf-8-sig").replace("\r\n", "\n")
    if path.suffix == ".py":
        try:
            ast.parse(text)
            return True
        except SyntaxError:
            return False
    return fix.parses(fix.FileCtx(path.name, text).kind or "txt", text)


def check(name: str, src: Path, stats: dict) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / name
        shutil.copytree(src, root, ignore=shutil.ignore_patterns(".git"), symlinks=True)
        before = findings(root)
        plan = fix.plan_findings(root, before, Project(root))
        for f, reason in plan.skipped:
            if f.rule_id in fix.FIXERS:
                stats["skipped"][f.rule_id] += 1
                stats["reasons"][f"{f.rule_id}: {reason}"] += 1
        plan.apply()
        after = findings(root)
        count_before = Counter((f.rule_id, f.file) for f in before)
        count_after = Counter((f.rule_id, f.file) for f in after)
        fixed = Counter((f.rule_id, f.file) for f in plan.fixed)
        for (rule, file), n in fixed.items():
            stats["fixed"][rule] += n
            left = count_after[(rule, file)] - (count_before[(rule, file)] - n)
            if left > 0:
                stats["still_reported"][rule] += left
                stats["details"].append(f"{name}: {rule} still reported in {file}")
        for key, n in count_after.items():
            extra = n - count_before.get(key, 0)
            if extra > 0:
                stats["introduced"][key[0]] += extra
                stats["details"].append(f"{name}: {key[0]} introduced in {key[1]}")
        for c in plan.changes:
            stats["files_changed"] += 1
            if not parses(root / c.file):
                stats["broken_files"] += 1
                stats["details"].append(f"{name}: {c.file} no longer parses")
        again = fix.plan_findings(root, after, Project(root))
        for c in again.changes:
            for f in c.fixed:
                if (f.rule_id, f.file) in fixed:
                    stats["not_idempotent"][f.rule_id] += 1
                    stats["details"].append(f"{name}: second run changes {f.rule_id} in {f.file} again")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("names", nargs="*")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    stats = {k: Counter() for k in ("fixed", "skipped", "still_reported", "introduced", "not_idempotent", "reasons")}
    stats.update(files_changed=0, broken_files=0, details=[])
    targets = [(r["name"], checkout_path(r)) for r in corpus()]
    targets += [(p.name, p) for p in sorted((ROOT / "benchmark" / "seeded").iterdir()) if p.is_dir()]
    targets += [(p.name, p) for p in sorted((ROOT / "tests" / "fixtures").iterdir()) if p.is_dir()]
    for name, path in targets:
        if a.names and name not in a.names:
            continue
        if not path.is_dir():
            print(f"missing {name}: run tools/benchmark.py fetch", file=sys.stderr)
            continue
        check(name, path, stats)
        print(f"{name}: fixed {sum(stats['fixed'].values())} so far", file=sys.stderr, flush=True)
    print(f"{'rule':8} {'fixed':>6} {'skipped':>8} {'left':>5} {'new':>4} {'twice':>6}")
    for rule in sorted(fix.FIXERS):
        print(f"{rule:8} {stats['fixed'][rule]:6} {stats['skipped'][rule]:8} {stats['still_reported'][rule]:5} "
              f"{stats['introduced'][rule]:4} {stats['not_idempotent'][rule]:6}")
    print(f"files changed: {stats['files_changed']}, no longer parse: {stats['broken_files']}, "
          f"findings introduced: {sum(stats['introduced'].values())}")
    for reason, n in stats["reasons"].most_common():
        print(f"  skipped {n:4}  {reason}")
    for d in stats["details"]:
        print("  " + d)
    if a.json:
        Path(a.json).write_text(json.dumps(stats, indent=2, default=dict), encoding="utf-8")
    bad = stats["broken_files"] or sum(stats["still_reported"].values()) or sum(stats["introduced"].values()) \
        or sum(stats["not_idempotent"].values())
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
