"""Real-world regression harness against pinned public applications.

    python tools/realworld_regression.py --check
    python tools/realworld_regression.py --fetch --check --json realworld-results.json
    python tools/realworld_regression.py --compare

Verifies must-detect vulnerabilities, must-not-flag false positives, and high/critical budgets
across real repositories (DVWA, DVNA, NodeGoat, Vulnerable-Flask-App, Vulpy, Flask, Starlette,
Express, full-stack-fastapi-template).
"""
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
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from vibeaudit import external  # noqa: E402
from vibeaudit.scanner import Options, scan  # noqa: E402

MANIFEST = ROOT / "benchmark" / "realworld_manifest.json"


def default_cache_dir() -> Path:
    return Path(os.environ.get("VIBEAUDIT_BENCH_DIR") or Path.home() / ".cache" / "vibeaudit-bench")


def checkout_path(repo: Dict[str, Any], cache_dir: Path) -> Path:
    return cache_dir / f"{repo['name']}-{repo['commit'][:12]}"


def _git(*args: str, cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
    git_exe = shutil.which("git") or "git"
    return subprocess.run(  # noqa: S603 - fixed git executable for pinned commit checkouts
        [git_exe, "-c", "core.autocrlf=false", "-c", "core.symlinks=false", *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=300,
    )


def fetch_repo(repo: Dict[str, Any], cache_dir: Path, attempts: int = 2) -> Tuple[bool, str]:
    target = checkout_path(repo, cache_dir)
    if (target / ".bench-ok").is_file() or target.is_dir():
        return True, "cached"
    cache_dir.mkdir(parents=True, exist_ok=True)
    for attempt in range(1, attempts + 1):
        tmp = Path(tempfile.mkdtemp(prefix=repo["name"] + "-", dir=str(cache_dir)))
        try:
            for step in (
                ("init", "-q"),
                ("remote", "add", "origin", repo["url"]),
                ("fetch", "-q", "--depth", "1", "origin", repo["commit"]),
                ("checkout", "-q", "FETCH_HEAD"),
            ):
                out = _git(*step, cwd=tmp)
                if out.returncode != 0:
                    raise RuntimeError(out.stderr.strip()[-200:] or "git failed")
            head = _git("rev-parse", "HEAD", cwd=tmp).stdout.strip()
            if head != repo["commit"]:
                raise RuntimeError(f"checked out {head}, expected {repo['commit']}")
            (tmp / ".bench-ok").write_text(head, encoding="utf-8")
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
            tmp.rename(target)
            return True, "fetched"
        except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
            shutil.rmtree(tmp, ignore_errors=True)
            if attempt == attempts:
                return False, str(exc)
            time.sleep(2 * attempt)
    return False, "unreachable"


def _matches(finding: Any, spec: Dict[str, Any]) -> bool:
    if finding.rule_id != spec["rule"]:
        return False
    file_pat = spec.get("file")
    if file_pat and finding.file != file_pat:
        return False
    file_prefix = spec.get("file_prefix")
    if file_prefix and not finding.file.startswith(file_prefix):
        return False
    line = spec.get("line")
    if line is not None and finding.line != line:
        return False
    return True


def evaluate_repo(repo: Dict[str, Any], path: Path, compare: bool = False) -> Dict[str, Any]:
    res = scan(
        str(path),
        Options(offline=True, external="none", feedback=False, cache=False, min_severity="low", include_preview=True),
    )
    failures: List[str] = []
    must_detect = repo.get("must_detect", [])
    detected = 0
    for spec in must_detect:
        if any(_matches(f, spec) for f in res.findings):
            detected += 1
        else:
            failures.append(
                f"missed {spec['rule']} at {spec.get('file') or spec.get('file_prefix', '*')}:{spec.get('line', '*')}"
            )
    for spec in repo.get("must_not_flag", []):
        hits = [f for f in res.findings if _matches(f, spec)]
        if hits:
            failures.append(
                f"false positive {spec['rule']} at {spec.get('file') or spec.get('file_prefix', '*')}"
                f" ({len(hits)} hit(s))"
            )
    high_crit = sum(1 for f in res.gating if f.severity in ("high", "critical"))
    max_hc = repo.get("max_high_or_critical")
    if max_hc is not None and high_crit > max_hc:
        failures.append(f"gating high+critical {high_crit} exceeds cap {max_hc}")

    entry: Dict[str, Any] = {
        "name": repo["name"],
        "kind": repo["kind"],
        "findings": len(res.findings),
        "gating_high_or_critical": high_crit,
        "score": res.score,
        "grade": res.grade,
        "must_detect_hit": detected,
        "must_detect_total": len(must_detect),
        "recall": round(detected / len(must_detect), 4) if must_detect else None,
        "duration_seconds": res.meta.get("duration_seconds"),
        "failures": failures,
        "passed": not failures,
    }
    if compare:
        comp: Dict[str, Any] = {}
        for tool in ("bandit", "semgrep"):
            if external.available(tool):
                ext = external.run_tool(tool, path, no_config=True) or []
                comp[tool] = len(ext)
        entry["external_counts"] = comp
    return entry


def load_manifest(path: Path = MANIFEST) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return list(data.get("repos", []))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Real-world repository regression and recall suite.")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--cache-dir", type=Path, default=default_cache_dir())
    parser.add_argument("--fetch", action="store_true", help="clone/fetch missing pinned repositories")
    parser.add_argument("--check", action="store_true", help="exit 1 if any assertion fails")
    parser.add_argument("--compare", action="store_true", help="also count installed bandit/semgrep findings")
    parser.add_argument("--json", type=Path, default=None, help="write JSON results to file")
    args = parser.parse_args(argv)

    repos = load_manifest(args.manifest)
    results: List[Dict[str, Any]] = []
    skipped: List[str] = []
    for repo in repos:
        if args.fetch:
            ok, msg = fetch_repo(repo, args.cache_dir)
            if not ok:
                skipped.append(f"{repo['name']} ({msg})")
                continue
        path = checkout_path(repo, args.cache_dir)
        if not path.is_dir():
            skipped.append(f"{repo['name']} (not cached)")
            continue
        results.append(evaluate_repo(repo, path, compare=args.compare))

    print(f"{'Repository':30} {'Kind':16} {'Score':7} {'Findings':8} {'High/Crit':9} {'Recall':9} Status")
    print("-" * 92)
    for r in results:
        rec = f"{r['must_detect_hit']}/{r['must_detect_total']}" if r["must_detect_total"] else "-"
        sc = f"{r['score']}/{r['grade']}" if r["score"] is not None else "N/A"
        status = "PASS" if r["passed"] else "FAIL: " + "; ".join(r["failures"])
        print(f"{r['name']:30} {r['kind']:16} {sc:7} {r['findings']:8} {r['gating_high_or_critical']:9} {rec:9} {status}")
    if skipped:
        print(f"\nSkipped ({len(skipped)}): {', '.join(skipped)}")

    payload = {"repos": results, "skipped": skipped, "passed": all(r["passed"] for r in results) and len(results) > 0}
    if args.json is not None:
        args.json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if args.check:
        if not results:
            print("error: no repositories evaluated", file=sys.stderr)
            return 1
        if any(not r["passed"] for r in results):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
