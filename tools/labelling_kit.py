"""Second-labeller kit: a blind, stratified sample of labelled findings, and agreement with the maintainers' labels.

    python tools/labelling_kit.py sample              # writes benchmark/second-label/sample.json (no verdicts, no code)
    python tools/labelling_kit.py show                # prints each item with its code, from your checkout
    python tools/labelling_kit.py kappa ANSWERS.json  # Cohen's kappa between ANSWERS and the maintainers' labels

`show` needs the corpus checked out (python tools/benchmark.py fetch). Answers are a JSON object
{"<id>": "tp" | "fp", ...} keyed by the ids in sample.json. See docs/LABELLING.md.
"""
from __future__ import annotations

import json
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests"), str(ROOT / "tools")]
import benchmark as B  # noqa: E402

OUT = ROOT / "benchmark" / "second-label"
SIZE = 150
SEED = 1509
CONTEXT = 6


def _labels() -> List[dict]:
    out = []
    for repo in B.corpus():
        for lb in B.load_labels(repo["name"]):
            out.append(dict(lb, repo=repo["name"]))
    return out


def sample() -> int:
    """No code goes into the committed sample: the corpus is third-party code, and secret findings would carry
    the secret. `show` prints the code from the labeller's own checkout."""
    from vibeaudit.rules import RULES

    labels = _labels()
    by_cat: Dict[str, List[dict]] = defaultdict(list)
    for lb in labels:
        by_cat[getattr(RULES.get(lb["rule"]), "category", "other")].append(lb)
    rnd = random.Random(SEED)
    picked: List[dict] = []
    # proportional to each category's share, at least 3 per category, so rare categories are represented
    for _cat, items in sorted(by_cat.items()):
        n = max(3, round(SIZE * len(items) / len(labels)))
        picked += rnd.sample(items, min(n, len(items)))
    rnd.shuffle(picked)
    picked = picked[:SIZE]
    repos = {r["name"]: r for r in B.corpus()}
    items, key = [], {}
    for i, lb in enumerate(picked, 1):
        sid = f"S{i:03d}"
        rule = RULES.get(lb["rule"])
        repo = repos[lb["repo"]]
        items.append({"id": sid, "repo": repo["url"], "commit": repo["commit"], "file": lb["file"], "line": lb["line"],
                      "rule": lb["rule"], "title": getattr(rule, "title", ""), "why": getattr(rule, "why", "")})
        key[sid] = {"repo": lb["repo"], "rule": lb["rule"], "file": lb["file"], "line": lb["line"]}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "sample.json").write_text(json.dumps({"seed": SEED, "items": items}, indent=1) + "\n", encoding="utf-8")
    (OUT / "key.json").write_text(json.dumps(key, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {len(items)} findings to {OUT / 'sample.json'}")
    return 0


def show() -> int:
    items = json.loads((OUT / "sample.json").read_text(encoding="utf-8"))["items"]
    key = json.loads((OUT / "key.json").read_text(encoding="utf-8"))
    repos = {r["name"]: r for r in B.corpus()}
    for it in items:
        path = B.checkout_path(repos[key[it["id"]]["repo"]]) / it["file"]
        print(f"=== {it['id']}  {it['rule']} {it['title']}")
        print(f"    {it['repo']} @ {it['commit'][:12]}  {it['file']}:{it['line']}")
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            print("    (not checked out: run python tools/benchmark.py fetch)")
            continue
        for n in range(max(0, it["line"] - CONTEXT - 1), min(len(lines), it["line"] + CONTEXT)):
            print(f"{'>' if n + 1 == it['line'] else ' '}{n + 1:5}  {lines[n][:160]}")
    return 0


def kappa(answers_path: str) -> int:
    answers = json.loads(Path(answers_path).read_text(encoding="utf-8"))
    key = json.loads((OUT / "key.json").read_text(encoding="utf-8"))
    truth = {(lb["repo"], lb["rule"], lb["file"], lb["line"]): lb["verdict"] for lb in _labels()}
    pairs = []
    for sid, verdict in answers.items():
        k = key.get(sid)
        if k and verdict in ("tp", "fp"):
            mine = truth.get((k["repo"], k["rule"], k["file"], k["line"]))
            if mine:
                pairs.append((sid, mine, verdict))
    if not pairs:
        print("no comparable answers")
        return 1
    n = len(pairs)
    agree = sum(a == b for _, a, b in pairs) / n
    expected = sum((sum(a == v for _, a, _b in pairs) / n) * (sum(b == v for _, _a, b in pairs) / n) for v in ("tp", "fp"))
    k = (agree - expected) / (1 - expected) if expected < 1 else 1.0
    print(f"{n} findings compared: raw agreement {agree:.1%}, Cohen's kappa {k:.2f}")
    print(f"maintainers tp/fp: {sum(a == 'tp' for _, a, _b in pairs)}/{sum(a == 'fp' for _, a, _b in pairs)}; "
          f"second labeller tp/fp: {sum(b == 'tp' for _, _a, b in pairs)}/{sum(b == 'fp' for _, _a, b in pairs)}")
    print("disagreements: " + (", ".join(sid for sid, a, b in pairs if a != b) or "none"))
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "sample":
        sys.exit(sample())
    if len(sys.argv) >= 2 and sys.argv[1] == "show":
        sys.exit(show())
    if len(sys.argv) >= 3 and sys.argv[1] == "kappa":
        sys.exit(kappa(sys.argv[2]))
    print(__doc__)
    sys.exit(2)
