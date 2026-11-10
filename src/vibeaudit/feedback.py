"""Per-project feedback: findings a person has reviewed, stored in `.vibeaudit/feedback.json` so the team shares
it through version control. Findings marked as false positives are hidden from later scans; confirmed ones
are kept. Entries are matched by fingerprint (rule, file and line text), so they survive line moves."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Dict, List, Optional, Set

from .store import read_json, write_json

FILE = Path(".vibeaudit") / "feedback.json"
VERDICTS = ("false-positive", "confirmed")


def load(root: Path) -> List[Dict]:
    data = read_json(Path(root) / FILE)
    entries = data.get("entries") if isinstance(data, dict) else None
    return [e for e in entries if isinstance(e, dict) and isinstance(e.get("fingerprint"), str)
            and e.get("verdict") in VERDICTS] if isinstance(entries, list) else []


def false_positives(root: Path) -> Set[str]:
    return {e["fingerprint"] for e in load(root) if e["verdict"] == "false-positive"}


def record(root: Path, rule: str, file: str, line: int, verdict: str, note: str = "") -> Optional[Dict]:
    """Find the current finding `rule` at `file:line` and record a verdict for it. None if there is no such
    finding (the scan is offline and skips third-party tools, so only built-in rules can be marked)."""
    from .scanner import Options, scan

    res = scan(str(root), Options(offline=True, external="none", feedback=False))  # a verdict can be changed later
    file = file.replace("\\", "/")
    while file.startswith("./"):
        file = file[2:]
    match = next((f for f in res.findings if f.rule_id == rule.upper() and f.file == file and f.line == line), None)
    if match is None:
        return None
    entry = {"fingerprint": match.fingerprint, "rule": match.rule_id, "file": match.file, "line": match.line,
             "verdict": verdict, "note": note, "date": dt.date.today().isoformat(), "message": match.message}
    entries = [e for e in load(root) if e["fingerprint"] != match.fingerprint] + [entry]
    write_json(Path(root) / FILE, {"version": 1, "entries": entries})
    return entry


def summary(root: Path) -> Dict[str, Dict[str, int]]:
    """Per rule: how many findings were marked false positive and how many confirmed."""
    out: Dict[str, Dict[str, int]] = {}
    for e in load(root):
        counts = out.setdefault(str(e.get("rule", "?")), {v: 0 for v in VERDICTS})
        counts[e["verdict"]] += 1
    return dict(sorted(out.items()))
