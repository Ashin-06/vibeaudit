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


def relative_path(root: Path, file: str) -> str:
    """A path as reports show it (relative to the project, forward slashes), from whatever an editor or a
    shell gives: absolute paths, backslashes, a leading ./"""
    candidate = Path(file)
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(Path(root).resolve()).as_posix()
        except ValueError:
            pass  # outside the project: keep it as given, so the lookup reports "no finding"
    out = file.replace("\\", "/")
    while out.startswith("./"):
        out = out[2:]
    return out


def record(root: Path, rule: str, file: str, line: int, verdict: str, note: str = "",
           config: Optional[str] = None) -> Optional[Dict]:
    """Find the current finding `rule` at `file:line` and record a verdict for it. None if there is no such
    finding. Built-in rules and loaded plugin rules can be marked; third-party tools are not run."""
    from .config import project_options
    from .scanner import scan

    # The project's settings apply, so only findings the scan really reports can be marked. Dependency
    # findings (DEP001, DEP003, DEP004) need the registry and OSV, so those use the network (and its cache)
    # unless the configuration says offline. feedback=False so that a verdict can be changed later.
    opts = project_options(str(root), config, external="none", feedback=False)
    opts.offline = opts.offline or not rule.upper().startswith("DEP")
    res = scan(str(root), opts)
    file = relative_path(root, file)
    match =next((f for f in res.findings if f.rule_id == rule.upper() and f.file == file and f.line == line), None)
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
