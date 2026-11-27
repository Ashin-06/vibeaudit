"""Per-project feedback: findings a person has reviewed, stored in `.vibeaudit/feedback.json` so the team shares
it through version control. Findings marked as false positives are hidden from later scans; confirmed ones
are kept. Entries are matched by fingerprint (rule, file and line text), so they survive line moves."""
from __future__ import annotations

import datetime as dt
import difflib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .store import read_json, write_json

FILE = Path(".vibeaudit") / "feedback.json"
VERDICTS = ("false-positive", "confirmed")
DEMOTE_MIN_VERDICTS = 3
DEMOTE_FP_RATE = 0.30

_HELPER_SKIP = {
    "app", "async", "await", "bool", "catch", "class", "const", "ctx", "def", "delete", "dict", "elif", "else",
    "err", "error", "except", "export", "false", "filter", "finally", "for", "from", "func", "function", "get",
    "group", "handler", "import", "int", "json", "len", "let", "list", "log", "map", "match", "mount", "new",
    "next", "none", "null", "params", "patch", "post", "print", "public", "put", "query", "req", "request",
    "res", "response", "return", "route", "router", "select", "self", "send", "set", "status", "str", "super",
    "switch", "this", "throw", "true", "try", "update", "use", "var", "void", "while", "with", "yield",
}
_HELPER_HINT = re.compile(r"(?i)(?:auth|user|session|token|jwt|verify|check|require|ensure|guard|protect|perm|role|admin|login|tenant|api_?key)")


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


def noisy_rules(root: Path, min_verdicts: int = DEMOTE_MIN_VERDICTS, threshold: float = DEMOTE_FP_RATE) -> Dict[str, Tuple[int, int, float]]:
    """Rules whose false-positive share exceeds `threshold` across at least `min_verdicts` reviewed findings."""
    out: Dict[str, Tuple[int, int, float]] = {}
    for rule, counts in summary(root).items():
        fp = counts.get("false-positive", 0)
        total = fp + counts.get("confirmed", 0)
        if total >= min_verdicts and total > 0 and (fp / total) > threshold:
            out[rule] = (fp, total, fp / total)
    return out


def _safe_ident(raw: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", raw).strip("_").lower() or "case"


def export_tests(root: Path) -> str:
    """Render `.vibeaudit/feedback.json` verdicts as a standalone ASCII pytest regression file."""
    entries = load(root)
    if not entries:
        return ""
    lines = [
        '"""Generated by `vibeaudit feedback export` from .vibeaudit/feedback.json."""',
        "from __future__ import annotations",
        "",
        "from pathlib import Path",
        "",
        "from vibeaudit.config import project_options",
        "from vibeaudit.scanner import scan",
        "",
        "ROOT = Path(__file__).resolve().parent",
        "",
    ]
    used_names: Set[str] = set()
    for i, e in enumerate(entries, 1):
        rule = str(e.get("rule", "RULE")).upper()
        file_rel = str(e.get("file", ""))
        line = int(e.get("line") or 0)
        verdict = str(e.get("verdict", ""))
        fp = str(e.get("fingerprint", ""))
        base = f"test_{_safe_ident(rule)}_{_safe_ident(file_rel)}_{line}"
        fn_name = base if base not in used_names else f"{base}_{i}"
        used_names.add(fn_name)
        lines.append(f"def {fn_name}():")
        note = str(e.get("note", "")).replace('"', "'")
        if note:
            lines.append(f'    # {verdict}: {note}')
        if verdict == "confirmed":
            lines.append('    opts = project_options(str(ROOT), offline=True, external="none", feedback=False, include_preview=True)')
            lines.append("    res = scan(str(ROOT), opts)")
            lines.append("    hits = [(f.rule_id, f.file) for f in res.findings]")
            lines.append(f'    assert ({rule!r}, {file_rel!r}) in hits')
        else:
            lines.append("    # Keeps this false positive suppressed via .vibeaudit/feedback.json until the rule handles the pattern.")
            lines.append('    opts = project_options(str(ROOT), offline=True, external="none", feedback=True, include_preview=True)')
            lines.append("    res = scan(str(ROOT), opts)")
            lines.append(f'    assert {fp!r} not in {{f.fingerprint for f in res.findings}}')
        lines.append("")
    return "\n".join(lines).encode("ascii", "replace").decode("ascii")


def suggest_auth_helpers(root: Path, config: Optional[str] = None) -> Dict[str, Any]:
    """Infer candidate `auth-helpers` from auth findings marked false-positive and propose a `.vibeaudit.toml` diff."""
    from .config import project_options
    from .scanner import scan

    entries = [e for e in load(root) if e.get("verdict") == "false-positive"
               and str(e.get("rule", "")).upper() in ("AUTH001", "AUTH002", "AUTH003", "AUTH004", "AUTH017")]
    if not entries:
        return {"candidates": [], "diff": ""}

    opts = project_options(str(root), config, offline=True, external="none", feedback=False)
    res = scan(str(root), opts)
    existing = set(opts.auth_helpers)
    routes_by_file: Dict[str, list] = {}
    for r in res.routes:
        routes_by_file.setdefault(r.file, []).append(r)

    counts: Dict[str, int] = {}
    locs: Dict[str, List[str]] = {}
    for e in entries:
        rel, ln = str(e.get("file", "")), int(e.get("line") or 0)
        candidates_in_file = routes_by_file.get(rel, [])
        route = next((r for r in candidates_in_file if r.line == ln), None)
        if route is None and candidates_in_file:
            route = min(candidates_in_file, key=lambda r: abs(r.line - ln))
        if route is None:
            continue
        names = set(re.findall(r"(?:@|\b)([A-Za-z_][A-Za-z0-9_]{2,50})\s*\(", route.body))
        for nm in names:
            if nm.lower() in _HELPER_SKIP or nm in existing or not _HELPER_HINT.search(nm):
                continue
            counts[nm] = counts.get(nm, 0) + 1
            locs.setdefault(nm, [])
            tag = f"{rel}:{route.line}"
            if tag not in locs[nm]:
                locs[nm].append(tag)

    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    if not ranked:
        return {"candidates": [], "diff": ""}

    new_names = [nm for nm, _c in ranked]
    merged = list(opts.auth_helpers) + [nm for nm in new_names if nm not in existing]
    toml_path = Path(root) / ".vibeaudit.toml"
    before = toml_path.read_text(encoding="utf-8") if toml_path.is_file() else ""
    line_val = "auth-helpers = [" + ", ".join(f'"{x}"' for x in merged) + "]"
    if re.search(r"(?m)^[ \t]*auth-helpers\s*=", before):
        after = re.sub(r"(?m)^[ \t]*auth-helpers\s*=[^\n]*", line_val, before, count=1)
    else:
        after = (before.rstrip("\n") + "\n" if before else "") + line_val + "\n"
    diff = "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile="a/.vibeaudit.toml", tofile="b/.vibeaudit.toml",
    ))
    return {
        "candidates": [{"name": nm, "count": cnt, "locations": locs[nm]} for nm, cnt in ranked],
        "diff": diff,
    }
