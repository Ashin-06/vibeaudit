"""Report renderers: terminal text, JSON, SARIF 2.1.0, Markdown and a self-contained HTML page."""
from __future__ import annotations

import html
import json
import os
import sys
from collections import Counter
from typing import Dict, List

from . import __version__
from .model import SEVERITIES, Finding
from .rules import CATEGORIES, RULES, SECURITY_SEVERITY

TOOL_URL = "https://github.com/Ashin-06/vibeaudit"


class Result:
    def __init__(self, root: str, findings: List[Finding], meta: Dict):
        self.root = root
        self.findings = findings
        self.meta = meta

    @property
    def counts(self) -> Dict[str, int]:
        c = Counter(f.severity for f in self.findings)
        return {s: c.get(s, 0) for s in SEVERITIES}

    @property
    def score(self) -> int:
        weights = {"critical": 25, "high": 10, "medium": 3, "low": 1, "info": 0}
        return max(0, 100 - sum(weights[f.severity] for f in self.findings))

    @property
    def grade(self) -> str:
        c = self.counts
        if c["critical"]:
            return "F"
        s = self.score
        return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"


def _cat(c: str) -> str:
    return CATEGORIES.get(c, c)


# ------------------------------------------------------------------- text
def render_text(res: Result, color: bool, verbose: bool = True) -> str:
    def paint(s: str, code: str) -> str:
        return f"\033[{code}m{s}\033[0m" if color else s

    colors = {"critical": "1;37;41", "high": "1;31", "medium": "33", "low": "36", "info": "2"}
    out = []
    out.append(paint(f"vibeaudit {__version__}", "1") + f"  scanned {res.meta.get('files_scanned', 0)} files in {res.root}")
    stack = res.meta.get("stack") or []
    if stack:
        out.append("Stack: " + ", ".join(stack))
    out.append("")
    for f in res.findings:
        tag = paint(f"[{f.severity.upper()}]", colors[f.severity])
        loc = f"{f.file}:{f.line}" if f.line else f.file
        out.append(f"{tag} {f.rule_id} {f.title}")
        out.append(f"  {loc}  {f.message}")
        if verbose:
            if f.snippet:
                out.append(f"    > {f.snippet[:160]}")
            if f.why:
                out.append(f"  Why: {f.why}")
            if f.fix:
                out.append(f"  Fix: {f.fix}")
            if f.llm_verdict:
                out.append(f"  LLM triage: {f.llm_verdict} - {f.llm_reason}")
        out.append("")
    c = res.counts
    out.append(paint("Summary", "1"))
    out.append("  " + "  ".join(f"{s}: {c[s]}" for s in SEVERITIES if s != "info") + f"   total: {len(res.findings)}")
    by_cat = Counter(f.category for f in res.findings)
    for cat, n in by_cat.most_common():
        out.append(f"  {_cat(cat)}: {n}")
    out.append(f"  Score: {res.score}/100  Grade: {res.grade}")
    for note in res.meta.get("notes", []):
        out.append(f"  Note: {note}")
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------- json
def render_json(res: Result) -> str:
    return json.dumps({
        "tool": "vibeaudit", "version": __version__, "root": res.root,
        "summary": {"counts": res.counts, "total": len(res.findings), "score": res.score, "grade": res.grade},
        "meta": res.meta, "findings": [f.to_dict() for f in res.findings],
    }, indent=2) + "\n"


# ------------------------------------------------------------------ sarif
def render_sarif(res: Result) -> str:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rule_ids = sorted({f.rule_id for f in res.findings})
    index = {r: i for i, r in enumerate(rule_ids)}
    rules = []
    for rid in rule_ids:
        sample = next(f for f in res.findings if f.rule_id == rid)
        meta = RULES.get(rid)
        sev = meta.severity if meta else sample.severity
        tags = ["security", sample.category] + [t for t in (sample.cwe, sample.owasp) if t]
        rules.append({
            "id": rid, "name": rid.replace(":", "_"),
            "shortDescription": {"text": sample.title or rid},
            "fullDescription": {"text": sample.why or sample.title or rid},
            "help": {"text": sample.fix or "", "markdown": f"**Why:** {sample.why}\n\n**Fix:** {sample.fix}"},
            "defaultConfiguration": {"level": level[sev]},
            "properties": {"tags": tags, "security-severity": SECURITY_SEVERITY[sev], "precision": "medium"},
        })
    results = []
    for f in res.findings:
        results.append({
            "ruleId": f.rule_id, "ruleIndex": index[f.rule_id], "level": level[f.severity],
            "message": {"text": f.message + (f" Fix: {f.fix}" if f.fix else "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(1, f.line)}}}],
            "partialFingerprints": {"vibeaudit/v1": f.fingerprint},
            "properties": {"severity": f.severity, "security-severity": SECURITY_SEVERITY[f.severity],
                           "category": f.category, "source": f.source},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "vibeaudit", "version": __version__, "informationUri": TOOL_URL,
                                      "rules": rules}},
                  "automationDetails": {"id": "vibeaudit/"}, "results": results}],
    }
    return json.dumps(doc, indent=2) + "\n"


# --------------------------------------------------------------- markdown
def _md(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def render_markdown(res: Result) -> str:
    c = res.counts
    out = [f"# vibeaudit report", "", f"Scanned `{res.root}` ({res.meta.get('files_scanned', 0)} files) with vibeaudit {__version__}.", ""]
    if res.meta.get("stack"):
        out += [f"Stack: {', '.join(res.meta['stack'])}", ""]
    out += [f"**Score: {res.score}/100 (grade {res.grade})**", "", "| Severity | Count |", "| --- | --- |"]
    out += [f"| {s} | {c[s]} |" for s in SEVERITIES if s != "info"]
    out += ["", "| Category | Count |", "| --- | --- |"]
    out += [f"| {_cat(k)} | {v} |" for k, v in Counter(f.category for f in res.findings).most_common()]
    for note in res.meta.get("notes", []):
        out += ["", f"> Note: {note}"]
    out += ["", "## Findings", ""]
    if not res.findings:
        out.append("No findings.")
    for f in res.findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        out += [f"### [{f.severity.upper()}] {f.rule_id} {_md(f.title)}", "", f"`{loc}` - {_md(f.message)}", ""]
        if f.snippet:
            out += ["```", f.snippet.replace("```", "'''"), "```", ""]
        out += [f"- **Why it matters:** {_md(f.why)}", f"- **Fix:** {_md(f.fix)}"]
        refs = ", ".join(x for x in (f.cwe, f.owasp) if x)
        if refs:
            out.append(f"- **References:** {refs}")
        if f.llm_verdict:
            out.append(f"- **LLM triage:** {f.llm_verdict} - {_md(f.llm_reason or '')}")
        out.append("")
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------- html
CSS = """
:root{--bg:#ffffff;--fg:#1d2330;--muted:#5b6475;--card:#f5f7fa;--line:#dde2ea;--crit:#b3001b;--high:#d9480f;
--med:#b07d00;--low:#1971c2;--info:#868e96;--code:#eef1f5}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#11151c;--fg:#e6e9ef;--muted:#9aa3b2;
--card:#1a2029;--line:#2c3440;--crit:#ff6b6b;--high:#ff922b;--med:#fcc419;--low:#74c0fc;--info:#adb5bd;--code:#0c1016}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,
"Segoe UI",Roboto,sans-serif}main{max-width:1000px;margin:0 auto;padding:24px 16px 64px}h1{margin:0 0 4px;font-size:24px}
.muted{color:var(--muted)}.tiles{display:flex;flex-wrap:wrap;gap:12px;margin:20px 0}.tile{background:var(--card);
border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:110px}.tile b{display:block;font-size:22px}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}.filters button{border:1px solid var(--line);
background:var(--card);color:var(--fg);border-radius:999px;padding:4px 12px;cursor:pointer;font:inherit}
.filters button[aria-pressed="true"]{outline:2px solid var(--low)}.f{background:var(--card);border:1px solid var(--line);
border-left:5px solid var(--info);border-radius:8px;padding:12px 14px;margin:10px 0}.f.critical{border-left-color:var(--crit)}
.f.high{border-left-color:var(--high)}.f.medium{border-left-color:var(--med)}.f.low{border-left-color:var(--low)}
.sev{font-weight:700;text-transform:uppercase;font-size:12px}.critical .sev{color:var(--crit)}.high .sev{color:var(--high)}
.medium .sev{color:var(--med)}.low .sev{color:var(--low)}.loc{font-family:ui-monospace,Consolas,monospace;font-size:13px;
word-break:break-all}pre{background:var(--code);padding:8px 10px;border-radius:6px;overflow-x:auto;font-size:13px;margin:8px 0}
dt{font-weight:600;margin-top:6px}dd{margin:0 0 0 0}
"""
JS = """
document.querySelectorAll('.filters button').forEach(function(b){b.addEventListener('click',function(){
var s=b.getAttribute('data-sev');document.querySelectorAll('.filters button').forEach(function(x){
x.setAttribute('aria-pressed',x===b?'true':'false')});document.querySelectorAll('.f').forEach(function(f){
f.hidden=!(s==='all'||f.classList.contains(s))})})});
"""


def render_html(res: Result) -> str:
    e = html.escape
    c = res.counts
    parts = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'\">",
        f"<title>vibeaudit report</title><style>{CSS}</style></head><body><main>",
        "<h1>vibeaudit report</h1>",
        f"<div class=\"muted\">{e(res.root)} - {res.meta.get('files_scanned', 0)} files - vibeaudit {e(__version__)}</div>",
    ]
    if res.meta.get("stack"):
        parts.append(f"<div class=\"muted\">Stack: {e(', '.join(res.meta['stack']))}</div>")
    parts.append("<div class=\"tiles\">")
    parts.append(f"<div class=\"tile\"><span class=\"muted\">Score</span><b>{res.score}/100</b>Grade {e(res.grade)}</div>")
    for s in SEVERITIES[:4]:
        parts.append(f"<div class=\"tile\"><span class=\"muted\">{s.title()}</span><b>{c[s]}</b></div>")
    parts.append("</div>")
    for note in res.meta.get("notes", []):
        parts.append(f"<p class=\"muted\">Note: {e(note)}</p>")
    parts.append("<div class=\"filters\" role=\"group\" aria-label=\"Filter by severity\">"
                 "<button data-sev=\"all\" aria-pressed=\"true\">All</button>"
                 + "".join(f"<button data-sev=\"{s}\" aria-pressed=\"false\">{s.title()}</button>" for s in SEVERITIES[:4])
                 + "</div>")
    if not res.findings:
        parts.append("<p>No findings.</p>")
    for f in res.findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        parts.append(f"<section class=\"f {e(f.severity)}\"><div><span class=\"sev\">{e(f.severity)}</span> "
                     f"<b>{e(f.rule_id)}</b> {e(f.title)} <span class=\"muted\">({e(_cat(f.category))})</span></div>")
        parts.append(f"<div class=\"loc\">{e(loc)}</div><div>{e(f.message)}</div>")
        if f.snippet:
            parts.append(f"<pre>{e(f.snippet)}</pre>")
        parts.append(f"<dl><dt>Why it matters</dt><dd>{e(f.why)}</dd><dt>Fix</dt><dd>{e(f.fix)}</dd>")
        refs = ", ".join(x for x in (f.cwe, f.owasp) if x)
        if refs:
            parts.append(f"<dt>References</dt><dd>{e(refs)}</dd>")
        if f.llm_verdict:
            parts.append(f"<dt>LLM triage</dt><dd>{e(f.llm_verdict)} - {e(f.llm_reason or '')}</dd>")
        parts.append("</dl></section>")
    parts.append(f"</main><script>{JS}</script></body></html>")
    return "\n".join(parts) + "\n"


RENDERERS = {"json": render_json, "sarif": render_sarif, "md": render_markdown, "markdown": render_markdown,
             "html": render_html}
EXTENSIONS = {"json": "json", "sarif": "sarif", "md": "md", "markdown": "md", "html": "html"}


def write_report(res: Result, fmt: str, path: str) -> None:
    text = RENDERERS[fmt](res)
    if path == "-":
        sys.stdout.write(text)
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
