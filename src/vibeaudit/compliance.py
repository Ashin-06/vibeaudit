"""Compliance mapping: the framework controls each rule's findings are evidence for (data/compliance_map.json),
and the `--report compliance:<framework>` page.

The mapping is an aid for reviewers, not a certification, an audit result or legal advice: a control without
findings is not thereby met, and most controls need evidence that code scanning cannot provide.
"""
from __future__ import annotations

import datetime as dt
import html
import json
from importlib import resources
from typing import Dict, List

from . import __version__
from .model import SEVERITIES, Finding
from .rules import RULES

FRAMEWORKS = ("owasp", "owasp-llm", "eu-ai-act", "soc2", "hipaa", "gdpr")
EVIDENCE_SHOWN = 10  # per control; the rest are counted and listed further down the page
_MAP: List[dict] = []


def mapping() -> dict:
    if not _MAP:
        _MAP.append(json.loads(resources.files("vibeaudit").joinpath("data", "compliance_map.json").read_text(encoding="utf-8")))
    return _MAP[0]


def controls(rule_id: str, framework: str) -> List[str]:
    return list(mapping()["rules"].get(rule_id, {}).get(framework, []))


STATUS = {
    "findings": ("Findings", "Checks that give evidence for this control reported something: review the findings."),
    "clear": ("No findings", "The checks mapped to this control ran and reported nothing. That is not proof the control is met."),
    "unchecked": ("Not checked", "Every check mapped to this control was disabled in this scan."),
    "uncovered": ("Not covered", "No vibeaudit check maps to this control; it needs other evidence."),
}

CSS = """
:root{--fg:#1d2330;--muted:#5b6475;--line:#d5dbe4;--card:#f5f7fa;--bad:#b3001b;--ok:#2b7a3d;--warn:#8a6100}
*{box-sizing:border-box}body{margin:0;background:#fff;color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",
Roboto,sans-serif}main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}h1{font-size:24px;margin:0 0 4px}
h2{font-size:18px;margin:32px 0 8px}.muted{color:var(--muted)}.aid{border:2px solid var(--warn);border-radius:8px;
padding:10px 14px;margin:16px 0;background:#fff8e6}.tiles{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}
.tile{border:1px solid var(--line);border-radius:8px;padding:8px 14px;min-width:130px;background:var(--card)}
.tile b{display:block;font-size:22px}table{border-collapse:collapse;width:100%;font-size:14px}
th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}th{background:var(--card)}
col.c1{width:26%}col.c2{width:12%}col.c3{width:24%}col.c4{width:38%}ul.ev .loc{word-break:normal;overflow-wrap:anywhere}
.wrap{overflow-x:auto}table{min-width:640px}
.st{font-weight:700;white-space:nowrap}.findings .st{color:var(--bad)}.clear .st{color:var(--ok)}
.unchecked .st,.uncovered .st{color:var(--muted)}code,.loc{font-family:ui-monospace,Consolas,monospace;font-size:13px;
word-break:break-all}ul.ev{margin:0;padding-left:18px}.f{border:1px solid var(--line);border-radius:8px;padding:8px 12px;
margin:8px 0}.sev{font-weight:700;text-transform:uppercase;font-size:12px}a{color:#1a5fb4}
@media print{@page{margin:14mm}body{font-size:10.5pt;color:#000}main{max-width:none;padding:0}.aid{background:none}
a{color:#000;text-decoration:none}tr,.f,.tile{break-inside:avoid}thead{display:table-header-group}
h2{break-after:avoid}.tile,th{background:none}.wrap{overflow:visible}table{min-width:0}}
"""


def render(res, framework: str) -> str:
    e = html.escape
    data = mapping()
    fw = data["frameworks"][framework]
    disabled = set(res.meta.get("disabled", []))

    def runs(rid: str) -> bool:
        rule = RULES.get(rid)
        return rid not in disabled and (rule is None or rule.category not in disabled)

    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings = sorted(res.findings, key=lambda f: (order.get(f.severity, 9), f.rule_id, f.file, f.line))
    anchor = {id(f): f"f{n}" for n, f in enumerate(findings, 1)}
    by_rule: Dict[str, List[Finding]] = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    rows, counts = [], {k: 0 for k in STATUS}
    for ctrl, title in fw["controls"].items():
        rules = [rid for rid, m in data["rules"].items() if ctrl in m.get(framework, [])]
        evidence = [f for rid in rules for f in by_rule.get(rid, [])]
        status = ("uncovered" if not rules else "findings" if evidence
                  else "clear" if any(runs(r) for r in rules) else "unchecked")
        counts[status] += 1
        rows.append((ctrl, title, status, rules, evidence))

    mapped = [f for f in findings if controls(f.rule_id, framework)]
    others = len(findings) - len(mapped)
    when = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">",
        f"<title>vibeaudit {e(fw['name'])} compliance aid</title><style>{CSS}</style></head><body><main>",
        f"<h1>{e(fw['name'])} ({e(fw['version'])}): compliance aid</h1>",
        f"<div class=\"muted\">{e(res.root)} - {res.meta.get('files_scanned', 0)} files - vibeaudit {e(__version__)} - {when}</div>",
        f"<p class=\"aid\"><b>Not a certification or legal advice.</b> {e(data['disclaimer'])}</p>",
    ]
    if res.meta.get("offline"):
        out.append("<p class=\"muted\">Scanned with --offline: registry and vulnerability checks used only the data "
                   "shipped with vibeaudit or an imported bundle.</p>")
    out.append("<div class=\"tiles\">" + "".join(
        f"<div class=\"tile\" title=\"{e(STATUS[k][1])}\"><span class=\"muted\">{STATUS[k][0]}</span><b>{counts[k]}</b>controls</div>"
        for k in STATUS) + "</div>")
    out.append("<p class=\"muted\">" + " ".join(f"<b>{e(label)}</b>: {e(text)}" for label, text in STATUS.values()) + "</p>")
    out.append("<h2>Controls</h2><div class=\"wrap\"><table><colgroup><col class=c1><col class=c2><col class=c3><col class=c4></colgroup><thead><tr><th>Control</th><th>Status</th><th>vibeaudit checks</th><th>Evidence</th></tr></thead><tbody>")
    for ctrl, title, status, rules, evidence in rows:
        ev = "".join(f"<li><a href=\"#{anchor[id(f)]}\">{e(f.rule_id)} <span class=\"loc\">{e(_loc(f))}</span></a></li>"
                     for f in evidence[:EVIDENCE_SHOWN])
        if len(evidence) > EVIDENCE_SHOWN:
            ev += f"<li>and {len(evidence) - EVIDENCE_SHOWN} more below</li>"
        label = STATUS[status][0] + (f" ({len(evidence)})" if evidence else "")
        out.append(f"<tr class=\"{status}\"><td><b>{e(ctrl)}</b><br>{e(title)}</td><td class=\"st\">{e(label)}</td>"
                   f"<td>{e(', '.join(rules)) or '-'}</td><td>{'<ul class=ev>' + ev + '</ul>' if ev else '-'}</td></tr>")
    out.append("</tbody></table></div>")
    out.append(f"<h2>Findings ({len(mapped)})</h2>")
    if not mapped:
        out.append("<p>No findings from checks mapped to this framework.</p>")
    for f in mapped:
        out.append(f"<div class=\"f\" id=\"{anchor[id(f)]}\"><span class=\"sev\">{e(f.severity)}</span> <b>{e(f.rule_id)}</b> "
                   f"{e(f.title)}{' (preview rule)' if f.preview else ''}<div class=\"loc\">{e(_loc(f))}</div><div>{e(f.message)}</div>"
                   f"<div class=\"muted\">Controls: {e(', '.join(controls(f.rule_id, framework)))}</div></div>")
    if others:
        out.append(f"<p class=\"muted\">{others} other findings come from checks that map to no {e(fw['name'])} control "
                   "(or from plugins and external tools) and are not listed here; see the full vibeaudit report.</p>")
    if framework not in ("owasp", "owasp-llm"):
        out.append(f"<p class=\"muted\">Only the {e(fw['name'])} controls that code scanning can give evidence for are "
                   "listed; the others need evidence from outside the code.</p>")
    out.append("</main></body></html>")
    # character references keep the page plain ASCII whatever the scanned code contains
    return ("\n".join(out) + "\n").encode("ascii", "xmlcharrefreplace").decode("ascii")


def _loc(f: Finding) -> str:
    return f"{f.file}:{f.line}" if f.line else f.file

