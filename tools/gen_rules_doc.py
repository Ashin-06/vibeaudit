"""Write docs/RULES.md, the rule catalogue, from the rule table in src/vibeaudit/rules.py.

    python tools/gen_rules_doc.py           # rewrite docs/RULES.md
    python tools/gen_rules_doc.py --check   # exit 1 if docs/RULES.md is out of date (used by the tests)
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from vibeaudit.rules import CATEGORIES, RULES  # noqa: E402

TARGET = ROOT / "docs" / "RULES.md"


def render() -> str:
    out = ["# vibeaudit rule catalogue", "",
           "Generated from `src/vibeaudit/rules.py` by `python tools/gen_rules_doc.py`; do not edit by hand.",
           "`vibeaudit rules` prints the same list, and `vibeaudit rules --format json` includes every field.", "",
           f"{len(RULES)} rules. Severity is the default; a finding can be reported lower (for example a "
           "pattern without user input reaching it) or higher (model output instead of user input).", "",
           f"{sum(r.preview for r in RULES.values())} rules are in preview: they are reported but do not count toward "
           "`--fail-on` or the score unless you pass `--include-preview`, except the severe ones marked `preview, gates` "
           "(injection-class bugs), which count unless you pass `--no-gate-severe-preview`. "
           "See [STABILITY.md](../STABILITY.md) for the "
           "policy and [benchmark/RESULTS.md](../benchmark/RESULTS.md) for the measured precision of every rule.", ""]
    for cat, label in CATEGORIES.items():
        rules = sorted((r for r in RULES.values() if r.category == cat), key=lambda r: r.id)
        if not rules:
            continue
        out += [f"## {label}", "", "| ID | Severity | Status | Rule |", "| --- | --- | --- | --- |"]
        out += [f"| [{r.id}](#{r.id.lower()}) | {r.severity} | {('preview, gates' if r.gates_in_preview else 'preview') if r.preview else 'stable'} | {r.title} |"
                for r in rules]
        out.append("")
        for r in rules:
            refs = ", ".join(x for x in (r.cwe, r.owasp) if x)
            out += [f"### {r.id}", "", f"**{r.title}** ({r.severity}{(', preview, gates' if r.gates_in_preview else ', preview') if r.preview else ''})", ""]
            if r.preview:
                out += [f"Preview: {r.preview_reason}", ""]
            out += [f"Why it matters: {r.why}", "", f"How to fix: {r.fix}", ""]
            if refs:
                out += [f"References: {refs}", ""]
    return "\n".join(out).rstrip() + "\n"


def main() -> int:
    text = render()
    if "--check" in sys.argv:
        current = TARGET.read_text(encoding="utf-8") if TARGET.is_file() else ""
        if current != text:
            print("docs/RULES.md is out of date: run python tools/gen_rules_doc.py", file=sys.stderr)
            return 1
        return 0
    TARGET.parent.mkdir(exist_ok=True)
    TARGET.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {TARGET.relative_to(ROOT)} ({len(RULES)} rules)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
