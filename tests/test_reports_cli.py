"""Report formats and the command line interface."""
import json

from helpers import materialize
from vibeaudit import __version__
from vibeaudit.cli import main
from vibeaudit.model import Finding
from vibeaudit.report import Result, render_html, render_markdown, render_sarif, render_text
from vibeaudit.rules import CATEGORIES, RULES


def _result():
    f = Finding("FE001", "web/<x>.js", 3, "msg <script>alert(1)</script>", "high", '<img src=x onerror="alert(1)">',
                title="t", category="frontend", why="w", fix="f")
    f.compute_fingerprint()
    return Result("/tmp/p", [f], {"files_scanned": 1, "stack": ["React"], "notes": ["n <b>"]})


def test_html_escapes_untrusted_content():
    out = render_html(_result())
    assert "<script>alert(1)" not in out and "<img src=x" not in out and "n <b>" not in out
    assert "&lt;script&gt;" in out
    out.encode("ascii")


def test_sarif_structure():
    doc = json.loads(render_sarif(_result()))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    assert run["tool"]["driver"]["rules"][0]["id"] == "FE001"
    res = run["results"][0]
    assert res["ruleIndex"] == 0 and res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
    assert res["partialFingerprints"]["vibeaudit/v1"]
    assert float(run["tool"]["driver"]["rules"][0]["properties"]["security-severity"]) > 7


def test_sarif_line_zero_becomes_one():
    f = Finding("SEC006", ".env", 0, "m", "high", title="t", category="secrets")
    f.compute_fingerprint()
    doc = json.loads(render_sarif(Result("/p", [f], {})))
    assert doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_markdown_and_text():
    md = render_markdown(_result())
    assert "### [HIGH] FE001" in md and "**Fix:**" in md
    txt = render_text(_result(), color=False)
    assert "web/<x>.js:3" in txt and "Score:" in txt


def test_rule_catalog_is_complete():
    for r in RULES.values():
        assert r.category in CATEGORIES and r.why and r.fix and r.severity in ("critical", "high", "medium", "low")
        (r.title + r.why + r.fix).encode("ascii")


def test_cli_exit_codes_and_reports(tmp_path, capsys):
    root = materialize("vuln_express", tmp_path)
    sarif = tmp_path / "out.sarif"
    html = tmp_path / "out.html"
    code = main(["scan", str(root), "--offline", "--external", "none", "--no-color", "-q",
                 "--report", f"sarif:{sarif}", "--report", f"html:{html}"])
    assert code == 1
    assert json.loads(sarif.read_text())["runs"][0]["results"]
    assert "vibeaudit report" in html.read_text()
    assert main(["scan", str(root), "--offline", "--external", "none", "-q", "--fail-on", "none"]) == 0


def test_cli_json_to_stdout(tmp_path, capsys):
    root = materialize("clean_app", tmp_path)
    code = main(["scan", str(root), "--offline", "--external", "none", "--report", "json:-"])
    out = capsys.readouterr().out
    assert code == 0
    assert json.loads(out)["summary"]["total"] == 0


def test_cli_write_baseline_then_use_it(tmp_path):
    root = materialize("vuln_flask_llm", tmp_path)
    base = tmp_path / "baseline.json"
    assert main(["scan", str(root), "--offline", "--external", "none", "-q", "--write-baseline", str(base)]) == 0
    assert main(["scan", str(root), "--offline", "--external", "none", "-q", "--baseline", str(base)]) == 0


def test_cli_errors(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "missing")]) == 2
    assert main(["scan", str(tmp_path), "--report", "pdf"]) == 2
    assert main(["scan", str(tmp_path), "--disable", "NOPE1"]) == 2
    assert main([]) == 2


def test_cli_rules_listing(capsys):
    assert main(["rules", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == len(RULES)
    assert main(["rules", "--format", "md"]) == 0
    assert "| SEC001 |" in capsys.readouterr().out


def test_version_string():
    assert __version__.count(".") == 2


def test_prompt_report_groups_by_file_with_fixes(tmp_path, capsys):
    from vibeaudit.report import render_prompt

    root = materialize("vuln_flask_llm", tmp_path)
    assert main(["scan", str(root), "--offline", "--external", "none", "-q", "--report", "prompt:-"]) == 1
    out = capsys.readouterr().out
    assert out.startswith("Fix the security and quality issues below")
    assert "## app.py" in out and "- [CRITICAL] LLM002 line 49:" in out and "  Fix: " in out
    assert "vibeaudit scan ." in out.splitlines()[-1]
    out.encode("ascii")
    assert render_prompt(Result("/p", [], {})) == "vibeaudit found no issues in this repository.\n"


def test_badge_is_valid_svg_with_score_and_grade(tmp_path):
    import xml.dom.minidom

    from vibeaudit.report import render_badge

    root = materialize("clean_app", tmp_path)
    out = tmp_path / "badge.svg"
    assert main(["scan", str(root), "--offline", "--external", "none", "-q", "--report", f"badge:{out}"]) == 0
    svg = out.read_text()
    doc = xml.dom.minidom.parseString(svg)
    assert doc.documentElement.tagName == "svg" and "vibeaudit: 100 A" in svg
    assert "#c62828" in render_badge(_result_with_critical())


def _result_with_critical():
    f = Finding("BE003", "a.py", 1, "m", "critical", title="t", category="backend")
    f.compute_fingerprint()
    return Result("/p", [f], {})
