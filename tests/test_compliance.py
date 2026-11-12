"""Compliance mapping (data/compliance_map.json) and the `--report compliance:<framework>` page."""
import re
import subprocess
import sys

import pytest
from helpers import materialize

from vibeaudit import compliance
from vibeaudit.model import Finding
from vibeaudit.report import Result
from vibeaudit.rules import RULES
from vibeaudit.scanner import Options, scan


def test_every_rule_has_a_mapping_entry():
    """New rules must be mapped: add an entry to src/vibeaudit/data/compliance_map.json for each one (empty
    lists where no control applies, with a "note" saying why when every list is empty)."""
    entries = compliance.mapping()["rules"]
    missing = sorted(set(RULES) - set(entries))
    assert not missing, f"rules without a compliance mapping entry in data/compliance_map.json: {missing}"
    stray = sorted(set(entries) - set(RULES))
    assert not stray, f"mapping entries for rules that do not exist: {stray}"


def test_entries_are_well_formed_and_match_the_rule_catalogue():
    data = compliance.mapping()
    assert tuple(data["frameworks"]) == compliance.FRAMEWORKS
    for rid, entry in data["rules"].items():
        for fw in compliance.FRAMEWORKS:
            assert isinstance(entry.get(fw), list), (rid, fw)
            unknown = set(entry[fw]) - set(data["frameworks"][fw]["controls"])
            assert not unknown, (rid, fw, unknown)
        assert any(entry[fw] for fw in compliance.FRAMEWORKS) or entry.get("note"), f"{rid}: no control and no note"
        if RULES[rid].owasp:  # the reference printed with every finding is part of the mapping
            assert RULES[rid].owasp in entry["owasp"] + entry["owasp-llm"], rid


def test_the_disclaimer_is_explicit():
    text = compliance.mapping()["disclaimer"]
    assert "not a certification" in text and "legal advice" in text and "not thereby met" in text


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    root = materialize("vuln_flask_llm", tmp_path_factory.mktemp("c"))
    return scan(str(root), Options(offline=True, external="none", min_severity="low", include_preview=True))


@pytest.mark.parametrize("framework", compliance.FRAMEWORKS)
def test_report_is_self_contained_printable_and_linked(result, framework):
    page = compliance.render(result, framework)
    assert page.isascii() and page.startswith("<!doctype html>")
    assert not re.search(r"""\ssrc=|<link|<script|@import|url\(|href=["']?(?:https?:|//)""", page, re.I)
    assert "@media print" in page and "Not a certification or legal advice." in page
    anchors = set(re.findall(r'id="(f\d+)"', page))
    links = set(re.findall(r'href="#(f\d+)"', page))
    assert links <= anchors
    statuses = re.findall(r'<tr class="(\w+)">', page)
    assert len(statuses) == len(compliance.mapping()["frameworks"][framework]["controls"])
    if framework in ("owasp", "soc2"):
        assert "findings" in statuses and links, framework  # the sample app has injection and secrets findings


def test_statuses(result, monkeypatch):
    import copy

    data = copy.deepcopy(compliance.mapping())
    data["frameworks"]["owasp-llm"]["controls"]["LLM99:2025"] = "A control no rule maps to"
    monkeypatch.setattr(compliance, "_MAP", [data])
    llm = compliance.render(result, "owasp-llm")
    assert re.search(r'<tr class="uncovered"><td><b>LLM99:2025</b>', llm)
    monkeypatch.undo()
    sql = [f for f in result.findings if f.rule_id == "BE001"]
    assert sql, "the sample app should have a SQL injection finding"
    soc2 = compliance.render(result, "soc2")
    assert re.search(r'<tr class="findings"><td><b>CC6.6</b>', soc2)
    quiet = Result(result.root, [], dict(result.meta, disabled=["backend", "frontend", "auth", "config", "llm"]))
    page = compliance.render(quiet, "soc2")
    assert re.search(r'<tr class="unchecked"><td><b>CC6.6</b>', page)  # every rule mapped to CC6.6 was disabled
    assert re.search(r'<tr class="clear"><td><b>CC8.1</b>', page)  # quality rules still ran and found nothing


def test_hostile_text_is_escaped():
    f = Finding("BE001", 'a"><script>alert(1)</script>.py', 3, "</td></tr><img src=x onerror=alert(1)>",
                severity="high", title="SQL injection", category="backend")
    page = compliance.render(Result("/tmp/<x>", [f], {"files_scanned": 1}), "owasp")
    assert "<script>" not in page and "<img" not in page and "&lt;script&gt;" in page


def test_cli(tmp_path):
    out = tmp_path / "gdpr.html"
    run = subprocess.run([sys.executable, "-m", "vibeaudit", "scan", str(materialize("vuln_flask_llm", tmp_path / "app")),
                          "--offline", "--external", "none", "-q", "--fail-on", "none", "-r", f"compliance:gdpr:{out}",
                          "-r", "compliance:HIPAA:-"], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert "GDPR" in out.read_text(encoding="utf-8") and "HIPAA Security and Privacy Rules" in run.stdout
    bad = subprocess.run([sys.executable, "-m", "vibeaudit", "scan", str(tmp_path), "--offline", "-q", "-r", "compliance:iso27001"],
                         capture_output=True, text=True)
    assert bad.returncode == 2 and "unknown compliance framework 'iso27001'" in bad.stderr
    default = subprocess.run([sys.executable, "-m", "vibeaudit", "scan", str(tmp_path / "app"), "--offline", "--external", "none",
                              "-q", "--fail-on", "none", "-r", "compliance:soc2"], capture_output=True, text=True, cwd=tmp_path)
    assert default.returncode == 0 and (tmp_path / "vibeaudit-compliance-soc2.html").is_file()
