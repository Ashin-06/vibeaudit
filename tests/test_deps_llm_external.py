"""Supply-chain checks (offline, mocked network and optional live network), LLM plumbing and external tool parsers."""
import datetime as dt
import json
import socket
from pathlib import Path

import pytest

from helpers import actual, expected, fake_values, materialize
from vibeaudit import deps, external, llm
from vibeaudit.scanner import Options, scan


def test_edit_distance_one():
    assert deps.edit_distance_one("requests", "reqeusts")
    assert deps.edit_distance_one("express", "expresss")
    assert deps.edit_distance_one("lodash", "lodas")
    assert deps.edit_distance_one("axios", "axioz")
    assert not deps.edit_distance_one("react", "react")
    assert not deps.edit_distance_one("flask", "django")


def test_typosquat_targets():
    assert deps.typosquat_target("reqeusts", "PyPI") == "requests"
    assert deps.typosquat_target("expresss", "npm") == "express"
    for real in ("requests", "flask", "fastapi", "openai", "langchain"):
        assert deps.typosquat_target(real, "PyPI") is None
    for real in ("react", "react-dom", "express", "zod", "openai", "@supabase/supabase-js"):
        assert deps.typosquat_target(real, "npm") is None


def test_parse_requirement():
    assert deps.parse_requirement("flask==3.0.3  # web") == ("flask", "3.0.3")
    assert deps.parse_requirement("uvicorn[standard]>=0.30") == ("uvicorn", None)
    assert deps.parse_requirement("-r other.txt") is None
    assert deps.parse_requirement("git+https://github.com/x/y") is None
    assert deps.parse_requirement("pkg @ https://x/y.whl") is None
    assert deps.parse_requirement("requests; python_version < '3.10'") == ("requests", None)


def _fake_network(monkeypatch, missing=(), new=(), vulns=None):
    now = dt.datetime.now(dt.timezone.utc)

    def fake_get_json(url, data=None):
        if "osv.dev/v1/querybatch" in url:
            queries = json.loads(data)["queries"]
            return 200, {"results": [{"vulns": [{"id": "GHSA-test"}]} if (vulns and q["package"]["name"] in vulns) else {} for q in queries]}
        if "osv.dev/v1/vulns/" in url:
            return 200, {"id": "GHSA-test", "database_specific": {"severity": "CRITICAL"},
                         "affected": [{"package": {"name": "pyyaml"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "6.0.2"}]}]}]}
        name = url.rstrip("/").split("/")[-1 if "npmjs" in url else -2].replace("%2F", "/")
        if name in missing:
            return 404, None
        created = (now - dt.timedelta(days=3 if name in new else 2000)).isoformat()
        if "npmjs" in url:
            return 200, {"dist-tags": {"latest": "1.0.0"}, "time": {"created": created}}
        return 200, {"releases": {"1.0": [{"upload_time_iso_8601": created}]}}

    monkeypatch.setattr(deps, "_get_json", fake_get_json)


def test_online_checks_with_mocked_registry(tmp_path, monkeypatch):
    _fake_network(monkeypatch, missing={"flask-openai-chat-helper"}, vulns={"pyyaml"})
    root = materialize("vuln_flask_llm", tmp_path)
    res = scan(str(root), Options(offline=False, external="none"))
    exp = expected("vuln_flask_llm", online=True) | {("requirements.txt", 5, "DEP004")}
    assert actual(res) == exp
    vuln = next(f for f in res.findings if f.rule_id == "DEP004")
    assert vuln.severity == "critical" and "6.0.2" in vuln.message
    squat = next(f for f in res.findings if f.rule_id == "DEP002")
    assert squat.severity == "low"  # long-established package with a similar name


def test_new_package_and_npm_malware_holding(tmp_path, monkeypatch):
    _fake_network(monkeypatch, new={"brand-new-ai-helper"})
    (tmp_path / "requirements.txt").write_text("brand-new-ai-helper==0.0.1\n")
    res = scan(str(tmp_path), Options(external="none"))
    assert [(f.rule_id) for f in res.findings] == ["DEP003"]

    def holding(url, data=None):
        if "osv" in url:
            return 200, {"results": [{}]}
        return 200, {"dist-tags": {"latest": "0.0.1-security"}, "description": "security holding package"}

    monkeypatch.setattr(deps, "_get_json", holding)
    (tmp_path / "requirements.txt").unlink()
    (tmp_path / "package.json").write_text('{"dependencies": {"some-removed-pkg": "1.0.0"}}')
    (tmp_path / "package-lock.json").write_text("{}")
    res = scan(str(tmp_path), Options(external="none"))
    assert [f.rule_id for f in res.findings] == ["DEP001"] and "malware" in res.findings[0].message


def test_network_failure_is_reported_not_crashing(tmp_path, monkeypatch):
    monkeypatch.setattr(deps, "_get_json", lambda url, data=None: (0, None))
    (tmp_path / "requirements.txt").write_text("some-unknown-pkg==1.0\n")
    res = scan(str(tmp_path), Options(external="none"))
    assert res.findings == []
    assert any("failed" in n for n in res.meta["notes"])


def _online():
    try:
        socket.create_connection(("pypi.org", 443), timeout=5).close()
        return True
    except OSError:
        return False


@pytest.mark.network
@pytest.mark.skipif(not _online(), reason="no network")
def test_live_registry_and_osv():
    ok = deps.registry_info(deps.Dep("requests", "PyPI", "r", 1))
    assert ok[0] == "ok" and ok[1].year < 2015
    assert deps.registry_info(deps.Dep("vibeaudit-surely-missing-pkg-8f3k2", "PyPI", "r", 1))[0] == "missing"
    assert deps.registry_info(deps.Dep("vibeaudit-surely-missing-pkg-8f3k2", "npm", "r", 1))[0] == "missing"
    assert deps.registry_info(deps.Dep("express", "npm", "r", 1))[0] == "ok"
    found = deps.osv_lookup([deps.Dep("jinja2", "PyPI", "r", 1, "2.4.1")])
    assert found and len(next(iter(found.values()))) > 0


# ------------------------------------------------------------------ LLM
def test_redact_removes_secrets():
    v = fake_values()
    text = f'key = "{v["FAKE_OPENAI_KEY"]}"\nOPENAI_API_KEY=abc\npostgres://u:{v["FAKE_DB_PW"]}@db.example.net/x\n{v["FAKE_SERVICE_ROLE_JWT"]}'
    out = llm.redact(text)
    for secret in (v["FAKE_OPENAI_KEY"], v["FAKE_DB_PW"], v["FAKE_SERVICE_ROLE_JWT"], "=abc"):
        assert secret not in out


def test_parse_json_variants():
    assert llm.parse_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert llm.parse_json('Sure! {"a": [1, 2]} hope it helps') == {"a": [1, 2]}
    with pytest.raises(llm.LLMError):
        llm.parse_json("no json here")


def test_provider_requires_key(monkeypatch):
    for k in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(llm.LLMError):
        llm.Provider("gemini")
    with pytest.raises(llm.LLMError):
        llm.Provider("nope")


def test_triage_annotates_but_never_removes(tmp_path, monkeypatch):
    root = materialize("vuln_express", tmp_path)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    prompts = []

    def fake_complete(self, prompt):
        self.requests += 1
        prompts.append(prompt)
        return json.dumps({"results": [{"id": i, "verdict": "false_positive", "reason": "the code says it is safe"} for i in range(6)]})

    monkeypatch.setattr(llm.Provider, "complete", fake_complete)
    base = scan(str(root), Options(offline=True, external="none"))
    res = scan(str(root), Options(offline=True, external="none", llm="gemini", llm_max_requests=2))
    assert len(res.findings) == len(base.findings)
    assert [f.severity for f in res.findings] == [f.severity for f in base.findings]
    assert sum(1 for f in res.findings if f.llm_verdict == "false_positive") == 12
    assert len(prompts) == 2


def test_review_adds_labelled_findings(tmp_path, monkeypatch):
    root = materialize("vuln_agent", tmp_path)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")

    def fake_complete(self, prompt):
        self.requests += 1
        if "Audit this file" in prompt:
            return json.dumps({"issues": [{"line": 2, "severity": "high", "title": "Something missed", "why": "w", "fix": "f"},
                                          {"line": 99999, "severity": "high", "title": "bad line"}]})
        return json.dumps({"results": []})

    monkeypatch.setattr(llm.Provider, "complete", fake_complete)
    res = scan(str(root), Options(offline=True, external="none", llm="gemini", llm_review=True, llm_max_requests=5))
    extra = [f for f in res.findings if f.rule_id == "AI001"]
    assert extra and all(f.title == "Something missed" and f.line == 2 and "unverified" in f.message for f in extra)
    assert all(f.source == "llm-review" for f in extra)


# ------------------------------------------------------------- external
def test_external_parsers(tmp_path):
    root = Path(tmp_path)
    secret = "abcd" * 8
    g = external.parse_gitleaks([{"RuleID": "generic-api-key", "File": str(root / "a.py"), "StartLine": 3,
                                  "Secret": secret, "Line": f"key = '{secret}'", "Description": "Generic API Key"}], root)
    assert g[0].file == "a.py" and g[0].line == 3 and secret not in g[0].snippet
    b = external.parse_bandit({"results": [
        {"test_id": "B324", "test_name": "hashlib", "issue_text": "Use of weak MD5 hash",
         "issue_severity": "HIGH", "issue_confidence": "HIGH", "filename": str(root / "x.py"), "line_number": 7,
         "code": "hashlib.md5(data)", "issue_cwe": {"id": 327}},
        {"test_id": "B101", "issue_severity": "LOW", "issue_confidence": "HIGH", "filename": "y.py", "line_number": 1}]}, root)
    assert len(b) == 1 and b[0].rule_id == "bandit:B324" and b[0].cwe == "CWE-327"
    s = external.parse_semgrep({"results": [{"check_id": "python.lang.security.audit.eval-detected", "path": "z.py",
                                             "start": {"line": 4}, "extra": {"message": "eval", "severity": "ERROR",
                                                                             "metadata": {"cwe": ["CWE-95: Eval"]}, "lines": "eval(x)"}}]}, root)
    assert s[0].severity == "high" and s[0].cwe == "CWE-95" and s[0].file == "z.py"
    o = external.parse_osv_scanner({"results": [{"source": {"path": str(root / "requirements.txt")}, "packages": [
        {"package": {"name": "jinja2", "version": "2.4.1"}, "vulnerabilities": [{"id": "GHSA-1", "database_specific": {"severity": "HIGH"}}]}]}]}, root)
    assert o[0].file == "requirements.txt" and o[0].severity == "high"


def test_external_duplicates_of_builtin_findings_are_dropped(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("eval(x)\n")
    dup = external.parse_bandit({"results": [{"test_id": "B999", "test_name": "eval", "issue_text": "eval",
                                              "issue_severity": "MEDIUM", "issue_confidence": "HIGH",
                                              "filename": "a.py", "line_number": 1, "code": "eval(x)"}]}, tmp_path)
    monkeypatch.setattr(external, "available", lambda name: name == "bandit")
    monkeypatch.setattr(external, "run_tool", lambda name, root: dup)
    res = scan(str(tmp_path), Options(offline=True, external="auto"))
    assert [f.rule_id for f in res.findings] == ["BE003"] and res.meta["external_tools"] == ["bandit"]
