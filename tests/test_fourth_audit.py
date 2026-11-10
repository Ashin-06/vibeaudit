"""Regression tests for the fourth external audit (0.5.1) and the audit passes that followed it.

Each finding test was run against 0.5.1 first and failed there; findings that did not reproduce are listed
in the CHANGELOG with the reason."""
import subprocess
from pathlib import Path

import pytest
from helpers import fake_values

from vibeaudit import deps, feedback
from vibeaudit.scanner import Options, scan

ROOT = Path(__file__).parent.parent


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _rules(tmp_path, prefix=""):
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    assert res.meta.get("internal_errors", []) == []
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id.startswith(prefix))


# 1 ------------------------------------------------- breaker state between tests
def test_1a_a_test_that_trips_the_circuit_breaker():
    for _ in range(10):
        deps.BREAKER.record("pypi.org", False)
    assert deps.BREAKER.open("pypi.org")


def test_1b_the_next_test_starts_with_a_closed_breaker():
    assert not deps.BREAKER.open("pypi.org")


# 2 ------------------------------------------------------------------- LLM010
def test_2_search_kwargs_without_a_filter_is_not_a_tenant_filter(tmp_path):
    write(tmp_path, "app.py",
          "@app.post('/ask')\n@login_required\ndef ask():\n    r = store.as_retriever(search_kwargs={'k': 4})\n    return r.invoke(request.json['q'])\n\n"
          "@app.post('/ask2')\n@login_required\ndef ask2():\n"
          "    r = store.as_retriever(search_kwargs={'k': 4, 'filter': {'owner': current_user.id}})\n    return r.invoke(request.json['q'])\n")
    assert _rules(tmp_path, "LLM010") == [("app.py", 4, "LLM010")]


# 3 ------------------------------------------------------------------ contracts
def test_3_a_catch_all_top_level_route_is_not_a_missing_prefix(tmp_path):
    write(tmp_path, "app.py", "@app.get('/<slug>')\ndef page(slug):\n    return ''\n\n@app.get('/users')\ndef users():\n    return []\n")
    write(tmp_path, "web/a.js", "export const a = () => fetch('/static/logo');\nexport const b = () => fetch('/api/users');\n")
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    api = [(f.line, f.rule_id, f.message) for f in res.findings if f.rule_id.startswith("API")]
    assert [(ln, r) for ln, r, _m in api] == [(2, "API001")] and "`/users`" in api[0][2]


# 4 ---------------------------------------------------- secrets in bundles
def test_4_secrets_in_minified_and_committed_bundles(tmp_path):
    if subprocess.run(["git", "--version"], capture_output=True).returncode != 0:
        pytest.skip("git is not installed")
    key = fake_values()["FAKE_OPENAI_KEY"]
    bundle = "var a=1;" * 900 + f'const k="{key}";' + "function b(){return a}" * 300  # one 10 KB line
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    write(tmp_path, "public/bundle.js", bundle)
    write(tmp_path, "dist/index.js", bundle)
    write(tmp_path, "node_modules/lib/index.js", bundle)  # dependencies stay out of the scan
    subprocess.run(["git", "-C", str(tmp_path), "add", "public", "dist"], check=True)
    found = _rules(tmp_path, "SEC")
    assert found == [("dist/index.js", 1, "SEC001"), ("public/bundle.js", 1, "SEC001")]
    # code rules still skip generated bundles
    assert not [r for r in _rules(tmp_path) if r[0] in ("dist/index.js", "public/bundle.js") and not r[2].startswith("SEC")]


# 5 ----------------------------------------------------------------- self-scan
def test_5_vibeaudit_scans_itself_clean():
    res = scan(str(ROOT), Options(offline=True, external="none", excludes=["tests/fixtures/**", "build/**"]))
    assert [(f.rule_id, f.file, f.line) for f in res.findings] == []


# 6 ------------------------------------------------------------------ feedback
def test_6_feedback_accepts_absolute_and_backslash_paths(tmp_path):
    write(tmp_path, "api/app.py", "@app.post('/api/items')\ndef items():\n    db.execute('DELETE FROM items')\n    return ''\n")
    absolute = str((tmp_path / "api" / "app.py").resolve())
    assert feedback.record(tmp_path, "AUTH001", absolute, 2, "false-positive") is not None
    assert feedback.record(tmp_path, "AUTH001", ".\\api\\app.py", 2, "confirmed") is not None
    assert [e["file"] for e in feedback.load(tmp_path)] == ["api/app.py"]


# 7 --------------------------------------------------------- network tests
def test_7_network_tests_are_opt_in():
    text = (ROOT / "pyproject.toml").read_text()
    assert 'addopts = "-m \'not network\'"' in text
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "pytest -q -m network" in ci and "continue-on-error: true" in ci


# 8 ------------------------------------------------------------------ contracts
def test_8_nested_template_literals_in_the_path(tmp_path):
    write(tmp_path, "app.py", "@app.get('/api/items/<iid>')\ndef item(iid):\n    return {}\n")
    write(tmp_path, "web/a.js", "export const a = () => fetch(`/api/items/${isAlt ? `alt-${id}` : id}`, { method: 'DELETE' });\n")
    assert _rules(tmp_path, "API") == [("web/a.js", 1, "API002")]
