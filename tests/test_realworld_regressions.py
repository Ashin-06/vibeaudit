"""Regression tests for real-world false-positive fixes, missed detections, usability, and explain RULE."""
from __future__ import annotations

import json
from pathlib import Path

from vibeaudit import cli, deps, explain, external, mcp_server, report
from vibeaudit.scanner import Options, scan


def _scan(root: Path, **kw):
    opts = Options(offline=True, external="none", feedback=False, cache=False, **kw)
    return scan(str(root), opts)


# ------------------------------------------------------------------ False positives
def test_auth008_skips_user_properties_and_zero_arg_helpers(tmp_path):
    (tmp_path / "auth.py").write_text(
        "class User:\n"
        "    @property\n"
        "    def is_authenticated(self) -> bool:\n"
        "        return True\n"
        "    def require_authentication(self, realm, env):\n"
        "        return True\n"
        "    def is_admin(self):\n"
        "        return True\n"
        "def verify_token(token):\n"
        "    return True\n"
    )
    (tmp_path / "user.js").write_text(
        "const user = { isAuthenticated() { return true; } };\n"
        "function isAdmin(req) { return true; }\n"
    )
    res = _scan(tmp_path)
    auth8 = [(f.file, f.line) for f in res.findings if f.rule_id == "AUTH008"]
    assert auth8 == [("auth.py", 9), ("user.js", 2)]


def test_html_pre_and_code_blocks_are_ignored(tmp_path):
    (tmp_path / "tutorial.html").write_text(
        "<h1>Example</h1>\n"
        "<pre>\n"
        "var x = eval(req.body.preTax);\n"
        'app.use(express.session({ secret: "s3Cur3" }));\n'
        "</pre>\n"
        "<code>eval(req.body.q)</code>\n"
    )
    res = _scan(tmp_path, include_preview=True)
    assert [f for f in res.findings if f.rule_id in ("BE003", "SEC004")] == []


def test_dep002_ignores_flash_and_marks_offline_heuristic_low(tmp_path):
    assert deps.typosquat_target("flash", "npm") is None
    assert deps.typosquat_target("reqeusts", "PyPI") == "requests"
    assert deps.typosquat_target("expresss", "npm") == "express"
    (tmp_path / "package.json").write_text('{"name": "app", "dependencies": {"flash": "1.1.0"}}')
    (tmp_path / "package-lock.json").write_text("{}")
    res = _scan(tmp_path)
    assert [f for f in res.findings if f.rule_id == "DEP002"] == []


def test_qa006_skips_dynamic_vcs_version_module(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["hatchling", "hatch-vcs"]\n'
        '[project]\nname = "demo"\ndynamic = ["version"]\n'
    )
    pkg = tmp_path / "demo"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("from ._version import __version__\nfrom .missing_mod import x\n")
    res = _scan(tmp_path, include_preview=True)
    qa6 = [f for f in res.findings if f.rule_id == "QA006"]
    assert len(qa6) == 1 and "missing_mod" in qa6[0].message


# ------------------------------------------------------------------ Missed detections
def test_js_node_missed_detections(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"name": "app", "dependencies": {"express": "4.18.0", "mongoose": "7.0.0", "needle": "3.0.0", "mathjs": "11.0.0", "node-serialize": "0.0.4"}}'
    )
    (tmp_path / "dao.js").write_text(
        "function byThreshold(threshold) {\n"
        "  return { $where: `this.stocks > '${threshold}'` };\n"
        "}\n"
    )
    (tmp_path / "routes.js").write_text(
        "const express = require('express');\n"
        "const needle = require('needle');\n"
        "const mathjs = require('mathjs');\n"
        "const serialize = require('node-serialize');\n"
        "const app = express();\n"
        "app.get('/fetch', (req, res) => needle.get(req.query.url, () => res.end()));\n"
        "app.post('/calc', (req, res) => res.send(String(mathjs.eval(req.body.eqn))));\n"
        "app.post('/import', (req, res) => res.json(serialize.unserialize(req.files.data)));\n"
        "const re = /([0-9]+)+#/;\n"
    )
    res = _scan(tmp_path, include_preview=True)
    rules = {f.rule_id for f in res.findings}
    assert {"BE010", "BE005", "BE003", "BE004", "BE023"} <= rules


def test_php_reflected_dom_fi_and_weak_session_id(tmp_path):
    (tmp_path / "xss_r.php").write_text("<?php\n$html = '';\n$html .= '<pre>Hello ' . $_GET['name'] . '</pre>';\n?>\n")
    (tmp_path / "xss_d.php").write_text(
        "<?php\necho <<<EOF\n<script>\nvar x = document.location.href;\ndocument.write(x);\n</script>\nEOF;\n?>\n"
    )
    sub = tmp_path / "fi" / "source"
    sub.mkdir(parents=True)
    (sub / "low.php").write_text("<?php\n$page_target = $_GET['page'];\n?>\n")
    (tmp_path / "fi" / "index.php").write_text("<?php\nrequire_once 'source/low.php';\ninclude($page_target);\n?>\n")
    (tmp_path / "weak.php").write_text(
        "<?php\n$val = md5($_SESSION['id']);\nsetcookie('dvwaSession', $val, time()+3600, '/', $_SERVER['HTTP_HOST']);\n?>\n"
    )
    res = _scan(tmp_path, include_preview=True)
    by_file = {(f.file, f.rule_id) for f in res.findings}
    assert ("xss_r.php", "FE001") in by_file
    assert ("xss_d.php", "FE001") in by_file
    assert ("fi/index.php", "BE006") in by_file
    assert ("weak.php", "BE015") in by_file


# ------------------------------------------------------------------ Usability & Top-Class features
def test_bandit_noise_reduction():
    raw = {
        "results": [
            {"test_id": "B108", "issue_severity": "MEDIUM", "issue_confidence": "HIGH", "filename": "a.py", "line_number": 1, "issue_text": "/tmp"},
            {"test_id": "B324", "issue_severity": "MEDIUM", "issue_confidence": "HIGH", "filename": "a.py", "line_number": 2, "issue_text": "sha1", "code": "hashlib.sha1(s)"},
            {"test_id": "B324", "issue_severity": "HIGH", "issue_confidence": "HIGH", "filename": "a.py", "line_number": 3, "issue_text": "md5", "code": "hashlib.md5(s)", "issue_cwe": {"id": 327}},
        ]
    }
    parsed = external.parse_bandit(raw, Path("."))
    assert [(f.rule_id, f.line) for f in parsed] == [("bandit:B324", 3)]


def test_context_downgrade_grouped_output_and_languages(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "demo.py").write_text("import pickle\ndef load(req_data):\n    return pickle.loads(req_data)\n")
    (tmp_path / "app.php").write_text("<?php\necho $_GET['x'];\n?>\n")
    wf = tmp_path / ".github" / "workflows" / "ci.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text(
        "on: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        + "".join("      - uses: docker/build-push-action@v5\n" for _ in range(5))
    )
    res = _scan(tmp_path, include_preview=True)
    doc_f = next(f for f in res.findings if f.file == "docs/demo.py" and f.rule_id == "BE004")
    assert doc_f.severity == "low" and doc_f.confidence == "low"
    assert res.meta["languages"]["PHP"].startswith("preview")
    txt = report.render_text(res, color=False, verbose=True)
    assert "Top 5 findings (fix these first)" in txt
    assert "Languages:" in txt and "PHP (preview" in txt
    assert "(x5 across 1 files)" in txt
    md = report.render_markdown(res)
    assert "(x5 across 1 files)" in md
    html_out = report.render_html(res)
    assert "AI assistant fix prompt" in html_out


def test_require_ignore_reason(tmp_path):
    (tmp_path / "a.py").write_text(
        "eval(x)  # vibeaudit: ignore[BE003]\n"
        "eval(y)  # vibeaudit: ignore[BE003] -- legacy expression evaluator for static constants\n"
    )
    default_res = _scan(tmp_path, include_preview=True)
    assert default_res.findings == []
    strict_res = _scan(tmp_path, include_preview=True, require_ignore_reason=True)
    lines = [f.line for f in strict_res.findings if f.rule_id == "BE003"]
    assert lines == [1]
    assert strict_res.meta["suppressions"] == [
        {"file": "a.py", "line": 2, "rule_id": "BE003", "reason": "legacy expression evaluator for static constants"}
    ]


def test_explain_rule_cli_and_mcp(capsys):
    rc = cli.main(["explain", "BE001"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "BE001" in out and "Unsafe example" in out and "Safe example" in out

    rc_json = cli.main(["explain", "BE023", "--format", "json"])
    assert rc_json == 0
    data = json.loads(capsys.readouterr().out)
    assert data["rule_id"] == "BE023" and "unsafe" in data["example"] and "safe" in data["example"]

    mcp_data = mcp_server.tool_explain_rule({"rule_id": "BE001"})
    assert "example" in mcp_data and "unsafe" in mcp_data["example"]


def test_explain_finding_includes_ai_prompt(tmp_path):
    (tmp_path / "app.py").write_text("eval(user_input)\n")
    res = _scan(tmp_path, include_preview=True)
    f = next(x for x in res.findings if x.rule_id == "BE003")
    info = explain.explain(f, (tmp_path / "app.py").read_text())
    assert "ai_prompt" in info and "BE003" in info["ai_prompt"]
    assert "AI assistant prompt:" in explain.render(info)
