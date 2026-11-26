"""Tests for v0.16.0 fixes and features: context-sensitive sanitizers, threat-feed anti-rollback,
Python MongoDB BE010, Cypher/KQL BE022, fix --verify + rollback, --privacy-report, and attack-path correlation.
"""
import datetime as dt
import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from test_lang_precision_fixes import _scan

from vibeaudit import bundle, feed, scanner
from vibeaudit.cli import main as cli_main
from vibeaudit.correlate import ai_risk_profile, attack_paths
from vibeaudit.model import Finding
from vibeaudit.scanner import Options


def _rules(res):
    return {f.rule_id for f in res.findings}


# ------------------------------------------------ Context-sensitive & span-scoped sanitization (JS/TS)
def test_js_context_sensitive_and_span_scoped_sanitizers(tmp_path: Path):
    res = _scan(tmp_path, {
        "package.json": '{"name":"app","dependencies":{"express":"4.19.0"}}\n',
        "routes/sql_url_encode.js": (
            'const express = require("express");\nconst app = express();\n'
            'app.get("/a", (req, res) => {\n'
            '  const q = "SELECT * FROM users WHERE id = " + encodeURIComponent(req.query.id);\n'
            "  db.query(q);\n"
            '  res.send("ok");\n'
            "});\n"
        ),
        "routes/sql_html_escape.js": (
            'const express = require("express");\nconst app = express();\n'
            'app.get("/b", (req, res) => {\n'
            "  const clean = DOMPurify.sanitize(req.query.bio);\n"
            '  db.query("SELECT * FROM users WHERE bio = \'" + clean + "\'");\n'
            '  el.innerHTML = clean;\n'
            '  res.send("ok");\n'
            "});\n"
        ),
        "routes/partial_sanitize.js": (
            'const express = require("express");\nconst app = express();\n'
            'app.get("/c", (req, res) => {\n'
            '  db.query("SELECT * FROM users WHERE id = " + Number(req.query.a) + " AND name = \'" + req.query.b + "\'");\n'
            '  res.send("ok");\n'
            "});\n"
        ),
        "routes/shell_and_redirect.js": (
            'const express = require("express");\nconst { exec } = require("child_process");\nconst app = express();\n'
            'app.get("/d", (req, res) => {\n'
            '  exec("echo " + DOMPurify.sanitize(req.query.x));\n'
            "  res.redirect(DOMPurify.sanitize(req.query.next));\n"
            "});\n"
        ),
    })
    by_file = {}
    for f in res.findings:
        by_file.setdefault(f.file, set()).add(f.rule_id)

    assert "BE001" in by_file.get("routes/sql_url_encode.js", set())
    assert "BE001" in by_file.get("routes/sql_html_escape.js", set())
    assert "FE001" not in by_file.get("routes/sql_html_escape.js", set())
    assert "BE001" in by_file.get("routes/partial_sanitize.js", set())
    assert {"BE002", "BE008"} <= by_file.get("routes/shell_and_redirect.js", set())


# ------------------------------------------------ Context-sensitive & span-scoped sanitization (Python)
def test_py_context_sensitive_sanitizers_and_cross_call(tmp_path: Path):
    res = _scan(tmp_path, {
        "app.py": (
            "import html, os, shlex, urllib.parse\n"
            "from flask import Flask, request, redirect\n"
            "from markupsafe import Markup\n"
            "from werkzeug.utils import secure_filename\n"
            "app = Flask(__name__)\n"
            '@app.get("/x")\n'
            "def view(conn):\n"
            "    raw = request.args['n']\n"
            "    clean_html = html.escape(raw)\n"
            "    conn.execute(f\"SELECT * FROM u WHERE n = '{clean_html}'\")\n"
            '    os.system("echo " + clean_html)\n'
            "    safe_markup = Markup(clean_html)\n"
            '    open("/data/" + clean_html)\n'
            '    open("/data/" + secure_filename(raw))\n'
            '    os.system("ls " + shlex.quote(raw))\n'
            '    os.system("ls " + urllib.parse.quote(raw))\n'
            "    return str(safe_markup)\n"
        ),
    })
    by_line = {f.line: f.rule_id for f in res.findings}
    lines = (tmp_path / "app.py").read_text(encoding="utf-8").splitlines()
    line_no = lambda sub: next(i + 1 for i, l in enumerate(lines) if sub in l)

    assert by_line.get(line_no("conn.execute")) == "BE001"
    assert by_line.get(line_no('os.system("echo "')) == "BE002"
    assert by_line.get(line_no("Markup(clean_html)")) != "FE001"
    assert by_line.get(line_no('open("/data/" + clean_html')) == "BE006"
    assert by_line.get(line_no("secure_filename")) != "BE006"
    assert by_line.get(line_no("shlex.quote")) != "BE002"
    assert by_line.get(line_no("urllib.parse.quote")) == "BE002"


# ------------------------------------------------ Threat-feed anti-rollback in bundle import
def test_bundle_import_rejects_expired_and_rollback_feeds(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(feed, "cache_dir", lambda: tmp_path / "cache")
    monkeypatch.setattr(bundle, "cache_dir", lambda: tmp_path / "cache")
    from vibeaudit import updater

    monkeypatch.setattr(updater, "cache_dir", lambda: tmp_path / "cache")
    key = feed.generate_key(bits=1024)
    pub = {"n": key["n"], "e": key["e"]}
    monkeypatch.setattr(feed, "public_key", lambda: pub)

    now = dt.datetime.now(dt.timezone.utc)
    newer = feed.build({"slopsquatted": [], "model_sunsets": [], "prompt_injection": []}, key, now=now)
    older = feed.build({"slopsquatted": [], "model_sunsets": [], "prompt_injection": []}, key, now=now - dt.timedelta(days=2))
    expired = feed.build({"slopsquatted": [], "model_sunsets": [], "prompt_injection": []}, key, now=now - dt.timedelta(days=45))

    cache_feed = tmp_path / "cache" / "data" / feed.FEED
    cache_feed.parent.mkdir(parents=True, exist_ok=True)
    cache_feed.write_bytes(newer)

    # Build minimal bundle zip with lists + feed
    def make_zip(zip_path: Path, feed_bytes: bytes) -> None:
        from vibeaudit.updater import FILES, data_bytes

        members = {f"data/{n}": data_bytes(n) for n in FILES}
        members[f"data/{feed.FEED}"] = feed_bytes
        manifest = {
            "format": bundle.FORMAT,
            "vibeaudit": "0.16.0",
            "created": now.isoformat(timespec="seconds"),
            "files": {k: {"sha256": hashlib.sha256(v).hexdigest(), "size": len(v)} for k, v in members.items()},
        }
        with zipfile.ZipFile(zip_path, "w") as z:
            z.writestr("manifest.json", json.dumps(manifest))
            for k, v in members.items():
                z.writestr(k, v)

    z_old = tmp_path / "rollback.zip"
    make_zip(z_old, older)
    with pytest.raises(bundle.BundleError, match="older than the installed feed"):
        bundle.import_bundle(z_old, lambda _m: None)
    assert cache_feed.read_bytes() == newer

    z_exp = tmp_path / "expired.zip"
    make_zip(z_exp, expired)
    with pytest.raises(bundle.BundleError, match="expired on"):
        bundle.import_bundle(z_exp, lambda _m: None)
    assert cache_feed.read_bytes() == newer


# ------------------------------------------------ Query-language injection (Python BE010 & Cypher/KQL BE022)
def test_python_mongo_be010_and_cypher_kql_be022(tmp_path: Path):
    res = _scan(tmp_path, {
        "mongo_api.py": (
            "import json\n"
            "from pymongo import MongoClient\n"
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n"
            "col = MongoClient()['db']['users']\n"
            '@app.post("/users/search")\n'
            "def search():\n"
            "    flt = json.loads(request.args['q'])\n"
            "    col.find_one(flt)\n"
            '    col.find_one({"name": {"$eq": request.args["q"]}})\n'
            '    return "ok"\n'
        ),
        "graph_and_kusto.py": (
            "from azure.kusto.data import KustoClient\n"
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n"
            "kusto = KustoClient(None)\n"
            '@app.get("/graph")\n'
            "def g(session):\n"
            "    name = request.args['name']\n"
            "    session.run(f\"MATCH (n:User {{name: '{name}'}}) RETURN n\")\n"
            '    session.run("MATCH (n:User {name: $name}) RETURN n", {"name": name})\n'
            '    kusto.execute("db", f"Logs | where User == \'{name}\'")\n'
            '    return "ok"\n'
        ),
        "cypher.js": (
            'const express = require("express");\nconst app = express();\n'
            'app.get("/nodes", async (req, res) => {\n'
            "  await session.run(`MATCH (n) WHERE n.id = '${req.query.id}' RETURN n`);\n"
            '  res.send("ok");\n'
            "});\n"
        ),
    })
    assert "BE010" in {f.rule_id for f in res.findings if f.file == "mongo_api.py"}
    assert len([f for f in res.findings if f.file == "mongo_api.py" and f.rule_id == "BE010"]) == 1
    assert len([f for f in res.findings if f.file == "graph_and_kusto.py" and f.rule_id == "BE022"]) == 2
    assert "BE022" in {f.rule_id for f in res.findings if f.file == "cypher.js"}


# ------------------------------------------------ fix --verify & rollback
def test_fix_verify_passes_and_rolls_back_on_regression(tmp_path: Path, capsys):
    target = tmp_path / "client.py"
    original = 'import requests\ndef fetch(url):\n    return requests.get(url, verify=False, timeout=10)\n'
    target.write_bytes(original.encode("utf-8"))

    # Without --apply returns 2
    assert cli_main(["fix", str(tmp_path), "--verify"]) == 2

    # Valid fix + --verify succeeds and persists edit
    rc = cli_main(["fix", str(tmp_path), "--apply", "--verify"])
    assert rc == 0
    assert "verify=True" in target.read_text(encoding="utf-8")

    # Rollback test when simulated post-scan introduces or retains finding
    target.write_bytes(original.encode("utf-8"))
    from vibeaudit import fix as fix_mod

    p = fix_mod.plan(str(tmp_path), ["BE013"])
    assert len(p.applied_changes if hasattr(p, "applied_changes") else p.changes) == 1
    p.apply()
    assert "verify=True" in target.read_text(encoding="utf-8")

    class FakeRes:
        findings = [Finding("BE999", "client.py", 1, "introduced", "high", "x", fingerprint="newfp")]

    ver = fix_mod.verify_plan(tmp_path, p, Options(offline=True, external="none"), scan_fn=lambda *_a, **_k: FakeRes())
    assert ver["ok"] is False and ver["rolled_back"] is True
    assert target.read_bytes() == original.encode("utf-8")


# ------------------------------------------------ scan --privacy-report
def test_scan_privacy_report_redacts_secrets_and_never_calls_network(tmp_path: Path, capsys, monkeypatch):
    def no_net(*_a, **_k):
        raise AssertionError("privacy-report must not open network connections")

    import socket

    monkeypatch.setattr(socket.socket, "connect", no_net)
    (tmp_path / "app.py").write_text(
        'import requests\nTOKEN = "sk_' + 'live_51HxQ2bL8tYv3kPzR9mN4wE7a"\n'
        'requests.get("https://example.com", verify=False)\n',
        encoding="utf-8",
    )
    rc = cli_main(["scan", str(tmp_path), "--offline", "--privacy-report"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "vibeaudit privacy-report:" in out and "nothing sent" in out
    assert "51HxQ2bL8tYv3kPzR9mN4wE7a" not in out


# ------------------------------------------------ Attack-path correlation & AI risk profile
def test_correlate_attack_paths_and_ai_risk_profile(tmp_path: Path):
    f_auth = Finding("AUTH001", "api.py", 10, "No auth", "high")
    f_sqli = Finding("BE001", "api.py", 14, "SQLi", "high")
    f_prompt = Finding("LLM027", ".mcp.json", 5, "Poisoned description", "high")
    f_tool = Finding("LLM005", "agent.py", 22, "Shell tool", "high")
    f_stub = Finding("AUTH008", "auth.py", 3, "Always True", "critical")

    paths = attack_paths([f_auth, f_sqli, f_prompt, f_tool, f_stub], [])
    ids = {p["id"] for p in paths}
    assert {"unauthenticated-exploit-chain", "agentic-prompt-to-action"} <= ids

    prof = ai_risk_profile([f_stub])
    assert prof["total_signals"] == 1 and prof["signals"]["placeholder_auth"] == 1

    res = scanner.scan(str(tmp_path), Options(offline=True, external="none"))
    assert "attack_paths" in res.meta and "ai_risk_profile" in res.meta
