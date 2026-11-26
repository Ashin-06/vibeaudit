"""Tests for v0.17.0 features: getattr/globals dynamic dispatch, data-driven LLM defaults, normalized scoring, git history secrets, AI-BOM export, and Next.js matcher gap."""
from __future__ import annotations

import json
import subprocess

from vibeaudit import aibom, cli, report
from vibeaudit.model import Finding
from vibeaudit.scanner import Options, scan


def _scan(path, **kw):
    kw.setdefault("offline", True)
    kw.setdefault("external", "none")
    return scan(str(path), Options(**kw))


def _lines(res, rule):
    return sorted(f.line for f in res.findings if f.rule_id == rule)


def test_getattr_and_globals_dynamic_dispatch_reported_as_be003(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import Flask, request\napp = Flask(__name__)\n"
        "ALLOWED = {'strip', 'lower'}\n\n"
        "@app.get('/direct')\ndef direct():\n"
        "    return str(getattr(os, request.args['f'])('id'))\n\n"
        "@app.get('/assigned')\ndef assigned():\n"
        "    fn = getattr(os, request.args['f'])\n"
        "    return str(fn('id'))\n\n"
        "@app.get('/globals')\ndef glob():\n"
        "    fn = globals()[request.args['f']]\n"
        "    return str(fn())\n\n"
        "@app.get('/read_only')\ndef read_only(user=None):\n"
        "    return str(getattr(user, request.args['field']))\n\n"
        "@app.get('/allow')\ndef allow():\n"
        "    name = request.args['f']\n"
        "    if name not in ALLOWED:\n        raise ValueError('bad')\n"
        "    return getattr('ok', name)()\n"
    )
    assert _lines(_scan(tmp_path), "BE003") == [8, 13, 18]


def test_normalized_score_scales_with_repo_size_and_raw_penalty():
    findings = [Finding("BE001", "a.py", i, "sql", "high", category="backend") for i in range(1, 21)]
    small = report.Result("/small", findings, {"files_scanned": 5})
    large = report.Result("/large", findings, {"files_scanned": 500})
    assert small.linear_score == 0 and large.linear_score == 0
    assert small.raw_penalty == 200 and large.raw_penalty == 200
    assert large.score > small.score > 0
    assert large.score == large.normalized_score
    assert large.density_per_100_files < small.density_per_100_files
    doc = json.loads(report.render_json(large))
    assert doc["summary"]["score"] == large.score
    assert doc["summary"]["normalized_score"] == large.normalized_score
    assert doc["summary"]["linear_score"] == 0
    assert doc["summary"]["raw_penalty"] == 200
    assert "raw penalty: 200" in report.render_text(large, color=False)

    clean = report.Result("/clean", [], {"files_scanned": 100})
    assert clean.score == 100 and clean.normalized_score == 100 and clean.raw_penalty == 0


def test_git_history_secret_scanning_finds_deleted_provider_key_and_masks_snippet(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@example.com"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Test"], check=True, capture_output=True)
    leaked = "sk-ant-" + "api03-" + ("A" * 80)
    (tmp_path / "app.py").write_text(f"API_KEY = '{leaked}'\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "app.py"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", "oops"], check=True, capture_output=True)
    (tmp_path / "app.py").write_text("API_KEY = os.environ['API_KEY']\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "app.py"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", "remove key"], check=True, capture_output=True)

    without = _scan(tmp_path, history=False)
    assert [f for f in without.findings if f.rule_id == "SEC001"] == []

    with_hist = _scan(tmp_path, history=True, history_commits=20)
    hits = [f for f in with_hist.findings if f.rule_id == "SEC001"]
    assert len(hits) == 1
    assert "git history" in hits[0].message
    assert leaked not in hits[0].snippet
    assert leaked not in hits[0].message


def test_aibom_report_emits_valid_cyclonedx_16(tmp_path):
    (tmp_path / "requirements.txt").write_text("openai==1.50.0\n")
    (tmp_path / "app.py").write_text(
        "import openai\nMODEL = 'gpt-4.1-mini'\n"
        "def run():\n    return openai.OpenAI().chat.completions.create(model='gpt-3.5-turbo-0613', messages=[], max_tokens=100)\n"
    )
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"docs": {"command": "npx", "args": ["docs@1.0.0"]}}}))
    (tmp_path / "CLAUDE.md").write_text("# Instructions\nBe safe.\n")

    res = _scan(tmp_path)
    out = tmp_path / "ai-bom.cdx.json"
    assert cli.main(["scan", str(tmp_path), "--offline", "--external", "none", "--fail-on", "none", "-r", f"aibom:{out}"]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    names = {c["name"]: c for c in doc["components"]}
    assert "OpenAI SDK" in names and names["OpenAI SDK"]["type"] == "library"
    assert "gpt-3.5-turbo-0613" in names and names["gpt-3.5-turbo-0613"]["type"] == "machine-learning-model"
    assert {"name": "vibeaudit:ai:retired", "value": "true"} in names["gpt-3.5-turbo-0613"]["properties"]
    assert "docs" in names and names["docs"]["type"] == "service"
    assert "CLAUDE.md" in names and names["CLAUDE.md"]["type"] == "data"


def test_nextjs_middleware_matcher_excludes_unauthenticated_api(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"next": "15.0.0", "next-auth": "5.0.0"}}')
    (tmp_path / "middleware.ts").write_text(
        "import { auth as middleware } from '@/auth';\nexport default middleware;\n"
        "export const config = { matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'] };\n"
    )
    api = tmp_path / "app" / "api" / "items"
    api.mkdir(parents=True)
    (api / "route.ts").write_text("export async function POST(req: Request) { return db.item.create({ data: {} }); }\n")
    res = _scan(tmp_path)
    assert _lines(res, "AUTH018") == [3]

    (tmp_path / "middleware.ts").write_text(
        "import { auth as middleware } from '@/auth';\nexport default middleware;\n"
        "export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };\n"
    )
    assert _lines(_scan(tmp_path), "AUTH018") == []
