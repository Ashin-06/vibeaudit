"""Regression tests for v0.20.0 features: chunk-bounded history, timeline, coverage matrix, SEC006, and correlate."""
from __future__ import annotations

import json
import subprocess

from vibeaudit import cli, correlate, mcp_server, parse, secretscan
from vibeaudit.model import Finding
from vibeaudit.report import render_json, render_sarif, render_text
from vibeaudit.scanner import Options, scan


def _scan(path, **kw):
    kw.setdefault("offline", True)
    kw.setdefault("external", "none")
    return scan(str(path), Options(**kw))


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def test_git_history_single_huge_line_triggers_strict_chunk_byte_cap(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    # Single 200 KB line with zero embedded newlines: line-buffered reading would allocate 200 KB first.
    (tmp_path / "huge.txt").write_text("X" * 200_000)
    _git(tmp_path, "add", "huge.txt")
    _git(tmp_path, "commit", "-m", "huge line")

    res = secretscan.scan_git_history(tmp_path, lambda _f: None, max_commits=10, max_bytes=4096)
    assert res["status"] == "truncated_size"
    assert res["truncated"] is True
    assert res["bytes_scanned"] <= 4097


def test_git_history_exposure_timeline_tracks_first_last_and_current_status(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    leaked = "sk-ant-" + "api03-" + ("B" * 80)

    (tmp_path / "app.py").write_text(f"API_KEY = '{leaked}'\n")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-m", "c1")
    sha1 = subprocess.run(["git", "-C", str(tmp_path), "rev-parse", "--short=12", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()

    (tmp_path / "app.py").write_text(f"API_KEY = '{leaked}'\nDEBUG = 0\n")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-m", "c2")

    (tmp_path / "app.py").write_text("API_KEY = os.environ['API_KEY']\n")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-m", "c3 removed")

    res = _scan(tmp_path, history=True, history_commits=10)
    tl = res.meta["history"]["timeline"]
    assert len(tl) == 1
    item = tl[0]
    assert item["file"] == "app.py"
    assert item["first_commit"].startswith(sha1[:7])
    assert item["historical_exposure"] is True
    assert item["current_exposure"] is False
    assert leaked not in json.dumps(res.meta)


def test_coverage_matrix_tracks_complete_partial_reports_and_mcp(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "big.py").write_text("# " + ("A" * 500) + "\n")

    clean = _scan(tmp_path)
    cov_ok = clean.meta["coverage"]
    assert cov_ok["overall_status"] == "complete"
    assert cov_ok["config_mode"] == "project"
    assert cov_ok["scanners"]["python"]["status"] == "complete"
    assert cov_ok["scanners"]["go"]["status"] == "not_applicable"
    assert cov_ok["scanners"]["git_history"]["status"] == "not_applicable"

    no_cfg = _scan(tmp_path, no_config=True)
    assert no_cfg.meta["coverage"]["config_mode"] == "ignored (--no-config)"

    partial = _scan(tmp_path, max_file_bytes=200)
    cov_p = partial.meta["coverage"]
    assert cov_p["overall_status"] == "partial"
    assert cov_p["files_skipped_size"] == 1
    assert "big.py" in cov_p["scanners"]["python"]["skipped_files"]
    assert "Coverage: partial" in render_text(partial, color=False)

    jdoc = json.loads(render_json(partial))
    assert jdoc["coverage"]["overall_status"] == "partial"
    sdoc = json.loads(render_sarif(partial))
    assert sdoc["runs"][0]["properties"]["coverage"]["overall_status"] == "partial"
    assert sdoc["runs"][0]["invocations"][0]["executionSuccessful"] is False

    mcp_res = mcp_server.tool_scan_project({"path": str(tmp_path), "offline": True})
    assert mcp_res["coverage"]["overall_status"] == "complete"


def test_sec006_ignores_example_and_test_env_files_but_flags_real_secrets(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    secret = "sk_live_" + ("A1b2C3d4" * 4)
    for name in (".env.example.complete", ".env.test", ".env.testing-ci", ".env.local.demo", ".env.docker", ".env"):
        (tmp_path / name).write_text(f"STRIPE_KEY={secret}\nAPP_SECRET=real_secret_value_123456\n")
        _git(tmp_path, "add", "-f", name)
    _git(tmp_path, "commit", "-m", "env")

    sec006 = sorted(f.file for f in _scan(tmp_path).findings if f.rule_id == "SEC006")
    assert sec006 == [".env", ".env.docker"]


def test_parse_js_functions_supports_module_exports_and_correlate_compound_chains():
    if parse.parser("js") is not None:
        fns = parse.js_functions("js", "module.exports.findUser = async (id) => id;\n")
        assert fns and fns[0][0] == "findUser"

    findings = [
        Finding("LLM005", "agent.py", 10, "shell tool", "critical", category="llm"),
        Finding("LLM003", "agent.py", 4, "no max_tokens", "medium", category="llm"),
        Finding("BE019", "pay.py", 20, "client price", "high", category="backend"),
        Finding("DATA010", "pay.py", 25, "no transaction", "medium", category="data"),
    ]
    ids = {ap["id"] for ap in correlate.attack_paths(findings, [])}
    assert {"agentic-unbounded-privilege", "payment-compound-risk"} <= ids
    assert cli  # keep import checked cleanly
