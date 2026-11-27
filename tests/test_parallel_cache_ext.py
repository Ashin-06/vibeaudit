"""Tests for parallel scanning (--jobs), content-hash scan cache, external config isolation, and JSON report schema."""
from __future__ import annotations

import importlib.resources
import json

from vibeaudit import cli, external, report, store
from vibeaudit.scanner import Options, scan


def _make_poly_repo(root, count_per_kind: int = 25) -> None:
    (root / "package.json").write_text('{"name": "app", "dependencies": {"express": "4.19.0"}}\n')
    (root / "package-lock.json").write_text("{}\n")
    (root / "requirements.txt").write_text("flask==3.0.3\n")
    (root / "helpers.py").write_text("import os\n\ndef run_shell(cmd: str):\n    os.system(cmd)\n")
    (root / "routes.py").write_text(
        "from flask import Flask, request\nfrom helpers import run_shell\n"
        "app = Flask(__name__)\n\n"
        "@app.post('/run')\ndef do_run():\n    return str(run_shell(request.args['cmd']))\n"
    )
    (root / "server.js").write_text(
        "const express = require('express');\nconst app = express();\n"
        "app.post('/echo', (req, res) => { res.send(req.query.msg); });\n"
    )
    (root / "Dockerfile").write_text("FROM python:3.12\nCOPY . /app\n")
    for i in range(count_per_kind):
        sub = root / f"pkg_{i % 5}"
        sub.mkdir(exist_ok=True)
        (sub / f"mod_{i}.py").write_text(f"def f_{i}(x):\n    return x + {i}\n")
        (sub / f"comp_{i}.ts").write_text(f"export const v_{i} = (x: number) => x + {i};\n")
        (sub / f"note_{i}.md").write_text(f"# Doc {i}\n")


def test_parallel_scan_matches_sequential_exactly(tmp_path):
    _make_poly_repo(tmp_path, count_per_kind=25)  # > 64 files to trigger ProcessPoolExecutor
    seq = scan(str(tmp_path), Options(offline=True, external="none", cache=False, jobs=1))
    par = scan(str(tmp_path), Options(offline=True, external="none", cache=False, jobs=2))

    assert seq.meta["files_scanned"] >= 64
    assert par.meta["scan_cache"] == {"hit": False, "jobs": 2}
    assert seq.meta["scan_cache"] == {"hit": False, "jobs": 1}

    def sig(res):
        return sorted((f.rule_id, f.file, f.line, f.severity, f.fingerprint) for f in res.findings)

    assert sig(par) == sig(seq)
    assert sorted((r.file, r.line, r.path, r.has_auth) for r in par.routes) == \
        sorted((r.file, r.line, r.path, r.has_auth) for r in seq.routes)
    assert par.score == seq.score
    assert par.grade == seq.grade


def test_persistent_scan_cache_hit_invalidation_and_corrupt_recovery(tmp_path, monkeypatch):
    monkeypatch.setenv("VIBEAUDIT_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(store, "ENABLED", True)
    proj = tmp_path / "proj"
    proj.mkdir()
    _make_poly_repo(proj, count_per_kind=3)

    cold = scan(str(proj), Options(offline=True, external="none"))
    assert cold.meta["scan_cache"]["hit"] is False

    warm = scan(str(proj), Options(offline=True, external="none"))
    assert warm.meta["scan_cache"]["hit"] is True
    assert [(f.rule_id, f.file, f.line, f.fingerprint) for f in warm.findings] == \
        [(f.rule_id, f.file, f.line, f.fingerprint) for f in cold.findings]
    assert warm.score == cold.score

    # File edit invalidates snapshot cache cleanly
    (proj / "added.py").write_text("from flask import request\ndef p():\n    eval(request.args['x'])\n")
    edited = scan(str(proj), Options(offline=True, external="none"))
    assert edited.meta["scan_cache"]["hit"] is False
    assert any(f.file == "added.py" and f.rule_id == "BE003" for f in edited.findings)

    # Options change invalidates snapshot cache
    changed_opts = scan(str(proj), Options(offline=True, external="none", auth_helpers=["custom_auth"]))
    assert changed_opts.meta["scan_cache"]["hit"] is False

    # --no-cache bypasses reading cache
    bypass = scan(str(proj), Options(offline=True, external="none", cache=False))
    assert bypass.meta["scan_cache"]["hit"] is False

    # Corrupt cache file degrades gracefully
    for snap in (tmp_path / "cache" / "scans").glob("*.json"):
        snap.write_text("{not valid json!!!", encoding="utf-8")
    recovered = scan(str(proj), Options(offline=True, external="none"))
    assert recovered.meta["scan_cache"]["hit"] is False


def test_external_repo_config_detection_warning_and_gitleaks_isolation(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / ".gitleaks.toml").write_text("[allowlist]\npaths = ['''.*''']\n")
    (tmp_path / ".gitleaksignore").write_text("abc:1\n")
    (tmp_path / ".bandit").write_text("[bandit]\nskips: B101\n")
    (tmp_path / ".semgrepignore").write_text("*.py\n")
    (tmp_path / "osv-scanner.toml").write_text("[[IgnoredVulns]]\nid = 'GHSA-1'\n")

    detected = external.detect_repo_configs(tmp_path)
    assert ".gitleaks.toml" in detected["gitleaks"] and ".gitleaksignore" in detected["gitleaks"]
    assert ".bandit" in detected["bandit"]
    assert ".semgrepignore" in detected["semgrep"]
    assert "osv-scanner.toml" in detected["osv-scanner"]

    seen_cmds = []

    def fake_run(cmd):
        seen_cmds.append(list(cmd))
        return "[]"

    monkeypatch.setattr(external, "_run", fake_run)
    external.run_tool("gitleaks", tmp_path, no_config=True)
    gl_cmd = seen_cmds[0]
    assert "--config" in gl_cmd and "--gitleaks-ignore-path" in gl_cmd and "--ignore-gitleaks-allow" in gl_cmd

    monkeypatch.setattr(external, "available", lambda n: n == "gitleaks")
    monkeypatch.setattr(external, "run_tool", lambda n, r, no_cfg=False: [])
    res = scan(str(tmp_path), Options(offline=True, external="gitleaks", cache=False))
    assert "gitleaks" in res.meta["external_configs_detected"]
    assert any("Repo-local external scanner config" in n for n in res.meta["notes"])

    res_iso = scan(str(tmp_path), Options(offline=True, external="gitleaks", cache=False, no_config=True))
    assert "gitleaks" in res_iso.meta["external_configs_detected"]
    assert not any("Repo-local external scanner config" in n for n in res_iso.meta["notes"])


def _validate_against_report_schema(doc: dict, schema: dict) -> None:
    for req in schema["required"]:
        assert req in doc, f"missing top-level key {req}"
    assert doc["tool"] == "vibeaudit"
    assert isinstance(doc["version"], str) and doc["version"]
    s_req = schema["properties"]["summary"]["required"]
    for req in s_req:
        assert req in doc["summary"], f"missing summary.{req}"
    assert doc["summary"]["score_model"] in ("diminishing-v2", "linear-v1")
    assert doc["summary"]["grade"] in ("A", "B", "C", "D", "F", "N/A")
    assert isinstance(doc["summary"]["score"], (int, type(None)))
    assert doc["coverage"]["overall_status"] in ("complete", "partial")
    f_req = schema["properties"]["findings"]["items"]["required"]
    for f in doc["findings"]:
        for req in f_req:
            assert req in f, f"missing finding.{req}"
    r_req = schema["properties"]["routes"]["items"]["required"]
    for r in doc["routes"]:
        for req in r_req:
            assert req in r, f"missing route.{req}"


def test_json_report_matches_shipped_schema(tmp_path):
    schema = json.loads(importlib.resources.files("vibeaudit").joinpath("data", "report.schema.json").read_text(encoding="utf-8"))
    proj = tmp_path / "proj"
    proj.mkdir()
    _make_poly_repo(proj, count_per_kind=2)
    doc = json.loads(report.render_json(scan(str(proj), Options(offline=True, external="none", cache=False))))
    _validate_against_report_schema(doc, schema)

    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    empty_doc = json.loads(report.render_json(scan(str(empty_dir), Options(offline=True, external="none", cache=False))))
    _validate_against_report_schema(empty_doc, schema)
    assert empty_doc["summary"]["score"] is None and empty_doc["summary"]["grade"] == "N/A"


def test_cli_jobs_flag_validation(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    assert cli.main(["scan", str(tmp_path), "--offline", "--external", "none", "--jobs", "-1", "-q"]) == 2
    assert cli.main(["scan", str(tmp_path), "--offline", "--external", "none", "--no-cache", "--jobs", "0", "-q"]) == 0
