"""Tests for parallel scanning (--jobs), content-hash scan cache, external config isolation, and JSON report schema."""
from __future__ import annotations

import concurrent.futures
import importlib.resources
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from vibeaudit import __version__, cli, external, feed, parse, report, scancache, store
from vibeaudit.scanner import Options, scan


def _make_poly_repo(root: Path, count_per_kind: int = 25) -> None:
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
    assert seq.meta["scan_cache"]["hit"] is False
    assert seq.meta["scan_cache"]["jobs"] == 1
    assert seq.meta["scan_cache"]["parallel_used"] is False
    assert par.meta["scan_cache"]["hit"] is False
    assert par.meta["scan_cache"]["jobs"] == 2
    assert par.meta["scan_cache"]["parallel_used"] is True

    def sig(res):
        return sorted((f.rule_id, f.file, f.line, f.severity, f.fingerprint) for f in res.findings)

    assert sig(par) == sig(seq)
    assert sorted((r.file, r.line, r.path, r.has_auth) for r in par.routes) == \
        sorted((r.file, r.line, r.path, r.has_auth) for r in seq.routes)
    assert par.score == seq.score
    assert par.grade == seq.grade


@pytest.mark.parametrize(
    ("fail_task", "exc_cls", "exc_msg"),
    [
        ("js", ValueError, "simulated js worker crash"),
        ("secrets", AssertionError, "simulated secrets invariant"),
        ("project", RuntimeError, "simulated project wave2 crash"),
        ("quality_ui", OSError, "simulated quality I/O error"),
    ],
)
def test_parallel_worker_exception_falls_back_sequentially_without_partial_leak(
    tmp_path, monkeypatch, fail_task, exc_cls, exc_msg
):
    _make_poly_repo(tmp_path, count_per_kind=25)
    seq = scan(str(tmp_path), Options(offline=True, external="none", cache=False, jobs=1))
    cancelled_tasks = []

    class _FakeFuture:
        def __init__(self, task_name: str, fn, args):
            self._task_name = task_name
            self._fn = fn
            self._args = args

        def result(self):
            if self._task_name == fail_task:
                raise exc_cls(exc_msg)
            return self._fn(*self._args)

        def cancel(self):
            cancelled_tasks.append(self._task_name)
            return True

    class _FakeExecutor:
        def __init__(self, max_workers=1):
            self.max_workers = max_workers

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def submit(self, fn, task_name, *args):
            return _FakeFuture(task_name, fn, (task_name, *args))

    monkeypatch.setattr(concurrent.futures, "ProcessPoolExecutor", _FakeExecutor)
    logs: list[str] = []
    par = scan(str(tmp_path), Options(offline=True, external="none", cache=False, jobs=2, log=logs.append))

    def sig(res):
        return sorted((f.rule_id, f.file, f.line, f.severity, f.fingerprint) for f in res.findings)

    assert sig(par) == sig(seq)
    assert par.score == seq.score
    assert par.grade == seq.grade
    assert par.meta["scan_cache"]["parallel_used"] is False
    fb = par.meta["scan_cache"]["parallel_fallback"]
    assert fb["reason"] == "worker_error"
    assert fb["task"] == fail_task
    assert exc_cls.__name__ in fb["error"] and exc_msg in fb["error"]
    assert any(fail_task in n and exc_cls.__name__ in n for n in par.meta["notes"])
    assert any("warning:" in entry and fail_task in entry for entry in logs)
    assert cancelled_tasks  # remaining wave futures were cancelled on failure


def test_parallel_pool_creation_error_falls_back_sequentially(tmp_path, monkeypatch):
    _make_poly_repo(tmp_path, count_per_kind=25)
    seq = scan(str(tmp_path), Options(offline=True, external="none", cache=False, jobs=1))

    class _BrokenPool:
        def __init__(self, max_workers=1):
            raise RuntimeError("pool init blocked")

    monkeypatch.setattr(concurrent.futures, "ProcessPoolExecutor", _BrokenPool)
    par = scan(str(tmp_path), Options(offline=True, external="none", cache=False, jobs=2))
    assert par.score == seq.score
    assert [(f.rule_id, f.file, f.line) for f in par.findings] == \
        [(f.rule_id, f.file, f.line) for f in seq.findings]
    fb = par.meta["scan_cache"]["parallel_fallback"]
    assert fb["reason"] == "pool_error"
    assert "RuntimeError" in fb["error"]


def test_persistent_scan_cache_telemetry_bounds_invalidation_and_corrupt_recovery(tmp_path, monkeypatch):
    monkeypatch.setenv("VIBEAUDIT_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(store, "ENABLED", True)
    proj = tmp_path / "proj"
    proj.mkdir()
    _make_poly_repo(proj, count_per_kind=3)

    cold = scan(str(proj), Options(offline=True, external="none"))
    assert cold.meta["scan_cache"]["hit"] is False
    assert cold.meta["scan_cache"]["reason"] == "miss"
    assert cold.meta["scan_cache"]["snapshot_bytes"] > 0
    assert cold.meta["scan_cache"]["cached_findings"] >= len(cold.findings)
    assert cold.meta["scan_cache"]["write_ms"] >= 0.0

    warm = scan(str(proj), Options(offline=True, external="none"))
    assert warm.meta["scan_cache"]["hit"] is True
    assert warm.meta["scan_cache"]["reason"] == "hit"
    assert warm.meta["scan_cache"]["snapshot_bytes"] == cold.meta["scan_cache"]["snapshot_bytes"]
    assert warm.meta["scan_cache"]["cached_findings"] == cold.meta["scan_cache"]["cached_findings"]
    assert warm.meta["scan_cache"]["read_ms"] >= 0.0
    assert [f.to_dict() for f in warm.findings] == [f.to_dict() for f in cold.findings]
    assert [r.to_dict() for r in warm.routes] == [r.to_dict() for r in cold.routes]
    assert warm.score == cold.score and warm.grade == cold.grade
    assert warm.meta["coverage"] == cold.meta["coverage"]

    # Bounded size limit rejects oversized cache files cleanly
    snap_files = [p for p in (tmp_path / "cache" / "scans").glob("*.json") if p.name != "secret_files.json"]
    assert len(snap_files) == 1
    monkeypatch.setattr(scancache, "MAX_SNAPSHOT_BYTES", 128)
    assert store.read_json(snap_files[0], max_bytes=128) is None
    oversized = scan(str(proj), Options(offline=True, external="none"))
    assert oversized.meta["scan_cache"]["hit"] is False
    assert oversized.meta["scan_cache"]["reason"] == "oversized"
    monkeypatch.setattr(scancache, "MAX_SNAPSHOT_BYTES", 20 * 1024 * 1024)

    # Corrupt, non-dict, format mismatch, and version mismatch snapshots recover cleanly
    for payload, expected_reason in (
        ("{not valid json!!!", "corrupt"),
        ("[]", "corrupt"),
        (json.dumps({"format": 999, "version": __version__, "fingerprint": "x", "findings": [], "routes": []}), "format_mismatch"),
        (json.dumps({"format": scancache.CACHE_FORMAT, "version": "0.0.0-bogus", "fingerprint": "x", "findings": [], "routes": []}), "version_mismatch"),
    ):
        snap_files[0].write_text(payload, encoding="utf-8")
        res = scan(str(proj), Options(offline=True, external="none"))
        assert res.meta["scan_cache"]["hit"] is False
        assert res.meta["scan_cache"]["reason"] == expected_reason

    # Corrupt finding entry triggers corrupt reason and rebuilds snapshot
    bad_snap = json.loads(snap_files[0].read_text(encoding="utf-8"))
    bad_snap["findings"] = [{"broken": True}]
    snap_files[0].write_text(json.dumps(bad_snap), encoding="utf-8")
    rebuilt = scan(str(proj), Options(offline=True, external="none"))
    assert rebuilt.meta["scan_cache"]["hit"] is False
    assert rebuilt.meta["scan_cache"]["reason"] == "corrupt"

    # Option & dependency state invalidation matrix
    base_opts = Options(offline=True, external="none")
    assert scan(str(proj), base_opts).meta["scan_cache"]["hit"] is True
    invalidation_cases = [
        Options(offline=True, external="none", max_file_bytes=200_000),
        Options(offline=True, external="none", file_timeout=10.0),
        Options(offline=True, external="none", auth_helpers=["custom_auth"]),
        Options(offline=True, external="none", sanitizers=["clean_html"]),
        Options(offline=True, external="none", public_paths=["/healthz"]),
        Options(offline=True, external="none", excludes=["*.md"]),
    ]
    for alt_opts in invalidation_cases:
        alt_res = scan(str(proj), alt_opts)
        assert alt_res.meta["scan_cache"]["hit"] is False
        assert alt_res.meta["scan_cache"]["reason"] == "fingerprint_mismatch"

    # Re-warm under base options (last invalidation case overwrote snapshot), then mutate parser mode, feed version, and file contents
    assert scan(str(proj), base_opts).meta["scan_cache"]["reason"] == "fingerprint_mismatch"
    assert scan(str(proj), base_opts).meta["scan_cache"]["hit"] is True
    monkeypatch.setattr(parse, "mode", lambda: {"go": "tree-sitter"})
    assert scan(str(proj), base_opts).meta["scan_cache"]["reason"] == "fingerprint_mismatch"
    assert scan(str(proj), base_opts).meta["scan_cache"]["hit"] is True
    monkeypatch.setattr(feed, "cached", lambda: {"version": "9999.01.01"})
    assert scan(str(proj), base_opts).meta["scan_cache"]["reason"] == "fingerprint_mismatch"

    # File edit invalidates snapshot cache cleanly
    (proj / "added.py").write_text("from flask import request\ndef p():\n    eval(request.args['x'])\n")
    edited = scan(str(proj), base_opts)
    assert edited.meta["scan_cache"]["hit"] is False
    assert any(f.file == "added.py" and f.rule_id == "BE003" for f in edited.findings)

    # --no-cache bypasses reading cache
    bypass = scan(str(proj), Options(offline=True, external="none", cache=False))
    assert bypass.meta["scan_cache"]["hit"] is False
    assert bypass.meta["scan_cache"]["reason"] == "disabled"


def test_concurrent_cache_writers_across_processes(tmp_path):
    proj = tmp_path / "proj"
    cache_dir = tmp_path / "shared_cache"
    proj.mkdir()
    _make_poly_repo(proj, count_per_kind=3)

    env = dict(os.environ)
    env["VIBEAUDIT_CACHE_DIR"] = str(cache_dir)
    env.pop("VIBEAUDIT_NO_CACHE", None)
    src_dir = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = src_dir + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")

    cmd = [
        sys.executable, "-m", "vibeaudit", "scan", str(proj),
        "--offline", "--external", "none", "--fail-on", "none", "--report", "json:-", "-q",
    ]
    procs = [subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env) for _ in range(4)]
    outputs = []
    for p in procs:
        out, err = p.communicate(timeout=60)
        assert p.returncode == 0, err.decode("utf-8", "replace")
        outputs.append(json.loads(out.decode("utf-8")))

    ref_findings = [(f["rule_id"], f["file"], f["line"], f["fingerprint"]) for f in outputs[0]["findings"]]
    for doc in outputs[1:]:
        assert [(f["rule_id"], f["file"], f["line"], f["fingerprint"]) for f in doc["findings"]] == ref_findings
        assert doc["summary"]["score"] == outputs[0]["summary"]["score"]

    scans_dir = cache_dir / "scans"
    snap_files = [p for p in scans_dir.glob("*.json") if p.name != "secret_files.json"]
    assert len(snap_files) == 1
    assert list(scans_dir.glob("*.tmp")) == []
    json.loads(snap_files[0].read_text(encoding="utf-8"))
    if (scans_dir / "secret_files.json").exists():
        json.loads((scans_dir / "secret_files.json").read_text(encoding="utf-8"))


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


def test_semgrep_no_config_isolation_and_partial_fallback(tmp_path, monkeypatch):
    # Use a Semgrep-only marker line so built-in BE003 deduplication does not mask Semgrep's findings.
    (tmp_path / "vuln.py").write_text("# semgrep-test-sink\ndef handle(data):\n    return data\n")
    (tmp_path / "clean.py").write_text("x = 1\n")
    (tmp_path / ".semgrepignore").write_text("vuln.py\n")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / ".semgrepignore").write_text("*.py\n")
    (sub / "nested.py").write_text("# semgrep-test-sink\ndef run(x):\n    return x\n")

    detected = external.detect_repo_configs(tmp_path)
    assert ".semgrepignore" in detected["semgrep"]
    assert "sub/.semgrepignore" in detected["semgrep"]

    def fake_semgrep(cmd):
        target = Path(cmd[-1])
        ignored = set()
        ig_file = target / ".semgrepignore"
        if ig_file.is_file():
            ignored = {ln.strip() for ln in ig_file.read_text(encoding="utf-8").splitlines() if ln.strip()}
        results = []
        for py_file in sorted(target.rglob("*.py")):
            rel = py_file.relative_to(target).as_posix()
            sub_ig = py_file.parent / ".semgrepignore"
            local_ignored = set()
            if sub_ig.is_file():
                local_ignored = {ln.strip() for ln in sub_ig.read_text(encoding="utf-8").splitlines() if ln.strip()}
            if rel in ignored or py_file.name in ignored or "*.py" in local_ignored:
                continue
            for idx, line in enumerate(py_file.read_text(encoding="utf-8").splitlines(), 1):
                if "semgrep-test-sink" in line:
                    results.append({
                        "check_id": "python.lang.security.audit.test-sink",
                        "path": str(py_file),
                        "start": {"line": idx},
                        "extra": {
                            "message": "Detected semgrep test sink",
                            "severity": "ERROR",
                            "lines": line,
                            "metadata": {"cwe": ["CWE-95: Eval Injection"]},
                        },
                    })
        return json.dumps({"results": results})

    monkeypatch.setattr(external, "_run", fake_semgrep)
    monkeypatch.setattr(external, "available", lambda n: n == "semgrep")

    # Project-config mode honors .semgrepignore and skips vuln.py
    unisolated = scan(str(tmp_path), Options(offline=False, external="semgrep", cache=False))
    unisolated_semgrep = [f for f in unisolated.findings if f.source == "semgrep"]
    assert not any(f.file == "vuln.py" for f in unisolated_semgrep)
    assert unisolated.meta["coverage"]["external"]["semgrep"]["isolation"] == "none"

    # --no-config stages a clean shadow tree omitting repo .semgrepignore files
    isolated = scan(str(tmp_path), Options(offline=False, external="semgrep", cache=False, no_config=True))
    semgrep_files = {f.file for f in isolated.findings if f.source == "semgrep"}
    assert "vuln.py" in semgrep_files
    assert "sub/nested.py" in semgrep_files
    ext_sem = isolated.meta["coverage"]["external"]["semgrep"]
    assert ext_sem["status"] == "complete" and ext_sem["isolation"] == "full"
    assert isolated.meta["coverage"]["overall_status"] == "complete"

    # Exceeding staging limits degrades transparently to partial isolation and partial overall coverage
    monkeypatch.setattr(external, "MAX_ISOLATION_STAGE_FILES", 1)
    partial = scan(str(tmp_path), Options(offline=False, external="semgrep", cache=False, no_config=True))
    part_sem = partial.meta["coverage"]["external"]["semgrep"]
    assert part_sem["status"] == "partial" and part_sem["isolation"] == "partial"
    assert partial.meta["coverage"]["overall_status"] == "partial"
    assert any("semgrep partially isolated" in r for r in partial.meta["coverage"]["incomplete_reasons"])


def _validate_against_report_schema(doc: dict, schema: dict) -> None:
    try:
        import jsonschema  # type: ignore[import-untyped]
    except ImportError:
        jsonschema = None
    if jsonschema is not None:
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(doc)
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
    pkg_schema_bytes = importlib.resources.files("vibeaudit").joinpath("data", "report.schema.json").read_bytes()
    repo_schema_path = Path(__file__).resolve().parents[1] / "src" / "vibeaudit" / "data" / "report.schema.json"
    assert pkg_schema_bytes == repo_schema_path.read_bytes()
    schema = json.loads(pkg_schema_bytes.decode("utf-8"))

    # 1. Clean repository
    clean_fixture = Path(__file__).resolve().parent / "fixtures" / "clean_app"
    clean_doc = json.loads(report.render_json(scan(str(clean_fixture), Options(offline=True, external="none", cache=False))))
    _validate_against_report_schema(clean_doc, schema)

    # 2. Multi-finding repository
    proj = tmp_path / "proj"
    proj.mkdir()
    _make_poly_repo(proj, count_per_kind=3)
    multi_doc = json.loads(report.render_json(scan(str(proj), Options(offline=True, external="none", cache=False))))
    assert len(multi_doc["findings"]) > 1
    _validate_against_report_schema(multi_doc, schema)

    # 3. Empty repository
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    empty_doc = json.loads(report.render_json(scan(str(empty_dir), Options(offline=True, external="none", cache=False))))
    _validate_against_report_schema(empty_doc, schema)
    assert empty_doc["summary"]["score"] is None and empty_doc["summary"]["grade"] == "N/A"

    # 4. Partial scan repository (oversized file skipped)
    partial_dir = tmp_path / "partial"
    partial_dir.mkdir()
    (partial_dir / "huge.py").write_text("x = '" + ("a" * 512) + "'\n")
    partial_doc = json.loads(report.render_json(scan(str(partial_dir), Options(offline=True, external="none", cache=False, max_file_bytes=64))))
    _validate_against_report_schema(partial_doc, schema)
    assert partial_doc["coverage"]["overall_status"] == "partial"


def test_cli_jobs_flag_validation(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    assert cli.main(["scan", str(tmp_path), "--offline", "--external", "none", "--jobs", "-1", "-q"]) == 2
    assert cli.main(["scan", str(tmp_path), "--offline", "--external", "none", "--no-cache", "--jobs", "0", "-q"]) == 0
