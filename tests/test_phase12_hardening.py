"""Tests for Phase 1 & Phase 2 hardening: subfolder QA001/QA002, VIBEAUDIT_MCP_ROOTS, and fix symlink guard."""
from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from vibeaudit import fix, mcp_server
from vibeaudit.model import Finding
from vibeaudit.scanner import Options, scan


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_subfolder_scan_finds_tests_and_ci_at_git_root(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: CI\non: [push]\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("def test_ok():\n    assert True\n")
    src = tmp_path / "src"
    src.mkdir()
    for i in range(4):
        (src / f"m{i}.py").write_text(f"def fn_{i}():\n    return {i}\n")

    res = scan(str(src), Options(offline=True, external="none"))
    rules = {f.rule_id for f in res.findings}
    assert "QA001" not in rules
    assert "QA002" not in rules

    # Subfolder inside a git repo that genuinely lacks both tests and CI must still report them
    bare_repo = tmp_path / "bare_repo"
    bare_repo.mkdir()
    subprocess.run(["git", "init"], cwd=bare_repo, check=True, capture_output=True)
    sub = bare_repo / "src"
    sub.mkdir()
    for i in range(4):
        (sub / f"m{i}.py").write_text(f"def fn_{i}():\n    return {i}\n")
    res_missing = scan(str(sub), Options(offline=True, external="none"))
    missing_rules = {f.rule_id for f in res_missing.findings}
    assert {"QA001", "QA002"} <= missing_rules


def test_mcp_roots_allowlist_restricts_paths(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    sub = allowed / "proj"
    sub.mkdir(parents=True)
    (sub / "app.py").write_text("x = 1\n")
    (sub / "mig.sql").write_text("SELECT 1;\n")
    outside = tmp_path / "secret_dir"
    outside.mkdir()
    (outside / "app.py").write_text("eval(x)\n")
    (outside / "mig.sql").write_text("DROP TABLE users;\n")

    monkeypatch.setenv("VIBEAUDIT_MCP_ROOTS", str(allowed))
    # Allowed directory and file calls succeed
    ok_proj = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                 "params": {"name": "scan_project", "arguments": {"path": str(sub)}}})
    assert ok_proj["result"]["isError"] is False

    ok_file = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                 "params": {"name": "scan_file", "arguments": {"file": str(sub / "app.py"), "project": str(sub)}}})
    assert ok_file["result"]["isError"] is False

    # Outside root calls rejected across path-taking tools
    for tool, args in (
        ("scan_project", {"path": str(outside)}),
        ("list_routes", {"path": str(outside)}),
        ("auto_repair", {"path": str(outside)}),
        ("scan_file", {"file": str(outside / "app.py"), "project": str(outside)}),
        ("audit_current_file", {"file": str(outside / "app.py"), "project": str(outside)}),
        ("simulate_migration", {"path": str(outside / "mig.sql")}),
        ("scan_project", {"path": str(tmp_path / "does_not_exist")}),
    ):
        err = mcp_server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": tool, "arguments": args}})
        assert err["result"]["isError"] is True
        assert "VIBEAUDIT_MCP_ROOTS" in err["result"]["content"][0]["text"]

    # Multiple roots separated by os.pathsep
    second = tmp_path / "second"
    second.mkdir()
    (second / "ok.py").write_text("x = 1\n")
    monkeypatch.setenv("VIBEAUDIT_MCP_ROOTS", f"{allowed}{os.pathsep}{second}")
    ok_second = mcp_server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                   "params": {"name": "scan_project", "arguments": {"path": str(second)}}})
    assert ok_second["result"]["isError"] is False


def test_mcp_roots_blocks_symlink_escape(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    secret_file = outside / "secret.py"
    secret_file.write_text("eval(x)\n")
    link = allowed / "escape.py"
    try:
        link.symlink_to(secret_file)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform")
    monkeypatch.setenv("VIBEAUDIT_MCP_ROOTS", str(allowed))
    res = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                             "params": {"name": "scan_file", "arguments": {"file": str(link), "project": str(allowed)}}})
    assert res["result"]["isError"] is True
    assert "VIBEAUDIT_MCP_ROOTS" in res["result"]["content"][0]["text"]


def test_fix_skips_and_refuses_symlinks(tmp_path):
    target = tmp_path / "real.py"
    target.write_text("import requests\nrequests.get('https://example.com')\n")
    link = tmp_path / "link.py"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform")

    f = Finding("REL001", "link.py", 2, "missing timeout", "medium", title="t", category="reliability")
    f.compute_fingerprint()
    planned = fix.plan_findings(tmp_path, [f])
    assert planned.changes == []
    assert any("symlink" in reason for _f, reason in planned.skipped)

    # Even if a Change is constructed directly pointing at a symlink, apply() and verify_plan() refuse it
    raw_change = fix.Change("link.py", link, target.read_bytes(), target.read_text(), "# changed\n", "\n", False, [f])
    direct = fix.Plan(tmp_path, [raw_change])
    assert direct.apply() == []
    assert link.is_symlink()
    assert target.read_text().startswith("import requests")

    direct.written = [raw_change]
    ver = fix.verify_plan(tmp_path, direct, None, scan_fn=lambda *_: type("R", (), {"findings": [f]})())
    assert ver["rolled_back_files"] == []
    assert link.is_symlink()
