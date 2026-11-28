"""Tests for init --mcp/--agent-hooks, --profile presets, baseline score delta trend, and shared parallel discovery."""
from __future__ import annotations

import importlib.resources
import json
import os

from vibeaudit import cli, config, files, parallel, report, scan
from vibeaudit.scanner import Options


def test_init_mcp_and_agent_hooks_clean_self_scan(tmp_path):
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".vscode").mkdir()
    (tmp_path / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")

    rc = cli.main(["init", str(tmp_path), "--mcp", "--agent-hooks", "--no-scan"])
    assert rc == 0
    assert (tmp_path / ".mcp.json").is_file()
    assert (tmp_path / ".cursor" / "mcp.json").is_file()
    assert (tmp_path / ".vscode" / "mcp.json").is_file()
    assert (tmp_path / ".claude" / "settings.json").is_file()

    mcp_data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert mcp_data["mcpServers"]["vibeaudit"]["args"] == ["mcp"]
    vs_data = json.loads((tmp_path / ".vscode" / "mcp.json").read_text(encoding="utf-8"))
    assert vs_data["servers"]["vibeaudit"]["args"] == ["mcp"]
    hooks_data = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert hooks_data["hooks"]["PostToolUse"][0]["matcher"] == "Write|Edit"

    # Generated agent/MCP configs must not trigger LLM016 self-findings
    res = scan(str(tmp_path), Options(offline=True, external="none", cache=False))
    assert not any(f.rule_id == "LLM016" for f in res.findings)


def test_profiles_cli_and_toml_precedence_and_schema(tmp_path):
    (tmp_path / "app.py").write_text("import os\nprint(os.getcwd())\n", encoding="utf-8")
    (tmp_path / "view.tsx").write_text("export function Hero() { return <img src='/a.png' />; }\n", encoding="utf-8")

    # ai-agent disables ui & quality while recording profile in meta
    out_json = tmp_path / "agent.json"
    rc = cli.main(["scan", str(tmp_path), "--offline", "--external", "none", "--profile", "ai-agent", "-r", f"json:{out_json}", "-q"])
    assert rc == 0
    doc = json.loads(out_json.read_text(encoding="utf-8"))
    assert doc["meta"]["profile"] == "ai-agent"
    assert not any(f["category"] in ("ui", "quality") for f in doc["findings"])

    schema = json.loads(importlib.resources.files("vibeaudit").joinpath("data", "report.schema.json").read_text(encoding="utf-8"))
    try:
        import jsonschema  # type: ignore[import-untyped]
    except ImportError:
        jsonschema = None
    if jsonschema is not None:
        jsonschema.Draft202012Validator(schema).validate(doc)

    # strict-ci fails on partial coverage and includes preview rules (QA001/UI001/etc.)
    (tmp_path / "big.py").write_text("x = '" + ("a" * 300) + "'\n", encoding="utf-8")
    rc_strict = cli.main(["scan", str(tmp_path), "--offline", "--external", "none", "--profile", "strict-ci", "--max-file-size", "64", "-q"])
    assert rc_strict == 1

    # Unknown profile in .vibeaudit.toml exits 2 cleanly
    (tmp_path / ".vibeaudit.toml").write_text('profile = "bogus"\n', encoding="utf-8")
    assert cli.main(["scan", str(tmp_path), "--offline", "--external", "none", "-q"]) == 2

    # Valid profile in pyproject.toml works via project_options
    (tmp_path / ".vibeaudit.toml").unlink()
    (tmp_path / "pyproject.toml").write_text('[tool.vibeaudit]\nprofile = "ai-agent"\n', encoding="utf-8")
    opts = config.project_options(str(tmp_path))
    assert opts.profile == "ai-agent"
    assert {"ui", "quality"} <= opts.disabled


def test_baseline_score_delta_trend_across_formats(tmp_path):
    (tmp_path / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
    base_path = tmp_path / "baseline.json"
    assert cli.main(["scan", str(tmp_path), "--offline", "--external", "none", "--write-baseline", str(base_path), "-q"]) == 0
    base_doc = json.loads(base_path.read_text(encoding="utf-8"))
    base_score = base_doc["summary"]["score"]

    # Force a higher baseline score to exercise negative delta formatting across text, md, json
    base_doc["summary"]["score"] = min(100, (base_score or 50) + 10) if (base_score or 50) < 90 else 100
    base_path.write_text(json.dumps(base_doc), encoding="utf-8")
    # Introduce a new high finding so score drops
    (tmp_path / "app.py").write_text("import requests\nrequests.get('https://example.com', verify=False)\n", encoding="utf-8")

    out_json = tmp_path / "cur.json"
    out_md = tmp_path / "cur.md"
    cli.main([
        "scan", str(tmp_path), "--offline", "--external", "none",
        "--baseline", str(base_path), "-r", f"json:{out_json}", "-r", f"md:{out_md}", "--fail-on", "none", "-q",
    ])
    cur_doc = json.loads(out_json.read_text(encoding="utf-8"))
    assert cur_doc["meta"]["baseline_score"] == base_doc["summary"]["score"]
    assert cur_doc["meta"]["score_delta"] == cur_doc["summary"]["score"] - base_doc["summary"]["score"]
    assert "vs baseline" in out_md.read_text(encoding="utf-8")

    res = scan(str(tmp_path), Options(offline=True, external="none", cache=False, baseline=str(base_path)))
    txt = report.render_text(res, color=False, verbose=False)
    assert "vs baseline" in txt


def test_parallel_workers_reuse_prediscovered_without_rewalking(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
    (tmp_path / "b.js").write_text("export const x = 1;\n", encoding="utf-8")
    project = files.Project(tmp_path)
    snapshot = parallel._export_discovered(project)

    def _boom(*_args, **_kwargs):
        raise AssertionError("worker must reuse prediscovered files without os.walk / git ls-files")

    monkeypatch.setattr(os, "walk", _boom)
    monkeypatch.setattr(files, "_git", _boom)
    worker_proj = files.Project(tmp_path, prediscovered=snapshot)
    assert [f.rel for f in worker_proj.files] == [f.rel for f in project.files]
