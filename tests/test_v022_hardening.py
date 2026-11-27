"""Tests for v0.22.0 production-hardening features."""
from __future__ import annotations

import hashlib
import json
import zipfile

import pytest

from vibeaudit import bundle, cli, config, external, report
from vibeaudit.model import Finding
from vibeaudit.scanner import scan


def test_empty_directory_reports_na_and_exits_1_unless_allowed(tmp_path, capsys):
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    sarif = tmp_path / "out.sarif"
    rc = cli.main(["scan", str(empty_dir), "--offline", "--external", "none", "--no-color", "--report", f"sarif:{sarif}"])
    out = capsys.readouterr()
    assert rc == 1
    assert "Score: N/A  Grade: N/A" in out.out
    assert "0 files were scanned" in out.err
    assert json.loads(sarif.read_text())["runs"][0]["properties"]["score_model"] == "diminishing-v2"

    # --allow-empty exits 0 while still reporting N/A and null score
    rc_ok = cli.main(["scan", str(empty_dir), "--offline", "--external", "none", "--allow-empty", "--report", "json:-"])
    json_out = capsys.readouterr().out
    assert rc_ok == 0
    doc = json.loads(json_out)
    assert doc["summary"]["score"] is None
    assert doc["summary"]["grade"] == "N/A"
    assert doc["summary"]["score_model"] == "diminishing-v2"


def test_over_broad_exclude_also_fails_empty_scan(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    assert cli.main(["scan", str(tmp_path), "--offline", "--external", "none", "--exclude", "*.py", "-q"]) == 1
    assert cli.main(["scan", str(tmp_path), "--offline", "--external", "none", "--exclude", "*.py", "--allow-empty", "-q"]) == 0


def test_empty_renderers_badge_html_markdown():
    empty = report.Result("/p", [], {"files_scanned": 0})
    assert empty.is_empty_scan
    assert empty.score is None and empty.grade == "N/A"
    assert "vibeaudit: N/A" in report.render_badge(empty)
    assert "Score</span><b>N/A</b>Grade N/A" in report.render_html(empty)
    assert "**Score: N/A (grade N/A, no files scanned)**" in report.render_markdown(empty)


def test_versioned_score_model_diminishing_vs_linear(tmp_path, capsys):
    for i in range(6):
        (tmp_path / f"f{i}.py").write_text("eval(user_input)\n")
    findings = [Finding("BE003", f"f{i}.py", 1, "m", "high", title="t", category="backend") for i in range(6)]
    r_v2 = report.Result(str(tmp_path), findings, {"files_scanned": 100, "score_model": "diminishing-v2"})
    r_v1 = report.Result(str(tmp_path), findings, {"files_scanned": 100, "score_model": "linear-v1"})
    assert r_v2.score_model == "diminishing-v2"
    assert r_v1.score_model == "linear-v1"
    assert r_v1.score == 40
    assert r_v2.score is not None and r_v2.score > r_v1.score

    rc = cli.main(["scan", str(tmp_path), "--offline", "--external", "none", "--fail-on", "none",
                   "--score-model", "linear-v1", "--report", "json:-"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["score_model"] == "linear-v1"
    assert doc["summary"]["score"] == doc["summary"]["linear_score"]


def test_rules_json_shorthand_flag(capsys):
    assert cli.main(["rules", "--json"]) == 0
    via_alias = json.loads(capsys.readouterr().out)
    assert cli.main(["rules", "--format", "json"]) == 0
    via_fmt = json.loads(capsys.readouterr().out)
    assert via_alias == via_fmt


def test_fix_max_tokens_and_llm011_note(tmp_path, capsys):
    (tmp_path / "ai.py").write_text(
        "import json\nfrom openai import OpenAI\nclient = OpenAI()\n\n"
        "def ask(q):\n"
        "    r = client.chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': q}])\n"
        "    return json.loads(r.choices[0].message.content)\n"
    )
    assert cli.main(["fix", str(tmp_path), "--max-tokens", "0"]) == 2
    capsys.readouterr()
    rc = cli.main(["fix", str(tmp_path), "--max-tokens", "2048"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "max_completion_tokens=2048" in captured.out
    assert "fall back to None/null" in captured.err


def test_bundle_total_uncompressed_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(bundle, "MAX_BUNDLE_UNCOMPRESSED", 5000)
    monkeypatch.setattr(bundle, "cache_dir", lambda: tmp_path / "cache")
    payload = b"x" * 3000
    h = hashlib.sha256(payload).hexdigest()
    path = tmp_path / "over_total.zip"
    with zipfile.ZipFile(path, "w") as z:
        manifest = {"format": bundle.FORMAT, "files": {
            "data/pypi_top.txt.gz": {"sha256": h, "size": len(payload)},
            "data/npm_top.txt.gz": {"sha256": h, "size": len(payload)},
        }}
        z.writestr("manifest.json", json.dumps(manifest))
        z.writestr("data/pypi_top.txt.gz", payload)
        z.writestr("data/npm_top.txt.gz", payload)
    with pytest.raises(bundle.BundleError, match="uncompressed size"):
        bundle.import_bundle(path, lambda _m: None)


def test_external_run_tool_isolates_configs_when_no_config(tmp_path, monkeypatch):
    recorded: list[list[str]] = []

    def fake_run(cmd):
        recorded.append(list(cmd))
        return "{}"

    monkeypatch.setattr(external, "_run", fake_run)
    external.run_tool("bandit", tmp_path, no_config=True)
    external.run_tool("semgrep", tmp_path, no_config=True)
    external.run_tool("osv-scanner", tmp_path, no_config=True)
    external.run_tool("gitleaks", tmp_path, no_config=True)

    assert any(cmd[0] == "bandit" and "-c" in cmd for cmd in recorded)
    assert any(cmd[0] == "semgrep" and "--no-git-ignore" in cmd for cmd in recorded)
    assert any(cmd[0] == "osv-scanner" and "--config" in cmd for cmd in recorded)
    assert any(cmd[0] == "gitleaks" and "--ignore-gitleaks-allow" in cmd for cmd in recorded)


def test_project_config_disabling_rules_records_warning_and_note(tmp_path, capsys):
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / ".vibeaudit.toml").write_text('disable = ["BE003", "quality"]\nscore-model = "linear-v1"\nallow-empty = true\n')
    cfg, path = config.load(tmp_path)
    assert path is not None and cfg["score_model"] == "linear-v1" and cfg["allow_empty"] is True
    res = scan(str(tmp_path), config.project_options(str(tmp_path), offline=True, external="none"))
    assert res.meta["config_disabled"] == ["BE003", "quality"]
    assert any("Project config disables" in n for n in res.meta["notes"])
