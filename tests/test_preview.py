"""Preview rules (STABILITY.md): reported, but left out of --fail-on and the score unless --include-preview."""
import json

from vibeaudit.cli import main
from vibeaudit.rules import RULES

PREVIEW_ONLY = "export function show(el, data) {\n  el.innerHTML = data;\n}\n"  # FE001, a preview rule


def _scan(tmp_path, capsys, *args):
    code = main(["scan", str(tmp_path), "--offline", "--external", "none", "--fail-on", "medium",
                 "--report", "json:-", *args])
    return code, json.loads(capsys.readouterr().out)


def test_preview_findings_are_reported_but_do_not_fail_or_lower_the_score(tmp_path, capsys):
    assert RULES["FE001"].preview and RULES["FE001"].preview_reason
    (tmp_path / "show.js").write_text(PREVIEW_ONLY)
    code, out = _scan(tmp_path, capsys)
    assert [(f["rule_id"], f.get("preview")) for f in out["findings"]] == [("FE001", True)]
    assert code == 0 and out["summary"]["score"] == 100
    code, out = _scan(tmp_path, capsys, "--include-preview")
    assert code == 1 and out["summary"]["score"] < 100


def test_include_preview_from_the_config_file(tmp_path, capsys):
    (tmp_path / "show.js").write_text(PREVIEW_ONLY)
    (tmp_path / ".vibeaudit.toml").write_text("include-preview = true\n")
    assert _scan(tmp_path, capsys)[0] == 1
    assert _scan(tmp_path, capsys, "--no-config")[0] == 0


def test_stable_findings_still_fail_next_to_preview_ones(tmp_path, capsys):
    (tmp_path / "show.js").write_text(PREVIEW_ONLY)
    (tmp_path / "a.py").write_text("import os\nos.system('ls ' + x)\n")  # BE002, stable
    code, out = _scan(tmp_path, capsys)
    assert code == 1 and sorted(f["rule_id"] for f in out["findings"]) == ["BE002", "FE001"]
