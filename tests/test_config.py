"""Project configuration files and how they combine with command line flags."""
import json

import pytest

from vibeaudit.cli import main
from vibeaudit.config import ConfigError, load, parse

VULN = "import os\nos.system('ls ' + x)\ntry:\n    pass\nexcept Exception:\n    pass\n"


def _json(tmp_path, capsys, *args):
    code = main(["scan", str(tmp_path), "--offline", "--external", "none", "--report", "json:-", *args])
    out = json.loads(capsys.readouterr().out)
    return code, sorted(f["rule_id"] for f in out["findings"])


def test_vibeaudit_toml_settings_apply(tmp_path, capsys):
    (tmp_path / "a.py").write_text(VULN)
    (tmp_path / "legacy").mkdir()
    (tmp_path / "legacy" / "old.py").write_text("eval(x)\n")
    (tmp_path / ".vibeaudit.toml").write_text('disable = ["QA003"]\nexclude = ["legacy"]\nfail-on = "critical"\n')
    code, rules = _json(tmp_path, capsys)
    assert rules == ["BE002"] and code == 0  # BE002 here is medium, below fail-on = critical


def test_pyproject_tool_table_and_cli_override(tmp_path, capsys):
    (tmp_path / "a.py").write_text(VULN)
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n\n[tool.vibeaudit]\nmin-severity = "medium"\n')
    assert _json(tmp_path, capsys)[1] == ["BE002"]
    assert _json(tmp_path, capsys, "--min-severity", "low")[1] == ["BE002", "QA003"]


def test_no_config_and_explicit_config(tmp_path, capsys):
    (tmp_path / "a.py").write_text(VULN)
    (tmp_path / ".vibeaudit.toml").write_text('disable = ["BE002", "QA003"]\n')
    assert _json(tmp_path, capsys)[1] == []
    assert _json(tmp_path, capsys, "--no-config")[1] == ["BE002", "QA003"]
    other = tmp_path / "ci.toml"
    other.write_text('disable = ["QA003"]\n')
    assert _json(tmp_path, capsys, "--config", str(other))[1] == ["BE002"]


@pytest.mark.parametrize("text,message", [
    ("fail_on = 'loud'\n", "fail_on"),
    ("exclude = 'legacy'\n", "list of strings"),
    ("offline = 'yes'\n", "boolean"),
    ("file-timeout = 0\n", "number"),
    ("dissable = ['QA001']\n", "unknown setting"),
    ("llm = 'gpt'\n", "llm"),
    ("[broken\n", "cannot read TOML"),
])
def test_invalid_settings_are_errors(tmp_path, capsys, text, message):
    (tmp_path / ".vibeaudit.toml").write_text(text)
    with pytest.raises(ConfigError, match=message):
        load(tmp_path)
    assert main(["scan", str(tmp_path), "--offline", "--external", "none", "-q"]) == 2
    assert message.split()[0] in capsys.readouterr().err


def test_unrelated_or_broken_pyproject_is_ignored(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project\n")
    assert load(tmp_path) == ({}, None)
    (tmp_path / "pyproject.toml").write_text('[tool.black]\nline-length = 100\n')
    assert load(tmp_path) == ({}, None)


def test_parse_normalises_dashes():
    assert parse({"auth-helpers": ["require_member"], "max-file-size": 5}, "x") == {"auth_helpers": ["require_member"], "max_file_size": 5}


def test_project_auth_helpers_sanitizers_and_public_paths(tmp_path, capsys):
    (tmp_path / "app.py").write_text(
        "@app.post('/api/items')\n@org_member_only\ndef create():\n    db.insert(request.json)\n    return ''\n\n"
        "@app.post('/api/survey-form')\ndef survey():\n    db.insert(request.json)\n    return ''\n\n"
        "@app.get('/q')\ndef q():\n    cursor.execute('SELECT * FROM t WHERE n = ' + clean_input(request.args['n']))\n    return ''\n")
    before = _json(tmp_path, capsys)[1]
    assert before.count("AUTH001") == 2 and "BE001" in before
    (tmp_path / ".vibeaudit.toml").write_text(
        'auth-helpers = ["org_member_only"]\nsanitizers = ["clean_input"]\npublic-paths = ["/api/survey-*"]\n')
    after = _json(tmp_path, capsys)[1]
    assert "AUTH001" not in after
    assert after.count("BE001") == 1  # still string-built SQL (medium), no longer request data (high)
