"""Severe preview rules (STABILITY.md): injection-class preview rules still count toward --fail-on and the score
unless --no-gate-severe-preview (or gate-severe-preview = false); other preview rules are unaffected."""
import json

import pytest

from vibeaudit.cli import main
from vibeaudit.rules import RULES

SEVERE = ("BE002", "BE003", "BE004", "BE008", "FE001")
# one file per rule, each with request data reaching the sink
SAMPLES = {
    "BE002": ("app.py", "import os\nfrom flask import request\n@app.get('/ping')\ndef ping():\n"
                        "    return os.popen('ping ' + request.args['host']).read()\n"),
    "BE003": ("app.py", "from flask import request\n@app.post('/calc')\ndef calc():\n    return str(eval(request.json['expr']))\n"),
    "BE004": ("app.py", "import pickle\nfrom flask import request\n@app.post('/load')\ndef load():\n"
                        "    return str(pickle.loads(request.data))\n"),
    "BE008": ("server.js", "app.get('/go', (req, res) => {\n  res.redirect(req.query.url);\n});\n"),
    "FE001": ("show.js", "document.getElementById('out').innerHTML = new URLSearchParams(location.search).get('msg');\n"),
}


def _scan(tmp_path, capsys, *args, level="high"):
    code = main(["scan", str(tmp_path), "--offline", "--external", "none", "--fail-on", level, "--report", "json:-", *args])
    return code, json.loads(capsys.readouterr().out)


def test_the_five_severe_rules_are_the_ones_marked():
    assert sorted(r for r, meta in RULES.items() if meta.gates_in_preview) == sorted(SEVERE)
    assert all(RULES[r].preview for r in SEVERE)


@pytest.mark.parametrize("rule", SEVERE)
def test_severe_preview_rule_fails_by_default_and_not_with_the_flag(tmp_path, capsys, rule):
    name, text = SAMPLES[rule]
    (tmp_path / name).write_text(text)
    # BE008 (open redirect) is a medium-severity rule, so it can only ever fail --fail-on medium
    level = "medium" if RULES[rule].severity == "medium" else "high"
    code, out = _scan(tmp_path, capsys, level=level)
    hits = [f for f in out["findings"] if f["rule_id"] == rule]
    assert hits and all(f.get("preview") and f.get("gates_in_preview") for f in hits)
    assert code == 1 and out["summary"]["score"] < 100
    code, out = _scan(tmp_path, capsys, "--no-gate-severe-preview", level=level)
    assert code == 0, [f["rule_id"] for f in out["findings"]]
    (tmp_path / ".vibeaudit.toml").write_text("gate-severe-preview = false\n")
    assert _scan(tmp_path, capsys, level=level)[0] == 0
    assert _scan(tmp_path, capsys, "--include-preview", level=level)[0] == 1  # still counts every preview rule


def test_other_preview_rules_are_unaffected(tmp_path, capsys):
    assert RULES["SEC003"].preview and not RULES["SEC003"].gates_in_preview
    (tmp_path / "config.py").write_text("API_SECRET = 'q8Zr2Lm9Xv4Tn7Kp3Wd6Bs1Hc5Jf0Ga'\n")  # SEC003, high, preview
    code, out = _scan(tmp_path, capsys)
    assert [f["rule_id"] for f in out["findings"]] == ["SEC003"] and code == 0
    assert _scan(tmp_path, capsys, "--include-preview")[0] == 1
