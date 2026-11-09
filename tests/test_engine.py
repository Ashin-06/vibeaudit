"""Unit tests for the lexer, heuristics and the scanning pipeline features (suppression, baseline, git)."""
import json
import shutil
import subprocess

import pytest

from helpers import fake_values, materialize
from vibeaudit import heuristics as H
from vibeaudit.lexer import js_views, match_close, py_views, stmt_end
from vibeaudit.scanner import Options, scan


def _scan(path, **kw):
    kw.setdefault("offline", True)
    kw.setdefault("external", "none")
    return scan(str(path), Options(**kw))


def test_js_views_blank_comments_strings_and_keep_offsets():
    src = 'const a = "x // not a comment"; // real comment\nconst b = `t ${a + "}"} u`; /* c */ const r = /ab"c/g;\n'
    v = js_views(src)
    assert len(v.code) == len(src) == len(v.bare)
    assert "real comment" not in v.code and "not a comment" in v.code
    assert "not a comment" not in v.bare
    assert "${a +" in v.bare  # template expressions stay visible as code
    assert v.code.count("\n") == src.count("\n")
    assert len(v.comments) == 2


def test_js_views_apostrophe_in_jsx_text_does_not_swallow_the_file():
    src = "const x = <p>Don't panic</p>;\nconst y = eval(input);\n"
    v = js_views(src)
    assert "eval(input)" in v.bare


def test_regex_literal_is_not_a_comment():
    v = js_views("const re = /https?:\\/\\//; doThing();\n")
    assert "doThing()" in v.code


def test_match_close_and_stmt_end():
    bare = "f(a, (b), [c, {d}]) + 1;\nnext"
    assert bare[match_close(bare, 1)] == ")"
    assert bare[stmt_end(bare, 0)] == ";"


def test_py_views_blank_comments():
    v = py_views("x = 1  # secret comment\ny = 'not # a comment'\n")
    assert "secret comment" not in v.code and "not # a comment" in v.code
    assert "not # a comment" not in v.bare


def test_looks_random_and_mask():
    assert H.looks_random("Zq8wX2vR7nP4tL9k")
    for value in ("your-api-key-here", "changeme", "ENV_VAR_NAME", "https://example.com/a", "hello-world-app", "1.2.3"):
        assert not H.looks_random(value), value
    assert H.mask("abcdefghijklmnop").startswith("abcd") and "ijkl" not in H.mask("abcdefghijklmnop")


def test_inline_suppression(tmp_path):
    (tmp_path / "a.py").write_text("import os\nos.system('ls ' + x)  # vibeaudit: ignore[BE002]\neval(y)\n")
    rules = {f.rule_id for f in _scan(tmp_path).findings}
    assert "BE002" not in rules and "BE003" in rules
    (tmp_path / "a.py").write_text("import os\n# vibeaudit: ignore\nos.system('ls ' + x)\n")
    assert not [f for f in _scan(tmp_path).findings if f.rule_id == "BE002"]


def test_disable_rule_and_category(tmp_path):
    (tmp_path / "a.py").write_text("eval(x)\ntry:\n    pass\nexcept Exception:\n    pass\n")
    assert {f.rule_id for f in _scan(tmp_path).findings} == {"BE003", "QA003"}
    assert {f.rule_id for f in _scan(tmp_path, disabled={"QA003"}).findings} == {"BE003"}
    assert {f.rule_id for f in _scan(tmp_path, disabled={"quality"}).findings} == {"BE003"}


def test_min_severity_filter(tmp_path):
    (tmp_path / "a.py").write_text("eval(x)\ntry:\n    pass\nexcept Exception:\n    pass\n")
    assert {f.rule_id for f in _scan(tmp_path, min_severity="medium").findings} == {"BE003"}


def test_baseline_hides_known_findings_and_survives_line_moves(tmp_path):
    from vibeaudit.report import render_json

    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "a.py").write_text("eval(x)\n")
    base = tmp_path / "base.json"
    base.write_text(render_json(_scan(proj)))
    (proj / "a.py").write_text("\n\nimport os\neval(x)\nexec(y)\n")
    rules = [(f.rule_id, f.line) for f in _scan(proj, baseline=str(base)).findings]
    assert rules == [("BE003", 5)]


def test_findings_in_test_files_are_ignored_except_real_keys(tmp_path):
    (tmp_path / "tests").mkdir()
    key = fake_values()["FAKE_OPENAI_KEY"]
    (tmp_path / "tests" / "test_x.py").write_text(f'eval(x)\nKEY = "{key}"\n')
    assert [f.rule_id for f in _scan(tmp_path).findings] == ["SEC001"]


def test_placeholders_and_firebase_config_are_not_secrets(tmp_path):
    google = fake_values()["FAKE_GOOGLE_KEY"]
    (tmp_path / "firebase.js").write_text(
        f'const firebaseConfig = {{ apiKey: "{google}", authDomain: "x.firebaseapp.com", projectId: "x" }};\n'
        'const OPENAI_API_KEY = "sk-your-key-here";\nconst password = "Password";\n')
    assert _scan(tmp_path).findings == []


def test_gemini_key_outside_firebase_config_is_reported(tmp_path):
    google = fake_values()["FAKE_GOOGLE_KEY"]
    (tmp_path / "ai.py").write_text(f'GEMINI_API_KEY = "{google}"\n')
    assert [f.rule_id for f in _scan(tmp_path).findings] == ["SEC001"]


def test_minified_and_vendor_files_are_skipped(tmp_path):
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "index.js").write_text("eval(a)\n")
    (tmp_path / "bundle.js").write_text("eval(a);" * 2000)
    assert _scan(tmp_path).findings == []


def test_syntax_errors_do_not_crash(tmp_path):
    (tmp_path / "broken.py").write_text("def x(:\n  eval(y\n")
    (tmp_path / "broken.js").write_text("function (( { eval(`${\n")
    _scan(tmp_path)


def test_binary_and_huge_files_are_skipped(tmp_path):
    (tmp_path / "data.py").write_bytes(b"eval(x)\x00\x01")
    (tmp_path / "big.py").write_text("eval(x)\n" + "#" * 2_000_000)
    assert _scan(tmp_path).findings == []


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_git_mode_reports_committed_env_and_ignores_ignored_files(tmp_path):
    def git(*args):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    key = fake_values()["FAKE_OPENAI_KEY"]
    (tmp_path / ".env").write_text(f"OPENAI_API_KEY={key}\n")
    (tmp_path / ".gitignore").write_text("ignored.py\n")
    (tmp_path / "ignored.py").write_text("eval(x)\n")
    git("add", ".env", ".gitignore")
    git("commit", "-qm", "init")
    res = _scan(tmp_path)
    assert res.meta["git"] is True
    assert {(f.rule_id, f.file) for f in res.findings} == {("SEC006", ".env"), ("SEC001", ".env")}


def test_self_scan_does_not_crash():
    import vibeaudit

    from pathlib import Path

    res = _scan(Path(vibeaudit.__file__).parent)
    assert res.meta["files_scanned"] > 10


def test_json_report_of_fixture_is_ascii_and_has_fix_text(tmp_path):
    from vibeaudit.report import render_json

    root = materialize("vuln_express", tmp_path)
    text = render_json(_scan(root))
    text.encode("ascii")
    data = json.loads(text)
    assert data["summary"]["total"] == len(data["findings"]) > 10
    assert all(f["fix"] and f["why"] and f["file"] for f in data["findings"])
