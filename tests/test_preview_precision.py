"""Preview-rule precision work (item 5): causes found on the tuned split, each test failed before its fix."""
from vibeaudit.rules import RULES
from vibeaudit.scanner import Options, scan


def test_bson_and_gridfs_ship_with_pymongo(tmp_path):
    # alerta: `import bson` with only pymongo declared
    (tmp_path / "requirements.txt").write_text("pymongo\n")
    (tmp_path / "app.py").write_text("import bson\nimport gridfs\nimport pymongo\n")
    res = scan(str(tmp_path), Options(offline=True, external="none", include_preview=True))
    assert [f for f in res.findings if f.rule_id == "QA007"] == []


def test_ui014_is_stable_after_clearing_the_held_out_bar():
    assert not RULES["UI014"].preview


def test_ui014_img_sized_by_its_parents_css_class(tmp_path):
    # pomb: `.user-avatar img { width: 100%; height: 100% }` in style.css sizes the avatar image
    (tmp_path / "static").mkdir()
    (tmp_path / "static" / "style.css").write_text(".owner-avatar img,\n.user-avatar img {\n  width: 100%;\n  height: 100%;\n}\n")
    (tmp_path / "templates").mkdir()
    (tmp_path / "templates" / "a.html").write_text(
        '<button class="user-avatar" type="button"><img src="{{ url }}" alt=""></button>\n'
        '<div class="card"><img src="{{ url }}" alt=""></div>\n')
    res = scan(str(tmp_path), Options(offline=True, external="none", include_preview=True))
    assert [(f.file, f.line) for f in res.findings if f.rule_id == "UI014"] == [("templates/a.html", 2)]
