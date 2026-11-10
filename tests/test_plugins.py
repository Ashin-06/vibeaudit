"""Custom rules through the public API and the --plugin flag."""
import json

import pytest

import vibeaudit
from vibeaudit import plugins
from vibeaudit.cli import main

PLUGIN = '''
from vibeaudit import file_rule, route_rule, rule


@route_rule("ORG001", "Billing route without audit log", severity="high", fix="Call audit_log() in every billing route.")
def billing(route):
    if route.path.startswith("/api/billing") and "audit_log(" not in route.body:
        return f"{route.path} changes billing without calling audit_log()."


@file_rule("ORG002", "print() in production code", severity="low", kinds=["py"])
def prints(sf):
    for i, line in enumerate(sf.lines, 1):
        if line.strip().startswith("print("):
            yield i, "Use the logger instead of print()."


@rule("ORG003", "Broken plugin", severity="low")
def broken(ctx):
    raise RuntimeError("bug in a custom rule")
    yield
'''

APP = ("@app.post('/api/billing/charge')\n@login_required\ndef charge():\n    print('charging')\n    return ''\n\n"
       "@app.post('/api/billing/refund')\n@login_required\ndef refund():\n    audit_log('refund')\n    return ''\n")


@pytest.fixture(autouse=True)
def clean_registry():
    yield
    for rule_id in ("ORG001", "ORG002", "ORG003", "LIB001"):
        plugins.unregister(rule_id)


def test_plugin_file_via_cli(tmp_path, capsys):
    (tmp_path / "app.py").write_text(APP)
    plugin = tmp_path.parent / f"{tmp_path.name}_rules.py"
    plugin.write_text(PLUGIN)
    code = main(["scan", str(tmp_path), "--offline", "--external", "none", "--plugin", str(plugin), "--report", "json:-"])
    data = json.loads(capsys.readouterr().out)
    got = sorted((f["rule_id"], f["line"], f["severity"]) for f in data["findings"] if f["rule_id"].startswith("ORG"))
    assert got == [("ORG001", 3, "high"), ("ORG002", 4, "low")]
    assert next(f for f in data["findings"] if f["rule_id"] == "ORG001")["fix"] == "Call audit_log() in every billing route."
    assert any("custom rule ORG003" in e for e in data["meta"]["internal_errors"])  # a broken rule is isolated
    assert code == 1


def test_library_api_and_registration_rules(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")

    @vibeaudit.rule("LIB001", "Always one", severity="info")
    def always(ctx):
        yield {"file": "a.py", "line": 1, "message": "hello"}

    res = vibeaudit.scan(str(tmp_path), vibeaudit.Options(offline=True, external="none"))
    assert [(f.rule_id, f.category, f.message) for f in res.findings] == [("LIB001", "custom", "hello")]
    with pytest.raises(ValueError, match="built-in"):
        plugins.rule("BE001", "clash")(lambda ctx: [])
    with pytest.raises(ValueError, match="rule id"):
        plugins.rule("bad id", "x")(lambda ctx: [])
    with pytest.raises(ValueError, match="severity"):
        plugins.rule("LIB002", "x", severity="huge")(lambda ctx: [])


def test_plugin_load_errors(tmp_path, capsys):
    assert main(["scan", str(tmp_path), "--plugin", str(tmp_path / "missing.py")]) == 2
    assert main(["scan", str(tmp_path), "--plugin", "no_such_module_xyz"]) == 2
    assert "cannot load plugin" in capsys.readouterr().err


def test_public_names():
    assert callable(vibeaudit.scan) and vibeaudit.Options and vibeaudit.Finding and vibeaudit.Route and vibeaudit.Result
    with pytest.raises(AttributeError):
        vibeaudit.not_a_thing  # noqa: B018
