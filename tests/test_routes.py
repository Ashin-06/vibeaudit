"""vibeaudit routes: the attack-surface inventory, and the routes section of the JSON report."""
import json

from helpers import materialize
from vibeaudit.cli import main


def test_routes_json_for_the_express_fixture(tmp_path, capsys):
    root = materialize("vuln_express", tmp_path)
    assert main(["routes", str(root), "--format", "json"]) == 0
    rows = {(tuple(r["methods"]), r["path"]): r for r in json.loads(capsys.readouterr().out)}
    notes = rows[(("POST",), "/api/notes")]
    assert notes["authenticated"] is False and notes["writes_data"] is True and notes["file"] == "server.js"
    assert rows[(("DELETE",), "/users/:id")]["file"] == "routes/admin.js"
    assert rows[(("POST",), "/api/login")]["reads_body"] is True


def test_routes_text_and_markdown(tmp_path, capsys):
    root = materialize("vuln_flask_llm", tmp_path)
    assert main(["routes", str(root)]) == 0
    out = capsys.readouterr().out
    assert "/api/chat" in out and "app.py:30" in out
    assert "write data or call a paid AI API without a visible auth check" in out
    assert main(["routes", str(root), "--format", "md"]) == 0
    assert "| POST | `/api/chat` | no |" in capsys.readouterr().out
    assert main(["routes", str(tmp_path / "missing")]) == 2


def test_json_report_lists_routes(tmp_path, capsys):
    root = materialize("clean_app", tmp_path)
    main(["scan", str(root), "--offline", "--external", "none", "--report", "json:-"])
    routes = json.loads(capsys.readouterr().out)["routes"]
    assert {r["path"] for r in routes} >= {"/api/chat", "/login", "/webhooks/stripe"}
    assert all(r["authenticated"] for r in routes if r["path"] == "/api/chat")
