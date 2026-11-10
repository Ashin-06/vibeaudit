"""Regression tests for the second external audit: one test per finding that reproduced.

Each test was run against the unfixed code first and failed; see the CHANGELOG for findings that did not
reproduce and why."""
import json
from pathlib import Path

from vibeaudit import deps, mcp_server
from vibeaudit.scanner import Options, scan


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _rules(tmp_path, prefix="", **kw):
    res = scan(str(tmp_path), Options(offline=True, external="none", **kw))
    assert res.meta.get("internal_errors", []) == []
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id.startswith(prefix))


# ------------------------------------------------------------------ datascan
def test_a1_prisma_money_float_in_any_prisma_file(tmp_path):
    model = "model Order {\n  id    Int   @id\n  price Float\n}\n"
    write(tmp_path, "prisma/schema.prisma", model)
    write(tmp_path, "prisma/schema/billing.prisma", model.replace("Order", "Invoice"))  # multi-file schema
    assert _rules(tmp_path, "DATA004") == [("prisma/schema.prisma", 3, "DATA004"), ("prisma/schema/billing.prisma", 3, "DATA004")]


def test_a2_serverless_config_files(tmp_path):
    """A2 did not reproduce (every non-binary file is loaded, whatever its type); kept as a guard."""
    write(tmp_path, "app.py", "import sqlite3\n\ndef get():\n    return sqlite3.connect('app.db')\n")
    assert _rules(tmp_path, "DATA009") == []
    for name in ("netlify.toml", "wrangler.toml", "serverless.yml", "template.yaml"):
        write(tmp_path, name, "x = 1\n")
        assert _rules(tmp_path, "DATA009") == [("app.py", 4, "DATA009")], name
        (tmp_path / name).unlink()


def test_a3_nested_sqlite_call_reported_once(tmp_path):
    write(tmp_path, "vercel.json", "{}")
    write(tmp_path, "app.py", "import sqlite3\nfrom contextlib import closing\n\ndef get():\n"
          "    with closing(\n        sqlite3.connect('app.db')\n    ) as c:\n        return c\n")
    assert _rules(tmp_path, "DATA009") == [("app.py", 6, "DATA009")]


def test_a5_naive_datetime_through_aliases_and_explicit_none(tmp_path):
    write(tmp_path, "m.py",
          "import datetime as dt\nfrom datetime import datetime as DT\nfrom datetime import datetime, timezone\n\n"
          "a = dt.datetime.utcnow()\n"            # 5
          "b = DT.utcnow()\n"                     # 6
          "created_at = datetime.now(None)\n"     # 7
          "updated_at = datetime.now(timezone.utc)\n"
          "c = arrow.utcnow()\n")
    assert _rules(tmp_path, "DATA006") == [("m.py", 5, "DATA006"), ("m.py", 6, "DATA006"), ("m.py", 7, "DATA006")]


def test_a6_sql_timestamps_only_in_table_definitions(tmp_path):
    write(tmp_path, "db/reports.sql", "SELECT created_at timestamp, id FROM events;\n"
          "CREATE TABLE logs (\n  id int,\n  created_at timestamp\n);\n"
          "ALTER TABLE logs ADD COLUMN updated_at timestamp;\n")
    assert _rules(tmp_path, "DATA006") == [("db/reports.sql", 4, "DATA006"), ("db/reports.sql", 6, "DATA006")]


def test_a7_per_request_client_in_drf_and_api_route_handlers(tmp_path):
    write(tmp_path, "views.py", "from rest_framework.decorators import api_view\n\n@api_view(['GET'])\ndef a(request):\n"
          "    engine = create_engine(URL)\n    return None\n\n@app.api_route('/b', methods=['GET'])\ndef b():\n"
          "    client = MongoClient(URL)\n    return None\n")
    assert _rules(tmp_path, "DATA008") == [("views.py", 5, "DATA008"), ("views.py", 10, "DATA008")]


def test_a9_transactions_in_python_and_more_js_write_styles(tmp_path):
    write(tmp_path, "shop/views.py",
          "@api_view(['POST'])\ndef checkout(request):\n    Order.objects.create(user=request.user)\n"
          "    Payment.objects.create(amount=1)\n    return None\n\n"
          "@api_view(['POST'])\ndef safe(request):\n    with transaction.atomic():\n        Order.objects.create(user=request.user)\n"
          "        Payment.objects.create(amount=1)\n    return None\n")
    write(tmp_path, "server.js",
          "const express = require('express');\nconst app = express();\n"
          "app.post('/a', async (req, res) => {\n  await Order.create(req.body);\n  await Payment.create(req.body);\n  res.json({});\n});\n"
          "app.post('/b', async (req, res) => {\n  await db.insert(orders).values(req.body);\n  await db.insert(payments).values(req.body);\n  res.json({});\n});\n"
          "app.post('/c', async (req, res) => {\n  await order.save();\n  await payment.save();\n  res.json({});\n});\n"
          "app.post('/d', async (req, res) => {\n  await db.insert(orders).values(a);\n  await db.insert(orders).values(b);\n  res.json({});\n});\n")
    assert _rules(tmp_path, "DATA010") == [("server.js", 3, "DATA010"), ("server.js", 8, "DATA010"), ("server.js", 13, "DATA010"),
                                            ("shop/views.py", 2, "DATA010")]


# --------------------------------------------------------------- qualityscan
def test_b1_no_duplicate_keys_in_rule_tables():
    """A repeated key in a dict literal silently replaces the first entry."""
    import ast as _ast

    src = Path(__file__).parent.parent / "src" / "vibeaudit"
    for path in src.glob("*.py"):
        for node in _ast.walk(_ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, _ast.Dict):
                keys = [k.value for k in node.keys if isinstance(k, _ast.Constant)]
                assert len(keys) == len(set(keys)), f"{path.name}:{node.lineno} repeats {[k for k in keys if keys.count(k) > 1][0]!r}"


def test_b3_names_from_function_bodies_are_not_module_exports(tmp_path):
    write(tmp_path, "pyproject.toml", "[project]\nname = 'x'\ndependencies = []\n")
    write(tmp_path, "app/__init__.py", "")
    write(tmp_path, "app/money.py",
          "import os\n\ndef to_cents(amount):\n    total = amount * 100\n    return total\n\n"
          "if os.name == 'nt':\n    SEP = '\\\\'\nelse:\n    SEP = '/'\ntry:\n    import fast as speed\nexcept ImportError:\n    speed = None\n")
    write(tmp_path, "app/main.py", "from .money import amount, total, to_cents, SEP, speed\n")
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    msgs = sorted(f.message for f in res.findings if f.rule_id == "QA006")
    assert msgs == ["`amount` is imported from `.money` but is not defined there.",
                    "`total` is imported from `.money` but is not defined there."]


def test_b3_dunder_all_is_honoured(tmp_path):
    write(tmp_path, "app/__init__.py", "")
    write(tmp_path, "app/api.py", "__all__ = ['lazy_thing']\n\ndef __dir__():\n    return __all__\n")
    write(tmp_path, "app/main.py", "from .api import lazy_thing\n")
    assert _rules(tmp_path, "QA006") == []


def test_b4_js_export_names(tmp_path):
    write(tmp_path, "package.json", '{"name": "x"}')
    write(tmp_path, "lib/a.ts", "// export function old() {}\nconst a = 1, x = 2, y = 3;\nexport { a as b, x as default, y };\n")
    write(tmp_path, "main.ts", "import { old, a, b, y } from './lib/a';\n")
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    msgs = sorted(f.message for f in res.findings if f.rule_id == "QA006")
    assert msgs == ["`a` is imported from `./lib/a` but that file does not export it.",
                    "`old` is imported from `./lib/a` but that file does not export it."]


def test_b5_ts_nocheck_reported_on_its_own_line(tmp_path):
    write(tmp_path, "a.ts", "/**\n * Generated header\n */\n// @ts-nocheck\nexport const a = 1;\n")
    write(tmp_path, "b.ts", "// @ts-nocheck\nexport const b = 1;\n")
    assert _rules(tmp_path, "QA008") == [("a.ts", 4, "QA008"), ("b.ts", 1, "QA008")]


def test_b6_dependencies_are_collected_once_per_scan(tmp_path, monkeypatch):
    write(tmp_path, "requirements.txt", "flask==3.0.0\n")
    write(tmp_path, "app.py", "import flask\n")
    calls = []
    real = deps._fill_from_lockfiles  # runs once at the end of every full manifest parse
    monkeypatch.setattr(deps, "_fill_from_lockfiles", lambda p, d: calls.append(1) or real(p, d))
    scan(str(tmp_path), Options(offline=True, external="none"))
    assert len(calls) == 1


# ------------------------------------------------------- config and entry points
def test_c1_project_config_reaches_routes_mcp_and_the_api(tmp_path, capsys):
    write(tmp_path, "app.py", "@app.post('/api/items')\ndef items():\n    require_team(request)\n    return ''\n")
    write(tmp_path, ".vibeaudit.toml", "auth-helpers = ['require_team']\n")
    assert not [f for f in scan(str(tmp_path)).findings if f.rule_id == "AUTH001"]
    out = mcp_server.tool_scan_project({"path": str(tmp_path)})
    assert not [f for f in out["findings"] if f["rule_id"] == "AUTH001"]
    routes = mcp_server.tool_list_routes({"path": str(tmp_path)})
    assert routes["routes"][0]["authenticated"] is True
    from vibeaudit.cli import main

    assert main(["routes", str(tmp_path), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["authenticated"] is True


def test_c2_scan_file_finds_the_project_root_without_git(tmp_path):
    write(tmp_path, "pyproject.toml", "[project]\nname = 'x'\ndependencies = []\n")
    write(tmp_path, "pkg/__init__.py", "")
    write(tmp_path, "pkg/sub/__init__.py", "")
    write(tmp_path, "pkg/helpers.py", "def ok():\n    return 1\n")
    write(tmp_path, "pkg/sub/views.py", "from pkg.helpers import ok\n")
    out = mcp_server.tool_scan_file({"file": str(tmp_path / "pkg" / "sub" / "views.py")})
    assert out["root"] == str(tmp_path.resolve())


def test_c3_check_package_recovers_after_a_network_blip(monkeypatch):
    deps.BREAKER.reset()
    for _ in range(10):
        deps.BREAKER.record("pypi.org", False)
    assert deps.BREAKER.open("pypi.org")
    monkeypatch.setattr(deps, "_registry_lookup", lambda d: ("ok", None, "") if not deps.BREAKER.open("pypi.org") else ("error", None, ""))
    out = mcp_server.tool_check_package({"name": "some-pkg", "ecosystem": "PyPI"})
    assert out["registry"] == "ok"


# ------------------------------------------------------------------ packaging
def test_d1_pytest_finds_src_and_tests_without_install():
    text = (Path(__file__).parent.parent / "pyproject.toml").read_text()
    assert 'pythonpath = ["src", "tests"]' in text


def test_d3_action_does_not_glob_expand_args():
    text = (Path(__file__).parent.parent / "action.yml").read_text()
    assert "set -f" in text


# ------------------------------------------------- extra bugs found while fixing the audit
def test_x1_containerfile_is_a_dockerfile(tmp_path):
    body = "FROM node\nCOPY . .\nCOPY .env .env\nCMD node server.js\n"
    write(tmp_path, "Dockerfile", body)
    docker = [(r, ln) for _f, ln, r in _rules(tmp_path, "CFG")]
    (tmp_path / "Dockerfile").unlink()
    write(tmp_path, "Containerfile", body)  # Podman's name for the same file
    assert docker and [(r, ln) for _f, ln, r in _rules(tmp_path, "CFG")] == docker


def test_x2_undeclared_package_reported_once_per_project(tmp_path):
    write(tmp_path, "requirements.txt", "flask==3.0.0\n")
    for name in ("a.py", "b.py", "c.py"):
        write(tmp_path, name, "import requests\n")
    write(tmp_path, "web/package.json", '{"name": "web", "dependencies": {}}')
    for name in ("web/a.ts", "web/b.ts"):
        write(tmp_path, name, "import axios from 'axios';\n")
    write(tmp_path, "api/package.json", '{"name": "api", "dependencies": {}}')
    write(tmp_path, "api/c.ts", "import axios from 'axios';\n")  # a different package.json: its own finding
    assert _rules(tmp_path, "QA007") == [("a.py", 1, "QA007"), ("api/c.ts", 1, "QA007"), ("web/a.ts", 1, "QA007")]


def test_x3_feedback_uses_the_project_config(tmp_path):
    from vibeaudit import feedback

    write(tmp_path, "legacy/app.py", "@app.post('/api/items')\ndef items():\n    db.execute('DELETE FROM items')\n    return ''\n")
    assert feedback.record(tmp_path, "AUTH001", "legacy/app.py", 2, "false-positive") is not None
    (tmp_path / ".vibeaudit").joinpath("feedback.json").unlink()
    write(tmp_path, ".vibeaudit.toml", "exclude = ['legacy/**']\n")
    assert feedback.record(tmp_path, "AUTH001", "legacy/app.py", 2, "false-positive") is None  # the scan does not report it


def test_x4_public_api_exposes_project_options(tmp_path):
    import vibeaudit

    write(tmp_path, ".vibeaudit.toml", "disable = ['QA001']\n")
    opts = vibeaudit.project_options(str(tmp_path), offline=True)
    assert opts.offline is True and opts.disabled == {"QA001"}


def test_x5_sweep_false_alarms_api_clients_and_generated_files(tmp_path):
    """Found by the sweep: SDK calls counted as database writes, @ts-nocheck in generated files."""
    write(tmp_path, "package.json", '{"dependencies": {"next": "14.0.0"}}')
    write(tmp_path, "app/api/embed/route.ts",
          "export async function POST(req: Request) {\n  const e = await openai.embeddings.create({ input: 'x' });\n"
          "  const s = await stripe.checkout.sessions.create({});\n  await prisma.doc.create({ data: {} });\n"
          "  return Response.json({});\n}\n")
    write(tmp_path, "src/routeTree.gen.ts", "/* eslint-disable */\n\n// @ts-nocheck\nexport const a = 1;\n")
    write(tmp_path, "src/api.ts", "/* eslint-disable */\n\n// @ts-nocheck\nexport const b = 1;\n")
    assert _rules(tmp_path, "DATA010") == []
    assert _rules(tmp_path, "QA008") == [("src/api.ts", 3, "QA008")]
