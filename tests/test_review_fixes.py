"""Regression tests for issues found in an external review of 0.11.0."""
from __future__ import annotations

from vibeaudit.exploit import build_poc
from vibeaudit.fix import FileCtx
from vibeaudit.model import Finding, Route
from vibeaudit.scanner import Options, scan


def _rules(root, rule):
    res = scan(str(root), Options(offline=True, external="none", include_preview=True))
    return [(f.file, f.line) for f in res.findings if f.rule_id == rule]


def test_poc_for_a_non_auth_rule_does_not_claim_an_auth_oracle():
    route = Route("app.py", 3, "/logs", ["GET"], "", "flask", "py")
    poc = build_poc(Finding("BE006", "app.py", 5, "path traversal"), [route], "http://127.0.0.1:8000")
    assert "Unauthorized" not in poc["expected_safe"] and "authentication" not in poc["oracle"]


def test_indent_unit_ignores_two_space_lines_inside_strings():
    text = 'PROMPT = """\n  two\n  spaces\n"""\n\n\ndef f():\n    if x:\n        return 1\n'
    assert FileCtx("a.py", text).unit() == "    "


def test_user_key_into_a_server_side_dict_is_not_tainted(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "FILES = {'app': '/var/log/app.log'}\n"
        "@app.get('/log')\n"
        "def log():\n"
        "    path = FILES.get(request.args.get('name'))\n"
        "    return open(path).read()\n", encoding="utf-8")
    assert _rules(tmp_path, "BE006") == []


def test_user_value_from_request_get_is_still_tainted(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.get('/log')\n"
        "def log():\n"
        "    return open(request.args.get('path')).read()\n", encoding="utf-8")
    assert _rules(tmp_path, "BE006")


def test_regex_checked_table_name_is_not_sql_injection(tmp_path):
    code = (
        "import re, sqlite3\n"
        "class Store:\n"
        "    def __init__(self, table):\n"
        "        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', table):\n"
        "            raise ValueError(table)\n"
        "        self.table = table\n"
        "        self.db = sqlite3.connect(':memory:')\n"
        "    def rows(self, tool):\n"
        "        return self.db.execute(f'SELECT * FROM {self.table} WHERE id = ?', (tool,))\n")
    (tmp_path / "store.py").write_text(code, encoding="utf-8")
    assert _rules(tmp_path, "BE001") == []
    # a pattern that lets quotes through is not a check
    (tmp_path / "store.py").write_text(code.replace("[A-Za-z_][A-Za-z0-9_]*", ".+"), encoding="utf-8")
    assert _rules(tmp_path, "BE001")


def test_tuple_assigned_and_local_checked_table_names(tmp_path):
    (tmp_path / "pg.py").write_text(
        "import re\n"
        "class Journal:\n"
        "    def __init__(self, conninfo, table='j'):\n"
        "        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', table):\n"
        "            raise ValueError(table)\n"
        "        self.conninfo, self.table = conninfo, table\n"
        "        self.db.execute(f'CREATE TABLE IF NOT EXISTS {table} (tx TEXT)')\n"
        "    def rows(self, tx):\n"
        "        return self.db.execute(f'SELECT * FROM {self.table} WHERE tx = %s', (tx,))\n", encoding="utf-8")
    assert _rules(tmp_path, "BE001") == []


def test_health_check_rule_covers_js_servers_beyond_express():
    from vibeaudit.relscan import HEALTH_FRAMEWORKS
    assert {"fastify", "hono", "express", "python"} <= HEALTH_FRAMEWORKS and "spring" not in HEALTH_FRAMEWORKS


def test_mcp_package_tool_accepts_every_osv_ecosystem():
    from vibeaudit.mcp_server import ECOSYSTEMS
    assert {"Go", "Maven", "crates.io", "NuGet", "Packagist"} <= set(ECOSYSTEMS)


def test_explain_traces_request_data_in_other_languages():
    from vibeaudit.explain import trace
    go = 'func h(c *gin.Context) {\n  name := c.Query("name")\n  q := "SELECT * FROM u WHERE n=" + name\n  db.Raw(q)\n}\n'
    steps = trace("main.go", go, 4)
    assert [s.role for s in steps][0] == "source" and steps[0].line == 2 and steps[-1].role == "sink"
    java = ('@GetMapping("/u")\npublic List<U> u(@RequestParam String name) {\n'
            '  String q = "SELECT * FROM u WHERE n=" + name;\n  return jdbc.queryForList(q);\n}\n')
    assert trace("A.java", java, 4)[0].role == "source"
    php = '<?php\n$id = $_GET["id"];\n$sql = "SELECT * FROM t WHERE id=" . $id;\nmysqli_query($db, $sql);\n'
    assert trace("a.php", php, 4)[0].line == 2
    assert trace("main.go", 'func f() {\n  x := 1\n  db.Raw(x)\n}\n', 3) == []
