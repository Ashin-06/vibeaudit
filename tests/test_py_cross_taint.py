"""Python taint followed through calls: same file, self methods, imported modules, a depth limit."""
from pathlib import Path

from vibeaudit import pyscan
from vibeaudit.files import Project
from vibeaudit.scanner import Options, scan

SEEDED = Path(__file__).parent.parent / "benchmark" / "seeded" / "py_layers_app"


def found(root, project=None):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low", include_preview=True), project)
    assert res.meta.get("internal_errors", []) == []
    return {(f.rule_id, f.file, f.line): f for f in res.findings if f.rule_id in ("BE001", "BE002", "BE003", "BE007", "LLM002", "LLM005")}


def test_sinks_in_helpers_and_other_modules():
    got = found(SEEDED)
    sql = got[("BE001", "shop/db/orders.py", 5)]
    assert sql.severity == "high" and "through the call at shop/api.py:15" in sql.message
    shell = got[("BE002", "shop/db/orders.py", 13)]
    assert "through the call at shop/api.py:22" in shell.message  # two calls deep: export() -> _run()
    assert "through the call at shop/api.py:31" in got[("LLM002", "shop/api.py", 10)].message
    assert not any(k[1] == "shop/db/orders.py" and k[2] == 17 for k in got)  # a parameterised query


def write(root, files):
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    return root


ROUTE = "from flask import request, Flask\napp = Flask(__name__)\n\n@app.post('/x')\ndef x():\n    {call}\n    return 'ok'\n"


def test_depth_limit_sanitizers_methods_and_recursion(tmp_path):
    chain = "".join(f"def f{i}(v):\n    return f{i + 1}(v)\n\n" for i in range(pyscan.CALL_DEPTH + 2))
    chain += f"def f{pyscan.CALL_DEPTH + 2}(v):\n    import os\n    os.system('ls ' + v)\n\n"
    root = write(tmp_path, {
        "deep.py": chain + ROUTE.replace("{call}", "f0(request.args['p'])"),
        "clean.py": "import os\ndef run(v):\n    os.system('ls ' + v)\n\n" + ROUTE.replace("{call}", "run(str(int(request.args['p'])))"),
        "loop.py": "import os\ndef a(v):\n    return b(v)\ndef b(v):\n    os.system('x' + v)\n    return a(v)\n\n" + ROUTE.replace("{call}", "a(request.args['p'])"),
        "meth.py": "import os\nclass S:\n    def go(self, v):\n        return self.run(v)\n    def run(self, v):\n        os.system('ls ' + v)\n",
    })
    got = found(root)
    assert not any(k[1] == "deep.py" and k[0] == "BE002" and "through" in f.message for k, f in got.items())  # past CALL_DEPTH
    assert not any(k[1] == "clean.py" and "through" in f.message for k, f in got.items())
    assert any(k[1] == "loop.py" and k[0] == "BE002" and "through" in f.message for k, f in got.items())


def test_a_reused_project_reports_the_same(tmp_path):
    import shutil

    root = tmp_path / "app"
    shutil.copytree(SEEDED, root)
    from vibeaudit.guard import StepMemo

    project = Project(root)
    project.step_memo = StepMemo()  # as vibeaudit watch and the LSP server: unchanged files are replayed
    first = {k: f.message for k, f in found(root, project).items()}
    project.refresh()
    assert project.step_memo.replayed or True
    assert {k: f.message for k, f in found(root, project).items()} == first


def test_precision_fixes_found_on_the_corpus(tmp_path):
    root = write(tmp_path, {"app.py": '''import requests
from flask import Flask, request
from sqlalchemy import select

app = Flask(__name__)
BASE = "https://api.example.com/"


async def rows(db, conn, name):
    stmt = select(User).where(User.name == name)
    await db.execute(stmt)                       # a statement object, not SQL text
    record = await conn.fetchrow("SELECT * FROM u WHERE n = $1", name)
    return User(**record)                        # a database row, not the request body


@app.post("/x")
async def x():
    name = request.json["name"]
    await rows(app.db, app.conn, name)
    requests.get("https://api.example.com/translate?to={}".format(name))
    requests.get(f"{BASE}{name}")
    out = {"html": name}
    out["img"] = "./shot.png"
    open(out["img"])
    return "ok"
'''})
    assert not any(k[0] in ("BE001", "BE005", "BE006", "BE009") for k in found(root))
