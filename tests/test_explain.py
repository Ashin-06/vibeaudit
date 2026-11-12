"""`vibeaudit explain`: choosing a finding and tracing the data flow that led to it."""
from __future__ import annotations

import json

from vibeaudit import explain
from vibeaudit.cli import main
from vibeaudit.model import Finding

PY = '''from flask import Flask, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI()


@app.post("/run")
def run():
    data = request.get_json()
    question = data["question"]
    prefix = "answer: "
    prompt = prefix + question
    db = get_db()
    plan = client.chat.completions.create(model="m", max_tokens=5, messages=[
        {"role": "user", "content": prompt},
    ])
    script = plan.choices[0].message.content
    exec(script)
    return "ok"


@app.delete("/users/<user_id>")
def delete(user_id):
    db = get_db()
    db.execute(f"DELETE FROM users WHERE id = {user_id}")
'''

JS = '''const express = require("express");
const db = require("./db");
const app = express();
app.get("/search", async (req, res) => {
  const q = req.query.q;
  const term = q.trim();
  const rows = await db.query(`SELECT * FROM items WHERE name = '${term}'`);
  res.json(rows);
});
'''


def steps(rel, text, line):
    return [(s.role, s.line, s.note) for s in explain.trace(rel, text, line)]


def test_python_flows_from_request_and_model_output():
    flow = steps("app.py", PY, 19)  # exec(script)
    assert [(r, ln) for r, ln, _n in flow] == [("source", 15), ("assignment", 18), ("sink", 19)]
    assert "model output" in flow[0][2]
    prompt = steps("app.py", PY, 16)  # inside the multi-line model call: the prompt argument
    assert [(r, ln) for r, ln, _n in prompt] == [("source", 10), ("assignment", 11), ("assignment", 13), ("sink", 16)]
    assert all(ln != 14 for _r, ln, _n in prompt)  # `db = get_db()` leads nowhere: not shown
    sql = steps("app.py", PY, 26)
    assert sql[0][0] == "source" and "route parameter" in sql[0][2] and sql[-1][:2] == ("sink", 26)


def test_javascript_flow_and_direct_use():
    flow = steps("server.js", JS, 7)
    assert [(r, ln) for r, ln, _n in flow] == [("source", 5), ("assignment", 6), ("sink", 7)]
    assert steps("server.js", "app.get('/x', (req, res) => fetch(req.query.url));\n", 1) == [
        ("sink", 1, "user input is used directly on this line")]


def test_no_flow_for_rules_about_the_line_itself():
    assert steps("a.py", "import requests\nr = requests.get('https://x')\n", 2) == []
    django = "from django.db import models\n\n\nclass A(models.Model):\n    kind = models.CharField(choices=Kind.choices)\n"
    assert steps("models.py", django, 5) == []  # `.choices` of a Django enum is not model output
    assert steps("notes.txt", "x", 1) == [] and steps("broken.py", "def (:\n", 1) == []


def test_select():
    a = Finding("BE001", "app.py", 26, "m", "high")
    b = Finding("AUTH001", "app.py", 26, "m", "high")
    for f in (a, b):
        f.compute_fingerprint()
    assert explain.select([a, b], "app.py:26") == [a, b]
    assert explain.select([a, b], "./app.py:26:be001") == [a]
    assert explain.select([a, b], a.fingerprint[:8]) == [a]
    assert explain.select([a, b], "app.py:27") == [] and explain.select([a, b], "nonsense") == []


def test_cli(tmp_path, capsys):
    (tmp_path / "app.py").write_text(PY)
    assert main(["explain", "app.py:19", "--path", str(tmp_path)]) == 0
    text = capsys.readouterr().out
    assert "LLM002" in text and "Data flow (traced back" in text and "from  app.py:15" in text and "Fix:" in text
    assert main(["explain", "app.py:26:BE001", "--path", str(tmp_path), "--format", "json"]) == 0
    (e,) = json.loads(capsys.readouterr().out)
    assert e["rule_id"] == "BE001" and e["flow"][0]["role"] == "source" and any(c["current"] for c in e["code"])
    assert main(["explain", "app.py:3", "--path", str(tmp_path)]) == 1
    assert main(["explain", "app.py:19", "--path", str(tmp_path / "missing")]) == 2


def test_trace_stops_at_a_function_parameter():
    src = "def find(cursor, name):\n    q = \"SELECT * FROM t WHERE n = '%s'\" % name\n    cursor.execute(q)\n"
    flow = explain.trace("db.py", src, 3)
    assert [(s.role, s.line) for s in flow] == [("parameter", 1), ("assignment", 2), ("sink", 3)]
    assert "parameter of `find`" in flow[0].note and "callers are not followed" in flow[0].note
    assert explain.trace("m.py", "class A:\n    def f(self):\n        return self.x\n", 3) == []  # self is not an origin
