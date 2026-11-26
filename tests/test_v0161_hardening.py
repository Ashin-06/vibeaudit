"""Regression tests for v0.16.1 taint correctness, sanitizer scoping, and parser/transport hardening."""
from __future__ import annotations

import base64
import io
import json
import ssl

import pytest

from vibeaudit import feed, mcp_server, probe
from vibeaudit.scanner import Options, scan


def _scan(path, **kw):
    kw.setdefault("offline", True)
    kw.setdefault("external", "none")
    return scan(str(path), Options(**kw))


def _lines(res, rule):
    return sorted(f.line for f in res.findings if f.rule_id == rule)


def test_path_guard_and_instead_of_or_still_reports_traversal(tmp_path):
    (tmp_path / "app.py").write_text(
        "from pathlib import Path\nfrom flask import Flask, request\napp = Flask(__name__)\nBASE = Path('/srv/data')\n\n"
        "@app.get('/read')\ndef read():\n"
        "    p = Path(request.args['file'])\n"
        "    if p.is_absolute() and '..' in p.parts:\n"
        "        raise ValueError('bad')\n"
        "    return (BASE / p).read_text() if False else open(BASE / p).read()\n"
    )
    assert _lines(_scan(tmp_path), "BE006") == [11]


def test_path_guard_negated_and_conditional_still_reports_traversal(tmp_path):
    (tmp_path / "app.py").write_text(
        "from pathlib import Path\nfrom flask import Flask, request\napp = Flask(__name__)\nBASE = Path('/srv/data')\n\n"
        "@app.get('/neg')\ndef neg():\n"
        "    p = Path(request.args['file'])\n"
        "    if not (p.is_absolute() or '..' in p.parts):\n"
        "        raise ValueError('bad')\n"
        "    return open(BASE / p).read()\n\n"
        "@app.get('/cond')\ndef cond(strict: bool = False):\n"
        "    p = Path(request.args['file'])\n"
        "    if strict and (p.is_absolute() or '..' in p.parts):\n"
        "        raise ValueError('bad')\n"
        "    return open(BASE / p).read()\n\n"
        "@app.get('/log')\ndef log_only():\n"
        "    p = Path(request.args['file'])\n"
        "    if p.is_absolute() or '..' in p.parts:\n"
        "        print(p)\n"
        "    return open(BASE / p).read()\n"
    )
    assert _lines(_scan(tmp_path), "BE006") == [11, 18, 25]


def test_valid_path_guard_and_canonical_check_preserve_sql_taint(tmp_path):
    (tmp_path / "app.py").write_text(
        "from pathlib import Path\nfrom flask import Flask, request\napp = Flask(__name__)\nBASE = Path('/srv/data').resolve()\n\n"
        "@app.get('/ok')\ndef ok():\n"
        "    p = Path(request.args['file'])\n"
        "    if p.is_absolute() or '..' in p.parts:\n"
        "        raise ValueError('bad')\n"
        "    data = open(BASE / p).read()\n"
        "    cur.execute(f\"SELECT * FROM logs WHERE file = '{p}'\")\n"
        "    return data\n\n"
        "@app.get('/canon')\ndef canon():\n"
        "    p = Path(request.args['file'])\n"
        "    resolved = (BASE / p).resolve()\n"
        "    if not resolved.is_relative_to(BASE):\n"
        "        raise ValueError('escape')\n"
        "    cur.execute(f\"SELECT * FROM logs WHERE file = '{resolved}'\")\n"
        "    return open(resolved).read()\n"
    )
    res = _scan(tmp_path)
    # lexical-only is_absolute/.. guard does not block symlinks inside BASE -> BE006 on line 11
    assert _lines(res, "BE006") == [11]
    assert _lines(res, "BE001") == [12, 21]


def test_startswith_and_unresolved_is_relative_to_do_not_suppress_path_traversal(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\nfrom pathlib import Path\nfrom flask import Flask, request\napp = Flask(__name__)\n"
        "BASE_STR = '/srv/app'\nBASE_LEX = Path('/srv/app')\nBASE_RES = Path('/srv/app').resolve()\n\n"
        "@app.get('/prefix')\ndef prefix():\n"
        "    p = request.args['file']\n"
        "    if not str(p).startswith(BASE_STR):\n"
        "        raise ValueError('bad')\n"
        "    return open(p).read()\n\n"
        "@app.get('/unres_p')\ndef unres_p():\n"
        "    p = BASE_RES / request.args['file']\n"
        "    if not p.is_relative_to(BASE_RES):\n"
        "        raise ValueError('bad')\n"
        "    return open(p).read()\n\n"
        "@app.get('/unres_base')\ndef unres_base():\n"
        "    p = (BASE_LEX / request.args['file']).resolve()\n"
        "    if not p.is_relative_to(BASE_LEX):\n"
        "        raise ValueError('bad')\n"
        "    return open(p).read()\n\n"
        "@app.get('/abspath')\ndef abspath():\n"
        "    p = Path(os.path.abspath(BASE_RES / request.args['file']))\n"
        "    if not p.is_relative_to(BASE_RES):\n"
        "        raise ValueError('bad')\n"
        "    return open(p).read()\n"
    )
    assert _lines(_scan(tmp_path), "BE006") == [14, 21, 28, 35]


def test_literal_eval_and_validate_and_binary_digest_do_not_hide_sqli(tmp_path):
    (tmp_path / "app.py").write_text(
        "import ast\nimport hashlib\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
        "def validate_input(v):\n    return v\n\n"
        "@app.get('/a')\ndef a():\n"
        "    v1 = ast.literal_eval(request.args['q'])\n"
        "    cur.execute(f\"SELECT * FROM t WHERE a = '{v1}'\")\n"
        "    v2 = validate_input(request.args['q'])\n"
        "    cur.execute(f\"SELECT * FROM t WHERE b = '{v2}'\")\n"
        "    v3 = hashlib.sha256(request.args['q'].encode()).digest().decode('latin1')\n"
        "    cur.execute(f\"SELECT * FROM t WHERE c = '{v3}'\")\n"
        "    v4 = hashlib.sha256(request.args['q'].encode()).hexdigest()\n"
        "    cur.execute(f\"SELECT * FROM t WHERE d = '{v4}'\")\n"
    )
    high_sql = [f.line for f in _scan(tmp_path).findings if f.rule_id == "BE001" and f.severity == "high"]
    assert high_sql == [12, 14, 16]


def test_augassign_invalidates_html_sanitization(tmp_path):
    (tmp_path / "app.py").write_text(
        "import html\nfrom flask import Flask, request\nfrom markupsafe import Markup\napp = Flask(__name__)\n\n"
        "@app.get('/bad')\ndef bad():\n"
        "    safe = html.escape(request.args['q'])\n"
        "    safe += request.args['q']\n"
        "    return Markup(safe)\n\n"
        "@app.get('/good')\ndef good():\n"
        "    safe = html.escape(request.args['q'])\n"
        "    safe += '!'\n"
        "    return Markup(safe)\n"
    )
    assert _lines(_scan(tmp_path), "FE001") == [10]


def test_js_schema_parse_and_zod_string_do_not_hide_sqli_or_xss(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "4.18.0"}}')
    (tmp_path / "server.ts").write_text(
        "import express from 'express';\n"
        "const app = express();\n"
        "app.get('/sql', (req, res) => {\n"
        "  const n = userSchema.parse(req.query.name);\n"
        "  db.query(`SELECT * FROM users WHERE name = '${n}'`);\n"
        "  const s = z.string().max(100).parse(req.query.bio);\n"
        "  db.query(`SELECT * FROM users WHERE bio = '${s}'`);\n"
        "  const id = z.number().parse(req.query.id);\n"
        "  db.query(`SELECT * FROM users WHERE id = ${id}`);\n"
        "});\n"
        "app.get('/xss', (req, res) => {\n"
        "  const name = userSchema.parse(req.query.name);\n"
        "  el.innerHTML = name;\n"
        "});\n"
    )
    res = _scan(tmp_path)
    high_sql = sorted(f.line for f in res.findings if f.rule_id == "BE001" and f.severity == "high")
    assert high_sql == [5, 7]
    assert _lines(res, "FE001") == [13]


def test_mongodb_where_and_js_schema_nosql_scoping(tmp_path):
    (tmp_path / "py_mongo.py").write_text(
        "from pymongo import MongoClient\nfrom flask import Flask, request\napp = Flask(__name__)\ncoll = MongoClient().db.u\n\n"
        "@app.post('/w')\ndef w():\n"
        "    q = request.json['q']\n"
        "    coll.find({'$where': f\"this.a == '{q}'\"})\n"
        "    coll.find({'$where': str(q)})\n"
        "    coll.find({'name': str(q)})\n"
    )
    assert _lines(_scan(tmp_path), "BE010") == [9, 10]

    js_dir = tmp_path / "js"
    js_dir.mkdir()
    (js_dir / "package.json").write_text('{"dependencies": {"express": "4.18.0", "mongoose": "8.0.0", "express-mongo-sanitize": "2.2.0"}}')
    (js_dir / "routes.js").write_text(
        "const express = require('express');\nconst app = express();\n"
        "app.get('/w', async (req, res) => {\n"
        "  await User.find({ $where: `this.name == '${req.query.name}'` });\n"
        "});\n"
    )
    assert _lines(_scan(js_dir), "BE010") == [4]


def test_feed_size_and_bool_version_rejection():
    key = feed.generate_key(1024)
    pub = {"n": key["n"], "e": key["e"]}
    oversized = b"x" * (feed.MAX_FEED_BYTES + 1)
    with pytest.raises(feed.FeedError, match="too large"):
        feed.open_feed(oversized, pub)

    payload = json.dumps({"format": feed.FORMAT, "version": True, "created": "2026-01-01T00:00:00+00:00",
                          "expires": "2099-01-01T00:00:00+00:00", "data": {}})
    sig = base64.b64encode(feed.sign(payload.encode("utf-8"), key)).decode("ascii")
    raw = json.dumps({"payload": payload, "signature": sig}).encode("utf-8")
    with pytest.raises(feed.FeedError):
        feed.open_feed(raw, pub)


def test_mcp_hardening_rejects_bad_params_empty_and_large_batches():
    res_params = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": [1, 2]})
    assert res_params["error"]["code"] == -32602

    res_args = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                  "params": {"name": "explain_rule", "arguments": "AUTH001"}})
    assert res_args["error"]["code"] == -32602

    out = io.StringIO()
    big_batch = json.dumps([{"jsonrpc": "2.0", "id": i, "method": "ping"} for i in range(mcp_server.MAX_BATCH + 1)])
    inp = io.StringIO("[]\n" + big_batch + "\n" + ("a" * (mcp_server.MAX_LINE_BYTES + 1)) + "\n")
    assert mcp_server.serve(inp, out) == 0
    lines = [json.loads(line) for line in out.getvalue().splitlines()]
    assert [l["error"]["code"] for l in lines] == [-32600, -32600, -32600]


def test_probe_verifies_tls_on_remote_targets_by_default():
    remote = probe.Target("https://example.com", own=True, rate=1.0, max_requests=5)
    assert remote._ssl_context().verify_mode == ssl.CERT_REQUIRED

    remote_insecure = probe.Target("https://example.com", own=True, rate=1.0, max_requests=5, insecure=True)
    assert remote_insecure._ssl_context().verify_mode == ssl.CERT_NONE

    local = probe.Target("https://127.0.0.1:8443", own=False, rate=1.0, max_requests=5)
    assert local._ssl_context().verify_mode == ssl.CERT_NONE


def test_redirect_augassign_query_string_stays_same_site(tmp_path):
    (tmp_path / "views.py").write_text(
        "from django.shortcuts import redirect\nfrom django.urls import reverse\n\n"
        "def safe_search(request):\n"
        "    q = request.GET.get('q')\n"
        "    search_url = reverse('docs')\n"
        "    if q:\n"
        "        search_url += '?q=%s' % q\n"
        "    return redirect(search_url)\n\n"
        "def bad_append(request):\n"
        "    q = request.GET.get('q')\n"
        "    bad_url = reverse('docs')\n"
        "    if q:\n"
        "        bad_url += q\n"
        "    return redirect(bad_url)\n"
    )
    assert _lines(_scan(tmp_path), "BE008") == [16]


def test_js_arbitrary_schema_parse_and_zod_union_do_not_hide_nosql_or_sqli(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "4.18.0", "mongoose": "8.0.0"}}')
    (tmp_path / "routes.ts").write_text(
        "import express from 'express';\nimport { z } from 'zod';\n"
        "const app = express();\n"
        "const filterSchema = z.record(z.unknown());\n"
        "app.post('/users/search', async (req, res) => {\n"
        "  const filter = filterSchema.parse(req.body.filter);\n"
        "  await User.find(filter);\n"
        "  await User.find(filterSchema.parse(req.body.filter));\n"
        "  await User.find({ email: userSchema.parse(req.body.email) });\n"
        "  const y = z.string().or(z.any()).parse(req.body.y);\n"
        "  await User.find({ y });\n"
        "  await User.find({ email: String(req.body.email) });\n"
        "  const s = z.string().max(100).parse(req.body.name);\n"
        "  await User.find({ name: s });\n"
        "  const eq = { email: { $eq: req.body.email } };\n"
        "  await User.find(eq);\n"
        "  const found = items.find((u) => u.id === req.query.id);\n"
        "  const x = z.number().or(z.string()).parse(req.query.x);\n"
        "  db.query(`SELECT * FROM users WHERE name = '${x}'`);\n"
        "});\n"
    )
    res = _scan(tmp_path)
    assert _lines(res, "BE010") == [7, 8, 9, 11]
    assert sorted(f.line for f in res.findings if f.rule_id == "BE001" and f.severity == "high") == [19]
