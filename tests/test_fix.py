"""`vibeaudit fix`: every codemod removes its finding, keeps the file parseable, adds no other finding and is
idempotent. Each case first asserts that the finding is reported, so a test fails if its codemod is removed."""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Dict

import pytest

from vibeaudit import fix
from vibeaudit.config import project_options
from vibeaudit.scanner import scan


def write(root: Path, files: Dict[str, str], newline: str = "\n") -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text.replace("\n", newline).encode("utf-8"))


def findings(root: Path):
    return scan(str(root), project_options(str(root), offline=True, external="none")).findings


def keys(fs):
    return {(f.rule_id, f.file) for f in fs}


def roundtrip(root: Path, files: Dict[str, str], rule: str, newline: str = "\n") -> Dict[str, str]:
    write(root, files, newline)
    before = findings(root)
    assert rule in {f.rule_id for f in before}, f"{rule} is not reported before the fix"
    plan = fix.plan(str(root))
    assert rule in {f.rule_id for f in plan.fixed}, plan.skipped
    diff = plan.diff()
    assert diff.startswith("--- a/")
    assert plan.apply()
    after = findings(root)
    assert rule not in {f.rule_id for f in after}, [f.message for f in after if f.rule_id == rule]
    gone = {(f.rule_id, f.file, f.snippet) for f in before}
    new = [f for f in after if (f.rule_id, f.file) not in keys(before)]
    assert not new, [(f.rule_id, f.message) for f in new]
    assert not {(f.rule_id, f.file) for f in after} - {(r, fl) for r, fl, _s in gone}
    out = {}
    for rel in files:
        data = (root / rel).read_bytes()
        text = data.decode("utf-8")
        if newline == "\r\n":
            assert text.count("\r\n") == text.count("\n"), "line endings changed"
        if rel.endswith(".py"):
            ast.parse(text)
        elif rel.endswith((".js", ".ts")):
            assert fix.parses("js", text.replace("\r\n", "\n"))
        out[rel] = text.replace("\r\n", "\n")
    again = fix.plan(str(root))
    assert not [c for c in again.changes if any(f.rule_id == rule for f in c.fixed)], again.diff()
    return out


def test_timeout_python(tmp_path):
    src = ("import requests\nfrom urllib.request import urlopen\n\n\ndef get(u):\n    a = requests.get(u)\n"
           "    b = requests.post(\n        u,\n        json={'a': 1},\n    )\n    c = urlopen(u)\n    return a, b, c\n")
    out = roundtrip(tmp_path, {"app.py": src}, "REL001")["app.py"]
    assert "requests.get(u, timeout=10)" in out
    assert "        json={'a': 1},\n        timeout=10,\n    )" in out
    assert "urlopen(u, timeout=10)" in out


def test_timeout_crlf_and_unicode(tmp_path):
    src = "# -*- coding: utf-8 -*-\nimport requests\n\nr = requests.get('https://ex.com/\u00e9\u00e8\u4e2d', headers={'x': '\u2603'})\n"
    out = roundtrip(tmp_path, {"app.py": src}, "REL001", newline="\r\n")["app.py"]
    assert "headers={'x': '\u2603'}, timeout=10)" in out


def test_token_limit_python(tmp_path):
    src = ("from openai import OpenAI\nfrom langchain_openai import ChatOpenAI\nclient = OpenAI()\n\n\ndef ask(q):\n"
           "    r = client.chat.completions.create(model='gpt-5-mini', messages=[{'role': 'user', 'content': q}])\n"
           "    s = client.responses.create(model='gpt-5-mini', input=q)\n"
           "    llm = ChatOpenAI(model='gpt-5-mini')\n    return r, s, llm\n")
    out = roundtrip(tmp_path, {"app.py": src}, "LLM003")["app.py"]
    assert "max_completion_tokens=4096)" in out
    assert "input=q, max_output_tokens=4096)" in out
    assert "ChatOpenAI(model='gpt-5-mini', max_tokens=4096)" in out


def test_token_limit_js_ai_sdk_version(tmp_path):
    files = {
        "package.json": json.dumps({"dependencies": {"ai": "^5.0.0", "openai": "^5.0.0"}}),
        "app/api/chat/route.ts": (
            "import { generateText } from 'ai';\nimport OpenAI from 'openai';\nconst openai = new OpenAI();\n\n"
            "export async function POST(req: Request) {\n  const { prompt } = await req.json();\n"
            "  const a = await generateText({\n    model: 'openai/gpt-5-mini',\n    prompt,\n  });\n"
            "  const b = await openai.chat.completions.create({ model: 'gpt-5-mini', messages: [] });\n"
            "  return Response.json({ a, b });\n}\n"),
    }
    out = roundtrip(tmp_path, files, "LLM003")["app/api/chat/route.ts"]
    assert "    prompt,\n    maxOutputTokens: 4096,\n  });" in out
    assert "messages: [], max_completion_tokens: 4096 })" in out


def test_token_limit_ai_sdk_v4_and_unknown(tmp_path):
    files = {"package.json": json.dumps({"dependencies": {"ai": "4.3.0"}}),
             "lib/llm.ts": "import { streamText } from 'ai';\nexport const run = (p: string) => streamText({ model: m, prompt: p });\n"}
    out = roundtrip(tmp_path, files, "LLM003")["lib/llm.ts"]
    assert "prompt: p, maxTokens: 4096 })" in out
    write(tmp_path, {"package.json": json.dumps({"dependencies": {}}), "lib/llm.ts": files["lib/llm.ts"]})
    plan = fix.plan(str(tmp_path))
    assert any("AI SDK version" in r for f, r in plan.skipped if f.rule_id == "LLM003")


def test_json_parse_python(tmp_path):
    src = ("import json\nfrom openai import OpenAI\nclient = OpenAI()\n\n\ndef ask(q):\n"
           "    r = client.chat.completions.create(model='m', messages=[], max_tokens=10)\n"
           "    text = r.choices[0].message.content\n    data = json.loads(text)  # parse\n    return data\n\n\n"
           "def ask2(q):\n    r = client.chat.completions.create(model='m', messages=[], max_tokens=10)\n"
           "    return json.loads(r.choices[0].message.content)\n")
    out = roundtrip(tmp_path, {"app.py": src}, "LLM011")["app.py"]
    assert "    try:\n        data = json.loads(text)  # parse\n    except ValueError:\n        data = None\n" in out
    assert "    try:\n        return json.loads(r.choices[0].message.content)\n    except ValueError:\n        return None" in out


def test_json_parse_js(tmp_path):
    src = ("import OpenAI from 'openai';\nconst openai = new OpenAI();\n\nexport async function run(q: string) {\n"
           "  const r = await openai.chat.completions.create({ model: 'm', messages: [], max_tokens: 5 });\n"
           "  const data: Result = JSON.parse(r.choices[0].message.content);\n  return data;\n}\n")
    out = roundtrip(tmp_path, {"lib/run.ts": src}, "LLM011")["lib/run.ts"]
    assert ("  let data: Result | null;\n  try {\n    data = JSON.parse(r.choices[0].message.content);\n  } catch {\n"
            "    data = null;\n  }\n") in out


def test_jwt_pin_algorithm_python(tmp_path):
    src = ("import jwt\nALGORITHM = 'HS256'\n\n\ndef issue(u, key):\n    return jwt.encode({'sub': u}, key, algorithm=ALGORITHM)\n\n\n"
           "def read(token, key):\n    return jwt.decode(token, key)\n")
    out = roundtrip(tmp_path, {"auth.py": src}, "AUTH011")["auth.py"]
    assert "jwt.decode(token, key, algorithms=[ALGORITHM])" in out


def test_jwt_default_and_public_key(tmp_path):
    out = roundtrip(tmp_path, {"auth.py": "import jwt\n\n\ndef read(t, secret):\n    return jwt.decode(t, secret)\n"}, "AUTH011")
    assert 'algorithms=["HS256"]' in out["auth.py"]
    write(tmp_path, {"auth.py": "import jwt\n\n\ndef read(t, public_key):\n    return jwt.decode(t, public_key)\n"})
    assert any("public key" in r for f, r in fix.plan(str(tmp_path)).skipped if f.rule_id == "AUTH011")


def test_jwt_none_and_mixed_js(tmp_path):
    src = ("const jwt = require('jsonwebtoken');\nfunction sign(u) {\n  return jwt.sign(u, process.env.S, { algorithm: 'HS256' });\n}\n"
           "function check(t) {\n  return jwt.verify(t, process.env.S, { algorithms: ['HS256', 'RS256'] });\n}\n"
           "function check2(t) {\n  return jwt.verify(t, process.env.S, { algorithms: ['HS256', 'none'], ignoreExpiration: true });\n}\n"
           "module.exports = { sign, check, check2 };\n")
    out = roundtrip(tmp_path, {"auth.js": src}, "BE016")["auth.js"]
    assert "{ algorithms: ['HS256'], ignoreExpiration: false }" in out
    assert "{ algorithms: ['HS256'] });" in out  # AUTH011 on the mixed list is fixed in the same run


def test_jwt_unverified_is_skipped(tmp_path):
    write(tmp_path, {"auth.py": "import jwt\n\n\ndef read(t):\n    return jwt.decode(t, options={'verify_signature': False})\n"})
    plan = fix.plan(str(tmp_path))
    assert not plan.changes
    assert any("verification key" in r for f, r in plan.skipped if f.rule_id == "BE016")


def test_money_django_and_sqlalchemy(tmp_path):
    src = ("from django.db import models\nfrom django.db.models import FloatField\n\n\nclass Order(models.Model):\n"
           "    total = models.FloatField(default=0)\n    tax = FloatField()\n")
    out = roundtrip(tmp_path, {"shop/models.py": src}, "DATA004")["shop/models.py"]
    assert "total = models.DecimalField(default=0, max_digits=12, decimal_places=2)" in out
    assert "tax = DecimalField(max_digits=12, decimal_places=2)" in out
    assert "from django.db.models import FloatField, DecimalField" in out


def test_money_sqlalchemy(tmp_path):
    src = ("from sqlalchemy import (\n    Column,\n    Float,\n)\nfrom flask_sqlalchemy import SQLAlchemy\ndb = SQLAlchemy()\n\n\n"
           "class Item(db.Model):\n    price = Column(Float)\n    fee = db.Column(db.Float(precision=8), nullable=False)\n")
    out = roundtrip(tmp_path, {"models.py": src}, "DATA004")["models.py"]
    assert "price = Column(Numeric(12, 2))" in out
    assert "fee = db.Column(db.Numeric(12, 2), nullable=False)" in out
    assert "    Float,\n    Numeric,\n)" in out


def test_money_sql_and_prisma(tmp_path):
    files = {"db/schema.sql": "create table orders (\n  id serial primary key,\n  amount double precision not null\n);\n",
             "prisma/schema.prisma": "model Order {\n  id    Int    @id\n  price Float?\n}\n"}
    out = roundtrip(tmp_path, files, "DATA004")
    assert "amount numeric(12, 2) not null" in out["db/schema.sql"]
    assert "price Decimal?" in out["prisma/schema.prisma"]


def test_money_migration_is_skipped(tmp_path):
    write(tmp_path, {"supabase/migrations/001.sql": "create table orders (amount float8);\n"})
    plan = fix.plan(str(tmp_path))
    assert not plan.changes and any("migration" in r for f, r in plan.skipped if f.rule_id == "DATA004")


def test_cors_python(tmp_path):
    src = ('"""App."""\nfrom fastapi import FastAPI\nfrom fastapi.middleware.cors import CORSMiddleware\nfrom flask import Flask\n'
           "from flask_cors import CORS\n\napp = FastAPI()\napp.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n"
           "web = Flask(__name__)\nCORS(web, supports_credentials=True)\n")
    out = roundtrip(tmp_path, {"main.py": src}, "BE012")["main.py"]
    assert '"""App."""\nimport os\nfrom fastapi import FastAPI' in out
    assert out.count("import os") == 1
    assert "allow_origins=" + fix.PY_CORS_ORIGINS in out
    assert "CORS(web, supports_credentials=True, origins=" + fix.PY_CORS_ORIGINS + ")" in out


def test_cors_js(tmp_path):
    src = "const express = require('express');\nconst cors = require('cors');\nconst app = express();\napp.use(cors({ origin: true, credentials: true }));\n"
    out = roundtrip(tmp_path, {"server.js": src}, "BE012")["server.js"]
    assert "cors({ origin: " + fix.JS_CORS_ORIGINS + ", credentials: true })" in out


# ------------------------------------------------------------ adversarial
def test_rule_filter_and_unfixable_rules(tmp_path):
    write(tmp_path, {"app.py": "import requests\nimport jwt\nr = requests.get('u')\nx = jwt.decode('t', 'k')\n"})
    plan = fix.plan(str(tmp_path), rules=["rel001"])
    assert {f.rule_id for f in plan.fixed} == {"REL001"}
    assert "algorithms" not in plan.diff()


def test_mixed_line_endings_and_non_utf8_are_left_alone(tmp_path):
    (tmp_path / "a.py").write_bytes(b"import requests\r\nr = requests.get('u')\n")
    (tmp_path / "b.py").write_bytes("import requests\nr = requests.get('\u00e9')\n".encode("latin-1"))
    plan = fix.plan(str(tmp_path))
    assert not plan.changes
    reasons = {f.file: r for f, r in plan.skipped if f.rule_id == "REL001"}
    assert reasons["a.py"] == "the file mixes line endings" and reasons["b.py"] == "the file is not UTF-8"


def test_bom_is_kept(tmp_path):
    (tmp_path / "a.py").write_bytes(b"\xef\xbb\xbfimport requests\nr = requests.get('u')\n")
    fix.plan(str(tmp_path)).apply()
    assert (tmp_path / "a.py").read_bytes() == b"\xef\xbb\xbfimport requests\nr = requests.get('u', timeout=10)\n"


def test_shapes_that_cannot_be_rewritten_are_skipped(tmp_path):
    src = ("import json\nfrom openai import OpenAI\nclient = OpenAI()\nr = client.chat.completions.create(model='m', messages=[], max_tokens=1)\n"
           "a, b = json.loads(r.choices[0].message.content)\n"
           "if r: c = json.loads(r.choices[0].message.content)\n")
    write(tmp_path, {"app.py": src})
    plan = fix.plan(str(tmp_path))
    assert not plan.changes
    assert len([f for f, _r in plan.skipped if f.rule_id == "LLM011"]) == 2


def test_file_changed_after_planning_is_not_overwritten(tmp_path):
    write(tmp_path, {"a.py": "import requests\nr = requests.get('u')\n"})
    plan = fix.plan(str(tmp_path))
    (tmp_path / "a.py").write_text("import requests\nr = requests.get('v')\n")
    assert plan.apply() == []
    assert "'v')" in (tmp_path / "a.py").read_text()


def test_suppressed_findings_are_not_fixed(tmp_path):
    write(tmp_path, {"a.py": "import requests\nr = requests.get('u')  # vibeaudit: ignore[REL001]\n"})
    assert not fix.plan(str(tmp_path)).changes


@pytest.mark.parametrize("src", [
    "import requests\nr = requests.get(*args)\n",
    "import requests\nr = requests.get(\n    'u'  # comment, with comma\n)\n",
    "import requests\nr = requests.get('u',)\n",
    "import requests\nr = requests.get()\n",
    "import requests\nr = requests.get('u', **{})\n",
    "import requests\nr = (requests.get('a'), requests.get('b'))\n",
    "import requests\nr = requests.get(f'{x}', headers={'a': (1, 2)})\n",
])
def test_odd_call_shapes_stay_valid(tmp_path, src):
    write(tmp_path, {"a.py": src})
    plan = fix.plan(str(tmp_path))
    plan.apply()
    ast.parse((tmp_path / "a.py").read_text())
    assert not fix.plan(str(tmp_path)).changes  # idempotent


def test_balanced_check():
    assert fix.balanced("f({[]})") and not fix.balanced("f({[})") and not fix.balanced("(")
    assert fix.parses("js", "const s = '(';\n// )\nf(`${a}`)\n")


# ------------------------------------------------------------ CLI, MCP and LLM patches
def test_cli_diff_then_apply(tmp_path, capsys):
    from vibeaudit.cli import main

    write(tmp_path, {"a.py": "import requests\nr = requests.get('u')\n"})
    assert main(["fix", str(tmp_path)]) == 0
    out, err = capsys.readouterr()
    assert "+r = requests.get('u', timeout=10)" in out and "1 fixes proposed in 1 files" in err
    assert "timeout" not in (tmp_path / "a.py").read_text()  # the diff alone writes nothing
    assert main(["fix", str(tmp_path), "--apply"]) == 0
    assert "timeout=10" in (tmp_path / "a.py").read_text()
    assert main(["fix", str(tmp_path), "--rule", "NOPE1"]) == 2
    assert main(["fix", str(tmp_path / "missing")]) == 2


def test_cli_diff_applies_with_git_apply(tmp_path):
    import shutil
    import subprocess
    import sys

    if not shutil.which("git"):
        pytest.skip("git not installed")
    write(tmp_path, {"a.py": "import requests\nr = requests.get('u')\n", "b.py": "import requests\nr = requests.get('v')\n"}, "\n")
    (tmp_path / "b.py").write_bytes(b"import requests\r\nr = requests.get('v')\r\n")
    diff = subprocess.run([sys.executable, "-m", "vibeaudit", "fix", str(tmp_path)], capture_output=True, check=True).stdout
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "core.autocrlf=false", "apply", "-"], input=diff, cwd=tmp_path, check=True)
    assert (tmp_path / "a.py").read_bytes().endswith(b"timeout=10)\n")
    assert (tmp_path / "b.py").read_bytes().endswith(b"timeout=10)\r\n")


def test_mcp_auto_repair_returns_diff_and_writes_nothing(tmp_path):
    from vibeaudit.mcp_server import handle

    write(tmp_path, {"a.py": "import requests\nr = requests.get('u')\n", "b.py": "import requests\nr = requests.get('v')\n"})

    def call(args):
        return handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "auto_repair", "arguments": args}})["result"]

    res = call({"path": str(tmp_path), "file": "b.py"})
    assert not res["isError"] and res["structuredContent"]["files"] == ["b.py"]
    assert "+r = requests.get('v', timeout=10)" in res["structuredContent"]["diff"]
    assert "timeout" not in (tmp_path / "b.py").read_text()
    assert call({"path": str(tmp_path), "rules": "REL001"})["isError"]
    assert call({"path": str(tmp_path), "file": str(tmp_path.parent / "x.py")})["isError"]
    assert call({"path": str(tmp_path), "rules": ["XX9"]})["isError"]


class FakeProvider:
    def __init__(self, answers):
        self.answers = list(answers)
        self.requests = 0
        self.prompts = []

    def complete(self, prompt):
        self.requests += 1
        self.prompts.append(prompt)
        return self.answers.pop(0)


def test_llm_patches_are_checked_and_never_applied(tmp_path):
    src = "import jwt\n\n\ndef read(t):\n    return jwt.decode(t, options={'verify_signature': False})\n"
    write(tmp_path, {"auth.py": src, "settings.py": "API_KEY = 'sk-live-abcdefghijklmnopqrstuvwx'\n"})
    plan = fix.plan(str(tmp_path))
    good = json.dumps({"start_line": 5, "end_line": 5, "explanation": "verify with the key",
                       "replacement": "    return jwt.decode(t, KEY, algorithms=['HS256'])"})
    provider = FakeProvider([good])
    text, n = fix.patches(tmp_path, plan.skipped, provider, 5, lambda m: None)
    assert n == 1 and "+    return jwt.decode(t, KEY, algorithms=['HS256'])" in text and "BE016 auth.py:5" in text
    assert (tmp_path / "auth.py").read_text() == src
    for bad in ({"start_line": 1, "end_line": 99, "replacement": "x"},  # outside the window it was shown
                {"start_line": 5, "end_line": 5, "replacement": "    return jwt.decode(t, <REDACTED>)"},
                {"start_line": 5, "end_line": 5, "replacement": "    return jwt.decode(t"},  # does not parse
                {"start_line": 0}):
        text, n = fix.patches(tmp_path, plan.skipped, FakeProvider([json.dumps(bad)]), 5, lambda m: None)
        assert n == 0 and text == ""
    capped = FakeProvider([good, good])
    fix.patches(tmp_path, plan.skipped, capped, 0, lambda m: None)
    assert capped.requests == 0


def test_js_json_parse_outside_statement_position_is_skipped():
    from vibeaudit.model import Finding

    src = "const f = (s) =>\n  data = JSON.parse(s);\nconst g = [\n  x = JSON.parse(s),\n];\n"
    ctx = fix.FileCtx("a.js", src)
    assert isinstance(fix.fix_json_parse(ctx, Finding("LLM011", "a.js", 2, "m")), str)
    assert isinstance(fix.fix_json_parse(ctx, Finding("LLM011", "a.js", 4, "m")), str)
    ok = fix.fix_json_parse(fix.FileCtx("a.js", "if (ok)\n  data = JSON.parse(s);\n"), Finding("LLM011", "a.js", 2, "m"))
    assert isinstance(ok, list)


def test_cors_origin_in_a_string_is_not_rewritten():
    from vibeaudit.model import Finding

    src = "app.use(cors({ note: 'origin: true', credentials: true }));\n"
    assert isinstance(fix.fix_cors(fix.FileCtx("a.js", src), Finding("BE012", "a.js", 1, "m")), str)


# ------------------------------------------------------------ DATA013 Redis expiry
def test_redis_ttl_python(tmp_path):
    src = ("import redis\nr = redis.Redis()\n\n\ndef save(k, v, user):\n    r.set(k, v)\n"
           "    r.hset(f\"user:{user}\", \"seen\", 1)  # profile\n    r.sadd('active', user)\n")
    out = roundtrip(tmp_path, {"cache.py": src}, "DATA013")["cache.py"]
    assert "    r.set(k, v, ex=3600)\n" in out
    assert "    r.hset(f\"user:{user}\", \"seen\", 1)  # profile\n    r.expire(f\"user:{user}\", 3600)\n" in out
    assert "    r.sadd('active', user)\n    r.expire('active', 3600)" in out


def test_redis_ttl_async_python(tmp_path):
    src = ("import redis.asyncio as aioredis\nr = aioredis.from_url('redis://x')\n\n\n"
           "async def save(k):\n    await r.lpush(k, 1)\n")
    out = roundtrip(tmp_path, {"q.py": src}, "DATA013")["q.py"]
    assert "    await r.lpush(k, 1)\n    await r.expire(k, 3600)" in out


def test_redis_ttl_node_redis_and_options(tmp_path):
    src = ("import { createClient } from 'redis';\nconst client = createClient();\n"
           "export async function put(k: string, v: string) {\n  await client.set(k, v);\n"
           "  await client.set(`lock:${k}`, v, { NX: true });\n  await client.hset(k, 'a', '1');\n}\n")
    out = roundtrip(tmp_path, {"cache.ts": src}, "DATA013")["cache.ts"]
    assert "await client.set(k, v, { EX: 3600 });" in out and "{ NX: true, EX: 3600 }" in out
    assert "  await client.hset(k, 'a', '1');\n  await client.expire(k, 3600);\n" in out


def test_redis_ttl_ioredis_and_upstash(tmp_path):
    files = {"a.js": "const Redis = require('ioredis');\nconst redis = new Redis();\nfunction f(k, v) {\n  return redis.set(k, v);\n}\nmodule.exports = f;\n",
             "b.ts": "import { Redis } from '@upstash/redis';\nconst redis = Redis.fromEnv();\nexport const g = (k: string) => redis.set(k, 1);\n"}
    out = roundtrip(tmp_path, files, "DATA013")
    assert 'redis.set(k, v, "EX", 3600)' in out["a.js"] and "redis.set(k, 1, { ex: 3600 })" in out["b.ts"]


def test_redis_ttl_skips_what_it_cannot_rewrite(tmp_path):
    src = ("import redis\nr = redis.Redis()\n\n\ndef f(u, v):\n    r.hset(key_for(u), 'a', 1)\n"
           "    r.set(u, v, None, None, True)\n    x = r.hset('h', 'a', 1)\n")
    write(tmp_path, {"c.py": src})
    plan = fix.plan(str(tmp_path))
    assert not plan.changes
    reasons = sorted(r for f, r in plan.skipped if f.rule_id == "DATA013")
    assert reasons == ["the call has more arguments than a key and a value", "the key is computed by a call; evaluating it twice could differ",
                       "the write is not a statement of its own"]


def test_redis_ttl_attribute_clients(tmp_path):
    src = ("import redis.asyncio as redis\n\n\nclass Store:\n    def __init__(self):\n        self.client = redis.Redis()\n\n"
           "    async def put(self, key, value, ts):\n        await self.client.hset(key, 'v', value)\n"
           "        await self.client.zadd('recent', {key: ts})\n")
    out = roundtrip(tmp_path, {"store.py": src}, "DATA013")["store.py"]
    assert "        await self.client.hset(key, 'v', value)\n        await self.client.expire(key, 3600)\n" in out
    assert "        await self.client.zadd('recent', {key: ts})\n        await self.client.expire('recent', 3600)" in out
