"""LLM rules added in 0.8.6, and the Phase 1 items that existing rules already cover."""
from vibeaudit.rules import RULES
from vibeaudit.scanner import Options, scan

PY_AGENT = '''import os
import sqlite3
import subprocess

import requests
from flask import Flask, redirect, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI()


@app.post("/ask")
def ask():
    q = request.json["q"]
    r = client.chat.completions.create(model="gpt-4o", max_tokens=200, messages=[{"role": "user", "content": q}])
    answer = r.choices[0].message.content
    db = sqlite3.connect("x.db")
    db.execute(f"SELECT * FROM notes WHERE title = '{answer}'")
    subprocess.run(["git", "checkout", answer], check=True)
    subprocess.run(["git", "checkout", "--", answer], check=True)
    with open(os.path.join("/srv/files", answer)) as fh:
        return fh.read()


@app.post("/preview")
def preview():
    url = request.json["url"]
    return requests.get(url, timeout=5).text


@app.get("/login/done")
def done():
    return redirect(request.args.get("next"))
'''

JS_AGENT = """import OpenAI from 'openai';
import { exec, execFile } from 'child_process';
import fs from 'fs';
import { sql } from './db';
const openai = new OpenAI();
export async function POST(req: Request) {
  const { q } = await req.json();
  const r = await openai.chat.completions.create({ model: 'gpt-4o', max_tokens: 100, messages: [{ role: 'user', content: q }] });
  const out = r.choices[0].message.content;
  await sql.unsafe(`SELECT * FROM t WHERE x = '${out}'`);
  exec(`ls ${out}`);
  execFile('git', ['checkout', out]);
  execFile('git', ['checkout', '--', out]);
  return new Response(fs.readFileSync('/srv/' + out, 'utf8'));
}
"""

JS_PREVIEW = """export async function POST(req: Request) {
  const { url } = await req.json();
  const res = await fetch(url);
  return new Response(await res.text());
}
"""


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def found(root):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low"))
    assert res.meta.get("internal_errors", []) == []
    return {(f.file, f.line, f.rule_id) for f in res.findings}


def test_new_rules_start_as_preview():
    assert RULES["LLM019"].preview and RULES["LLM019"].preview_reason


def test_model_output_as_sql_shell_argument_and_path(tmp_path):
    write(tmp_path, "agent.py", PY_AGENT)
    write(tmp_path, "app/api/agent/route.ts", JS_AGENT)
    write(tmp_path, "package.json", '{"dependencies": {"next": "15.0.0", "openai": "4.0.0"}}')
    write(tmp_path, "requirements.txt", "flask\nrequests\nopenai\n")
    f = found(tmp_path)
    # SQL, shell and file path sinks: LLM002 (Phase 1 item "model output used as SQL, a shell argument or a path")
    assert {("agent.py", 19, "LLM002"), ("agent.py", 22, "LLM002"),
            ("app/api/agent/route.ts", 10, "LLM002"), ("app/api/agent/route.ts", 11, "LLM002"),
            ("app/api/agent/route.ts", 14, "LLM002")} <= f
    # an argument (not the program) of a process run without a shell: LLM019, but not after `--`
    llm019 = sorted(x for x in f if x[2] == "LLM019")
    assert llm019 == [("agent.py", 20, "LLM019"), ("app/api/agent/route.ts", 12, "LLM019")]


def test_fetch_this_url_and_redirect_features(tmp_path):
    write(tmp_path, "agent.py", PY_AGENT)
    write(tmp_path, "app/api/preview/route.ts", JS_PREVIEW)
    write(tmp_path, "package.json", '{"dependencies": {"next": "15.0.0"}}')
    write(tmp_path, "requirements.txt", "flask\nrequests\nopenai\n")
    f = found(tmp_path)
    assert {("agent.py", 29, "BE005"), ("app/api/preview/route.ts", 3, "BE005"), ("agent.py", 34, "BE008")} <= f


AGENT_LOOP_PY = '''from openai import OpenAI

client = OpenAI()


def run(messages, tools):
    resp = client.chat.completions.create(model="gpt-4o", max_tokens=100, messages=messages, tools=tools)
    while resp.choices[0].message.tool_calls:
        messages.append(call_tools(resp))
        resp = client.chat.completions.create(model="gpt-4o", max_tokens=100, messages=messages, tools=tools)
    return resp


def bounded(messages, tools):
    resp = client.chat.completions.create(model="gpt-4o", max_tokens=100, messages=messages, tools=tools)
    steps = 0
    while resp.choices[0].message.tool_calls and steps < 10:
        steps += 1
        resp = client.chat.completions.create(model="gpt-4o", max_tokens=100, messages=messages, tools=tools)
    return resp


def poll(job):
    while not job.done:
        job.refresh()
'''

AGENT_LOOP_TS = """import Anthropic from '@anthropic-ai/sdk';
const client = new Anthropic();
export async function run(messages: any[]) {
  let res = await client.messages.create({ model: 'm', max_tokens: 100, messages });
  while (res.stop_reason === 'tool_use') {
    messages.push(await useTools(res));
    res = await client.messages.create({ model: 'm', max_tokens: 100, messages });
  }
  let step = 0;
  do {
    res = await client.messages.create({ model: 'm', max_tokens: 100, messages });
    step++;
  } while (res.stop_reason === 'tool_use' && step < 8);
  do {
    res = await client.messages.create({ model: 'm', max_tokens: 100, messages });
  } while (res.stop_reason === 'tool_use');
  return res;
}
"""


def test_agent_loops_without_a_step_limit(tmp_path):
    write(tmp_path, "agent.py", AGENT_LOOP_PY)
    write(tmp_path, "loop.ts", AGENT_LOOP_TS)
    write(tmp_path, "requirements.txt", "openai\n")
    write(tmp_path, "package.json", '{"dependencies": {"@anthropic-ai/sdk": "0.30.0"}}')
    f = found(tmp_path)
    assert sorted(x for x in f if x[2] in ("LLM020", "LLM009")) == [
        ("agent.py", 8, "LLM020"), ("loop.ts", 5, "LLM020"), ("loop.ts", 16, "LLM020")]


def test_user_text_in_prompts_without_delimiters(tmp_path):
    write(tmp_path, "chat.py",
          "from openai import OpenAI\nclient = OpenAI()\n\n"
          "def answer(question, ticket):\n"
          '    prompt = f"You are a support assistant. Answer the customer using only the docs. {question}"\n'   # 5
          '    safe = f"You are a support assistant. Answer using only the docs.\n<question>{question}</question>"\n'
          '    quoted = f"You are a support assistant. Answer the customer using only the docs: \\"{question}\\""\n'
          '    note = f"Ticket {ticket.id} was updated by the customer and should be answered soon."\n'
          "    return client.chat.completions.create(model='m', max_tokens=5, messages=[{'role': 'user', 'content': prompt}])\n")
    write(tmp_path, "route.ts",
          "import OpenAI from 'openai';\nconst openai = new OpenAI();\n"
          "export async function POST(req: Request) {\n  const { message } = await req.json();\n"
          "  const prompt = `Summarize the following support request in two sentences and do not add facts: ${message}`;\n"   # 5
          "  const ok = `Summarize the following support request in two sentences and do not add facts:\n---\n${message}\n---`;\n"
          "  return openai.chat.completions.create({ model: 'm', max_tokens: 5, messages: [{ role: 'user', content: prompt + ok }] });\n}\n")
    write(tmp_path, "requirements.txt", "openai\n")
    write(tmp_path, "package.json", '{"dependencies": {"openai": "4.0.0"}}')
    assert sorted(x for x in found(tmp_path) if x[2] == "LLM021") == [("chat.py", 5, "LLM021"), ("route.ts", 5, "LLM021")]


def test_documents_indexed_without_cleaning(tmp_path):
    write(tmp_path, "ingest.py",
          "from langchain_community.document_loaders import WebBaseLoader\nfrom langchain_chroma import Chroma\n\n"
          "def ingest(url, emb):\n    docs = WebBaseLoader(url).load()\n    return Chroma.from_documents(docs, emb)\n")   # 6
    write(tmp_path, "clean_ingest.py",
          "from langchain_community.document_loaders import WebBaseLoader\nfrom langchain_chroma import Chroma\n"
          "import bleach\n\ndef ingest(url, emb):\n    docs = WebBaseLoader(url).load()\n"
          "    for d in docs:\n        d.page_content = bleach.clean(d.page_content, strip=True)\n"
          "    return Chroma.from_documents(docs, emb)\n")
    write(tmp_path, "requirements.txt", "langchain-community\nlangchain-chroma\nbleach\n")
    assert sorted(x for x in found(tmp_path) if x[2] == "LLM022") == [("ingest.py", 6, "LLM022")]


FLASK_LLM = ("from flask import Flask, request\nfrom flask_login import login_required\nfrom openai import OpenAI\n"
             "app = Flask(__name__)\nclient = OpenAI()\n\n@app.post('/ask')\n@login_required\ndef ask():\n"
             "    r = client.chat.completions.create(model='m', max_tokens=50, messages=[{'role': 'user', 'content': request.json['q']}])\n"
             "    return r.choices[0].message.content\n")


def test_per_user_cost_limits(tmp_path):
    write(tmp_path, "app.py", FLASK_LLM)
    write(tmp_path, "requirements.txt", "flask\nflask-login\nopenai\n")
    assert [x for x in found(tmp_path) if x[2] == "LLM023"] == [("app.py", 9, "LLM023")]
    write(tmp_path, "usage.py", "def record(user, r):\n    user.tokens_used += r.usage.total_tokens\n")
    assert [x for x in found(tmp_path) if x[2] == "LLM023"] == []


def test_llm_code_without_tests_or_evals(tmp_path):
    write(tmp_path, "app.py", FLASK_LLM)
    write(tmp_path, "requirements.txt", "flask\nflask-login\nopenai\n")
    assert [x for x in found(tmp_path) if x[2] == "LLM024"] == []          # no tests at all: QA001's
    write(tmp_path, "tests/test_math.py", "def test_add():\n    assert 1 + 1 == 2\n")
    assert [x for x in found(tmp_path) if x[2] == "LLM024"] == [("app.py", 3, "LLM024")]
    write(tmp_path, "tests/test_ask.py", "from app import ask\n\ndef test_ask(monkeypatch):\n    pass\n")
    assert [x for x in found(tmp_path) if x[2] == "LLM024"] == []


def test_prompt_checks_are_linear_on_hostile_input(tmp_path):
    import time
    write(tmp_path, "a.py", "import openai\n" + 'f"' * 20000 + "\n" + ('x = f"""You are helpful. Answer the following ' + "{q} " * 2000 + '"""\n') * 20)
    write(tmp_path, "b.ts", "openai.chat.completions.create({});\n" + "`" * 20001 + "\n" + ("const p = `You are helpful. Answer the following " + "${q} " * 2000 + "`;\n") * 20)
    start = time.time()
    found(tmp_path)
    assert time.time() - start < 30


def test_prompt_rules_skip_logs_own_keys_and_endpoint_tests(tmp_path):
    write(tmp_path, "route.ts",
          "import OpenAI from 'openai';\nconst openai = new OpenAI();\n"
          "export async function POST(req: Request) {\n  const { question } = await req.json();\n"
          "  console.log(`Answer bot is now processing the following question from the user: ${question}`);\n"
          "  return openai.chat.completions.create({ model: 'm', max_tokens: 5, messages: [] });\n}\n")
    write(tmp_path, "package.json", '{"dependencies": {"openai": "4.0.0"}}')
    assert [x for x in found(tmp_path) if x[2] == "LLM021"] == []
    write(tmp_path, "app.py", FLASK_LLM.replace("client = OpenAI()", "client = OpenAI(api_key=current_user.settings.openai_api_key)"))
    write(tmp_path, "requirements.txt", "flask\nflask-login\nopenai\n")
    assert [x for x in found(tmp_path) if x[2] == "LLM023"] == []
    write(tmp_path, "tests/test_math.py", "def test_add():\n    assert 1 + 1 == 2\n")
    write(tmp_path, "tests/test_e2e.py", "import requests\n\ndef test_ask():\n    requests.post('http://localhost:5000/ask', json={})\n")
    assert [x for x in found(tmp_path) if x[2] == "LLM024"] == []


def test_http_tests_of_the_llm_service_count(tmp_path):
    write(tmp_path, "svc/app.py", FLASK_LLM)
    write(tmp_path, "svc/requirements.txt", "flask\nflask-login\nopenai\n")
    write(tmp_path, "svc/test_api.py", "import requests\n\ndef test_health():\n    requests.get('http://localhost:5000/health')\n")
    assert [x for x in found(tmp_path) if x[2] == "LLM024"] == []


def test_cost_bounded_by_rate_limit_and_token_cap_or_a_gateway(tmp_path):
    limited = FLASK_LLM.replace("@login_required\n", "@login_required\n@limiter.limit('10 per minute')\n").replace(
        "from openai import OpenAI\n", "from openai import OpenAI\nfrom flask_limiter import Limiter\nlimiter = Limiter()\n")
    write(tmp_path, "app.py", limited)
    write(tmp_path, "requirements.txt", "flask\nflask-login\nflask-limiter\nopenai\n")
    assert [x for x in found(tmp_path) if x[2] == "LLM023"] == []
    write(tmp_path, "app.py", FLASK_LLM.replace("client = OpenAI()", "client = OpenAI(base_url='https://gateway.ai.cloudflare.com/v1/acct/gw/openai')"))
    assert [x for x in found(tmp_path) if x[2] == "LLM023"] == []
