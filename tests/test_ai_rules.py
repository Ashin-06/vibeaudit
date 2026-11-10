"""AI rules LLM010-LLM015."""
import json

from vibeaudit.scanner import Options, scan


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _rules(tmp_path, prefix="LLM01"):
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id.startswith(prefix))


def test_vector_search_needs_a_tenant_filter_on_authenticated_routes(tmp_path):
    write(tmp_path, "app.py",
          "@app.post('/ask')\n@login_required\ndef ask():\n    docs = store.similarity_search(request.json['q'])\n    return ''\n\n"
          "@app.post('/ask2')\n@login_required\ndef ask2():\n"
          "    docs = store.similarity_search(request.json['q'], filter={'user_id': current_user.id})\n    return ''\n\n"
          "@app.post('/public')\ndef public():\n    docs = store.similarity_search(request.json['q'])\n    return ''\n")
    assert _rules(tmp_path) == [("app.py", 4, "LLM010")]


def test_supabase_rpc_with_the_users_jwt_is_left_to_row_level_security(tmp_path):
    handler = ("export async function POST(req) {\n  const user = await getUser(req)\n  if (!user) return new Response('', {status: 401})\n"
               "  const { data } = await {client}.rpc('match_documents', { query_embedding: e, match_count: 5 })\n"
               "  return Response.json(data)\n}\n")
    write(tmp_path, "package.json", '{"dependencies": {"next": "14.0.0"}}')
    write(tmp_path, "app/api/search/route.ts", handler.replace("{client}", "supabase"))
    assert _rules(tmp_path) == []
    write(tmp_path, "app/api/search/route.ts", handler.replace("{client}", "supabaseAdmin"))
    assert _rules(tmp_path) == [("app/api/search/route.ts", 4, "LLM010")]


def test_json_parse_of_model_output(tmp_path):
    write(tmp_path, "a.py",
          "import json\n\ndef plan(q):\n    reply = client.chat.completions.create(model='m', max_tokens=9, messages=q)\n"
          "    return json.loads(reply.choices[0].message.content)\n\n"
          "def plan_safe(q):\n    reply = client.chat.completions.create(model='m', max_tokens=9, messages=q)\n    try:\n"
          "        return json.loads(reply.choices[0].message.content)\n    except ValueError:\n        return None\n\n"
          "def plan_json_mode(q):\n    reply = client.chat.completions.create(model='m', max_tokens=9, messages=q,\n"
          "                                           response_format={'type': 'json_object'})\n"
          "    return json.loads(reply.choices[0].message.content)\n")
    write(tmp_path, "b.ts",
          "export async function a(q) {\n  const r = await openai.chat.completions.create({ model: 'm', max_tokens: 9, messages: q })\n"
          "  return JSON.parse(r.choices[0].message.content)\n}\n"
          "export async function b(q) {\n  const r = await openai.chat.completions.create({ model: 'm', max_tokens: 9, messages: q,\n"
          "    response_format: { type: 'json_object' } })\n  return JSON.parse(r.choices[0].message.content)\n}\n"
          "export async function c(q) {\n  const r = await openai.chat.completions.create({ model: 'm', max_tokens: 9, messages: q })\n"
          "  try {\n    return JSON.parse(r.choices[0].message.content)\n  } catch {\n    return null\n  }\n}\n")
    assert _rules(tmp_path) == [("a.py", 5, "LLM011"), ("b.ts", 3, "LLM011")]


def test_retired_models_are_reported_once_per_project(tmp_path):
    write(tmp_path, "a.py", "MODEL = 'claude-2.1'\nCURRENT = 'claude-sonnet-4-5'\n")
    write(tmp_path, "b.py", "MODELS = ['claude-2.1', 'gemini-1.5-pro']\n")
    assert _rules(tmp_path) == [("a.py", 1, "LLM012"), ("b.py", 1, "LLM012")]


def test_mcp_config_exposure(tmp_path):
    servers = {
        "fs_root": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/"]},
        "fs_home": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "~"]},
        "fs_project": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "./src"]},
        "plain": {"url": "http://mcp.corp.example.org/sse"},
        "local": {"url": "http://localhost:3001/sse"},
        "tls": {"url": "https://mcp.corp.example.org/sse"},
        "keyed": {"command": "node", "args": ["s.js"], "env": {"SERVICE_API_KEY": "svc_q8Zr2LmW4vNpTt"}},
        "ref": {"command": "node", "args": ["s.js"], "env": {"SERVICE_API_KEY": "${SERVICE_API_KEY}", "LOG_LEVEL": "debug"}},
    }
    text = json.dumps({"mcpServers": servers}, indent=1)
    write(tmp_path, ".mcp.json", text)
    lines = text.splitlines()
    at = lambda s: next(i for i, ln in enumerate(lines, 1) if s in ln)  # noqa: E731
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    got = sorted((f.line, f.rule_id) for f in res.findings if f.rule_id in ("LLM013", "LLM014") or f.rule_id.startswith("SEC"))
    # the hardcoded key is reported once, as LLM014, not again by the generic secret rules
    assert got == sorted([(at('"/"'), "LLM013"), (at('"~"'), "LLM013"), (at("http://mcp.corp"), "LLM013"),
                          (at("svc_q8Zr2"), "LLM014")])


def test_agent_with_untrusted_input_and_dangerous_tools(tmp_path):
    tools = ("@tool\ndef web_search(q: str) -> str:\n    return ''\n\n"
             "@tool\ndef run_shell(cmd: str) -> str:\n    return ''\n\n"
             "@tool\ndef summarize(t: str) -> str:\n    return ''\n\n")
    write(tmp_path, "agent.py", tools + "agent = create_react_agent(llm, [web_search, run_shell])\n")
    assert _rules(tmp_path) == [("agent.py", 13, "LLM015")]
    write(tmp_path, "agent.py", tools.replace("run_shell", "word_count") + "agent = create_react_agent(llm, [web_search, word_count])\n")
    assert _rules(tmp_path) == []
