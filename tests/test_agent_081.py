"""AI agent and LLM rules added in 0.8.1 (LLM016-LLM018)."""
import time

from vibeaudit.rules import RULES
from vibeaudit.scanner import Options, scan

NEW = ("LLM016", "LLM017", "LLM018")


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def found(root, *rules):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low"))
    assert res.meta.get("internal_errors", []) == []
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id in (rules or NEW))


def test_new_rules_start_as_preview():
    assert all(RULES[r].preview and RULES[r].preview_reason for r in NEW)


def test_agent_configs_that_approve_everything(tmp_path):
    write(tmp_path, ".claude/settings.json",
          '{\n  "permissions": {\n    "defaultMode": "bypassPermissions",\n'            # 3
          '    "allow": ["Bash", "Bash(npm test)", "Read"]\n  }\n}\n')                    # 4
    write(tmp_path, ".vscode/settings.json", '{\n  "chat.tools.autoApprove": true,\n  "editor.tabSize": 2\n}\n')   # 2
    write(tmp_path, ".mcp.json", '{\n "mcpServers": {\n  "fs": {\n   "command": "fs-server",\n   "autoApprove": ["*"]\n  },\n'
          '  "gh": {\n   "command": "gh-server",\n   "autoApprove": ["list_issues"]\n  }\n }\n}\n')              # 5
    write(tmp_path, ".codex/config.toml", 'model = "o4"\napproval_policy = "never"\n')                             # 2
    write(tmp_path, "scripts/agent.sh", "#!/bin/sh\nclaude -p \"$TASK\" --dangerously-skip-permissions\n")         # 2
    write(tmp_path, ".claude/settings.local.json", '{"permissions": {"allow": ["Bash(git status)", "Edit"]}}\n')
    assert found(tmp_path) == [(".claude/settings.json", 3, "LLM016"), (".claude/settings.json", 4, "LLM016"),
                               (".codex/config.toml", 2, "LLM016"), (".mcp.json", 5, "LLM016"),
                               (".vscode/settings.json", 2, "LLM016"), ("scripts/agent.sh", 2, "LLM016")]


def test_streams_without_cancellation(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next": "15.0.0", "ai": "4.0.0", "openai": "4.0.0"}}')
    write(tmp_path, "app/api/chat/route.ts",
          "import { streamText } from 'ai';\nimport { openai } from '@ai-sdk/openai';\n"
          "export async function POST(req: Request) {\n  const { messages } = await req.json();\n"
          "  const result = streamText({ model: openai('gpt-4o'), messages });\n  return result.toDataStreamResponse();\n}\n")
    write(tmp_path, "app/api/safe/route.ts",
          "import { streamText } from 'ai';\nimport { openai } from '@ai-sdk/openai';\n"
          "export async function POST(req: Request) {\n  const { messages } = await req.json();\n"
          "  const result = streamText({ model: openai('gpt-4o'), messages, abortSignal: req.signal });\n"
          "  return result.toDataStreamResponse();\n}\n")
    write(tmp_path, "api.py", "from fastapi import FastAPI, Request\nfrom fastapi.responses import StreamingResponse\n"
          "from openai import OpenAI\napp = FastAPI()\nclient = OpenAI()\n\n"
          "@app.post('/chat')\nasync def chat(request: Request):\n"
          "    def gen():\n        for c in client.chat.completions.create(model='gpt-4o', messages=[], stream=True):\n"
          "            yield c.choices[0].delta.content or ''\n    return StreamingResponse(gen())\n\n"
          "@app.post('/chat2')\nasync def chat2(request: Request):\n"
          "    async def gen():\n        for c in client.chat.completions.create(model='gpt-4o', messages=[], stream=True):\n"
          "            if await request.is_disconnected():\n                break\n"
          "            yield c.choices[0].delta.content or ''\n    return StreamingResponse(gen())\n")
    assert found(tmp_path, "LLM017") == [("api.py", 8, "LLM017"), ("app/api/chat/route.ts", 3, "LLM017")]


def test_prompts_and_completions_in_logs(tmp_path):
    write(tmp_path, "bot.py", "import logging\nfrom openai import OpenAI\nlogger = logging.getLogger(__name__)\n"
          "def ask(prompt):\n    logger.info('prompt: %s', prompt)\n"                                  # 5
          "    r = OpenAI().chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': prompt}])\n"
          "    logger.debug(r.choices[0].message.content)\n"                                          # 7
          "    logger.info('prompt tokens: %d', len(prompt))\n"
          "    logger.info('done in %s ms', 12)\n    return r\n")
    write(tmp_path, "util.py", "import logging\nlog = logging.getLogger()\ndef f(prompt):\n    log.info(prompt)\n")  # no model here
    write(tmp_path, "chat.ts", "import OpenAI from 'openai';\nconst openai = new OpenAI();\n"
          "export async function ask(messages) {\n  console.log('messages', messages);\n"                # 4
          "  const r = await openai.chat.completions.create({ model: 'gpt-4o', messages });\n"
          "  console.log('count', messages.length);\n  return r;\n}\n")
    assert found(tmp_path, "LLM018") == [("bot.py", 5, "LLM018"), ("bot.py", 7, "LLM018"), ("chat.ts", 4, "LLM018")]


def test_new_agent_patterns_are_linear_on_hostile_input(tmp_path):
    write(tmp_path, ".mcp.json", '{"mcpServers": {' + ", ".join(f'"s{i}": {{"autoApprove": ["x"]}}' for i in range(5000)) + "}}")
    write(tmp_path, "a.py", "import openai\n" + "logger.info(" + "(" * 20000 + "\n" + "logger.info(" * 5000 + "\n")
    write(tmp_path, "b.sh", "--yolo " * 20000)
    start = time.time()
    found(tmp_path)
    assert time.time() - start < 15


def test_docs_that_mention_the_flags_are_not_agent_launches(tmp_path):
    # vibeaudit's own CHANGELOG and docs/RULES.md name the flags while explaining the rule
    write(tmp_path, "CHANGELOG.md", "- LLM016 reports `--dangerously-skip-permissions` and `--yolo`.\n")
    write(tmp_path, "docs/agents.txt", "never use --dangerously-skip-permissions outside a sandbox\n")
    write(tmp_path, "Makefile", "agent:\n\tclaude -p \"$(TASK)\" --dangerously-skip-permissions\n")
    assert found(tmp_path, "LLM016") == [("Makefile", 2, "LLM016")]
