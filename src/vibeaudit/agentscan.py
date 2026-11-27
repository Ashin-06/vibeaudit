"""AI agent and LLM checks: LLM016-LLM018, LLM025, LLM027, LLM028 (all preview)."""
from __future__ import annotations

import re
from typing import Callable, Iterable, List, Tuple

from . import heuristics as H
from .files import Project, SourceFile
from .guard import GUARD, finditer
from .model import Route
from .store import loads_json

Add = Callable[..., None]  # ProjectScanner.add(sf_or_rel, line, rule, message, severity="")

AGENT_SETTINGS = re.compile(
    r"(?:^|/)(?:\.claude/settings(?:\.local)?\.json|\.cursor/(?:mcp|settings|cli)\.json|\.vscode/(?:settings|mcp)\.json"
    r"|\.gemini/settings\.json|\.mcp\.json|mcp\.json|\.codex/config\.toml|\.windsurf/[\w.-]+\.json|\.roo/mcp\.json)$")
# files a coding agent reads as instructions from the developer
AGENT_INSTRUCTIONS = re.compile(
    r"(?:^|/)(?:(?:CLAUDE|AGENTS|GEMINI)(?:\.local)?\.md|\.cursorrules|\.windsurfrules|\.clinerules"
    r"|\.github/copilot-instructions\.md|\.github/instructions/[^/]+\.md|\.cursor/rules/[^/]+\.mdc?"
    r"|\.windsurf/rules/[^/]+\.md|\.claude/(?:commands|agents)/[^/]+\.md|\.claude/skills/.+/SKILL\.md)$")
SKIP_PERMISSION_FLAGS = re.compile(
    r"--dangerously-skip-permissions\b|--dangerously-bypass-approvals-and-sandbox\b|--yolo\b"
    r"|--permission-mode[ =]+bypassPermissions\b|--approval-mode[ =]+yolo\b")
RUNS_COMMANDS = re.compile(r"\.(?:sh|bash|zsh|ps1|cmd|bat|mk|toml)$", re.I)
CODEX_UNSAFE = re.compile(  # [ \t]* not \s*: with (?m)^ a \s* would rescan every following blank line
    r"""(?m)^[ \t]*(?:approval_policy[ \t]*=[ \t]*["']never["']|sandbox_mode[ \t]*=[ \t]*["']danger-full-access["'])""")
# shell or every-tool grants: "Bash", "Bash(*)", "Bash(:*)", "*"
BROAD_TOOL = re.compile(r"^(?:Bash|Shell|run_terminal_cmd|terminal|\*|mcp__\*|Bash\(\s*\*?\s*(?::\s*\*)?\s*\))$")

STREAM_PY = re.compile(r"\bstream\s*=\s*True\b|\.stream\s*\(|\bastream\w*\s*\(")
STREAM_RESPONSE_PY = re.compile(r"\b(?:StreamingResponse|EventSourceResponse|stream_with_context)\s*\(")
DISCONNECT_PY = re.compile(r"is_disconnected|CancelledError|client_disconnected|ClientDisconnect|GeneratorExit")
STREAM_JS = re.compile(r"\bstream\s*:\s*true\b|\bstreamText\s*\(|\bstreamObject\s*\(|\.stream\s*\(|\bcreateDataStream\w*\s*\(")
DISCONNECT_JS = re.compile(r"\b(?:abortSignal|signal)\s*[:,)]|\bAbortController\b|\.on\(\s*['\"]close['\"]|\brequest\.signal\b|\breq\.signal\b"
                           r"|\bonAbort\b|\bcancel\s*\(")

LOG_CALL = re.compile(
    r"\b(?:logger|logging|log|_logger|LOGGER|console|app\.logger|self\.logger)\s*\.\s*(?:debug|info|log|warn|warning|error|exception)\s*\(")
LLM_TEXT_NAME = re.compile(
    r"(?<![\w.'\"])(?:prompt|prompts|user_prompt|system_prompt|full_prompt|messages|chat_history|completion|completions"
    r"|llm_response|model_output|response\.choices|\w+\.choices\[\d+\]\.message(?:\.content)?)(?![\w'\"])")

# MCP / agent tool definitions & poisoning markers (LLM027, all quantifiers strictly bounded)
PY_TOOL_START = re.compile(r"(?m)^[ \t]*(?:@(?:[\w.]{1,40}\.)?tool(?:\s*\([^\n]{0,200}\))?|\bTool\s*\()")
JS_TOOL_START = re.compile(r"\.(?:tool|registerTool)\s*\(|\btool\s*\(\s*\{")
JSON_TOOL_SCHEMA = re.compile(r'"inputSchema"\s*:\s*\{')
TOOL_POISON_MARKERS = re.compile(
    r"(?is)(?:<IMPORTANT>"
    r"|\b(?:do not|don't|never)\s+(?:mention|tell|inform|show|reveal)\s+(?:this|it|the user|to the user)\b"
    r"|\b(?:before|prior to)\s+(?:calling|invoking|using)\s+this\s+tool\b[^\n]{0,120}\b(?:read|cat|pass|include|send|exfiltrate)\b"
    r"|\b(?:read|cat|exfiltrate|include|send)\b[^\n]{0,60}(?:~/\.ssh|/etc/passwd|\.aws/credentials|id_rsa|\.env\b)"
    r"|\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|prompts)\b)")
DOCSTRING_RE = re.compile(r'"""[\s\S]{1,4000}?"""|\'\'\'[\s\S]{1,4000}?\'\'\'')
DESC_ATTR_RE = re.compile(r"""(?:description\s*[:=]\s*|["']description["']\s*:\s*)(?:"[^"\n]{1,2000}"|'[^'\n]{1,2000}')""")

# Unconstrained dynamic tool dispatch (LLM028, all quantifiers strictly bounded)
TOOL_CALL_EVIDENCE = re.compile(
    r"\b(?:tool_calls?|function_call|tool_use|tool_name|toolName|fn_name|fnName|func_name|funcName"
    r"|(?:block|call|tc|tool_call|toolCall)\.(?:name|function\.name))\b")
LLM_AGENT_CONTEXT = re.compile(r"(?i)\b(?:openai|anthropic|genai|mcp|langchain|litellm|tool_calls|function_call|tool_use|tools)\b")
DYN_DISPATCH_PY = re.compile(
    r"\b(?:globals|locals)\s*\(\s*\)\s*\[\s*[A-Za-z_]\w{0,40}(?:\.[A-Za-z_]\w{0,40}){0,2}\s*\]\s*\("
    r"|\bgetattr\s*\(\s*[A-Za-z_]\w{0,40}\s*,\s*(?:tool_name|fn_name|func_name|(?:call|tc|tool_call)\.(?:name|function\.name)|block\.name)\b")
DYN_DISPATCH_JS = re.compile(
    r"\b(?:globalThis|window|global)\s*\[\s*(?:toolName|fnName|funcName|tool_name|(?:call|tc|toolCall)\.(?:name|function\.name)|block\.name)\s*\]\s*\(")
ALLOWLIST_GUARD = re.compile(r"\b(?:ALLOWED_TOOLS|TOOL_ALLOWLIST|VALID_TOOLS|SAFE_TOOLS|ALLOWLIST|hasOwnProperty)\b|\bin\s+[A-Z][A-Z0-9_]{2,30}\b")


def run(project: Project, routes: List[Route], add: Add) -> None:
    for sf in project.files:
        if sf.text is None or sf.is_test:
            continue
        GUARD.run(sf.rel, "agent file checks", _file, sf, add)
    for r in routes:
        _stream_cancel(r, add)


def _file(sf: SourceFile, add: Add) -> None:
    if AGENT_SETTINGS.search(sf.rel):
        _agent_settings(sf, add)
    if AGENT_INSTRUCTIONS.search(sf.rel):
        _injection(sf, add)
    # files that run commands (not docs that only mention the flag)
    if sf.kind in ("yaml", "workflow", "docker", "compose") or RUNS_COMMANDS.search(sf.rel) \
            or sf.rel.rsplit("/", 1)[-1] in ("package.json", "Makefile", "justfile", "Procfile"):
        for m in finditer(SKIP_PERMISSION_FLAGS, sf.text or ""):
            add(sf, sf.line_at(m.start()), "LLM016", f"A coding agent is started with `{m.group(0)}`, so it runs every tool without asking.")
    if sf.kind in ("py", "js", "json") and not sf.is_example:
        _mcp_tool_poisoning(sf, add)
    v = sf.cache.get("views")
    if v is not None and sf.kind in ("py", "js"):
        _logged_llm_text(sf, v.code, v.bare, add)
        _dynamic_tool_dispatch(sf, v.code, add)


def _mcp_tool_poisoning(sf: SourceFile, add: Add) -> None:
    text = sf.text or ""
    if sf.kind == "py":
        starts = [m.start() for m in finditer(PY_TOOL_START, text)]
    elif sf.kind == "js":
        starts = [m.start() for m in finditer(JS_TOOL_START, text)]
    else:
        starts = [max(0, m.start() - 1200) for m in finditer(JSON_TOOL_SCHEMA, text)]
    if not starts:
        return
    seen_lines = set()
    for pos in starts:
        block = text[pos:pos + 2400]
        # inspect only docstrings / description strings inside the tool definition block
        for str_rx in ((DOCSTRING_RE, DESC_ATTR_RE) if sf.kind == "py" else (DESC_ATTR_RE,)):
            for sm in finditer(str_rx, block):
                pm = TOOL_POISON_MARKERS.search(sm.group(0))
                if pm is None:
                    continue
                line = sf.line_at(pos + sm.start() + pm.start())
                if line not in seen_lines:
                    seen_lines.add(line)
                    add(sf, line, "LLM027",
                        "MCP/agent tool description contains covert instructions or credential-read directives (tool poisoning).")


def _dynamic_tool_dispatch(sf: SourceFile, code: str, add: Add) -> None:
    if not (TOOL_CALL_EVIDENCE.search(code) and LLM_AGENT_CONTEXT.search(code)):
        return
    rx = DYN_DISPATCH_PY if sf.kind == "py" else DYN_DISPATCH_JS
    for m in finditer(rx, code):
        ctx_start = max(0, m.start() - 320)
        if ALLOWLIST_GUARD.search(code[ctx_start:m.end() + 80]):
            continue
        add(sf, sf.line_at(m.start()), "LLM028",
            "Dynamic tool dispatch calls a function directly from a model-supplied name without an allow-list mapping.")


def _injection(sf: SourceFile, add: Add) -> None:
    from . import feed

    for entry, pattern in feed.injection_patterns():
        m = next(iter(finditer(pattern, sf.text or "")), None)  # one finding per pattern and file
        if m is not None:
            add(sf, sf.line_at(m.start()), "LLM025",
                f"{entry['description']} ({entry['id']}): the agent reads this file as the developer's instructions.")


def _agent_settings(sf: SourceFile, add: Add) -> None:
    text = sf.text or ""
    if sf.rel.endswith(".toml"):
        for m in finditer(CODEX_UNSAFE, text):
            add(sf, sf.line_at(m.start()), "LLM016", "The Codex agent runs commands without approval or outside its sandbox.")
        return
    try:
        data = loads_json(text)
    except ValueError:
        return
    if not isinstance(data, dict):
        return

    def line_of(needle: str) -> int:
        return next((i for i, ln in enumerate(sf.lines, 1) if needle in ln), 1)

    raw_perms = data.get("permissions")
    perms: dict = raw_perms if isinstance(raw_perms, dict) else {}
    if perms.get("defaultMode") == "bypassPermissions":
        add(sf, line_of("bypassPermissions"), "LLM016", "The agent's permission mode is bypassPermissions: it never asks before acting.")
    for tool in _strings(perms.get("allow")):
        if BROAD_TOOL.match(tool.strip()):
            add(sf, line_of(f'"{tool}"'), "LLM016", f"`{tool}` lets the agent run any shell command without asking.")
    for key, value in _walk(data):
        low = key.lower()
        if low in ("chat.tools.autoapprove", "chat.tools.global.autoapprove", "github.copilot.chat.agent.autoapprove",
                   "autoaccept", "yolo", "alwaysallowexecute") and value is True:
            add(sf, line_of(f'"{key}"'), "LLM016", f"`{key}` is on: the agent runs tools without asking.")
        elif low in ("autoapprove", "alwaysallow") and isinstance(value, list) and any(str(v).strip() in ("*", "**") for v in value):
            add(sf, line_of(f'"{key}"'), "LLM016", "Every tool of this MCP server is approved in advance.")


def _strings(value) -> List[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _walk(value, depth: int = 0) -> Iterable[Tuple[str, object]]:
    if depth > 8:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            yield str(k), v
            yield from _walk(v, depth + 1)
    elif isinstance(value, list):
        for v in value[:500]:
            yield from _walk(v, depth + 1)


def _stream_cancel(r: Route, add: Add) -> None:
    body = r.body
    if not r.calls_llm:
        return
    if r.lang == "py":
        if STREAM_PY.search(body) and STREAM_RESPONSE_PY.search(body) and not DISCONNECT_PY.search(body):
            add(r.file, r.line, "LLM017", f"{r.path} streams a completion but never checks for a closed connection, so the model keeps generating.")
    elif STREAM_JS.search(body) and not DISCONNECT_JS.search(body):
        add(r.file, r.line, "LLM017", f"{r.path} streams a completion without passing the request's abort signal to the model call.")


def _logged_llm_text(sf: SourceFile, code: str, bare: str, add: Add) -> None:
    if not (H.LLM_CALL_JS.search(code) if sf.kind == "js" else re.search(r"openai|anthropic|genai|langchain|litellm|llama_index|ollama", code)):
        return
    seen = set()
    for m in finditer(LOG_CALL, bare):
        end = code.find("\n", m.end())
        args = bare[m.end():end if end > 0 else len(bare)][:300]
        n = LLM_TEXT_NAME.search(args)
        line = sf.line_at(m.start())
        if n and line not in seen and not re.search(r"\blen\s*\(\s*$|\.length\s*$", args[:n.start()]) \
                and not re.match(r"\s*\.\s*(?:length|count)\b|\s*\)\s*\.\s*length", args[n.end():]):
            seen.add(line)
            add(sf, line, "LLM018", f"`{n.group(0)}` is written to the logs: prompts and completions often hold personal data.")
