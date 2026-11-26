"""AI Bill of Materials (AI-BOM) collector and CycloneDX 1.6 JSON renderer."""
from __future__ import annotations

import datetime as dt
import json
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List

from . import __version__, feed
from .files import Project
from .guard import finditer
from .store import loads_json

MODEL_ASSIGN = re.compile(
    r"""(?:\bmodel(?:_id|_name|Id|Name)?\b|["']model(?:_id|_name|Id|Name)?["'])\s*[:=]\s*["']([a-zA-Z0-9][a-zA-Z0-9.:/_-]{2,78})["']"""
)
MCP_FILES = (".mcp.json", "mcp.json", "claude_desktop_config.json", "mcp_config.json")
PROMPT_NAMES = ("CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules", ".clinerules", "copilot-instructions.md")
AI_STACK_NAMES = {"OpenAI SDK", "Anthropic SDK", "Google GenAI SDK", "LangChain", "LlamaIndex", "LiteLLM", "CrewAI", "Vercel AI SDK", "MCP"}


def collect(project: Project, stack: List[str]) -> Dict[str, Any]:
    """Collect AI providers, models (with retirement status), MCP servers, and agent instruction/prompt files."""
    retired = set(feed.sunsets().keys())
    try:
        from importlib import resources

        raw_ret = resources.files("vibeaudit").joinpath("data", "retired_models.txt").read_text(encoding="utf-8")
        for line in raw_ret.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                retired.add(line)
    except (OSError, ValueError):
        pass

    def is_retired(mid: str) -> bool:
        for pat in retired:
            if pat.endswith("*") and mid.startswith(pat[:-1]):
                return True
            if mid == pat:
                return True
        return False

    models: Dict[str, Dict[str, Any]] = {}
    mcp_servers: Dict[str, Dict[str, Any]] = {}
    prompt_files: List[str] = []

    for sf in project.files:
        if sf.text is None or sf.is_test:
            continue
        base = sf.rel.rsplit("/", 1)[-1]
        if base in PROMPT_NAMES or sf.rel.endswith(".github/copilot-instructions.md"):
            prompt_files.append(sf.rel)
        if base in MCP_FILES or sf.rel.endswith((".cursor/mcp.json", ".vscode/mcp.json")):
            try:
                doc = loads_json(sf.text)
            except ValueError:
                doc = None
            if isinstance(doc, dict):
                servers = doc.get("mcpServers") or doc.get("servers") or {}
                if isinstance(servers, dict):
                    for sname, cfg in servers.items():
                        cmd = cfg.get("command", "") if isinstance(cfg, dict) else ""
                        url = cfg.get("url", "") if isinstance(cfg, dict) else ""
                        mcp_servers.setdefault(str(sname), {"name": str(sname), "file": sf.rel, "transport": "stdio" if cmd else "http", "target": str(cmd or url)[:120]})
        if sf.kind in ("py", "js", "yaml", "json", "toml") and "model" in sf.text:
            for m in finditer(MODEL_ASSIGN, sf.text):
                mid = m.group(1)
                if "/" in mid and mid.startswith(("http", "./", "../", "/")):
                    continue
                if mid.lower() in ("default", "auto", "none", "true", "false", "model", "gpt", "custom"):
                    continue
                entry = models.setdefault(mid, {"id": mid, "retired": is_retired(mid), "locations": []})
                loc = f"{sf.rel}:{sf.line_at(m.start())}"
                if loc not in entry["locations"] and len(entry["locations"]) < 10:
                    entry["locations"].append(loc)

    return {
        "providers": [s for s in stack if s in AI_STACK_NAMES],
        "models": sorted(models.values(), key=lambda x: x["id"]),
        "mcp_servers": sorted(mcp_servers.values(), key=lambda x: x["name"]),
        "prompt_files": sorted(set(prompt_files)),
    }


def render(res) -> str:
    """Render a CycloneDX 1.6 JSON AI Bill of Materials for the audited project."""
    inv = res.meta.get("ai_inventory")
    if inv is None:
        inv = collect(Project(Path(res.root)), res.meta.get("stack") or [])
    components: List[Dict[str, Any]] = []
    for p in inv.get("providers", []):
        components.append({"type": "library", "name": p, "properties": [{"name": "vibeaudit:ai:kind", "value": "sdk"}]})
    for m in inv.get("models", []):
        props = [
            {"name": "vibeaudit:ai:retired", "value": "true" if m.get("retired") else "false"},
            {"name": "vibeaudit:ai:locations", "value": ", ".join(m.get("locations", []))},
        ]
        components.append({"type": "machine-learning-model", "name": m["id"], "properties": props})
    for s in inv.get("mcp_servers", []):
        components.append({
            "type": "service",
            "name": s["name"],
            "properties": [
                {"name": "vibeaudit:mcp:file", "value": s.get("file", "")},
                {"name": "vibeaudit:mcp:transport", "value": s.get("transport", "")},
            ],
        })
    for pf in inv.get("prompt_files", []):
        components.append({"type": "data", "name": pf, "properties": [{"name": "vibeaudit:ai:kind", "value": "agent-instructions"}]})

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "tools": {"components": [{"type": "application", "name": "vibeaudit", "version": __version__}]},
            "component": {"type": "application", "name": str(res.root)},
        },
        "components": components,
    }
    return json.dumps(bom, indent=2) + "\n"
