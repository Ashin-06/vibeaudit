"""Attack-path correlation and observable AI-code risk signals across static findings and routes."""
from __future__ import annotations

from typing import Dict, List

from .model import Finding, Route

AUTH_ENTRY_RULES = {"AUTH001", "AUTH002"}
EXPLOIT_SINK_RULES = {"BE001", "BE002", "BE003", "BE009", "BE010", "BE021", "BE022", "AUTH003"}
PROMPT_ENTRY_RULES = {"LLM001", "LLM010", "LLM021", "LLM022", "LLM025", "LLM027"}
AGENT_ACTION_RULES = {"LLM002", "LLM005", "LLM006", "LLM028"}
CLIENT_SECRET_RULES = {"SEC008", "SEC009", "FE002"}
ACCESS_GAP_RULES = {"AUTH001", "AUTH005", "AUTH006", "AUTH007"}


def _loc(f: Finding) -> str:
    return f"{f.file}:{f.line}" if f.line else f.file


def attack_paths(findings: List[Finding], routes: List[Route]) -> List[dict]:
    """Correlate individual findings into high-impact multi-step attack paths without altering raw findings."""
    paths: List[dict] = []
    by_file: Dict[str, List[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    for rel in sorted(by_file):
        fs = by_file[rel]
        entries = [f for f in fs if f.rule_id in AUTH_ENTRY_RULES]
        sinks = [f for f in fs if f.rule_id in EXPLOIT_SINK_RULES]
        if entries and sinks:
            paths.append({
                "id": "unauthenticated-exploit-chain",
                "severity": "critical",
                "title": "Unauthenticated endpoint paired with injection or access-control sink",
                "steps": [_loc(entries[0]) + f" ({entries[0].rule_id})", _loc(sinks[0]) + f" ({sinks[0].rule_id})"],
                "files": [rel],
                "rules": sorted({entries[0].rule_id, sinks[0].rule_id}),
            })

    prompt_entries = [f for f in findings if f.rule_id in PROMPT_ENTRY_RULES]
    agent_actions = [f for f in findings if f.rule_id in AGENT_ACTION_RULES]
    if prompt_entries and agent_actions:
        paths.append({
            "id": "agentic-prompt-to-action",
            "severity": "critical",
            "title": "Untrusted prompt/RAG/MCP input alongside dangerous model/agent execution",
            "steps": [_loc(prompt_entries[0]) + f" ({prompt_entries[0].rule_id})",
                      _loc(agent_actions[0]) + f" ({agent_actions[0].rule_id})"],
            "files": sorted({prompt_entries[0].file, agent_actions[0].file}),
            "rules": sorted({prompt_entries[0].rule_id, agent_actions[0].rule_id}),
        })

    client_leaks = [f for f in findings if f.rule_id in CLIENT_SECRET_RULES]
    access_gaps = [f for f in findings if f.rule_id in ACCESS_GAP_RULES]
    if client_leaks and access_gaps:
        paths.append({
            "id": "client-to-backend-privilege",
            "severity": "critical",
            "title": "Client-exposed secret or service key alongside unauthenticated/open backend access",
            "steps": [_loc(client_leaks[0]) + f" ({client_leaks[0].rule_id})",
                      _loc(access_gaps[0]) + f" ({access_gaps[0].rule_id})"],
            "files": sorted({client_leaks[0].file, access_gaps[0].file}),
            "rules": sorted({client_leaks[0].rule_id, access_gaps[0].rule_id}),
        })

    agent_tools = [f for f in findings if f.rule_id in {"LLM005", "LLM006", "LLM013", "LLM028"}]
    agent_limits = [f for f in findings if f.rule_id in {"LLM003", "LLM004", "LLM009", "LLM020"}]
    if agent_tools and agent_limits:
        paths.append({
            "id": "agentic-unbounded-privilege",
            "severity": "high",
            "title": "Privileged agent tools or MCP access paired with missing token, rate, or loop limits",
            "steps": [_loc(agent_tools[0]) + f" ({agent_tools[0].rule_id})",
                      _loc(agent_limits[0]) + f" ({agent_limits[0].rule_id})"],
            "files": sorted({agent_tools[0].file, agent_limits[0].file}),
            "rules": sorted({agent_tools[0].rule_id, agent_limits[0].rule_id}),
        })

    for rel in sorted(by_file):
        fs = by_file[rel]
        price = [f for f in fs if f.rule_id == "BE019"]
        guards = [f for f in fs if f.rule_id in {"AUTH001", "AUTH002", "AUTH003", "DATA010", "BE018"}]
        if price and guards:
            paths.append({
                "id": "payment-compound-risk",
                "severity": "critical",
                "title": "Client-controlled pricing paired with missing auth, transaction, or server validation",
                "steps": [_loc(price[0]) + f" ({price[0].rule_id})", _loc(guards[0]) + f" ({guards[0].rule_id})"],
                "files": [rel],
                "rules": sorted({price[0].rule_id, guards[0].rule_id}),
            })

    return paths


def ai_risk_profile(findings: List[Finding]) -> dict:
    """Summarize observable AI-assisted failure patterns (no authorship attribution claims)."""
    buckets = {
        "placeholder_auth": {"AUTH008"},
        "hallucinated_deps": {"DEP001"},
        "unfinished_stubs": {"QA004", "QA005", "QA011"},
        "broken_ui_or_contracts": {"UI004", "API001", "API002"},
        "client_key_leaks": {"SEC008", "SEC009", "FE002"},
        "unbounded_llm": {"LLM003", "LLM004", "LLM009", "LLM020"},
    }
    signals = {
        key: sum(1 for f in findings if f.rule_id in rules)
        for key, rules in buckets.items()
    }
    signals = {k: v for k, v in signals.items() if v}
    return {"signals": signals, "total_signals": sum(signals.values())}
