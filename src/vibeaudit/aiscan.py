"""More AI checks: vector search without a tenant filter, retired model ids, and agents that combine untrusted
input with dangerous tools (the "lethal trifecta")."""
from __future__ import annotations

import re
from typing import Callable, List

from .files import Project, SourceFile
from .guard import GUARD, finditer
from .model import Finding, Route

Emit = Callable[[Finding], None]

VECTOR_QUERY = re.compile(
    r"\.\s*similarity_search(?:_with_score|_by_vector)?\s*\(|\.\s*as_retriever\s*\(|\.\s*max_marginal_relevance_search\s*\("
    r"|\bcollection\s*\.\s*query\s*\(|\bindex\s*\.\s*query\s*\(|\.\s*search\s*\(\s*collection_name\b"
    r"|\.\s*rpc\s*\(\s*['\"]match_\w*['\"]|\bORDER\s+BY\s+\w*embedding\w*\s*(?:<->|<=>|<#>)", re.I)
TENANT_FILTER = re.compile(r"(?i)\bfilter\b|\bwhere\b|\bnamespace\b|query_filter|user_?id|tenant|org_?id|owner|account_?id")  # search_kwargs alone is not a filter
SERVICE_ROLE = re.compile(r"(?i)service_?role|supabaseAdmin|admin_?client")
_RETIRED: List["re.Pattern[str]"] = []


def retired_models() -> "re.Pattern[str]":
    """A quoted model id from data/retired_models.txt (refreshed by `vibeaudit update`); `*` is any id suffix."""
    if not _RETIRED:
        from .updater import data_bytes, model_ids

        alts = sorted((re.escape(i[:-1]) + r"[\w.@-]*" if i.endswith("*") else re.escape(i)
                       for i in model_ids(data_bytes("retired_models.txt"))), key=len, reverse=True)
        _RETIRED.append(re.compile(r"""['"`](""" + "|".join(alts) + r""")['"`]"""))
    return _RETIRED[0]
AGENT = re.compile(r"\b(?:create_react_agent|initialize_agent|AgentExecutor|create_openai_tools_agent|create_tool_calling_agent"
                   r"|createReactAgent|createToolCallingAgent|AgentExecutor\.fromAgentAndTools|Agent)\s*\(|\bnew\s+Agent\s*\(")
TOOL_NAME = re.compile(r"""@tool(?:\(\s*['"]([\w-]+)['"])?\s*\n\s*(?:async\s+)?def\s+(\w+)|\bTool\s*\(\s*name\s*=\s*['"]([\w-]+)['"]"""
                       r"""|\b(\w+)\s*:\s*tool\s*\(|name\s*:\s*['"]([\w-]+)['"]\s*,\s*description""")
UNTRUSTED_TOOL = re.compile(r"(?i)search|browse|browser|fetch|scrape|crawl|web|url|read_page|read_?email|inbox|rss|youtube|wikipedia|tavily|serp|duckduckgo|http_get|requests_get|read_file|download")
DANGEROUS_TOOL = re.compile(r"(?i)shell|bash|terminal|exec|python|run_code|run_command|send_?email|email_?send|write_?file|delete|remove|sql|query_?db|transfer|pay|post_|tweet|slack_?send|create_?issue|git_?push|deploy")


class AiScanner:
    def __init__(self, project: Project, emit: Emit, routes: List[Route]):
        self.p = project
        self.emit = emit
        self.routes = routes
        self.retired_seen: set = set()

    def add(self, sf: SourceFile, rule: str, line: int, msg: str, sev: str = "") -> None:
        self.emit(Finding(rule, sf.rel, line, msg, sev, sf.line(line).strip()[:200]))

    def run(self) -> None:
        GUARD.run("<project>", "vector search filters", self._vector)
        for sf in self.p.files:
            if sf.text is None or sf.is_test or sf.kind not in ("py", "js"):
                continue
            GUARD.run(sf.rel, "AI checks", self._file, sf)

    def _vector(self) -> None:
        for r in self.routes:
            if not r.has_auth:
                continue  # a public docs bot shares one index on purpose
            for m in finditer(VECTOR_QUERY, r.body):
                if ".rpc" in m.group(0) and not SERVICE_ROLE.search(r.body):
                    continue  # a Supabase client carrying the user's JWT is filtered by row-level security
                # the filter is often built on the lines before the call (`scoped = {...}; search(q, **scoped)`)
                window = r.body[max(0, m.start() - 300):m.start() + 400]
                if not TENANT_FILTER.search(window):
                    sf = self.p.get(r.file)
                    if sf is not None:
                        self.add(sf, "LLM010", self._call_line(sf, r, m),
                                 f"{r.path} searches the vector store without a user or tenant filter.")
                    break

    @staticmethod
    def _call_line(sf: SourceFile, r: Route, m: "re.Match[str]") -> int:
        """The line of the search call itself (stable when the route above it grows), else the route line."""
        text = sf.text or ""
        nth = r.body.count(m.group(0), 0, m.start())  # earlier calls of the same kind in this route
        pos = len("\n".join(sf.lines[:max(0, r.line - 4)]))  # from just above the route (decorators)
        for _ in range(nth + 1):
            pos = text.find(m.group(0), pos)
            if pos < 0:
                return r.line
            pos += 1
        return sf.line_at(pos - 1)

    def _file(self, sf: SourceFile) -> None:
        v = sf.cache.get("views")
        code = v.code if v is not None else (sf.text or "")  # type: ignore[attr-defined]
        for m in finditer(retired_models(), code):
            if m.group(1) not in self.retired_seen:  # model lists repeat ids across files; once per project is enough
                self.retired_seen.add(m.group(1))
                self.add(sf, "LLM012", sf.line_at(m.start()), f"Model `{m.group(1)}` has been retired or deprecated by its provider.")
        agent = AGENT.search(code)
        if agent is None:
            return
        names = {next(g for g in m.groups() if g) for m in TOOL_NAME.finditer(code) if any(m.groups())}
        untrusted = sorted(n for n in names if UNTRUSTED_TOOL.search(n))
        dangerous = sorted(n for n in names if DANGEROUS_TOOL.search(n) and n not in untrusted)
        if untrusted and dangerous:
            self.add(sf, "LLM015", sf.line_at(agent.start()),
                     f"The agent reads untrusted content ({', '.join(untrusted[:3])}) and can act ({', '.join(dangerous[:3])}); "
                     "injected instructions in that content can trigger those actions.")
