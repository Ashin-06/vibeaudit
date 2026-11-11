"""Run every check over a project and return a cleaned-up, prioritised result."""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Set

from . import external, plugins
from .deps import DepScanner
from . import heuristics as H
from .files import Project
from .guard import GUARD
from .jsscan import JsScanner
from .model import SEVERITY_RANK, SUPPRESS, TEST_FILE_RULES, Finding, at_least
from .projectscan import ProjectScanner
from .pyscan import PyScanner
from .qualityscan import QualityScanner
from .datascan import DataScanner
from .relscan import ReliabilityScanner
from .aiscan import AiScanner
from .uiscan import UiScanner
from .contracts import ContractScanner
from .report import Result
from .rules import RULES
from .secretscan import SecretScanner

STACK_MARKERS = {
    "flask": "Flask", "fastapi": "FastAPI", "django": "Django", "streamlit": "Streamlit", "gradio": "Gradio",
    "openai": "OpenAI SDK", "anthropic": "Anthropic SDK", "google-genai": "Google GenAI SDK",
    "google-generativeai": "Google GenAI SDK", "langchain": "LangChain", "llama-index": "LlamaIndex",
    "litellm": "LiteLLM", "crewai": "CrewAI", "next": "Next.js", "react": "React", "vue": "Vue",
    "svelte": "Svelte", "@sveltejs/kit": "SvelteKit", "express": "Express", "fastify": "Fastify", "hono": "Hono",
    "@supabase/supabase-js": "Supabase", "supabase": "Supabase", "firebase": "Firebase", "@prisma/client": "Prisma",
    "mongoose": "MongoDB", "drizzle-orm": "Drizzle", "stripe": "Stripe", "ai": "Vercel AI SDK",
    "@anthropic-ai/sdk": "Anthropic SDK", "@google/generative-ai": "Google GenAI SDK", "@google/genai": "Google GenAI SDK",
    "@langchain/core": "LangChain", "@modelcontextprotocol/sdk": "MCP",
}


@dataclass
class Options:
    offline: bool = False
    excludes: List[str] = field(default_factory=list)
    disabled: Set[str] = field(default_factory=set)
    min_severity: str = "info"
    external: str = "auto"  # auto | none | comma list
    baseline: Optional[str] = None
    max_file_bytes: int = 1_000_000
    llm: Optional[str] = None
    llm_model: Optional[str] = None
    llm_review: bool = False
    llm_max_requests: int = 10
    file_timeout: float = 30.0
    auth_helpers: List[str] = field(default_factory=list)
    sanitizers: List[str] = field(default_factory=list)
    public_paths: List[str] = field(default_factory=list)
    changes: Optional[dict] = None  # from gitdiff.changed(): report only findings on changed lines
    feedback: bool = True  # hide findings marked false positive in .vibeaudit/feedback.json
    cache: bool = True  # read and write the user cache (registry, OSV, LLM verdicts) during this scan
    include_preview: bool = False  # count findings of preview rules toward --fail-on and the score
    log: Callable[[str], None] = lambda s: None


def _stack(project: Project) -> List[str]:
    found = []
    names = set(project.all_js_deps())
    for f in project.files:
        if re.search(r"(?:^|/)(?:requirements[\w.-]*\.txt|pyproject\.toml)$", f.rel) and f.text:
            names |= {m.lower() for m in re.findall(r"(?m)^\s*\"?([A-Za-z0-9][A-Za-z0-9._-]*)", f.text)}
    for key, label in STACK_MARKERS.items():
        if key in names and label not in found:
            found.append(label)
    return found


def suppressed(project: Project, f: Finding) -> bool:
    sf = project.get(f.file)
    if not sf or not f.line:
        return False
    # parsed once per line: one long line with thousands of findings must not be searched thousands of times
    memo: dict = sf.cache.setdefault("suppress", {})  # type: ignore[assignment]
    for ln in (f.line, f.line - 1):
        if ln not in memo:
            m = SUPPRESS.search(sf.line(ln))
            memo[ln] = None if m is None else ("*" if not m.group(1) else {x.strip().upper() for x in m.group(1).split(",")})
        rules = memo[ln]
        if rules == "*" or (rules and f.rule_id.upper() in rules):
            return True
    return False


_SCAN_LOCK = threading.RLock()


def scan(root: str, opts: Optional[Options] = None) -> Result:
    """Scan `root`. Without `opts`, the project's own .vibeaudit.toml / [tool.vibeaudit] settings apply.

    Safe to call from several threads: scans run one at a time, because the time budget, the custom auth
    helpers and the cache switch are process-wide (scans are CPU-bound, so threads would not speed them up)."""
    if opts is None:
        from .config import project_options

        opts = project_options(root)
    with _SCAN_LOCK, warnings.catch_warnings():
        # ast.parse() warns about the scanned code (invalid escape sequences); that is not vibeaudit's output
        warnings.simplefilter("ignore", SyntaxWarning)
        warnings.filterwarnings("ignore", "invalid escape sequence", DeprecationWarning)  # the same before 3.12
        if opts.cache:
            return _scan(root, opts)
        from . import store

        previous, store.ENABLED = store.ENABLED, False
        try:  # only this scan skips the cache; a long-lived caller keeps its own setting
            return _scan(root, opts)
        finally:
            store.ENABLED = previous


def _scan(root: str, opts: Options) -> Result:
    start = time.time()
    GUARD.reset(opts.file_timeout)
    H.CUSTOM.reset(opts.auth_helpers, opts.sanitizers, opts.public_paths)
    project = Project(Path(root), opts.excludes, opts.max_file_bytes)
    raw: List[Finding] = []
    emit = raw.append
    notes: List[str] = []

    js_routes = JsScanner(project, emit).run()
    py_routes = PyScanner(project, emit).run()
    SecretScanner(project, emit).run()
    ProjectScanner(project, emit, js_routes + py_routes).run()
    QualityScanner(project, emit).run()
    DataScanner(project, emit, js_routes + py_routes).run()
    ReliabilityScanner(project, emit, js_routes + py_routes).run()
    AiScanner(project, emit, js_routes + py_routes).run()
    UiScanner(project, emit).run()
    ContractScanner(project, emit, js_routes + py_routes).run()
    plugins.run(project, js_routes + py_routes, emit)
    deps = DepScanner(project, emit, opts.offline)
    GUARD.run("<project>", "dependency checks", deps.run)
    notes += deps.notes

    ran = []
    if opts.external != "none":
        wanted = external.TOOLS if opts.external == "auto" else [t.strip() for t in opts.external.split(",") if t.strip()]
        for tool in wanted:
            if tool not in external.TOOLS:
                notes.append(f"Unknown external tool {tool!r} ignored.")
                continue
            if opts.offline and tool in external.NEEDS_NETWORK:
                continue
            if not external.available(tool):
                if opts.external != "auto":
                    notes.append(f"{tool} is not installed; skipped.")
                continue
            opts.log(f"running {tool} ...")
            res = GUARD.run("<project>", tool, external.run_tool, tool, project.root)
            if res is None:
                notes.append(f"{tool} failed to run or produced no readable output.")
                continue
            ran.append(tool)
            raw.extend(res)

    findings = finalize(project, raw, opts)
    if opts.changes is not None:
        from .gitdiff import keep

        findings = [f for f in findings if keep(opts.changes, f.file, f.line)]
    hidden = 0
    if opts.feedback:
        from .feedback import false_positives

        reviewed = false_positives(project.root)
        if reviewed:
            before = len(findings)
            findings = [f for f in findings if f.fingerprint not in reviewed]
            hidden = before - len(findings)
            if hidden:
                notes.append(f"{hidden} findings marked as false positives in .vibeaudit/feedback.json are hidden.")
    if GUARD.skipped:
        notes.append(f"{len(GUARD.skipped)} file checks were skipped (time budget or nesting); see meta.skipped.")
    if GUARD.internal_errors:
        notes.append(f"{len(GUARD.internal_errors)} internal errors; results may be incomplete. Please report them.")

    if opts.llm:
        from . import llm
        try:
            provider = llm.Provider(opts.llm, opts.llm_model)
            llm.triage(project, findings, provider, opts.llm_max_requests, notes.append)
            if opts.llm_review:
                risky = _risky_files(project, findings, js_routes + py_routes)
                extra = llm.review(project, findings, risky, provider, opts.llm_max_requests, notes.append)
                findings = finalize(project, findings + extra, opts, already=True)
            notes.append(f"LLM ({provider.name}/{provider.model}) used {provider.requests} requests.")
        except llm.LLMError as e:
            notes.append(f"LLM checks skipped: {e}")

    meta = {
        "files_scanned": len(project.files), "duration_seconds": round(time.time() - start, 2),
        "stack": _stack(project), "external_tools": ran, "offline": opts.offline, "notes": notes,
        "routes_found": len(js_routes) + len(py_routes), "git": project.is_git,
        "skipped": list(GUARD.skipped), "internal_errors": list(GUARD.internal_errors),
        "feedback_hidden": hidden, "include_preview": opts.include_preview,
    }
    if opts.changes is not None:
        meta["changed_files"] = len(opts.changes)
    return Result(str(project.root), findings, meta, js_routes + py_routes)


def _risky_files(project: Project, findings: List[Finding], routes) -> List[str]:
    score = {}
    for r in routes:
        score[r.file] = score.get(r.file, 0) + 2 + (3 if r.calls_llm else 0)
    for f in findings:
        score[f.file] = score.get(f.file, 0) + 1
    return [f for f, _ in sorted(score.items(), key=lambda kv: -kv[1]) if project.get(f)][:5]


def finalize(project: Project, raw: List[Finding], opts: Options, already: bool = False) -> List[Finding]:
    out: List[Finding] = []
    occurrences: dict = {}
    seen = set()
    builtin_locs = set()
    baseline: Set[str] = set()
    if opts.baseline:
        try:
            data = json.loads(Path(opts.baseline).read_text(encoding="utf-8"))
            baseline = {f["fingerprint"] for f in data.get("findings", []) if "fingerprint" in f}
        except (OSError, ValueError, AttributeError, TypeError):
            opts.log(f"could not read baseline {opts.baseline}")
    # a secret in an MCP config is reported once, by the more specific LLM014
    mcp_secrets = {(f.file, f.line) for f in raw if f.rule_id == "LLM014"}
    # built-in findings first so that duplicates from external tools are the ones dropped
    for f in sorted(raw, key=lambda x: x.source != "vibeaudit"):
        if f.rule_id.startswith("SEC") and (f.file, f.line) in mcp_secrets:
            continue
        meta = RULES.get(f.rule_id)
        if meta and not already:
            f.title = f.title or meta.title
            f.category = f.category or meta.category
            f.severity = f.severity or meta.severity
            f.why = f.why or meta.why
            f.fix = f.fix or meta.fix
            f.cwe = f.cwe or meta.cwe
            f.owasp = f.owasp or meta.owasp
        if meta is not None:
            f.preview = meta.preview
        f.severity = f.severity or "medium"
        f.category = f.category or "backend"
        if f.rule_id in opts.disabled or (meta and meta.category in opts.disabled) or f.category in opts.disabled:
            continue
        sf = project.get(f.file)
        if sf is not None and (sf.is_test or sf.is_example) and f.rule_id not in TEST_FILE_RULES \
                and f.source == "vibeaudit":
            continue
        if not at_least(f.severity, opts.min_severity) or suppressed(project, f):
            continue
        key = (f.rule_id, f.file, f.line, f.message)
        if key in seen:
            continue
        loc = (f.file, f.line)
        if f.source not in ("vibeaudit", "llm-review", "plugin") and loc in builtin_locs:
            continue
        seen.add(key)
        if f.source == "vibeaudit":
            builtin_locs.add(loc)
        if not f.fingerprint:
            f.compute_fingerprint()
            # the same rule on two identical lines of one file (two `return True` stubs) must not share a
            # fingerprint, or baselining one would hide the other
            n = occurrences.get(f.fingerprint, 0)
            occurrences[f.fingerprint] = n + 1
            if n:
                f.fingerprint = hashlib.sha256(f"{f.fingerprint}#{n}".encode()).hexdigest()[:32]
        if f.fingerprint in baseline:
            continue
        out.append(f)
    out.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.category, f.file, f.line, f.rule_id))
    return out
