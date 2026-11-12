"""Data and operations checks added in 0.8.8: DATA014-DATA016 and CFG018 (all preview).

DATA014: personal data stored in a vector store's metadata.
DATA015: cache-aside reads that recompute on a miss with no lock (cache stampede).
DATA016: background or scheduled jobs with side effects and nothing that makes a retry safe.
CFG018: a pull_request_target workflow that checks out the pull request's code while secrets are available.
"""
from __future__ import annotations

import ast
import re
from typing import Callable, List, Optional

from .files import Project, SourceFile
from .guard import GUARD, finditer
from .lexer import match_close

Add = Callable[..., None]  # ProjectScanner.add(sf_or_rel, line, rule, message, severity="")

VECTOR_HINT = re.compile(r"(?i)pinecone|chroma|qdrant|weaviate|milvus|pgvector|lancedb|vectorstore|vector_store|VectorStore|upstash/vector|turbopuffer")
METADATA = re.compile(r"""(?i)\bmetadatas?['"]?\s*[:=]\s*[\[{(]""")
PII_KEY = re.compile(
    r"""(?i)['"]?\b(e_?mail|email_?address|phone(?:_?number)?|ssn|social_?security\w*|(?:home_?|street_?)?address|full_?name"""
    r"""|first_?name|last_?name|date_?of_?birth|dob|birth_?date|ip_?address|credit_?card\w*|passport\w*|national_?id)\b['"]?\s*[:=]""")

CACHE_GET = re.compile(r"\b(\w+)\s*=\s*(?:await\s+)?(?:self\.)?\w*(?:cache|redis|client|kv|memcache)\w*\s*\.\s*get\s*\(")
CACHE_SET = re.compile(r"(?i)\b\w*(?:cache|redis|client|kv|memcache)\w*\s*\.\s*(?:set|setex)\s*\(")
EXPENSIVE = re.compile(
    r"(?i)\b(?:fetch|requests\.\w+|httpx\.\w+|axios\.\w+|\.query\s*\(|\.execute\s*\(|\.find\w*\s*\(|\.aggregate\s*\(|\.objects\.|select\s*\("
    r"|chat\.completions|messages\.create|generateText|\.invoke\s*\()")
STAMPEDE_GUARD = re.compile(
    r"(?i)\block\b|\.lock\s*\(|setnx|\bnx\s*[:=]\s*(?:true|True)|['\"]NX['\"]|singleflight|single_flight|dogpile|stale.?while.?revalidate"
    r"|\bswr\b|mutex|semaphore|@cached|cachetools|unstable_cache|\bcache\s*\(|lru_cache|early_?expir|probabilistic")

PY_TASK = re.compile(r"(?m)^[ \t]*@(?:\w+\.)*(?:task|shared_task|periodic_task|scheduled_job|job|actor|cron|on_message)\b")
JS_JOB = re.compile(r"\bnew\s+Worker\s*\(|\bcron\s*\.\s*schedule\s*\(|@Cron\s*\(|@Process\s*\(|\.process\s*\(\s*(?:['\"`]\w+['\"`]\s*,\s*)?async|\bschedule\.scheduleJob\s*\(|inngest\.createFunction\s*\(")
SIDE_EFFECT = re.compile(
    r"(?i)\bstripe\.\w+\.create\s*\(|\bcharges?\.create\s*\(|paymentIntents\.create|\bsend_?(?:mail|email)\s*\(|\bsendMail\s*\(|\bemails?\.send\s*\("
    r"|\btransfers?\.create\s*\(|\bpayouts?\.create\s*\(|\bINSERT\s+INTO\b|\.insert(?:One|Many)?\s*\(|\.create\s*\(|\bbulk_create\s*\(")
IDEMPOTENT = re.compile(
    r"(?i)idempoten|get_or_create|update_or_create|upsert|on\s+conflict|on\s+duplicate|\bexists?\s*\(|already|processed|dedup|deduplicat"
    r"|\bunique\b|\bjob_?id\b|jobId|\block\b|\.lock\s*\(|setnx|\bnx\s*[:=]")

PR_TARGET = re.compile(r"(?m)^[ \t]*(?:on:\s*\[?[^\n]*\bpull_request_target\b|pull_request_target\s*:|-\s*pull_request_target\b|on:\s*pull_request_target\b)")
HEAD_CHECKOUT = re.compile(r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs/pull/\$\{\{\s*github\.event\.(?:number|pull_request\.number)")
SECRET_USE = re.compile(r"\$\{\{\s*secrets\.(?!GITHUB_TOKEN\b)\w+|secrets\s*:\s*inherit")


def run(project: Project, add: Add) -> None:
    for sf in project.files:
        if sf.text is None or sf.is_test or sf.is_example:
            continue
        if sf.kind == "workflow":
            GUARD.run(sf.rel, "pull_request_target", _pwn_request, sf, add)
            continue
        if sf.kind not in ("py", "js"):
            continue
        v = sf.cache.get("views")
        if v is None:
            continue
        GUARD.run(sf.rel, "vector metadata", _vector_pii, sf, v, add)
        GUARD.run(sf.rel, "cache stampede", _stampede, sf, v, add)
        GUARD.run(sf.rel, "job idempotency", _jobs, sf, v, add)


def _vector_pii(sf: SourceFile, v, add: Add) -> None:
    code = v.code  # type: ignore[attr-defined]
    if not VECTOR_HINT.search(code):
        return
    for m in finditer(METADATA, code):
        window = code[m.end():m.end() + 600]
        k = PII_KEY.search(window)
        if k:
            add(sf, sf.line_at(m.end() + k.start()), "DATA014",
                f"`{k.group(1)}` is stored in vector metadata, which is returned with search results and is hard to delete per user.")


def _stampede(sf: SourceFile, v, add: Add) -> None:
    code, bare = v.code, v.bare  # type: ignore[attr-defined]
    if STAMPEDE_GUARD.search(code):
        return
    from .storagescan import REDIS_CLIENT
    clients = {m.group(1) for m in REDIS_CLIENT.finditer(code)}
    getter, setter = CACHE_GET, CACHE_SET
    if clients:
        names = "|".join(re.escape(c) for c in sorted(clients))
        getter = re.compile(r"\b(\w+)\s*=\s*(?:await\s+)?(?:self\.)?(?:%s|\w*(?:cache|redis|kv|memcache)\w*)\s*\.\s*get\s*\(" % names)
        setter = re.compile(r"\b(?:%s|\w*(?:cache|redis|kv|memcache)\w*)\s*\.\s*(?:set|setex)\s*\(" % names)
    for m in finditer(getter, bare):
        window = code[m.end():m.end() + 1500]
        s = setter.search(window)
        if s and EXPENSIVE.search(window[:s.start()]) and re.search(r"\b(?:if\s+(?:not\s+)?|!|===?\s*null|is\s+None)\s*" + re.escape(m.group(1)) + r"\b|\b" + re.escape(m.group(1)) + r"\s*(?:is\s+None|===?\s*(?:null|undefined))", window[:s.start()]):
            add(sf, sf.line_at(m.start()), "DATA015",
                "On a cache miss every request recomputes the value at once (no lock or single-flight), so an expired hot key "
                "sends a burst of identical queries to the backend.")


def _jobs(sf: SourceFile, v, add: Add) -> None:
    code, bare = v.code, v.bare  # type: ignore[attr-defined]
    if sf.kind == "py":
        for body, line in _py_tasks(sf):
            _job_body(sf, body, line, add)
    else:
        for m in finditer(JS_JOB, bare):
            brace = bare.find("{", m.end())
            if brace < 0 or brace - m.end() > 400:
                continue
            close = match_close(bare, brace)
            if close < 0:
                continue
            _job_body(sf, code[brace:close], sf.line_at(m.start()), add)


def _py_tasks(sf: SourceFile):
    if not PY_TASK.search(sf.text or ""):
        return
    tree: Optional[ast.Module] = sf.cache.get("ast")  # type: ignore[assignment]
    if tree is None:
        try:
            tree = ast.parse(sf.text or "")
        except (SyntaxError, ValueError):
            return
    lines = (sf.text or "").splitlines()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.decorator_list:
            deco = lines[node.decorator_list[0].lineno - 1] if node.decorator_list[0].lineno <= len(lines) else ""
            if PY_TASK.search(deco + "\n"):
                yield "\n".join(lines[node.lineno - 1:node.end_lineno or node.lineno]), node.lineno


def _job_body(sf: SourceFile, body: str, line: int, add: Add) -> None:
    m = SIDE_EFFECT.search(body)
    if m and not IDEMPOTENT.search(body):
        add(sf, line, "DATA016", f"This job has a side effect (`{m.group(0).strip()[:40]}`) and nothing makes it safe to run twice; "
                                 "queues and schedulers retry, so a retry repeats it.")


def _pwn_request(sf: SourceFile, add: Add) -> None:
    text = sf.text or ""
    if not PR_TARGET.search(text):
        return
    m = HEAD_CHECKOUT.search(text)
    if m and SECRET_USE.search(text):
        add(sf, sf.line_at(m.start()), "CFG018",
            "pull_request_target runs with this repository's secrets, and this job checks out the pull request's code: "
            "a fork can run its own code with your secrets.")
