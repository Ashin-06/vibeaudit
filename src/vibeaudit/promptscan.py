"""Prompt, RAG and LLM-operations checks added in 0.8.6: LLM021-LLM024 (all preview).

LLM021: user text placed in a prompt without delimiters.
LLM022: documents from the web or files stored in a vector store with no cleaning step (chunk poisoning).
LLM023: LLM endpoints for signed-in users with no per-user usage or cost tracking anywhere.
LLM024: a project with tests, none of which touch its LLM code (no prompt tests or evals).
"""
from __future__ import annotations

import re
from typing import Callable, List, Optional

from . import heuristics as H
from .files import Project, SourceFile
from .guard import GUARD, finditer
from .model import Route

Add = Callable[..., None]  # ProjectScanner.add(sf_or_rel, line, rule, message, severity="")

PY_LLM = re.compile(r"\b(?:openai|anthropic|genai|langchain\w*|litellm|llama_index|ollama|cohere|mistralai|groq)\b")
PY_FSTRING = re.compile(r"\b[fF][rR]?(\"\"\"|'''|\"|')")
JS_TEMPLATE = re.compile(r"`")
PY_SLOT = re.compile(r"(?<!\{)\{\s*([A-Za-z_][\w.]*)(?:\[[^\]\n]{0,40}\])?\s*(?:![rsa])?(?::[^{}\n]{0,20})?\}(?!\})")
JS_SLOT = re.compile(r"\$\{\s*([A-Za-z_$][\w$.]*)\s*\}")
INSTRUCTION = re.compile(
    r"(?i)\b(?:you are|you're|answer|respond|reply|summari[sz]e|translate|classify|extract|rewrite|based on"
    r"|the following|below|your task|as an? (?:assistant|expert)|do not|don't|must|only)\b")
# delimiters that mark where the user's text starts and ends
DELIMITER = re.compile(r"```|\"\"\"|'''|<\/?[\w-]{1,40}>|-{3,}|#{3,}|={3,}|\[|\]|[\"'`]|\\[\"'`]")
# where a string is a prompt: assigned to a prompt-like name, a message's content, or passed to a model or template call
PROMPT_CONTEXT = re.compile(
    r"(?i)(?:\w{0,30}(?:prompt|instruction|template|content|message|query|input|context)\w{0,30}[ \t]{0,4}(?:\+?=|:)\s*(?:[fFrR]{1,2})?['\"`]{0,3}$"
    r"|(?:invoke|create|generate\w*|complete\w*|chat|ask|predict|run|format|from_template)\s*\(\s*(?:[fFrR]{1,2})?['\"`]{0,3}$)")
LOG_CONTEXT = re.compile(r"(?i)\b(?:console\s*\.\s*\w+|print|log(?:ger|ging)?\s*\.\s*\w+|logger|warn|error|raise\s+\w+)\s*\(\s*\S{0,3}$")
# the user pays for their own model calls with a key they entered
BYOK = re.compile(r"(?i)(?:profile|user|account|settings)\w*\??\.\w*api_?key|userApiKey|user_api_key|\bbyok\b")
NOT_USER_TEXT = re.compile(r"(?i)^(?:prompt|user_?prompt|instructions?|system\w*|template|content|body)$")

LOADER = re.compile(
    r"\b(?:WebBaseLoader|UnstructuredURLLoader|RecursiveUrlLoader|SitemapLoader|AsyncHtmlLoader|AsyncChromiumLoader"
    r"|PlaywrightURLLoader|SeleniumURLLoader|FireCrawlLoader|CheerioWebBaseLoader|PuppeteerWebBaseLoader"
    r"|RecursiveUrlLoader|BeautifulSoupWebReader|TrafilaturaWebReader|SimpleWebPageReader|PyPDFLoader|PDFLoader"
    r"|UnstructuredFileLoader|Docx2txtLoader|SimpleDirectoryReader|UnstructuredLoader)\b")
VECTOR_WRITE = re.compile(
    r"\.\s*(?:a?add_documents|add_texts|from_documents|from_texts|addDocuments|fromDocuments|fromTexts|insert_nodes)\s*\(")
CLEANING = re.compile(
    r"(?i)sanitiz|bleach|strip_?tags|html2text|clean_?(?:text|html|doc|content)|remove_?(?:instructions|injection)"
    r"|prompt_?injection|injection_?(?:check|guard|filter)|moderat|presidio|redact|guardrail|lakera|rebuff|llm_?guard")

COST_EVIDENCE = re.compile(
    r"(?i)\busage\s*[\].]\s*\[?['\"]?(?:total_?tokens|input_?tokens|output_?tokens|prompt_?tokens|completion_?tokens|totalTokens|promptTokens)"
    r"|usage_?metadata|\bquota|\bcredits?\b|token_?budget|tokens_?used|tokensUsed|max_?cost|spend_?limit|cost_?limit"
    r"|usage_?limit|daily_?limit|monthly_?limit|ratelimit\w*\s*\(\s*\w*user|\bbilling\b|stripe\.(?:subscriptions|billing)"
    # gateways that enforce budgets and limits outside the app
    r"|portkey|helicone|max_?budget|budget_?duration|gateway\.ai\.cloudflare\.com|ai[-_]?gateway|\blitellm\b.{0,80}budget")
# a token cap per call plus a rate limit on the endpoint bounds what one client can spend
TOKEN_CAP = re.compile(r"(?i)\bmax_?(?:output_?|completion_?|new_?)?tokens\b|\bmaxOutputTokens\b|\bmaxTokens\b")

TEST_LLM = re.compile(
    r"(?i)openai|anthropic|\bllm\b|prompt|completion|\bgpt|claude|gemini|langchain|generateText|streamText|chat_?model"
    r"|\bevals?\b|deepeval|ragas|promptfoo|langsmith|braintrust")
HTTP_TEST = re.compile(r"(?i)https?://(?:localhost|127\.0\.0\.1)|\btest_?client\b|\bTestClient\b|\bsupertest\b|\brequest\s*\(\s*app\s*\)")
EVAL_FILE = re.compile(r"(?i)(?:^|/)(?:promptfoo[\w.-]*\.ya?ml|evals?/|[\w-]+\.eval\.[jt]s|deepeval|ragas)")


def run(project: Project, routes: List[Route], add: Add) -> None:
    llm_files: List[SourceFile] = []
    for sf in project.files:
        if sf.text is None or sf.kind not in ("py", "js") or sf.is_test or sf.is_example or sf.is_vendored:
            continue
        v = sf.cache.get("views")
        if v is None or not _calls_llm(sf, v.code):  # type: ignore[attr-defined]
            continue
        llm_files.append(sf)
        GUARD.run(sf.rel, "prompt delimiters", _delimiters, sf, v, add)
        GUARD.run(sf.rel, "rag ingestion", _ingestion, sf, v, add)
    if llm_files:
        GUARD.run("<project>", "llm cost limits", _cost_limits, project, routes, add)
        GUARD.run("<project>", "llm tests", _llm_tests, project, routes, llm_files, add)


def _calls_llm(sf: SourceFile, code: str) -> bool:
    return bool(H.LLM_CALL_JS.search(code) if sf.kind == "js" else PY_LLM.search(code))


def _strings(sf: SourceFile, code: str, bare: str):
    """(offset, text) of every f-string (Python) or template literal (JS) in the file."""
    if sf.kind == "py":
        for m in finditer(PY_FSTRING, code):
            if bare[m.start()] != code[m.start()]:
                continue  # inside another string
            q = m.group(1)
            end = code.find(q, m.end())
            if end < 0 or (len(q) == 1 and "\n" in code[m.end():end]):
                continue
            yield m.end(), code[m.end():end]
    else:
        ticks = [m.start() for m in finditer(JS_TEMPLATE, code) if bare[m.start()] == "`"]
        for a, b in zip(ticks[::2], ticks[1::2]):
            if b - a < 6000:
                yield a + 1, code[a + 1:b]


def _delimiters(sf: SourceFile, v, add: Add) -> None:
    code, bare = v.code, v.bare
    slot_rx = PY_SLOT if sf.kind == "py" else JS_SLOT
    for start, text in _strings(sf, code, bare):
        literal = slot_rx.sub(" ", text)
        if len(re.findall(r"[A-Za-z]", literal)) < 40 or not INSTRUCTION.search(literal):
            continue
        lead = code[max(0, start - 120):start]
        if re.search(r"(?i)\brole\b['\"]?\s*[:=]\s*['\"]system", lead):
            continue  # a system prompt: LLM001's
        if not PROMPT_CONTEXT.search(lead[-60:]) or LOG_CONTEXT.search(lead[-60:]):
            continue  # not a prompt (a log line, an error message, a URL)
        for s in slot_rx.finditer(text):
            name = s.group(1).rsplit(".", 1)[-1]
            if not H.USERISH_NAME.match(name) or NOT_USER_TEXT.match(name):
                continue
            before, after = text[max(0, s.start() - 12):s.start()].rstrip(), text[s.end():s.end() + 12].lstrip()
            if DELIMITER.search(before[-4:]) or DELIMITER.search(after[:4]):
                continue
            add(sf, sf.line_at(start + s.start()), "LLM021",
                f"`{name}` is placed in the prompt without delimiters, so instructions inside it read like yours.")
            break


def _ingestion(sf: SourceFile, v, add: Add) -> None:
    code = v.code
    if not LOADER.search(code) or CLEANING.search(code):
        return
    m = VECTOR_WRITE.search(v.bare)
    if m:
        add(sf, sf.line_at(m.start()), "LLM022",
            "Documents loaded from the web or from files go into the vector store unchanged; instructions hidden in "
            "them reach the model as trusted context.")


def _cost_limits(project: Project, routes: List[Route], add: Add) -> None:
    texts = {f.rel: f.text or "" for f in project.files if f.kind in ("py", "js") and not f.is_test}
    llm_routes = [r for r in routes if r.calls_llm and r.has_auth
                  and not (H.RATE_LIMIT_EVIDENCE.search(r.body + texts.get(r.file, ""))
                           and TOKEN_CAP.search(r.body + texts.get(r.file, "")))]
    if not llm_routes:
        return
    for sf in project.files:
        if sf.text is not None and not sf.is_test and sf.kind in ("py", "js") and (COST_EVIDENCE.search(sf.text) or BYOK.search(sf.text)):
            return
    r = sorted(llm_routes, key=lambda r: (r.file, r.line))[0]
    add(r.file, r.line, "LLM023", f"{r.path} calls a model for signed-in users, but nothing in the project tracks "
                                  "tokens or cost per user, so one account can run up the whole bill.")


def _llm_tests(project: Project, routes: List[Route], llm_files: List[SourceFile], add: Add) -> None:
    tests = [f for f in project.files if f.is_test and f.kind in ("py", "js") and f.text]
    if not tests or any(EVAL_FILE.search(f.rel) for f in project.files):
        return
    stems = {f.rel.rsplit("/", 1)[-1].rsplit(".", 1)[0] for f in llm_files}
    # an end-to-end test that calls an LLM endpoint by its path exercises the LLM code too
    paths = {r.path.rstrip("/") for r in routes if r.calls_llm and len(r.path.strip("/")) >= 3}
    # and so does an HTTP test of the service the LLM code lives in
    tops = {f.rel.split("/", 1)[0] for f in llm_files if "/" in f.rel}
    for t in tests:
        text = t.text or ""
        if TEST_LLM.search(text) or any(re.search(r"\b%s\b" % re.escape(s), text) for s in stems if len(s) >= 3) \
                or any(p in text for p in paths) \
                or (t.rel.split("/", 1)[0] in tops and HTTP_TEST.search(text)):
            return
    first = sorted(llm_files, key=lambda f: f.rel)[0]
    v = first.cache.get("views")
    m: Optional[re.Match] = (H.LLM_CALL_JS if first.kind == "js" else PY_LLM).search(v.code if v is not None else first.text or "")  # type: ignore[attr-defined]
    add(first, first.line_at(m.start()) if m else 1, "LLM024",
        "The project has tests, but none of them exercises its LLM code: a prompt change can break answers unnoticed.")
