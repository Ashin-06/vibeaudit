"""JavaScript / TypeScript (and Vue, Svelte, HTML) analysis.

There is no JS parser in the standard library, so this works on lexer views (comments and string
contents blanked) with bracket matching. Data flow is a per-file approximation: identifiers
assigned from request data or model output are tracked as tainted until a fixpoint.
"""
from __future__ import annotations

import os
import posixpath
import re
from typing import Callable, Dict, List, Optional, Set, Tuple

from . import heuristics as H
from .guard import GUARD, finditer
from .files import Project, SourceFile
from .lexer import Views, first_arg, js_views, match_close, split_args, stmt_end
from .model import Finding, Route

Emit = Callable[[Finding], None]

USER_SRC = re.compile(
    r"\b(?:req|request)\s*\.\s*(?:body|query|params|headers|cookies|files?)\b"
    r"|\b(?:req|request)\s*\.\s*(?:json|formData|text)\s*\(\s*\)"
    r"|\bsearchParams\s*\.\s*get\s*\(|\bformData\s*\.\s*get\s*\("
    r"|\bevent\s*\.\s*(?:body|queryStringParameters|pathParameters)\b"
    r"|\bctx\s*\.\s*(?:request\s*\.\s*body|query|params)\b"
    r"|\bc\s*\.\s*req\s*\.\s*(?:json|query|param|parseBody|formData)\s*\("
    r"|\b(?:window\s*\.\s*)?location\s*\.\s*(?:hash|search)\b|\bdocument\s*\.\s*(?:URL|referrer)\b"
)
LLM_SRC = re.compile(
    r"\.\s*choices\s*\[\s*\d+\s*\]|\.\s*output_text\b|\.\s*content\s*\[\s*0\s*\]\s*\.\s*text\b"
    r"|\.\s*response\s*\.\s*text\s*\(\s*\)|\b(?:generateText|generateObject)\s*\("
    r"|\.\s*(?:chat\s*\.\s*completions|responses|messages)\s*\.\s*create\s*\(|\.\s*generateContent\s*\("
    r"|\b(?:llm|chain|agent|chatModel|model)\w*\s*\.\s*invoke\s*\("
)
SANITIZER = re.compile(
    r"(?i)\b(?:DOMPurify|purify|sanitize\w*|xss|escape\w*|encodeURIComponent|encodeURI|he\s*\.\s*encode|insane"
    r"|parseInt|parseFloat|Number|Boolean|validator\s*\.\s*\w+|\w+Schema\s*\.\s*(?:safe)?[pP]arse|z\s*\.\s*\w+)\s*\("
)
WHOLE_BODY = re.compile(
    r"^\s*(?:await\s+)?(?:(?:req|request|c\s*\.\s*req|ctx\s*\.\s*request)\s*\.\s*(?:body|json\s*\(\s*\))"
    r"|JSON\s*\.\s*parse\s*\(\s*(?:event|req)\s*\.\s*body\s*\))\s*(?:as\s+[\w<>\[\]]+)?\s*$"
)
DECL = re.compile(r"\b(?:const|let|var)\s+(\{[^}]*\}|\[[^\]]*\]|[A-Za-z_$][\w$]*)\s*(?::[^=;\n]+?)?=(?![=>])")
ASSIGN = re.compile(r"(?:^|[;{}\n])[ \t]*([A-Za-z_$][\w$]*)[ \t]*=(?![=>])")
SQL_KW = re.compile(
    r"(?i)\b(?:select\b[\s\S]*?\bfrom|insert\s+into|update\s+[\w\".`]+\s+set|delete\s+from|drop\s+table|where\s)"
)
SERVER_IMPORT = re.compile(
    r"""(?:from\s+|require\s*\(\s*)['"](?:express|fastify|hono|koa|@koa/router|koa-router|next/server|server-only|node:[\w/]+|fs|fs/promises|child_process|pg|mysql2?|mysql2/promise|mongoose|mongodb|@prisma/client|drizzle-orm[\w/-]*|bcrypt|bcryptjs|jsonwebtoken|nodemailer|ioredis|redis|dotenv|dotenv/config|@supabase/ssr)['"]"""
    r"""|import\s+['"](?:server-only|dotenv/config)['"]|\bDeno\s*\.\s*(?:serve|env)\b"""
)
SERVER_PATH = re.compile(
    r"(?:^|/)(?:api|server|backend|functions|lambda|lambdas|netlify|middleware|scripts|bin|cli|migrations|prisma|db"
    r"|database|models|controllers|services|workers|cron|jobs|seed|seeds)(?:/|$)"
    r"|(?:^|/)(?:route|middleware|server|instrumentation)\.[cm]?[jt]sx?$|\+server\.[jt]s$|\+(?:page|layout)\.server\.[jt]s$"
    r"|\.server\.[cm]?[jt]sx?$|\.config\.[cm]?[jt]s$"
)
FRAMEWORK_FILE = re.compile(
    r"""(?:from\s+|require\s*\(\s*)['"](?:express|fastify|hono|hono/[\w-]+|koa|@koa/router|koa-router|restify|polka|@hapi/hapi)['"]"""
    r"|\bexpress\s*\.\s*Router\s*\(|\bRouter\s*\(\s*\)"
)
ROUTE_CALL = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*(['\"`])([^'\"`\n]*)\3")
ROUTER_NAME = re.compile(r"^(?:app|router|server|api|fastify|route|routes|hono|r|\w*Router|\w*router|\w*App|\w*Routes|\w*routes|\w*Api|\w*api)$")
USE_CALL = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\.\s*use\s*\(")
IMPORT_DEFAULT = re.compile(r"""\bimport\s+([A-Za-z_$][\w$]*)(?:\s*,\s*\{[^}]*\})?\s+from\s+['"]([^'"]+)['"]""")
IMPORT_NAMED = re.compile(r"""\bimport\s+\{([^}]*)\}\s+from\s+['"]([^'"]+)['"]""")
REQUIRE = re.compile(r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)""")
FUNC_DEFS = [
    re.compile(r"\b(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\("),
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::\s*[^=\n]+?)?=>"),
    re.compile(r"\bexports\s*\.\s*([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\b[^{]*|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)"),
    re.compile(r"(?:^|[,{])[ \t]*(?:async[ \t]+)?([A-Za-z_$][\w$]*)[ \t]*(?::[ \t]*(?:async[ \t]+)?(?:function\b[ \t]*\w*[ \t]*)?)?\([^()]*\)[ \t]*(?::[ \t]*[\w<>\[\]|, ]+)?[ \t]*(?:=>[ \t]*)?\{", re.M),
]
NOT_FUNC = {"if", "for", "while", "switch", "catch", "function", "return", "with", "else", "do", "try", "constructor"}
MAXTOK = re.compile(r"max_tokens|max_completion_tokens|max_output_tokens|maxTokens|maxOutputTokens|maxCompletionTokens|max_new_tokens")
AGENT_LOOP_TEST = re.compile(r"(?i)tool_?calls?|tool_?use|stop_?reason|finish_?reason|function_?call|requires_action"
                             r"|!\s*(?:done|finished|isDone|isFinished|complete)\b")
BOUND = re.compile(
    r"(?i)\b\w*(?:max|limit|step|iter|turn|count|attempt|round|budget|tries|retries)\w*\s*(?:[<>]=?|===?|!==?)"
    r"|(?:[<>]=?|===?|!==?)\s*\w*(?:max|limit|step|iter|turn|count|attempt|round|budget|tries|retries)"
)
SECURITY_TODO = re.compile(
    r"\b(?:TODO|FIXME|XXX|HACK)\b[^\n]{0,100}?\b(?:auth\w*|secur\w*|validat\w*|sanitiz\w*|permission\w*"
    r"|rate.?limit\w*|csrf|password\w*|encrypt\w*|hash\w*|admin|access control|ownership|verif\w*|secret\w*|api.?keys?)\b"
    r"|\bin (?:a )?(?:real|prod(?:uction)?)\b[^\n]{0,60}?\b(?:you (?:should|would|must)|should|replace|implement|add|use a)\b"
    r"|\bfor (?:demo|testing|simplicity|now)(?: purposes)?\b[^\n]{0,60}?\b(?:auth\w*|password|secret|key|token|security|validat\w*|hardcod\w*|skip\w*)"
    r"|\b(?:this is (?:not|in)secure|replace (?:this )?with (?:a |your )?real|mock(?:ed)? auth\w*|skip(?:ping)? auth\w*"
    r"|bypass(?:ing)? auth\w*|disabled? (?:auth\w*|security|validation|csrf))",
    re.I,
)
AUTH_STUB = re.compile(
    r"(?:\bfunction\s+|\b(?:const|let|var)\s+)((?:is|verify|check|validate|authenticate|authorize|has|require|ensure|can)"
    r"[\w$]{0,40}?(?:auth|token|admin|permission|signature|password|login|jwt|credential|apikey|api_key|role|access|webhook)[\w$]{0,40})(?![\w$])"
    r"\s*(?:=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]| ]+)?\s*=>\s*(?:\{\s*return\s+true\s*;?\s*\}|true\b)"
    r"|\([^)]*\)\s*(?::\s*[\w<>\[\]| ]+)?\s*\{\s*return\s+true\s*;?\s*\})",
    re.I,
)


# template values that come from users or a model: {{ user.bio|safe }}, {{ comment.text|safe }}, {{ answer|safe }}
USER_TEMPLATE_VALUE = re.compile(
    r"(?i)\b(?:user|profile|comment|bio|message|msg|input|request|query|params|args|form|review|reply|feedback|"
    r"chat|answer|response|completion|output|llm|prompt|content)\w*")


def is_static_string(code: str) -> bool:
    s = code.strip()
    if not s:
        return True
    if re.fullmatch(r"(?:'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\")(?:\s*\+\s*(?:'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"))*", s):
        return True  # a literal, or literals joined with +
    if re.fullmatch(r"`[^`]*`", s) and "${" not in s:
        return True
    return bool(re.fullmatch(r"-?\d+(?:\.\d+)?", s))


CALLED = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*)\s*\(")  # names a function body calls


def ident_re(name: str) -> "re.Pattern[str]":
    return re.compile(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])")


class FileState:
    def __init__(self, sf: SourceFile, views: Views):
        self.sf = sf
        self.v = views
        # Taint is scoped: a name tainted inside one function is not tainted in another function of the
        # same file. Scopes are function spans; (0, 10 ** 12) is top-level code, visible everywhere.
        self.scopes: List[Tuple[int, int]] = []
        self.taint: Dict[str, Dict[Tuple[int, int], Set[str]]] = {}
        self.whole_body: Dict[str, Set[Tuple[int, int]]] = {}
        self.sql_names: Dict[str, Set[Tuple[int, int]]] = {}
        self.decl_rhs: Dict[str, str] = {}
        self.handled: Set[int] = set()  # sink offsets already reported
        self.is_framework = bool(FRAMEWORK_FILE.search(views.code))
        # computed once per file content and kept in sf.cache by a long-lived Project (vibeaudit watch, lsp):
        # both depend only on this file (and the configured sanitizers, part of the cache key)
        self.defs: Optional[List[Tuple[str, int, int]]] = None  # functions found by index_functions
        self.tainted = False  # compute_taint has run
        self.facts: Dict[Tuple[int, int], Tuple[bool, frozenset]] = {}  # see JsScanner.compute_llm_funcs

    def scope_of(self, at: int) -> Tuple[int, int]:
        best = (0, 10 ** 12)
        for a, b in self.scopes:
            if a <= at < b and (b - a) < (best[1] - best[0]):
                best = (a, b)
        return best

    @staticmethod
    def visible(spans, at: Optional[int]) -> bool:
        return bool(spans) and (at is None or any(a <= at < b for a, b in spans))

    def taint_at(self, at: Optional[int]) -> Dict[str, Set[str]]:
        out: Dict[str, Set[str]] = {}
        for name, by_scope in self.taint.items():
            for (a, b), kinds in by_scope.items():
                if at is None or a <= at < b:
                    out[name] = out.get(name, set()) | kinds
        return out

    def add_taint(self, name: str, scope: Tuple[int, int], kinds: Set[str]) -> bool:
        current = self.taint.setdefault(name, {}).setdefault(scope, set())
        if kinds <= current:
            return False
        current |= kinds
        return True

    def kinds(self, code: str, bare: str, at: Optional[int] = None) -> Set[str]:
        if SANITIZER.search(code) or H.CUSTOM.is_sanitizer(code):
            return set()
        k: Set[str] = set()
        if USER_SRC.search(code):
            k.add("user")
        if LLM_SRC.search(code):
            k.add("llm")
        for name, kinds in self.taint_at(at).items():
            if kinds - k and ident_re(name).search(bare):
                k |= kinds
        return k


def _decl_names(target: str) -> List[str]:
    target = target.strip()
    if target[:1] in "{[":
        names = []
        for part in target[1:-1].split(","):
            part = part.split("=")[0].strip()
            if ":" in part:
                part = part.split(":", 1)[1].strip()
            part = part.lstrip(".").strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", part):
                names.append(part)
        return names
    return [target]


class JsScanner:
    def __init__(self, project: Project, emit: Emit):
        self.p = project
        self.emit = emit
        self.files: List[FileState] = []
        self.func_index: Dict[str, List[Tuple[FileState, int, int]]] = {}
        self.llm_funcs: Set[str] = set()
        self.authed_files: Set[str] = set()
        self.routes: List[Route] = []
        deps = project.all_js_deps()
        self.mongo = bool(deps & {"mongoose", "mongodb"})
        self.mongo_sanitized = bool(deps & {"express-mongo-sanitize", "mongo-sanitize"})

    # ------------------------------------------------------------------ helpers
    def add(self, fs: FileState, rule: str, offset: int, msg: str, sev: str = "") -> None:
        line = fs.sf.line_at(offset)
        self.emit(Finding(rule, fs.sf.rel, line, msg, sev, fs.sf.line(line).strip()))

    def is_client(self, sf: SourceFile, v: Views) -> bool:
        if sf.kind == "html":
            return True
        head = v.code[:600]
        if re.search(r"^\s*['\"]use client['\"]", head, re.M):
            return True
        if re.search(r"^\s*['\"]use server['\"]", head, re.M):
            return False
        if SERVER_PATH.search(sf.rel) or SERVER_IMPORT.search(v.code):
            return False
        if re.search(r"process\s*\.\s*env\s*\.\s*(?!NEXT_PUBLIC_|REACT_APP_|VITE_|EXPO_PUBLIC_|NODE_ENV\b)[A-Z]", v.code):
            return False
        ext = os.path.splitext(sf.rel)[1].lower()
        deps = self.p.js_deps(sf.rel)
        if ext in (".vue", ".svelte"):
            return True
        if "next" in deps:
            return bool(re.search(r"(?:^|/)pages/(?!api/)", sf.rel))
        if "@sveltejs/kit" in deps:
            return bool(re.search(r"(?:^|/)\+(?:page|layout)\.[jt]s$", sf.rel)) or ("/lib/" in sf.rel and "/server/" not in sf.rel)
        client_stack = {"vite", "react-scripts", "@vitejs/plugin-react", "@vitejs/plugin-react-swc", "@vitejs/plugin-vue",
                        "expo", "react-native", "@angular/core", "vue", "svelte", "solid-js", "preact", "parcel"}
        if deps & client_stack:
            return sf.rel.startswith(("src/", "app/", "components/")) or "/src/" in sf.rel or "/components/" in sf.rel
        return False

    def resolve_import(self, fs: FileState, spec: str) -> Optional[str]:
        if spec.startswith("@/") or spec.startswith("~/"):
            bases = ["src/" + spec[2:], spec[2:]]
        elif spec.startswith("."):
            bases = [posixpath.normpath(posixpath.join(posixpath.dirname(fs.sf.rel), spec))]
        else:
            return None
        for base in bases:
            for ext in ("", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", "/index.js", "/index.ts"):
                if self.p.get(base + ext):
                    return base + ext
        return None

    def imports(self, fs: FileState) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for m in finditer(IMPORT_DEFAULT, fs.v.code):
            out[m.group(1)] = m.group(2)
        for m in finditer(REQUIRE, fs.v.code):
            out[m.group(1)] = m.group(2)
        for m in finditer(IMPORT_NAMED, fs.v.code):
            for part in m.group(1).split(","):
                name = part.split(" as ")[-1].strip()
                if name:
                    out[name] = m.group(2)
        return out

    def call_args(self, fs: FileState, open_paren: int) -> List[Tuple[str, str, int]]:
        close = match_close(fs.v.bare, open_paren)
        if close < 0:
            return []
        return [(fs.v.code[a:b], fs.v.bare[a:b], a) for a, b in split_args(fs.v.bare, open_paren + 1, close)]

    # --------------------------------------------------------------------- run
    def run(self) -> List[Route]:
        for sf in self.p.files:
            if sf.kind in ("js", "html") and sf.text is not None:
                GUARD.run(sf.rel, "JavaScript lexing", self._load, sf)
        for fs in self.files:
            GUARD.run(fs.sf.rel, "function index", self.index_functions, fs)
        GUARD.run("<project>", "JavaScript call graph", self.compute_llm_funcs)
        for fs in self.files:
            GUARD.run(fs.sf.rel, "data flow", self.compute_taint, fs)
        GUARD.run("<project>", "middleware and router mounts", self.compute_mount_auth)
        if GUARD.memo is not None:  # what the checks read besides their own file (see guard.NEEDS_CONTEXT)
            GUARD.sink("js routes", self.routes)
            GUARD.memo.context["JavaScript checks"] = (
                frozenset(self.llm_funcs), frozenset(self.authed_files), self.mongo, self.mongo_sanitized,
                H.CUSTOM.signature())
        for fs in self.files:
            if not fs.sf.is_test:
                GUARD.run(fs.sf.rel, "JavaScript checks", self._check_file, fs)
        return self.routes

    def _load(self, sf: SourceFile) -> None:
        v = sf.cache.get("js_views") or js_views(sf.text or "")
        sf.cache["views"] = sf.cache["js_views"] = v
        sf.is_client = self.is_client(sf, v)
        cached = sf.cache.get("js_state")
        signature = H.CUSTOM.signature()
        if isinstance(cached, tuple) and cached[0] == signature:
            fs = cached[1]
            fs.handled = set()  # per scan: which sinks this scan already reported
        else:
            fs = FileState(sf, v)
            sf.cache["js_state"] = (signature, fs)
        self.files.append(fs)

    def _check_file(self, fs: FileState) -> None:
        self.check_tools(fs)
        self.check_sinks(fs)
        self.check_html_sinks(fs)
        self.check_llm(fs)
        self.check_misc(fs)
        self.check_comments(fs)
        self.extract_routes(fs)

    # ------------------------------------------------------------- indexing
    def index_functions(self, fs: FileState) -> None:
        if fs.defs is not None:
            for name, a, b in fs.defs:
                self.func_index.setdefault(name, []).append((fs, a, b))
            return
        defs: List[Tuple[str, int, int]] = []
        self._index_functions(fs, defs)
        fs.defs = defs
        for name, a, b in defs:
            self.func_index.setdefault(name, []).append((fs, a, b))

    def _index_functions(self, fs: FileState, defs: List[Tuple[str, int, int]]) -> None:
        bare = fs.v.bare
        for rx in FUNC_DEFS:
            for m in finditer(rx, bare):
                name = m.group(1)
                if name in NOT_FUNC:
                    continue
                start = m.end()
                if bare[m.end() - 1] == "(":
                    close = match_close(bare, m.end() - 1)
                    if close < 0:
                        continue
                    start = close + 1
                k = start
                while k < len(bare) and bare[k] in " \t\n:=>":
                    k += 1
                if bare[m.end() - 1] == "{":
                    k = m.end() - 1
                elif k < len(bare) and bare[k] != "{":
                    # skip a TS return type annotation up to the body brace
                    brace = bare.find("{", k)
                    nl = bare.find("\n", k)
                    if brace != -1 and (nl == -1 or brace <= nl):
                        k = brace
                if k < len(bare) and bare[k] == "{":
                    end = match_close(bare, k)
                else:
                    end = stmt_end(bare, k)
                if end > m.start():
                    defs.append((name, m.start(), end + 1))
                    fs.scopes.append((m.start(), end + 1))

    def body_of(self, name: str, near: Optional[FileState] = None) -> Optional[str]:
        defs = self.func_index.get(name.split(".")[-1])
        if not defs:
            return None
        from .files import _read

        for fs, _a, _b in defs:
            _read(fs.sf)  # which definition is picked depends on every file that defines the name
        if near is not None:
            for fs, a, b in defs:
                if fs is near:
                    return fs.v.code[a:b]
        if len(defs) == 1:
            fs, a, b = defs[0]
            return fs.v.code[a:b]
        if near is not None and "." in name:
            spec = self.imports(near).get(name.split(".")[0])
            target = self.resolve_import(near, spec) if spec else None
            for fs, a, b in defs:
                if fs.sf.rel == target:
                    return fs.v.code[a:b]
        return None

    def compute_llm_funcs(self) -> None:
        """Functions that call a model, directly or through up to three levels of other such functions.
        Each function's own facts (calls a model itself; which names it calls) are kept in its file's state,
        so a long-lived Project only looks at the bodies of changed files."""
        generic = {"GET", "POST", "PUT", "PATCH", "DELETE", "default", "handler", "main", "run", "fetch"}
        facts: Dict[str, Tuple[bool, Set[str]]] = {}
        for name, defs in self.func_index.items():
            if name in generic:
                continue
            direct, calls = False, set()
            for fs, a, b in defs:
                got = fs.facts.get((a, b))
                if got is None:
                    body = fs.v.code[a:b]
                    got = fs.facts[(a, b)] = (bool(H.LLM_CALL_JS.search(body)), frozenset(CALLED.findall(body)))
                direct = direct or got[0]
                calls |= got[1]
            facts[name] = (direct, calls)
        self.llm_funcs = {n for n, (direct, _c) in facts.items() if direct}
        for _ in range(3):
            if not self.llm_funcs:
                break
            new = {n for n, (_d, calls) in facts.items() if n not in self.llm_funcs and calls & self.llm_funcs}
            if not new:
                break
            self.llm_funcs |= new

    def calls_llm(self, code: str) -> bool:
        if H.LLM_CALL_JS.search(code):
            return True
        return any(re.search(r"(?<![\w$])" + re.escape(n) + r"\s*\(", code) for n in self.llm_funcs)

    def compute_taint(self, fs: FileState) -> None:
        if fs.tainted:
            return
        fs.tainted = True
        code, bare = fs.v.code, fs.v.bare
        assigns: List[Tuple[List[str], int, int, bool]] = []
        for m in finditer(DECL, bare):
            end = stmt_end(bare, m.end())
            assigns.append((_decl_names(m.group(1)), m.end(), end, m.group(1).strip()[:1] not in "{["))
        for m in finditer(ASSIGN, bare):
            end = stmt_end(bare, m.end())
            assigns.append(([m.group(1)], m.end(), end, True))
        scoped = [(names, a, b, plain, fs.scope_of(a)) for names, a, b, plain in assigns]
        for names, a, b, plain, scope in scoped:
            rhs = code[a:b]
            if plain and len(names) == 1:
                fs.decl_rhs.setdefault(names[0], rhs)
                if WHOLE_BODY.match(rhs):
                    fs.whole_body.setdefault(names[0], set()).add(scope)
                if SQL_KW.search(rhs) and ("${" in rhs or re.search(r"['\"`]\s*\+|\+\s*['\"`]", rhs)):
                    fs.sql_names.setdefault(names[0], set()).add(scope)
        self._taint_server_action_params(fs)
        for _ in range(6):
            changed = False
            for names, a, b, _plain, scope in scoped:
                GUARD.tick()
                k = fs.kinds(code[a:b], bare[a:b], a)
                if not k:
                    continue
                for n in names:
                    changed |= fs.add_taint(n, scope, k)
            if not changed:
                break

    def _taint_server_action_params(self, fs: FileState) -> None:
        """Server action arguments come straight from the client: `export async function save(id)` in a
        "use server" file, or a function whose body starts with the "use server" directive."""
        code, bare = fs.v.code, fs.v.bare
        file_level = bool(re.search(r"^\s*['\"]use server['\"]", code[:600], re.M))
        for a, b in fs.scopes:
            brace = bare.find("{", a, b)
            inline = brace >= 0 and re.match(r"\{\s*['\"]use server['\"]", code[brace:brace + 40])
            exported = file_level and re.search(r"\bexport\s+(?:default\s+)?(?:async\s+)?$", code[max(0, a - 40):a])
            if not (inline or exported):
                continue
            p_open = bare.find("(", a, b)
            p_close = match_close(bare, p_open) if p_open >= 0 else -1
            if p_close < 0:
                continue
            for x, y in split_args(bare, p_open + 1, p_close):
                piece = code[x:y].strip()
                if piece.startswith("{"):
                    names = _decl_names(piece[:match_close(bare[x:y].strip(), 0) + 1])
                else:
                    m = re.match(r"(?:\.\.\.)?\s*([A-Za-z_$][\w$]*)", piece)
                    names = [m.group(1)] if m else []
                for name in names:
                    fs.add_taint(name, (a, b), {"user"})

    def compute_mount_auth(self) -> None:
        """Express-style `app.use(requireAuth)` and `app.use('/x', requireAuth, router)` protection."""
        not_auth = re.compile(r"(?:session|cookieSession|expressSession|passport\s*\.\s*(?:initialize|session))\s*\(")

        def is_auth(c: str) -> bool:
            return (bool(H.AUTH_MIDDLEWARE.search(c)) and not not_auth.search(c)) or H.CUSTOM.is_auth(c)

        for fs in self.files:
            if not fs.is_framework:
                continue
            imports = self.imports(fs)
            global_auth = False
            for m in finditer(USE_CALL, fs.v.bare):
                args = self.call_args(fs, m.end() - 1)
                mw = [c.strip() for c, _b, _o in args if not is_static_string(c)]
                if not mw:
                    continue
                last = mw[-1]
                target = None
                if re.fullmatch(r"[A-Za-z_$][\w$]*", last) and last in imports:
                    target = self.resolve_import(fs, imports[last])
                if target:
                    if global_auth or any(is_auth(c) for c in mw[:-1]):
                        self.authed_files.add(target)
                elif any(is_auth(c) for c in mw):
                    global_auth = True  # protects routes and routers registered after this line
                    fs.sf.cache.setdefault("auth_from", m.start())

    # ---------------------------------------------------------------- tools
    def check_tools(self, fs: FileState) -> None:
        rx = re.compile(
            r"\btool\s*\(\s*\{|\.\s*(?:tool|registerTool|addTool)\s*\(|\bnew\s+(?:DynamicTool|DynamicStructuredTool)\s*\("
            r"|\btool\s*\(\s*(?:async\b|\(|function\b)"
        )
        danger = [
            (re.compile(r"(?<![\w$.])(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(|\.\s*(?:exec|execSync|spawn)\s*\("), "a shell command", "critical"),
            (re.compile(r"(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(|\bvm\s*\.\s*run\w*\s*\("), "dynamic code execution", "critical"),
            (re.compile(r"\bfs(?:\s*\.\s*promises)?\s*\.\s*(?:writeFile|writeFileSync|unlink|unlinkSync|rm|rmSync|appendFile|rename)\s*\("), "file system writes", "high"),
            (re.compile(r"\.\s*(?:\$queryRawUnsafe|\$executeRawUnsafe|unsafe)\s*\("), "raw SQL", "high"),
        ]
        if "child_process" not in fs.v.code and not re.search(r"\beval\s*\(|new\s+Function|\bfs\b|Unsafe\s*\(", fs.v.bare):
            return
        for m in finditer(rx, fs.v.bare):
            open_paren = m.end() - 1 if fs.v.bare[m.end() - 1] == "(" else fs.v.bare.rfind("(", m.start(), m.end())
            close = match_close(fs.v.bare, open_paren)
            if close < 0:
                continue
            seg = fs.v.bare[open_paren:close]
            for drx, what, sev in danger:
                for d in finditer(drx, seg):
                    off = open_paren + d.start()
                    if what == "a shell command" and "child_process" not in fs.v.code:
                        continue
                    fs.handled.add(off)
                    self.add(fs, "LLM005", off, f"An agent tool runs {what} with model-chosen arguments.", sev)

    # ---------------------------------------------------------------- sinks
    def check_sinks(self, fs: FileState) -> None:
        code, bare = fs.v.code, fs.v.bare
        has_cp = "child_process" in code
        server = not fs.sf.is_client

        def report(kind_rule: str, off: int, kinds: Set[str], what: str, user_sev: str, plain_msg: str = "",
                   plain_sev: str = "") -> None:
            if off in fs.handled:
                return
            fs.handled.add(off)
            if "llm" in kinds:
                sev = "critical" if kind_rule in ("BE001", "BE002", "BE003") else "high"
                self.add(fs, "LLM002", off, f"Model output flows into {what}.", sev)
            elif "user" in kinds:
                self.add(fs, kind_rule, off, f"Request data flows into {what}.", user_sev)
            elif plain_msg:
                self.add(fs, kind_rule, off, plain_msg, plain_sev)

        # command execution
        if has_cp:
            for m in finditer(r"(?<![\w$.])(?:exec|execSync)\s*\(|\b(?:child_process|cp|childProcess)\s*\.\s*(?:exec|execSync)\s*\(", bare):
                args = self.call_args(fs, m.end() - 1)
                if args and not is_static_string(args[0][0]):
                    report("BE002", m.start(), fs.kinds(args[0][0], args[0][1], m.start()), "a shell command", "critical",
                           "Shell command built from a variable; if any part comes from users or a model this is command injection.",
                           "medium")
            for m in finditer(r"(?<![\w$])(?:spawn|spawnSync|execFile|execFileSync)\s*\(", bare):
                args = self.call_args(fs, m.end() - 1)
                if not args:
                    continue
                joined = " ".join(a[0] for a in args)
                if re.search(r"\bshell\s*:\s*true", joined):
                    k = fs.kinds(joined, " ".join(a[1] for a in args), m.start())
                    report("BE002", m.start(), k, "a spawned process", "high",
                           "Process spawned with shell: true and a dynamic command.", "medium")
                else:
                    k = fs.kinds(args[0][0], args[0][1], m.start())  # without a shell only the program name is dangerous
                    if k & {"user", "llm"}:
                        report("BE002", m.start(), k, "the program a process runs", "high")
                    elif len(args) > 1 and args[1][1].lstrip().startswith("[") and "'--'" not in args[1][0]                             and '"--"' not in args[1][0] and "llm" in fs.kinds(args[1][0], args[1][1], m.start()):
                        self.add(fs, "LLM019", m.start(), "Model output is passed as an argument of a spawned process; "
                                                          "a value such as `--upload-pack=...` becomes an option.", "high")
        # dynamic code
        for m in finditer(r"(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(|\bvm\s*\.\s*(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(", bare):
            args = self.call_args(fs, m.end() - 1)
            if args and not all(is_static_string(a[0]) for a in args):
                joined = " ".join(a[0] for a in args)
                report("BE003", m.start(), fs.kinds(joined, " ".join(a[1] for a in args), m.start()), "eval / new Function",
                       "critical", "Code is evaluated from a dynamic string.", "medium")
        # SQL
        for m in finditer(r"\.\s*(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe|unsafe|exec|run|all|get|prepare)\s*\(", bare):
            args = self.call_args(fs, m.end() - 1)
            if not args:
                continue
            a_code, a_bare, _ = args[0]
            name = a_bare.strip()
            if re.match(r"(?:async\b|function\b|\(?\s*[\w$]*\s*\)?\s*=>|\(\s*[\w$.]+\s*\|\|)", name) or re.search(r"=>\s*\{", name[:200]) \
                    or re.search(r"\bPromise\s*$", bare[max(0, m.start() - 20):m.start()]):
                continue  # Promise.all(rows.map(async (r) => ...)): a callback, not a query string
            dynamic = False
            if SQL_KW.search(a_code) and ("${" in a_code or re.search(r"['\"`]\s*\+|\+\s*['\"`]", a_code)):
                dynamic = True
            elif re.fullmatch(r"[A-Za-z_$][\w$]*", name) and fs.visible(fs.sql_names.get(name), m.start()):
                dynamic = True
                a_code = fs.decl_rhs.get(name, a_code)
            if dynamic:
                report("BE001", m.start(), fs.kinds(a_code, a_code, m.start()), "a SQL query built with string formatting", "high",
                       "SQL query built with string interpolation; use parameters even for values you think are safe.",
                       "medium")
        # NoSQL
        if self.mongo and not self.mongo_sanitized:
            for m in finditer(r"\.\s*(?:find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace|updateOne|updateMany|deleteOne|deleteMany|countDocuments|exists)\s*\(", bare):
                args = self.call_args(fs, m.end() - 1)
                if not args:
                    continue
                a_code, a_bare, _ = args[0]
                direct = re.fullmatch(r"\s*(?:req|request)\s*\.\s*(?:body|query)\s*", a_code) or re.search(
                    r":\s*(?:req|request)\s*\.\s*(?:body|query|params)\s*\.\s*[\w$]+\s*(?=[,}])", a_code)
                if not direct and a_code.strip().startswith("{"):
                    for name, kinds in fs.taint_at(m.start()).items():
                        if "user" in kinds and not fs.visible(fs.whole_body.get(name), m.start()) and re.search(
                                r"[{,:]\s*" + re.escape(name) + r"\s*(?=[,}])", a_bare):
                            direct = True
                            break
                if direct:
                    report("BE010", m.start(), {"user"}, "a MongoDB query filter without type checks", "high")
        # mass assignment
        for m in finditer(r"\.\s*(?:create|insert|insertOne|insertMany|update|updateOne|updateMany|upsert|findByIdAndUpdate|findOneAndUpdate|build|bulkCreate)\s*\(|\bnew\s+[A-Z][\w$]*\s*\(|\bObject\s*\.\s*assign\s*\(", bare):
            args = self.call_args(fs, m.end() - 1)
            if not args:
                continue
            whole = [n for n, spans in fs.whole_body.items() if fs.visible(spans, m.start())]
            whole_rx = re.compile(
                r"(?<![\w$.])(?:req|request)\s*\.\s*body\b(?!\s*\.)"
                + (r"|(?:\.\.\.\s*|data\s*:\s*)(?:" + "|".join(map(re.escape, whole)) + r")\b(?!\s*[.\[])" if whole else "")
            )
            hit = any(whole_rx.search(a[0]) for a in args) or any(a[1].strip() in whole for a in args)
            if hit and not re.match(r"\bnew\s+(?:Error|URL|Response|NextResponse|Map|Set|Date|Request|Headers|Promise)\b", bare[m.start():m.end()]):
                report("BE009", m.start(), {"user"}, "a database write of the whole request body", "high")
        if not server:
            return
        # SSRF
        for m in finditer(r"(?<![\w$.])fetch\s*\(|\baxios(?:\s*\.\s*(?:get|post|put|delete|patch|request|head))?\s*\(|(?<![\w$.])got(?:\s*\.\s*(?:get|post))?\s*\(|\bhttps?\s*\.\s*(?:get|request)\s*\(", bare):
            arg = first_arg(bare, m.end() - 1)
            if not arg:
                continue
            a_code = code[arg[0]:arg[1]].strip()
            if re.match(r"""['"`](?:https?://[^'"`$/]+/|/(?!/))""", a_code):
                continue  # fixed host or relative path
            k = fs.kinds(a_code, bare[arg[0]:arg[1]], m.start())
            if k & {"user", "llm"}:
                report("BE005", m.start(), k, "an outbound HTTP request URL", "high")
        # path traversal
        fs_import = re.search(r"""['"](?:node:)?fs(?:/promises)?['"]""", code)
        for m in finditer(r"\b(?:res|reply|response)\s*\.\s*(?:sendFile|download)\s*\(|\bfs(?:\s*\.\s*promises)?\s*\.\s*(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|unlinkSync|rm|rmSync|appendFile|appendFileSync)\s*\(" + (r"|(?<![\w$.])(?:readFile|writeFile|unlink|rm|appendFile)\s*\(" if fs_import else ""), bare):
            arg = first_arg(bare, m.end() - 1)
            if arg:
                k = fs.kinds(code[arg[0]:arg[1]], bare[arg[0]:arg[1]], m.start())
                if k & {"user", "llm"} and "basename" not in code[arg[0]:arg[1]]:
                    report("BE006", m.start(), k, "a file system path", "high")
        # open redirect
        for m in finditer(r"\b(?:res|reply)\s*\.\s*redirect\s*\(|(?<![\w$.])redirect\s*\(|\b(?:NextResponse|Response)\s*\.\s*redirect\s*\(", bare):
            args = self.call_args(fs, m.end() - 1)
            if not args:
                continue
            target = args[-1] if bare[m.start():m.end()].startswith("res") else args[0]
            t_code = target[0].strip()
            if re.match(r"""['"`]/(?!/)""", t_code) or re.match(r"""new\s+URL\s*\(\s*['"`]/(?!/)""", t_code):
                continue
            if re.match(r"(?:[\w$.]+\s*\(\s*)?`\$\{\s*[\w$.]*\borigin\s*\}/", t_code):
                continue  # `${url.origin}/signin`: the app's own origin and a fixed path
            k = fs.kinds(t_code, target[1], m.start())
            if k & {"user", "llm"}:
                report("BE008", m.start(), k, "a redirect target", "medium")

    def check_html_sinks(self, fs: FileState) -> None:
        code, bare = fs.v.code, fs.v.bare

        def judge(off: int, expr_code: str, expr_bare: str, where: str) -> None:
            if off in fs.handled or is_static_string(expr_code) or SANITIZER.search(expr_code) or H.CUSTOM.is_sanitizer(expr_code):
                return
            fs.handled.add(off)
            k = fs.kinds(expr_code, expr_bare, off)
            if "llm" in k:
                self.add(fs, "LLM002", off, f"Model output is rendered as raw HTML ({where}); prompt injection becomes XSS.", "high")
            elif "user" in k:
                self.add(fs, "FE001", off, f"User-controlled data is rendered as raw HTML ({where}).", "high")
            elif expr_code.strip().startswith("`") and not re.search(r"<[A-Za-z][\w-]*[\s>/]", expr_code):
                return  # an inline script / snippet built from config values, not markup from data
            else:
                self.add(fs, "FE001", off, f"Unsanitized value rendered as raw HTML ({where}).", "medium")

        for m in finditer(r"\.\s*(?:innerHTML|outerHTML)\s*\+?=(?!=)", bare):
            end = stmt_end(bare, m.end())
            judge(m.start(), code[m.end():end], bare[m.end():end], "innerHTML")
        for m in finditer(r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:", bare):
            tag = re.findall(r"<\s*([A-Za-z][\w.]*)", bare[max(0, m.start() - 400):m.start()])
            if tag and tag[-1].lower() == "style":
                continue  # generated CSS (for example the shadcn/ui chart component)
            end = stmt_end(bare, m.end())
            judge(m.start(), code[m.end():end], bare[m.end():end], "dangerouslySetInnerHTML")
        for m in finditer(r"\.\s*insertAdjacentHTML\s*\(|\bdocument\s*\.\s*(?:write|writeln)\s*\(|\bbypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)\s*\(", bare):
            args = self.call_args(fs, m.end() - 1)
            if args:
                a = args[1] if "insertAdjacent" in m.group(0) and len(args) > 1 else args[0]
                judge(m.start(), a[0], a[1], m.group(0).strip(" .(").split(".")[-1].strip())
        for m in finditer(r"\bv-html\s*=\s*\"([^\"]*)\"", code):
            judge(m.start(), m.group(1), m.group(1), "v-html")
        for m in finditer(r"\{@html\s+([^}]*)\}", code):
            judge(m.start(), m.group(1), m.group(1), "{@html}")
        if not fs.sf.is_client:
            for m in finditer(r"\b(?:res|reply)\s*\.\s*send\s*\(", bare):
                arg = first_arg(bare, m.end() - 1)
                if arg and re.search(r"<\w", code[arg[0]:arg[1]]):
                    k = fs.kinds(code[arg[0]:arg[1]], bare[arg[0]:arg[1]], m.start())
                    if k & {"user", "llm"}:
                        judge(m.start(), code[arg[0]:arg[1]], bare[arg[0]:arg[1]], "HTML response")
        if fs.sf.kind == "html":
            # |safe on staff-authored CMS fields or generated docs is the intent (benchmark: 26 of 26 such findings
            # on djangoproject.com and others were false), so only values named like user or model input are reported
            for m in finditer(r"\{\{([^}\n]*)\|\s*safe\b[^}\n]*\}\}", code):
                if USER_TEMPLATE_VALUE.search(m.group(1)):
                    self.add(fs, "FE001", m.start(), "Template output marked safe, so it is not HTML-escaped.", "medium")
            if not re.search(r"(?i)e-?mail|\.txt$", fs.sf.rel):  # plain-text email templates turn escaping off on purpose
                for m in finditer(r"\{%\s*autoescape\s+(?:false|off)\s*%\}", code):
                    self.add(fs, "FE001", m.start(), "Template autoescaping is turned off.", "medium")

    # ------------------------------------------------------------------ llm
    def check_llm(self, fs: FileState) -> None:
        code, bare = fs.v.code, fs.v.bare
        has_llm = bool(H.LLM_CALL_JS.search(code))
        # direct provider calls from the browser
        for m in finditer(r"\bdangerouslyAllowBrowser\s*:\s*true", code):
            if self._own_backend(fs, m.start()):
                continue
            self.add(fs, "FE002", m.start(), "dangerouslyAllowBrowser: true ships the API key to the browser.")
        if fs.sf.is_client:
            seen_lines = set()
            for m in finditer(H.LLM_HOSTS.pattern + r"|\bnew\s+(?:OpenAI|Anthropic|GoogleGenerativeAI|GoogleGenAI|Groq|Mistral|CohereClient|ChatOpenAI|ChatAnthropic)\s*\(", code):
                line = fs.sf.line_at(m.start())
                if line in seen_lines or "dangerouslyAllowBrowser" in fs.sf.line(line):
                    continue
                seen_lines.add(line)
                self.add(fs, "FE002", m.start(), "AI provider called directly from browser code; the key is exposed to every visitor.")
            m = re.search(r"\brole\s*:\s*['\"]system['\"]\s*,\s*content\s*:\s*['\"`][^'\"`]{20,}"
                          r"|\b(?:systemPrompt|SYSTEM_PROMPT|systemMessage|system_prompt|systemInstruction)\s*[:=]\s*['\"`][^'\"`]{40,}"
                          r"|['\"`]You are (?:a|an|the)\b[^'\"`]{80,}", code)
            if m and bare[m.start()] == code[m.start()]:
                self.add(fs, "LLM007", m.start(), "A system prompt is defined in code that ships to the browser.")
        # untrusted text in the system prompt
        if has_llm:
            for m in finditer(r"\brole\s*:\s*['\"]system['\"]", code):
                start = self._enclosing_brace(bare, m.start())
                if start < 0:
                    continue
                end = match_close(bare, start)
                obj_code = code[start:end]
                cm = re.search(r"\bcontent\s*:\s*", obj_code)
                if cm:
                    a = start + cm.end()
                    self._system_prompt(fs, m.start(), code[a:stmt_end(bare, a)], bare[a:stmt_end(bare, a)])
            for m in finditer(r"(?<![\w$.])(?:system|systemInstruction|instructions)\s*:\s*", bare):
                a = m.end()
                b = stmt_end(bare, a)
                self._system_prompt(fs, m.start(), code[a:b], bare[a:b])
        # JSON.parse of model output outside a try block
        for m in finditer(r"\bJSON\s*\.\s*parse\s*\(", bare):
            arg = first_arg(bare, m.end() - 1)
            # JSON mode is looked for earlier in the enclosing function; it is not traced back to the call itself
            if (arg and "llm" in fs.kinds(code[arg[0]:arg[1]], bare[arg[0]:arg[1]], m.start()) and not self._inside_try(bare, m.start())
                    and not H.JSON_MODE.search(code, max(fs.scope_of(m.start())[0], m.start() - 3000), m.start())):
                self.add(fs, "LLM011", m.start(), "Model output is parsed with JSON.parse() without handling invalid JSON.")
        # token limits
        for m in finditer(r"\.\s*(?:chat\s*\.\s*completions\s*\.\s*(?:create|parse)|completions\s*\.\s*create|responses\s*\.\s*create)\s*\(|\b(?:generateText|streamText|generateObject|streamObject)\s*\(", bare):
            arg = first_arg(bare, m.end() - 1)
            if not arg:
                continue
            a_code = code[arg[0]:arg[1]].strip()
            if a_code.startswith("{"):
                bounded = MAXTOK.search(a_code) or re.search(r"\.\.\.\s*[\w$]", a_code)
            else:
                bounded = MAXTOK.search(fs.decl_rhs.get(a_code, "max_tokens"))
            if not bounded:
                self.add(fs, "LLM003", m.start(), "Model call has no output token limit.")
        if not MAXTOK.search(code):
            m = re.search(r"\.\s*generateContent(?:Stream)?\s*\(|\bfetch\s*\(\s*['\"`]" + H.LLM_HOSTS.pattern
                          + r"[^'\"`]*(?:completions|/messages|generateContent|/responses)", code)
            if m:
                self.add(fs, "LLM003", m.start(), "Model call has no output token limit (maxOutputTokens / max_tokens).")
        # unbounded agent loops
        for m in finditer(r"\bwhile\s*\(\s*true\s*\)|\bfor\s*\(\s*;\s*;\s*\)", bare):
            brace = bare.find("{", m.end())
            if brace < 0:
                continue
            body = code[brace:match_close(bare, brace)]
            if self.calls_llm(body) and not BOUND.search(body):
                self.add(fs, "LLM009", m.start(), "Loop calls a model with no step or budget limit.")
        # agent loops: run while the model keeps asking for tools (LLM020)
        for m in finditer(r"\bwhile\s*\(", bare):
            if re.match(r"\s*true\s*\)", bare[m.end():m.end() + 10]):
                continue  # LLM009's
            close = match_close(bare, m.end() - 1)
            if close < 0 or not AGENT_LOOP_TEST.search(code[m.end():close]):
                continue
            after = bare[close + 1:close + 40].lstrip()
            if after.startswith("{"):
                brace = close + 1 + bare[close + 1:].find("{")
                body = code[brace:match_close(bare, brace)]
            else:  # `do { ... } while (cond);`
                start = bare.rfind("do", 0, m.start())
                body = code[start:m.start()] if start >= 0 and m.start() - start < 20000 else ""
            if body and self.calls_llm(body) and not BOUND.search(code[m.end():close] + body):
                self.add(fs, "LLM020", m.start(), "Agent loop calls the model until it stops asking for tools, with no step limit.")
        for m in finditer(H.DANGEROUS_AGENT_OPTIONS, code):
            if bare[m.start()] != code[m.start()]:
                continue  # inside a string literal
            self.add(fs, "LLM006", m.start(), f"Dangerous agent option: {m.group(0).strip()[:60]}")

    def _own_backend(self, fs: FileState, off: int) -> bool:
        """The client options object sets baseURL to something other than an AI provider (a proxy)."""
        start = self._enclosing_brace(fs.v.bare, off)
        if start < 0:
            return False
        obj = fs.v.code[start:match_close(fs.v.bare, start) + 1]
        m = re.search(r"\bbase_?ur[li]\s*:\s*([^,}\n]+)", obj, re.I)
        return bool(m) and not H.LLM_HOSTS.search(m.group(1))

    @staticmethod
    def _inside_try(bare: str, pos: int) -> bool:
        depth = 0
        for k in range(pos, -1, -1):
            ch = bare[k]
            if ch == "}":
                depth += 1
            elif ch == "{":
                if depth == 0:
                    if re.search(r"\btry\s*$", bare[max(0, k - 20):k]):
                        return True
                else:
                    depth -= 1
        return False

    @staticmethod
    def _enclosing_brace(bare: str, pos: int) -> int:
        depth = 0
        for k in range(pos, -1, -1):
            ch = bare[k]
            if ch in ")]}":
                depth += 1
            elif ch in "([{":
                if depth == 0:
                    return k if ch == "{" else -1
                depth -= 1
        return -1

    def _system_prompt(self, fs: FileState, off: int, expr_code: str, expr_bare: str) -> None:
        if is_static_string(expr_code):
            return
        parts = re.findall(r"\$\{([^}]*)\}", expr_code)
        if re.search(r"['\"`]\s*\+|\+\s*['\"`]", expr_code):
            parts.append(expr_bare)
        if not parts:
            return
        joined = " ".join(parts)
        k = fs.kinds(joined, joined, off)
        if "user" in k:
            self.add(fs, "LLM001", off, "Request data is interpolated into the system prompt.", "high")
            return
        idents = set(re.findall(r"(?<![\w$.])([A-Za-z_$][\w$]*)", joined))
        if any(H.USERISH_NAME.match(i) for i in idents):
            self.add(fs, "LLM001", off, "A user-supplied value appears to be interpolated into the system prompt.", "medium")

    # ----------------------------------------------------------------- misc
    def check_misc(self, fs: FileState) -> None:
        code, bare, sf = fs.v.code, fs.v.bare, fs.sf
        rel = sf.rel
        if sf.is_client:
            for m in finditer(r"\b(?:local|session)Storage\s*\.\s*(?:getItem|setItem)\s*\(\s*['\"`](?:is_?admin|admin|role|user_?role|roles|permissions?|is_?premium|is_?pro|plan|tier|credits|subscription|is_?paid|access_?level|is_?verified)['\"`]", code, re.I):
                self.add(fs, "FE003", m.start(), "Authorization state is read from or written to browser storage.")
            for m in finditer(r"\blocalStorage\s*\.\s*setItem\s*\(\s*['\"`](?:[^'\"`]*(?:token|jwt|bearer|session_?id|credential)[^'\"`]*|(?:[^'\"`]*[._-])?(?:auth|session))['\"`]", code, re.I):
                if re.search(r"(?i)credential_?(?:id|public_?key)\b", m.group(0)):
                    continue  # a WebAuthn credential id or public key is not a secret
                self.add(fs, "FE005", m.start(), "Auth token stored in localStorage.")
            for m in finditer(r"""['"`]https?://(?:localhost|127\.0\.0\.1)(?::\d+)?[/'"`]""", code):
                line = sf.line(sf.line_at(m.start()))
                if not re.search(r"process\.env|import\.meta\.env|NODE_ENV|\bdev\b|__DEV__|isDev|development", line, re.I):
                    self.add(fs, "FE007", m.start(), "Hardcoded localhost URL in frontend code.")
            for m in finditer(r"\b(?:SUPABASE_)?SERVICE_ROLE(?:_KEY)?\b|\bserviceRoleKey\b", code):
                self.add(fs, "SEC009", m.start(), "Supabase service_role key referenced in browser code.")
                break
        for m in finditer(r"addEventListener\s*\(\s*['\"]message['\"]\s*,", code):
            before = code[max(0, m.start() - 40):m.start()]
            if re.search(r"(?i)(?:worker\w*|self|port\d*)\s*(?:\.\s*current)?\s*\.\s*$", before) or (
                    re.search(r"(?i)(?:^|/)workers?/|worker\.[cm]?[jt]s$", sf.rel) and not re.search(r"\bwindow\s*\.\s*$", before)):
                continue  # a Web Worker channel talks only to its own page: there is no foreign origin to check
            close = match_close(bare, bare.find("(", m.start()))
            seg = code[m.start():close]
            handler = re.search(r",\s*([A-Za-z_$][\w$]*)\s*\)?\s*$", seg)
            if handler and not re.search(r"=>|function", seg):
                seg += self.body_of(handler.group(1), fs) or ".origin"
            if ".origin" not in seg:
                self.add(fs, "FE004", m.start(), "message event handler does not check event.origin.")
        if re.search(r"(?:^|/)next\.config\.[cm]?[jt]s$", rel):
            for m in finditer(r"\bproductionBrowserSourceMaps\s*:\s*true", code):
                self.add(fs, "FE006", m.start(), "productionBrowserSourceMaps is enabled.")
        if re.search(r"(?:^|/)vite\.config\.[cm]?[jt]s$", rel):
            for m in finditer(r"\bsourcemap\s*:\s*true", code):
                self.add(fs, "FE006", m.start(), "Vite build emits public source maps.")
        # CORS: an open origin only matters together with credentials; without them the browser sends no
        # cookies, so another site cannot act as the logged-in user (benchmark: 34 of 35 were wildcard-only)
        for m in finditer(r"\bcors\s*\(", bare):
            args = self.call_args(fs, m.end() - 1)
            a = args[0][0] if args else ""
            if re.search(r"\borigin\s*:\s*(?:['\"]\*['\"]|true\b)", a) and re.search(r"\bcredentials\s*:\s*true", a):
                self.add(fs, "BE012", m.start(), "CORS allows any origin together with credentials.", "high")
        if re.search(r"Access-Control-Allow-Credentials['\"`]\s*[,:]\s*['\"`]?true", code, re.I):
            for m in finditer(r"Access-Control-Allow-Origin['\"`]\s*[,:]\s*(?:['\"`]\*['\"`]|(?:req|request)\s*\.\s*headers\s*(?:\.\s*origin|\[\s*['\"]origin['\"]\s*\]|\.get\s*\(\s*['\"]origin['\"]\s*\)))", code, re.I):
                self.add(fs, "BE012", m.start(), "CORS header allows any (or a reflected) origin together with credentials.", "high")
        for m in finditer(r"\brejectUnauthorized\s*:\s*false|\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0", code):
            self.add(fs, "BE013", m.start(), "TLS certificate verification is disabled.")
        for m in finditer(r"createHash\s*\(\s*['\"](?:md5|sha1|sha256|sha512)['\"]\s*\)\s*\.\s*update\s*\(\s*[^)]*pass", code, re.I):
            self.add(fs, "BE014", m.start(), "Password hashed with a fast hash instead of bcrypt/argon2.")
        for m in finditer(r"\.\s*password\s*(?:===?|!==?)\s*(?:(?:req|request)\s*\.\s*body\s*\.\s*password|password|body\s*\.\s*password|input\s*\.\s*password|credentials\s*\.\s*password|data\s*\.\s*password)\b|(?<![\w$.])password\s*(?:===?|!==?)\s*[\w$]+\s*\.\s*password\b", bare):
            self.add(fs, "BE014", m.start(), "Password compared in plaintext; passwords appear to be stored unhashed.")
        for m in finditer(r"Math\s*\.\s*random\s*\(\s*\)", bare):
            line = bare[bare.rfind("\n", 0, m.start()) + 1: bare.find("\n", m.start()) if bare.find("\n", m.start()) != -1 else len(bare)]
            if re.search(r"(?i)token|secret|passw|otp|api_?key|reset|verif|nonce|salt|session|invite|magic", line):
                self.add(fs, "BE015", m.start(), "Math.random() used to generate a secret value.")
        for m in finditer(r"\balgorithms\s*:\s*\[[^\]]*['\"]none['\"]", code, re.I):
            self.add(fs, "BE016", m.start(), "JWT verification accepts the 'none' algorithm.")
        for m in finditer(r"\bignoreExpiration\s*:\s*true", code):
            self.add(fs, "BE016", m.start(), "JWT expiry is ignored.", "medium")
        if not sf.is_client and re.search(r"\bjwt\s*\.\s*decode\s*\(", bare) and not re.search(r"\b(?:jwt\s*\.\s*verify|jwtVerify)\s*\(", bare):
            m = re.search(r"\bjwt\s*\.\s*decode\s*\(", bare)
            self.add(fs, "BE016", m.start(), "jwt.decode() does not verify the signature, and jwt.verify() is not used in this file.", "medium")
        for m in finditer(r"\b(?:res|reply)\s*(?:\.\s*status\s*\([^)]*\))?\s*\.\s*(?:json|send)\s*\([^;]*?\b(?:err|error|e|ex)\s*\.\s*stack\b", bare):
            self.add(fs, "BE017", m.start(), "Stack trace returned to the client.")
        # auth stubs
        for m in finditer(AUTH_STUB, code):
            self.add(fs, "AUTH008", m.start(), f"`{m.group(1)}` always returns true.")
        # swallowed errors
        for m in finditer(r"\bcatch\s*(?:\(\s*[\w$]*\s*(?::\s*\w+)?\s*\))?\s*\{\s*\}|\.\s*catch\s*\(\s*(?:\(\s*[\w$]*\s*\)|[\w$]+)\s*=>\s*\{\s*\}\s*\)", code):
            if re.search(r"//|/\*", sf.text[m.start():m.end()]):
                continue  # an explanatory comment means the empty handler is deliberate
            self.add(fs, "QA003", m.start(), "Error is caught and ignored.")
        # secrets printed to logs
        for m in finditer(r"\bconsole\s*\.\s*(?:log|info|debug|warn|error)\s*\(", bare):
            close = match_close(bare, m.end() - 1)
            seg_code = code[m.end():close]
            seg_bare = bare[m.end():close]
            if re.search(r"process\s*\.\s*env\s*\.\s*\w*(?:KEY|SECRET|TOKEN|PASSWORD|PASS)\w*", seg_code) or re.search(
                    r"(?<![\w$])(?:[\w$]+\s*\.\s*)?(?:apiKey|api_key|secretKey|secret|password|passwd|accessToken|access_token|privateKey|private_key|serviceRoleKey|token)\b(?!\s*[.(\[])", seg_bare):
                self.add(fs, "SEC010", m.start(), "A secret value is written to the console.")

    def check_comments(self, fs: FileState) -> None:
        for a, b in fs.v.comments:
            text = fs.sf.text[a:b]
            m = SECURITY_TODO.search(text)
            if m:
                self.add(fs, "QA004", a + m.start(), f"Comment: {text.strip()[:120]}")

    # --------------------------------------------------------------- routes
    def _route(self, fs: FileState, off: int, path: str, methods: List[str], body: str, framework: str,
               middleware: str = "", known: bool = True) -> None:
        sf = fs.sf
        auth = bool(H.AUTH_EVIDENCE.search(body) or H.AUTH_MIDDLEWARE.search(middleware) or H.CUSTOM.is_auth(middleware + body))
        if sf.rel in self.authed_files or off > sf.cache.get("auth_from", 10 ** 12):
            auth = True
        if framework == "supabase-edge" and re.search(r"""headers\s*\.\s*get\s*\(\s*['"]authorization['"]""", body, re.I) \
                and not self._jwt_check_disabled(path.rsplit("/", 1)[-1]):
            auth = True  # requires a bearer token and the platform verifies it before the function runs
        if not known:
            auth = True  # handler body not found; do not guess
        params = re.findall(r"(?:<(?:\w+:)?(\w+)>|\{(\w+)\}|:(\w+)|\[(?:\.\.\.)?(\w+)\])", path)
        GUARD.publish("js routes", self.routes, Route(
            file=sf.rel, line=sf.line_at(off), path=path, methods=methods, body=middleware + "\n" + body,
            framework=framework, lang="js", has_auth=auth, calls_llm=known and self.calls_llm(body),
            reads_body=bool(re.search(r"\b(?:req|request)\s*\.\s*body\b|\b(?:req|request)\s*\.\s*(?:json|formData)\s*\(|\bc\s*\.\s*req\s*\.\s*(?:json|parseBody)\s*\(|\bevent\s*\.\s*body\b", body)),
            params=[next(x for x in p if x) for p in params],
        ))

    def extract_routes(self, fs: FileState) -> None:
        sf, code, bare = fs.sf, fs.v.code, fs.v.bare
        rel = sf.rel
        if fs.is_framework:
            for m in finditer(ROUTE_CALL, code):
                if not ROUTER_NAME.match(m.group(1)) or bare[m.start():m.end()].count("(") != 1:
                    continue
                open_paren = code.index("(", m.end(2))
                args = self.call_args(fs, open_paren)
                if len(args) < 2:
                    continue
                handler = args[-1][0].strip()
                middleware = " ".join(a[0] for a in args[1:-1])
                if "=>" in handler or handler.startswith(("function", "async")):
                    body, known = handler, True
                elif re.fullmatch(r"[A-Za-z_$][\w$.]*", handler):
                    found = self.body_of(handler, fs)
                    body, known = (found or ""), found is not None
                else:
                    body, known = handler, True
                self._route(fs, m.start(), m.group(4), [m.group(2).upper()], body, "express", middleware, known)
        app_route = re.search(r"(?:^|/)app/(.*?)/?route\.[cm]?[jt]s$", rel)
        kit_route = re.search(r"(?:^|/)src/routes/(.*?)/?\+server\.[jt]s$", rel)
        if app_route or kit_route:
            segs = (app_route or kit_route).group(1)
            path = "/" + "/".join(s for s in segs.split("/") if s and not (s.startswith("(") and s.endswith(")")))
            for m in finditer(r"\bexport\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|\bexport\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*(?::[^=]+)?=", bare):
                method = m.group(1) or m.group(2)
                if m.group(1):
                    p_open = bare.find("(", m.end())
                    p_close = match_close(bare, p_open) if p_open >= 0 else -1
                    brace = bare.find("{", p_close) if p_close >= 0 else -1
                    end = match_close(bare, brace) if brace >= 0 else -1
                    body = code[m.start():end + 1] if end > 0 else code[m.start():]
                else:
                    body = code[m.start():stmt_end(bare, m.end())]
                helpers = self._local_helpers(fs, body)
                self._route(fs, m.start(), path, [method], body + helpers, "next-app" if app_route else "sveltekit")
        pages_api = re.search(r"(?:^|/)pages/api/(.+?)\.[cm]?[jt]sx?$", rel)
        if pages_api:
            path = "/api/" + re.sub(r"(?:^|/)index$", "", pages_api.group(1))
            methods = sorted(set(re.findall(r"\bmethod\s*(?:===?|!==?)\s*['\"](GET|POST|PUT|PATCH|DELETE)['\"]", code))) or ["ALL"]
            m = re.search(r"\bexport\s+default\b", bare)
            self._route(fs, m.start() if m else 0, path, methods, code, "next-pages")
        if re.search(r"^\s*['\"]use server['\"]", code[:600], re.M):
            for m in finditer(r"\bexport\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|\bexport\s+const\s+([A-Za-z_$][\w$]*)\s*=\s*async\b", bare):
                name = m.group(1) or m.group(2)
                brace = bare.find("{", m.end())
                end = match_close(bare, brace) if brace >= 0 else -1
                body = code[m.start():end + 1] if end > 0 else ""
                if H.MUTATION_EVIDENCE.search(body):
                    self._route(fs, m.start(), "server action " + name, ["POST"], body + self._local_helpers(fs, body), "next-server-action")
        edge = re.search(r"(?:^|/)supabase/functions/([^/_][^/]*)/index\.[jt]s$", rel)
        if edge:
            m = re.search(r"\b(?:Deno\s*\.\s*)?serve\s*\(", bare)
            self._route(fs, m.start() if m else 0, "/functions/v1/" + edge.group(1), ["ALL"], code, "supabase-edge")
        for m in finditer(r"\bonRequest\s*\(", bare):
            close = match_close(bare, m.end() - 1)
            self._route(fs, m.start(), "firebase function", ["ALL"], code[m.start():close], "firebase-functions")

    def _jwt_check_disabled(self, function: str) -> bool:
        for f in self.p.files:
            if f.rel.endswith("supabase/config.toml") and f.text:
                block = re.search(r"\[functions\." + re.escape(function) + r"\]([^\[]*)", f.text)
                if block and re.search(r"verify_jwt\s*=\s*false", block.group(1)):
                    return True
        return False

    def _local_helpers(self, fs: FileState, body: str) -> str:
        """Bodies of helpers the handler calls (same file, or imported from the project), one level deep,
        so `const user = await getServerProfile()` implemented in lib/ counts as an auth check."""
        out = []
        for name in sorted(set(re.findall(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(", body))):
            if name in ("GET", "POST", "PUT", "PATCH", "DELETE") or name in NOT_FUNC:
                continue
            found = self.body_of(name, fs)
            if found and len(found) < 20000:
                out.append(found)
        return "\n".join(out)
