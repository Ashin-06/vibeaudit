"""Rust support: a linear lexer, route discovery for Actix Web and Axum, and a per-handler data flow from request
extractors into the generic injection rules (BE001 SQL, BE002 commands, BE005 SSRF, BE006 file paths, BE008
redirects). Routes feed the shared route checks (AUTH001-AUTH004, AUTH010, LLM004). N+1 queries and reqwest
timeouts stay in polyscan.

Known limits: a handler's taint comes from its own extractors (`web::Json<T>`, `Path(id)`, ...), not from
functions it calls; routers assembled across crates or by macros are not followed; Kotlin-style nested block
comments are read as ending at the first `*/`.
"""
from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Set, Tuple

from . import heuristics as H
from .files import Project, SourceFile
from .calls import Fn, Follower, rust_params, via_note
from .goscan import _split_top
from .guard import GUARD, finditer
from .lexer import Views, match_close
from .model import Finding, Route

Emit = Callable[[Finding], None]

TOKEN = re.compile(
    r'//[^\n]*'
    r'|/\*.*?(?:\*/|\Z)'
    r'|b?r(#*)".*?(?:"\1|\Z)'
    r'|b?"(?:\\.|[^"\\])*(?:"|\Z)'
    r"|b?'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|.)|[^'\\\n])'",
    re.S,
)
_NOT_NL = re.compile(r"[^\n]")


def rust_views(src: str) -> Views:
    """Offset-preserving views: `code` without comments, `bare` also without string and char contents."""
    code: List[str] = []
    bare: List[str] = []
    comments: List[Tuple[int, int]] = []
    last = 0
    for m in TOKEN.finditer(src):
        s, a, b = m.group(0), m.start(), m.end()
        code.append(src[last:a])
        bare.append(src[last:a])
        if s.startswith("/"):
            blank = _NOT_NL.sub(" ", s)
            code.append(blank)
            bare.append(blank)
            comments.append((a, b))
        else:
            q = s.index(s.lstrip("br#")[0]) + 1  # past the opening quote
            close = len(s) - (len(m.group(1) or "") + 1 if s.lstrip("b").startswith("r") else 1)
            close = close if close >= q and s[close:close + 1] in "\"'" else len(s)
            code.append(s)
            bare.append(s[:q] + _NOT_NL.sub(" ", s[q:close]) + s[close:])
        last = b
    code.append(src[last:])
    bare.append(src[last:])
    return Views("".join(code), "".join(bare), comments)


FN_DECL = re.compile(r"\bfn\s+(\w+)\s*(?:<[^>{;]{0,200}>)?\s*\(")
ACTIX_ATTR = re.compile(r"#\[\s*(get|post|put|patch|delete|head|route)\s*\(\s*\"")
BUILDER_ROUTE = re.compile(r"\.\s*route\s*\(\s*\"")
RESOURCE = re.compile(r"\bweb\s*::\s*resource\s*\(\s*\"")
SCOPE = re.compile(r"\bweb\s*::\s*scope\s*\(\s*\"")
NEST = re.compile(r"\.\s*nest\s*\(\s*\"")
METHOD_CALL = re.compile(r"\b(?:web\s*::\s*|routing\s*::\s*)?(get|post|put|patch|delete|head|any)\s*\(\s*\)?\s*(?:\.\s*to\s*\()?\s*([A-Za-z_][\w:]*)")
AUTH_TYPE = re.compile(r"(?i)\b\w*(?:auth|claims|identity|currentuser|session|principal|loggedin|bearer|apikey|jwt|admin)\w*\b")
AUTH_MW = re.compile(H.AUTH_MIDDLEWARE.pattern + r"|\b\w*(?:anonymous|login_required|require_login)\w*\b")  # the pattern is already (?i)  # `reject_anonymous_users`
AUTH_LAYER = re.compile(r"\.\s*(?:wrap|layer|route_layer)\s*\(([^;]{0,400})")
EXTRACTOR = re.compile(r"\b(?:web\s*::\s*)?(Path|Query|Json|Form|Multipart|Bytes|String)\b")
LLM_CALL = re.compile(r"\.\s*chat\s*\(\s*\)\s*\.\s*create\s*\(|\bcreate_chat_completion\b|\bCreateChatCompletionRequest|\banthropic\b.*\bmessages\b"
                      r"|\b(?:completion_model|agent|client)\s*\.\s*(?:prompt|completion|chat)\s*\(")
SAFE_PATH_TYPE = re.compile(r"\(?(?:i8|i16|i32|i64|i128|isize|u8|u16|u32|u64|u128|usize|f32|f64|bool|Uuid|uuid::Uuid|char)(?:,(?:i8|i16|i32|i64|i128|isize|u8|u16|u32|u64|u128|usize|f32|f64|bool|Uuid|uuid::Uuid|char))*,?\)?")  # fullmatch on the type with whitespace removed


FN_ATTRS = re.compile(r"(?:#\[[^\]\n]{0,300}\]\s*)+(?:pub(?:\([\w\s:]{0,40}\))?\s+)?(?:async\s+)?\Z")
CFG_TEST_MOD = re.compile(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*(?:pub(?:\s*\([\w\s:]{0,40}\))?\s+)?mod\s+\w+\s*\{")


def without_test_modules(code: str, bare: str) -> str:
    """`code` with each `#[cfg(test)] mod x { ... }` blanked (offsets kept): inline unit tests are not app code."""
    parts: List[str] = []
    last = 0
    for m in finditer(CFG_TEST_MOD, bare):
        if m.start() < last:
            continue  # nested in a module already blanked
        end = match_close(bare, m.end() - 1)
        end = len(bare) if end < 0 else end + 1
        parts += [code[last:m.start()], _NOT_NL.sub(" ", code[m.start():end])]
        last = end
    return "".join(parts) + code[last:]


# a request extractor of the project's own: Axum `impl<S> FromRequestParts<S> for OrgContext`, Actix `impl FromRequest for User`
EXTRACTOR_IMPL = re.compile(r"\bimpl\b[^{;]{0,200}?\bFromRequest(?:Parts)?\b[^{;]{0,200}?\bfor\s+([A-Z]\w*)[^{;]{0,200}\{")
# ...that turns a request away: 401/403 rejections
REJECTS = re.compile(r"\b(?:Unauthenticated|Unauthori[sz]ed|UNAUTHORIZED|Forbidden|FORBIDDEN|ErrorUnauthorized|ErrorForbidden)\b"
                     r"|\bStatusCode\s*::\s*from_u16\s*\(\s*40[13]\b")


def is_rust(sf: SourceFile) -> bool:
    return sf.rel.endswith(".rs") and sf.text is not None


class RustScanner:
    def __init__(self, project: Project, emit: Emit):
        self.p = project
        self.emit = emit
        self.files: List[SourceFile] = []
        self.funcs: Dict[str, List[Tuple[SourceFile, int, int, int, int]]] = {}  # name -> (sf, start, params open, close, end)
        self.routes: List[Route] = []
        self.handlers: Set[Tuple[str, int]] = set()  # (file, fn start) of handler functions
        self.fn_prefix: Dict[str, str] = {}  # function name -> prefix it is nested or scoped under
        self.extractors: Dict[str, str] = {}  # type -> body of its FromRequest(Parts) impl
        self.auth_extractors: Set[str] = set()  # those that reject unauthenticated requests
        self.follower = Follower(rust_params)  # cross-function taint
        self.depth, self.via = 0, None  # while a followed call is checked: how deep, and the call it came through
        self.reported: Set[Tuple[str, int, str, bool]] = set()

    def add(self, sf: SourceFile, off: int, rule: str, msg: str, sev: str = "") -> None:
        line = sf.line_at(off)
        if self.via is not None:
            if not msg.startswith("Request data"):
                return  # a followed call only adds what the request data reaches; the rest is reported once already
            msg += via_note(self.via)
        key = (sf.rel, line, rule, self.via is not None)  # a followed finding replaces the plain one (scanner.finalize)
        if key in self.reported:
            return
        self.reported.add(key)
        self.emit(Finding(rule, sf.rel, line, msg, sev, sf.line(line).strip()[:200]))

    def run(self) -> List[Route]:
        self.files = [f for f in self.p.files if is_rust(f) and not f.is_test and not re.search(r"(?:^|/)tests?/|(?:^|/)benches/", f.rel)]
        if not self.files:
            return []
        for sf in self.files:
            GUARD.run(sf.rel, "Rust lexing", self._load, sf)
        self._auth_extractors()
        for sf in self.files:
            GUARD.run(sf.rel, "Rust prefixes", self._prefixes, sf)
        for sf in self.files:
            GUARD.run(sf.rel, "Rust routes", self._routes, sf)
        for sf in self.files:
            GUARD.run(sf.rel, "Rust checks", self._checks, sf)
        GUARD.run("<project>", "Rust calls", self.follower.follow, self._follow)
        return self.routes

    def _follow(self, fn: Fn, seed: Set[str], depth: int, via: str) -> None:
        v = fn.sf.cache["rust_views"]
        self.depth, self.via = depth, via
        try:
            self._function(fn.sf, v.code, v.bare, fn.start, fn.body[0], fn.body[1], set(seed))  # type: ignore[attr-defined]
        finally:
            self.depth, self.via = 0, None

    # ------------------------------------------------------------------ index
    def _load(self, sf: SourceFile) -> None:
        v = sf.cache.get("rust_views") or rust_views(sf.text or "")
        sf.cache["rust_views"] = v
        bare = v.bare
        for m in finditer(FN_DECL, bare):
            po = m.end() - 1
            pc = match_close(bare, po)
            if pc < 0:
                continue
            brace = bare.find("{", pc)
            semi = bare.find(";", pc)
            if brace < 0 or (0 <= semi < brace):
                continue
            end = match_close(bare, brace)
            if end > 0:
                self.funcs.setdefault(m.group(1), []).append((sf, m.start(), po, pc, end + 1))
                self.follower.define(m.group(1), Fn(sf, m.start(), v.code[po + 1:pc], (pc, end + 1)))
        for m in finditer(EXTRACTOR_IMPL, bare):
            end = match_close(bare, m.end() - 1)
            body = v.code[m.end():end if end > 0 else m.end() + 4000]
            self.extractors[m.group(1)] = self.extractors.get(m.group(1), "") + body

    def _auth_extractors(self) -> None:
        """Extractor types whose impl rejects with 401/403, names an auth type, or builds on one that does
        (`OrgContext` from `AuthContext::from_request_parts`)."""
        known = {t for t, body in self.extractors.items() if REJECTS.search(body) or AUTH_TYPE.search(t)}
        for _ in range(3):
            more = {t for t, body in self.extractors.items() if t not in known and any(
                re.search(r"\b" + re.escape(k) + r"\b", body) for k in known)}
            if not more:
                break
            known |= more
        self.auth_extractors = known

    def _helper_auth(self, sf: SourceFile, body: str) -> str:
        """A function of the same file that the handler calls first checks the caller (SCIM's `change()` calls
        `authenticate()` on the bearer token): one call deep, like the Python and JavaScript helpers. Returns that
        helper's code (empty if none), so the route checks also see its scoping (`WHERE tenant_id = $1`)."""
        for name in list(dict.fromkeys(re.findall(r"(?<![.:\w])([a-z_]\w*)\s*\(", body)))[:20]:
            for f, a, _po, pc, b in self.funcs.get(name, []):
                if f is sf and H.AUTH_EVIDENCE.search(f.cache["rust_views"].code[pc:b]):  # type: ignore[attr-defined]
                    return f.cache["rust_views"].code[a:b]  # type: ignore[attr-defined]
        return ""

    def _fn(self, name: str, sf: SourceFile) -> Optional[Tuple[SourceFile, int, int, int, int]]:
        found = self.funcs.get(name.rsplit("::", 1)[-1], [])
        same = [f for f in found if f[0] is sf]
        return (same or found or [None])[0]  # type: ignore[return-value]

    # ------------------------------------------------------------------ prefixes
    def _prefixes(self, sf: SourceFile) -> None:
        """`web::scope("/api").service(handler)` and Axum `.nest("/api", router_fn())`: the prefix each function gets."""
        v = sf.cache["rust_views"]
        code, bare = v.code, v.bare  # type: ignore[attr-defined]
        for rx in (SCOPE, NEST):
            for m in finditer(rx, bare):
                q = m.end() - 1
                end = code.find('"', q + 1)
                prefix = code[q + 1:end]
                if rx is SCOPE:
                    open_p = bare.rfind("(", m.start(), q)
                    outer = self._call_extent(bare, m.start())
                    span = code[m.end():outer]
                    for s in re.finditer(r"\.\s*service\s*\(\s*([A-Za-z_][\w:]*)\s*\)", span):
                        self.fn_prefix.setdefault(s.group(1).rsplit("::", 1)[-1], prefix)
                    _ = open_p
                else:
                    close = match_close(bare, bare.rfind("(", m.start(), q))
                    arg = code[end + 1:close].lstrip(" ,\n\t")
                    call = re.match(r"([A-Za-z_][\w:]*)\s*\(", arg)
                    if call:
                        self.fn_prefix.setdefault(call.group(1).rsplit("::", 1)[-1], prefix)

    @staticmethod
    def _call_extent(bare: str, start: int) -> int:
        """End of the method chain that starts at `start` (the end of the statement or of the enclosing call)."""
        depth, i = 0, start
        while i < len(bare):
            ch = bare[i]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    return i
                depth -= 1
            elif ch == ";" and depth == 0:
                return i
            i += 1
        return len(bare)

    # ------------------------------------------------------------------ routes
    def _routes(self, sf: SourceFile) -> None:
        v = sf.cache["rust_views"]
        code, bare = v.code, v.bare  # type: ignore[attr-defined]
        if not re.search(r"\bactix_web\b|\baxum\b|#\[\s*(?:get|post|put|patch|delete)\s*\(", code):
            return
        actix = "actix_web" in code or "actix-web" in code
        # Actix attribute macros on handler functions
        for m in finditer(ACTIX_ATTR, bare):
            q = m.end() - 1
            end = code.find('"', q + 1)
            path = code[q + 1:end]
            close = match_close(bare, bare.find("(", m.start()))
            attr = code[m.start():close]
            verbs = [m.group(1).upper()] if m.group(1) != "route" else re.findall(r"method\s*=\s*\"(\w+)\"", attr) or ["ALL"]
            fm = FN_DECL.search(bare, close)
            if not fm:
                continue
            fn = self._fn(fm.group(1), sf)
            if fn is None or fn[0] is not sf:
                continue
            prefix = self.fn_prefix.get(fm.group(1), "")
            self._route(sf, m.start(), _join(prefix, path), verbs, fn, "actix", code[m.start():fm.start()])
        # builder routes: Actix `.route("/p", web::get().to(h))`, `web::resource("/p").route(...)`, Axum `.route("/p", get(h).post(h2))`
        enclosing = self._enclosing
        for rx in (BUILDER_ROUTE, RESOURCE):
            for m in finditer(rx, bare):
                q = m.end() - 1
                end = code.find('"', q + 1)
                path = code[q + 1:end]
                if rx is RESOURCE:
                    stop = self._call_extent(bare, m.end())
                    calls = code[end:stop]
                else:
                    close = match_close(bare, bare.rfind("(", m.start(), q))
                    calls = code[end + 1:close]
                    if rx is BUILDER_ROUTE and RESOURCE.search(bare, max(0, m.start() - 200), m.start()):
                        continue  # part of a web::resource chain, handled above
                owner = enclosing(sf, m.start())
                prefix = self.fn_prefix.get(owner, "") if owner else ""
                for scope in finditer(SCOPE, bare[:m.start()]):
                    if self._call_extent(bare, scope.start()) > m.start():
                        se = code.find('"', scope.end())
                        prefix = _join(prefix, code[scope.end():se])
                chain_end = self._call_extent(bare, m.start())
                chain = code[m.start():chain_end]
                layered = any(AUTH_MW.search(x.group(1)) for x in AUTH_LAYER.finditer(chain))
                scoped_auth = self._wrapped(bare, code, m.start())
                for mm in METHOD_CALL.finditer(calls):
                    fn = self._fn(mm.group(2), sf)
                    if fn is None:
                        continue
                    # Actix: `web::get().to(h)`; Axum: `get(h)` (a file may use both crates)
                    framework = "actix" if (re.search(r"\.\s*to\s*\(|\bweb\s*::", calls) or (actix and rx is RESOURCE)) else "axum"
                    self._route(sf, m.start(), _join(prefix, path), [mm.group(1).upper() if mm.group(1) != "any" else "ALL"], fn,
                                framework, "", layered or scoped_auth)

    def _wrapped(self, bare: str, code: str, at: int) -> bool:
        """An Actix scope or App that `.wrap(...)`s auth middleware around the chain containing `at`."""
        for scope in finditer(SCOPE, bare[:at]):
            stop = self._call_extent(bare, scope.start())
            if stop > at and any(AUTH_MW.search(x.group(1)) for x in AUTH_LAYER.finditer(code[scope.start():stop])):
                return True
        return False

    def _enclosing(self, sf: SourceFile, at: int) -> Optional[str]:
        best = None
        for name, lst in self.funcs.items():
            for f, a, _po, _pc, b in lst:
                if f is sf and a <= at < b and (best is None or a > best[1]):
                    best = (name, a)
        return best[0] if best else None

    def _route(self, sf: SourceFile, off: int, path: str, verbs: List[str], fn, framework: str, attrs: str,
               layered: bool = False) -> None:
        fsf, a, po, pc, b = fn
        code = fsf.cache["rust_views"].code  # type: ignore[attr-defined]
        params = code[po + 1:pc]
        body = attrs + code[a:b]
        types = re.sub(r"\b\w+\s*:", " ", params)
        # attributes on the handler, such as `#[actix_web_grants::protect(...)]` (names only: a path may say "auth")
        above = FN_ATTRS.search(code, max(0, a - 600), a)
        guards = " ".join(re.findall(r"#\[\s*([\w:]+)", attrs + (above.group(0) if above else "")))
        helper = self._helper_auth(fsf, code[pc:b])
        body += "\n" + helper if helper else ""
        custom = bool(self.auth_extractors & set(re.findall(r"\b[A-Z]\w*", types))) or bool(helper)
        has_auth = (layered or custom or bool(AUTH_TYPE.search(types)) or bool(AUTH_MW.search(guards))
                    or bool(H.AUTH_EVIDENCE.search(code[pc:b])) or H.CUSTOM.is_auth(body))
        self.handlers.add((fsf.rel, a))
        self.routes.append(Route(sf.rel, sf.line_at(off), path, verbs, body, framework, "rust", has_auth=has_auth,
                                 calls_llm=bool(LLM_CALL.search(body) or H.LLM_HOSTS.search(body)),
                                 reads_body=bool(re.search(r"\b(?:Json|Form|Multipart|Bytes)\b", params)),
                                 params=re.findall(r"[{:](\w+)\}?", path)))

    # ------------------------------------------------------------------ data flow
    def _checks(self, sf: SourceFile) -> None:
        v = sf.cache["rust_views"]
        code, bare = v.code, v.bare  # type: ignore[attr-defined]
        for name, lst in self.funcs.items():
            for f, a, po, pc, b in lst:
                if f is not sf:
                    continue
                GUARD.tick()
                tainted = _extracted(code[po + 1:pc]) if (sf.rel, a) in self.handlers else set()
                self._function(sf, code, bare, a, pc, b, tainted)

    def _function(self, sf: SourceFile, code: str, bare: str, a: int, pc: int, b: int, tainted: Set[str]) -> None:
        body_c, body_b = code[pc:b], bare[pc:b]
        assigned: Dict[str, str] = {}
        for m in finditer(LET, body_b):
            end = body_b.find(";", m.end())
            rhs = body_c[m.end():end if end > 0 else len(body_c)]
            names = [n for n in re.findall(r"\b([a-z_]\w*)\b", m.group(1)) if n not in ("mut", "ref")]
            for n in names:
                assigned.setdefault(n, rhs)
        # `let sql = if above { "... <" } else { "... >" };` is one of two constants, whatever `above` is
        assigned = {n: rhs for n, rhs in assigned.items() if not CONST_IF.match(rhs)}
        # a name checked for path separators with an early return cannot climb out of its folder
        guarded = {g.group(1) for g in finditer(PATH_GUARD, body_c)}
        path_tainted = _spread(tainted - guarded, assigned)
        tainted = _spread(tainted, assigned)
        for rx, rule, what, sev in SINKS:
            for m in finditer(rx, body_b):
                close = match_close(body_b, m.end() - 1)
                if close < 0:
                    continue
                if rule == "BE001" and m.group(0).lstrip().startswith(".") and SQLX_CHAIN.search(
                        body_b, max(body_b.rfind(";", 0, m.start()), body_b.rfind("{", 0, m.start()), 0), m.start()):
                    continue  # sqlx `query(...).bind(x).execute(&pool)`: the argument is the executor, not SQL
                argv = _split_top(body_c[m.end():close])
                if rule == "BE001" and m.group(0).lstrip().startswith(".") and argv \
                        and re.match(r"\s*(?:sqlx\s*::\s*)?query(?:_as|_scalar)?(?:_unchecked)?!", assigned.get(argv[0].strip().lstrip("&"), "")):
                    continue  # `tx.execute(query)` with `let query = sqlx::query!(...)`: a checked query with bound values
                pick = argv[:1] if rule != "BE008" or "Location" not in body_c[m.start():close] else argv
                if rule == "BE002":
                    pick = argv[:1]
                names = path_tainted if rule in ("BE006", "BE008") else tainted
                hit = next((x for x in pick if _mentions(x, names) or _direct_source(x)), None)
                if hit is not None and not (rule == "BE005" and _fixed_host(hit, assigned)):
                    self.add(sf, pc + m.start(), rule, f"Request data flows into {what}.", sev)
                elif rule == "BE001" and pick and _formatted(pick[0], assigned):
                    self.add(sf, pc + m.start(), "BE001", "SQL query built with format!; use bind parameters even for "
                                                          "values you think are safe.", "medium")
        for m in finditer(SHELL_ARG, body_c):  # the literals are only in `code`: Command::new("sh").arg("-c").arg(x)
            close = match_close(body_b, m.end() - 1)
            arg = body_c[m.end():close] if close > 0 else ""
            if _mentions(arg, tainted) or _direct_source(arg):
                self.add(sf, pc + m.start(), "BE002", "Request data flows into a shell command.", "critical")
            elif arg.strip() and not re.fullmatch(r'\s*&?\s*"(?:\\.|[^"\\])*"\s*', arg):
                # sh -c with a variable command: no request data traced, but one step from command injection
                self.add(sf, pc + m.start(), "BE002", "A shell runs a command built from a variable; if any part comes "
                                                      "from users or a model this is command injection.", "medium")
        if tainted:
            self.follower.note(sf, body_c, body_b, pc, lambda x: _mentions(x, tainted) or _direct_source(x), self.depth, self.via)


LET = re.compile(r"\blet\s+(?:mut\s+)?([^=;:]{1,120}?)\s*(?::[^=;]{1,120})?=(?!=)")
SINKS = [
    (re.compile(r"\b(?:sqlx\s*::\s*)?(?:query|query_as|query_scalar)\s*(?:::\s*<[^>\n]{0,120}>\s*)?\(|\bsql_query\s*\(|\.\s*(?:execute|prepare|query_row|query_map)\s*\("),
     "BE001", "a SQL query", "high"),
    (re.compile(r"\bCommand\s*::\s*new\s*\("), "BE002", "a command", "critical"),
    (re.compile(r"\breqwest\s*::\s*get\s*\(|\b\w*client\w*\s*\.\s*(?:get|post|put|patch|delete|head)\s*\("), "BE005",
     "an outbound HTTP request URL", "high"),
    (re.compile(r"\b(?:std\s*::\s*|tokio\s*::\s*)?fs\s*::\s*(?:read|read_to_string|read_dir|write|remove_file|remove_dir_all|create_dir_all|copy|rename)\s*\("
                r"|\bFile\s*::\s*(?:open|create)\s*\(|\bNamedFile\s*::\s*open(?:_async)?\s*\("),
     "BE006", "a file system path", "high"),
    (re.compile(r"\bRedirect\s*::\s*(?:to|temporary|permanent|see_other)\s*\(|\.\s*(?:append_header|insert_header)\s*\("),
     "BE008", "a redirect target", "medium"),
]
CONST_IF = re.compile(r'\s*if\b[^{;]{0,200}\{\s*(?:r#*)?"[^"]{0,2000}"#*\s*\}\s*else\s*\{\s*(?:r#*)?"[^"]{0,2000}"#*\s*\}\s*$')
SQLX_CHAIN = re.compile(r"\b(?:query|query_as|query_scalar|sql_query)\s*(?:::\s*<[^>\n]{0,120}>\s*)?\(")
SHELL_ARG = re.compile(r"\"(?:sh|bash|/bin/sh|/bin/bash|cmd|powershell)\"\s*\)\s*\.\s*args?\s*\(\s*(?:\[\s*)?\"(?:-c|/C|-Command)\"\s*[,)]\s*(?:\.\s*arg\s*\()?")
SOURCE = re.compile(r"\b(?:req|request)\s*\.\s*(?:match_info|query_string|uri|headers)\s*\(")


PATH_GUARD = re.compile(r"\bif\s+(\w+)\s*\.\s*contains\s*\(\s*(?:'/'|\"/\"|\"\.\.\")\s*\)[^{;]{0,200}\{[^{}]{0,200}\breturn\b")


def _spread(seed: Set[str], assigned: Dict[str, str]) -> Set[str]:
    """`seed` plus every `let` name whose value mentions a name already in the set."""
    out = set(seed)
    for _ in range(4):
        grew = False
        for n, rhs in assigned.items():
            if n not in out and _mentions(rhs, out):
                out.add(n)
                grew = True
        if not grew:
            break
    return out


def _extracted(params: str) -> Set[str]:
    """Names bound by request extractors: `Json(body): Json<T>`, `body: web::Json<T>`, `Path(id): Path<String>`."""
    out: Set[str] = set()
    for part in _split_top(params):
        pat, _, ty = part.partition(":")
        ty = ty.strip()
        m = EXTRACTOR.search(ty)
        if not m:
            continue
        inner = re.search(r"<(.*)>", ty)
        if m.group(1) == "Path" and inner and SAFE_PATH_TYPE.fullmatch(re.sub(r"\s+", "", inner.group(1))):
            continue  # numbers and UUIDs cannot carry an injection
        out.update(n for n in re.findall(r"\b([a-z_]\w*)\b", pat) if n not in ("mut", "ref"))
    return out


def _mentions(text: str, names: Set[str]) -> bool:
    if not names:
        return False
    bare = rust_views(text).bare
    return any(re.search(r"(?<![\w.])%s\b" % re.escape(n), bare) for n in names)


def _direct_source(text: str) -> bool:
    return bool(SOURCE.search(rust_views(text).bare))


def _formatted(arg: str, assigned: Dict[str, str]) -> bool:
    """The SQL is built with format! (directly or in a `let` the argument names), with something formatted in."""
    a = arg.strip().lstrip("&*").strip()
    text = assigned.get(a, a) if re.fullmatch(r"[a-z_]\w*", a) else a
    m = re.search(r"\bformat!\s*\(\s*\"((?:\\.|[^\"\\])*)\"\s*,", text)
    if not m or not re.search(r"(?i)\b(?:select|insert|update|delete)\b", m.group(1)):
        return False
    end = text.find(")", m.end())
    args = [x.strip() for x in text[m.end():end if end > 0 else len(text)].split(",") if x.strip()]
    # only constants formatted in (`RETURNING {}`, `source::CONNECTION`): a fixed column list, not data
    return not (args and all(re.fullmatch(r"(?:\w+::)*[A-Z][A-Z0-9_]*", x) for x in args))


def _fixed_host(arg: str, assigned: Dict[str, str]) -> bool:
    a = arg.strip().lstrip("&*").strip()
    text = assigned.get(a, a) if re.fullmatch(r"[a-z_]\w*", a) else a
    return bool(re.match(r"\s*&?\s*format!\s*\(\s*\"https?://[^/{\"]+/", text))


def _join(prefix: str, path: str) -> str:
    if not prefix:
        return path or "/"
    if not path or path == "/":
        return prefix.rstrip("/") or "/"
    return prefix.rstrip("/") + "/" + path.lstrip("/")
