"""Go support (Phase 5, 0.10.0): a linear lexer, route discovery for net/http, Gin, Echo, Fiber and Chi, a
per-function data flow from request data, and the Go checks.

Generic rules reported for Go: BE001 (SQL injection), BE002 (command injection), BE005 (SSRF), BE006 (path
traversal), BE008 (open redirect). Go rules: GO001 (goroutine that never stops), GO002 (response body never
closed), GO003 (map written concurrently without a lock), GO004 (SQL built with string formatting).
Routes feed the shared route checks (AUTH001-AUTH003, AUTH010, LLM004).
"""
from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Set, Tuple

from .files import Project, SourceFile
from .guard import GUARD, finditer
from .lexer import Views, _blank, match_close
from .model import Finding, Route

Emit = Callable[[Finding], None]


def go_views(src: str) -> Views:
    """Linear scan for Go comments and string literals: `code` has comments blanked, `bare` also has the
    contents of strings and runes blanked (quotes kept). Unterminated literals end at the line (or the file
    for raw strings), so broken code still gets usable views."""
    n = len(src)
    code, bare = list(src), list(src)
    comments: List[Tuple[int, int]] = []
    i = 0
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            _blank(code, i, j)
            _blank(bare, i, j)
            comments.append((i, j))
            i = j
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            _blank(code, i, j)
            _blank(bare, i, j)
            comments.append((i, j))
            i = j
        elif c == "`":
            j = src.find("`", i + 1)
            j = n if j < 0 else j
            _blank(bare, i + 1, j)
            i = j + 1
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            j = min(j, n)
            _blank(bare, i + 1, j)
            i = j + 1
        else:
            i += 1
    return Views("".join(code), "".join(bare), comments)


# ------------------------------------------------------------------ functions
FUNC_DECL = re.compile(r"(?m)^func[ \t]*(?:\([^()\n]{0,200}\)[ \t]*)?(\w+)[ \t]*(?:\[[^\]\n]{0,200}\])?[ \t]*\(")


def _func_spans(v: Views) -> Dict[str, List[Tuple[int, int]]]:
    """Function name -> (start, end of body) for every top-level function and method in the file."""
    out: Dict[str, List[Tuple[int, int]]] = {}
    for m in finditer(FUNC_DECL, v.bare):
        brace = _body_brace(v.bare, m.end() - 1)
        if brace < 0:
            continue
        end = match_close(v.bare, brace)
        if end > 0:
            out.setdefault(m.group(1), []).append((m.start(), end + 1))
    return out


def _body_brace(bare: str, open_paren: int) -> int:
    """The `{` that opens a function body: on the signature's line, after the parameters and results."""
    close = match_close(bare, open_paren)
    if close < 0:
        return -1
    nl = bare.find("\n", close)
    seg_end = nl if nl >= 0 else len(bare)
    j = bare.rfind("{", close, seg_end)
    return j if j >= 0 and bare[j + 1:seg_end].strip() == "" else -1


def _enclosing_func(spans: Dict[str, List[Tuple[int, int]]], off: int) -> Tuple[int, int]:
    best = (0, 0)
    for lst in spans.values():
        for a, b in lst:
            if a <= off < b and (best == (0, 0) or a > best[0]):
                best = (a, b)
    return best


# ------------------------------------------------------------------ routes
ROUTE_CALL = re.compile(
    r"\b(\w+)\s*\.\s*(GET|POST|PUT|PATCH|DELETE|Any|Get|Post|Put|Patch|Delete|All|HandleFunc|Handle|Match|Add)\s*\(")
GROUP_ASSIGN = re.compile(r"\b(\w+)\s*:?=\s*(\w+)\s*\.\s*(?:Group|Route|Party)\s*\(")
MOUNT_CALL = re.compile(r"\b(\w+)\s*\.\s*Mount\s*\(")
PREPARE_ASSIGN = re.compile(r"(?m)^[ \t]*(\w+)(?:[ \t]*,[ \t]*\w+)?[ \t]*:?=[ \t]*[^\n]{0,140}\.\s*(?:Prepare|PrepareContext|Preparex|PrepareNamed)\s*\(")
METHOD_PATTERN = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+")
AUTH_NAME = re.compile(
    # a name containing one of these words; no unbounded \w* runs (they are quadratic on long identifiers)
    r"(?i)auth|jwt|session|login|protect|require|guard|permission|casbin|verify\w{0,20}token|apikey|keyauth"
    r"|token\w{0,20}middleware|middleware\s*\.\s*\w{0,30}(?:user)")
AUTH_IN_BODY = re.compile(
    r"(?i)c\s*\.\s*(?:Get|MustGet|Locals)\s*\(\s*\"(?:user\w*|claims|uid|currentUser|userID|user_id)\"|"
    r"r\s*\.\s*Context\s*\(\s*\)\s*\.\s*Value\s*\([^)]{0,60}(?:user|claims|auth)|\bcurrentUser\b|getUser\w*\s*\(|"
    r"\bclaims\b|ParseWithClaims|jwt\s*\.\s*Parse|session\s*\.\s*(?:Get|Values)|\bIsAuthenticated\b")
STRING_ARG = re.compile(r"[ \t\n]{0,40}\"([^\"\n]{0,300})\"")


class GoScanner:
    def __init__(self, project: Project, emit: Emit):
        self.p = project
        self.emit = emit
        self.files: List[SourceFile] = []
        self.funcs: Dict[str, List[Tuple[SourceFile, int, int]]] = {}
        self.mounted: Dict[str, List[Tuple[str, bool, str]]] = {}  # sub-router fn -> [(prefix, auth, mw_text)]
        self.routes: List[Route] = []
        self.injection_lines: Set[Tuple[str, int]] = set()  # lines with BE001
        self.formatted: List[Finding] = []  # GO004, held back until every BE001 is known
        from .calls import Follower, go_params

        self.follower = Follower(go_params)  # cross-function taint
        self.depth, self.via = 0, None  # while a followed call is checked: how deep, and the call it came through

    def add(self, sf: SourceFile, off: int, rule: str, msg: str, sev: str = "") -> None:
        line = sf.line_at(off)
        if self.via is not None:
            if not msg.startswith("Request data"):
                return  # a followed call only adds what the request data reaches; the rest is reported once already
            from .calls import via_note

            msg += via_note(self.via)
        f = Finding(rule, sf.rel, line, msg, sev, sf.line(line).strip())
        if rule == "GO004":
            self.formatted.append(f)
            return
        if rule == "BE001":
            self.injection_lines.add((sf.rel, line))
        self.emit(f)

    def run(self) -> List[Route]:
        self.files = [f for f in self.p.files if f.kind == "go" and f.text is not None]
        if not self.files:
            return []
        for sf in self.files:
            GUARD.run(sf.rel, "Go lexing", self._load, sf)
        for sf in self.files:
            if not sf.is_test:
                GUARD.run(sf.rel, "Go mounts", self._mounts, sf)
        for sf in self.files:
            if not sf.is_test:
                GUARD.run(sf.rel, "Go routes", self._routes, sf)
        for sf in self.files:
            if not sf.is_test and not sf.is_example:
                GUARD.run(sf.rel, "Go checks", self._checks, sf)
        GUARD.run("<project>", "Go calls", self.follower.follow, self._follow)
        # GO004 is for formatted SQL with no traced request data; where BE001 reports the line, it says more
        for f in self.formatted:
            if (f.file, f.line) not in self.injection_lines:
                self.emit(f)
        self.formatted = []
        return self.routes

    def _load(self, sf: SourceFile) -> None:
        v = sf.cache.get("go_views") or go_views(sf.text or "")
        sf.cache["views"] = sf.cache["go_views"] = v
        spans = _func_spans(v)
        sf.cache["go_funcs"] = spans
        from .calls import Fn

        for name, lst in spans.items():
            for a, b in lst:
                self.funcs.setdefault(name, []).append((sf, a, b))
                m = FUNC_DECL.match(v.bare, a)
                close = match_close(v.bare, m.end() - 1) if m else -1
                if close > 0 and not sf.is_test:
                    self.follower.define(name, Fn(sf, a, v.code[m.end():close], (a, b)))

    # -------------------------------------------------------------- routes
    def _mounts(self, sf: SourceFile) -> None:
        """Record `r.Mount("/prefix", subRouter())` calls so routes inside `subRouter` inherit prefix, auth and role middleware."""
        v: Views = sf.cache["views"]  # type: ignore[assignment]
        code, bare = v.code, v.bare
        parents = self._parents(sf)
        for m in finditer(MOUNT_CALL, bare):
            close = match_close(bare, m.end() - 1)
            if close < 0:
                continue
            argv = _split_top(code[m.end():close])
            if len(argv) < 2:
                continue
            p = STRING_ARG.match(argv[0])
            if not p:
                continue
            sub = re.search(r"(\w+)\s*\([^()]*\)\s*$", argv[1].strip())
            if not sub:
                continue
            prefix, auth, mw_text = self._prefix_and_auth_mw(m.group(1), parents, code, bare, m.start())
            full = "/" + "/".join(x.strip("/") for x in (prefix, p.group(1)) if x.strip("/"))
            self.mounted.setdefault(sub.group(1), []).append((full, auth, mw_text))

    def _parents(self, sf: SourceFile) -> Dict[str, Tuple[str, str, bool]]:
        """Group var -> (parent var, prefix, the group call names auth middleware), per file."""
        cached = sf.cache.get("go_parents")
        if cached is not None:
            return cached  # type: ignore[return-value]
        v: Views = sf.cache["views"]  # type: ignore[assignment]
        parents: Dict[str, Tuple[str, str, bool]] = {}
        for m in finditer(GROUP_ASSIGN, v.bare):
            close = match_close(v.bare, m.end() - 1)
            args = v.code[m.end():close] if close > 0 else ""
            p = STRING_ARG.match(args)
            parents[m.group(1)] = (m.group(2), p.group(1) if p else "", bool(AUTH_NAME.search(args.split(",", 1)[-1]) if "," in args else False))
        sf.cache["go_parents"] = parents
        return parents

    def _param_router(self, sf: SourceFile, root: str, off: int) -> Optional[Tuple[str, int]]:
        """(function name, parameter index) when `root` is a parameter of the function around `off` and the
        router is not created in it: its routes get their auth and prefix from the callers."""
        v: Views = sf.cache["views"]  # type: ignore[assignment]
        spans: Dict[str, List[Tuple[int, int]]] = sf.cache["go_funcs"]  # type: ignore[assignment]
        best: Optional[Tuple[str, int, int]] = None
        for name, lst in spans.items():
            for a, b in lst:
                if a <= off < b and (best is None or a > best[1]):
                    best = (name, a, b)
        if best is None:
            return None
        name, a, b = best
        if re.search(r"\b%s\s*:?=\s*(?:gin|chi|echo|fiber|mux|http|httprouter)\s*\.\s*(?:Default|New\w*)\s*\(" % re.escape(root), v.bare[a:b]):
            return None
        m = FUNC_DECL.match(v.bare, a)
        if not m:
            return None
        close = match_close(v.bare, m.end() - 1)
        params = [re.match(r"\s*(\w+)", x).group(1) for x in _split_top(v.bare[m.end():close]) if re.match(r"\s*\w+", x)]  # type: ignore[union-attr]
        return (name, params.index(root)) if root in params else None

    def _callers(self, fname: str, idx: int, depth: int = 0) -> List[Tuple[bool, str]]:
        """(auth, prefix) of the router passed as argument `idx` at each call of `fname`."""
        out: List[Tuple[bool, str]] = []
        if depth > 3:
            return out
        call = re.compile(r"(?<![\w.])(?:\w+\s*\.\s*)?%s\s*\(" % re.escape(fname))
        for sf in self.files:
            if sf.is_test:
                continue
            v: Views = sf.cache["views"]  # type: ignore[assignment]
            for m in finditer(call, v.bare):
                if re.search(r"func\s*(?:\([^()]*\)\s*)?$", v.bare[max(0, m.start() - 60):m.start()]):
                    continue  # the definition
                close = match_close(v.bare, m.end() - 1)
                argv = _split_top(v.code[m.end():close]) if close > 0 else []
                if idx >= len(argv):
                    continue
                expr = argv[idx].strip()
                base = re.match(r"(\w+)", expr)
                if not base:
                    continue
                pre = STRING_ARG.match(expr[expr.find("(") + 1:]) if ".Group(" in expr.replace(" ", "") else None
                expr_auth = bool(AUTH_NAME.search(expr.split(",", 1)[-1])) if "," in expr else False
                prefix, auth = self._prefix_and_auth(base.group(1), self._parents(sf), v.code, v.bare, m.start())
                up = self._param_router(sf, base.group(1), m.start())
                if up is not None and not auth:
                    higher = self._callers(up[0], up[1], depth + 1)
                    if higher:
                        auth = any(a for a, _ in higher)
                        prefix = higher[0][1].rstrip("/") + "/" + prefix.lstrip("/") if prefix else higher[0][1]
                    else:
                        auth = True  # unknown: do not guess that it is public
                full = "/".join(x.strip("/") for x in (prefix, pre.group(1) if pre else "") if x.strip("/"))
                out.append((auth or expr_auth, "/" + full if full else ""))
        return out

    def _routes(self, sf: SourceFile) -> None:
        v: Views = sf.cache["views"]  # type: ignore[assignment]
        code, bare = v.code, v.bare
        parents = self._parents(sf)
        for m in finditer(ROUTE_CALL, bare):
            recv, verb = m.group(1), m.group(2)
            close = match_close(bare, m.end() - 1)
            if close < 0:
                continue
            args = code[m.end():close]
            p = STRING_ARG.match(args)
            if not p:
                continue
            path = p.group(1)
            if verb in ("HandleFunc", "Handle", "Match", "Add"):
                mm = METHOD_PATTERN.match(path)
                if verb in ("Match", "Add"):
                    continue  # rare forms whose method list comes first
                methods = [mm.group(1)] if mm else ["ALL"]
                path = path[mm.end():] if mm else path
                if not path.startswith("/"):
                    continue
                framework = "net/http"
            else:
                methods = ["ALL"] if verb in ("Any", "All") else [verb.upper()]
                framework = "go"
                if not path.startswith("/") and path != "":
                    continue
            rest = args[p.end():]
            handler_args = [a.strip() for a in _split_top(rest) if a.strip()]
            prefix, auth, mw_text = self._prefix_and_auth_mw(recv, parents, code, bare, m.start())
            root = recv
            while root in parents and parents[root][0] != root:
                root = parents[root][0]
            # if this function builds a sub-router mounted via `r.Mount("/prefix", fn())`, inherit mount context
            enc_name = self._enclosing_func_name(sf, m.start())
            if enc_name and enc_name in self.mounted:
                mounts = self.mounted[enc_name]
                # authed only when every mount point is: one public `r.Mount` exposes the whole sub-router
                open_mounts = [mt for mt in mounts if not mt[1]]
                if not open_mounts:
                    auth = True
                mounts = open_mounts or mounts  # judge by the exposed mounts only (their prefix and middleware)
                outer = mounts[0][0]
                prefix = outer.rstrip("/") + "/" + prefix.lstrip("/") if prefix else outer
                mw_text = "\n".join(x for x in (mw_text, *(mw for _, _, mw in mounts if mw)) if x)
            up = self._param_router(sf, root, m.start()) if not auth else None
            if up is not None:  # the router comes from the caller: take its auth and prefix from there
                callers = self._callers(up[0], up[1])
                if callers:
                    auth = any(a for a, _ in callers)
                    outer = callers[0][1]
                    prefix = outer.rstrip("/") + "/" + prefix.lstrip("/") if prefix else outer
                else:
                    auth = True  # no caller found: unknown, so not reported as public
            if any(AUTH_NAME.search(a) for a in handler_args[:-1]):
                auth = True
            body, line_off = self._handler_body(sf, code, handler_args[-1] if handler_args else "", m.start())
            if AUTH_IN_BODY.search(body):
                auth = True
            full = ("/" + "/".join(s.strip("/") for s in (prefix, path) if s.strip("/"))) or "/"
            params = re.findall(r"[:{*](\w+)", full)
            route_body = "\n".join(x for x in (mw_text, code[m.start():close + 1], body) if x)
            self.routes.append(Route(
                sf.rel, sf.line_at(m.start()), full, methods, route_body, framework, "go",
                has_auth=auth, calls_llm=bool(re.search(r"(?i)openai|anthropic|genai|langchaingo|ollama|\bllm\b", body)),
                reads_body=bool(re.search(r"\b(?:ShouldBind\w*|Bind\w*|BodyParser|Decode)\s*\(", body)), params=params))

    def _enclosing_func_name(self, sf: SourceFile, off: int) -> Optional[str]:
        spans: Dict[str, List[Tuple[int, int]]] = sf.cache["go_funcs"]  # type: ignore[assignment]
        best: Optional[Tuple[str, int]] = None
        for name, lst in spans.items():
            for a, b in lst:
                if a <= off < b and (best is None or a > best[1]):
                    best = (name, a)
        return best[0] if best else None

    def _prefix_and_auth(self, recv: str, parents: Dict[str, Tuple[str, str, bool]], code: str, bare: str, off: int) -> Tuple[str, bool]:
        prefix, auth, _mw = self._prefix_and_auth_mw(recv, parents, code, bare, off)
        return prefix, auth

    def _prefix_and_auth_mw(self, recv: str, parents: Dict[str, Tuple[str, str, bool]], code: str, bare: str, off: int) -> Tuple[str, bool, str]:
        prefix, auth, seen, cur = "", False, set(), recv
        chain = [recv]
        mw_parts: List[str] = []
        while cur in parents and cur not in seen:
            seen.add(cur)
            parent, p, a = parents[cur]
            prefix = p.rstrip("/") + "/" + prefix.lstrip("/") if prefix else p
            auth = auth or a
            cur = parent
            chain.append(cur)
        # `x.Use(Auth...)` / `x.With(Auth...)` on the router or one of its parent groups, before the route
        names = "|".join(re.escape(c) for c in chain)
        # a `Use` inside a router closure that does not hold this route belongs to other routes (chi shadows `r`)
        others = [(s, e) for s, e, _ in _closure_blocks(code, bare, len(bare)) if not s < off < e]
        for u in finditer(re.compile(r"\b(?:%s)\s*\.\s*(?:Use|With)\s*\(" % names), bare[:off]):
            if any(s < u.start() < e for s, e in others):
                continue
            close = match_close(bare, u.end() - 1)
            if close > 0:
                seg = code[u.end():close]
                mw_parts.append(seg)
                if AUTH_NAME.search(bare[u.end():close]):
                    auth = True
        # chi: routes inside `r.Group(func(r chi.Router) { r.Use(Auth) ... })` or `r.Route("/p", func(r chi.Router) {`
        for start, end, pre in _closure_blocks(code, bare, off):
            if pre:
                prefix = pre.rstrip("/") + "/" + prefix.lstrip("/") if prefix else pre
            block = bare[start:off]
            for u in finditer(re.compile(r"\.\s*(?:Use|With)\s*\("), block):
                close = match_close(bare, start + u.end() - 1)
                if close > 0:
                    seg = code[start + u.end():close]
                    mw_parts.append(seg)
                    if AUTH_NAME.search(bare[start + u.end():close]):
                        auth = True
        return prefix, auth, "\n".join(mw_parts)

    def _handler_body(self, sf: SourceFile, code: str, handler: str, off: int) -> Tuple[str, int]:
        if handler.startswith("func"):
            v: Views = sf.cache["views"]  # type: ignore[assignment]
            k = code.find(handler[:20], off)
            brace = v.bare.find("{", k) if k >= 0 else -1
            end = match_close(v.bare, brace) if brace >= 0 else -1
            return (code[brace:end + 1], brace) if end > 0 else ("", off)
        m = re.search(r"(\w+)\s*(?:\([^()]*\))?\s*$", handler.strip())
        for other, a, b in self.funcs.get(m.group(1) if m else "", [])[:1]:
            return (other.text or "")[a:b], a
        return "", off

    # -------------------------------------------------------------- checks
    def _checks(self, sf: SourceFile) -> None:
        v: Views = sf.cache["views"]  # type: ignore[assignment]
        spans: Dict[str, List[Tuple[int, int]]] = sf.cache["go_funcs"]  # type: ignore[assignment]
        for name, lst in spans.items():
            for a, b in lst:
                GUARD.tick()
                self._function(sf, v, a, b)
        self._goroutines(sf, v)
        self._shared_maps(sf, v)

    def _follow(self, fn, seed: Set[str], depth: int, via: str) -> None:
        self.depth, self.via = depth, via
        try:
            self._function(fn.sf, fn.sf.cache["views"], fn.body[0], fn.body[1], seed)  # type: ignore[arg-type]
        finally:
            self.depth, self.via = 0, None

    def _function(self, sf: SourceFile, v: Views, a: int, b: int, seed: Set[str] = frozenset()) -> None:  # type: ignore[assignment]
        code, bare = v.code[a:b], v.bare[a:b]
        tainted = _taint(code, bare, seed)
        # prepared statements: `stmt, err := db.Prepare("...")`; `stmt.QueryRow(userId)` passes bound values, not SQL
        prepared = {m.group(1) for m in finditer(PREPARE_ASSIGN, bare)}
        # variables holding SQL text built with Sprintf or +: `q := fmt.Sprintf("... %d", n); db.Exec(q)`
        # name -> [(offset, built?)]: a variable counts as built SQL only if its latest assignment before the sink
        # formats SQL text (`query := "SELECT ... ?"` in a safe branch after a Sprintf branch is not)
        assigned: Dict[str, List[Tuple[int, bool]]] = {}
        for m in finditer(ASSIGN, bare):
            if "," in m.group(1):
                continue
            is_built = bool(re.search(r"(?i)\b(?:select|insert|update|delete)\b", code[m.start(2):m.end(2)])
                            and SQL_BUILT.search(bare[m.start(2):m.end(2)]))
            assigned.setdefault(m.group(1), []).append((m.start(), is_built))

        def built_at(name: str, at: int) -> bool:
            before = [b for off, b in assigned.get(name, []) if off < at]
            return bool(before) and before[-1]
        for rx, rule, what, sev in SINKS:
            for m in finditer(rx, bare):
                close = match_close(bare, m.end() - 1)
                if close < 0:
                    continue
                args = code[m.end():close]
                argv = _split_top(args)
                pick = _sink_args(rule, m.group(0), argv)
                if rule == "BE001" and what == "a SQL query":
                    recv_m = re.search(r"(\w+)\s*$", bare[max(0, m.start() - 60):m.start()])
                    if recv_m and (recv_m.group(1) in prepared or re.search(r"(?i)(?:^|_)stmt$|Stmt$", recv_m.group(1))):
                        continue  # prepared statement: arguments are bound parameters, not SQL text
                if what == "a SQL clause" and pick and re.match(r'\s*"/', pick[0]):
                    continue  # a router's Group("/prefix" + ...), not a GORM clause
                hit = next((x for x in pick if _is_tainted(x, tainted)), None)
                if hit is not None and rule == "BE008" and _api_result(hit, code, bare, m.start(), tainted):
                    continue
                if hit is not None:
                    self.add(sf, a + m.start(), rule, f"Request data flows into {what}.", sev)
                elif rule == "BE002" and len(pick) == 1 and SHELL_C.match(args) and not _constant(pick[0]):
                    # sh -c with a variable command: no request data traced, but one away from command injection
                    self.add(sf, a + m.start(), "BE002", "A shell runs a command built from a variable; if any part comes "
                                                         "from users or a model this is command injection.", "medium")
                elif rule == "BE001" and pick and ((SQL_BUILT.search(_unquoted(pick[0])) and not _constant(pick[0]))
                                                   or built_at(pick[0].strip(), m.start())):
                    self.add(sf, a + m.start(), "GO004", "SQL is built with string formatting; pass values as query parameters.")
        self._response_bodies(sf, v, a, b)
        open_paren = bare.find("(", bare.find(")") + 1 if bare.startswith("func (") or bare.startswith("func(") else 0)
        body = bare.find("{", match_close(bare, open_paren) if open_paren >= 0 else 0)
        if body > 0:  # calls in the body (not the signature), passing request data on
            self.follower.note(sf, code[body:], bare[body:], a + body, lambda x: _is_tainted(x, tainted), self.depth, self.via)

    def _response_bodies(self, sf: SourceFile, v: Views, a: int, b: int) -> None:
        code, bare = v.code[a:b], v.bare[a:b]
        for m in finditer(RESP_ASSIGN, bare):
            name = m.group(1)
            if name == "_":
                continue
            rest = code[m.end():]
            if re.search(r"\b%s\s*\.\s*Body\s*\.\s*Close\s*\(" % re.escape(name), rest) \
                    or re.search(r"\breturn\b[^\n]*\b%s\b" % re.escape(name), rest) \
                    or re.search(r"\w\s*\([^()\n]*\b%s\b(?!\s*\.)" % re.escape(name), rest) \
                    or re.search(r"\b%s\s*\.\s*Body\s*\)" % re.escape(name), rest):
                continue  # closed, returned, or handed to a function that owns it
            self.add(sf, a + m.start(), "GO002", f"The response body of `{name}` is never closed, so the connection is "
                                                 "not reused and leaks under load; add `defer " + name + ".Body.Close()`.")

    def _goroutines(self, sf: SourceFile, v: Views) -> None:
        code, bare = v.code, v.bare
        spans: Dict[str, List[Tuple[int, int]]] = sf.cache["go_funcs"]  # type: ignore[assignment]
        for m in finditer(GO_STMT, bare):
            if m.group(1):  # go func(...) { ... }(...)
                brace = bare.find("{", m.end())
                end = match_close(bare, brace) if brace >= 0 else -1
                body = code[brace:end + 1] if end > 0 else ""
            else:
                name = m.group(2).rsplit(".", 1)[-1]
                found = self.funcs.get(name, [])
                body = ((found[0][0].text or "")[found[0][1]:found[0][2]]) if len(found) == 1 else ""
            if not any(x <= m.start() < y for x, y in self._handler_regions(sf, code)):
                continue  # started once (at startup, by a constructor): a background loop for the process's lifetime
            if body and FOREVER.search(body) and not EXIT.search(body):
                self.add(sf, m.start(), "GO001", "This goroutine loops forever with no way to stop it (no context, done "
                                                 "channel or return), so it leaks on every call and at shutdown.")

    def _handler_regions(self, sf: SourceFile, code: str) -> List[Tuple[int, int]]:
        regions = []
        for r in self.routes:
            if r.file == sf.rel and r.body:
                k = code.find(r.body.split("\n", 1)[-1][:60])
                if k >= 0:
                    regions.append((k, k + len(r.body)))
        return regions

    def _shared_maps(self, sf: SourceFile, v: Views) -> None:
        code, bare = v.code, v.bare
        if LOCKED.search(code):
            return
        maps = {m.group(1) for m in finditer(PKG_MAP, code)}
        if not maps:
            return
        names = "|".join(re.escape(x) for x in sorted(maps))
        write = re.compile(r"\b(%s)\s*\[[^\]\n]{1,120}\]\s*(?:=|\+=|-=|\+\+|--)(?!=)|\bdelete\s*\(\s*(%s)\s*," % (names, names))
        # concurrent writers: HTTP handlers (each request runs in its own goroutine) and goroutine bodies
        regions: List[Tuple[int, int]] = []
        for r in self.routes:
            if r.file == sf.rel:
                k = code.find(r.body.split("\n", 1)[-1][:60]) if r.body else -1
                if k >= 0:
                    regions.append((k, k + len(r.body)))
        for m in finditer(GO_STMT, bare):
            brace = bare.find("{", m.end())
            end = match_close(bare, brace) if brace >= 0 and m.group(1) else -1
            if end > 0:
                regions.append((brace, end))
        reported: Set[str] = set()
        for a, b in regions:
            for w in finditer(write, bare[a:b]):
                name = w.group(1) or w.group(2)
                if name not in reported:
                    reported.add(name)
                    self.add(sf, a + w.start(), "GO003", f"Package-level map `{name}` is written from concurrent requests or "
                                                         "goroutines without a lock; concurrent map writes crash the program.")


def _split_top(args: str) -> List[str]:
    """Top-level arguments; commas and brackets inside string literals (raw `...` SQL included) do not count."""
    out, depth, start, quote, i = [], 0, 0, "", 0
    while i < len(args):
        ch = args[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in '"`':
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(args[start:i])
            start = i + 1
        i += 1
    out.append(args[start:])
    return [x for x in out if x.strip()] if args.strip() else []


def _closure_blocks(code: str, bare: str, off: int) -> List[Tuple[int, int, str]]:
    """`func(r chi.Router) {` blocks that enclose `off` (every one when `off` is the end of the file), outermost
    first, with the prefix of the `Route("/p", ...)` call they are passed to."""
    out = []
    for m in finditer(CHI_CLOSURE, bare):
        if m.start() >= off:
            break
        brace = bare.find("{", m.end() - 1)
        end = match_close(bare, brace) if brace >= 0 else -1
        if end > 0 and (off >= len(bare) or brace < off < end):
            p = re.search(r"\.\s*Route\s*\(\s*\"([^\"\n]*)\"\s*,\s*$", code[max(0, m.start() - 200):m.start()])
            out.append((brace, end, p.group(1) if p else ""))
    return out


# ------------------------------------------------------------------ data flow and sinks
SOURCES = re.compile(
    r"\b(?:r|req|request)\s*\.\s*(?:URL\s*\.\s*Query\s*\(\s*\)\s*\.\s*Get|FormValue|PostFormValue|Form\s*\.\s*Get|PostForm\s*\.\s*Get"
    r"|Header\s*\.\s*Get|URL\s*\.\s*Path|URL\s*\.\s*RawQuery|PathValue|Cookie)\b"
    r"|\bmux\s*\.\s*Vars\s*\(|\bchi\s*\.\s*URLParam\s*\("
    r"|\b(?:c|ctx)\s*\.\s*(?:Param|Params|Query|DefaultQuery|QueryParam|QueryParams|PostForm|DefaultPostForm|FormValue|GetHeader|Cookie)\s*\(")
BINDS = re.compile(
    r"\b(?:c|ctx)\s*\.\s*(?:ShouldBind\w*|Bind\w*|BodyParser|QueryParser)\s*\(\s*&?\s*(\w+)"
    r"|\bjson\s*\.\s*NewDecoder\s*\(\s*(?:r|req|request)\s*\.\s*Body\s*\)\s*\.\s*Decode\s*\(\s*&?\s*(\w+)"
    r"|\bjson\s*\.\s*Unmarshal\s*\([^,\n]{1,80},\s*&\s*(\w+)")
ASSIGN = re.compile(r"(?m)^[ \t]*((?:\w+\s*,\s*)*\w+)\s*:?=\s*([^\n]{1,400})")


def _taint(code: str, bare: str, seed: Set[str] = frozenset()) -> Set[str]:  # type: ignore[assignment]
    tainted: Set[str] = set(seed)
    for m in finditer(BINDS, bare):
        tainted.add(next(g for g in m.groups() if g))
    assigns = [(m.group(1), code[m.start(2):m.end(2)], bare[m.start(2):m.end(2)]) for m in finditer(ASSIGN, bare)]
    for _ in range(4):
        changed = False
        for names, rhs, rhs_bare in assigns:
            if SOURCES.search(rhs_bare) or any(re.search(r"\b%s\b" % re.escape(t), rhs_bare) for t in tainted):
                for n in (x.strip() for x in names.split(",")):
                    if n and n != "_" and n != "err" and n not in tainted:
                        tainted.add(n)
                        changed = True
        if not changed:
            break
    return tainted


def _is_tainted(arg: str, tainted: Set[str]) -> bool:
    bare = go_views(arg).bare
    return bool(SOURCES.search(bare) or any(re.search(r"\b%s\b" % re.escape(t), bare) for t in tainted))


SHELL_C = re.compile(r'\A\s*(?:\w+\s*,\s*)?"(?:sh|bash|/bin/sh|/bin/bash|cmd|powershell)"\s*,\s*"(?:-c|/c|-Command)"\s*,')
STDLIB_PKGS = {"strings", "fmt", "url", "path", "filepath", "strconv", "bytes", "html", "template", "json", "base64",
               "hex", "regexp", "unicode", "utf8", "sort", "slices", "maps", "net", "http", "os", "io", "bufio", "time"}


def _unquoted(arg: str) -> str:
    """The argument with the contents of string literals removed (a `+` inside the SQL text is not concatenation)."""
    return re.sub(r'"(?:\\.|[^"\\\n])*"|`[^`]*`', '""', arg)


def _api_result(arg: str, code: str, bare: str, at: int, tainted: Set[str]) -> bool:
    """`c.Redirect(302, invoice.PDFURL)` where `invoice, err := h.svc.GetInvoice(ctx, id)`: a field of what a service
    or client returned. A request value passed to that call does not choose the URL it sends back."""
    m = re.fullmatch(r"\s*(\w+)(?:\s*\.\s*\w+)+\s*", arg)
    if not m:
        return False
    var = re.escape(m.group(1))
    found = list(re.finditer(r"\b%s\b(?:\s*,\s*\w+)*\s*:?=\s*([A-Za-z_]\w*)((?:\s*\.\s*\w+)+)\s*\(" % var, bare[:at]))
    if not found:
        return False
    root = found[-1].group(1)
    return root not in STDLIB_PKGS and root not in tainted


def _constant(arg: str) -> bool:
    return bool(re.fullmatch(r"\s*(?:\"[^\"\n]*\"|`[^`]*`)(?:\s*\+\s*(?:\"[^\"\n]*\"|`[^`]*`))*\s*", arg))


SQL_BUILT = re.compile(r"\bfmt\s*\.\s*Sprintf\s*\(|\+\s*\w|\w\s*\+|strings\s*\.\s*(?:Join|Replace)\s*\(")

SINKS = [
    (re.compile(r"\.\s*(?:Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Raw|Queryx|QueryRowx|MustExec|NamedExec)\s*\("),
     "BE001", "a SQL query", "high"),
    (re.compile(r"\.\s*(?:Where|Order|Group|Having|Joins)\s*\((?=\s*(?:fmt\s*\.\s*Sprintf|\"(?!/)[^\"\n]*\"\s*\+|\w+\s*\+))"),
     "BE001", "a SQL clause", "high"),
    (re.compile(r"\bexec\s*\.\s*Command(?:Context)?\s*\("), "BE002", "a command", "critical"),
    (re.compile(r"\bhttp\s*\.\s*(?:Get|Post|Head|PostForm)\s*\(|\bhttp\s*\.\s*NewRequest(?:WithContext)?\s*\(|\b\w*[cC]lient\s*\.\s*(?:Get|Post|Head)\s*\("),
     "BE005", "an outbound HTTP request URL", "high"),
    (re.compile(r"\bos\s*\.\s*(?:Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll)\s*\(|\bioutil\s*\.\s*(?:ReadFile|WriteFile)\s*\("
                r"|\bhttp\s*\.\s*ServeFile\s*\(|\b(?:c|ctx)\s*\.\s*(?:File|FileAttachment|SendFile|Attachment)\s*\("),
     "BE006", "a file system path", "high"),
    (re.compile(r"\bhttp\s*\.\s*Redirect\s*\(|\b(?:c|ctx)\s*\.\s*Redirect\s*\("), "BE008", "a redirect target", "medium"),
]


def _sink_args(rule: str, call: str, argv: List[str]) -> List[str]:
    """The arguments of a sink call that matter."""
    if not argv:
        return []
    if rule == "BE001":
        a = argv[1:] if argv and re.match(r"\s*(?:ctx|context)\b", argv[0]) else argv
        return a[:1]
    if rule == "BE002":
        rest = argv[1:] if "Context" in call else argv
        if len(rest) >= 3 and re.match(r"\s*\"(?:sh|bash|/bin/sh|/bin/bash|cmd|powershell)\"", rest[0]) and re.match(r"\s*\"(?:-c|/c|-Command)\"", rest[1]):
            return rest[2:3]
        return rest[:1]  # without a shell only the program is dangerous
    if rule == "BE005":
        if "NewRequest" in call:
            return argv[2:3] if "Context" in call else argv[1:2]
        return argv[:1]
    if rule == "BE006":
        if "ServeFile" in call:
            return argv[2:3]
        if re.search(r"(?:File|FileAttachment|SendFile|Attachment)\s*\($", call) and "os" not in call:
            return argv[:1]
        return argv[:1]
    if rule == "BE008":
        if "http" in call:
            return argv[2:3]
        return argv[1:2] if len(argv) > 1 else argv[:1]
    return argv[:1]


RESP_ASSIGN = re.compile(
    r"\b(\w+)\s*,\s*\w+\s*:?=\s*(?:http\s*\.\s*(?:Get|Post|Head|PostForm)|\w*[cC]lient\s*\.\s*(?:Do|Get|Post|Head|PostForm)"
    r"|http\s*\.\s*DefaultClient\s*\.\s*Do)\s*\(")
GO_STMT = re.compile(r"(?m)^[ \t]*go[ \t]+(?:(func)\s*\(|([\w.]+)\s*\()")
FOREVER = re.compile(r"\bfor\s*\{|\bfor\s+range\s+(?:time\s*\.\s*Tick\s*\(|\w+\s*\.\s*C\b)|\bfor\s+\w+\s*:=\s*range\s+time\s*\.\s*Tick\s*\(")
EXIT = re.compile(r"\.\s*Done\s*\(\s*\)|<-\s*\w*(?:done|quit|stop|exit|shutdown|close|cancel|ctx)\w*|\breturn\b|\bbreak\b|\bos\s*\.\s*Exit\b", re.I)
PKG_MAP = re.compile(r"(?m)^(?:var[ \t]+|[ \t]+)(\w+)[ \t]*(?:map\[[^\]\n]{1,80}\][^\n=]{1,80})?=[ \t]*(?:make\s*\(\s*map\[|map\[[^\]\n]{1,80}\][^{\n]{0,80}\{)")
LOCKED = re.compile(r"\bsync\s*\.\s*(?:Mutex|RWMutex|Map)\b|\.\s*(?:Lock|RLock)\s*\(\s*\)|\batomic\s*\.")
CHI_CLOSURE = re.compile(r"\bfunc\s*\(\s*\w+\s+(?:chi\s*\.\s*Router|\*?\w*\.?\w*Router|\*?fiber\s*\.\s*Router)\s*\)\s*\{")
