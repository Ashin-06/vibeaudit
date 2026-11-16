"""C# and ASP.NET Core: a lexer, controller and minimal-API routes with the authorization model, request data
followed into the generic sinks (cssinks), and CSHARP001-CSHARP003 (preview).

Authorization: [Authorize] / [AllowAnonymous] on a controller or action, `.RequireAuthorization()` /
`.AllowAnonymous()` on a minimal endpoint or a route group, `MapControllers().RequireAuthorization()`, a global
FallbackPolicy, and a custom auth filter or middleware class.
"""
from __future__ import annotations

import re
from typing import Callable, Dict, List, Tuple

from .files import Project, SourceFile
from .guard import GUARD, finditer
from .heuristics import PUBLIC_PATH
from .lexer import Views, _blank, match_close
from .model import Finding, Route
from .polyscan import BODY_READ, POLY_TEST_RE, _calls_llm, _has_auth

Emit = Callable[[Finding], None]
UNSECURED = "aspnet-unsecured"  # a route in a project with no authorization at all (CSHARP001; AUTH001 skips it)


def cs_views(src: str) -> Views:
    """Comments blanked in `code`; comments and string contents blanked in `bare`. Handles "..." with escapes,
    @"..." (doubled quotes), $"..." and $@"...", raw \"\"\"...\"\"\" strings and char literals."""
    n = len(src)
    code, bare = list(src), list(src)
    comments: List[Tuple[int, int]] = []
    i = 0
    while i < n:
        c = src[i]
        if c == "/" and src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            _blank(code, i, j)
            _blank(bare, i, j)
            comments.append((i, j))
            i = j
        elif c == "/" and src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            _blank(code, i, j)
            _blank(bare, i, j)
            comments.append((i, j))
            i = j
        elif c in "@$\"":
            k = i
            while k < n and src[k] in "@$":
                k += 1
            if k >= n or src[k] != "\"":
                i = k if k > i else i + 1
                continue
            if src.startswith('"""', k):  # raw string literal: as many quotes close it as opened it
                q = k
                while q < n and src[q] == '"':
                    q += 1
                quotes = q - k
                end = src.find('"' * quotes, q)
                end = n if end < 0 else end
                _blank(bare, q, end)
                i = end + quotes
                continue
            verbatim = "@" in src[i:k]
            j = k + 1
            while j < n:
                ch = src[j]
                if verbatim and ch == '"' and j + 1 < n and src[j + 1] == '"':
                    j += 2
                    continue
                if not verbatim and ch == "\\":
                    j += 2
                    continue
                if ch == '"' or (not verbatim and ch == "\n"):
                    break
                j += 1
            _blank(bare, k + 1, min(j, n))
            i = j + 1
        elif c == "'":
            j = i + 1
            while j < n and j - i < 12 and src[j] not in "'\n":
                j += 2 if src[j] == "\\" else 1
            if j < n and src[j] == "'":
                _blank(bare, i + 1, j)
                i = j + 1
            else:
                i += 1
        else:
            i += 1
    return Views("".join(code), "".join(bare), comments)


def views_of(sf: SourceFile) -> Views:
    v = sf.cache.get("cs_views")
    if v is None:
        v = sf.cache["cs_views"] = cs_views(sf.text or "")
    return v  # type: ignore[return-value]


# ------------------------------------------------------------------ routes and authorization
CLASS = re.compile(r"\bclass\s+(\w+)")
HTTP_ATTR = re.compile(r"\[\s*Http(Get|Post|Put|Delete|Patch)\s*(?:\(\s*(?:template\s*:\s*)?\"([^\"\n]{0,200})\"[^)\]\n]{0,100}\))?\s*\]")
ROUTE_ATTR = re.compile(r"\[\s*Route\s*\(\s*\"([^\"\n]{0,200})\"\s*\)\s*\]")
AUTHORIZE = re.compile(r"\[\s*(?:\w+\s*,\s*){0,5}Authorize\b")
ANONYMOUS = re.compile(r"\[\s*(?:\w+\s*,\s*){0,5}AllowAnonymous\b")
MINIMAL = re.compile(r"\b(\w+)\s*\.\s*Map(Get|Post|Put|Delete|Patch|Methods)\s*\(\s*\"([^\"\n]{0,200})\"")
GROUP = re.compile(r"\b(\w+)\s*=\s*(\w+)\s*\.\s*MapGroup\s*\(\s*\"([^\"\n]{0,200})\"\s*\)([^;]{0,300});")
GROUP_AUTH = re.compile(r"\b(\w+)\s*\.\s*RequireAuthorization\s*\(")
FALLBACK = re.compile(r"\bFallbackPolicy\s*=")
CONTROLLERS_AUTH = re.compile(r"\bMapControllers\s*\(\s*\)\s*\.\s*RequireAuthorization\s*\(")
ANY_AUTH = re.compile(r"\[\s*(?:\w+\s*,\s*){0,5}Authorize\b|\.\s*RequireAuthorization\s*\(|FallbackPolicy\s*=")
# a project's own auth filter or middleware (an API-key attribute, a token-checking middleware)
CUSTOM_AUTH = re.compile(
    r"(?i)\bclass\s+\w{0,40}(?:auth|apikey|api_key|token|jwt)\w{0,40}\s*(?:<[^>{]{0,80}>)?\s*:\s*[^{]{0,200}?"
    r"\b(?:IAuthorizationFilter|IAsyncAuthorizationFilter|IActionFilter|IAsyncActionFilter|ActionFilterAttribute"
    r"|AuthorizeAttribute|AuthenticationHandler|IMiddleware|IEndpointFilter)\b"
    r"|\bclass\s+\w{0,40}(?:Auth|ApiKey|Token|Jwt)\w{0,40}Middleware\b")


class CsScanner:
    def __init__(self, project: Project, emit: Emit):
        self.p = project
        self.emit = emit

    def add(self, sf: SourceFile, rule: str, line: int, msg: str, sev: str = "") -> None:
        self.emit(Finding(rule, sf.rel, line, msg, sev, sf.line(line).strip()[:200]))

    def run(self) -> List[Route]:
        files = [f for f in self.p.files if f.rel.endswith(".cs") and f.text is not None
                 and not f.is_test and not POLY_TEST_RE.search(f.rel)]
        if not files:
            return []
        code = "\n".join(views_of(f).code for f in files)
        custom = bool(CUSTOM_AUTH.search(code))
        any_auth = custom or bool(ANY_AUTH.search(code))
        everywhere = custom or bool(FALLBACK.search(code))
        controllers = everywhere or bool(CONTROLLERS_AUTH.search(code))
        routes: List[Route] = []
        for sf in files:
            got = GUARD.run(sf.rel, "C# routes", self._routes, sf, controllers, everywhere)
            routes.extend(got or [])
        if not any_auth:
            self._no_authorization(routes)
        from . import cssinks

        for sf in files:
            if not sf.is_example:
                GUARD.run(sf.rel, "C# data flow", cssinks.check, sf, views_of(sf), self.add)
                GUARD.run(sf.rel, "C# configuration", self._config, sf)
        return routes

    def _routes(self, sf: SourceFile, controllers: bool, everywhere: bool) -> List[Route]:
        v = views_of(sf)
        code, bare = v.code, v.bare
        out: List[Route] = []
        # controllers: [Route] and [Authorize] on the class, [Http*] on its actions
        for cm in finditer(CLASS, bare):
            brace = bare.find("{", cm.end())
            end = match_close(bare, brace) if brace >= 0 else -1
            if end < 0 or not HTTP_ATTR.search(code, brace, end):
                continue
            before = code[max(0, cm.start() - 800):cm.start()]
            head = before[max(before.rfind(c) for c in "{};") + 1:]  # the attributes of this class only
            prefix = ""
            rm = ROUTE_ATTR.search(head)
            if rm:
                prefix = re.sub(r"(?i)\[controller\]", re.sub(r"Controller$", "", cm.group(1)).lower(), rm.group(1))
            class_auth = bool(AUTHORIZE.search(head)) and not ANONYMOUS.search(head)
            for hm in finditer(HTTP_ATTR, code[:end]):
                if hm.start() < brace:
                    continue
                attrs = _attribute_block(code, hm.start())
                sig = _skip_attributes(bare, hm.end())
                name = re.compile(r"\b(\w+)\s*(?:<[^<>()]{0,80}>)?\s*\(").search(bare, sig, min(end, sig + 300))
                close = match_close(bare, name.end() - 1) if name else -1
                stop = _body_end(bare, close) if close >= 0 else -1
                body = code[attrs:stop + 1] if stop > 0 else code[attrs:min(end, hm.end() + 400)]
                attr_text = code[attrs:sig]
                path = _join(prefix, hm.group(2) or "")
                if name:
                    path = re.sub(r"(?i)\[action\]", name.group(1), path)
                anonymous = bool(ANONYMOUS.search(attr_text))
                auth = (class_auth or controllers or bool(AUTHORIZE.search(attr_text)) or _has_auth(body)) and not anonymous
                out.append(self._route(sf, hm.start(), path, hm.group(1), body, auth))
        # minimal APIs: app.MapGet("/x", handler).RequireAuthorization(), also on route groups
        groups: Dict[str, Tuple[str, bool]] = {}
        for gm in finditer(GROUP, bare):
            parent_prefix, parent_auth = groups.get(gm.group(2), ("", False))
            prefix = code[gm.start(3):gm.end(3)]
            chain = code[gm.end(3):gm.end()]
            groups[gm.group(1)] = (_join(parent_prefix, prefix),
                                   parent_auth or ("RequireAuthorization" in chain and "AllowAnonymous" not in chain))
        for gm in finditer(GROUP_AUTH, bare):
            if gm.group(1) in groups:
                groups[gm.group(1)] = (groups[gm.group(1)][0], True)
        for mm in finditer(MINIMAL, bare):
            close = match_close(bare, bare.find("(", mm.start()))
            if close < 0:
                continue
            tail = code[close + 1:close + 300]
            chain = tail.split(";", 1)[0]
            group_prefix, group_auth = groups.get(mm.group(1), ("", False))
            handler = code[mm.start():close + 1]
            anonymous = "AllowAnonymous" in chain or bool(ANONYMOUS.search(handler))
            auth = ("RequireAuthorization" in chain or group_auth or everywhere
                    or bool(AUTHORIZE.search(handler))) and not anonymous
            verb = mm.group(2) if mm.group(2) != "Methods" else "ALL"
            out.append(self._route(sf, mm.start(), _join(group_prefix, code[mm.start(3):mm.end(3)]), verb,
                                   handler + chain, auth))
        return out

    @staticmethod
    def _route(sf: SourceFile, offset: int, path: str, verb: str, body: str, auth: bool) -> Route:
        return Route(sf.rel, sf.line_at(offset), path, [verb.upper()], body, "aspnet", "cs", has_auth=auth,
                     calls_llm=_calls_llm(body), reads_body=bool(BODY_READ.search(body)),
                     params=re.findall(r"\{(\w+)", path))

    def _no_authorization(self, routes: List[Route]) -> None:
        """CSHARP001: endpoints that change data in a project with no authorization anywhere."""
        by_file: Dict[str, List[Route]] = {}
        for r in routes:
            if r.mutating and not r.has_auth and not PUBLIC_PATH.search(r.path):
                by_file.setdefault(r.file, []).append(r)
            if not r.has_auth:
                r.framework = UNSECURED
        for rel, rs in sorted(by_file.items()):
            sf = self.p.get(rel)
            if sf is not None:
                first = min(rs, key=lambda r: r.line)
                self.add(sf, "CSHARP001", first.line,
                         f"{len(rs)} endpoints here change data, and the project has no authorization anywhere "
                         "([Authorize], RequireAuthorization or a fallback policy), so anyone can call them.")

    def _config(self, sf: SourceFile) -> None:
        code = views_of(sf).code
        binder = "SerializationBinder" in code
        deserializes = bool(re.search(r"\.\s*Deserialize\s*\(", code))
        for m in finditer(UNSAFE_TYPES, code):
            text = m.group(0)
            if ("TypeNameHandling" in text and binder) or ("TypeNameHandling" not in text and not deserializes):
                continue
            self.add(sf, "CSHARP002", sf.line_at(m.start()),
                     f"`{text.strip()[:60]}` lets the payload name the type to create; a gadget type gives remote "
                     "code execution.", "high")
        for m in finditer(DEV_PAGE, code):
            if DEV_ONLY.search(code[max(0, m.start() - 400):m.start()]):
                continue
            self.add(sf, "CSHARP003", sf.line_at(m.start()),
                     "The developer error page is enabled outside Development: stack traces, source and "
                     "configuration are shown to anyone who triggers an error.", "medium")


UNSAFE_TYPES = re.compile(
    r"\bTypeNameHandling\s*=\s*TypeNameHandling\s*\.\s*(?:All|Auto|Objects|Arrays)\b"
    r"|\bnew\s+(?:BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter|ObjectStateFormatter)\s*\("
    r"|\bnew\s+JavaScriptSerializer\s*\(\s*new\s+SimpleTypeResolver\s*\(")
DEV_PAGE = re.compile(r"\bUse(?:DeveloperExceptionPage|DatabaseErrorPage|MigrationsEndPoint)\s*\(\s*\)")
DEV_ONLY = re.compile(r"IsDevelopment\s*\(\s*\)|IsEnvironment\s*\(\s*\"Development\"|#\s*if\s+DEBUG")


def _attribute_block(code: str, start: int) -> int:
    """Start of the run of attribute lines that ends with the one at `start`."""
    i = code.rfind("\n", 0, start) + 1
    while i > 0:
        prev = code.rfind("\n", 0, i - 1) + 1
        if not code[prev:i].strip().startswith("["):
            break
        i = prev
    return i


def _skip_attributes(bare: str, i: int) -> int:
    """Index after any further [Attribute(...)] blocks following `i`."""
    n = len(bare)
    while True:
        while i < n and bare[i] in " \t\r\n":
            i += 1
        if i < n and bare[i] == "[":
            j = match_close(bare, i)
            if j < 0:
                return i
            i = j + 1
        else:
            return i


def _body_end(bare: str, close: int) -> int:
    """End of a method body after its parameter list: the matching `}` or the `;` of an expression body."""
    j = close + 1
    limit = min(len(bare), close + 300)
    while j < limit:
        if bare[j] == "{":
            return match_close(bare, j)
        if bare.startswith("=>", j):
            k = bare.find(";", j)
            return k if 0 <= k - j < 2000 else -1
        if bare[j] == ";":
            return -1
        j += 1
    return -1


def _join(prefix: str, sub: str) -> str:
    if sub.startswith("~/"):
        return "/" + sub[2:].strip("/")
    parts = [p.strip("/") for p in (prefix, sub) if p.strip("/")]
    return "/" + "/".join(parts) if parts else "/"
