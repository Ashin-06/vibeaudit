"""Phase 5 polyglot checks: Go, Java/Kotlin, C#/.NET, Rust and PHP.

Extracts canonical HTTP routes (fed into ProjectScanner's auth, admin, IDOR and ContractScanner
checks) and checks SQL injection (BE001), command injection (BE002), raw HTML sinks (FE001),
N+1 queries in loops (DATA001) and outbound HTTP calls without a timeout (REL001).
"""
from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Tuple

from . import heuristics as H
from .files import Project, SourceFile
from .guard import GUARD, finditer
from .model import Finding, Route, join_path

Emit = Callable[[Finding], None]

POLY_EXTS = (".go", ".java", ".kt", ".cs", ".cshtml", ".rs", ".php")
POLY_TEST_RE = re.compile(r"_test\.go$|(?:Test|Tests|Spec)\.(?:java|kt|cs|php)$|(^|/)(?:src/test|tests?)/", re.I)

# Direct per-language patterns (kept simple and bounded so every pattern runs in linear time)
GO_SQLI = re.compile(
    r"""\b(?:db|tx|conn|pool)\s*\.\s*(?:Raw|Exec|Query|QueryRow|Where|Order)\s*\(\s*(?:fmt\.Sprintf\s*\(|"[^"\n]{0,200}"\s*\+)""")
JAVA_SQLI = re.compile(
    r"""\b(?:jdbcTemplate\s*\.\s*(?:query(?:ForObject|ForList)?|update|execute)|entityManager\s*\.\s*create(?:Native)?Query|statement\s*\.\s*execute(?:Query|Update)?)\s*\(\s*"[^"\n]{0,200}"\s*\+"""
    r"""|\bcreateNativeQuery\s*\(\s*"[^"\n]{0,200}"\s*\+""")
CS_SQLI = re.compile(
    r"""\.\s*(?:FromSqlRaw|ExecuteSqlRaw|SqlQueryRaw)\s*\(\s*(?:\$"|"[^"\n]{0,200}"\s*\+|string\.Format\s*\()""")
RS_SQLI = re.compile(
    r"""\b(?:sqlx::query(?:_as)?|diesel::sql_query)\s*\(\s*&?\s*format!\s*\(""")
PHP_SQLI = re.compile(
    r"""(?:\bDB::(?:raw|select|statement)|->\s*(?:whereRaw|selectRaw|orderByRaw|query|exec))\s*\(\s*(?:"[^"\n]{0,200}\$\w+|'[^'\n]{0,200}'\s*\.\s*\$)""")

GO_CMDI = re.compile(r"""\bexec\.Command\s*\(\s*"(?:sh|bash|cmd|powershell)"\s*,\s*"(?:-c|/c)"\s*,\s*(?!")""")
JAVA_CMDI = re.compile(
    r"""\bRuntime\.getRuntime\(\)\.exec\s*\(\s*(?!")|\bnew\s+ProcessBuilder\s*\(\s*"(?:sh|bash|cmd)"\s*,\s*"(?:-c|/c)"\s*,\s*(?!")""")
CS_CMDI = re.compile(
    r"""\bProcess\.Start\s*\(\s*(?:new\s+ProcessStartInfo\s*\(\s*)?"(?:cmd|powershell|sh|bash)(?:\.exe)?"\s*,\s*(?:\$"|"[^"\n]{0,200}"\s*\+)""")
RS_CMDI = re.compile(
    r"""\bCommand::new\s*\(\s*"(?:sh|bash|cmd)"\s*\)\s*\.arg\s*\(\s*"(?:-c|/c)"\s*\)\s*\.arg\s*\(\s*(?!")""")
PHP_CMDI = re.compile(
    r"""\b(?:shell_exec|system|passthru)\s*\(\s*(?:"[^"\n]{0,200}\$|\$\w+|(?:"[^"\n]{0,200}"|'[^'\n]{0,200}')\s*\.\s*\$)""")

GO_HTTP = re.compile(r"""\bhttp\.(?:Get|Post|PostForm)\s*\(""")
JAVA_HTTP = re.compile(r"""\bnew\s+RestTemplate\s*\(\s*\)|\bHttpClient\.newHttpClient\s*\(\s*\)""")
CS_HTTP = re.compile(r"""\bnew\s+HttpClient\s*\(\s*\)""")
RS_HTTP = re.compile(r"""\breqwest::get\s*\(|\breqwest::Client::new\s*\(\s*\)|\bClient::new\s*\(\s*\)""")
PHP_HTTP = re.compile(r"""\bHttp::(?:get|post|put|delete)\s*\(""")

LOOP_HEAD = re.compile(r"""\b(?:for|foreach)\b""")
GO_LOOP_DB = re.compile(r"""\b(?:db|tx)\s*\.\s*(?:First|Find|Take|Last|Where|Create|Save|Exec|Query|QueryRow)\s*\(""")
JAVA_LOOP_DB = re.compile(
    r"""\b\w{1,40}Repository\s*\.\s*(?:find|get|save|delete)\w*\s*\(|\bentityManager\s*\.\s*(?:find|create(?:Native)?Query)\s*\(|\bjdbcTemplate\s*\.\s*(?:query|update)\w*\s*\(""")
CS_LOOP_DB = re.compile(r"""\.\s*(?:FirstOrDefaultAsync|SingleOrDefaultAsync|FindAsync|ToListAsync|SaveChangesAsync|ExecuteSqlRawAsync)\s*\(""")
RS_LOOP_DB = re.compile(r"""\b(?:sqlx::query|diesel::\w+|collection\.find_one)\b""")
PHP_LOOP_DB = re.compile(r"""\b(?:DB::(?:select|table)|[A-Z]\w{0,40}::(?:find|where|create|first))\s*\(|->\s*(?:save|delete|execute|fetch)\s*\(""")

BLADE_RAW = re.compile(r"""\{!!\s*\$(?!slot\b|attributes\b)[^!\n]{1,200}!!\}|\becho\s+\$_(?:GET|POST|REQUEST)\b""")
RAZOR_RAW = re.compile(r"""@Html\.Raw\s*\(""")

POLY_AUTH = re.compile(
    r"""(?i)@PreAuthorize|@Secured|@RolesAllowed|@Authenticated|\bSecurityContext\b|\bAuthenticationPrincipal\b"""
    r"""|\[Authorize\b|\bRequireAuthorization\s*\(|\bHttpContext\.User\b"""
    r"""|\bmiddleware\s*\([^)\n]{0,120}\bauth\b|\bauth:sanctum\b|\bauth:api\b|#\[IsGranted|\bdenyAccessUnlessGranted\b|\bAuth::(?:user|id)\b"""
    r"""|\bAuthMiddleware\b|\bRequireAuth\b|\bAuthRequired\b|\bClaims\b|\bIdentity\b|\bJwtAuth\b"""
)
POLY_LLM = re.compile(r"""(?i)openai|anthropic|gemini|generativelanguage|ChatCompletion|GenerateContent|langchain""")
BODY_READ = re.compile(
    r"""\bBindJSON\s*\(|\bShouldBind\w*\s*\(|\bBodyParser\s*\(|json\.NewDecoder\s*\(\s*\w+\.Body\b|@RequestBody\b|\[FromBody\]|\bweb::Json\b|\bJson<|\$request->(?:input|all|validated)\b""")

# Framework route patterns
GO_STD_ROUTE = re.compile(r'\bhttp\.HandleFunc\s*\(\s*"([^"\n]{1,200})"')
GO_ROUTER_VAR = re.compile(r'\b(\w+)\s*:?=\s*\w+\.(?:Group|Route)\s*\(\s*"([^"\n]{1,200})"')
GO_METHOD_ROUTE = re.compile(
    r"""\b(\w+)\s*\.\s*(GET|POST|PUT|DELETE|PATCH|Get|Post|Put|Delete|Patch)\s*\(\s*"([^"\n]{1,200})"\s*,\s*([^,\n)]+)""")

SPRING_CLASS_PREFIX = re.compile(r'@RequestMapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?"([^"\n]{1,200})"')
SPRING_METHOD_ROUTE = re.compile(
    r"""@(Get|Post|Put|Delete|Patch)Mapping\s*(?:\(\s*(?:(?:value|path)\s*=\s*)?"([^"\n]{0,200})"[^)\n]*\))?""")
JAXRS_CLASS_PATH = re.compile(r"""\bclass\s+\w+""")
JAXRS_METHOD_ROUTE = re.compile(
    r"""@(GET|POST|PUT|DELETE|PATCH)\b(?:[ \t\n]{0,120}@Path\s*\(\s*"([^"\n]{1,200})"\s*\))?""")

CS_CLASS_ROUTE = re.compile(r"""\[Route\s*\(\s*"([^"\n]{1,200})"\s*\)\s*]""")
CS_ATTR_ROUTE = re.compile(r"""\[Http(Get|Post|Put|Delete|Patch)(?:\s*\(\s*"([^"\n]{0,200})"\s*\))?\s*]""")
CS_MINIMAL_ROUTE = re.compile(r"""\b\w+\.Map(Get|Post|Put|Delete|Patch)\s*\(\s*"([^"\n]{1,200})"\s*,""")

RS_ACTIX_ATTR = re.compile(r"""#\[(get|post|put|delete|patch)\s*\(\s*"([^"\n]{1,200})"\s*\)\]""")
RS_RESOURCE_ROUTE = re.compile(
    r"""\bweb::resource\s*\(\s*"([^"\n]{1,200})"\s*\)\s*\.route\s*\(\s*web::(get|post|put|delete|patch)\s*\(\s*\)(?:\s*\.to\s*\(\s*(\w+)\s*\))?""")
RS_AXUM_ROUTE = re.compile(
    r"""\.route\s*\(\s*"([^"\n]{1,200})"\s*,\s*(?:routing::)?(get|post|put|delete|patch)\s*\(\s*(\w+)?""")

PHP_LARAVEL_ROUTE = re.compile(
    r"""\bRoute::(get|post|put|delete|patch)\s*\(\s*['"]([^'"\n]{1,200})['"]\s*,\s*([^;\n]{1,200})""")
PHP_SYMFONY_ROUTE = re.compile(
    r"""#\[Route\s*\(\s*['"]([^'"\n]{1,200})['"][^\]\n]{0,200}\]""")


POLY_SEVERE = frozenset({"BE001", "BE002", "FE001"})  # injection and XSS: gate even in preview


def _lang_of(rel: str) -> Optional[str]:
    low = rel.lower()
    if low.endswith(".go"):
        return "go"
    if low.endswith((".java", ".kt")):
        return "java"
    if low.endswith(".cs"):
        return "cs"
    if low.endswith(".cshtml"):
        return "cshtml"
    if low.endswith(".rs"):
        return "rs"
    if low.endswith(".php"):
        return "php"
    return None


def strip_comments(src: str, lang: str) -> str:
    """Replace comments with spaces while keeping line breaks and offsets exact."""
    n = len(src)
    out = list(src)
    i = 0
    while i < n:
        c = src[i]
        if c == '"':
            i += 1
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == "'" and lang in ("php", "js"):
            i += 1
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == "'":
                    i += 1
                    break
                i += 1
            continue
        if c == "`" and lang == "go":
            end = src.find("`", i + 1)
            i = n if end < 0 else end + 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            end = src.find("\n", i + 2)
            end = n if end < 0 else end
            for k in range(i, end):
                out[k] = " "
            i = end
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            end = src.find("*/", i + 2)
            end = n if end < 0 else end + 2
            for k in range(i, end):
                if out[k] != "\n":
                    out[k] = " "
            i = end
            continue
        if lang == "php" and c == "#" and (i + 1 >= n or src[i + 1] != "["):
            end = src.find("\n", i + 1)
            end = n if end < 0 else end
            for k in range(i, end):
                out[k] = " "
            i = end
            continue
        i += 1
    return "".join(out)


def _brace_block(code: str, open_pos: int, limit: int = 4000) -> str:
    if open_pos < 0 or open_pos >= len(code) or code[open_pos] != "{":
        return code[max(0, open_pos):min(len(code), open_pos + 1200)]
    depth = 0
    end = min(len(code), open_pos + limit)
    in_str = False
    i = open_pos
    while i < end:
        ch = code[i]
        if ch == "\\" and in_str:
            i += 2
            continue
        if ch == '"':
            in_str = not in_str
        elif not in_str:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return code[open_pos:i + 1]
        i += 1
    return code[open_pos:end]


def _params_in(path: str) -> List[str]:
    found = re.findall(r":(\w+)|\{(\w+)(?::[^}]+)?\}|<(?:\w+:)?(\w+)>", path)
    return [next(g for g in groups if g) for groups in found if any(groups)]


def _has_auth(text: str) -> bool:
    return bool(POLY_AUTH.search(text) or H.AUTH_EVIDENCE.search(text) or H.CUSTOM.is_auth(text))


def _calls_llm(text: str) -> bool:
    return bool(H.LLM_HOSTS.search(text) or POLY_LLM.search(text))


def _named_body(code: str, name: str, lang: str) -> str:
    """Look up a named handler function/method in the same file when a route references it."""
    if not name or not re.fullmatch(r"\w+", name):
        return ""
    esc = re.escape(name)
    if lang == "go":
        pat = rf"\bfunc\s+(?:\([^)]*\)\s*)?{esc}\s*\("
    elif lang == "rs":
        pat = rf"\b(?:pub\s+)?(?:async\s+)?fn\s+{esc}\s*\("
    elif lang == "php":
        pat = rf"\bfunction\s+{esc}\s*\("
    else:
        return ""
    m = re.search(pat, code)
    if not m:
        return ""
    brace = code.find("{", m.end())
    return code[m.start():brace] + _brace_block(code, brace) if brace >= 0 else ""


class PolyScanner:
    def __init__(self, project: Project, emit: Emit):
        self.p = project
        self.emit = emit
        self.routes: List[Route] = []

    def add(self, sf: SourceFile, line: int, rule: str, msg: str, sev: str = "") -> None:
        self.emit(Finding(rule, sf.rel, line, msg, sev, sf.line(line).strip()[:200]))

    def run(self) -> List[Route]:
        for sf in self.p.files:
            lang = _lang_of(sf.rel)
            if lang is None or sf.text is None:
                continue
            if sf.is_test or sf.is_example or sf.is_one_off or sf.is_vendored or POLY_TEST_RE.search(sf.rel):
                continue
            GUARD.run(sf.rel, "polyglot checks", self._scan_file, sf, lang)
        return self.routes

    def _scan_file(self, sf: SourceFile, lang: str) -> None:
        raw = sf.text or ""
        if lang == "cshtml":
            for m in finditer(RAZOR_RAW, raw):
                self.add(sf, sf.line_at(m.start()), "FE001", "Razor `@Html.Raw()` outputs unescaped HTML.")
            return
        code = strip_comments(raw, lang)
        if lang == "go":
            self._go(sf, code)
        elif lang == "java":
            self._java(sf, code)
        elif lang == "cs":
            self._cs(sf, code)
        elif lang == "rs":
            self._rs(sf, code)
        elif lang == "php":
            self._php(sf, code)

    def _emit_route(self, sf: SourceFile, offset: int, path: str, methods: List[str], body: str,
                    framework: str, lang: str) -> None:
        if not path.startswith("/"):
            path = "/" + path
        r = Route(
            file=sf.rel, line=sf.line_at(offset), path=path, methods=[m.upper() for m in methods],
            body=body, framework=framework, lang=lang, has_auth=_has_auth(body),
            calls_llm=_calls_llm(body), reads_body=bool(BODY_READ.search(body)), params=_params_in(path),
        )
        self.routes.append(r)

    def _loop_n_plus_one(self, sf: SourceFile, code: str, db_rx: re.Pattern) -> None:
        seen = set()
        for m in finditer(LOOP_HEAD, code):
            line_end = code.find("\n", m.end())
            brace = code.find("{", m.end(), len(code) if line_end < 0 else line_end + 80)
            if brace < 0:
                continue
            body = _brace_block(code, brace, limit=2000)
            hit = db_rx.search(body)
            if hit:
                ln = sf.line_at(brace + hit.start())
                if ln not in seen:
                    seen.add(ln)
                    self.add(sf, ln, "DATA001", "Database call runs inside a loop (possible N+1 query).")

    def _check_timeout(self, sf: SourceFile, code: str, rx: re.Pattern, label: str) -> None:
        for m in finditer(rx, code):
            if rx is PHP_HTTP:
                stmt_start = max(0, code.rfind(";", 0, m.start()) + 1, m.start() - 120)
                window = code[stmt_start:m.end()]
            else:
                nl2 = code.find("\n", m.end())
                nl2 = code.find("\n", nl2 + 1) if nl2 >= 0 else -1
                end = min(len(code), nl2 if nl2 >= 0 else m.end() + 180, m.end() + 250)
                window = code[max(0, m.start() - 100):end]
            if re.search(r"(?i)timeout|RequestFactory|ofSeconds|ofMillis", window):
                continue
            self.add(sf, sf.line_at(m.start()), "REL001", f"`{label}` has no timeout; a slow upstream can hang this worker.")

    # ------------------------------------------------------------------ Go
    def _go(self, sf: SourceFile, code: str) -> None:
        framework = "gin" if "gin." in code or '"github.com/gin-gonic/gin"' in code else \
            "fiber" if '"github.com/gofiber/fiber' in code else \
            "chi" if '"github.com/go-chi/chi' in code else "net-http"

        groups: Dict[str, Tuple[str, bool]] = {}
        for m in finditer(GO_ROUTER_VAR, code):
            line_end = code.find("\n", m.start())
            line = code[m.start():line_end if line_end >= 0 else len(code)]
            groups[m.group(1)] = (m.group(2), _has_auth(line))
        authed_vars = {m.group(1) for m in finditer(r"\b(\w+)\.Use\s*\(([^)\n]{0,200})\)", code) if _has_auth(m.group(2))}

        for m in finditer(GO_STD_ROUTE, code):
            spec = m.group(1).strip()
            parts = spec.split(None, 1)
            if len(parts) == 2 and parts[0].upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                methods, path = [parts[0].upper()], parts[1]
            else:
                methods, path = [], spec
            line_end = code.find("\n", m.start())
            end_pos = line_end if line_end >= 0 else len(code)
            route_line = code[m.start():end_pos]
            arg = route_line.split(",", 1)[1].split(")")[0].strip() if "," in route_line else ""
            brace = code.find("{", m.end(), end_pos)
            body = _brace_block(code, brace) if brace >= 0 else _named_body(code, arg.rsplit(".", 1)[-1], "go")
            if not body:
                body = route_line
            if not methods:
                methods = ["POST"] if (H.MUTATION_EVIDENCE.search(body) or _calls_llm(body) or BODY_READ.search(body)) else ["GET"]
            self._emit_route(sf, m.start(), path, methods, body, "net-http", "go")

        for m in finditer(GO_METHOD_ROUTE, code):
            var, verb, sub, handler = m.group(1), m.group(2).upper(), m.group(3), m.group(4).strip()
            prefix, grp_auth = groups.get(var, ("", False))
            full_path = join_path(prefix, sub)
            line_end = code.find("\n", m.start())
            end_pos = line_end if line_end >= 0 else len(code)
            route_line = code[m.start():end_pos]
            brace = code.find("{", m.end(), end_pos)
            body = _brace_block(code, brace) if brace >= 0 else _named_body(code, handler.rsplit(".", 1)[-1], "go")
            if not body:
                body = route_line
            if grp_auth or var in authed_vars or _has_auth(route_line):
                body = "RequireAuth() " + body
            self._emit_route(sf, m.start(), full_path, [verb], body, framework, "go")

        for m in finditer(GO_SQLI, code):
            self.add(sf, sf.line_at(m.start()), "BE001", "SQL query built by formatting strings into the query.")
        for m in finditer(GO_CMDI, code):
            self.add(sf, sf.line_at(m.start()), "BE002", "Shell command executed with dynamic input.")
        self._loop_n_plus_one(sf, code, GO_LOOP_DB)
        self._check_timeout(sf, code, GO_HTTP, "http.Get/Post()")

    # -------------------------------------------------------- Java / Kotlin
    def _java(self, sf: SourceFile, code: str) -> None:
        is_quarkus = "jakarta.ws.rs" in code or "javax.ws.rs" in code or "@Path(" in code
        framework = "quarkus" if is_quarkus else "spring"
        cls_pos = code.find("class ")
        cls_head = code[:cls_pos + 120] if cls_pos >= 0 else code[:600]
        class_auth = _has_auth(cls_head)

        prefix = ""
        pm = SPRING_CLASS_PREFIX.search(cls_head) if not is_quarkus else re.search(r'@Path\s*\(\s*"([^"\n]{1,200})"\s*\)', cls_head)
        if pm:
            prefix = pm.group(1)

        if not is_quarkus:
            for m in finditer(SPRING_METHOD_ROUTE, code):
                if m.start() < cls_pos:
                    continue
                verb, sub = m.group(1).upper(), m.group(2) or ""
                path = join_path(prefix, sub)
                ctx_start = max(0, m.start() - 200)
                brace = code.find("{", m.end(), m.end() + 400)
                body = code[ctx_start:brace] + _brace_block(code, brace) if brace >= 0 else code[ctx_start:m.end() + 600]
                if class_auth:
                    body = "@PreAuthorize " + body
                self._emit_route(sf, m.start(), path, [verb], body, "spring", "java")
        else:
            for m in finditer(JAXRS_METHOD_ROUTE, code):
                verb, sub = m.group(1).upper(), m.group(2) or ""
                path = join_path(prefix, sub)
                ctx_start = max(0, m.start() - 200)
                brace = code.find("{", m.end(), m.end() + 400)
                body = code[ctx_start:brace] + _brace_block(code, brace) if brace >= 0 else code[ctx_start:m.end() + 600]
                if class_auth:
                    body = "@RolesAllowed " + body
                self._emit_route(sf, m.start(), path, [verb], body, "quarkus", "java")

        for m in finditer(JAVA_SQLI, code):
            self.add(sf, sf.line_at(m.start()), "BE001", "SQL query built by concatenating strings into JDBC/JPA.")
        for m in finditer(JAVA_CMDI, code):
            self.add(sf, sf.line_at(m.start()), "BE002", "OS process executed with dynamic command arguments.")
        self._loop_n_plus_one(sf, code, JAVA_LOOP_DB)
        self._check_timeout(sf, code, JAVA_HTTP, "RestTemplate/HttpClient")

    # ------------------------------------------------------------ C# / .NET
    def _cs(self, sf: SourceFile, code: str) -> None:
        cls_m = re.search(r"\bclass\s+(\w+)", code)
        cls_head = code[:cls_m.start() + 80] if cls_m else code[:600]
        class_auth = _has_auth(cls_head) and "[AllowAnonymous]" not in cls_head
        prefix = ""
        rm = CS_CLASS_ROUTE.search(cls_head)
        if rm:
            prefix = rm.group(1)
            if cls_m and "[controller]" in prefix.lower():
                ctrl = re.sub(r"Controller$", "", cls_m.group(1)).lower()
                prefix = re.sub(r"\[controller\]", ctrl, prefix, flags=re.I)

        for m in finditer(CS_ATTR_ROUTE, code):
            verb, sub = m.group(1).upper(), m.group(2) or ""
            path = join_path(prefix, sub)
            ctx_start = max(0, m.start() - 200)
            brace = code.find("{", m.end(), m.end() + 400)
            body = code[ctx_start:brace] + _brace_block(code, brace) if brace >= 0 else code[ctx_start:m.end() + 600]
            if "[AllowAnonymous]" in body:
                continue
            if class_auth:
                body = "[Authorize] " + body
            self._emit_route(sf, m.start(), path, [verb], body, "aspnet", "cs")

        for m in finditer(CS_MINIMAL_ROUTE, code):
            verb, path = m.group(1).upper(), m.group(2)
            brace = code.find("{", m.end(), m.end() + 180)
            tail = code[m.end():m.end() + 400]
            body = (_brace_block(code, brace) if brace >= 0 else "") + " " + tail
            self._emit_route(sf, m.start(), path, [verb], body, "aspnet", "cs")

        for m in finditer(CS_SQLI, code):
            self.add(sf, sf.line_at(m.start()), "BE001", "Raw EF Core SQL query built with string interpolation or concatenation.")
        for m in finditer(CS_CMDI, code):
            self.add(sf, sf.line_at(m.start()), "BE002", "Shell process started with formatted command string.")
        self._loop_n_plus_one(sf, code, CS_LOOP_DB)
        self._check_timeout(sf, code, CS_HTTP, "new HttpClient()")

    # ---------------------------------------------------------------- Rust
    def _rs(self, sf: SourceFile, code: str) -> None:
        for m in finditer(RS_ACTIX_ATTR, code):
            verb, path = m.group(1).upper(), m.group(2)
            brace = code.find("{", m.end(), m.end() + 400)
            body = code[m.end():brace] + _brace_block(code, brace) if brace >= 0 else code[m.end():m.end() + 600]
            self._emit_route(sf, m.start(), path, [verb], body, "actix", "rs")

        for m in finditer(RS_RESOURCE_ROUTE, code):
            path, verb, fn_name = m.group(1), m.group(2).upper(), m.group(3) or ""
            body = _named_body(code, fn_name, "rs") or code[m.start():m.end() + 200]
            self._emit_route(sf, m.start(), path, [verb], body, "actix", "rs")

        for m in finditer(RS_AXUM_ROUTE, code):
            path, verb, fn_name = m.group(1), m.group(2).upper(), m.group(3) or ""
            body = _named_body(code, fn_name, "rs") or code[m.start():m.end() + 200]
            self._emit_route(sf, m.start(), path, [verb], body, "axum", "rs")

        for m in finditer(RS_SQLI, code):
            self.add(sf, sf.line_at(m.start()), "BE001", "SQL query built dynamically with format!() instead of bound parameters.")
        for m in finditer(RS_CMDI, code):
            self.add(sf, sf.line_at(m.start()), "BE002", "Shell command executed with dynamic input.")
        self._loop_n_plus_one(sf, code, RS_LOOP_DB)
        self._check_timeout(sf, code, RS_HTTP, "reqwest")

    # ----------------------------------------------------------------- PHP
    def _php(self, sf: SourceFile, code: str) -> None:
        raw = sf.text or ""
        for m in finditer(PHP_LARAVEL_ROUTE, code):
            verb, path, rest = m.group(1).upper(), m.group(2), m.group(3)
            line_end = code.find("\n", m.start())
            end_pos = line_end if line_end >= 0 else len(code)
            stmt_end = code.find(";", m.start())
            full_stmt = code[m.start():stmt_end if stmt_end > 0 else m.end() + 120]
            brace = code.find("{", m.start(), end_pos)
            body = _brace_block(code, brace) if brace >= 0 else full_stmt
            if brace < 0:
                ctrl_m = re.search(r"['\"](\w+)['\"]\s*\]|@\s*(\w+)", rest)
                if ctrl_m:
                    method_name = ctrl_m.group(1) or ctrl_m.group(2)
                    body = full_stmt + " " + (_named_body(code, method_name, "php") or "")
            if _has_auth(full_stmt):
                body = "middleware('auth') " + body
            self._emit_route(sf, m.start(), path, [verb], body, "laravel", "php")

        for m in finditer(PHP_SYMFONY_ROUTE, code):
            path = m.group(1)
            attr = m.group(0)
            mm = re.search(r"methods:\s*\[([^\]]{1,80})\]", attr)
            methods = [v.strip().strip("'\"").upper() for v in mm.group(1).split(",")] if mm else ["GET"]
            ctx_start = max(0, m.start() - 120)
            brace = code.find("{", m.end(), m.end() + 300)
            body = code[ctx_start:brace] + _brace_block(code, brace) if brace >= 0 else code[ctx_start:m.end() + 600]
            self._emit_route(sf, m.start(), path, methods, body, "symfony", "php")

        for m in finditer(PHP_SQLI, code):
            self.add(sf, sf.line_at(m.start()), "BE001", "Raw SQL query interpolates or concatenates a PHP variable.")
        for m in finditer(PHP_CMDI, code):
            self.add(sf, sf.line_at(m.start()), "BE002", "Shell execution function receives dynamic PHP variables.")
        for m in finditer(BLADE_RAW, raw):
            self.add(sf, sf.line_at(m.start()), "FE001", "Unescaped `{!! ... !!}` output in template/PHP can execute script (XSS).")
        self._loop_n_plus_one(sf, code, PHP_LOOP_DB)
        self._check_timeout(sf, code, PHP_HTTP, "Http::get/post()")
