"""Java and Kotlin: a lexer, Spring and JAX-RS (Quarkus) route discovery, and the security configuration that
decides which routes need a login.

Routes feed the same route checks as Python and JavaScript (AUTH001-AUTH004, AUTH010, LLM004, the API contract
checks). A route counts as authenticated when its method or class has @PreAuthorize, @Secured, @RolesAllowed,
@Authenticated or @PermitAll (deliberately public), or when a Spring Security filter chain (or Quarkus
`quarkus.http.auth.permission`) requires a login for its path.

Known limits: one level of class nesting is followed; paths built from constants (`@GetMapping(Paths.USERS)`)
keep the constant's name; controllers that inherit their mappings from an annotated interface are not matched
to it; Kotlin's nested block comments are read as ending at the first `*/`.
"""
from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Tuple

from .files import Project, SourceFile
from .guard import GUARD
from .heuristics import LLM_HOSTS, PUBLIC_PATH
from .lexer import Views, match_close
from .model import Finding, Route

EXTS = (".java", ".kt", ".kts")
UNSECURED = "spring-unsecured"  # a Spring route in a project with no security configuration (JAVA001)
# a hand-written authentication interceptor or filter, used instead of Spring Security
CUSTOM_AUTH = re.compile(
    r"\bclass\s+\w{0,40}(?:Auth|Login|Jwt|JWT|Token|Session|Apikey|ApiKey|Sso|SSO|Cas)\w{0,40}\s*(?:<[^>{]{0,80}>)?"
    r"(?:\s*\([^)]{0,200}\))?\s*(?::|extends|implements)\s*[^{]{0,200}?\b(?:HandlerInterceptor\w{0,20}|Filter|OncePerRequestFilter"
    r"|GenericFilterBean|WebFilter|ContainerRequestFilter|AsyncHandlerInterceptor)\b")
TOKEN = re.compile(
    r'//[^\n]*'
    r'|/\*.*?(?:\*/|\Z)'
    r'|"""(?:.|\n)*?(?:"""|\Z)'
    r'|"(?:\\.|[^"\\\n])*(?:"|$)'
    r"|'(?:\\.|[^'\\\n]){1,10}'",
    re.S | re.M,
)
_NOT_NL = re.compile(r"[^\n]")


def is_jvm(rel: str) -> bool:
    return rel.endswith(EXTS)


def jvm_views(src: str) -> Views:
    """Offset-preserving views as for the other languages: `code` without comments, `bare` without comments
    and string contents (quotes kept). Strings include Java text blocks and Kotlin raw strings."""
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
            q = 3 if s.startswith('"""') else 1
            end = q if len(s) >= 2 * q and s.endswith(s[0] * q) else 0
            code.append(s)
            bare.append(s[:q] + _NOT_NL.sub(" ", s[q:len(s) - end]) + s[len(s) - end:])
        last = b
    code.append(src[last:])
    bare.append(src[last:])
    return Views("".join(code), "".join(bare), comments)


def views_of(sf: SourceFile) -> Views:
    v = sf.cache.get("jvm_views")
    if v is None:
        v = sf.cache["jvm_views"] = jvm_views(sf.text or "")
    return v  # type: ignore[return-value]


# ------------------------------------------------------------------ annotations
ANNOTATION = re.compile(r"@\s*((?:\w+\s*\.\s*)*\w+)")
STRING = re.compile(r'"((?:\\.|[^"\\\n])*)"')
MAPPINGS = {"GetMapping": ["GET"], "PostMapping": ["POST"], "PutMapping": ["PUT"], "DeleteMapping": ["DELETE"],
            "PatchMapping": ["PATCH"], "RequestMapping": []}
JAXRS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
AUTH_ANNOTATIONS = {"PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed", "Authenticated", "DenyAll", "PermitAll",
                    "PreFilter", "PostFilter"}
LLM_CALL = re.compile(
    r"\.\s*chat\s*\(\s*\)\s*\.\s*completions\s*\(\s*\)|\.\s*createChatCompletion\s*\(|\bChatClient\b|\bchatClient\s*\.\s*prompt\s*\("
    r"|\b(?:chatModel|chatLanguageModel|languageModel|streamingChatModel|model)\s*\.\s*(?:call|generate|chat|stream)\s*\("
    r"|\bAiServices\b|\.\s*messages\s*\(\s*\)\s*\.\s*create\s*\(|\bGenerativeModel\b"
)


class Annotation:
    __slots__ = ("name", "args", "start", "end")

    def __init__(self, name: str, args: str, start: int, end: int):
        self.name, self.args, self.start, self.end = name, args, start, end

    def strings(self) -> List[str]:
        return [m.group(1) for m in STRING.finditer(self.args)]

    def attr(self, key: str) -> Optional[str]:
        """The text of `key = ...` in the arguments (up to the next top-level comma)."""
        m = re.search(r"\b" + key + r"\s*=\s*", self.args)
        if not m:
            return None
        depth, out = 0, []
        for ch in self.args[m.end():]:
            if ch in "({[":
                depth += 1
            elif ch in ")}]":
                if depth == 0:
                    break
                depth -= 1
            elif ch == "," and depth == 0:
                break
            out.append(ch)
        return "".join(out)


def annotations(code: str, bare: str, a: int, b: int) -> List[Annotation]:
    """Annotations between offsets a and b, with their argument text (from `code`, so strings are kept)."""
    out = []
    i = a
    while True:
        m = ANNOTATION.search(bare, i, b)
        if not m:
            return out
        name = m.group(1).rsplit(".", 1)[-1].strip()
        j = m.end()
        while j < b and bare[j] in " \t\r\n":
            j += 1
        args, end = "", m.end()
        if j < b and bare[j] == "(":
            close = match_close(bare, j)
            if close > 0:
                args, end = code[j + 1:close], close + 1
        out.append(Annotation(name, args, m.start(), end))
        i = max(end, m.end())


# ------------------------------------------------------------------ classes and members
CLASS = re.compile(r"\b(?:class|interface|object)\s+(\w+)")
FUN = re.compile(r"\bfun\s+(?:<[^>]*>\s*)?(?:[\w.]+\.)?(\w+)\s*\(")
JAVA_METHOD = re.compile(r"\b(\w+)\s*\(")  # \b: start only at a word boundary (linear time)


def _boundary_before(bare: str, start: int, i: int) -> int:
    """Offset just after the last `;`, `{` or `}` between `start` and `i` (the start of this member's text)."""
    k = max(bare.rfind(";", start, i), bare.rfind("}", start, i), bare.rfind("{", start, i))
    return k + 1 if k >= 0 else start


def _depth1_spans(bare: str, a: int, b: int) -> List[Tuple[int, int]]:
    """Top-level runs of a class body (between a and b), skipping nested blocks."""
    spans, i, run = [], a, a
    while i < b:
        ch = bare[i]
        if ch == "{":
            close = match_close(bare, i)
            if close < 0:
                break
            spans.append((run, i))
            i = close + 1
            run = i
            continue
        i += 1
    spans.append((run, b))
    return spans


def _method_after(code: str, bare: str, i: int, end: int) -> Optional[Tuple[str, int, int, int]]:
    """(name, offset of the parameter list, offset of the end of the parameters, end of the body) of the method
    declared after the annotations that end at i."""
    j = i
    while True:  # skip further annotations
        while j < end and bare[j] in " \t\r\n":
            j += 1
        if j < end and bare[j] == "@":
            m = ANNOTATION.match(bare, j)
            if not m:
                return None
            j = m.end()
            k = j
            while k < end and bare[k] in " \t\r\n":
                k += 1
            if k < end and bare[k] == "(":
                c = match_close(bare, k)
                if c < 0:
                    return None
                j = c + 1
            continue
        break
    m = FUN.search(bare, j, end) or JAVA_METHOD.search(bare, j, end)
    if not m or bare.find("{", j, m.start()) >= 0 or bare.find(";", j, m.start()) >= 0:
        return None
    po = m.end() - 1
    pc = match_close(bare, po)
    if pc < 0:
        return None
    k = pc + 1
    nxt = re.compile(r"[{;=]").search(bare, k, end)
    if nxt is None:
        return m.group(1), po, pc, pc + 1
    if bare[nxt.start()] == "{":
        c = match_close(bare, nxt.start())
        return m.group(1), po, pc, (c + 1 if c > 0 else end)
    if bare[nxt.start()] == "=":  # Kotlin expression body: up to the end of the line
        nl = bare.find("\n", nxt.start())
        return m.group(1), po, pc, nl if nl > 0 else end
    return m.group(1), po, pc, nxt.start() + 1


def _join(base: str, sub: str) -> str:
    path = "/" + "/".join(p.strip("/") for p in (base, sub) if p and p.strip("/"))
    return path if path != "/" or not (base or sub) else "/"


def _paths(a: Annotation) -> List[str]:
    for key in ("value", "path"):
        v = a.attr(key)
        if v is not None:
            return [m.group(1) for m in STRING.finditer(v)] or [v.strip()]
    if a.args.strip() and "=" not in a.args.split('"', 1)[0]:
        got = a.strings()
        if got:
            return got
        first = a.args.split(",", 1)[0].strip()
        return [first] if first else [""]
    return [""]


def _methods(a: Annotation) -> List[str]:
    if a.name in MAPPINGS and MAPPINGS[a.name]:
        return MAPPINGS[a.name]
    v = a.attr("method")
    if v:
        got = re.findall(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b", v)
        if got:
            return sorted(set(got), key=got.index)
    return ["ALL"]


def file_routes(sf: SourceFile, security: "Security") -> List[Route]:
    text = sf.text or ""
    if not re.search(r"@\s*(?:\w+\.)*(?:RestController|Controller|Path)\b", text):
        return []
    v = views_of(sf)
    code, bare = v.code, v.bare
    routes: List[Route] = []
    for cm in CLASS.finditer(bare):
        open_brace = bare.find("{", cm.end())
        if open_brace < 0 or bare.find(";", cm.end(), open_brace) >= 0:
            continue
        close = match_close(bare, open_brace)
        if close < 0:
            continue
        head_start = _boundary_before(bare, 0, cm.start())
        cls = annotations(code, bare, head_start, cm.start())
        names = {a.name for a in cls}
        spring = bool(names & {"RestController", "Controller"})
        jaxrs = "Path" in names
        if not spring and not jaxrs:
            continue
        base = ""
        for a in cls:
            if a.name in ("RequestMapping", "Path"):
                base = _paths(a)[0]
        class_auth = bool(names & AUTH_ANNOTATIONS)
        for a0, b0 in _depth1_spans(bare, open_brace + 1, close):
            for ann_group in _member_groups(code, bare, a0, b0):
                routes.extend(_routes_for(sf, code, bare, ann_group, b0, close, base, spring, class_auth, security))
    return routes


def _member_groups(code: str, bare: str, a: int, b: int) -> List[List[Annotation]]:
    """Runs of annotations at the top level of a class body, one run per member."""
    anns = annotations(code, bare, a, b)
    groups: List[List[Annotation]] = []
    for an in anns:
        if groups and not bare[groups[-1][-1].end:an.start].strip():
            groups[-1].append(an)
        else:
            groups.append([an])
    return groups


def _routes_for(sf: SourceFile, code: str, bare: str, group: List[Annotation], span_end: int, class_end: int, base: str,
                spring: bool, class_auth: bool, security: "Security") -> List[Route]:
    mapping = next((a for a in group if a.name in MAPPINGS), None) if spring else None
    verb = next((a for a in group if a.name in JAXRS), None)
    if mapping is None and verb is None:
        return []
    method = _method_after(code, bare, group[-1].end, class_end)
    if method is None:
        return []
    name, po, pc, body_end = method
    start = group[0].start
    body = code[start:body_end]
    params_text = code[po + 1:pc]
    if mapping is not None:
        subpaths, verbs = _paths(mapping), _methods(mapping)
        framework = "spring"
    else:
        sub = next((a for a in group if a.name == "Path"), None)
        subpaths, verbs, framework = ([_paths(sub)[0]] if sub else [""]), [verb.name], "jax-rs"  # type: ignore[union-attr]
    names = {a.name for a in group}
    explicit = class_auth or bool(names & AUTH_ANNOTATIONS)
    out = []
    for sub in subpaths:
        path = _join(base, sub)
        params = re.findall(r"\{(\w+)(?::[^}]*)?\}", path)
        params += [p for p in re.findall(r"@\s*(?:PathVariable|PathParam)\b[^,)]*?\b(\w+)\s*(?::|,|\)|$)", params_text) if p not in params]
        has_auth = explicit or security.protects(path, verbs)
        out.append(Route(sf.rel, sf.line_at(start), path, verbs, body, framework, "jvm", has_auth=has_auth,
                         calls_llm=bool(LLM_CALL.search(body) or LLM_HOSTS.search(body)),
                         reads_body=bool(re.search(r"@\s*RequestBody\b", params_text)) or framework == "jax-rs" and "POST" in verbs,
                         params=params))
    return out


# ------------------------------------------------------------------ security configuration
MATCHERS = re.compile(r"\b(?:requestMatchers|antMatchers|mvcMatchers|pathMatchers|regexMatchers)\s*\(")
DSL_AUTHORIZE = re.compile(r"\bauthorize\s*\(\s*(?:HttpMethod\.\w+\s*,\s*)?(\"[^\"]*\"|anyRequest)\s*,\s*(\w+)")
OPEN = ("permitAll", "anonymous")


def _ant(pattern: str) -> "re.Pattern[str]":
    out = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("/**", i):
            out += r"(?:/.*)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "{":
            j = pattern.find("}", i)
            out += "[^/]+"
            i = j + 1 if j > i else i + 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out + "/?$")


class Security:
    """What the project's Spring Security filter chain (or Quarkus configuration) requires, path by path."""

    def __init__(self) -> None:
        self.present = False  # a filter chain or security configuration exists
        self.rules: List[Tuple["re.Pattern[str]", bool]] = []  # (path pattern, needs login), in declaration order
        self.default: Optional[bool] = None  # anyRequest(): True = login, False = open
        self.custom = False  # a hand-written auth HandlerInterceptor or servlet filter (no Spring Security chain)

    def protects(self, path: str, verbs: List[str]) -> bool:
        if self.custom and not self.rules and self.default is None:
            return True  # its paths cannot be read statically, so a route is not guessed to be public
        for rule in self.rules:
            rx, needs = rule[0], rule[1]
            only = rule[2] if len(rule) > 2 else None  # type: ignore[misc]
            if only and not ({v.upper() for v in verbs} & only or "ALL" in {v.upper() for v in verbs}):
                continue  # a matcher scoped to other HTTP methods
            if rx.match(path):
                return needs
        return bool(self.default)

    @classmethod
    def of(cls, project: Project) -> "Security":
        sec = cls()
        for sf in project.files:
            if sf.text is None:
                continue
            if is_jvm(sf.rel) and re.search(r"SecurityFilterChain|WebSecurityConfigurerAdapter|SecurityWebFilterChain"
                                            r"|authorizeHttpRequests|authorizeRequests|authorizeExchange|EnableWebSecurity", sf.text):
                sec.present = True
                sec._spring(views_of(sf))
            elif re.search(r"(?:^|/)application[\w-]*\.(?:properties|ya?ml)$", sf.rel) and "quarkus.http.auth.permission" in sf.text:
                sec.present = True
                sec._quarkus(sf.text)
            if is_jvm(sf.rel) and not sf.is_test and CUSTOM_AUTH.search(sf.text):
                sec.present = sec.custom = True
        return sec

    def _spring(self, v: Views) -> None:
        code, bare = v.code, v.bare
        for m in MATCHERS.finditer(bare):
            close = match_close(bare, m.end() - 1)
            if close < 0:
                continue
            patterns = [s for s in STRING.findall(code[m.end():close]) if s.startswith("/")]
            # `antMatchers(HttpMethod.GET, "/articles/**")` applies to GET only
            scoped = set(re.findall(r"\bHttpMethod\s*\.\s*([A-Z]+)", code[m.end():close]))
            rest = bare[close + 1:close + 200]
            act = re.match(r"\s*\.\s*(\w+)", rest)
            if not patterns or not act:
                continue
            needs = act.group(1) not in OPEN
            self.rules += [(_ant(p), needs, scoped) for p in patterns]  # type: ignore[misc]
        m = re.search(r"\banyRequest\s*\(\s*\)\s*\.\s*(\w+)", bare)
        if m:
            self.default = m.group(1) not in OPEN
        elif re.search(r"\.\s*anyExchange\s*\(\s*\)\s*\.\s*(\w+)", bare):
            self.default = re.search(r"\.\s*anyExchange\s*\(\s*\)\s*\.\s*(\w+)", bare).group(1) not in OPEN  # type: ignore[union-attr]
        for m in DSL_AUTHORIZE.finditer(code):  # Kotlin DSL: authorize("/x/**", permitAll)
            target, act = m.group(1), m.group(2)
            if target == "anyRequest":
                self.default = act not in OPEN
            else:
                self.rules.append((_ant(target.strip('"')), act not in OPEN))
        if self.default is None and re.search(r"\.\s*authenticated\s*\(\s*\)|\bhasRole\s*\(|\bhasAuthority\s*\(", bare) and not self.rules:
            self.default = True

    def _quarkus(self, text: str) -> None:
        perms: Dict[str, Dict[str, str]] = {}
        for m in re.finditer(r"(?m)^\s*quarkus\.http\.auth\.permission\.([\w-]+)\.(paths|policy)\s*[=:]\s*(.+?)\s*$", text):
            perms.setdefault(m.group(1), {})[m.group(2)] = m.group(3)
        for p in perms.values():
            needs = p.get("policy", "authenticated") not in ("permit",)
            for path in p.get("paths", "").split(","):
                path = path.strip()
                if path in ("/*", "/**", "/"):
                    self.default = needs
                elif path:
                    self.rules.append((_ant(path.replace("/*", "/**") if path.endswith("/*") else path), needs))


def routes(project: Project, security: Optional[Security] = None) -> List[Route]:
    security = security or Security.of(project)
    out: List[Route] = []
    for sf in project.files:
        if sf.text is not None and is_jvm(sf.rel) and not sf.is_test:
            got = GUARD.run(sf.rel, "Java checks", file_routes, sf, security)
            out.extend(got or [])
    return out


class JvmScanner:
    """Java and Kotlin: routes for the shared route checks, and the JAVA rules."""

    def __init__(self, project: Project, emit: Callable[[Finding], None]):
        self.p = project
        self.emit = emit

    def add(self, sf: SourceFile, rule: str, line: int, msg: str, sev: str = "") -> None:
        self.emit(Finding(rule, sf.rel, line, msg, sev, sf.line(line).strip()[:200]))

    def run(self) -> List[Route]:
        if not any(is_jvm(sf.rel) for sf in self.p.files):
            return []
        security = Security.of(self.p)
        found = routes(self.p, security)
        if not security.present:
            self._no_security(found)
            for r in found:  # JAVA001 reports these once per controller; AUTH001 skips them
                if r.framework == "spring":
                    r.framework = UNSECURED
        from . import jvmconfig, jvmsinks

        jvmconfig.run(self.p, security.present, self.add)
        for sf in self.p.files:
            if is_jvm(sf.rel) and sf.text is not None and not sf.is_test and not sf.is_example:
                GUARD.run(sf.rel, "JVM data flow", jvmsinks.check, sf, views_of(sf), self.add)
        return found

    def _no_security(self, found: List[Route]) -> None:
        """JAVA001: Spring controllers in a project with no Spring Security configuration at all."""
        by_file: Dict[str, List[Route]] = {}
        for r in found:
            if r.framework == "spring":
                by_file.setdefault(r.file, []).append(r)
        for rel, rs in sorted(by_file.items()):
            open_routes = [r for r in rs if not r.has_auth and not PUBLIC_PATH.search(r.path)]
            if not open_routes:
                continue
            sf = self.p.get(rel)
            if sf is None:
                continue
            first = min(open_routes, key=lambda r: r.line)
            self.add(sf, "JAVA001", first.line,
                     f"{len(open_routes)} endpoints in this controller have no @PreAuthorize, @Secured or @RolesAllowed, "
                     "and the project configures no Spring Security filter chain, so anyone can call them.")
