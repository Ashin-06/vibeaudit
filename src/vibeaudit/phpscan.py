"""PHP support: a linear lexer, route discovery for Laravel and Symfony, and a per-function data flow from request
input (and the superglobals, for plain PHP pages) into the generic injection rules: BE001 SQL, BE002 commands,
BE003 eval, BE004 unserialize, BE005 outbound URLs, BE006 file paths, BE008 redirects and FE001 echoed HTML.
Routes feed the shared route checks (AUTH001-AUTH004, AUTH010, LLM004). N+1 queries and HTTP client timeouts stay
in polyscan.

Known limits: a function's taint comes from its own request reads and parameters, not from functions it calls;
routes registered from service providers or packages are not followed; Laravel's automatic `/api` prefix is
assumed for routes/api.php; a Blade `{!! !!}` is reported unless the value goes through a known sanitizer.
"""
from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Set, Tuple

from . import heuristics as H
from .files import Project, SourceFile
from .goscan import _split_top
from .guard import GUARD, finditer
from .lexer import Views, match_close
from .model import Finding, Route

Emit = Callable[[Finding], None]

# ------------------------------------------------------------------ lexer
OPEN_TAG = re.compile(r"<\?(?:php\b|=)?", re.I)
TOKEN = re.compile(r"""//|\#(?!\[)|/\*|'|"|`|<<<[ \t]*(['"]?)([A-Za-z_]\w*)\1|\?>""")
SINGLE = re.compile(r"'(?:\\.|[^'\\])*(?:'|\Z)", re.S)
DOUBLE = re.compile(r'"(?:\\.|[^"\\])*(?:"|\Z)', re.S)
BACKTICK = re.compile(r"`(?:\\.|[^`\\])*(?:`|\Z)", re.S)
_NOT_NL = re.compile(r"[^\n]")


def php_views(src: str) -> Views:
    """Offset-preserving views of the PHP code: `code` without comments and inline HTML, `bare` also without string
    contents. A file with no `<?php` tag (a Blade template) is all HTML: both views are blank."""
    code: List[str] = []
    bare: List[str] = []
    comments: List[Tuple[int, int]] = []
    n = len(src)
    pos = 0
    html = True

    def blank(a: int, b: int) -> None:
        s = _NOT_NL.sub(" ", src[a:b])
        code.append(s)
        bare.append(s)

    while pos < n:
        if html:
            m = OPEN_TAG.search(src, pos)
            end = m.end() if m else n
            blank(pos, end)
            pos, html = end, False
            continue
        m = TOKEN.search(src, pos)
        if not m:
            code.append(src[pos:])
            bare.append(src[pos:])
            break
        code.append(src[pos:m.start()])
        bare.append(src[pos:m.start()])
        a, t = m.start(), m.group(0)
        if t == "?>":
            blank(a, m.end())
            pos, html = m.end(), True
            continue
        if t in ("//", "#"):
            nl = src.find("\n", a)
            nl = n if nl < 0 else nl
            close = src.find("?>", a, nl)
            b = close if close >= 0 else nl
            blank(a, b)
            comments.append((a, b))
            pos = b
            continue
        if t == "/*":
            b = src.find("*/", a + 2)
            b = n if b < 0 else b + 2
            blank(a, b)
            comments.append((a, b))
            pos = b
            continue
        if t.startswith("<<<"):
            ident = m.group(2)
            body_start = src.find("\n", m.end())
            body_start = n if body_start < 0 else body_start + 1
            close = re.compile(r"(?m)^[ \t]*" + re.escape(ident) + r"\b").search(src, body_start)
            b = close.end() if close else n
            body_end = close.start() if close else n
            code.append(src[a:b])
            bare.append(src[a:body_start] + _NOT_NL.sub(" ", src[body_start:body_end]) + src[body_end:b])
            pos = b
            continue
        rx = SINGLE if t == "'" else DOUBLE if t == '"' else BACKTICK
        sm = rx.match(src, a)
        b = sm.end() if sm else n
        s = src[a:b]
        closed = len(s) >= 2 and s[-1] == t
        code.append(s)
        bare.append(t + _NOT_NL.sub(" ", s[1:-1] if closed else s[1:]) + (t if closed else ""))
        pos = b
    return Views("".join(code), "".join(bare), comments)


def is_php(sf: SourceFile) -> bool:
    return sf.rel.endswith(".php") and not sf.rel.endswith(".blade.php") and sf.text is not None


# ------------------------------------------------------------------ patterns
FN_DECL = re.compile(r"\bfunction\s+&?\s*(\w+)\s*\(")
CLASS_DECL = re.compile(r"\b(?:class|trait)\s+(\w+)[^{;]{0,300}\{")
VERBS = ("get", "post", "put", "patch", "delete", "options", "any", "match")
ROUTE_CALL = re.compile(r"(?:\bRoute\s*::\s*|->\s*)(get|post|put|patch|delete|options|any|match)\s*\(")
RESOURCE = re.compile(r"\bRoute\s*::\s*(resource|apiResource)\s*\(")
GROUP = re.compile(r"(?:\bRoute\s*::\s*group|->\s*group)\s*\(")
SYMFONY_ATTR = re.compile(r"#\[\s*(?:\\?Symfony\\Component\\Routing\\Attribute\\|\\?Symfony\\Component\\Routing\\Annotation\\)?Route\s*\(")
SYMFONY_ANNOTATION = re.compile(r"@Route\s*\(")
STRING_LIT = re.compile(r"""'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)\"""")
PHP_AUTH = re.compile(
    r"""(?i)\$this\s*->\s*authorize\w*\s*\(|\bGate\s*::\s*(?:authorize|allows|denies|check|any|none|inspect)\s*\("""
    r"""|\bauth\s*\(\s*\)\s*->\s*(?:user|id|check|guest)\s*\(|\bAuth\s*::\s*(?:user|id|check|guest|guard)\s*\("""
    r"""|\$request\s*->\s*user\s*\(|\babort_(?:if|unless)\s*\([^;]{0,200}40[13]|\babort\s*\(\s*40[13]"""
    r"""|denyAccessUnlessGranted\s*\(|\$this\s*->\s*getUser\s*\(|\bisGranted\s*\(|#\[\s*(?:IsGranted|CurrentUser)\b"""
    r"""|\bdvwaCurrentUser\s*\(|\$_SESSION\s*\[\s*['"](?:user|username|user_id|logged_?in|uid|id)['"]""")
AUTH_MW = re.compile(H.AUTH_MIDDLEWARE.pattern + r"|\bcan:|\bverified\b|\bsanctum\b|\bpassport\b|\bpermission:|\brole:")
# Laravel middleware: `auth`, `auth:sanctum`, `can:...`, `ApiAuthenticate::class`; not session, CSRF or cookie middleware
LARAVEL_AUTH = re.compile(r"(?i)(?<![\w-])auth(?::[\w,]+)?(?![\w-])|\b(?!AuthenticateSession)\w*Authenticat\w*|\b\w*Authori[sz]e\w*"
                          r"|\bauthorize:|\bcan:|\brole:|\bpermission:|\bverified\b|\bsanctum\b|\bpassport\b|\bjwt\b|\bjwt\.")
INCLUDE = re.compile(r"\b(?:require|include)(?:_once)?\s*\(?\s*(?:__DIR__\s*\.\s*['\"]|base_path\s*\(\s*['\"])([^'\"]+\.php)['\"]")
SOURCE = re.compile(
    r"""\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|\$_SERVER\s*\[\s*['"](?:HTTP_\w+|QUERY_STRING|REQUEST_URI|PHP_SELF|PATH_INFO)['"]"""
    r"""|\$request\s*->\s*(?:input|get|query|post|all|json|route|header|cookie|file|string|str|integer|boolean|only|except|validated|safe|getContent|toArray)\s*\("""
    r"""|\$request\s*->\s*(?:query|request|attributes|headers|cookies|files)\s*->\s*(?:get|all)\s*\("""
    r"""|\brequest\s*\(\s*['"]|\bRequest\s*::\s*(?:input|get|query|all)\s*\(|\bInput\s*::\s*(?:get|all)\s*\("""
    r"""|\$request\s*->\s*(?!(?:user|session|route|ip|method|path|url|fullUrl|is|has|filled|missing|wantsJson|expectsJson|ajax"""
    r"""|headers|cookies|files|attributes|query|request|server|validate|merge|replace|setUserResolver|getMethod|isMethod)\b)[a-z_]\w*\b(?!\s*\()""")
ASSIGN = re.compile(r"(\$\w+)\s*(?:\[[^\]\n]{0,80}\]\s*)?(?:\.=|=)(?![=>])")
SANITIZERS = re.compile(
    r"""(?i)\b(?:htmlspecialchars|htmlentities|e|esc_html|esc_attr|strip_tags|intval|floatval|abs|count|md5|sha1|hash"""
    r"""|password_hash|basename|is_numeric|ctype_digit|filter_var|escapeshellarg|escapeshellcmd|mysqli_real_escape_string"""
    r"""|real_escape_string|addslashes|quote|urlencode|rawurlencode|json_encode|clean|purify|Purifier::clean)\s*\(|\(\s*int\s*\)""")
SINKS = [
    (re.compile(r"\bDB\s*::\s*(?:select|selectOne|statement|insert|update|delete|unprepared|raw|cursor|scalar)\s*\("
                r"|->\s*(?:whereRaw|orWhereRaw|selectRaw|orderByRaw|havingRaw|groupByRaw|fromRaw|executeQuery|executeStatement|createQuery|createNativeQuery)\s*\("
                r"|(?:\$\w*(?:pdo|db|dbh|conn|connection|mysqli|link|database|wpdb)|\$(?:GLOBALS\s*\[[^\]]{1,40}\])\w*|->\s*(?:db|pdo|conn|connection|database)\w*"
                r"|\bDB\s*::\s*connection\s*\([^()]*\))\s*->\s*(?:query|exec|prepare|multi_query|real_query)\s*\("
                r"|\b(?:mysql_query|pg_query|sqlite_query|mysqli_multi_query)\s*\("),
     "BE001", "a SQL query", "high", 0),
    (re.compile(r"\b(?:mysqli_query|mysqli_prepare|mysqli_real_query)\s*\("), "BE001", "a SQL query", "high", 1),
    (re.compile(r"(?<![>:$\\])\b(?:shell_exec|exec|system|passthru|popen|proc_open|pcntl_exec)\s*\("), "BE002", "a shell command", "critical", 0),
    (re.compile(r"(?<![>:$\\])\b(?:eval|create_function)\s*\("), "BE003", "eval()", "critical", 0),
    (re.compile(r"(?<![>:$\\])\bunserialize\s*\("), "BE004", "unserialize()", "high", 0),
    (re.compile(r"\bHttp\s*::\s*(?:\w+\([^()]*\)\s*->\s*)*(?:get|post|put|patch|delete|head)\s*\(|\bcurl_init\s*\("),
     "BE005", "an outbound HTTP request URL", "high", 0),
    (re.compile(r"(?<![>:$\\])\b(?:include|include_once|require|require_once)\b\s*\(?|(?<![>:$\\])\b(?:file_get_contents|fopen|file|readfile|unlink|"
                r"file_put_contents|is_file|file_exists|opendir|scandir|copy|rename|move_uploaded_file)\s*\("
                r"|\bStorage\s*::\s*(?:disk\([^()]*\)\s*->\s*)?(?:get|delete|download|put|readStream|path)\s*\("
                r"|->\s*download\s*\(|\bnew\s+(?:BinaryFileResponse|SplFileObject)\s*\("),
     "BE006", "a file system path", "high", 0),
    (re.compile(r"\bredirect\s*\(\s*(?=[^)\s])|\bredirect\s*\(\s*\)\s*->\s*(?:to|away)\s*\(|\bRedirect\s*::\s*(?:to|away)\s*\("
                r"|\bnew\s+RedirectResponse\s*\(|\$this\s*->\s*redirect\s*\(|(?<![>:$\\])\bheader\s*\("),
     "BE008", "a redirect target", "medium", 0),
    (re.compile(r"\b(?:echo|print)\b\s*\(?"), "FE001", "the HTML response", "high", 0),
]
BLADE_RAW = re.compile(r"\{!!\s*(.{1,200}?)\s*!!\}")
BLADE_SAFE = re.compile(r"(?i)^\$(?:slot|attributes)\b|\b(?:clean|purify|Purifier::clean|e|htmlspecialchars|strip_tags|json_encode|"
                        r"csrf_field|method_field|old|trans|__|Js::from|@json|svg|vite|mix|asset)\s*\(|->toHtml\s*\(|^\$\w*(?:svg|icon)\w*$"
                        # HTML the application builds itself: presenters, rendered views, pagination links, `$help_html`
                        r"|->\s*(?:present|render|links|toHtml)\s*\(|(?:html|link|url|div|icon|svg|badge|button|markup|tag)\w{0,3}"
                        r"(?:\s*\(\s*\))?\s*$"
                        # a choice between constant strings: `$errors->has('notes') ? ' has-error' : ''`
                        r"|\?\s*(['\"])[^'\"$]*\1\s*:\s*(['\"])[^'\"$]*\2\s*$")
SHELL_LIKE = re.compile(r"(?i)^\s{0,40}(?:['\"]\s{0,40})?(?:sh|bash|ls|cat|ping|nslookup|cd|rm|cp|mv|git|convert|ffmpeg|php|python|curl|wget)\b")
SQL_WORDS = re.compile(r"(?i)\b(?:select\b[\s\S]{0,200}\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b")
# a redirect to a path on this site, to a fixed host, or to a URL the router builds is not an open redirect
LOCAL_TARGET = re.compile(r"""\s{0,40}(?:['"](?:/(?!/)|https?://[\w.-]+(?:[:/?'"]|$))|(?:\$this\s*->\s*)?(?:route|url|action|generateUrl|"""
                          r"""redirectToRoute|path)\s*\(|(?:url|URL)\s*(?:\(\s*\))?\s*(?:::|->)\s*(?:route|to|action|signedRoute|temporarySignedRoute)\s*\("""
                          # a helper that checks the target: Helper::sameOriginUrl(), wallabag's $this->redirectHelper->to()
                          r"""|[\w\\:$>-]{0,80}(?i:same_?origin|safe|internal|local|validated?)\w{0,40}(?i:url|redirect|target)\w{0,40}\s*\("""
                          r"""|(?:\$this\s*->\s*)?\w{0,40}redirect_?helper\w{0,40}\s*->\s*\w+\s*\()""", re.I)
SANITIZED = re.compile(r"\s{0,40}(?:" + SANITIZERS.pattern[4:] + ")", re.I)  # a value that starts with a sanitizer


def _strings(text: str) -> List[str]:
    return [a if a is not None else b for a, b in STRING_LIT.findall(text)]


def _join(prefix: str, path: str) -> str:
    p = "/".join(x.strip("/") for x in (prefix, path) if x and x.strip("/"))
    return "/" + p


def _singular(name: str) -> str:
    name = name.replace("-", "_")
    if name.endswith("ies"):
        return name[:-3] + "y"
    return name[:-1] if name.endswith("s") and not name.endswith("ss") else name


CONST_CHOICE = re.compile(r"""\?\s*(['"])[^'"$]*\1\s*:\s*(['"])[^'"$]*\2\s*$""")
CAST = re.compile(r"""\((?:int|float|bool)\)\s*\(?\s*\$\w+(?:\s*->\s*\w+\s*\([^()]*\))*\s*\)?|\b(?:intval|floatval|abs)\s*\([^()]*\)""")


def _clean(value: str) -> bool:
    """A value that cannot carry request text: a sanitizer, a choice between constant strings
    (`$request->input('order') === 'asc' ? 'asc' : 'desc'`), or arithmetic on (int) casts."""
    v = value.strip().rstrip(";")
    if SANITIZED.match(v) or CONST_CHOICE.search(v):
        return True
    rest = CAST.sub("0", v)
    return rest != v and not re.search(r"\$\w|\brequest\s*\(", rest)


def _names(text: str) -> Set[str]:
    return set(re.findall(r"\$\w+", text))


def _mentions(text: str, names: Set[str]) -> bool:
    return any(re.search(re.escape(nm) + r"\b", text) for nm in names) if names else False


class PhpScanner:
    def __init__(self, project: Project, emit: Emit):
        self.p = project
        self.emit = emit
        self.files: List[SourceFile] = []
        self.funcs: Dict[str, List[Tuple[SourceFile, int, int, int, int]]] = {}  # name -> (sf, start, (, ), end)
        self.classes: Dict[str, Tuple[SourceFile, int, int]] = {}  # name -> (sf, start, end)
        self.routes: List[Route] = []
        self.handlers: Dict[Tuple[str, int], Set[str]] = {}  # handler -> route params
        self.access: List[Tuple[str, bool]] = []  # Symfony access_control: (path regex, requires a user)
        self.mw_groups: Dict[str, str] = {}  # Laravel middleware group -> its members (Kernel.php, bootstrap/app.php)
        self.included: Dict[str, Tuple[str, str]] = {}  # route file -> (prefix, middleware) of the group that requires it

    def add(self, sf: SourceFile, off: int, rule: str, msg: str, sev: str = "") -> None:
        line = sf.line_at(off)
        self.emit(Finding(rule, sf.rel, line, msg, sev, sf.line(line).strip()[:200]))

    def run(self) -> List[Route]:
        self.files = [f for f in self.p.files if is_php(f) and not f.is_test and not re.search(r"(?:^|/)vendor/", f.rel)]
        if not self.files and not any(f.rel.endswith(".blade.php") for f in self.p.files):
            return []
        self._security_yaml()
        for sf in self.files:
            GUARD.run(sf.rel, "PHP lexing", self._load, sf)
        for sf in self.files:
            GUARD.run(sf.rel, "Laravel middleware groups", self._middleware_groups, sf)
        for sf in self.files:
            if "->group(" in (sf.text or "") or "Route::group" in (sf.text or ""):
                GUARD.run(sf.rel, "Laravel route includes", self._includes, sf)
        for sf in self.files:
            GUARD.run(sf.rel, "PHP routes", self._routes, sf)
        for sf in self.files:
            GUARD.run(sf.rel, "PHP checks", self._checks, sf)
        for sf in self.p.files:
            if sf.rel.endswith(".blade.php") and sf.text and not sf.is_test:
                GUARD.run(sf.rel, "Blade output", self._blade, sf)
        return self.routes

    # ------------------------------------------------------------------ index
    def _load(self, sf: SourceFile) -> None:
        v = php_views(sf.text or "")
        sf.cache["php_views"] = v
        bare = v.bare
        for m in finditer(FN_DECL, bare):
            po = m.end() - 1
            pc = match_close(bare, po)
            if pc < 0:
                continue
            brace = bare.find("{", pc)
            semi = bare.find(";", pc)
            if brace < 0 or (0 <= semi < brace):
                continue  # abstract or interface method
            end = match_close(bare, brace)
            if end > 0:
                self.funcs.setdefault(m.group(1), []).append((sf, m.start(), po, pc, end + 1))
        for m in finditer(CLASS_DECL, bare):
            end = match_close(bare, m.end() - 1)
            if end > 0:
                self.classes.setdefault(m.group(1), (sf, m.start(), end + 1))

    def _method(self, cls: str, name: str) -> Optional[Tuple[SourceFile, int, int, int, int]]:
        c = self.classes.get(cls.rsplit("\\", 1)[-1])
        if c is None:
            return None
        sf, a, b = c
        return next((f for f in self.funcs.get(name, []) if f[0] is sf and a <= f[1] < b), None)

    def _class_of(self, sf: SourceFile, at: int) -> Optional[Tuple[str, int, int]]:
        best = None
        for name, (f, a, b) in self.classes.items():
            if f is sf and a <= at < b and (best is None or a > best[1]):
                best = (name, a, b)
        return best

    def _class_auth(self, cls: str, method: str) -> bool:
        """Controller middleware: `$this->middleware('auth')` in the constructor (minus ->except([...]) / outside
        ->only([...])), Laravel 11 `public static function middleware()`, or `#[IsGranted]` / `#[Middleware]` on the class."""
        c = self.classes.get(cls.rsplit("\\", 1)[-1])
        if c is None:
            return False
        sf, a, b = c
        code = sf.cache["php_views"].code  # type: ignore[attr-defined]
        head = code[max(0, a - 400):a]
        attrs = re.search(r"(?:#\[[^\]]{0,300}\]\s*)+(?:final\s+|abstract\s+|readonly\s+)*\Z", head)
        if attrs and (re.search(r"#\[\s*IsGranted", attrs.group(0)) or AUTH_MW.search(" ".join(_strings(attrs.group(0))))):
            return True
        body = code[a:b]
        for m in re.finditer(r"\$this\s*->\s*middleware\s*\(([^;]{0,400});", body):
            args = m.group(1)
            first = args.split(")", 1)[0]
            if not any(AUTH_MW.search(s) for s in _strings(first)):
                continue
            only = re.search(r"->\s*only\s*\(([^)]*)\)", args)
            except_ = re.search(r"->\s*except\s*\(([^)]*)\)", args)
            if only and method not in _strings(only.group(1)):
                continue
            if except_ and method in _strings(except_.group(1)):
                continue
            return True
        mw = re.search(r"\bstatic\s+function\s+middleware\s*\([^)]*\)[^{]*\{([^}]{0,1500})\}", body)
        if mw:
            for item in re.finditer(r"new\s+Middleware\s*\(([^)]*)\)|(['\"][^'\"]+['\"])", mw.group(1)):
                text = item.group(1) or item.group(2)
                names = _strings(text)
                if not names or not AUTH_MW.search(names[0]):
                    continue
                only = re.search(r"only\s*:\s*\[([^\]]*)\]", text)
                except_ = re.search(r"except\s*:\s*\[([^\]]*)\]", text)
                if (only and method not in _strings(only.group(1))) or (except_ and method in _strings(except_.group(1))):
                    continue
                return True
        return False

    # ------------------------------------------------------------------ Symfony security.yaml
    def _security_yaml(self) -> None:
        for f in self.p.files:
            if not re.search(r"(?:^|/)security\.ya?ml$", f.rel) or not f.text:
                continue
            for m in re.finditer(r"\{\s*path\s*:\s*['\"]?([^,'\"}]+)['\"]?\s*,\s*([^}]*)\}", f.text):
                rest = m.group(2)
                roles = re.search(r"roles\s*:\s*\[?([^\]}]*)", rest)
                needs = bool(roles) and not re.search(r"PUBLIC_ACCESS|IS_AUTHENTICATED_ANONYMOUSLY", roles.group(1) if roles else "")
                self.access.append((m.group(1).strip(), needs))

    def _access_protects(self, path: str) -> bool:
        for rx, needs in self.access:  # the first matching rule wins, as in Symfony
            try:
                if re.search(rx, path):
                    return needs
            except re.error:
                continue
        return False

    # ------------------------------------------------------------------ routes
    def _routes(self, sf: SourceFile) -> None:
        v = sf.cache["php_views"]
        code, bare = v.code, v.bare  # type: ignore[attr-defined]
        if "Route" in code:
            self._laravel(sf, code, bare)
        if re.search(r"#\[\s*(?:\\?[\w\\]*\\)?Route\s*\(", code) or "@Route" in (sf.text or ""):
            self._symfony(sf, code, bare)

    def _middleware_groups(self, sf: SourceFile) -> None:
        """`protected $middlewareGroups = ['api' => [...]]` (Kernel.php) and `$middleware->group('api', [...])`,
        `$middleware->api(append: [...])` (bootstrap/app.php, Laravel 11)."""
        code = sf.cache["php_views"].code  # type: ignore[attr-defined]
        if "middleware" not in code.lower():
            return
        m = re.search(r"\$middlewareGroups\s*=\s*\[", code)
        if m:
            for g in re.finditer(r"['\"](\w+)['\"]\s*=>\s*\[([^\]]*)\]", code[m.end():m.end() + 6000]):
                self.mw_groups[g.group(1)] = self.mw_groups.get(g.group(1), "") + " " + g.group(2)
        for g in re.finditer(r"\$middleware\s*->\s*group\s*\(\s*['\"](\w+)['\"]\s*,\s*\[([^\]]*)\]", code):
            self.mw_groups[g.group(1)] = self.mw_groups.get(g.group(1), "") + " " + g.group(2)
        for g in re.finditer(r"\$middleware\s*->\s*(web|api)\s*\(([^;]*)\)\s*;", code):
            self.mw_groups[g.group(1)] = self.mw_groups.get(g.group(1), "") + " " + g.group(2)

    def _mw_auth(self, text: str) -> bool:
        """Middleware names or classes that require a signed-in user, with group names expanded."""
        names = _strings(text) + re.findall(r"([\w\\]+)\s*::\s*class", text)
        for _ in range(2):
            names += [x for n in names if n in self.mw_groups for x in _strings(self.mw_groups[n])
                      + re.findall(r"([\w\\]+)\s*::\s*class", self.mw_groups[n]) if x not in names]
        return any(LARAVEL_AUTH.search(n.rsplit("\\", 1)[-1]) for n in names)

    def _includes(self, sf: SourceFile) -> None:
        """Route files required inside a group (`Route::middleware('web')->group(function () { require
        base_path('routes/web/hardware.php'); })`) take that group's prefix and middleware."""
        v = sf.cache["php_views"]
        code, bare = v.code, v.bare  # type: ignore[attr-defined]
        for a, b, prefix, mw in self._groups(code, bare):
            for m in INCLUDE.finditer(code, a, b):
                path = m.group(1).lstrip("/")
                if m.group(0).find("__DIR__") >= 0:
                    path = "/".join(sf.rel.split("/")[:-1] + [path])
                parts: List[str] = []
                for seg in path.split("/"):
                    if seg == "..":
                        parts = parts[:-1]
                    elif seg not in ("", "."):
                        parts.append(seg)
                self.included["/".join(parts)] = (prefix, mw)

    def _groups(self, code: str, bare: str) -> List[Tuple[int, int, str, str]]:
        """(start, end, prefix, middleware text) of every `Route::...->group(function () {...})` closure."""
        out = []
        for m in finditer(GROUP, bare):
            close = match_close(bare, m.end() - 1)
            if close < 0:
                continue
            stmt = max(bare.rfind(";", 0, m.start()), bare.rfind("{", 0, m.start()), bare.rfind("}", 0, m.start())) + 1
            brace = bare.find("{", m.end(), close)
            if brace < 0:
                continue
            head = code[stmt:brace]
            prefix = ""
            pm = re.search(r"(?:->|::)\s*prefix\s*\(\s*['\"]([^'\"]*)['\"]|['\"]prefix['\"]\s*=>\s*['\"]([^'\"]*)['\"]", head)
            if pm:
                prefix = pm.group(1) if pm.group(1) is not None else pm.group(2)
            mws = re.findall(r"(?:->|::)\s*middleware\s*\(([^;]*?)\)\s*(?:->|$)|['\"]middleware['\"]\s*=>\s*(\[[^\]]*\]|['\"][^'\"]*['\"])", head)
            end = match_close(bare, brace)
            out.append((brace, end if end > 0 else close, prefix, " ".join(a or b for a, b in mws)))
        return out

    def _laravel(self, sf: SourceFile, code: str, bare: str) -> None:
        groups = self._groups(code, bare)
        # Laravel maps routes/api.php under /api with the `api` middleware group and routes/web.php with `web`;
        # a file required inside a group (RouteServiceProvider) takes that group's prefix and middleware
        if sf.rel in self.included:
            base, base_mw = self.included[sf.rel]
        elif re.search(r"(?:^|/)routes/api\.php$", sf.rel):
            base, base_mw = "/api", "'api'"
        else:
            base, base_mw = "", "'web'" if re.search(r"(?:^|/)routes/web\.php$", sf.rel) else ""

        def scope(at: int) -> Tuple[str, str]:
            prefix, mw = base, base_mw
            for a, b, p, gm in sorted(groups):
                if a < at < b:
                    prefix, mw = _join(prefix, p) if p else prefix, mw + " " + gm
            return prefix, mw

        for m in finditer(ROUTE_CALL, bare):
            stmt = max(bare.rfind(";", 0, m.start()), bare.rfind("{", 0, m.start()), bare.rfind("}", 0, m.start())) + 1
            if not re.match(r"\s*Route\s*::", code[stmt:m.start() + 8]):
                continue  # `$client->get('/x')`, not a route
            close = match_close(bare, m.end() - 1)
            if close < 0:
                continue
            args = _split_top(code[m.end():close])
            verb = m.group(1)
            if verb == "match":
                if len(args) < 2:
                    continue
                verbs = [s.upper() for s in _strings(args[0])] or ["ALL"]
                args = args[1:]
            else:
                verbs = ["ALL" if verb == "any" else verb.upper()]
            paths = _strings(args[0]) if args else []
            if not paths:
                continue
            end = bare.find(";", close)
            tail = code[close:end if end > 0 else close + 400]
            head = code[stmt:m.start()]
            prefix, scoped = scope(m.start())
            mw = scoped + " " + " ".join(re.findall(r"middleware\s*\(([^)]*)\)", head + tail))
            fn, ctrl_auth = self._laravel_handler(sf, code, bare, args[1:] if len(args) > 1 else [], m.end(), close)
            path = _join(prefix, paths[0])
            self._route(sf, m.start(), path, verbs, fn, "laravel", mw, self._mw_auth(mw) or ctrl_auth)
        for m in finditer(RESOURCE, bare):
            close = match_close(bare, m.end() - 1)
            if close < 0:
                continue
            args = _split_top(code[m.end():close])
            names = _strings(args[0]) if args else []
            ctrl = re.search(r"([\w\\]+)\s*::\s*class|['\"]([\w\\]+)['\"]", args[1]) if len(args) > 1 else None
            if not names or not ctrl:
                continue
            cls = (ctrl.group(1) or ctrl.group(2)).rsplit("\\", 1)[-1]
            end = bare.find(";", close)
            tail = code[close:end if end > 0 else close + 400]
            only = re.search(r"->\s*only\s*\(([^)]*)\)", tail)
            except_ = re.search(r"->\s*except\s*\(([^)]*)\)", tail)
            options = " ".join(args[2:])  # Route::resource('hardware', X::class, ['middleware' => ['auth']])
            mw = " ".join(re.findall(r"middleware\s*\(([^)]*)\)", tail)) + " " + \
                " ".join(re.findall(r"['\"]middleware['\"]\s*=>\s*(\[[^\]]*\]|['\"][^'\"]*['\"])", options))
            segs = names[0].split(".")
            path = ""
            for i, s in enumerate(segs):
                path = _join(path, s)
                if i < len(segs) - 1:
                    path = _join(path, "{" + _singular(s) + "}")
            item = _join(path, "{" + _singular(segs[-1]) + "}")
            actions = [("index", "GET", path), ("store", "POST", path), ("show", "GET", item), ("update", "PUT", item),
                       ("update", "PATCH", item), ("destroy", "DELETE", item)]
            if m.group(1) == "resource":
                actions += [("create", "GET", _join(path, "create")), ("edit", "GET", _join(item, "edit"))]
            prefix, scoped = scope(m.start())
            mw = scoped + " " + mw
            for action, verb, p in actions:
                if (only and action not in _strings(only.group(1))) or (except_ and action in _strings(except_.group(1))):
                    continue
                fn = self._method(cls, action)
                if fn is None:
                    continue
                self._route(sf, m.start(), _join(prefix, p), [verb], fn, "laravel", mw,
                            self._mw_auth(mw) or self._class_auth(cls, action))

    def _laravel_handler(self, sf: SourceFile, code: str, bare: str, rest: List[str], start: int, close: int):
        """The handler of a route: `[UserController::class, 'store']`, `'UserController@store'`, an invokable
        `UserController::class`, or an inline closure (returned as a span of this file)."""
        text = ", ".join(rest)
        m = re.search(r"\[\s*([\w\\]+)\s*::\s*class\s*,\s*['\"](\w+)['\"]\s*\]", text) or \
            re.search(r"['\"]([\w\\]+)@(\w+)['\"]", text)
        if m:
            return self._method(m.group(1), m.group(2)), self._class_auth(m.group(1), m.group(2))
        m = re.search(r"^\s*([\w\\]+)\s*::\s*class\s*$", text)
        if m:
            return self._method(m.group(1), "__invoke"), self._class_auth(m.group(1), "__invoke")
        fm = re.search(r"\b(?:function|fn)\s*\(", bare[start:close])
        if fm:
            po = start + fm.end() - 1
            pc = match_close(bare, po)
            if pc > 0:
                brace = bare.find("{", pc, close)
                arrow = bare.find("=>", pc, close)
                if brace >= 0 and (arrow < 0 or brace < arrow):
                    end = match_close(bare, brace)
                    return (sf, start + fm.start(), po, pc, (end + 1) if end > 0 else close), False
                return (sf, start + fm.start(), po, pc, close), False
        return None, False

    def _symfony(self, sf: SourceFile, code: str, bare: str) -> None:
        raw = sf.text or ""
        hits: List[Tuple[int, str]] = []  # (offset, argument text) of each route attribute or annotation
        for m in finditer(SYMFONY_ATTR, bare):
            close = match_close(bare, m.end() - 1)
            if close > 0:
                hits.append((m.start(), code[m.end():close]))
        for a, b in sf.cache["php_views"].comments:  # type: ignore[attr-defined]
            for m in SYMFONY_ANNOTATION.finditer(raw, a, b):
                close = raw.find(")", m.end(), b)
                if close > 0:
                    hits.append((m.start(), raw[m.end():close].replace("{", "[").replace("}", "]").replace("=", ":")))
        for at, args in sorted(hits):
            pm = re.search(r"(?:^|,)\s*(?:path\s*:\s*)?(['\"])([^'\"]*)\1", args)
            if not pm:
                continue
            path = pm.group(2)
            mm = re.search(r"methods\s*:\s*\[([^\]]*)\]|methods\s*:\s*(['\"][A-Z|]+['\"])", args)
            verbs = [x.upper() for s in _strings((mm.group(1) or mm.group(2)) if mm else "") for x in s.split("|")] or ["ALL"]
            fm = FN_DECL.search(bare, at)
            cls = self._class_of(sf, at)
            if cls is None:
                continue  # a class-level prefix: applied below
            name, ca, cb = cls
            if not fm or fm.start() > cb:
                continue
            fn = next((f for f in self.funcs.get(fm.group(1), []) if f[0] is sf and f[1] == fm.start()), None)
            if fn is None:
                continue
            prefix = ""
            for pat, pargs in hits:
                if pat < ca and code[pat:ca].count("function") == 0 and not code[pat:ca].strip().count(";"):
                    pp = re.search(r"(?:^|,)\s*(?:path\s*:\s*)?(['\"])([^'\"]*)\1", pargs)
                    prefix = pp.group(2) if pp else prefix
            full = _join(prefix, path)
            # every attribute and docblock above the method (`#[IsGranted('delete', 'activity')]` may come before the
            # route) and above the class (`#[IsGranted('plugins')] final class ...`)
            above = max(bare.rfind(";", ca, at), bare.rfind("}", ca, at), bare.find("{", ca) if bare.find("{", ca) < at else -1) + 1
            attrs = raw[above:fm.start()] + "\n" + raw[max(0, ca - 600):ca].rsplit(";", 1)[-1]
            auth = self._class_auth(name, fm.group(1)) or bool(re.search(r"#\[\s*IsGranted|@IsGranted|@Security\s*\(", attrs)) \
                or self._access_protects(full)
            self._route(sf, at, full, verbs, fn, "symfony", attrs, auth)

    def _route(self, sf: SourceFile, off: int, path: str, verbs: List[str], fn, framework: str, attrs: str,
               auth: bool) -> None:
        if fn is None:
            return
        fsf, a, po, pc, b = fn
        code = fsf.cache["php_views"].code  # type: ignore[attr-defined]
        body = attrs + "\n" + code[a:b]
        # checks every action of the controller makes: `$this->middleware(function (...) { $this->checkPermission(...) })`
        # in the constructor, or Laravel 11's `public static function middleware()`
        cls = self._class_of(fsf, a)
        if cls is not None:
            for name in ("__construct", "middleware"):
                for f, ca, _po, _pc, cb in self.funcs.get(name, []):
                    if f is fsf and cls[1] <= ca < cls[2] and "middleware" in code[ca:cb].lower():
                        body += "\n" + code[ca:cb]
        has_auth = auth or bool(PHP_AUTH.search(code[pc:b])) or bool(H.AUTH_EVIDENCE.search(code[pc:b])) \
            or H.CUSTOM.is_auth(body)
        route_params = set(re.findall(r"\{(\w+)\??\}", path))
        self.handlers.setdefault((fsf.rel, a), set()).update(route_params)
        self.routes.append(Route(sf.rel, sf.line_at(off), path, verbs, body, framework, "php", has_auth=has_auth,
                                 calls_llm=bool(H.LLM_HOSTS.search(body) or re.search(r"\bOpenAI\s*::\s*chat\s*\(|->\s*chat\s*\(\s*\)\s*->\s*create\s*\(", body)),
                                 reads_body=bool(re.search(r"\$request\s*->\s*(?:input|all|json|post|validated|getContent|request\s*->)", body)),
                                 params=sorted(route_params)))

    # ------------------------------------------------------------------ data flow
    def _checks(self, sf: SourceFile) -> None:
        v = sf.cache["php_views"]
        code, bare = v.code, v.bare  # type: ignore[attr-defined]
        spans = []
        for lst in self.funcs.values():
            for f, a, po, pc, b in lst:
                if f is not sf:
                    continue
                GUARD.tick()
                params = code[po + 1:pc]
                tainted: Set[str] = set()
                for p in self.handlers.get((sf.rel, a), set()):
                    if re.search(r"\$" + re.escape(p) + r"\b", params) and not re.search(r"\b(?:int|float|bool)\s+\$" + re.escape(p) + r"\b", params) \
                            and not re.search(r"\b[A-Z]\w*\s+\$" + re.escape(p) + r"\b", params.replace("string ", "")):
                        tainted.add("$" + p)
                self._function(sf, code, bare, pc, b, tainted)
                spans.append((a, b))
        # top-level code of a plain PHP page (DVWA's vulnerabilities/*/source/low.php) is one more "function"
        top_c, top_b = list(code), list(bare)
        for a, b in spans:
            for k in range(a, b):
                if top_c[k] != "\n":
                    top_c[k] = " "
                    top_b[k] = " "
        tc, tb = "".join(top_c), "".join(top_b)
        if SOURCE.search(tc):
            self._function(sf, tc, tb, 0, len(tc), set())

    def _function(self, sf: SourceFile, code: str, bare: str, pc: int, b: int, tainted: Set[str]) -> None:
        body_c, body_b = code[pc:b], bare[pc:b]
        assigned: Dict[str, List[str]] = {}
        for m in finditer(ASSIGN, body_b):
            end = body_b.find(";", m.end())
            rhs = body_c[m.end():end if end > 0 else len(body_c)]
            assigned.setdefault(m.group(1), []).append(rhs)
        for name, rhss in assigned.items():
            if any(SOURCE.search(r) and not _clean(r) for r in rhss):
                tainted.add(name)
        for _ in range(4):
            grew = False
            for name, rhss in assigned.items():
                if name not in tainted and any(_mentions(r, tainted) and not _clean(r) for r in rhss):
                    tainted.add(name)
                    grew = True
            if not grew:
                break
        # a name passed through a sanitizer in place (`$id = intval($id);`) is clean from then on
        cleaned = {n for n, rhss in assigned.items() if any(_clean(r) for r in rhss)}
        for rx, rule, what, sev, argi in SINKS:
            for m in finditer(rx, body_b):
                if rule == "FE001":
                    end = body_b.find(";", m.end())
                    arg = body_c[m.end():end if end > 0 else m.end() + 300]
                    if (_mentions(arg, tainted - cleaned) or SOURCE.search(arg)) and not SANITIZERS.search(arg):
                        self.add(sf, pc + m.start(), rule, f"Request data is written into {what} without escaping (XSS).", sev)
                    continue
                if body_b[m.end() - 1] != "(":
                    end = body_b.find(";", m.end())
                    argv = [body_c[m.end():end if end > 0 else m.end() + 300]]  # `include $page;`, `require 'x.php';`
                else:
                    close = match_close(body_b, m.end() - 1)
                    if close < 0:
                        continue
                    argv = _split_top(body_c[m.end():close])
                if rule == "BE008" and m.group(0).lstrip().startswith("header"):
                    if not argv or not re.match(r"""\s*['"]\s*Location\s*:""", argv[0], re.I):
                        continue  # some other header
                if len(argv) <= argi:
                    continue
                arg = argv[argi]
                if rule == "BE001" and "->" in m.group(0) and not re.search(r"['\"]|\$", arg):
                    continue
                live = tainted - cleaned
                if rule in ("BE006", "BE008"):
                    # `redirect($book->getUrl())`: a model built from the request, but the URL or path the server derives
                    # from it is not request data
                    arg = re.sub(r"\$(?!request\b)\w+(?:\s*->\s*\w+(?:\s*\([^()]*\))?)+", "", arg)
                hit = (_mentions(arg, live) or bool(SOURCE.search(arg))) and not SANITIZED.match(arg)
                if rule == "BE001" and hit and not re.search(r"\$\w|\.\s*\$|\{\$", arg):
                    hit = False
                if rule == "BE006" and hit and re.search(r"\bbasename\s*\(", arg):
                    hit = False
                if rule == "BE008" and hit and (LOCAL_TARGET.match(arg) or (re.fullmatch(r"\s*\$\w+\s*", arg) and assigned.get(arg.strip())
                                                and all(LOCAL_TARGET.match(r) for r in assigned[arg.strip()]))):
                    hit = False
                if hit:
                    self.add(sf, pc + m.start(), rule, f"Request data flows into {what}.", sev)
                elif rule == "BE001" and self._interpolated_sql(arg, assigned, cleaned, sf.rel):
                    self.add(sf, pc + m.start(), "BE001", "SQL query built by interpolating or concatenating a variable; use "
                                                         "bound parameters.", "medium")
                elif rule == "BE002" and re.search(r"\$\w", arg) and not re.search(r"escapeshellarg\s*\(", arg) \
                        and (SHELL_LIKE.search(arg) or re.match(r"\s*\$\w+\s*$", arg)):
                    self.add(sf, pc + m.start(), "BE002", "Shell command built from a variable; use escapeshellarg() or "
                                                         "avoid the shell.", "medium")

    @staticmethod
    def _interpolated_sql(arg: str, assigned: Dict[str, List[str]], cleaned: Set[str], rel: str = "") -> bool:
        if re.search(r"(?:^|/)migrations/", rel):
            return False  # schema migrations: table names and prefixes, no request input
        a = arg.strip()
        text = (assigned.get(a) or [a])[-1] if re.fullmatch(r"\$\w+", a) else a
        if not SQL_WORDS.search(text):
            return False
        names = re.findall(r"\$\w+", re.sub(r"\$(?:this|wpdb)\b", "", text))
        return any(n not in cleaned for n in names)

    # ------------------------------------------------------------------ Blade
    def _blade(self, sf: SourceFile) -> None:
        text = sf.text or ""
        for m in finditer(BLADE_RAW, text):
            value = m.group(1).strip()
            if not value.startswith("$") or BLADE_SAFE.search(value):
                continue
            self.add(sf, m.start(), "FE001", "Unescaped `{!! ... !!}` output in a Blade template can execute script (XSS).", "high")
