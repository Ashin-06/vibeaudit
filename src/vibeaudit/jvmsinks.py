"""Java and Kotlin data flow: request data from Spring and JAX-RS handler parameters (and HttpServletRequest),
followed through local assignments in the same method, into the generic sinks:

BE001 SQL injection, BE002 command injection, BE004 unsafe deserialization, BE005 SSRF, BE006 path traversal,
BE008 open redirect.

A per-method approximation: values passed to other methods are not followed.
"""
from __future__ import annotations

import re
from typing import Callable, List, Optional, Set, Tuple

from .files import SourceFile
from .guard import finditer
from .lexer import Views, match_close

Add = Callable[..., None]  # JvmScanner.add(sf, rule, line, message, severity="")

REQUEST_ANNOTATION = re.compile(
    r"@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|RequestPart"
    r"|QueryParam|PathParam|FormParam|HeaderParam|MatrixParam|BeanParam|CookieParam|RestQuery|RestPath|RestForm)\b")
SERVLET_PARAM = re.compile(r"\b(?:HttpServletRequest|ServerHttpRequest|ContainerRequestContext)\s+(\w+)|\b(\w{1,40})\s*:\s*HttpServletRequest\b")
SERVLET_SOURCE = r"\.\s*(?:getParameter|getParameterValues|getHeader|getQueryString|getRequestURI|getPathInfo|getCookies|getInputStream|getReader)\s*\("
JAVA_METHOD = re.compile(
    r"(?m)^[ \t]*(?:@\w+(?:\([^()\n]{0,300}\))?\s+)*(?:(?:public|protected|private|static|final|synchronized|suspend|override|open)\s+)*"
    r"(?:fun\s+(\w+)|[\w<>\[\],.? ]{1,120}?\s(\w+))\s*\(")
DECL = re.compile(r"(?m)^[ \t]*(?:final\s+)?(?:val|var|[\w<>\[\],.?]{1,80})\s+(\w+)\s*(?::\s*[\w<>\[\],.? ]{1,80})?=\s*([^;\n]{1,400})")
CONCAT = re.compile(r"\+\s*\w|\w\s*\+|String\s*\.\s*format\s*\(|\.formatted\s*\(|\$\{|\$\w|\.concat\s*\(|StringBuilder|\.append\s*\(")

SINKS: List[Tuple["re.Pattern[str]", str, str, str, str]] = [
    # (call, rule, what, severity, which arguments: "first" | "any" | "concat-first")
    (re.compile(r"\.\s*(?:createQuery|createNativeQuery|createSQLQuery|query|queryForObject|queryForList|queryForMap|queryForRowSet"
                r"|update|batchUpdate|execute|executeQuery|executeUpdate|executeLargeUpdate|prepareStatement|prepareCall|addBatch)\s*\("),
     "BE001", "a SQL query", "high", "concat-first"),
    (re.compile(r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\bProcessBuilder\s*\(|\.\s*command\s*\("),
     "BE002", "a command", "critical", "any"),
    (re.compile(r"\bnew\s+ObjectInputStream\s*\(|\bObjectInputStream\s*\(|\bXMLDecoder\s*\(|\.\s*fromXML\s*\("),
     "BE004", "deserialization of Java objects", "high", "any"),
    # a URL that is opened (new URL(x).openConnection()), not one that is only parsed (new URL(x).getHost())
    (re.compile(r"\bnew\s+URL\s*\((?=[^()\n]{0,200}\)\s*\.\s*(?:openConnection|openStream)\b)"
                r"|\.\s*(?:getForObject|getForEntity|postForObject|postForEntity|exchange)\s*\("
                r"|\.\s*uri\s*\("),
     "BE005", "an outbound HTTP request URL", "high", "first"),
    (re.compile(r"\bnew\s+File(?:InputStream|OutputStream|Reader|Writer)?\s*\(|\bFile(?:InputStream|OutputStream|Reader|Writer)?\s*\("
                r"|\bPaths\s*\.\s*get\s*\(|\bPath\s*\.\s*of\s*\("),
     "BE006", "a file system path", "high", "any"),
    (re.compile(r"\.\s*sendRedirect\s*\(|\bRedirectView\s*\(|\bURI\s*\.\s*create\s*\((?=[^)]{0,200}\)\s*\)\s*\.\s*build)"),
     "BE008", "a redirect target", "medium", "first"),
]
REDIRECT_PREFIX = re.compile(r"\"redirect:\"\s*\+\s*(\w[\w.()]*)|\"redirect:\$\{?(\w+)")


def methods(sf: SourceFile, v: Views):
    """(name, declaration offset, parameter text, body start, body end) of every method with a body."""
    code, bare = v.code, v.bare
    for m in finditer(JAVA_METHOD, bare):
        name = m.group(1) or m.group(2)
        if name in ("if", "for", "while", "switch", "catch", "return", "new", "synchronized", "else"):
            continue
        close = match_close(bare, m.end() - 1)
        brace = _body_start(bare, close) if close >= 0 else -1
        end = match_close(bare, brace) if brace >= 0 else -1
        if end > 0:
            yield name, m.start(), code[m.end():close], brace, end + 1


def index(sf: SourceFile, v: Views, follower) -> None:
    from .calls import Fn

    for name, start, params, a, b in methods(sf, v):
        follower.define(name, Fn(sf, start, params, (a, b)))


def follow(follower, add: Add) -> None:
    """Check the methods that receive request data from a call, CALL_DEPTH calls deep."""
    from .jvm import views_of

    seen: Set[Tuple[str, int, str]] = set()

    def run(fn, seed: Set[str], depth: int, via: str) -> None:
        v = views_of(fn.sf)
        a, b = fn.body
        note = lambda c, bb, base, t: follower.note(fn.sf, c, bb, base, t, depth, via)  # noqa: E731
        _method(fn.sf, v.code[a:b], v.bare[a:b], a, set(seed), set(), _followed_add(add, via, seen), note)

    follower.follow(run)


def check(sf: SourceFile, v: Views, add: Add, follower=None) -> None:
    code, bare = v.code, v.bare
    note = (lambda c, bb, base, t: follower.note(sf, c, bb, base, t, 0, None)) if follower else None  # noqa: E731
    for m in finditer(JAVA_METHOD, bare):
        name = m.group(1) or m.group(2)
        if name in ("if", "for", "while", "switch", "catch", "return", "new", "synchronized", "else"):
            continue
        open_paren = m.end() - 1
        close = match_close(bare, open_paren)
        if close < 0:
            continue
        brace = _body_start(bare, close)
        if brace < 0:
            continue
        end = match_close(bare, brace)
        if end < 0:
            continue
        params = code[open_paren + 1:close]
        tainted = _params(params)
        servlet = {g for g in SERVLET_PARAM.findall(params) for g in g if g}
        if not tainted and not servlet:
            continue
        _method(sf, code[brace:end + 1], bare[brace:end + 1], brace, tainted, servlet, add, note)


def _body_start(bare: str, close: int) -> int:
    """The `{` of a method body after its parameter list (skipping a return type and `throws`), or -1."""
    j = close + 1
    limit = min(len(bare), close + 300)
    while j < limit:
        ch = bare[j]
        if ch == "{":
            return j
        if ch in ";=)":  # an abstract method, an expression body, or not a declaration at all
            return -1
        j += 1
    return -1


def _params(params: str) -> Set[str]:
    out: Set[str] = set()
    for part in _split(params):
        if not REQUEST_ANNOTATION.search(part):
            continue
        kotlin = re.search(r"(\w+)\s*:\s*[\w<>?.,\[\] ]+$", part.strip())
        java = re.search(r"(\w+)\s*$", part.strip())
        n = (kotlin or java)
        if n:
            out.add(n.group(1))
    return out


def _split(s: str) -> List[str]:
    out, depth, start = [], 0, 0
    for i, ch in enumerate(s):
        if ch in "(<[{":
            depth += 1
        elif ch in ")>]}":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(s[start:i])
            start = i + 1
    out.append(s[start:])
    return out


def _method(sf: SourceFile, code: str, bare: str, base: int, tainted: Set[str], servlet: Set[str], add: Add,
            note: "Optional[Note]" = None) -> None:
    sources = [re.escape(s) + r"\s*" + SERVLET_SOURCE for s in sorted(servlet)]
    source_rx = re.compile("|".join(sources)) if sources else None

    def is_tainted(text: str) -> bool:
        return bool((source_rx and source_rx.search(text)) or any(re.search(r"\b%s\b" % re.escape(t), text) for t in tainted))

    # Kotlin templates (`"... $q"`) live inside string literals, so the code view (strings kept) is what is checked
    decls = [(m.group(1), code[m.start(2):m.end(2)]) for m in finditer(DECL, bare)]
    for _ in range(4):
        grew = False
        for name, rhs in decls:
            if name not in tainted and is_tainted(rhs):
                tainted.add(name)
                grew = True
        if not grew:
            break
    reported: Set[Tuple[str, int]] = set()
    for rx, rule, what, sev, which in SINKS:
        for m in finditer(rx, bare):
            close = match_close(bare, m.end() - 1)
            if close < 0:
                continue
            args = code[m.end():close]
            argv = _split(args)
            if which == "first":
                picked = argv[:1]
            elif which == "concat-first":
                first = argv[0] if argv else ""
                picked = [first] if CONCAT.search(first) or (first.strip().isidentifier() and _built_sql(bare, code, first.strip())) else []
            else:
                picked = argv
            if any(is_tainted(a) for a in picked):
                line = sf.line_at(base + m.start())
                if (rule, line) not in reported:
                    reported.add((rule, line))
                    add(sf, rule, line, f"Request data flows into {what}.", sev)
    for m in finditer(REDIRECT_PREFIX, code):
        target = m.group(1) or m.group(2) or ""
        if is_tainted(target):
            line = sf.line_at(base + m.start())
            if ("BE008", line) not in reported:
                reported.add(("BE008", line))
                add(sf, "BE008", line, "Request data flows into a redirect target (\"redirect:\" + value).", "medium")
    if note is not None:
        note(code, bare, base, is_tainted)


# ------------------------------------------------------------ cross-function taint
Note = Callable[[str, str, int, Callable[[str], bool]], None]  # (body code, bare, offset, is_tainted)


def _followed_add(add: Add, via: str, seen: Set[Tuple[str, int, str]]) -> Add:
    """`add` for a followed call: only what the request data reaches, once per line, with the call it came through."""
    from .calls import via_note

    def wrapped(sf: SourceFile, rule: str, line: int, msg: str, sev: str = "") -> None:
        if msg.startswith("Request data") and (sf.rel, line, rule) not in seen:
            seen.add((sf.rel, line, rule))
            add(sf, rule, line, msg + via_note(via), sev)
    return wrapped


def _built_sql(bare: str, code: str, name: str) -> bool:
    """`name` holds SQL built by concatenation or formatting earlier in the method."""
    m = re.search(r"\b%s\s*=\s*([^;\n]{1,400})" % re.escape(name), code)
    return bool(m and CONCAT.search(m.group(1)) and re.search(r"(?i)\b(?:select|insert|update|delete|where)\b", m.group(1)))
