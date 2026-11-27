"""Frontend-to-backend contract checks: calls from the browser code to API paths that no route handles, or with
an HTTP method the route does not accept.

Router prefixes are resolved by pyscan (FastAPI, Flask) and jsscan (Express); with prefixes, the checks run only
when every route's full path is known (Route.prefix_resolved), so an unresolved mount never makes calls look unhandled."""
from __future__ import annotations

import re
from typing import Callable, List, Optional, Set, Tuple

from .files import Project, SourceFile
from .guard import GUARD, finditer
from .lexer import match_close
from .model import Finding, Route

Emit = Callable[[Finding], None]

def _string(n: str, base_path: bool = False) -> str:
    """A quoted path, or a template literal path whose `${...}` parts may contain quotes (`${id || 'new'}`)
    and one level of nested template literal (`${alt ? `alt-${id}` : id}`)."""
    prefix = r"(?:\$\{[^{}\n]{0,120}(?i:base_?path)[^{}\n]{0,60}\})?" if base_path else ""
    return (rf"""(?:(?P<q{n}>["'])(?P<s{n}>/[^"'\n]{{0,300}})(?P=q{n})"""
            rf"""|`{prefix}(?P<t{n}>/(?:[^`\n$]|\$\{{(?:[^{{}}`\n]|`[^`\n]{{0,120}}`){{0,120}}\}}|\$(?!\{{)){{0,300}})`)""")


CALL = re.compile(
    # an optional generic (useSWR<Doc[]>) and an optional `${...BASE_PATH...}` prefix are allowed before the path
    r"\b(?:fetch|useSWR|useSWRImmutable|\$fetch|ofetch)\s*(?:<[^<>()\n]{0,200}>)?\s*\(\s*" + _string("1", base_path=True)
    + r"|\b(?:axios|ky)\s*\.\s*(?P<verb>get|post|put|patch|delete)\s*\(\s*" + _string("2"))
METHOD_OPT = re.compile(r"""\bmethod\s*:\s*(["'`])(\w+)\1|\bmethod\s*:""")
FILE_BASED = {"next-app", "next-pages", "sveltekit"}
PREFIXES = re.compile(
    r"\binclude_router\s*\(|\bAPIRouter\s*\(|\bBlueprint\s*\(|\bregister_blueprint\s*\(|\burlpatterns\b|\bmount\s*\("
    r"|\bapp\s*\.\s*use\s*\(\s*['\"`]/|\bexpress\s*\.\s*Router\s*\(|\bnew\s+Hono\s*\(\s*\)\s*\.\s*basePath|\.route\s*\(\s*['\"`]/[^'\"`]*['\"`]\s*,")
REWRITES = re.compile(r"\brewrites\b|\bproxy\s*:|\"proxy\"\s*:|\[\[redirects\]\]|\brewrite\s*:")


def segments(path: str) -> List[str]:
    """Normalized path segments; any parameter becomes '*', a catch-all '**'."""
    out = []
    for s in path.split("?")[0].split("#")[0].split("/"):
        if not s:
            continue
        if s.startswith(("[...", "[[...")) or re.fullmatch(r"<path:\w+>|\{\w+:path\}|\*", s):
            out.append("**")
        elif s.startswith(("[", ":", "{", "<")) or "${" in s:
            out.append("*")
        else:
            out.append(s)
    return out


def matches(route: List[str], call: List[str]) -> bool:
    if not route:
        return not call
    if route[0] == "**":
        return True  # [[...x]] (zero or more) and [...x] (one or more) are treated alike
    return bool(call) and (route[0] == "*" or call[0] == "*" or route[0] == call[0]) and matches(route[1:], call[1:])


class ContractScanner:
    def __init__(self, project: Project, emit: Emit, routes: List[Route]):
        self.p = project
        self.emit = emit
        from .files import has

        no_prefixes = not any(has(f, PREFIXES) for f in project.files if f.kind in ("py", "js") and not f.is_test)
        # with router prefixes, compare only when every backend route's full path is known (pyscan and jsscan
        # resolve FastAPI, Flask and Express prefixes); one unresolved route would make its calls look unhandled
        resolved = all(getattr(r, "prefix_resolved", False) for r in routes if r.lang in ("py", "js"))
        self.routes: List[Tuple[List[str], Route]] = [
            (segments(r.path), r) for r in routes
            if r.path.startswith("/") and (r.framework in FILE_BASED or no_prefixes or resolved)]
        self.owned: Set[str] = {segs[0] for segs, _ in self.routes if segs and segs[0] not in ("*", "**")}
        config = " ".join(f.text or "" for f in project.files
                          if re.search(r"(?:^|/)(?:next|vite|nuxt)\.config\.\w+$|(?:^|/)(?:vercel\.json|netlify\.toml|package\.json)$", f.rel))
        self.rewritten = bool(REWRITES.search(config))

    def add(self, sf: SourceFile, rule: str, at: int, msg: str) -> None:
        line = sf.line_at(at)
        self.emit(Finding(rule, sf.rel, line, msg, "", sf.line(line).strip()[:200]))

    def run(self) -> None:
        if not self.routes or self._backend_unread():
            return
        self._run()

    def _backend_unread(self) -> bool:
        """A backend source file too large (or unreadable) to scan may hold routes: calls would look unhandled."""
        return any(f.rel.endswith((".py", ".rs", ".go", ".java", ".kt", ".cs", ".php", ".rb")) and not f.is_test
                   and f.rel not in self.p.binary and f.text is None for f in self.p.files)

    def _run(self) -> None:
        if not self.routes:
            return
        for sf in self.p.files:
            if sf.kind == "js" and sf.text is not None and not sf.is_test:
                GUARD.run(sf.rel, "API contracts", self._file, sf)

    def _file(self, sf: SourceFile) -> None:
        v = sf.cache.get("views")
        if v is None:
            return
        code, bare = v.code, v.bare
        for m in finditer(CALL, code):
            path = m.group("s1") or m.group("t1") or m.group("s2") or m.group("t2")
            call = segments(path)
            if not call:
                continue
            # `/api/users` called while the backend serves `/users`: a missing or extra prefix
            # (a route that starts with a parameter, like /<slug>, matches anything and proves nothing)
            unprefixed = [r for segs, r in self.routes
                          if len(call) > 1 and segs and segs[0] not in ("*", "**") and matches(segs, call[1:])]
            if call[0] not in self.owned and not unprefixed:
                continue  # served by something outside this repository
            method = self._method(m, code, bare)
            hits = [r for segs, r in self.routes if matches(segs, call)]
            if not hits:
                if not self.rewritten:
                    hint = f" The backend serves `{unprefixed[0].path}` without the `/{call[0]}` prefix." if unprefixed else ""
                    self.add(sf, "API001", m.start(), f"`{path}` is called here, but no route in the project handles it.{hint}")
                continue
            allowed = {x.upper() for r in hits for x in r.methods}
            if method and not allowed & {method, "ALL", "*"} and not (method == "HEAD" and "GET" in allowed):
                where = hits[0].file
                self.add(sf, "API002", m.start(),
                         f"{method} `{path}` is sent, but {where} only handles {', '.join(sorted(allowed))}.")

    @staticmethod
    def _method(m: "re.Match[str]", code: str, bare: str) -> Optional[str]:
        """The HTTP method of the call, or None when it is computed at run time."""
        if m.group("verb"):
            return m.group("verb").upper()
        open_paren = code.index("(", m.start())
        close = match_close(bare, open_paren)
        opt = METHOD_OPT.search(code, m.end(), close if close > 0 else m.end() + 400)
        if opt is None:
            return "GET"
        return opt.group(2).upper() if opt.group(2) else None
