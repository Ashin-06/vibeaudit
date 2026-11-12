"""AI-slop checks added in 0.8.4: QA009-QA011 (all preview).

QA009: Pages Router idioms in an App Router file (they silently do nothing there, or throw).
QA010: mock, fake or dummy data used as the fallback when a real call fails.
QA011: the same function, with the same code, defined in several files of one package.
"""
from __future__ import annotations

import ast
import posixpath
import re
from typing import Callable, Dict, List, Optional, Set, Tuple

from .files import Project, SourceFile
from .guard import GUARD, finditer

Add = Callable[..., None]  # ProjectScanner.add(sf_or_rel, line, rule, message, severity="")

APP_ROOT = re.compile(r"(?:^|/)app/layout\.(?:[jt]sx?|mjs)$")
PAGES_DATA = re.compile(
    r"\bexport\s+(?:(?:async\s+)?function\s+|(?:const|let|var)\s+)(getServerSideProps|getStaticProps|getStaticPaths|getInitialProps)\b")
NEXT_ROUTER = re.compile(r"""\bfrom\s+['"]next/router['"]|\brequire\s*\(\s*['"]next/router['"]\s*\)|\bimport\s+['"]next/router['"]""")
USE_CLIENT = re.compile(r"""\A\s*(?:;\s*)?['"]use client['"]""")
METADATA_EXPORT = re.compile(r"\bexport\s+(?:const\s+metadata\b|(?:async\s+)?function\s+generateMetadata\b)")

# identifiers that name made-up data: mockUsers, MOCK_POSTS, fakeData, getDummyItems, dummy
MOCK_ID = r"\w{0,40}(?:[mM]ock|MOCK|[fF]ake|FAKE|[dD]ummy|DUMMY)\w{0,40}"
MOCK_NAME = re.compile(r"^%s$" % MOCK_ID)
JS_FALLBACK = re.compile(r"(?:\|\||\?\?)\s*(?:\[\s*\.\.\.\s*)?(%s)\b" % MOCK_ID)
JS_CATCH = re.compile(r"\bcatch\s*(?:\([^()]{0,200}\))?\s*\{")
JS_CATCH_USE = re.compile(r"(?:\breturn\s+|\bset[A-Z]\w{0,40}\s*\(\s*|\bjson\s*\(\s*|[^=!<>]=\s*)(?:\[\s*\.\.\.\s*|\{\s*\.\.\.\s*)?(%s)\b" % MOCK_ID)
# mocks behind an explicit switch are deliberate
MOCK_SWITCH = re.compile(r"(?i)\buse_?mocks?\b|\bmock_?mode\b|\benable_?mocks?\b|\bNODE_ENV\b|\bisDev\w*|__DEV__|import\.meta\.env\.DEV|\bDEMO_MODE\b")
MOCK_PATH = re.compile(r"(?i)mock|fake|dummy|fixture|stories|storybook|\bseed|demo|sample|playground")

JS_FUNC = re.compile(r"(?m)^(?:export\s+)?(?:async\s+)?function\s*\*?\s*(\w+)\s*(?:<[^>{}\n]{0,100}>)?\s*\(")
JS_ARROW = re.compile(
    r"(?m)^(?:export\s+)?const\s+(\w+)\s*(?::[^=\n]{0,120})?=\s*(?:async\s*)?(?:\([^()]{0,300}\)|\w+)\s*(?::[^=\n]{0,120})?=>\s*\{")
# entry points a framework calls by name: the same code in two route files is the framework's shape, not a copied helper
FRAMEWORK_NAMES = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "getServerSideProps", "getStaticProps",
                   "getStaticPaths", "generateMetadata", "generateStaticParams", "loader", "action", "middleware",
                   "handler", "main", "default", "setup", "teardown", "configure", "upgrade", "downgrade"}
# standalone scripts and self-contained units copy small helpers on purpose so each one runs on its own
STANDALONE = re.compile(r"(?i)(?:^|/)(?:benchmarks?|bench|scripts?|evals?|evaluation|skills?)/|(?:^|/)examples?_[^/]*$")
# deployed separately from the rest of the repository: they can share code with each other (_shared), not with it
DEPLOY_UNIT = re.compile(r"^(?:.*/)?supabase/functions/")
MANIFESTS = ("package.json", "pyproject.toml", "setup.py", "requirements.txt")
MIN_LINES = 5


def run(project: Project, add: Add) -> None:
    roots = sorted({posixpath.dirname(f.rel) for f in project.files if APP_ROOT.search(f.rel)})
    code_files = [f for f in project.files if f.kind in ("js", "py") and f.text is not None and not _skipped(f)]
    for sf in code_files:
        if sf.kind == "js":
            if roots and any(sf.rel.startswith(r + "/") or not r and sf.rel.startswith("app/") for r in roots):
                GUARD.run(sf.rel, "app router idioms", _app_router, project, sf, add)
            GUARD.run(sf.rel, "mock fallbacks", _js_mock_fallback, sf, add)
        else:
            GUARD.run(sf.rel, "mock fallbacks", _py_mock_fallback, sf, add)
    GUARD.run("<project>", "duplicate functions", _duplicates, project, code_files, add)


def _skipped(sf: SourceFile) -> bool:
    return sf.is_test or sf.is_example or sf.is_one_off or sf.is_vendored


def _views(sf: SourceFile):
    return sf.cache.get("views")


def _app_router(project: Project, sf: SourceFile, add: Add) -> None:
    v = _views(sf)
    if v is None or "next" not in project.js_deps(sf.rel):
        return
    code, bare = v.code, v.bare  # type: ignore[attr-defined]
    for m in finditer(PAGES_DATA, bare):
        add(sf, sf.line_at(m.start()), "QA009",
            f"`{m.group(1)}` is a Pages Router function; the App Router never calls it, so this code does not run. "
            "Fetch in the server component (or a route handler) instead.")
    m = NEXT_ROUTER.search(code)
    if m:
        add(sf, sf.line_at(m.start()), "QA009",
            "`next/router` does not work in the App Router (useRouter throws \"NextRouter was not mounted\"); "
            "use `next/navigation`.")
    if USE_CLIENT.search(code):
        m = METADATA_EXPORT.search(bare)
        if m:
            add(sf, sf.line_at(m.start()), "QA009",
                "A \"use client\" file exports metadata, which Next.js only reads from server components.")


def _js_mock_fallback(sf: SourceFile, add: Add) -> None:
    v = _views(sf)
    if v is None or MOCK_PATH.search(sf.rel):
        return
    code, bare = v.code, v.bare  # type: ignore[attr-defined]
    if not re.search(r"(?:[mM]ock|MOCK|[fF]ake|FAKE|[dD]ummy|DUMMY)", bare) or MOCK_SWITCH.search(bare):
        return
    seen: Set[int] = set()
    pairs = _pairs(bare)
    for m in finditer(JS_CATCH, bare):
        close = pairs.get(m.end() - 1, -1)
        block = bare[m.end():close if close > 0 else m.end() + 2000]
        u = JS_CATCH_USE.search(block)
        if u:
            line = sf.line_at(m.end() + u.start(1))
            seen.add(line)
            add(sf, line, "QA010", f"When the call fails, the code falls back to made-up data (`{u.group(1)}`), "
                                   "so users see fake content instead of an error.")
    for m in finditer(JS_FALLBACK, bare):
        line = sf.line_at(m.start(1))
        if line not in seen:
            seen.add(line)
            add(sf, line, "QA010", f"Missing data falls back to made-up data (`{m.group(1)}`), which hides a failed "
                                   "or empty response.")


def _py_mock_fallback(sf: SourceFile, add: Add) -> None:
    text = sf.text or ""
    if MOCK_PATH.search(sf.rel) or not re.search(r"(?i)mock|fake|dummy", text) or MOCK_SWITCH.search(text):
        return
    tree = _py_tree(sf)
    if tree is None:
        return
    lines: Set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if _catches_import_error(node):
                continue  # a stand-in for an optional module, not data
            for sub in node.body:
                for n in ast.walk(sub):
                    if isinstance(n, (ast.Return, ast.Assign)) and n.value is not None:
                        name = _mock_name(n.value)
                        if name and n.lineno not in lines:
                            lines.add(n.lineno)
                            add(sf, n.lineno, "QA010", f"When the call fails, the code falls back to made-up data "
                                                       f"(`{name}`), so users see fake content instead of an error.")
        elif isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            for operand in node.values[1:]:
                name = _mock_name(operand)
                if name and node.lineno not in lines:
                    lines.add(node.lineno)
                    add(sf, node.lineno, "QA010", f"Missing data falls back to made-up data (`{name}`), which hides a "
                                                  "failed or empty response.")


def _catches_import_error(handler: ast.ExceptHandler) -> bool:
    t = handler.type
    names = t.elts if isinstance(t, ast.Tuple) else [t] if t is not None else []
    return any(isinstance(n, ast.Name) and n.id in ("ImportError", "ModuleNotFoundError") for n in names)


def _mock_name(node: ast.AST) -> str:
    """The made-up-data name a value is built from: mock_users, MOCK_DATA, get_fake_items(), self.dummy."""
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, (ast.List, ast.Tuple)) and node.elts and isinstance(node.elts[0], ast.Starred):
        node = node.elts[0].value
    name = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ""
    return name if name and MOCK_NAME.match(name) and not name.startswith(("Mock", "mock_open", "MagicMock")) else ""


def _py_tree(sf: SourceFile) -> Optional[ast.Module]:
    tree = sf.cache.get("ast")
    if tree is not None:
        return tree  # type: ignore[return-value]
    try:
        return ast.parse(sf.text or "")
    except (SyntaxError, ValueError):
        return None


def _pairs(bare: str) -> Dict[int, int]:
    """Offset of every bracket that is closed -> offset of its closing bracket, in one pass."""
    out: Dict[int, int] = {}
    stack: List[Tuple[str, int]] = []
    match = {")": "(", "}": "{", "]": "["}
    for m in re.finditer(r"[(){}\[\]]", bare):
        ch, i = m.group(0), m.start()
        if ch in "({[":
            stack.append((ch, i))
        else:
            while stack and stack[-1][0] != match[ch]:
                stack.pop()  # an unclosed bracket of another kind
            if stack:
                out[stack.pop()[1]] = i
    return out


def _package_of(rel: str, manifest_dirs: Set[str]) -> str:
    unit = DEPLOY_UNIT.match(rel)
    if unit:
        return unit.group(0)
    d = posixpath.dirname(rel)
    while d:
        if d in manifest_dirs:
            return d
        d = posixpath.dirname(d)
    return ""


def _duplicates(project: Project, files: List[SourceFile], add: Add) -> None:
    manifest_dirs = {posixpath.dirname(f.rel) for f in project.files if f.rel.rsplit("/", 1)[-1] in MANIFESTS}
    defs: Dict[Tuple[str, str, str], List[Tuple[str, int, SourceFile]]] = {}
    for sf in files:
        if STANDALONE.search(sf.rel):
            continue
        for name, key, line in _functions(sf):
            if name in FRAMEWORK_NAMES or name.startswith("__"):
                continue
            defs.setdefault((_package_of(sf.rel, manifest_dirs), name, key), []).append((sf.rel, line, sf))
    for (_, name, _), places in defs.items():
        files_seen = sorted({p[0] for p in places})
        if len(files_seen) < 2:
            continue
        first = files_seen[0]
        for rel, line, sf in sorted(places, key=lambda p: (p[0], p[1])):
            if rel != first:
                add(sf, line, "QA011", f"`{name}` is defined with the same code in {first}; keep one copy and import "
                                       "it, so a fix in one place reaches every caller.")


def _functions(sf: SourceFile) -> List[Tuple[str, str, int]]:
    out: List[Tuple[str, str, int]] = []
    if sf.kind == "py":
        tree = _py_tree(sf)
        if tree is None:
            return out
        for fn in tree.body:
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and (fn.end_lineno or fn.lineno) - fn.lineno + 1 >= MIN_LINES:
                body = ast.Module(body=fn.body, type_ignores=[])
                out.append((fn.name, ast.dump(fn.args) + ast.dump(body), fn.lineno))
        return out
    v = _views(sf)
    if v is None:
        return out
    code, bare = v.code, v.bare  # type: ignore[attr-defined]
    pairs = _pairs(bare)
    for rx in (JS_FUNC, JS_ARROW):
        for m in finditer(rx, bare):
            if rx is JS_FUNC:
                close_params = pairs.get(m.end() - 1, -1)
                if close_params < 0:
                    continue
                brace = bare.find("{", close_params, close_params + 300)
                start = m.end() - 1
            else:
                brace, start = m.end() - 1, m.start(1)
            if brace < 0:
                continue
            end = pairs.get(brace, -1)
            if end < 0 or code.count("\n", brace, end) + 1 < MIN_LINES:
                continue
            out.append((m.group(1), " ".join(code[start:end + 1].split()), sf.line_at(m.start())))
    return out
