"""`vibeaudit fix`: deterministic codemods for findings that have one obvious repair.

Every codemod works on one finding and returns text edits against the original file, so the edits of several
findings in one file never shift each other. A file's edits are kept only when the result still parses
(`ast.parse` for Python, balanced brackets for JavaScript and TypeScript). Nothing is written unless the
caller asks for it (`Plan.apply`); the default output is a unified diff.

A finding without a codemod, or whose code does not have the expected shape, is reported as skipped with the
reason. `patches()` can ask the optional LLM layer for a patch for those; it only ever writes a .patch file.
"""
from __future__ import annotations

import ast
import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple, Union

from .lexer import js_views, match_close, py_views, split_args, stmt_end
from .model import SEVERITY_RANK, Finding
from .pyscan import LC_CTORS, TOKEN_LIMIT_CALLS, dotted, last_name

Edit = Tuple[int, int, str]  # replace text[start:end] with the string
Result = Union[List[Edit], str]  # edits, or the reason no fix was made

TIMEOUT_SECONDS = 10
MAX_OUTPUT_TOKENS = 4096
MONEY_PRECISION = (12, 2)
JS_FIX_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")
PY_CORS_ORIGINS = '[o for o in os.environ.get("CORS_ORIGINS", "").split(",") if o]'
JS_CORS_ORIGINS = '(process.env.CORS_ORIGINS || "").split(",").filter(Boolean)'
JWT_ALG = re.compile(r"^(?:HS|RS|ES|PS)(?:256|384|512)$|^EdDSA$")
MONEY = r"(?:price|amount|balance|cost|total|fee|fees|salary|subtotal|tax|discount|credit|credits|revenue|payout|refund|wage)\w*"
MIGRATION_PATH = re.compile(r"(?i)(?:^|/)(?:migrations?|migrate|db/migrate|alembic|versions)(?:/|$)")


# ---------------------------------------------------------------- file context
class FileCtx:
    """One file's text (LF line endings, no BOM) with lazily built views."""

    def __init__(self, rel: str, text: str, project=None):
        self.rel = rel
        self.text = text
        self.project = project
        ext = rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
        self.kind = {"py": "py", "sql": "sql", "prisma": "prisma"}.get(ext, "js" if rel.lower().endswith(JS_FIX_EXTS) else "")
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]
        self._tree: Optional[ast.AST] = None
        self._views = None
        self.used: set = set()  # calls already claimed by a finding

    @property
    def tree(self) -> ast.Module:
        if self._tree is None:
            self._tree = ast.parse(self.text)
        return self._tree  # type: ignore[return-value]

    @property
    def views(self):
        if self._views is None:
            self._views = py_views(self.text) if self.kind == "py" else js_views(self.text)
        return self._views

    def line_start(self, n: int) -> int:
        return self.starts[n - 1] if 1 <= n <= len(self.starts) else len(self.text)

    def line_end(self, n: int) -> int:
        e = self.text.find("\n", self.line_start(n))
        return len(self.text) if e < 0 else e

    def pos(self, lineno: int, col: int) -> int:
        """Offset of an ast position; ast columns count UTF-8 bytes."""
        a = self.line_start(lineno)
        line = self.text[a:self.line_end(lineno)]
        return a + len(line.encode("utf-8")[:col].decode("utf-8", "ignore"))

    def span(self, node: ast.AST) -> Tuple[int, int]:
        return (self.pos(node.lineno, node.col_offset),  # type: ignore[attr-defined]
                self.pos(node.end_lineno, node.end_col_offset))  # type: ignore[attr-defined]

    def seg(self, node: ast.AST) -> str:
        a, b = self.span(node)
        return self.text[a:b]

    def line_of(self, offset: int) -> int:
        import bisect

        return bisect.bisect_right(self.starts, offset)

    def indent_of(self, offset: int) -> str:
        a = self.text.rfind("\n", 0, offset) + 1
        return re.match(r"[ \t]*", self.text[a:]).group(0)  # type: ignore[union-attr]

    def unit(self) -> str:
        """The file's indentation step: a tab, two or four spaces."""
        tabs = len(re.findall(r"(?m)^\t+\S", self.text))
        spaces = [len(m.group(1)) for m in re.finditer(r"(?m)^( +)[^ \t*\n]", self.text)]
        if tabs > len(spaces):
            return "\t"
        if self.kind == "py":
            return "    " if not spaces or any(s % 4 == 0 for s in spaces) and not any(s % 4 == 2 for s in spaces) else "  "
        return "    " if spaces and not any(s % 4 == 2 for s in spaces) else "  "


def append_item(ctx: FileCtx, open_idx: int, close_idx: int, last_end: Optional[int], item: str) -> List[Edit]:
    """Edits that add `item` as the last argument / property / element between two brackets, following the
    existing layout (one item per line, trailing comma or not)."""
    text, bare = ctx.text, ctx.views.bare
    if last_end is None:
        return [(open_idx + 1, open_idx + 1, item)]
    tail = bare[last_end:close_idx]
    comma = tail.lstrip().startswith(",")
    close_line = text.rfind("\n", 0, close_idx) + 1
    if not text[close_line:close_idx].strip() and "\n" in text[last_end:close_idx]:
        indent = ctx.indent_of(last_end)
        nl = text.find("\n", last_end)
        if comma:
            return [(nl + 1, nl + 1, f"{indent}{item},\n")]
        return [(last_end, last_end, ","), (nl + 1, nl + 1, f"{indent}{item}\n")]
    if comma:
        c = last_end + tail.index(",") + 1
        return [(c, c, " " + item)]
    return [(last_end, last_end, ", " + item)]


def js_last_end(bare: str, open_idx: int, close_idx: int) -> Optional[int]:
    """End of the last item between two brackets in the bare view (a trailing comma is skipped)."""
    j = close_idx - 1
    while j > open_idx and bare[j].isspace():
        j -= 1
    if bare[j] == ",":
        j -= 1
        while j > open_idx and bare[j].isspace():
            j -= 1
    return None if j <= open_idx else j + 1


# ------------------------------------------------------------- python helpers
def py_calls_on_line(ctx: FileCtx, line: int, pred: Callable[[ast.Call, str], bool]) -> List[ast.Call]:
    """Matching calls that start on `line`, left to right, without those an earlier finding on the same line
    already took (several findings of one rule can share a line); the first one is taken."""
    calls = [n for n in ast.walk(ctx.tree) if isinstance(n, ast.Call) and n.lineno == line and id(n) not in ctx.used
             and pred(n, dotted(n.func))]
    calls.sort(key=lambda c: c.col_offset)
    if calls:
        ctx.used.add(id(calls[0]))
    return calls


def py_append_arg(ctx: FileCtx, call: ast.Call, item: str) -> List[Edit]:
    func_end = ctx.span(call.func)[1]
    close_idx = ctx.span(call)[1] - 1
    open_idx = ctx.views.bare.index("(", func_end)
    items = [ctx.span(a)[1] for a in list(call.args) + list(call.keywords)]
    return append_item(ctx, open_idx, close_idx, max(items) if items else None, item)


def py_append_dict(ctx: FileCtx, node: ast.Dict, item: str) -> List[Edit]:
    a, b = ctx.span(node)
    ends = [ctx.span(v)[1] for v in node.values]
    return append_item(ctx, a, b - 1, max(ends) if ends else None, item)


def py_ensure_import(ctx: FileCtx, need: str, modules: Sequence[str], sibling: str) -> Optional[List[Edit]]:
    """Add `need` to the top-level `from <module> import ... sibling ...` statement. None if there is none."""
    for node in ctx.tree.body:
        if isinstance(node, ast.ImportFrom) and node.module in modules and any(a.name == sibling for a in node.names):
            if any(a.name == need and a.asname is None for a in node.names):
                return []
            a, b = ctx.span(node)
            if ctx.text[b - 1] == ")":
                return append_item(ctx, ctx.text.index("(", a), b - 1, js_last_end(ctx.views.bare, ctx.text.index("(", a), b - 1), need)
            return [(b, b, ", " + need)]
    return None


def py_ensure_module(ctx: FileCtx, module: str) -> List[Edit]:
    body = ctx.tree.body
    if any(isinstance(n, ast.Import) and any(a.name == module and a.asname is None for a in n.names) for n in body):
        return []
    imports = [n for n in body if isinstance(n, (ast.Import, ast.ImportFrom))]
    future = [n for n in imports if isinstance(n, ast.ImportFrom) and n.module == "__future__"]
    plain = [n for n in imports if n not in future]
    if plain:
        at = ctx.line_start(plain[0].lineno)
    elif future:
        at = ctx.line_start(future[-1].end_lineno + 1)  # type: ignore[operator]
    elif body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        at = ctx.line_start(body[0].end_lineno + 1)  # type: ignore[operator]
    elif body:
        at = ctx.line_start(body[0].lineno)
    else:
        at = 0
    if at > len(ctx.text) or (at == len(ctx.text) and ctx.text and not ctx.text.endswith("\n")):
        return [(len(ctx.text), len(ctx.text), f"\nimport {module}\n")]
    return [(at, at, f"import {module}\n")]


def multiline_string(node: ast.AST) -> bool:
    return any(isinstance(n, (ast.Constant, ast.JoinedStr)) and n.lineno != n.end_lineno  # type: ignore[attr-defined]
               for n in ast.walk(node) if isinstance(n, (ast.Constant, ast.JoinedStr)))


# --------------------------------------------------------------------- REL001
def fix_timeout(ctx: FileCtx, f: Finding) -> Result:
    if ctx.kind != "py":
        return "only Python requests and urlopen calls are rewritten"
    calls = py_calls_on_line(ctx, f.line, lambda c, d: (d.startswith("requests.") or d.endswith("urlopen")) and not any(
        k.arg in (None, "timeout") for k in c.keywords))
    if not calls:
        return "no call without a timeout on this line"
    # the scanner merges identical findings on one line, so every such call on the line is fixed here
    edits: List[Edit] = []
    for call in calls:
        ctx.used.add(id(call))
        if not (dotted(call.func).endswith("urlopen") and len(call.args) >= 3):  # urlopen(url, data, timeout)
            edits += py_append_arg(ctx, call, f"timeout={TIMEOUT_SECONDS}")
    return edits or "the timeout is passed positionally"


# --------------------------------------------------------------------- LLM003
def _ai_sdk_major(ctx: FileCtx) -> Optional[int]:
    pkg = ctx.project.nearest_package_json(ctx.rel) if ctx.project is not None else None
    for section in ("dependencies", "devDependencies"):
        spec = ((pkg or {}).get(section) or {}).get("ai")
        if isinstance(spec, str):
            m = re.search(r"\d+", spec)
            return int(m.group(0)) if m else None
    return None


def fix_token_limit(ctx: FileCtx, f: Finding) -> Result:
    if ctx.kind == "py":
        def wanted(c: ast.Call, d: str) -> bool:
            return (d.endswith(TOKEN_LIMIT_CALLS) or (isinstance(c.func, ast.Name) and c.func.id in LC_CTORS)
                    or d.endswith(("generate_content", "generate_content_async", "generate_content_stream")))

        calls = py_calls_on_line(ctx, f.line, lambda c, d: wanted(c, d) and not any(k.arg is None for k in c.keywords))
        if not calls:
            return "no model call on this line"
        call = calls[0]
        d = dotted(call.func)
        kws = {k.arg: k.value for k in call.keywords}
        if d.endswith(("generate_content", "generate_content_async", "generate_content_stream")):
            cfg = kws.get("config") or kws.get("generation_config")
            if isinstance(cfg, ast.Call):
                return py_append_arg(ctx, cfg, f"max_output_tokens={MAX_OUTPUT_TOKENS}")
            if isinstance(cfg, ast.Dict):
                return py_append_dict(ctx, cfg, f'"max_output_tokens": {MAX_OUTPUT_TOKENS}')
            return "the Gemini call has no inline config to add max_output_tokens to"
        if d.endswith(("responses.create", "responses.parse")):
            key = "max_output_tokens"
        elif d.endswith(("chat.completions.create", "chat.completions.parse")):
            key = "max_completion_tokens"
        elif isinstance(call.func, ast.Name) and call.func.id == "ChatGoogleGenerativeAI":
            key = "max_output_tokens"
        else:
            key = "max_tokens"
        return py_append_arg(ctx, call, f"{key}={MAX_OUTPUT_TOKENS}")
    if ctx.kind != "js":
        return "unsupported file type"
    bare, a, b = ctx.views.bare, ctx.line_start(f.line), ctx.line_end(f.line)
    rx = re.compile(r"\.\s*(chat\s*\.\s*completions\s*\.\s*(?:create|parse)|completions\s*\.\s*create|responses\s*\.\s*create)\s*\(|"
                    r"\b(generateText|streamText|generateObject|streamObject)\s*\(")
    m = rx.search(bare, a, b)
    if not m:
        return "no model call that takes an options object on this line"
    open_paren = m.end() - 1
    close = match_close(bare, open_paren)
    args = split_args(bare, open_paren + 1, close) if close > 0 else []
    if not args or not bare[args[0][0]:args[0][1]].strip().startswith("{"):
        return "the options are not an object literal"
    o = bare.index("{", args[0][0])
    oc = match_close(bare, o)
    if oc < 0:
        return "unbalanced options object"
    method = re.sub(r"\s", "", m.group(1) or "")
    if m.group(2):
        major = _ai_sdk_major(ctx)
        if major is None:
            return "cannot tell the AI SDK version from package.json"
        key = "maxOutputTokens" if major >= 5 else "maxTokens"
    elif method.startswith("chat."):
        key = "max_completion_tokens"
    elif method.startswith("responses."):
        key = "max_output_tokens"
    else:
        key = "max_tokens"
    return append_item(ctx, o, oc, js_last_end(bare, o, oc), f"{key}: {MAX_OUTPUT_TOKENS}")


# --------------------------------------------------------------------- LLM011
def _wrap_lines(ctx: FileCtx, first: int, last: int, before: str, after: str) -> Edit:
    """Replace lines first..last with `before`, the lines one step deeper, then `after` (both may use {i}
    for the original indentation and {u} for one indentation step)."""
    a, b = ctx.line_start(first), ctx.line_end(last)
    ind, u = ctx.indent_of(a), ctx.unit()
    body = "\n".join(u + ln if ln.strip() else ln for ln in ctx.text[a:b].split("\n"))
    return (a, b, before.format(i=ind, u=u) + body + after.format(i=ind, u=u))


def fix_json_parse(ctx: FileCtx, f: Finding) -> Result:
    if ctx.kind == "py":
        calls = py_calls_on_line(ctx, f.line, lambda c, d: d in ("json.loads", "json.load", "loads", "load"))
        if not calls:
            return "no json.loads() call on this line"
        cs, ce = ctx.span(calls[0])
        stmts = [n for n in ast.walk(ctx.tree) if isinstance(n, (ast.Assign, ast.AnnAssign, ast.Return))
                 and ctx.span(n)[0] <= cs and ce <= ctx.span(n)[1]]
        if not stmts:
            return "the call is not part of an assignment or return statement"
        st = min(stmts, key=lambda n: ctx.span(n)[1] - ctx.span(n)[0])
        sa, se = ctx.span(st)
        if ctx.text[ctx.line_start(st.lineno):sa].strip() or ctx.views.bare[se:ctx.line_end(st.end_lineno)].strip():  # type: ignore[arg-type]
            return "the statement shares its line with other code"
        if multiline_string(st):
            return "the statement contains a multi-line string"
        if isinstance(st, ast.Return):
            fallback = "return None"
        else:
            targets = st.targets if isinstance(st, ast.Assign) else [st.target]
            if any(isinstance(t, (ast.Tuple, ast.List, ast.Starred)) for t in targets):
                return "the result is unpacked"
            fallback = " = ".join(ctx.seg(t) for t in targets) + " = None"
        return [_wrap_lines(ctx, st.lineno, st.end_lineno, "{i}try:\n", "\n{i}except ValueError:\n{i}{u}" + fallback)]  # type: ignore[arg-type]
    if ctx.kind != "js":
        return "unsupported file type"
    bare, code = ctx.views.bare, ctx.views.code
    a = ctx.line_start(f.line)
    m = re.compile(r"([ \t]*)(?:(const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*([^=\n;]+?))?\s*=(?![=>])\s*|(return)\s+"
                   r"|([A-Za-z_$][\w$.]*)\s*=(?![=>])\s*)").match(bare, a)
    if not m:
        return "JSON.parse() is not the value of a declaration, assignment or return statement"
    # only at a statement boundary: after `x =>` or inside an expression a try block would not be valid
    prev = bare[:a].rstrip()[-1:]
    if not (prev in ("", ";", "{", "}") or (prev == ")" or re.search(r"\b(?:else|do)$", bare[:a].rstrip())) and not m.group(2)):
        return "the statement does not start at a statement boundary"
    expr = m.end()
    end = stmt_end(bare, expr)
    if not re.search(r"\bJSON\s*\.\s*parse\s*\(", bare[expr:end]):
        return "JSON.parse() is not the value of a declaration, assignment or return statement"
    rest_start = end + 1 if bare[end:end + 1] == ";" else end
    last = ctx.line_of(max(rest_start - 1, expr))
    if bare[rest_start:ctx.line_end(last)].strip() or "`" in code[expr:end] and ctx.line_of(end) != f.line:
        return "the statement shares its line with other code or spans a template literal"
    value = ctx.text[expr:end].rstrip()
    ind, u = m.group(1), ctx.unit()
    value = value.replace("\n", "\n" + u)
    if m.group(5):
        new = f"{ind}try {{\n{ind}{u}return {value};\n{ind}}} catch {{\n{ind}{u}return null;\n{ind}}}"
    else:
        name = m.group(3) or m.group(6)
        head = ""
        if m.group(2):
            ann = m.group(4)
            typ = "" if not ann else (f": {ann.strip()} | null" if re.fullmatch(r"[\w$.<>\[\], ]+", ann.strip()) else f": ({ann.strip()}) | null")
            head = f"{ind}{'var' if m.group(2) == 'var' else 'let'} {name}{typ};\n"
        new = f"{head}{ind}try {{\n{ind}{u}{name} = {value};\n{ind}}} catch {{\n{ind}{u}{name} = null;\n{ind}}}"
    return [(a, ctx.line_end(last), new)]


# ------------------------------------------------------------ BE016 / AUTH011
def _issued_algorithm(ctx: FileCtx) -> Optional[str]:
    """How the file issues tokens: the literal or the expression given to jwt.encode / jwt.sign."""
    if ctx.kind == "py":
        for n in ast.walk(ctx.tree):
            if isinstance(n, ast.Call) and dotted(n.func).endswith("jwt.encode"):
                for k in n.keywords:
                    if k.arg == "algorithm":
                        if isinstance(k.value, ast.Constant) and isinstance(k.value.value, str):
                            return repr(k.value.value) if JWT_ALG.match(k.value.value) else None
                        if isinstance(k.value, (ast.Name, ast.Attribute)):
                            return ctx.seg(k.value)
        for n in ctx.tree.body:
            if (isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                    and re.search(r"(?i)algorithm", n.targets[0].id) and isinstance(n.value, ast.Constant)
                    and isinstance(n.value.value, str) and JWT_ALG.match(n.value.value)):
                return n.targets[0].id
        return None
    m = re.search(r"""\bjwt\s*\.\s*sign\s*\([^;]{0,400}?\balgorithm\s*:\s*(['"])(\w+)\1""", ctx.views.code)
    return repr(m.group(2)) if m and JWT_ALG.match(m.group(2)) else None


def _list_after(ctx: FileCtx, a: int, b: int, key: str) -> Optional[Tuple[int, int]]:
    m = re.compile(key + r"""['"]?\s*[:=]\s*\[""").search(ctx.views.bare, a, b)
    if not m:
        return None
    close = match_close(ctx.views.bare, m.end() - 1)
    return (m.end() - 1, close) if close > 0 else None


def fix_jwt(ctx: FileCtx, f: Finding) -> Result:
    if ctx.kind not in ("py", "js"):
        return "unsupported file type"
    a, b = ctx.line_start(f.line), ctx.line_end(f.line)
    code, bare = ctx.views.code, ctx.views.bare
    if f.rule_id == "BE016" and "expiry" in f.message:
        m = re.search(r"\bignoreExpiration\s*:\s*(true)\b", code[a:b])
        return [(a + m.start(1), a + m.end(1), "false")] if m else "no ignoreExpiration on this line"
    calls = py_calls_on_line(ctx, f.line, lambda c, d: d.endswith("jwt.decode") or d == "decode") if ctx.kind == "py" else []
    algs = next((k.value for k in calls[0].keywords if k.arg == "algorithms"), None) if calls else None
    if isinstance(algs, (ast.List, ast.Tuple)):
        o, c = ctx.span(algs)
        span: Optional[Tuple[int, int]] = (o, c - 1)
    else:
        span = None if calls else _list_after(ctx, a, b, "algorithms")
    if span:
        o, c = span
        items = [ctx.text[s:e].strip() for s, e in split_args(bare, o + 1, c)]
        if f.rule_id == "BE016":
            keep = [t for t in items if not re.fullmatch(r"""(['"])none\1""", t, re.I)]
            if not keep or len(keep) == len(items):
                return "no algorithm other than 'none' is listed" if not keep else "no 'none' entry to remove"
            return [(o + 1, c, ", ".join(keep))]
        issued = _issued_algorithm(ctx)
        match = [t for t in items if issued and t.strip("'\"") == issued.strip("'\"")]
        if match:
            return [(o + 1, c, match[0])]
        return "the file does not show which algorithm the tokens are signed with"
    if f.rule_id == "BE016":
        return "the token is decoded without verification; the fix needs the verification key (try --llm)"
    if ctx.kind != "py":
        return "no algorithms list on this line"
    if not calls or any(k.arg in (None, "algorithms", "verify") for k in calls[0].keywords):
        return "no jwt.decode() call without algorithms on this line"
    call = calls[0]
    issued = _issued_algorithm(ctx)
    if issued is None:
        key = ctx.seg(call.args[1]) if len(call.args) > 1 else ""
        key = key or next((ctx.seg(k.value) for k in call.keywords if k.arg == "key"), "")
        if re.search(r"(?i)pub|pem|jwk|cert|rsa|ec_?key", key):
            return "the key looks like a public key and the file does not show the algorithm"
        issued = '"HS256"'
    if issued.startswith("'"):
        issued = '"' + issued[1:-1] + '"'
    return py_append_arg(ctx, call, f"algorithms=[{issued}]")


# --------------------------------------------------------------------- DATA004
def fix_money(ctx: FileCtx, f: Finding) -> Result:
    p, s = MONEY_PRECISION
    a, b = ctx.line_start(f.line), ctx.line_end(f.line)
    if ctx.kind == "prisma":
        m = re.compile(r"[ \t]*" + MONEY + r"[ \t]+(Float)\b", re.I).match(ctx.text, a, b)
        return [(m.start(1), m.end(1), "Decimal")] if m else "no Float money field on this line"
    if ctx.kind == "sql":
        if MIGRATION_PATH.search(ctx.rel):
            return "an applied migration must not be edited; add a new migration that alters the column"
        clean = re.sub(r"--[^\n]*|/\*[\s\S]*?\*/", lambda x: re.sub(r"[^\n]", " ", x.group(0)), ctx.text)
        m = re.compile(r"(?i)\b" + MONEY + r"\b\s+(float4?|float8|real|double\s+precision|double)\b").search(clean, a)
        if not m or m.start() >= b:
            return "no floating-point money column on this line"
        new = f"numeric({p}, {s})" if m.group(1).islower() else f"NUMERIC({p}, {s})"
        return [(m.start(1), m.end(1), new)]
    if ctx.kind != "py":
        return "unsupported file type"
    stmt = next((n for n in ast.walk(ctx.tree) if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.lineno == f.line
                 and n.value is not None), None)
    if stmt is None:
        return "no assignment on this line"
    edits: List[Edit] = []
    for n in ast.walk(stmt.value):  # type: ignore[arg-type]
        if isinstance(n, ast.Call) and last_name(n.func) == "FloatField":
            fa, fb = ctx.span(n.func)
            edits.append((fb - len("FloatField"), fb, "DecimalField"))
            edits += py_append_arg(ctx, n, f"max_digits={p}, decimal_places={s}")
            if isinstance(n.func, ast.Name):
                imp = py_ensure_import(ctx, "DecimalField", ("django.db.models",), "FloatField")
                if imp is None:
                    return "cannot find the import of FloatField"
                edits += imp
    if not edits:
        float_nodes = [n for n in ast.walk(stmt.value) if last_name(n) == "Float" and isinstance(n, (ast.Name, ast.Attribute))]  # type: ignore[arg-type]
        calls = {id(c.func): c for c in ast.walk(stmt.value) if isinstance(c, ast.Call)}  # type: ignore[arg-type]
        for n in float_nodes:
            target = calls.get(id(n), n)
            ta, tb = ctx.span(target)
            prefix = ctx.seg(n.value) + "." if isinstance(n, ast.Attribute) else ""
            edits.append((ta, tb, f"{prefix}Numeric({p}, {s})"))
            if isinstance(n, ast.Name):
                imp = py_ensure_import(ctx, "Numeric", ("sqlalchemy", "sqlalchemy.types", "sqlalchemy.sql.sqltypes"), "Float")
                if imp is None:
                    return "cannot find the import of Float"
                edits += imp
    return edits or "no Float column or FloatField on this line"


# ---------------------------------------------------------------------- BE012
def fix_cors(ctx: FileCtx, f: Finding) -> Result:
    if ctx.kind == "py":
        calls = py_calls_on_line(ctx, f.line, lambda c, d: last_name(c.func) in ("CORS", "add_middleware"))
        if not calls:
            return "no CORS call on this line"
        call = calls[0]
        kws = {k.arg: k.value for k in call.keywords}
        key = "allow_origins" if last_name(call.func) == "add_middleware" else "origins"
        if "resources" in kws or "allow_origin_regex" in kws:
            return "origins are set per resource or by a regular expression"
        edits = py_ensure_module(ctx, "os")
        if key in kws:
            va, vb = ctx.span(kws[key])
            return edits + [(va, vb, PY_CORS_ORIGINS)]
        return edits + py_append_arg(ctx, call, f"{key}={PY_CORS_ORIGINS}")
    if ctx.kind != "js":
        return "unsupported file type"
    bare, code = ctx.views.bare, ctx.views.code
    m = re.compile(r"\bcors\s*\(").search(bare, ctx.line_start(f.line), ctx.line_end(f.line))
    if not m:
        return "the origin is set in a response header; it needs an allow-list check (try --llm)"
    close = match_close(bare, m.end() - 1)
    o = re.compile(r"\borigin\s*:\s*(['\"]\*['\"]|true\b)").search(code, m.end(), close if close > 0 else m.end())
    if not o or bare[o.start()] != "o":  # `origin:` inside a string is not the option
        return "the origin option is not a literal in this call"
    return [(o.start(1), o.end(1), JS_CORS_ORIGINS)]


FIXERS: Dict[str, Callable[[FileCtx, Finding], Result]] = {
    "REL001": fix_timeout,
    "LLM003": fix_token_limit,
    "LLM011": fix_json_parse,
    "BE016": fix_jwt,
    "AUTH011": fix_jwt,
    "DATA004": fix_money,
    "BE012": fix_cors,
}


# ------------------------------------------------------------------ the plan
def parses(kind: str, text: str) -> bool:
    if kind == "py":
        try:
            ast.parse(text)
            return True
        except (SyntaxError, ValueError, RecursionError):
            return False
    if kind == "js":
        return balanced(js_views(text).bare)
    return True


def balanced(bare: str) -> bool:
    stack: List[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for ch in bare:
        if ch in "([{":
            stack.append(ch)
        elif ch in pairs:
            if not stack or stack.pop() != pairs[ch]:
                return False
    return not stack


def apply_edits(text: str, edits: List[Edit]) -> str:
    for a, b, s in sorted(edits, key=lambda e: (e[0], e[1]), reverse=True):
        text = text[:a] + s + text[b:]
    return text


@dataclass
class Change:
    file: str
    path: Path
    original: bytes
    before: str
    after: str
    eol: str
    bom: bool
    fixed: List[Finding] = field(default_factory=list)

    def diff(self) -> str:
        def split(text: str) -> List[str]:  # the file's own line endings, so `git apply` takes the patch
            return [ln + self.eol for ln in text.split("\n")[:-1]] + ([text.rsplit("\n", 1)[-1]] if not text.endswith("\n") else [])

        out = difflib.unified_diff(split(self.before), split(self.after), f"a/{self.file}", f"b/{self.file}")
        lines = []
        for ln in out:
            lines.append(ln if ln.endswith("\n") else ln + "\n\\ No newline at end of file\n")
        return "".join(lines)

    def encoded(self) -> bytes:
        text = self.after.replace("\n", "\r\n") if self.eol == "\r\n" else self.after
        return ("\ufeff" if self.bom else "").encode("utf-8") + text.encode("utf-8")


@dataclass
class Plan:
    root: Path
    changes: List[Change] = field(default_factory=list)
    skipped: List[Tuple[Finding, str]] = field(default_factory=list)

    def diff(self) -> str:
        return "".join(c.diff() for c in self.changes)

    @property
    def fixed(self) -> List[Finding]:
        return [f for c in self.changes for f in c.fixed]

    def apply(self) -> List[str]:
        """Write every change; a file that changed on disk since it was read is left alone. Returns the files written."""
        written = []
        for c in self.changes:
            try:
                if c.path.read_bytes() != c.original:
                    continue
                c.path.write_bytes(c.encoded())
            except OSError:
                continue
            written.append(c.file)
        return written


def read_text(path: Path) -> Union[Tuple[str, str, bool], str]:
    """(text with LF endings, original line ending, had a BOM), or the reason the file cannot be edited safely."""
    try:
        data = path.read_bytes()
    except OSError as e:
        return f"cannot read the file ({e.strerror})"
    bom = data.startswith(b"\xef\xbb\xbf")
    try:
        text = data[3 if bom else 0:].decode("utf-8")
    except UnicodeDecodeError:
        return "the file is not UTF-8"
    crlf, lf = text.count("\r\n"), text.count("\n")
    if text.count("\r") != crlf or (crlf and crlf != lf):
        return "the file mixes line endings"
    return text.replace("\r\n", "\n"), ("\r\n" if crlf else "\n"), bom


def plan_findings(root: Path, findings: Sequence[Finding], project=None, texts: Optional[Dict[str, str]] = None) -> Plan:
    """Plan fixes for `findings`. `texts` maps a file to the text to fix instead of its content on disk (an
    editor's unsaved buffer); such changes are for showing, not for `Plan.apply`."""
    plan = Plan(root)
    by_file: Dict[str, List[Finding]] = {}
    for f in findings:
        if f.rule_id not in FIXERS or f.source != "vibeaudit" or not f.line:
            plan.skipped.append((f, "no automatic fix for this rule"))
        else:
            by_file.setdefault(f.file, []).append(f)
    resolved_root = root.resolve()
    for rel in sorted(by_file):
        fs = sorted(by_file[rel], key=lambda f: f.line)
        path = root / rel
        try:
            inside = path.resolve().is_relative_to(resolved_root) if hasattr(Path, "is_relative_to") else \
                str(path.resolve()).startswith(str(resolved_root))
        except OSError:
            inside = False
        if not inside:
            got: Union[Tuple[str, str, bool], str] = "the file is outside the project"
        elif texts is not None and rel in texts:
            buf = texts[rel]
            got = (buf.replace("\r\n", "\n"), "\r\n" if "\r\n" in buf else "\n", False)
        else:
            got = read_text(path)
        if isinstance(got, str):
            plan.skipped += [(f, got) for f in fs]
            continue
        text, eol, bom = got
        ctx = FileCtx(rel, text, project)
        if ctx.kind == "py" and not parses("py", text):
            plan.skipped += [(f, "the file does not parse") for f in fs]
            continue
        edits: List[Edit] = []
        fixed: List[Finding] = []
        for f in fs:
            try:
                res = FIXERS[f.rule_id](ctx, f)
            except (ValueError, IndexError, AttributeError, SyntaxError, RecursionError) as e:
                res = f"internal error in the codemod ({type(e).__name__})"
            if isinstance(res, str):
                plan.skipped.append((f, res))
                continue
            new = [e for e in res if e not in edits]
            if any(a < eb and ea < b for a, b, _s in new for ea, eb, _es in edits):
                plan.skipped.append((f, "overlaps another fix in this file"))
                continue
            if not new and not res:
                plan.skipped.append((f, "nothing to change"))
                continue
            edits += new
            fixed.append(f)
        if not fixed:
            continue
        after = apply_edits(text, edits)
        old_ok = parses(ctx.kind, text)
        ok = parses(ctx.kind, after) if (ctx.kind != "js" or old_ok) else all(
            balanced(js_views(s).bare) for _a, _b, s in edits) and all(balanced(js_views(text[a:b]).bare) for a, b, _s in edits)
        if not ok or after == text:
            plan.skipped += [(f, "the fixed file would not parse") for f in fixed]
            continue
        original = b"" if texts is not None and rel in texts else path.read_bytes()
        plan.changes.append(Change(rel, path, original, text, after, eol, bom, fixed))
    return plan


def plan(root: str, rules: Sequence[str] = (), opts=None) -> Plan:
    """Scan `root` and plan a fix for every finding a codemod covers (only `rules` when given)."""
    from .config import project_options
    from .files import Project
    from .scanner import scan

    opts = opts or project_options(root, offline=True, external="none")
    res = scan(root, opts)
    wanted = {r.upper() for r in rules}
    findings = [f for f in res.findings if not wanted or f.rule_id in wanted]
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.file, f.line))
    return plan_findings(Path(root), findings, Project(Path(root), opts.excludes, opts.max_file_bytes))


# ------------------------------------------------------------ LLM patches
AGENTIC_CATEGORIES = ("auth", "backend", "data", "llm", "reliability")
PATCH_RADIUS = 30


def patches(root: Path, skipped: Sequence[Tuple[Finding, str]], provider, max_requests: int,
            log: Callable[[str], None]) -> Tuple[str, int]:
    """Ask the model for a patch for each finding without a codemod (most severe first). Returns the combined
    unified diff and the number of findings it covers. Nothing is applied; every hunk is checked to keep the
    file parseable and never to contain redacted text."""
    from .llm import LLMError, parse_json, redact

    out, count = [], 0
    todo = [f for f, _r in skipped if f.category in AGENTIC_CATEGORIES and f.line and f.source == "vibeaudit"]
    todo.sort(key=lambda f: SEVERITY_RANK.get(f.severity, 9))
    for f in todo:
        if provider.requests >= max_requests:
            log(f"LLM patches stopped after {provider.requests} requests (limit {max_requests}).")
            break
        got = read_text(root / f.file)
        if isinstance(got, str):
            continue
        text = got[0]
        lines = text.split("\n")
        lo, hi = max(1, f.line - PATCH_RADIUS), min(len(lines), f.line + PATCH_RADIUS)
        numbered = "\n".join(f"{i:5d}| {lines[i - 1]}" for i in range(lo, hi + 1))
        prompt = (
            f"Fix this finding with the smallest correct change.\nRule {f.rule_id}: {f.title}\nWhy: {f.why}\nFix: {f.fix}\n"
            f"Finding at line {f.line}: {f.message}\n"
            f'Reply with JSON: {{"start_line": <int>, "end_line": <int>, "replacement": "<the new text of those lines>", '
            f'"explanation": "<one sentence>"}}. start_line and end_line must be between {lo} and {hi}; the replacement '
            f"replaces those whole lines and keeps their indentation. If you cannot fix it safely, reply "
            f'{{"start_line": 0}}.\n\n<code file="{f.file}">\n{redact(numbered)}\n</code>')
        try:
            data = parse_json(provider.complete(prompt))
            s, e, rep = int(data["start_line"]), int(data.get("end_line", 0)), data.get("replacement")
        except (LLMError, KeyError, TypeError, ValueError, AttributeError) as err:
            log(f"LLM patch for {f.rule_id} at {f.file}:{f.line}: {err}")
            continue
        if not (lo <= s <= e <= hi) or not isinstance(rep, str) or "REDACTED" in rep:
            continue
        new_lines = lines[:s - 1] + rep.rstrip("\n").split("\n") + lines[e:]
        after = "\n".join(new_lines)
        kind = FileCtx(f.file, text).kind
        if after == text or not parses(kind or "txt", after):
            log(f"LLM patch for {f.rule_id} at {f.file}:{f.line} rejected: it does not parse or changes nothing.")
            continue
        out.append(f"# {f.rule_id} {f.file}:{f.line} (model-generated, unverified): {str(data.get('explanation', ''))[:200]}\n")
        out.append(Change(f.file, root / f.file, b"", text, after, "\n", False).diff())
        count += 1
    return "".join(out), count
