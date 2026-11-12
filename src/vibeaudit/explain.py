"""`vibeaudit explain FINDING`: why a finding was reported, and the code path that led to it.

A finding is chosen by FILE:LINE, FILE:LINE:RULE or a fingerprint prefix (from JSON or SARIF reports). The
explanation shows the rule (what it means, why it matters, how to fix it), the code around the line and, when
the line uses request data or model output, the data flow traced backwards from that line: each assignment
the value went through, up to where it came from (a request field, a route parameter, a model call).

The trace is computed for the explanation from the code (Python: the syntax tree of the enclosing function;
JavaScript and TypeScript: the declarations and assignments above the line). It is a best-effort slice that
follows variables, not calls into other functions.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import List, Optional, Set

from .model import Finding

MAX_DEPTH = 8
ORIGINS = ("source", "parameter")
RESPONSE_NAME = re.compile(r"(?i)r|res|resp|response|completion|chat_?completion|result|reply|answer|out(?:put)?|llm_\w+|model_\w+")


@dataclass
class Step:
    line: int
    code: str
    role: str  # "source", "parameter" (where the trace stops: a function's argument), "assignment" or "sink"
    note: str = ""
    used_by: int = 0  # the line whose value this step feeds (tracing only)

    def to_dict(self) -> dict:
        return {"line": self.line, "code": self.code, "role": self.role, "note": self.note}


def select(findings: List[Finding], ref: str) -> List[Finding]:
    """Findings matching FILE:LINE, FILE:LINE:RULE or a fingerprint prefix (at least 6 hex digits)."""
    ref = ref.strip()
    if re.fullmatch(r"[0-9a-f]{6,32}", ref):
        return [f for f in findings if f.fingerprint.startswith(ref)]
    m = re.fullmatch(r"(.+?):(\d+)(?::([A-Za-z]+\d+))?", ref.replace("\\", "/"))
    if not m:
        return []
    file, line, rule = m.group(1).lstrip("./"), int(m.group(2)), (m.group(3) or "").upper()
    return [f for f in findings if f.file == file and f.line == line and (not rule or f.rule_id == rule)]


def context(text: str, line: int, radius: int = 3) -> List[dict]:
    lines = text.split("\n")
    lo, hi = max(1, line - radius), min(len(lines), line + radius)
    return [{"line": n, "code": lines[n - 1], "current": n == line} for n in range(lo, hi + 1)]


def trace(rel: str, text: str, line: int) -> List[Step]:
    """Source-to-sink steps for the value used on `line`, or [] when no source was found."""
    if rel.endswith((".py", ".pyw")):
        return _python(text, line)
    if re.search(r"\.(?:[cm]?[jt]sx?)$", rel):
        return _javascript(text, line)
    return []


# ------------------------------------------------------------------ python
def _py_source(node: ast.AST) -> str:
    """'user input', 'model output' or '' for an expression."""
    from .pyscan import LLM_SUFFIXES, USER_ATTRS, dotted

    for n in ast.walk(node):
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id in ("request", "req") \
                and n.attr in USER_ATTRS:
            return "user input"
        if isinstance(n, ast.Call):
            d = dotted(n.func)
            if d in ("input", "sys.stdin.read") or d.endswith(".stdin.read"):
                return "user input"
            if d.endswith(LLM_SUFFIXES):
                return "model output"
        # `.choices` alone is also a Django field option: only on a response-like object
        if isinstance(n, ast.Attribute) and n.attr in ("choices", "output_text", "text") and isinstance(n.value, ast.Name) \
                and RESPONSE_NAME.fullmatch(n.value.id):
            return "model output"
    return ""


def _names(node: ast.AST) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}


def _python(text: str, line: int) -> List[Step]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    lines = text.split("\n")
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
             and n.lineno <= line <= (n.end_lineno or n.lineno)]
    scope = min(funcs, key=lambda n: (n.end_lineno or n.lineno) - n.lineno) if funcs else tree
    stmts = [n for n in ast.walk(scope) if isinstance(n, ast.stmt) and n.lineno <= line <= (n.end_lineno or n.lineno)
             and not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    if not stmts:
        return []
    sink = min(stmts, key=lambda n: (n.end_lineno or n.lineno) - n.lineno)

    def code(n: int) -> str:
        return lines[n - 1].strip() if 1 <= n <= len(lines) else ""

    assigns = []  # (line, target name, value node)
    for n in ast.walk(scope):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                assigns += [(n.lineno, x.id, n.value) for x in ast.walk(t) if isinstance(x, ast.Name)]
        elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and isinstance(n.target, ast.Name) and n.value is not None:
            assigns.append((n.lineno, n.target.id, n.value))
        elif isinstance(n, (ast.For, ast.AsyncFor)):
            assigns += [(n.lineno, x.id, n.iter) for x in ast.walk(n.target) if isinstance(x, ast.Name)]
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            for item in n.items:
                if item.optional_vars is not None:
                    assigns += [(n.lineno, x.id, item.context_expr) for x in ast.walk(item.optional_vars) if isinstance(x, ast.Name)]
    params = set()
    route = False
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        params = {a.arg for a in scope.args.args + scope.args.kwonlyargs}
        route = any(re.search(r"\.(?:route|get|post|put|patch|delete|api_route)\(", ast.unparse(d)) for d in scope.decorator_list)

    steps: List[Step] = [Step(line, code(line), "sink")]
    # the expressions on the finding's own line (a multi-line call: only the argument on this line)
    here = [n for n in ast.walk(sink) if getattr(n, "lineno", None) == line and getattr(n, "end_lineno", line) == line] or [sink]
    kind = next((k for k in map(_py_source, here) if k), "")
    if kind:
        steps[0].note = f"{kind} is used directly on this line"
        return steps
    seen: Set[str] = set()
    frontier = [(set().union(*map(_names, here)), line)]
    found: List[Step] = []
    for _ in range(MAX_DEPTH):
        nxt = []
        for names, before in frontier:
            for name in sorted(names - seen):
                seen.add(name)
                earlier = [a for a in assigns if a[1] == name and a[0] < before]
                if not earlier:
                    if name in params and route:
                        found.append(Step(scope.lineno, code(scope.lineno), "source",
                                          f"`{name}` is a route parameter (from the URL)", before))
                    elif name in params and name not in ("self", "cls"):
                        found.append(Step(scope.lineno, code(scope.lineno), "parameter",
                                          f"`{name}` is a parameter of `{scope.name}`; its callers are not followed", before))
                    continue
                at, _n, value = max(earlier, key=lambda a: a[0])
                kind = _py_source(value)
                if kind:
                    found.append(Step(at, code(at), "source", f"`{name}` comes from {kind}", before))
                else:
                    found.append(Step(at, code(at), "assignment", f"`{name}`", before))
                    nxt.append((_names(value), at))
        frontier = nxt
        if not frontier:
            break
    if not any(s.role in ORIGINS for s in found):
        return []
    return _ordered(found, steps[0])


def _ordered(found: List[Step], sink: Step) -> List[Step]:
    """Only the steps on a path from a source to the sink (`used_by` links each step to the line that used
    its value), in line order."""
    at = {}
    for s in found:
        at.setdefault(s.line, s)
    keep = {}
    for s in found:
        if s.role not in ORIGINS:
            continue
        cur, hops = s, 0
        while cur is not None and cur.line != sink.line and hops <= MAX_DEPTH:
            if cur.line not in keep or cur.role in ORIGINS:
                keep[cur.line] = cur
            cur, hops = at.get(cur.used_by), hops + 1
    return sorted(keep.values(), key=lambda s: s.line) + [sink]


# ------------------------------------------------------------------ javascript
JS_KEYWORDS = {
    "const", "let", "var", "await", "return", "new", "if", "else", "for", "while", "function", "async", "true", "false",
    "null", "undefined", "this", "typeof", "of", "in", "export", "default", "import", "from", "JSON", "Math", "console",
    "Object", "Array", "String", "Number", "Promise", "Response", "res", "throw", "try", "catch",
}


def _javascript(text: str, line: int) -> List[Step]:
    from .jsscan import LLM_SRC, USER_SRC
    from .lexer import js_views, stmt_end

    views = js_views(text)
    code, bare = views.code, views.bare
    starts = [0] + [m.end() for m in re.finditer("\n", text)]
    lines = text.split("\n")

    def line_of(off: int) -> int:
        import bisect

        return bisect.bisect_right(starts, off)

    def src(expr: str) -> str:
        return "user input" if USER_SRC.search(expr) else "model output" if LLM_SRC.search(expr) else ""

    a = starts[line - 1] if line - 1 < len(starts) else len(code)
    sink_code = code[a:stmt_end(bare, a) if a < len(bare) else a] or lines[line - 1]
    sink = Step(line, lines[line - 1].strip(), "sink")
    kind = src(sink_code)
    if kind:
        sink.note = f"{kind} is used directly on this line"
        return [sink]

    def idents(expr: str) -> Set[str]:
        return {m.group(1) for m in re.finditer(r"(?<![\w$.])([A-Za-z_$][\w$]*)", expr)} - JS_KEYWORDS

    seen: Set[str] = set()
    found: List[Step] = []
    frontier = [(idents(sink_code), a)]
    for _ in range(MAX_DEPTH):
        nxt = []
        for names, before in frontier:
            for name in sorted(names - seen):
                seen.add(name)
                rx = re.compile(r"(?:\b(?:const|let|var)\s+(?:\{[^}=]*\b" + re.escape(name) + r"\b[^}=]*\}|" + re.escape(name)
                                + r")\s*(?::[^=;\n]+)?|(?<![\w$.])" + re.escape(name) + r")\s*=(?![=>])")
                hits = [m for m in rx.finditer(bare, 0, before)]
                if not hits:
                    continue
                m = hits[-1]
                rhs = code[m.end():stmt_end(bare, m.end())]
                at = line_of(m.start())
                kind = src(rhs)
                user = line_of(before) if before != a else line
                if kind:
                    found.append(Step(at, lines[at - 1].strip(), "source", f"`{name}` comes from {kind}", user))
                else:
                    found.append(Step(at, lines[at - 1].strip(), "assignment", f"`{name}`", user))
                    nxt.append((idents(rhs), m.start()))
        frontier = nxt
        if not frontier:
            break
    if not any(s.role == "source" for s in found):
        return []
    return _ordered(found, sink)


# ------------------------------------------------------------------ the explanation
def explain(f: Finding, text: str) -> dict:
    steps = trace(f.file, text, f.line) if f.line else []
    return {"rule_id": f.rule_id, "title": f.title, "severity": f.severity, "file": f.file, "line": f.line,
            "message": f.message, "why": f.why, "fix": f.fix, "fingerprint": f.fingerprint, "preview": f.preview,
            "code": context(text, f.line) if f.line else [], "flow": [s.to_dict() for s in steps]}


def render(e: dict) -> str:
    out = [f"{e['rule_id']} {e['severity']}  {e['file']}:{e['line']}  {e['title']}" + (" (preview)" if e["preview"] else ""),
           f"  {e['message']}", "", f"Why: {e['why']}", f"Fix: {e['fix']}"]
    if e["code"]:
        width = len(str(e["code"][-1]["line"]))
        out += ["", "Code:"] + [f" {'>' if c['current'] else ' '} {c['line']:>{width}} | {c['code']}" for c in e["code"]]
    if e["flow"]:
        out += ["", "Data flow (traced back from the line, best effort):"]
        for s in e["flow"]:
            label = {"source": "from", "parameter": "from", "assignment": "via", "sink": "to"}[s["role"]]
            out.append(f"  {label:5} {e['file']}:{s['line']}  {s['code']}" + (f"   ({s['note']})" if s["note"] else ""))
    elif e["line"]:
        out += ["", "No data flow from request data or model output was traced to this line; the rule matched the code itself."]
    out.append(f"\nFingerprint: {e['fingerprint']}")
    return "\n".join(out)
