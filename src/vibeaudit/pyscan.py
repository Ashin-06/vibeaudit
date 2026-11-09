"""Python analysis on the real AST, with intra-procedural taint tracking.

Taint kinds:
  user - data from an HTTP request (Flask, FastAPI, Django, Starlette) or a route parameter
  llm  - text returned by a model call
  tool - arguments of an agent tool function (the model chooses them)
"""
from __future__ import annotations

import ast
import re
from typing import Callable, Dict, Iterator, List, Optional, Set, Tuple

from . import heuristics as H
from .files import Project, SourceFile
from .guard import GUARD
from .lexer import py_views
from .model import Finding, Route

Emit = Callable[[Finding], None]
Taint = Dict[str, int]  # kind -> line where it entered

USER_ATTRS = {
    "args", "form", "json", "get_json", "data", "get_data", "values", "files", "cookies", "headers",
    "query_params", "path_params", "body", "stream", "POST", "GET", "FILES", "COOKIES", "META", "query_string",
}
SANITIZERS = {
    "int", "float", "bool", "len", "abs", "round", "secure_filename", "escape", "quote", "basename",
    "clean", "literal_eval", "UUID", "uuid4", "hexdigest", "digest", "sha256", "md5", "urlencode", "quote_plus",
    "isdigit", "isalnum", "count", "startswith", "endswith", "type", "isinstance", "hash", "id",
}
ROUTE_ATTRS = {"route", "get", "post", "put", "patch", "delete", "api_route", "websocket", "head", "options"}
LLM_SUFFIXES = (
    "chat.completions.create", "chat.completions.parse", "completions.create", "responses.create", "responses.parse",
    "messages.create", "messages.stream", "generate_content", "generate_content_async", "generate_content_stream",
    "chat.complete", "chat.stream", "ChatCompletion.create", "ChatCompletion.acreate", "Completion.create",
    "litellm.completion", "litellm.acompletion", "ollama.chat", "ollama.generate", "Runner.run", "Runner.run_sync",
    "invoke_model", "converse", "send_message",
)
LLM_RECEIVER = re.compile(r"(?i)(llm|chain|agent|chat|executor|crew|graph|runnable|gemini|gpt|claude|openai|assistant|rag|qa_)")
TOKEN_LIMIT_CALLS = (
    "chat.completions.create", "chat.completions.parse", "completions.create", "responses.create", "responses.parse",
    "ChatCompletion.create", "litellm.completion", "litellm.acompletion",
)
TOKEN_KW = {"max_tokens", "max_completion_tokens", "max_output_tokens", "max_new_tokens", "generation_config", "config"}
LC_CTORS = {"ChatOpenAI", "AzureChatOpenAI", "ChatGoogleGenerativeAI", "ChatGroq", "ChatMistralAI", "ChatDeepSeek",
            "ChatXAI", "ChatTogether", "ChatFireworks"}
STUB_NAME = re.compile(
    r"(?i)^_?(?:verify|authenticate|authorize|check_auth|check_permission|has_permission|is_admin|is_authori[sz]ed"
    r"|is_authenticated|validate_token|validate_api_key|check_password|check_api_key|require_auth|is_logged_in)"
    r"|^_?(?:is|has|check|validate|can|require|ensure)_\w*(?:auth|token|admin|permission|signature|password|login|jwt"
    r"|credential|api_?key|role|access|webhook)"
)
SECRETISH = re.compile(r"(?i)(token|secret|passw|otp|\bpin\b|reset|verif|nonce|salt|api_?key|session|invite|magic)")
SECRET_VAR = re.compile(
    r"(?i)^(?:api_?key|secret|secret_key|password|passwd|token|access_token|auth_token|private_key|client_secret"
    r"|service_role_key|\w+_api_key|\w+_secret|\w+_token|\w+_password)$"
)
AUTH_ANNOTATION = re.compile(r"(?i)^(?:Authed|Authenticated|Current|Verified|LoggedIn|Logged_in|Admin)\w*$|Depends\(\s*[\w.]*(?:auth|user|token|current|admin|verify)")
BOUND_NAME = re.compile(r"(?i)(max|limit|step|iter|turn|count|attempt|round|budget|tries|retries|n_)")


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return dotted(node.value) + "." + node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func) + "()"
    if isinstance(node, ast.Subscript):
        return dotted(node.value) + "[]"
    return "?"


def last_name(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def root_name(node: ast.AST) -> str:
    while isinstance(node, (ast.Attribute, ast.Call, ast.Subscript)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else ""


def is_llm_call(call: ast.Call, llm_funcs: Set[str]) -> bool:
    d = dotted(call.func)
    if d.endswith(LLM_SUFFIXES) and not (d.endswith("send_message") and not LLM_RECEIVER.search(d)):
        return True
    name = last_name(call.func)
    root = root_name(call.func)
    if name in ("invoke", "ainvoke", "stream", "astream", "batch", "kickoff", "kickoff_async") and LLM_RECEIVER.search(root + "." + d):
        return True
    if name in ("predict", "run", "arun", "chat", "generate", "complete") and isinstance(call.func, ast.Attribute) and LLM_RECEIVER.search(root):
        return True
    if isinstance(call.func, ast.Name) and call.func.id in llm_funcs:
        return True
    if isinstance(call.func, ast.Attribute) and call.func.attr in llm_funcs and root in ("self", "cls"):
        return True
    return False


def const_str(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def is_formatted(node: ast.AST) -> bool:
    """f-string / % / + / .format() with at least one non-constant part."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not (isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return bool(node.args or node.keywords)
    return False


# Placeholder-only SQL formatting: `f"... IN ({','.join('?' * len(ids))})"` and friends only ever insert
# bind markers into the query text; the values themselves travel as parameters.
PLACEHOLDER_TOKEN = re.compile(r"^\s*(?:\?|%s|\$\d+|:\w+|@\w+)\s*$")
PLACEHOLDER_RUN = re.compile(r"^[\s,]*(?:(?:\?|%s|\$\d+|:\w+|@\w+)[\s,]*)+$")
JOIN_SEPARATOR = re.compile(r"^[\s,]*$")
NUMERIC_CALLS = {"len", "int", "min", "max", "sum"}


def interpolated(node: ast.AST) -> List[ast.AST]:
    """The non-constant pieces that a formatted string expression inserts into its text."""
    def operand(n: ast.AST) -> List[ast.AST]:
        if isinstance(n, ast.Constant):
            return []
        if is_formatted(n):
            return interpolated(n)
        return [n]

    if isinstance(node, ast.JoinedStr):
        return [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return operand(node.left) + operand(node.right)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        right = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
        return operand(node.left) + [r for r in right if not isinstance(r, ast.Constant)]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return operand(node.func.value) + list(node.args) + [k.value for k in node.keywords]
    return [node]


def _placeholder_str(node: ast.AST) -> bool:
    s = const_str(node)
    return s is not None and bool(PLACEHOLDER_RUN.match(s))


def placeholder_safe(node: ast.AST, assigned: Dict[str, ast.AST], bound: Set[str] = frozenset(), depth: int = 0) -> bool:
    """True when `node` can only evaluate to SQL bind markers such as "?, ?, ?" or ":p0, :p1"."""
    if depth > 6:
        return False
    if isinstance(node, ast.Name):
        if node.id in bound:
            return True
        if node.id in assigned:
            return placeholder_safe(assigned[node.id], assigned, bound, depth + 1)
        return False
    if isinstance(node, ast.Constant):
        return _placeholder_str(node) or (isinstance(node.value, int) and not isinstance(node.value, bool))
    if isinstance(node, ast.Call):
        name = last_name(node.func)
        if name in NUMERIC_CALLS and isinstance(node.func, ast.Name):
            return True  # numbers cannot carry SQL
        if name == "join" and isinstance(node.func, ast.Attribute) and len(node.args) == 1 and not node.keywords:
            sep = const_str(node.func.value)
            return sep is not None and bool(JOIN_SEPARATOR.match(sep)) and _sequence_safe(node.args[0], assigned, bound, depth + 1)
        return False
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        return any(_placeholder_str(side) for side in (node.left, node.right))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return all(placeholder_safe(s, assigned, bound, depth + 1) or const_str(s) is not None and JOIN_SEPARATOR.match(const_str(s) or "")
                   for s in (node.left, node.right))
    if isinstance(node, ast.JoinedStr):
        # f":p{i}" where i is a loop index: substitute a digit and check the result is one marker
        sample = "".join(str(v.value) if isinstance(v, ast.Constant) else "0" for v in node.values)
        values = [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
        return bool(PLACEHOLDER_RUN.match(sample)) and all(placeholder_safe(v, assigned, bound, depth + 1) for v in values)
    return False


def _sequence_safe(node: ast.AST, assigned: Dict[str, ast.AST], bound: Set[str], depth: int) -> bool:
    """True when every element of the iterable passed to str.join is a bind marker."""
    if isinstance(node, ast.Name) and node.id in assigned and depth <= 6:
        return _sequence_safe(assigned[node.id], assigned, bound, depth + 1)
    if isinstance(node, ast.Constant):
        return _placeholder_str(node)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        for seq, _count in ((node.left, node.right), (node.right, node.left)):
            if _placeholder_str(seq):
                return True
            if isinstance(seq, (ast.List, ast.Tuple)) and seq.elts and all(placeholder_safe(e, assigned, bound, depth) for e in seq.elts):
                return True
        return False
    if isinstance(node, (ast.List, ast.Tuple)):
        return bool(node.elts) and all(placeholder_safe(e, assigned, bound, depth) for e in node.elts)
    if isinstance(node, (ast.GeneratorExp, ast.ListComp)):
        inner = set(bound)
        for gen in node.generators:
            it = gen.iter
            fn = last_name(it.func) if isinstance(it, ast.Call) else ""
            if fn == "range" and isinstance(gen.target, ast.Name):
                inner.add(gen.target.id)  # an integer index
            elif fn == "enumerate" and isinstance(gen.target, ast.Tuple) and gen.target.elts and isinstance(gen.target.elts[0], ast.Name):
                inner.add(gen.target.elts[0].id)  # only the index, never the element
        return placeholder_safe(node.elt, assigned, inner, depth)
    return False


def string_parts(node: ast.AST) -> str:
    return " ".join(n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str))


def walk_shallow(node: ast.AST) -> Iterator[ast.AST]:
    """ast.walk that does not enter nested functions, classes or lambdas."""
    todo = [node]
    while todo:
        n = todo.pop()
        yield n
        for child in ast.iter_child_nodes(n):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                todo.append(child)


def header_exprs(stmt: ast.stmt) -> List[ast.AST]:
    """Expressions evaluated by the statement itself (bodies of compound statements are separate)."""
    if isinstance(stmt, (ast.If, ast.While)):
        return [stmt.test]
    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        return [stmt.iter]
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        return [i.context_expr for i in stmt.items]
    if isinstance(stmt, (ast.Try, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) or type(stmt).__name__ in ("TryStar", "Match"):
        return []
    return [stmt]


def merge(*ts: Taint) -> Taint:
    out: Taint = {}
    for t in ts:
        for k, v in t.items():
            out[k] = min(v, out.get(k, v))
    return out


class Ctx:
    def __init__(self, kind: str, params: Set[str]):
        self.kind = kind  # module | route | tool | plain
        self.env: Dict[str, Taint] = {}
        self.assigned: Dict[str, ast.AST] = {}
        self.params = params
        self.except_names: Set[str] = set()


class PyScanner:
    def __init__(self, project: Project, emit: Emit):
        self.p = project
        self.emit = emit
        self.trees: List[Tuple[SourceFile, ast.Module]] = []
        self.llm_funcs: Set[str] = set()
        self.routes: List[Route] = []
        self.global_auth = False
        self.file_auth: Set[str] = set()
        self.drf_default_auth = False
        self.sf: SourceFile = None  # type: ignore[assignment]
        self.reported: Set[Tuple[str, int, str]] = set()
        self.tool_methods: Set[int] = set()
        self.auth_aliases: Set[str] = set()

    def add(self, rule: str, node: ast.AST, msg: str, sev: str = "") -> None:
        line = getattr(node, "lineno", 1)
        key = (self.sf.rel, line, rule)
        if key in self.reported:
            return
        self.reported.add(key)
        self.emit(Finding(rule, self.sf.rel, line, msg, sev, self.sf.line(line).strip()))

    # --------------------------------------------------------------- phases
    def run(self) -> List[Route]:
        for sf in self.p.of_kind("py"):
            if sf.text is not None:
                GUARD.run(sf.rel, "Python parsing", self._parse, sf)
        GUARD.run("<project>", "Python call graph", self.index)
        for sf, tree in self.trees:
            self.sf = sf
            GUARD.run(sf.rel, "Python checks", self._check_file, sf, tree)
        return self.routes

    def _parse(self, sf: SourceFile) -> None:
        try:
            tree = ast.parse(sf.text or "", filename=sf.rel)
        except (SyntaxError, ValueError):
            return  # not valid Python (templates, Python 2, partial files): nothing to analyse
        self.trees.append((sf, tree))

    def _check_file(self, sf: SourceFile, tree: ast.Module) -> None:
        self.check_comments(sf)
        if not sf.is_test:
            self.scan_module(tree)

    def index(self) -> None:
        bodies: Dict[str, List[ast.AST]] = {}
        for sf, tree in self.trees:
            GUARD.tick()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    bodies.setdefault(node.name, []).append(node)
                elif isinstance(node, ast.Call):
                    d = dotted(node.func)
                    kws = {k.arg: k.value for k in node.keywords if k.arg}
                    deps = kws.get("dependencies")
                    if deps is not None and re.search(r"(?i)user|auth|token|verify|current|admin|security|api_?key",
                                                      ast.unparse(deps)):
                        if d.endswith("APIRouter"):
                            self.file_auth.add(sf.rel)
                        elif d.endswith(("FastAPI", "include_router")):
                            self.global_auth = True
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if any(last_name(d.func if isinstance(d, ast.Call) else d) == "before_request" for d in node.decorator_list):
                        seg = ast.get_source_segment(sf.text, node) or ""
                        if H.AUTH_EVIDENCE.search(seg) or re.search(r"abort\s*\(\s*40[13]|redirect\s*\(", seg):
                            self.global_auth = True
            for node in tree.body:
                # AuthedUser = Annotated[User, Depends(get_current_user)]
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    if re.search(r"Depends\(\s*[\w.]*(?:auth|user|token|current|admin|verify|session)", ast.unparse(node.value), re.I):
                        self.auth_aliases.add(node.targets[0].id)
            if re.search(r"DEFAULT_PERMISSION_CLASSES[\s\S]{0,200}IsAuthenticated", sf.text or ""):
                self.drf_default_auth = True
        direct = set()
        for name, nodes in bodies.items():
            for fn in nodes:
                if any(isinstance(n, ast.Call) and is_llm_call(n, set()) for n in walk_shallow(fn) if n is not fn):
                    direct.add(name)
        self.llm_funcs = direct
        for _ in range(3):
            new = set()
            for name, nodes in bodies.items():
                if name in self.llm_funcs:
                    continue
                for fn in nodes:
                    for n in walk_shallow(fn):
                        if isinstance(n, ast.Call) and last_name(n.func) in self.llm_funcs and (
                                isinstance(n.func, ast.Name) or root_name(n.func) in ("self", "cls")):
                            new.add(name)
            if not new:
                break
            self.llm_funcs |= new

    def check_comments(self, sf: SourceFile) -> None:
        from .jsscan import SECURITY_TODO

        views = py_views(sf.text or "")
        sf.cache["views"] = views
        for a, b in views.comments:
            text = sf.text[a:b]
            m = SECURITY_TODO.search(text)
            if m:
                line = sf.line_at(a)
                self.emit(Finding("QA004", sf.rel, line, f"Comment: {text.strip()[:120]}", "", sf.line(line).strip()))

    # ---------------------------------------------------------------- module
    def scan_module(self, tree: ast.Module) -> None:
        ctx = Ctx("module", set())
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and any("Tool" in dotted(b) for b in node.bases):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in ("_run", "_arun", "run", "execute", "__call__", "forward"):
                        self.tool_methods.add(id(item))
        self.walk_block(tree.body, ctx)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.scan_function(node)
            elif isinstance(node, ast.ExceptHandler):
                self.check_except(node)
            elif isinstance(node, ast.While):
                self.check_loop(node)
        self.check_module_text(tree)

    def scan_function(self, fn: ast.AST) -> None:
        assert isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
        route = self.route_info(fn)
        tool = self.is_tool(fn)
        params = [a for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs]
        if fn.args.vararg:
            params.append(fn.args.vararg)
        if fn.args.kwarg:
            params.append(fn.args.kwarg)
        names = {a.arg for a in params}
        ctx = Ctx("route" if route else "tool" if tool else "plain", names)
        defaults = dict(zip([a.arg for a in fn.args.args][::-1], fn.args.defaults[::-1]))
        defaults.update({a.arg: d for a, d in zip(fn.args.kwonlyargs, fn.args.kw_defaults) if d is not None})
        for a in params:
            if a.arg in ("self", "cls"):
                continue
            ann = ast.unparse(a.annotation) if a.annotation is not None else ""
            dflt = defaults.get(a.arg)
            if dflt is not None and isinstance(dflt, ast.Call) and last_name(dflt.func) in ("Depends", "Security"):
                continue
            if re.search(r"\b(?:Request|WebSocket|Session|AsyncSession|BackgroundTasks|Response|HttpRequest)\b", ann):
                continue
            if route:
                ctx.env[a.arg] = {"user": fn.lineno}
            elif tool:
                ctx.env[a.arg] = {"tool": fn.lineno}
        self.check_stub(fn)
        self.walk_block(fn.body, ctx)
        if route:
            self.add_route(fn, route)

    # ------------------------------------------------------------- routes
    def route_info(self, fn: ast.AST) -> Optional[Tuple[str, List[str], str]]:
        for d in fn.decorator_list:  # type: ignore[attr-defined]
            if not isinstance(d, ast.Call):
                continue
            name = last_name(d.func)
            if name == "api_view":
                methods = [c.value for c in ast.walk(d) if isinstance(c, ast.Constant) and isinstance(c.value, str)]
                return ("/" + fn.name, [m.upper() for m in methods] or ["GET"], "drf")  # type: ignore[attr-defined]
            if name not in ROUTE_ATTRS or not isinstance(d.func, ast.Attribute):
                continue
            path = const_str(d.args[0]) if d.args else None
            kws = {k.arg: k.value for k in d.keywords if k.arg}
            path = path if path is not None else const_str(kws.get("path") or kws.get("rule"))
            if path is None:
                continue
            if name in ("route", "api_route"):
                mnode = kws.get("methods")
                methods = [c.value.upper() for c in ast.walk(mnode) if isinstance(c, ast.Constant) and isinstance(c.value, str)] if mnode else ["GET"]
            else:
                methods = [name.upper()]
            return (path, methods or ["GET"], "python")
        return None

    def add_route(self, fn: ast.AST, info: Tuple[str, List[str], str]) -> None:
        path, methods, framework = info
        first = min([d.lineno for d in fn.decorator_list] + [fn.lineno])  # type: ignore[attr-defined]
        lines = (self.sf.text or "").split("\n")[first - 1: fn.end_lineno]  # type: ignore[attr-defined]
        body = "\n".join(lines)
        calls_llm = any(isinstance(n, ast.Call) and is_llm_call(n, self.llm_funcs) for n in walk_shallow(fn))
        auth = bool(H.AUTH_EVIDENCE.search(body)) or self.global_auth or self.sf.rel in self.file_auth
        for a in fn.args.args + fn.args.kwonlyargs:  # type: ignore[attr-defined]
            ann = ast.unparse(a.annotation) if a.annotation is not None else ""
            if ann and (ann.split("[")[0].split(".")[-1] in self.auth_aliases or AUTH_ANNOTATION.search(ann)):
                auth = True
        if framework == "drf" and self.drf_default_auth and "AllowAny" not in body:
            auth = True
        params = re.findall(r"<(?:\w+:)?(\w+)>|\{(\w+)\}", path)
        self.routes.append(Route(
            file=self.sf.rel, line=fn.lineno, path=path, methods=methods, body=body,  # type: ignore[attr-defined]
            framework=framework, lang="py", has_auth=auth, calls_llm=calls_llm,
            reads_body=bool(re.search(r"\brequest\s*\.\s*(?:json|get_json|form|data|values|POST|body)\b", body)),
            params=[a or b for a, b in params],
        ))

    def is_tool(self, fn: ast.AST) -> bool:
        if id(fn) in self.tool_methods:
            return True
        for d in fn.decorator_list:  # type: ignore[attr-defined]
            target = d.func if isinstance(d, ast.Call) else d
            if last_name(target) in ("tool", "function_tool", "kernel_function", "ai_function", "register_tool") or (
                    isinstance(target, ast.Attribute) and target.attr == "tool"):
                return True
        return False

    # -------------------------------------------------------------- taint
    def taint(self, node: Optional[ast.AST], ctx: Ctx) -> Taint:
        if node is None or isinstance(node, ast.Constant):
            return {}
        if isinstance(node, ast.Name):
            return dict(ctx.env.get(node.id, {}))
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in ("request", "req") and node.attr in USER_ATTRS:
                return {"user": node.lineno}
            return self.taint(node.value, ctx)
        if isinstance(node, ast.Subscript):
            return self.taint(node.value, ctx)
        if isinstance(node, ast.Call):
            if is_llm_call(node, self.llm_funcs):
                return {"llm": node.lineno}
            name = last_name(node.func)
            if name in SANITIZERS or re.match(r"(?i)(sanitize|validate|escape|clean)", name or ""):
                return {}
            parts = [self.taint(a, ctx) for a in node.args] + [self.taint(k.value, ctx) for k in node.keywords]
            if isinstance(node.func, ast.Attribute):
                parts.append(self.taint(node.func, ctx))
            return merge(*parts)
        if isinstance(node, ast.JoinedStr):
            return merge(*[self.taint(v, ctx) for v in node.values])
        if isinstance(node, ast.FormattedValue):
            return self.taint(node.value, ctx)
        if isinstance(node, ast.BinOp):
            return merge(self.taint(node.left, ctx), self.taint(node.right, ctx))
        if isinstance(node, ast.BoolOp):
            return merge(*[self.taint(v, ctx) for v in node.values])
        if isinstance(node, ast.IfExp):
            return merge(self.taint(node.body, ctx), self.taint(node.orelse, ctx))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return merge(*[self.taint(e, ctx) for e in node.elts])
        if isinstance(node, ast.Dict):
            return merge(*[self.taint(v, ctx) for v in node.values])
        if isinstance(node, (ast.Await, ast.Starred, ast.NamedExpr)):
            return self.taint(node.value, ctx)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return merge(self.taint(node.elt, ctx), *[self.taint(g.iter, ctx) for g in node.generators])
        if isinstance(node, ast.DictComp):
            return merge(self.taint(node.value, ctx), *[self.taint(g.iter, ctx) for g in node.generators])
        return {}

    def assign(self, target: ast.AST, t: Taint, ctx: Ctx, value: Optional[ast.AST] = None) -> None:
        if isinstance(target, ast.Name):
            ctx.env[target.id] = t
            if value is not None:
                ctx.assigned[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for e in target.elts:
                self.assign(e, t, ctx)
        elif isinstance(target, ast.Starred):
            self.assign(target.value, t, ctx)
        elif isinstance(target, (ast.Attribute, ast.Subscript)) and t:
            base = root_name(target)
            if base:
                ctx.env[base] = merge(ctx.env.get(base, {}), t)

    def walk_block(self, stmts: List[ast.stmt], ctx: Ctx) -> None:
        for st in stmts:
            GUARD.tick()
            for expr in header_exprs(st):
                for n in walk_shallow(expr):
                    if isinstance(n, ast.Call):
                        self.check_call(n, ctx)
                    elif isinstance(n, ast.Dict):
                        self.check_system_dict(n, ctx)
                    elif isinstance(n, ast.Compare):
                        self.check_compare(n)
            if isinstance(st, ast.Assign):
                t = self.taint(st.value, ctx)
                for tg in st.targets:
                    self.assign(tg, t, ctx, st.value)
                self.check_assign_random(st)
            elif isinstance(st, ast.AnnAssign) and st.value is not None:
                self.assign(st.target, self.taint(st.value, ctx), ctx, st.value)
            elif isinstance(st, ast.AugAssign):
                base = root_name(st.target)
                if base:
                    ctx.env[base] = merge(ctx.env.get(base, {}), self.taint(st.value, ctx))
            elif isinstance(st, (ast.For, ast.AsyncFor)):
                self.assign(st.target, self.taint(st.iter, ctx), ctx)
                self.walk_block(st.body, ctx)
                self.walk_block(st.orelse, ctx)
            elif isinstance(st, ast.While):
                self.walk_block(st.body, ctx)
                self.walk_block(st.orelse, ctx)
            elif isinstance(st, ast.If):
                checked = self._allowlisted(st.test)
                if checked and not isinstance(st.test.ops[0], ast.NotIn):  # type: ignore[attr-defined]
                    saved = {n: ctx.env.pop(n) for n in checked if n in ctx.env}
                    self.walk_block(st.body, ctx)
                    ctx.env.update(saved)
                else:
                    self.walk_block(st.body, ctx)
                self.walk_block(st.orelse, ctx)
                if checked and isinstance(st.test.ops[0], ast.NotIn) and st.body and isinstance(st.body[-1], (ast.Raise, ast.Return)):  # type: ignore[attr-defined]
                    for n in checked:
                        ctx.env.pop(n, None)  # rejected unless it is in the allow-list
            elif isinstance(st, (ast.With, ast.AsyncWith)):
                for item in st.items:
                    if item.optional_vars is not None:
                        self.assign(item.optional_vars, self.taint(item.context_expr, ctx), ctx)
                self.walk_block(st.body, ctx)
            elif isinstance(st, ast.Try) or type(st).__name__ == "TryStar":
                self.walk_block(st.body, ctx)  # type: ignore[attr-defined]
                for h in st.handlers:  # type: ignore[attr-defined]
                    if h.name:
                        ctx.except_names.add(h.name)
                    self.walk_block(h.body, ctx)
                self.walk_block(st.orelse, ctx)  # type: ignore[attr-defined]
                self.walk_block(st.finalbody, ctx)  # type: ignore[attr-defined]
            elif type(st).__name__ == "Match":
                for case in st.cases:  # type: ignore[attr-defined]
                    self.walk_block(case.body, ctx)
            elif isinstance(st, ast.Return) and ctx.kind == "route" and st.value is not None:
                self.check_error_leak(st, ctx)

    # -------------------------------------------------------------- sinks
    def sink(self, node: ast.AST, t: Taint, rule: str, what: str, user_sev: str, crit: bool) -> bool:
        if "tool" in t:
            self.add("LLM005", node, f"An agent tool passes a model-chosen argument to {what}.", "critical" if crit else "high")
        elif "llm" in t:
            self.add("LLM002", node, f"Model output (from the call on line {t['llm']}) flows into {what}.", "critical" if crit else "high")
        elif "user" in t:
            self.add(rule, node, f"Request data flows into {what}.", user_sev)
        else:
            return False
        return True

    def resolve(self, node: ast.AST, ctx: Ctx) -> ast.AST:
        if isinstance(node, ast.Name) and node.id in ctx.assigned:
            return ctx.assigned[node.id]
        return node

    def check_call(self, call: ast.Call, ctx: Ctx) -> None:
        d = dotted(call.func)
        name = last_name(call.func)
        kws = {k.arg: k.value for k in call.keywords if k.arg}
        arg0 = call.args[0] if call.args else None
        t0 = self.taint(arg0, ctx) if arg0 is not None else {}
        is_attr = isinstance(call.func, ast.Attribute)

        # SQL
        if is_attr and name in ("execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query") or d in ("text", "sqlalchemy.text", "sa.text"):
            if arg0 is not None:
                src = self.resolve(arg0, ctx)
                formatted = is_formatted(src) and re.search(r"(?i)\b(select|insert|update|delete|drop|create|alter|where)\b", string_parts(src))
                if formatted and all(placeholder_safe(p, ctx.assigned) for p in interpolated(src)):
                    pass  # only bind markers are formatted in; the values are passed as parameters
                elif t0 and (formatted or ctx.kind == "tool" or not isinstance(src, (ast.Constant, ast.JoinedStr, ast.BinOp))):
                    self.sink(call, t0, "BE001", "a SQL query", "high", True)
                elif formatted:
                    self.add("BE001", call, "SQL query built with string formatting; use parameters even for values you think are safe.", "medium")
        # shell
        elif d in ("os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput") or d.endswith("create_subprocess_shell"):
            if arg0 is not None and const_str(arg0) is None:
                if not self.sink(call, t0, "BE002", "a shell command", "critical", True):
                    self.add("BE002", call, "Shell command built from a variable; if any part comes from users or a model this is command injection.", "medium")
        elif d.startswith("subprocess.") and name in ("run", "call", "check_call", "check_output", "Popen"):
            shell = kws.get("shell")
            shell_on = isinstance(shell, ast.Constant) and shell.value is True
            if arg0 is not None:
                if shell_on and const_str(arg0) is None:
                    if not self.sink(call, t0, "BE002", "a shell command", "critical", True):
                        self.add("BE002", call, "subprocess with shell=True and a dynamic command.", "medium")
                elif isinstance(arg0, (ast.List, ast.Tuple)) and arg0.elts:
                    program = self.taint(arg0.elts[0], ctx)
                    if program:
                        self.sink(call, program, "BE002", "the program a subprocess runs", "high", True)
                elif t0:
                    self.sink(call, t0, "BE002", "a subprocess command", "high", True)
        # dynamic code
        elif isinstance(call.func, ast.Name) and name in ("eval", "exec", "compile") and arg0 is not None and const_str(arg0) is None:
            if not self.sink(call, t0, "BE003", f"{name}()", "critical", True):
                self.add("BE003", call, f"{name}() on a dynamic string.", "medium")
        # files
        elif (isinstance(call.func, ast.Name) and name == "open") or d in ("os.remove", "os.unlink", "shutil.rmtree", "os.rmdir") or name in ("send_file", "FileResponse"):
            if arg0 is not None:
                self.sink(call, t0, "BE006", "a file system path", "high", False)
        # outbound HTTP
        elif (root_name(call.func) in ("requests", "httpx", "urllib3", "aiohttp") and name in ("get", "post", "put", "patch", "delete", "head", "request", "urlopen", "stream")) or d.endswith("urlopen"):
            target = call.args[1] if name == "request" and len(call.args) > 1 else arg0
            if target is None:
                target = kws.get("url")
            if target is not None:
                tt = self.taint(target, ctx)
                fixed_host = isinstance(target, ast.JoinedStr) and target.values and isinstance(target.values[0], ast.Constant) and re.match(r"https?://[^/{]+/", str(target.values[0].value))
                if tt and not fixed_host:
                    self.sink(call, tt, "BE005", "an outbound HTTP request URL", "high", False)
            if isinstance(kws.get("verify"), ast.Constant) and kws["verify"].value is False:
                self.add("BE013", call, "TLS certificate verification disabled (verify=False).")
        # templates / html / redirects
        elif name == "render_template_string" and arg0 is not None:
            if not self.sink(call, t0, "BE007", "render_template_string()", "high", False) and is_formatted(arg0):
                self.add("BE007", call, "Template string built with formatting; user data in it becomes template code.", "medium")
        elif name in ("Markup", "mark_safe", "HTMLResponse") and (arg0 is not None or "content" in kws):
            value = arg0 if arg0 is not None else kws.get("content")
            tt = {} if self._rendered(value, ctx) else (t0 or self.taint(kws.get("content"), ctx))
            if not self.sink(call, tt, "FE001", f"{name}() (raw HTML)", "high", False) and arg0 is not None and is_formatted(arg0):
                self.add("FE001", call, f"{name}() marks a formatted string as safe HTML.", "medium")
        elif name in ("redirect", "RedirectResponse", "HttpResponseRedirect") and arg0 is not None:
            if not (isinstance(arg0, ast.JoinedStr) and arg0.values and isinstance(arg0.values[0], ast.Constant) and str(arg0.values[0].value).startswith("/")):
                self.sink(call, t0, "BE008", "a redirect target", "medium", False)
        # deserialization and model loading
        elif d in ("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "dill.loads", "dill.load", "marshal.loads", "marshal.load", "jsonpickle.decode", "shelve.open", "yaml.unsafe_load"):
            if not self.sink(call, t0, "BE004", d + "()", "high", True):
                self.add("BE004", call, f"{d}() can execute code if the data is ever attacker-controlled.", "medium")
        elif d == "yaml.load":
            loader = ast.unparse(kws["Loader"]) if "Loader" in kws else (ast.unparse(call.args[1]) if len(call.args) > 1 else "")
            if "Safe" not in loader and "BaseLoader" not in loader:
                self.add("BE004", call, "yaml.load without SafeLoader can construct arbitrary Python objects.", "high" if t0 else "medium")
        elif d.endswith("torch.load") or d == "load" and root_name(call.func) == "torch":
            wo = kws.get("weights_only")
            if not (isinstance(wo, ast.Constant) and wo.value is True):
                self.add("LLM008", call, "torch.load without weights_only=True unpickles arbitrary code.", "high" if t0 else "medium")
        elif name == "load_model" and isinstance(kws.get("safe_mode"), ast.Constant) and kws["safe_mode"].value is False:
            self.add("LLM008", call, "Keras load_model with safe_mode=False can run code from the model file.")
        # JWT
        elif d.endswith("jwt.decode") or (name == "decode" and root_name(call.func) == "jwt"):
            opts = ast.unparse(kws["options"]) if "options" in kws else ""
            algs = ast.unparse(kws["algorithms"]) if "algorithms" in kws else ""
            if (isinstance(kws.get("verify"), ast.Constant) and kws["verify"].value is False) or re.search(r"verify_signature['\"]\s*:\s*False", opts) or re.search(r"(?i)['\"]none['\"]", algs):
                self.add("BE016", call, "JWT decoded without verifying the signature.")
        # weak password hashing
        elif d.startswith("hashlib.") and name in ("md5", "sha1", "sha256", "sha512", "sha224", "sha384", "new") and arg0 is not None:
            if re.search(r"(?i)pass|pwd", ast.unparse(arg0)):
                self.add("BE014", call, f"Password hashed with {name}; use bcrypt/argon2.")
        # debug
        elif name == "run" and is_attr and isinstance(kws.get("debug"), ast.Constant) and kws["debug"].value is True and root_name(call.func) not in ("subprocess", "asyncio", "uvicorn"):
            self.add("BE011", call, "App started with debug=True.")
        # CORS
        elif name == "CORS":
            self.check_cors_flask(call, kws)
        elif name == "add_middleware" and call.args and last_name(call.args[0]) == "CORSMiddleware":
            origins = ast.unparse(kws.get("allow_origins", ast.Constant(""))) + ast.unparse(kws.get("allow_origin_regex", ast.Constant("")))
            creds = isinstance(kws.get("allow_credentials"), ast.Constant) and kws["allow_credentials"].value is True
            if re.search(r"['\"]\*['\"]|['\"]\.\*['\"]", origins):
                self.add("BE012", call, "CORS allows any origin" + (" together with credentials." if creds else "."), "high" if creds else "low")
        # CSRF
        # trust_remote_code
        if isinstance(kws.get("trust_remote_code"), ast.Constant) and kws["trust_remote_code"].value is True:
            self.add("LLM008", call, "trust_remote_code=True runs Python code from the model repository.")
        # mass assignment
        for k in call.keywords:
            if k.arg is None and not (isinstance(k.value, ast.Call) and last_name(k.value.func) in ("dict", "model_dump", "dump", "validated_data")):
                tk = self.taint(k.value, ctx)
                if ("user" in tk or "llm" in tk) and not is_llm_call(call, self.llm_funcs) and (
                        name[:1].isupper() or name in ("create", "update", "insert", "update_or_create", "get_or_create", "filter_by")):
                    self.add("BE009", call, "The whole request body is unpacked into a model write.")
        if name == "setattr" and len(call.args) >= 2 and "user" in self.taint(call.args[1], ctx):
            self.add("BE009", call, "setattr() with a request-controlled attribute name.")
        if name == "update" and is_attr and isinstance(call.func.value, ast.Attribute) and call.func.value.attr == "__dict__" and arg0 is not None and self.taint(arg0, ctx):
            self.add("BE009", call, "Object __dict__ updated from request data.")
        # LLM-specific
        self.check_llm_call(call, ctx, d, kws)
        self.check_log_secret(call, d)

    @staticmethod
    def _allowlisted(test: ast.AST) -> List[str]:
        """Names checked against a fixed collection: `x in ALLOWED` or `x not in ALLOWED`."""
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], (ast.In, ast.NotIn)) \
                and isinstance(test.left, ast.Name) and not isinstance(test.comparators[0], ast.Constant):
            return [test.left.id]
        return []

    def _rendered(self, node: Optional[ast.AST], ctx: Ctx) -> bool:
        """True when the value comes from a function call (a template render, an email builder) rather than
        straight from the request; such output is that function's responsibility to escape."""
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        if isinstance(node, ast.Name):
            node = ctx.assigned.get(node.id, node)
        return isinstance(node, ast.Call) and last_name(node.func) not in ("str", "format", "join", "get", "json", "get_json")

    def check_cors_flask(self, call: ast.Call, kws: Dict[str, ast.AST]) -> None:
        origins = kws.get("origins") or kws.get("resources")
        creds = isinstance(kws.get("supports_credentials"), ast.Constant) and kws["supports_credentials"].value is True
        wildcard = origins is None or re.search(r"['\"]\*['\"]", ast.unparse(origins))
        if wildcard:
            self.add("BE012", call, "Flask-CORS allows any origin" + (" together with credentials." if creds else "."), "high" if creds else "low")

    def check_llm_call(self, call: ast.Call, ctx: Ctx, d: str, kws: Dict[str, ast.AST]) -> None:
        name = last_name(call.func)
        has_star = any(k.arg is None for k in call.keywords)
        if d.endswith(TOKEN_LIMIT_CALLS) and not has_star and not (TOKEN_KW & set(kws)):
            self.add("LLM003", call, "Model call has no output token limit.")
        elif d.endswith(("generate_content", "generate_content_async", "generate_content_stream")) and not has_star:
            cfg = kws.get("config") or kws.get("generation_config")
            if cfg is None or (isinstance(cfg, (ast.Call, ast.Dict)) and "max_output_tokens" not in ast.unparse(cfg)):
                if not self._model_has_limit(call, ctx):
                    self.add("LLM003", call, "Gemini call has no max_output_tokens.")
        elif isinstance(call.func, ast.Name) and name in LC_CTORS and not has_star and not ({"max_tokens", "max_output_tokens", "max_completion_tokens"} & set(kws)):
            self.add("LLM003", call, f"{name}(...) has no max_tokens.")
        # system prompt built from user input
        for key in ("system", "instructions", "system_instruction", "system_prompt"):
            if key in kws and (is_llm_call(call, self.llm_funcs) or name in ("Agent", "GenerativeModel", "GenerateContentConfig", "create_react_agent", "Assistant")):
                self.check_system_value(kws[key], call, ctx)
        if name == "SystemMessage":
            v = call.args[0] if call.args else kws.get("content")
            if v is not None:
                self.check_system_value(v, call, ctx)
        if isinstance(call.func, ast.Attribute) and name == "from_messages" and call.args and isinstance(call.args[0], (ast.List, ast.Tuple)):
            for el in call.args[0].elts:
                if isinstance(el, ast.Tuple) and len(el.elts) == 2 and const_str(el.elts[0]) == "system":
                    self.check_system_value(el.elts[1], el, ctx)

    def _model_has_limit(self, call: ast.Call, ctx: Ctx) -> bool:
        src = self.sf.text or ""
        return "max_output_tokens" in src

    def check_system_dict(self, node: ast.Dict, ctx: Ctx) -> None:
        kv = {const_str(k): v for k, v in zip(node.keys, node.values) if k is not None}
        if const_str(kv.get("role")) == "system" and "content" in kv:
            self.check_system_value(kv["content"], node, ctx)

    def check_system_value(self, value: ast.AST, node: ast.AST, ctx: Ctx) -> None:
        value = self.resolve(value, ctx)
        t = self.taint(value, ctx)
        if not is_formatted(value):
            if "user" in t and not isinstance(value, ast.Constant):
                self.add("LLM001", node, "Request data is used as the system prompt.", "high")
            return
        if "user" in t:
            self.add("LLM001", node, "Request data is interpolated into the system prompt.", "high")
            return
        names = {n.id for n in ast.walk(value) if isinstance(n, ast.Name)}
        if any(n in ctx.params and H.USERISH_NAME.match(n) for n in names):
            self.add("LLM001", node, "A user-supplied parameter is interpolated into the system prompt.", "medium")

    def check_log_secret(self, call: ast.Call, d: str) -> None:
        if not (d == "print" or re.match(r"(?:logging|logger|log|_logger|LOGGER|self\.logger|app\.logger)\.(?:debug|info|warning|warn|error|exception|critical)$", d)):
            return
        for arg in call.args:
            sliced = {id(n.value) for n in ast.walk(arg) if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Slice)}
            for n in ast.walk(arg):
                if isinstance(n, ast.Name) and SECRET_VAR.match(n.id) and id(n) not in sliced:
                    self.add("SEC010", call, f"`{n.id}` is written to the logs.")
                    return
                if isinstance(n, ast.Call) and dotted(n.func) in ("os.getenv", "os.environ.get", "getenv") and n.args and re.search(r"KEY|SECRET|TOKEN|PASSWORD|PASS", const_str(n.args[0]) or ""):
                    self.add("SEC010", call, "An environment secret is written to the logs.")
                    return
                if isinstance(n, ast.Subscript) and dotted(n.value) == "os.environ" and re.search(r"KEY|SECRET|TOKEN|PASSWORD|PASS", const_str(n.slice) or ""):  # type: ignore[arg-type]
                    self.add("SEC010", call, "An environment secret is written to the logs.")
                    return

    def check_compare(self, node: ast.Compare) -> None:
        if len(node.ops) != 1 or not isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            return
        sides = [node.left, node.comparators[0]]

        def pw(n: ast.AST) -> bool:
            if isinstance(n, ast.Call):
                return False
            if isinstance(n, ast.Subscript):
                return bool(re.search(r"(?i)passw", const_str(n.slice) or ""))  # type: ignore[arg-type]
            return bool(re.search(r"(?i)^(?:password|passwd|pwd)$|password$", last_name(n)))

        same_source = root_name(sides[0]) and root_name(sides[0]) == root_name(sides[1])
        if all(pw(s) for s in sides) and not same_source and not any(
                re.search(r"(?i)hash|digest|confirm|repeat|again|new_?pass|old_?pass", ast.unparse(s)) for s in sides):
            self.add("BE014", node, "Password compared in plaintext; passwords appear to be stored unhashed.")

    def check_assign_random(self, st: ast.Assign) -> None:
        names = " ".join(ast.unparse(t) for t in st.targets)
        if not SECRETISH.search(names):
            return
        for n in ast.walk(st.value):
            if isinstance(n, ast.Call) and dotted(n.func).startswith("random.") and last_name(n.func) in ("choice", "choices", "randint", "random", "randrange", "sample", "getrandbits"):
                self.add("BE015", st, "random module used to generate a secret value; use the secrets module.")
                return

    def check_error_leak(self, st: ast.Return, ctx: Ctx) -> None:
        for n in ast.walk(st.value):  # type: ignore[arg-type]
            if isinstance(n, ast.Call) and (dotted(n.func) in ("traceback.format_exc", "traceback.format_exception") or (
                    last_name(n.func) in ("str", "repr") and n.args and isinstance(n.args[0], ast.Name) and n.args[0].id in ctx.except_names)):
                self.add("BE017", st, "Exception details are returned to the client.")
                return

    # --------------------------------------------------------- structural
    def check_stub(self, fn: ast.AST) -> None:
        if not STUB_NAME.match(fn.name):  # type: ignore[attr-defined]
            return
        body = [s for s in fn.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)) and not isinstance(s, ast.Pass)]  # type: ignore[attr-defined]
        if len(body) == 1 and isinstance(body[0], ast.Return) and isinstance(body[0].value, ast.Constant) and body[0].value.value is True:
            self.add("AUTH008", fn, f"`{fn.name}()` always returns True.")  # type: ignore[attr-defined]

    def check_except(self, h: ast.ExceptHandler) -> None:
        if not all(isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)) for s in h.body):
            return
        typ = ast.unparse(h.type) if h.type is not None else ""
        block = "\n".join(self.sf.lines[h.body[0].lineno - 1:getattr(h, "end_lineno", h.lineno)])
        if "#" in block:
            return  # an explanatory comment means ignoring the error is deliberate
        if re.search(r"ImportError|ModuleNotFoundError|KeyboardInterrupt|StopIteration|StopAsyncIteration|CancelledError", typ):
            return
        self.add("QA003", h, f"`except {typ or ''}` silently ignores the error.".replace("except :", "except:"))

    def check_loop(self, node: ast.While) -> None:
        if not (isinstance(node.test, ast.Constant) and node.test.value is True):
            return
        calls = any(isinstance(n, ast.Call) and is_llm_call(n, self.llm_funcs) for n in ast.walk(node))
        if not calls:
            return
        for n in ast.walk(node):
            if isinstance(n, ast.Compare):
                names = [x.id for x in ast.walk(n) if isinstance(x, ast.Name)] + [x.attr for x in ast.walk(n) if isinstance(x, ast.Attribute)]
                if any(BOUND_NAME.search(x) for x in names):
                    return
        self.add("LLM009", node, "while True loop calls a model with no step or budget limit.")

    def check_module_text(self, tree: ast.Module) -> None:
        sf = self.sf
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for d in node.decorator_list:
                    if last_name(d.func if isinstance(d, ast.Call) else d) in ("csrf_exempt",) or dotted(d).endswith("csrf.exempt"):
                        self.add("AUTH009", d, "CSRF protection disabled for this view.")
            if isinstance(node, ast.Assign):
                tgt = " ".join(ast.unparse(t) for t in node.targets)
                val = node.value
                if re.search(r"(?:^|\.|\[['\"])WTF_CSRF_ENABLED", tgt) and isinstance(val, ast.Constant) and val.value is False:
                    self.add("AUTH009", node, "Flask-WTF CSRF protection disabled.")
                if re.search(r"(?:^|\.)(?:debug|DEBUG)$|\[['\"]DEBUG['\"]\]", tgt) and isinstance(val, ast.Constant) and val.value is True:
                    if re.search(r"(?:^|/)settings(?:/(?!dev|local|test)[^/]*)?\.py$|(?:^|/)(?:app|main|config|wsgi|server)\.py$", sf.rel):
                        self.add("BE011", node, "DEBUG is hard-coded to True.")
                if tgt == "ALLOWED_HOSTS" and "'*'" in ast.unparse(val).replace('"', "'"):
                    self.add("CFG006", node, "ALLOWED_HOSTS accepts any host.")
