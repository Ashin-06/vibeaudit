"""Python analysis on the real AST, with taint tracking inside functions and through calls.

A call that passes tainted values to a function of the project (in the same file, a method of `self`, or a
function imported from another module of the project) is followed: the function is walked again with those
parameters tainted, up to CALL_DEPTH calls deep, so a sink in a helper is reported where it is, with the call
it came through. Calls whose callee cannot be resolved statically (dynamic dispatch, instances of other classes,
`*args`) are not followed.

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
from .files import Project, SourceFile, production_overrides
from .guard import GUARD
from .lexer import py_views
from .model import Finding, Route, join_path

Emit = Callable[[Finding], None]
# a database read returns stored rows, not the request data that was passed as a query parameter
DB_READS = {"fetchrow", "fetchval", "fetchone", "fetchall", "fetchmany", "scalar", "scalars", "scalar_one",
            "scalar_one_or_none", "one_or_none"}
# SQLAlchemy statement builders: execute(select(...).where(...)) runs a parameterised statement object
ORM_BUILDERS = {"select", "where", "filter", "filter_by", "limit", "offset", "order_by", "join", "outerjoin", "values",
                "select_from", "returning", "group_by", "having", "options", "distinct", "with_only_columns", "in_"}
FIXED_HOST = re.compile(r"https?://[^/{%]+/")
CALL_DEPTH = 3  # calls followed from a route, tool or model output to a sink
Taint = Dict[str, int]  # kind -> line where it entered

USER_ATTRS = {
    "args", "form", "json", "get_json", "data", "get_data", "values", "files", "cookies", "headers",
    "query_params", "path_params", "body", "stream", "POST", "GET", "FILES", "COOKIES", "META", "query_string",
    # the URL and Host header are attacker-chosen too (`'%s' % request.url` in an error page is a classic SSTI)
    "url", "base_url", "url_root", "host_url", "host", "full_path", "path", "referrer",
}
UNIVERSAL_SANITIZERS = {
    "int", "float", "bool", "len", "abs", "round", "UUID", "uuid4",
    "hexdigest", "isdigit", "isalnum", "count",
    "startswith", "endswith", "type", "isinstance", "hash", "id",
}
SANITIZERS = UNIVERSAL_SANITIZERS | {"literal_eval", "secure_filename", "escape", "quote", "basename", "clean", "urlencode", "quote_plus"}
_SINK_CONTEXTS = ("html", "shell", "path", "url", "redirect", "sql", "code", "deser", "nosql", "prompt")
MONGO_METHODS = {
    "find", "find_one", "find_one_and_update", "find_one_and_delete", "find_one_and_replace",
    "update_one", "update_many", "delete_one", "delete_many", "count_documents", "aggregate",
}
MONGO_MARKERS = ("pymongo", "motor", "mongoengine", "beanie", "MongoClient", "AsyncIOMotorClient")
CYPHER_KW = re.compile(r"(?i)\b(?:OPTIONAL\s+)?MATCH\s*\([^)\n]{0,120}\)|\bDETACH\s+DELETE\b|\bMERGE\s*\([^)\n]{0,120}\)")
KQL_KW = re.compile(r"(?i)\|\s*(?:where|project|summarize|take|limit|extend|join|order\s+by|sort\s+by|count)\b")


def _sanitizer_contexts(call: ast.Call, mod_imports: Dict[str, Tuple[str, Optional[str], int]]) -> Set[str]:
    d = dotted(call.func)
    name = last_name(call.func) or ""
    if name in UNIVERSAL_SANITIZERS or name in H.CUSTOM.sanitizers:
        return {"*"}
    ctxs: Set[str] = set()
    low_full = f"{d}.{name}".lower()
    if name == "literal_eval":
        ctxs.add("code")
    if name in ("secure_filename", "basename") or re.match(r"(?i)^(?:sanitize_?(?:file|path)|clean_?path)", name):
        ctxs.add("path")
    q_mod = mod_imports.get("quote", ("",))[0] if d == "quote" else ""
    if d.endswith(("shlex.quote", "pipes.quote")) or q_mod in ("shlex", "pipes") \
            or re.match(r"(?i)^(?:shell_?escape|escape_?shell|quote_?shell)", name):
        ctxs.add("shell")
    if name in ("urlencode", "quote_plus") or d.endswith(("urllib.parse.quote", "parse.quote")) \
            or "urllib" in q_mod:
        ctxs.add("url")
    if name in ("urlencode", "quote_plus"):
        ctxs.add("redirect")
    if name in ("escape_string", "sql_escape", "escape_identifier", "Identifier", "Literal") \
            or d.endswith(("sql.Identifier", "sql.Literal", "pymysql.converters.escape_string")) \
            or re.match(r"(?i)^(?:sql_?escape|escape_?sql)", name):
        ctxs.add("sql")
    if name in ("escape", "escape_html", "html_escape", "bleach_clean", "clean") or (
            re.match(r"(?i)^(?:sanitize|escape|clean)", name)
            and not any(k in low_full for k in ("sql", "shell", "cmd", "path", "file", "url", "cypher"))):
        ctxs.add("html")
    return ctxs


def _safe_mongo_filter(node: ast.AST) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    if not node.values:
        return True
    for k, v in zip(node.keys, node.values):
        key_name = const_str(k) if k is not None else None
        if k is None or key_name is None or key_name == "$where":
            return False
        if isinstance(v, ast.Dict) and len(v.keys) == 1 and const_str(v.keys[0]) == "$eq":
            continue
        if isinstance(v, ast.Call) and last_name(v.func) in ("str", "int", "float", "bool", "ObjectId"):
            continue
        if isinstance(v, ast.Constant):
            continue
        return False
    return True
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
# a loop that runs until the model stops asking for tools (or says it is done): an agent loop
AGENT_LOOP_TEST = re.compile(r"(?i)tool_?calls?|tool_?use|stop_?reason|finish_?reason|function_?call|requires_?action"
                             r"|\b(?:not\s+)?(?:done|finished|is_done|is_finished|complete|completed)\b")


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


def _leading_query_or_fragment(node: Optional[ast.AST], depth: int = 0) -> bool:
    """True when a formatted string expression always starts with `?` or `#` (query or fragment)."""
    if node is None or depth > 6:
        return False
    s = const_str(node)
    if s is not None:
        return s.startswith(("?", "#"))
    if isinstance(node, ast.JoinedStr) and node.values:
        first = const_str(node.values[0])
        return first is not None and first.startswith(("?", "#"))
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _leading_query_or_fragment(node.left, depth + 1)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return _leading_query_or_fragment(node.func.value, depth + 1)
    return False


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


def fragment_safe(node: ast.AST, assigned: Dict[str, ast.AST], depth: int = 0) -> bool:
    """True when `node` can only evaluate to fixed SQL text and bind markers, such as
    where = f"tx IN ({','.join('?' * len(chunk))})" + ("" if last is None else " AND id <= ?")."""
    if depth > 6:
        return False
    if placeholder_safe(node, assigned, depth=depth):
        return True
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)  # fixed SQL text written in the code
    if isinstance(node, ast.Name):
        return node.id in assigned and fragment_safe(assigned[node.id], assigned, depth + 1)
    if isinstance(node, ast.JoinedStr):
        return all(fragment_safe(v.value, assigned, depth + 1) for v in node.values if isinstance(v, ast.FormattedValue))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return fragment_safe(node.left, assigned, depth + 1) and fragment_safe(node.right, assigned, depth + 1)
    if isinstance(node, ast.IfExp):
        return fragment_safe(node.body, assigned, depth + 1) and fragment_safe(node.orelse, assigned, depth + 1)
    return False


def _ident_only(pattern: str) -> bool:
    """True when a regex accepts a plain SQL identifier and rejects quotes, spaces and separators."""
    try:
        rx = re.compile(pattern)
    except re.error:
        return False
    return bool(rx.fullmatch("users")) and not any(rx.fullmatch(bad)
                                                   for bad in ("a b", "a'b", 'a"b', "a;b", "a-b", "a)b", "a\nb"))


def _ident_check(node: ast.AST) -> Optional[str]:
    """The name checked by `if not re.fullmatch(IDENT, name): raise ...`, with an identifier-only IDENT."""
    if not (isinstance(node, ast.If) and isinstance(node.test, ast.UnaryOp) and isinstance(node.test.op, ast.Not)):
        return None
    call = node.test.operand
    if not (isinstance(call, ast.Call) and last_name(call.func) == "fullmatch" and len(call.args) >= 2):
        return None
    pat, name = call.args[0], call.args[1]
    if isinstance(pat, ast.Constant) and isinstance(pat.value, str) and isinstance(name, ast.Name)             and node.body and isinstance(node.body[-1], ast.Raise) and _ident_only(pat.value):
        return name.id
    return None


def _disjuncts(expr: ast.AST) -> List[ast.AST]:
    """Flatten top-level `or` expressions without descending into `and` or `not`."""
    if isinstance(expr, ast.BoolOp) and isinstance(expr.op, ast.Or):
        out: List[ast.AST] = []
        for v in expr.values:
            out.extend(_disjuncts(v))
        return out
    return [expr]


def _is_resolved_path(node: Optional[ast.AST], assigned: Dict[str, ast.AST], mod_assigned: Dict[str, ast.AST], depth: int = 0) -> bool:
    """True only when `node` comes from canonical `.resolve()` / `os.path.realpath()` resolution."""
    if node is None or depth > 6:
        return False
    if isinstance(node, ast.Name):
        nxt = assigned.get(node.id)
        if nxt is None:
            nxt = mod_assigned.get(node.id)
        return _is_resolved_path(nxt, assigned, mod_assigned, depth + 1) if nxt is not None else False
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "resolve":
            return True
        if dotted(node.func) in ("os.path.realpath", "posixpath.realpath", "ntpath.realpath", "realpath"):
            return True
        if last_name(node.func) in ("Path", "str") and len(node.args) == 1 and not node.keywords:
            return _is_resolved_path(node.args[0], assigned, mod_assigned, depth + 1)
    return False


def _unwrap_str_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "str" \
            and len(node.args) == 1 and not node.keywords and isinstance(node.args[0], ast.Name):
        return node.args[0].id
    return None


def _commonpath_guarded(d: ast.AST, loc: Dict[str, ast.AST], mod: Dict[str, ast.AST]) -> Set[str]:
    """Recognise canonical `os.path.commonpath([base, candidate]) != base` with both paths resolved."""
    if not (isinstance(d, ast.Compare) and len(d.ops) == 1 and isinstance(d.ops[0], ast.NotEq) and len(d.comparators) == 1):
        return set()
    pairs = [(d.left, d.comparators[0]), (d.comparators[0], d.left)]
    for call_node, base_cmp in pairs:
        if not (isinstance(call_node, ast.Call)
                and dotted(call_node.func) in ("os.path.commonpath", "posixpath.commonpath", "ntpath.commonpath", "commonpath")
                and len(call_node.args) == 1 and not call_node.keywords):
            continue
        seq = call_node.args[0]
        if not isinstance(seq, (ast.List, ast.Tuple)) or len(seq.elts) != 2:
            continue
        a, b = seq.elts
        if not (_is_resolved_path(a, loc, mod) and _is_resolved_path(b, loc, mod)):
            continue
        base_id = _unwrap_str_name(base_cmp)
        if not base_id:
            continue
        a_id, b_id = _unwrap_str_name(a), _unwrap_str_name(b)
        if a_id == base_id and b_id:
            return {b_id}
        if b_id == base_id and a_id:
            return {a_id}
    return set()


def _path_guarded(test: ast.AST, assigned: Optional[Dict[str, ast.AST]] = None,
                  mod_assigned: Optional[Dict[str, ast.AST]] = None) -> Set[str]:
    """Names a traversal guard verifies with canonical path containment (`not resolved.is_relative_to(base)`
    or `os.path.commonpath([base, resolved]) != base`, requiring both paths to be canonically resolved).
    Lexical checks (`is_absolute()` / `'..' in parts`) are not accepted because symlinks inside `base` can
    still escape it; note that canonical user-space checks retain an inherent filesystem TOCTOU window."""
    contained: Set[str] = set()
    loc = assigned or {}
    mod = mod_assigned or {}
    for d in _disjuncts(test):
        if isinstance(d, ast.UnaryOp) and isinstance(d.op, ast.Not) and isinstance(d.operand, ast.Call):
            fn = d.operand.func
            if isinstance(fn, ast.Attribute) and fn.attr == "is_relative_to" and isinstance(fn.value, ast.Name) \
                    and len(d.operand.args) == 1 and not d.operand.keywords:
                if _is_resolved_path(fn.value, loc, mod) and _is_resolved_path(d.operand.args[0], loc, mod):
                    contained.add(fn.value.id)
        else:
            contained |= _commonpath_guarded(d, loc, mod)
    return contained


def validated_idents(tree: ast.AST) -> Tuple[Set[str], List[Tuple[int, int, str]]]:
    """Identifiers checked against a strict pattern, safe to format into SQL: attributes set as
    `self.X = name` (or `self.a, self.X = a, name`) after the check, and the checked local names
    themselves, as (first line, last line, name) of the function that checks them."""
    attrs: Set[str] = set()
    local: List[Tuple[int, int, str]] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        checked = {n for n in (_ident_check(x) for x in ast.walk(fn)) if n}
        local += [(fn.lineno, getattr(fn, "end_lineno", fn.lineno), n) for n in checked]
        for node in ast.walk(fn):
            if not isinstance(node, ast.Assign):
                continue
            for t in node.targets:
                pairs = zip(t.elts, node.value.elts) if isinstance(t, (ast.Tuple, ast.List))                     and isinstance(node.value, (ast.Tuple, ast.List)) else [(t, node.value)]
                for tgt, val in pairs:
                    if isinstance(val, ast.Name) and val.id in checked and isinstance(tgt, ast.Attribute)                             and isinstance(tgt.value, ast.Name) and tgt.value.id == "self":
                        attrs.add(tgt.attr)
    return attrs, local


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
    """ast.walk that does not enter nested functions or classes (they are analysed on their own).

    Lambda bodies are entered: they run with the enclosing function's variables.
    """
    todo = [node]
    while todo:
        n = todo.pop()
        yield n
        for child in ast.iter_child_nodes(n):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
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


def _subscript_key(node: ast.Subscript) -> Optional[str]:
    """`name["key"]` as an env key, for taint tracked per constant key."""
    if isinstance(node.value, ast.Name) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, (str, int)):
        return f"{node.value.id}[{node.slice.value!r}]"
    return None


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
        self.sanitized: Dict[str, Set[str]] = {}
        self.assigned: Dict[str, ast.AST] = {}
        self.params = params
        self.except_names: Set[str] = set()
        self.try_depth = 0
        self.depth = 0  # calls followed to get here (cross-function taint)


class PyScanner:
    def __init__(self, project: Project, emit: Emit):
        self.p = project
        self.emit = emit
        self.trees: List[Tuple[SourceFile, ast.Module]] = []
        self.llm_funcs: Set[str] = set()
        self.routes: List[Route] = []
        self.global_auth = False
        self.global_roles = False  # that global auth hook also enforces roles
        self.file_auth: Set[str] = set()
        self.drf_default_auth = False
        self.sf: SourceFile = None  # type: ignore[assignment]
        self.reported: Set[tuple] = set()
        self.tool_methods: Set[int] = set()
        self._idents: Dict[str, Tuple[Set[str], List[Tuple[int, int, str]]]] = {}
        self.auth_aliases: Set[str] = set()
        self.tool_lambda_nodes: Set[int] = set()
        # cross-function taint: per file, top-level functions, methods and imported names; calls to follow
        self.defs: Dict[str, Dict[str, ast.AST]] = {}
        self.methods: Dict[str, Dict[str, ast.AST]] = {}
        self.imports: Dict[str, Dict[str, Tuple[str, Optional[str], int]]] = {}
        self.modules: Dict[str, str] = {}  # dotted module name (and its suffixes) -> file
        self.consts: Dict[str, Dict[str, str]] = {}  # per file: module-level NAME = "string"
        self.mod_assigned: Dict[str, Dict[str, ast.AST]] = {}  # per file: module-level NAME = expr
        self.calls: List[tuple] = []
        self.via: Optional[str] = None  # set while a callee is walked: how the tainted value got there

    def add(self, rule: str, node: ast.AST, msg: str, sev: str = "") -> None:
        line = getattr(node, "lineno", 1)
        # a finding reached through a followed call has its own key: scanner.finalize drops the plain finding on the
        # same line in its favour (also when the plain one is replayed by vibeaudit watch)
        key = (self.sf.rel, line, rule) + (("via",) if self.via else ())
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
        if GUARD.memo is not None:  # what the checks read besides their own file (see guard.NEEDS_CONTEXT)
            GUARD.sink("py routes", self.routes)
            GUARD.sink("py calls", self.calls)
            GUARD.memo.context["Python checks"] = (
                frozenset(self.llm_funcs), self.global_auth, self.global_roles, frozenset(self.file_auth), self.drf_default_auth,
                frozenset(self.auth_aliases), H.CUSTOM.signature())
        for sf, tree in self.trees:
            self.sf = sf
            GUARD.run(sf.rel, "Python checks", self._check_file, sf, tree)
        GUARD.run("<project>", "Python calls", self.follow_calls)
        GUARD.run("<project>", "Python router prefixes", self.resolve_prefixes)
        return self.routes

    def _parse(self, sf: SourceFile) -> None:
        tree = sf.cache.get("ast")  # kept between scans of a long-lived Project (vibeaudit watch); never mutated
        if not isinstance(tree, ast.Module):
            try:
                tree = ast.parse(sf.text or "", filename=sf.rel)
            except (SyntaxError, ValueError):
                return  # not valid Python (templates, Python 2, partial files): nothing to analyse
        sf.cache["ast"] = tree
        self.trees.append((sf, tree))

    def _check_file(self, sf: SourceFile, tree: ast.Module) -> None:
        self.check_comments(sf)
        if not sf.is_test:
            self.scan_module(tree)

    def index(self) -> None:
        bodies: Dict[str, List[ast.AST]] = {}
        for sf, tree in self.trees:
            GUARD.tick()
            self._index_callables(sf, tree)
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
                    # Flask's before_request, or a FastAPI / Starlette `@app.middleware("http")` that authenticates
                    if any(last_name(d.func if isinstance(d, ast.Call) else d) in ("before_request", "middleware")
                           for d in node.decorator_list):
                        seg = ast.get_source_segment(sf.text, node) or ""
                        if H.AUTH_EVIDENCE.search(seg) or re.search(r"abort\s*\(\s*40[13]|redirect\s*\(", seg):
                            self.global_auth = True
                            self.global_roles = self.global_roles or bool(H.ADMIN_ROLE_EVIDENCE.search(seg))
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

    # -------------------------------------------------- cross-function taint
    def _index_callables(self, sf: SourceFile, tree: ast.Module) -> None:
        defs, methods, imports, consts, mod_assigns = {}, {}, {}, {}, {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                mod_assigns[node.targets[0].id] = node.value
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    consts[node.targets[0].id] = node.value.value
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs[node.name] = node
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        methods.setdefault(item.name, item)
            elif isinstance(node, ast.ImportFrom):
                for a in node.names:
                    imports[a.asname or a.name] = (node.module or "", a.name, node.level)
            elif isinstance(node, ast.Import):
                for a in node.names:
                    imports[a.asname or a.name.split(".")[0]] = (a.name if a.asname else a.name.split(".")[0], None, 0)
        self.defs[sf.rel], self.methods[sf.rel], self.imports[sf.rel], self.consts[sf.rel] = defs, methods, imports, consts
        self.mod_assigned[sf.rel] = mod_assigns
        parts = sf.rel[:-3].split("/")
        if parts[-1] == "__init__":
            parts = parts[:-1]
        for i in range(len(parts)):
            self.modules.setdefault(".".join(parts[i:]), sf.rel)

    def resolve_prefixes(self) -> None:
        """FastAPI `APIRouter(prefix=...)` and `include_router(r, prefix=...)`, Flask `Blueprint(url_prefix=...)` and
        `register_blueprint(bp, url_prefix=...)`, through imports and nested routers. A route gets its full path
        and `prefix_resolved`; when a prefix is not a string literal, or a router is mounted twice or not at all,
        the route keeps its own path and stays unresolved."""
        own: Dict[Tuple[str, str], Tuple[Optional[str], bool]] = {}  # router -> (own prefix, is a Flask blueprint)
        mounts: Dict[Tuple[str, str], List[Tuple[Optional[Tuple[str, str]], Optional[str]]]] = {}
        apps: Set[Tuple[str, str]] = set()
        for sf, tree in self.trees:
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                        and isinstance(node.value, ast.Call):
                    kind = last_name(node.value.func)
                    kws = {k.arg: k.value for k in node.value.keywords if k.arg}
                    var = node.targets[0].id
                    if kind == "APIRouter":
                        own[(sf.rel, var)] = (const_str(kws["prefix"]) if "prefix" in kws else "", False)
                    elif kind == "Blueprint":
                        own[(sf.rel, var)] = (const_str(kws["url_prefix"]) if "url_prefix" in kws else "", True)
                    elif kind in ("FastAPI", "Flask", "APIFlask", "Quart"):
                        apps.add((sf.rel, var))
        for sf, tree in self.trees:
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in ("include_router", "register_blueprint") and node.args):
                    continue
                kws = {k.arg: k.value for k in node.keywords if k.arg}
                key = "prefix" if node.func.attr == "include_router" else "url_prefix"
                prefix = const_str(kws[key]) if key in kws else ""
                child = self._router_ref(sf.rel, node.args[0], own)
                parent_obj = node.func.value.id if isinstance(node.func.value, ast.Name) else None
                parent = (sf.rel, parent_obj) if parent_obj and (sf.rel, parent_obj) in own else None
                if child is not None:
                    mounts.setdefault(child, []).append((parent, prefix))

        def full(router: Tuple[str, str], depth: int = 0) -> Optional[str]:
            prefix, blueprint = own[router]
            found = mounts.get(router, [])
            if prefix is None or len(found) != 1 or depth > 8:
                return None
            parent, mount = found[0]
            if mount is None:
                return None
            base = "" if parent is None else full(parent, depth + 1)
            if base is None:
                return None
            if blueprint:  # register_blueprint(url_prefix=...) replaces the blueprint's own url_prefix
                return join_path(base, mount or prefix)
            return join_path(join_path(base, mount), prefix)

        for r in self.routes:
            m = re.match(r"\s*@\s*([A-Za-z_]\w*)\s*\.", r.body)
            obj = m.group(1) if m else None
            if obj is not None and (r.file, obj) in own:
                prefix = full((r.file, obj))
                if prefix is not None:
                    r.path = join_path(prefix, r.path)
                r.prefix_resolved = prefix is not None  # type: ignore[attr-defined]
            else:
                r.prefix_resolved = r.framework != "drf"  # type: ignore[attr-defined]  # on the app itself

    def _router_ref(self, rel: str, node: ast.AST, own) -> Optional[Tuple[str, str]]:
        """The (file, variable) of a router passed to include_router / register_blueprint."""
        if isinstance(node, ast.Name):
            if (rel, node.id) in own:
                return rel, node.id
            imp = self.imports.get(rel, {}).get(node.id)
            if imp and imp[1]:
                target = self._module_file(rel, imp[0], imp[2])
                if target and (target, imp[1]) in own:
                    return target, imp[1]
            return None
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):  # users.router
            imp = self.imports.get(rel, {}).get(node.value.id)
            if imp is None:
                return None
            module, name, level = imp
            target = self._module_file(rel, (module + "." + name if module else name) if name else module, level)
            if target and (target, node.attr) in own:
                return target, node.attr
        return None

    def _module_file(self, caller: str, module: str, level: int) -> Optional[str]:
        if level:
            base = caller.split("/")[:-1]
            base = base[:len(base) - (level - 1)] if level > 1 else base
            rel = "/".join(base + ([module.replace(".", "/")] if module else []))
            for cand in (rel + ".py", rel + "/__init__.py"):
                if cand in self.defs:
                    return cand
            return None
        return self.modules.get(module)

    def _callee(self, caller: str, spec: tuple) -> Optional[Tuple[str, ast.AST, bool]]:
        """(file, function, is a method) for a call recorded as ("name", f), ("self", m) or ("attr", base, f)."""
        if spec[0] == "self":
            fn = self.methods.get(caller, {}).get(spec[1])
            return (caller, fn, True) if fn is not None else None
        if spec[0] == "name":
            if spec[1] in self.defs.get(caller, {}):
                return caller, self.defs[caller][spec[1]], False
            imp = self.imports.get(caller, {}).get(spec[1])
            if imp is None or imp[1] is None:
                return None
            module, name, level = imp
            target = self._module_file(caller, module, level)
            fn = self.defs.get(target or "", {}).get(name)
            return (target, fn, False) if target and fn is not None else None
        imp = self.imports.get(caller, {}).get(spec[1])  # attr: `module.function(...)`
        if imp is None:
            return None
        module, name, level = imp
        target = self._module_file(caller, module + ("." + name if name else "") if module else (name or ""), level) \
            if name else self._module_file(caller, module, level)
        fn = self.defs.get(target or "", {}).get(spec[2])
        return (target, fn, False) if target and fn is not None else None

    def _note_call(self, call: ast.Call, ctx: Ctx) -> None:
        """Record a call that passes tainted values, to follow into the callee after every file is checked."""
        if ctx.depth >= CALL_DEPTH or ctx.kind == "module":
            return
        f = call.func
        if isinstance(f, ast.Name):
            spec: tuple = ("name", f.id)
        elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            spec = ("self", f.attr) if f.value.id in ("self", "cls") else ("attr", f.value.id, f.attr)
        else:
            return
        args = {}
        san_args = {}
        for i, a in enumerate(call.args):
            if isinstance(a, ast.Starred):
                break
            t = self.taint(a, ctx)
            if t:
                args[i] = t
                sc = self._safe_contexts(a, t, ctx)
                if sc:
                    san_args[i] = sc
        for k in call.keywords:
            if k.arg:
                t = self.taint(k.value, ctx)
                if t:
                    args[k.arg] = t
                    sc = self._safe_contexts(k.value, t, ctx)
                    if sc:
                        san_args[k.arg] = sc
        if args:
            via = self.via or f"{self.sf.rel}:{call.lineno}"
            GUARD.publish("py calls", self.calls, (self.sf.rel, spec, args, ctx.depth + 1, via, san_args))

    def follow_calls(self) -> None:
        seen: Set[tuple] = set()
        i = 0
        while i < len(self.calls):  # following a call can record further calls
            entry = self.calls[i]
            caller, spec, args, depth, via = entry[:5]
            san_args = entry[5] if len(entry) > 5 else {}
            i += 1
            GUARD.tick()
            got = self._callee(caller, spec)
            if got is None:
                continue
            rel, fn, method = got
            params = [a.arg for a in fn.args.posonlyargs + fn.args.args]  # type: ignore[attr-defined]
            if method and params and params[0] in ("self", "cls"):
                params = params[1:]
            env: Dict[str, Taint] = {}
            san_env: Dict[str, Set[str]] = {}
            kwonly = [a.arg for a in fn.args.kwonlyargs]  # type: ignore[attr-defined]
            for key, t in args.items():
                name = params[key] if isinstance(key, int) and key < len(params) else key if isinstance(key, str) else None
                if name in params or (isinstance(key, str) and name in kwonly):
                    env[name] = merge(env.get(name, {}), t)  # type: ignore[index]
                    if key in san_args:
                        san_env[name] = san_env.get(name, set()) | san_args[key]  # type: ignore[index]
            key = (rel, fn.lineno, tuple(sorted((k, tuple(sorted(v))) for k, v in env.items())),
                   tuple(sorted((k, tuple(sorted(v))) for k, v in san_env.items())))  # type: ignore[attr-defined]
            if not env or key in seen or self._is_source(fn):
                continue
            seen.add(key)
            sf = self.p.get(rel)
            if sf is None:
                continue
            ctx = Ctx("plain", set(params))
            ctx.env.update(env)
            ctx.sanitized.update(san_env)
            ctx.depth = depth
            self.sf, self.via = sf, via
            try:
                self.walk_block(fn.body, ctx)  # type: ignore[attr-defined]
            finally:
                self.via = None

    def _is_source(self, fn: ast.AST) -> bool:
        """Routes and agent tools taint their own parameters already."""
        return self.route_info(fn) is not None or self.is_tool(fn)

    def check_comments(self, sf: SourceFile) -> None:
        from .jsscan import SECURITY_TODO

        views = sf.cache.get("py_views") or py_views(sf.text or "")
        sf.cache["views"] = sf.cache["py_views"] = views
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
            elif isinstance(node, ast.Try) or type(node).__name__ == "TryStar":
                for handler in node.handlers:  # type: ignore[attr-defined]
                    self.check_except(handler, node)
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
        if self.global_roles:
            body += "\n# role checked by the global auth middleware"  # the route body carries its middleware's checks
        calls_llm = any(isinstance(n, ast.Call) and is_llm_call(n, self.llm_funcs) for n in walk_shallow(fn))
        auth = bool(H.AUTH_EVIDENCE.search(body)) or self.global_auth or self.sf.rel in self.file_auth or H.CUSTOM.is_auth(body)
        for a in fn.args.args + fn.args.kwonlyargs:  # type: ignore[attr-defined]
            ann = ast.unparse(a.annotation) if a.annotation is not None else ""
            if ann and (ann.split("[")[0].split(".")[-1] in self.auth_aliases or AUTH_ANNOTATION.search(ann)):
                auth = True
        if framework == "drf" and self.drf_default_auth and "AllowAny" not in body:
            auth = True
        params = re.findall(r"<(?:\w+:)?(\w+)>|\{(\w+)\}", path)
        GUARD.publish("py routes", self.routes, Route(
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
    def _checked_ident(self, node: ast.AST) -> bool:
        """self.X, or a local name, checked against a strict identifier pattern in this file."""
        rel = self.sf.rel
        if rel not in self._idents:
            tree = next((t for f, t in self.trees if f.rel == rel), None)
            self._idents[rel] = validated_idents(tree) if tree is not None else (set(), [])
        attrs, local = self._idents[rel]
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self":
            return node.attr in attrs
        if isinstance(node, ast.Name):
            return any(a <= node.lineno <= b and n == node.id for a, b, n in local)
        return False

    def taint(self, node: Optional[ast.AST], ctx: Ctx, sink: str = "") -> Taint:
        if node is None or isinstance(node, ast.Constant):
            return {}
        if isinstance(node, ast.Name):
            if sink and sink in ctx.sanitized.get(node.id, ()):
                return {}
            return dict(ctx.env.get(node.id, {}))
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in ("request", "req") and node.attr in USER_ATTRS:
                return {"user": node.lineno}
            return self.taint(node.value, ctx, sink=sink)
        if isinstance(node, ast.Subscript):
            key = _subscript_key(node)
            if key is not None and key in ctx.env:
                if sink and sink in ctx.sanitized.get(key, ()):
                    return {}
                return dict(ctx.env[key])
            return self.taint(node.value, ctx, sink=sink)
        if isinstance(node, ast.Call):
            if is_llm_call(node, self.llm_funcs):
                return {"llm": node.lineno}
            name = last_name(node.func)
            if name in DB_READS and isinstance(node.func, ast.Attribute):
                return {}
            ctxs = _sanitizer_contexts(node, self.imports.get(self.sf.rel, {}) if self.sf else {})
            if "*" in ctxs or (sink and sink in ctxs):
                return {}
            if name == "get" and isinstance(node.func, ast.Attribute) and node.args:
                # mapping.get(key[, default]): the key only selects a value; the result comes from the
                # mapping or the default, so a user-chosen key into a server-side dict is not tainted
                return merge(self.taint(node.func.value, ctx, sink=sink), *[self.taint(a, ctx, sink=sink) for a in node.args[1:]],
                             *[self.taint(k.value, ctx, sink=sink) for k in node.keywords])
            parts = [self.taint(a, ctx, sink=sink) for a in node.args] + [self.taint(k.value, ctx, sink=sink) for k in node.keywords]
            if isinstance(node.func, ast.Attribute):
                parts.append(self.taint(node.func, ctx, sink=sink))
            return merge(*parts)
        if isinstance(node, ast.JoinedStr):
            return merge(*[self.taint(v, ctx, sink=sink) for v in node.values])
        if isinstance(node, ast.FormattedValue):
            return self.taint(node.value, ctx, sink=sink)
        if isinstance(node, ast.BinOp):
            return merge(self.taint(node.left, ctx, sink=sink), self.taint(node.right, ctx, sink=sink))
        if isinstance(node, ast.BoolOp):
            return merge(*[self.taint(v, ctx, sink=sink) for v in node.values])
        if isinstance(node, ast.IfExp):
            return merge(self.taint(node.body, ctx, sink=sink), self.taint(node.orelse, ctx, sink=sink))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return merge(*[self.taint(e, ctx, sink=sink) for e in node.elts])
        if isinstance(node, ast.Dict):
            return merge(*[self.taint(v, ctx, sink=sink) for v in node.values])
        if isinstance(node, (ast.Await, ast.Starred, ast.NamedExpr)):
            return self.taint(node.value, ctx, sink=sink)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return merge(self.taint(node.elt, ctx, sink=sink), *[self.taint(g.iter, ctx, sink=sink) for g in node.generators])
        if isinstance(node, ast.DictComp):
            return merge(self.taint(node.value, ctx, sink=sink), *[self.taint(g.iter, ctx, sink=sink) for g in node.generators])
        return {}

    def _safe_contexts(self, value: Optional[ast.AST], raw_taint: Taint, ctx: Ctx) -> Set[str]:
        if not raw_taint or value is None:
            return set()
        return {c for c in _SINK_CONTEXTS if not self.taint(value, ctx, sink=c)}

    def assign(self, target: ast.AST, t: Taint, ctx: Ctx, value: Optional[ast.AST] = None,
               safe_ctxs: Optional[Set[str]] = None) -> None:
        if isinstance(target, ast.Name):
            ctx.env[target.id] = t
            if safe_ctxs:
                ctx.sanitized[target.id] = set(safe_ctxs)
            else:
                ctx.sanitized.pop(target.id, None)
            if value is not None:
                ctx.assigned[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(target.elts) \
                    and not any(isinstance(e, ast.Starred) for e in (*target.elts, *value.elts)):
                # `sql, args["r"] = sql + " WHERE r = :r", risk`: each target gets its own element's taint
                taints = [self.taint(v, ctx) for v in value.elts]  # the right side is evaluated before any binding
                safes = [self._safe_contexts(v, et, ctx) for v, et in zip(value.elts, taints)]
                for e, v, et, sc in zip(target.elts, value.elts, taints, safes):
                    self.assign(e, et, ctx, v, sc)
                return
            for e in target.elts:
                self.assign(e, t, ctx, None, safe_ctxs)
        elif isinstance(target, ast.Starred):
            self.assign(target.value, t, ctx, value, safe_ctxs)
        elif isinstance(target, ast.Subscript) and _subscript_key(target) is not None:
            k = _subscript_key(target)
            ctx.env[k] = t  # type: ignore[index]  # d["k"] = constant: that key is clean
            if safe_ctxs:
                ctx.sanitized[k] = set(safe_ctxs)  # type: ignore[index]
            else:
                ctx.sanitized.pop(k, None)  # type: ignore[arg-type]
        elif isinstance(target, (ast.Attribute, ast.Subscript)) and t:
            if isinstance(target, ast.Subscript) and _subscript_key(target) is not None:
                ctx.env[_subscript_key(target)] = t  # type: ignore[index]
            base = root_name(target)
            if base:
                ctx.env[base] = merge(ctx.env.get(base, {}), t)

    def walk_block(self, stmts: List[ast.stmt], ctx: Ctx) -> None:
        for st in stmts:
            GUARD.tick()
            for expr in header_exprs(st):
                for n in walk_shallow(expr):
                    if id(n) in self.tool_lambda_nodes:
                        continue  # already analysed as an agent tool, with model-controlled parameters
                    if isinstance(n, ast.Call):
                        self.check_call(n, ctx)
                    elif isinstance(n, ast.Dict):
                        self.check_system_dict(n, ctx)
                    elif isinstance(n, ast.Compare):
                        self.check_compare(n)
            if isinstance(st, ast.Assign):
                t = self.taint(st.value, ctx)
                sc = self._safe_contexts(st.value, t, ctx)
                for tg in st.targets:
                    self.assign(tg, t, ctx, st.value, sc)
                self.check_assign_random(st)
            elif isinstance(st, ast.AnnAssign) and st.value is not None:
                t = self.taint(st.value, ctx)
                self.assign(st.target, t, ctx, st.value, self._safe_contexts(st.value, t, ctx))
            elif isinstance(st, ast.AugAssign):
                base = root_name(st.target)
                if base:
                    if base in ctx.assigned:
                        ctx.assigned[base] = ast.BinOp(left=ctx.assigned[base], op=st.op, right=st.value)
                    rhs_t = self.taint(st.value, ctx)
                    if rhs_t:
                        rhs_sc = self._safe_contexts(st.value, rhs_t, ctx)
                        prev_t = ctx.env.get(base, {})
                        combined_sc = (ctx.sanitized.get(base, set()) & rhs_sc) if prev_t else rhs_sc
                        ctx.env[base] = merge(prev_t, rhs_t)
                        if combined_sc:
                            ctx.sanitized[base] = combined_sc
                        else:
                            ctx.sanitized.pop(base, None)
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
                if st.body and isinstance(st.body[-1], (ast.Raise, ast.Return)):
                    mod_a = self.mod_assigned.get(self.sf.rel, {}) if self.sf else {}
                    for n in _path_guarded(st.test, ctx.assigned, mod_a):
                        ctx.sanitized.setdefault(n, set()).add("path")  # path guard prevents traversal only
            elif isinstance(st, (ast.With, ast.AsyncWith)):
                for item in st.items:
                    if item.optional_vars is not None:
                        self.assign(item.optional_vars, self.taint(item.context_expr, ctx), ctx)
                self.walk_block(st.body, ctx)
            elif isinstance(st, ast.Try) or type(st).__name__ == "TryStar":
                ctx.try_depth += 1
                self.walk_block(st.body, ctx)  # type: ignore[attr-defined]
                ctx.try_depth -= 1
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
        via = f" (passed in through the call at {self.via})" if self.via else ""
        if "tool" in t:
            self.add("LLM005", node, f"An agent tool passes a model-chosen argument to {what}{via}.", "critical" if crit else "high")
        elif "llm" in t:
            src = f"from the call on line {t['llm']}" if not via else "from a model call"
            self.add("LLM002", node, f"Model output ({src}) flows into {what}{via}.", "critical" if crit else "high")
        elif "user" in t:
            self.add(rule, node, f"Request data flows into {what}{via}.", user_sev)
        else:
            return False
        return True

    def _literal_loop_name(self, node: ast.AST, call: ast.AST) -> bool:
        """The name is the variable of a `for x in ['a', 'b']:` loop over string literals just above the call."""
        above = "\n".join(self.sf.lines[max(0, getattr(call, "lineno", 1) - 8):getattr(call, "lineno", 1)])
        above = re.split(r"(?m)^\s*(?:async\s+)?def\s", above)[-1]  # not a loop in the function before this one
        return isinstance(node, ast.Name) and bool(re.search(
            r"\bfor\s+%s\s+in\s+[\[(]\s*(?:['\"][\w.-]{1,60}['\"]\s*,?\s*){1,60}[\])]\s*:" % re.escape(node.id), above))

    def _fixed_host(self, target: ast.AST) -> bool:
        """The URL starts with a literal scheme and host, so request data only reaches its path or query string."""
        if isinstance(target, ast.JoinedStr):
            first = target.values[0] if target.values else None
        elif isinstance(target, ast.Call) and isinstance(target.func, ast.Attribute) and target.func.attr == "format":
            first = target.func.value
        elif isinstance(target, ast.BinOp) and isinstance(target.op, (ast.Add, ast.Mod)):
            first = target.left
            while isinstance(first, ast.BinOp) and isinstance(first.op, ast.Add):
                first = first.left
        else:
            return False
        if isinstance(first, ast.FormattedValue) and isinstance(first.value, ast.Name):  # f"{API_BASE}{path}"
            prefix = self.consts.get(self.sf.rel, {}).get(first.value.id)
            return prefix is not None and bool(FIXED_HOST.match(prefix))
        return isinstance(first, ast.Constant) and isinstance(first.value, str) and bool(FIXED_HOST.match(first.value))

    def _own_functions(self) -> Set[str]:
        """Names of functions defined in the current file, computed once per file."""
        names = self.sf.cache.get("own_functions")
        if names is None:
            names = self.sf.cache["own_functions"] = set(re.findall(r"(?m)^[ \t]*(?:async[ \t]+)?def[ \t]+(\w+)", self.sf.text or ""))
        return names  # type: ignore[return-value]

    def resolve(self, node: ast.AST, ctx: Ctx) -> ast.AST:
        if isinstance(node, ast.Name) and node.id in ctx.assigned:
            return ctx.assigned[node.id]
        return node

    def check_call(self, call: ast.Call, ctx: Ctx) -> None:
        self._note_call(call, ctx)
        d = dotted(call.func)
        name = last_name(call.func)
        kws = {k.arg: k.value for k in call.keywords if k.arg}
        arg0 = call.args[0] if call.args else None
        t0 = self.taint(arg0, ctx) if arg0 is not None else {}
        is_attr = isinstance(call.func, ast.Attribute)

        # Cypher / KQL queries (BE022)
        if is_attr and name in ("run", "execute_query", "query", "ro_query"):
            qnode = kws.get("query") or arg0
            if qnode is not None:
                qsrc = self.resolve(qnode, ctx)
                if is_formatted(qsrc) and CYPHER_KW.search(string_parts(qsrc)) \
                        and not all(fragment_safe(p, ctx.assigned) or self._checked_ident(p) for p in interpolated(qsrc)):
                    tc = self.taint(qnode, ctx, sink="sql")
                    if tc:
                        self.sink(call, tc, "BE022", "a Cypher query", "high", True)
                    elif not self.sf.is_one_off:
                        self.add("BE022", call, "Cypher query built with string formatting; use `$param` parameters.", "medium")
        if is_attr and name in ("execute", "execute_query", "execute_mgmt", "execute_streaming_query"):
            file_txt = self.sf.text or ""
            if "kusto" in file_txt.lower():
                q_cands = [kws.get("query"), call.args[1] if len(call.args) > 1 else None, arg0]
                for qc in q_cands:
                    if qc is None:
                        continue
                    qsrc = self.resolve(qc, ctx)
                    if is_formatted(qsrc) and KQL_KW.search(string_parts(qsrc)):
                        tkq = self.taint(qc, ctx, sink="sql")
                        if tkq:
                            self.sink(call, tkq, "BE022", "a KQL query", "high", True)
                        elif not self.sf.is_one_off:
                            self.add("BE022", call, "KQL query built with string formatting; use query parameters.", "medium")
                        break
        # MongoDB / NoSQL filters (BE010)
        if is_attr and name in MONGO_METHODS and arg0 is not None and any(m in (self.sf.text or "") for m in MONGO_MARKERS):
            msrc = self.resolve(arg0, ctx)
            where_hit = False
            if isinstance(msrc, ast.Dict):
                for k, v in zip(msrc.keys, msrc.values):
                    if const_str(k) == "$where":
                        tv = self.taint(v, ctx, sink="")
                        if tv or is_formatted(self.resolve(v, ctx)):
                            t_hit = tv or {"user": call.lineno}
                            self.sink(call, {"user": t_hit.get("user", call.lineno)} if "user" in t_hit else t_hit,
                                      "BE010", "a MongoDB $where JavaScript expression", "high", True)
                            where_hit = True
                            break
                    elif k is not None:
                        tk = self.taint(k, ctx, sink="nosql")
                        if "user" in tk:
                            self.sink(call, {"user": tk["user"]}, "BE010", "a MongoDB query filter key from request data", "high", False)
                            where_hit = True
                            break
            if not where_hit:
                t_mongo = self.taint(arg0, ctx, sink="nosql")
                if "user" in t_mongo and not _safe_mongo_filter(msrc):
                    self.sink(call, {"user": t_mongo["user"]}, "BE010", "a MongoDB query filter without type checks", "high", False)
        # SQL
        if is_attr and name in ("execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query") or d in ("text", "sqlalchemy.text", "sa.text"):
            if arg0 is not None:
                src = self.resolve(arg0, ctx)
                t_sql = self.taint(arg0, ctx, sink="sql")
                formatted = is_formatted(src) and re.search(r"(?i)\b(select|insert|update|delete|drop|create|alter|where)\b", string_parts(src))
                if formatted and all(fragment_safe(p, ctx.assigned) or self._checked_ident(p) for p in interpolated(src)):
                    pass  # only bind markers are formatted in; the values are passed as parameters
                elif t_sql and (formatted or ctx.kind == "tool" or not isinstance(src, (ast.Constant, ast.JoinedStr, ast.BinOp))) \
                        and not (isinstance(src, ast.Call) and last_name(src.func) in ORM_BUILDERS):
                    self.sink(call, t_sql, "BE001", "a SQL query", "high", True)
                elif formatted and all(self._literal_loop_name(p, call) for p in interpolated(src)):
                    pass  # for table in ['alerts', 'users']: execute('DROP TABLE %s' % table): fixed names
                elif formatted and not self.sf.is_one_off:  # a migration formats in its own constant identifiers
                    self.add("BE001", call, "SQL query built with string formatting; use parameters even for values you think are safe.", "medium")
        # shell
        elif d in ("os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput") or d.endswith("create_subprocess_shell"):
            if arg0 is not None and const_str(arg0) is None:
                t_sh = self.taint(arg0, ctx, sink="shell")
                if not self.sink(call, t_sh, "BE002", "a shell command", "critical", True):
                    if not (self.taint(arg0, ctx, sink="") and not t_sh):
                        self.add("BE002", call, "Shell command built from a variable; if any part comes from users or a model this is command injection.", "medium")
        elif d.startswith("subprocess.") and name in ("run", "call", "check_call", "check_output", "Popen"):
            shell = kws.get("shell")
            shell_on = isinstance(shell, ast.Constant) and shell.value is True
            if arg0 is not None:
                t_sh = self.taint(arg0, ctx, sink="shell")
                if shell_on and const_str(arg0) is None:
                    if not self.sink(call, t_sh, "BE002", "a shell command", "critical", True):
                        if not (self.taint(arg0, ctx, sink="") and not t_sh):
                            self.add("BE002", call, "subprocess with shell=True and a dynamic command.", "medium")
                elif isinstance(arg0, (ast.List, ast.Tuple)) and arg0.elts:
                    program = self.taint(arg0.elts[0], ctx, sink="shell")
                    if program:
                        self.sink(call, program, "BE002", "the program a subprocess runs", "high", True)
                    else:
                        self.check_model_argument(call, arg0.elts, ctx)
                elif t_sh:
                    self.sink(call, t_sh, "BE002", "a subprocess command", "high", True)
        # user-controlled dynamic function dispatch: getattr(obj, tainted)(...) or globals()[tainted](...)
        dispatch = self.resolve(call.func, ctx) if isinstance(call.func, ast.Name) else call.func
        if isinstance(dispatch, ast.Call) and isinstance(dispatch.func, ast.Name) and dispatch.func.id == "getattr" and len(dispatch.args) >= 2:
            t_disp = self.taint(dispatch.args[1], ctx, sink="code")
            if t_disp:
                self.sink(call, t_disp, "BE003", "getattr() dynamic call dispatch", "critical", True)
        elif isinstance(dispatch, ast.Subscript) and isinstance(dispatch.value, ast.Call) \
                and isinstance(dispatch.value.func, ast.Name) and dispatch.value.func.id in ("globals", "locals", "vars"):
            t_disp = self.taint(dispatch.slice, ctx, sink="code")
            if t_disp:
                self.sink(call, t_disp, "BE003", f"{dispatch.value.func.id}() dynamic call dispatch", "critical", True)
        # dynamic code
        if isinstance(call.func, ast.Name) and name in ("eval", "exec", "compile") and arg0 is not None and const_str(arg0) is None \
                and name not in self._own_functions():  # not the module's own eval()
            t_code = self.taint(arg0, ctx, sink="code")
            if not self.sink(call, t_code, "BE003", f"{name}()", "critical", True):
                self.add("BE003", call, f"{name}() on a dynamic string.", "medium")
        # SymPy parses with eval: sympify() / parse_expr() on request data runs code
        elif name in ("sympify", "parse_expr") and arg0 is not None:
            t_code = self.taint(arg0, ctx, sink="code")
            if t_code:
                self.sink(call, t_code, "BE003", f"{name}() (it evaluates the string)", "critical", True)
        # files
        elif (isinstance(call.func, ast.Name) and name == "open") or d in ("os.remove", "os.unlink", "shutil.rmtree", "os.rmdir") or name in ("send_file", "FileResponse"):
            if arg0 is not None:
                self.sink(call, self.taint(arg0, ctx, sink="path"), "BE006", "a file system path", "high", False)
        # outbound HTTP
        elif (root_name(call.func) in ("requests", "httpx", "urllib3", "aiohttp") and name in ("get", "post", "put", "patch", "delete", "head", "request", "urlopen", "stream")) or d.endswith("urlopen"):
            target = call.args[1] if name == "request" and len(call.args) > 1 else arg0
            if target is None:
                target = kws.get("url")
            if target is not None:
                tt = self.taint(target, ctx, sink="url")
                fixed_host = self._fixed_host(self.resolve(target, ctx))
                if tt and not fixed_host:
                    self.sink(call, tt, "BE005", "an outbound HTTP request URL", "high", False)
            if isinstance(kws.get("verify"), ast.Constant) and kws["verify"].value is False:
                self.add("BE013", call, "TLS certificate verification disabled (verify=False).")
        # templates / html / redirects
        elif name == "render_template_string" and arg0 is not None:
            t_html = self.taint(arg0, ctx, sink="html")
            if not self.sink(call, t_html, "BE007", "render_template_string()", "high", False) and is_formatted(arg0):
                self.add("BE007", call, "Template string built with formatting; user data in it becomes template code.", "medium")
        elif name in ("Markup", "mark_safe", "HTMLResponse") and (arg0 is not None or "content" in kws):
            value = arg0 if arg0 is not None else kws.get("content")
            tt = {} if self._rendered(value, ctx) else self.taint(value, ctx, sink="html")
            if not self.sink(call, tt, "FE001", f"{name}() (raw HTML)", "high", False) and arg0 is not None and is_formatted(arg0):
                self.add("FE001", call, f"{name}() marks a formatted string as safe HTML.", "medium")
        elif name in ("redirect", "RedirectResponse", "HttpResponseRedirect") and arg0 is not None:
            # redirecting to the request's own URL (http -> https, trailing slash) goes back to the same site
            target = self.resolve(arg0, ctx)
            while isinstance(target, ast.BinOp) and isinstance(target.op, ast.Add) and _leading_query_or_fragment(target.right):
                target = target.left
            same_site = bool(re.fullmatch(r"request\.(?:url|base_url|url_root|host_url|full_path|path)(?:\.\w+\(.*\)|\[[^\]]*\])?",
                                          ast.unparse(target), re.S))
            # url_for() / reverse() build a path of this app; redirect(obj) uses the model's get_absolute_url()
            same_site = same_site or (isinstance(target, ast.Call) and last_name(target.func) in (
                "url_for", "reverse", "reverse_lazy", "resolve_url", "url_path_for", "first", "get_object_or_404"))
            if not same_site and not (isinstance(arg0, ast.JoinedStr) and arg0.values and isinstance(arg0.values[0], ast.Constant)
                                      and str(arg0.values[0].value).startswith("/")):
                self.sink(call, self.taint(arg0, ctx, sink="redirect"), "BE008", "a redirect target", "medium", False)
        # deserialization and model loading
        elif d in ("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "dill.loads", "dill.load", "marshal.loads", "marshal.load", "jsonpickle.decode", "shelve.open", "yaml.unsafe_load"):
            if not self.sink(call, t0, "BE004", d + "()", "high", True):
                self.add("BE004", call, f"{d}() can execute code if the data is ever attacker-controlled.", "medium")
        elif (d in ("json.loads", "json.load") and arg0 is not None and "llm" in t0 and ctx.try_depth == 0
              and not H.JSON_MODE.search("\n".join(self.sf.lines[max(t0["llm"] - 1, 0):call.lineno]))):
            self.add("LLM011", call, f"Model output (line {t0['llm']}) is parsed with {d}() without handling invalid JSON.")
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
            if creds and re.search(r"['\"]\*['\"]|['\"]\.\*['\"]", origins):  # without credentials no cookies are sent
                self.add("BE012", call, "CORS allows any origin together with credentials.", "high")
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
        # agent tools defined inline: Tool(name=..., func=lambda cmd: ...)
        if name in ("Tool", "StructuredTool", "DynamicTool", "FunctionTool", "from_function"):
            fn = kws.get("func") or kws.get("coroutine") or next((a for a in call.args if isinstance(a, ast.Lambda)), None)
            if isinstance(fn, ast.Lambda) and id(fn) not in self.tool_lambda_nodes:
                sub = Ctx("tool", {a.arg for a in fn.args.args})
                sub.env = dict(ctx.env)
                for a in fn.args.args:
                    sub.env[a.arg] = {"tool": fn.lineno}
                self.tool_lambda_nodes.update(id(n) for n in ast.walk(fn))
                for n in walk_shallow(fn.body):
                    if isinstance(n, ast.Call):
                        self.check_call(n, sub)
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
        if wildcard and creds:  # without credentials no cookies are sent
            self.add("BE012", call, "Flask-CORS allows any origin together with credentials.", "high")

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
        if self.sf.is_one_off and d == "print":
            return  # a helper script that fetches a token prints it on purpose
        for arg in call.args:
            sliced = {id(n.value) for n in ast.walk(arg) if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Slice)}
            # a secret passed into a one-way function prints its output (a signature, a digest), not the secret
            one_way = {id(s) for n in ast.walk(arg) if isinstance(n, ast.Call)
                       and re.search(r"(?i)(?:^|_)(?:sign|hmac|hash|digest|sha\d|blake|fingerprint|redact|mask)", last_name(n.func) or "")
                       for a in (*n.args, *(k.value for k in n.keywords)) for s in ast.walk(a)}
            for n in ast.walk(arg):
                if id(n) in one_way:
                    continue
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
            if isinstance(n, ast.Call) and dotted(n.func).startswith("random.") and "SystemRandom" not in ast.unparse(n.func) \
                    and last_name(n.func) in ("choice", "choices", "randint", "random", "randrange", "sample", "getrandbits"):
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

    def check_except(self, h: ast.ExceptHandler, owner: Optional[ast.AST] = None) -> None:
        if not all(isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)) for s in h.body):
            return
        last = owner.body[-1] if owner is not None and owner.body else None  # type: ignore[attr-defined]
        if last is not None and (
                (isinstance(last, ast.Raise) and last.exc is not None and "AssertionError" in ast.unparse(last.exc))
                or (isinstance(last, ast.Assert) and isinstance(last.test, ast.Constant) and not last.test.value)
                or (isinstance(last, ast.Expr) and isinstance(last.value, ast.Call) and last_name(last.value.func) == "fail")):
            return  # "this must raise" check: the exception is the expected outcome, not a swallowed error
        typ = ast.unparse(h.type) if h.type is not None else ""
        # from the line after `except ...:` (a comment may sit above `pass`) to the end of the handler
        block = "\n".join(self.sf.lines[h.lineno:getattr(h, "end_lineno", h.lineno)])
        if "#" in block:
            return  # an explanatory comment means ignoring the error is deliberate
        if typ and not re.search(r"\b(?:Base)?Exception\b", typ):
            return  # naming a specific exception (KeyError, OSError) means this failure was expected
        self.add("QA003", h, f"`except {typ or ''}` silently ignores the error.".replace("except :", "except:"))

    def check_model_argument(self, call: ast.Call, argv: list, ctx) -> None:
        """LLM019: model output as an argument (not the program) of a subprocess run without a shell."""
        prog = const_str(argv[0]) or "the program"
        for e in argv[1:]:
            if isinstance(e, ast.Constant) and e.value == "--":
                return  # everything after `--` is an operand, never an option
            te = self.taint(e, ctx, sink="shell")
            if te and "llm" in te and "tool" not in te:
                self.add("LLM019", call, f"Model output (from the call on line {te['llm']}) is passed as an argument to "
                                         f"`{prog}`; a value such as `--upload-pack=...` becomes an option.", "high")
                return

    def check_loop(self, node: ast.While) -> None:
        forever = isinstance(node.test, ast.Constant) and node.test.value is True
        if not forever and not AGENT_LOOP_TEST.search(ast.unparse(node.test)):
            return
        calls = any(isinstance(n, ast.Call) and is_llm_call(n, self.llm_funcs) for n in ast.walk(node))
        if not calls:
            return
        for n in ast.walk(node):
            if isinstance(n, ast.Compare):
                names = [x.id for x in ast.walk(n) if isinstance(x, ast.Name)] + [x.attr for x in ast.walk(n) if isinstance(x, ast.Attribute)]
                if any(BOUND_NAME.search(x) and not AGENT_LOOP_TEST.search(x) for x in names):
                    return
        if forever:
            self.add("LLM009", node, "while True loop calls a model with no step or budget limit.")
        else:
            self.add("LLM020", node, "Agent loop calls the model until it stops asking for tools, with no step limit.")

    def check_module_text(self, tree: ast.Module) -> None:
        sf = self.sf
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for d in node.decorator_list:
                    if last_name(d.func if isinstance(d, ast.Call) else d) in ("csrf_exempt",) or dotted(d).endswith("csrf.exempt"):
                        seg = ast.get_source_segment(sf.text or "", node) or ""
                        if "webhook" in getattr(node, "name", "").lower() and H.WEBHOOK_VERIFY.search(seg):
                            continue  # a webhook that verifies its sender's signature cannot carry a CSRF token
                        self.add("AUTH009", d, "CSRF protection disabled for this view.")
            if isinstance(node, ast.Assign):
                tgt = " ".join(ast.unparse(t) for t in node.targets)
                val = node.value
                if re.search(r"(?:^|\.|\[['\"])WTF_CSRF_ENABLED", tgt) and isinstance(val, ast.Constant) and val.value is False:
                    self.add("AUTH009", node, "Flask-WTF CSRF protection disabled.")
                if re.search(r"(?:^|\.)(?:debug|DEBUG)$|\[['\"]DEBUG['\"]\]", tgt) and isinstance(val, ast.Constant) and val.value is True:
                    if re.search(r"(?:^|/)settings(?:/(?!dev|local|test)[^/]*)?\.py$|(?:^|/)(?:app|main|config|wsgi|server)\.py$", sf.rel) \
                            and not production_overrides(self.p, sf.rel, "DEBUG"):
                        self.add("BE011", node, "DEBUG is hard-coded to True.")
                if tgt == "ALLOWED_HOSTS" and "'*'" in ast.unparse(val).replace('"', "'") and not production_overrides(self.p, sf.rel, tgt):
                    self.add("CFG006", node, "ALLOWED_HOSTS accepts any host.")
