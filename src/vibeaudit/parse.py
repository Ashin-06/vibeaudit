"""Optional tree-sitter function index for Go, Rust, Java, JavaScript and TypeScript (`pip install vibeaudit[parse]`).

The lexer-based scanners find functions with regular expressions, and routes and cross-function data flow are
built on that index. A real parser finds the declarations those patterns miss (Rust generics with nested `<>`
bounds, Go results that span lines, unusual Java layouts, complex TypeScript type annotations and destructured
JS/TS arrow signatures). When tree-sitter or a grammar does not import, or VIBEAUDIT_PARSER=regex is set,
every function here returns None and the scanners keep their regex index, so the core package stays
dependency free.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Any, Callable, Dict, List, Optional, Tuple

GRAMMARS: Dict[str, Tuple[str, str]] = {
    "go": ("tree_sitter_go", "language"),
    "rust": ("tree_sitter_rust", "language"),
    "java": ("tree_sitter_java", "language"),
    "js": ("tree_sitter_javascript", "language"),
    "ts": ("tree_sitter_typescript", "language_typescript"),
    "tsx": ("tree_sitter_typescript", "language_tsx"),
}
_FUNCS = {"go": ("function_declaration", "method_declaration"), "rust": ("function_item",),
          "java": ("method_declaration", "constructor_declaration")}
_JS_DECL_FUNCS = ("function_declaration", "generator_function_declaration", "method_definition")
_JS_VAL_FUNCS = ("arrow_function", "function_expression", "generator_function")

# (name, decl start, "(" of the parameters, ")" of the parameters, "{" of the body, offset after the closing "}")
Func = Tuple[str, int, int, int, int, int]
# (name, decl start, param_start, param_end, offset after the node end)
JsFunc = Tuple[str, int, int, int, int]


@lru_cache(maxsize=None)
def parser(lang: str) -> Optional[Any]:
    if os.environ.get("VIBEAUDIT_PARSER", "").lower() == "regex":
        return None
    entry = GRAMMARS.get(lang)
    if entry is None:
        return None
    mod_name, fn_name = entry
    try:
        import importlib

        import tree_sitter

        grammar = importlib.import_module(mod_name)
        return tree_sitter.Parser(tree_sitter.Language(getattr(grammar, fn_name)()))
    except Exception:  # missing package, old binding or ABI mismatch: fall back to the regex index
        return None


def _char_mapper(text: str, data: bytes) -> Callable[[int], int]:
    if len(data) == len(text):
        return lambda b: b
    # tree-sitter reports byte offsets; build an exact byte->char lookup table only if multibyte chars exist
    # or decode prefixes dynamically; simple slice cache via prefix mapping is O(N) once:
    mapping = [0] * (len(data) + 1)
    b_pos = 0
    for c_pos, ch in enumerate(text):
        b_len = len(ch.encode("utf-8", "surrogatepass"))
        for k in range(b_len):
            if b_pos + k <= len(data):
                mapping[b_pos + k] = c_pos
        b_pos += b_len
    mapping[len(data)] = len(text)
    return lambda b: mapping[min(max(b, 0), len(data))]


def mode() -> Dict[str, str]:
    """Language -> "tree-sitter" or "regex", for `vibeaudit doctor`."""
    return {lang: "tree-sitter" if parser(lang) is not None else "regex" for lang in GRAMMARS}


def functions(lang: str, text: str) -> Optional[List[Func]]:
    """Every function or method with a body, in document order (character offsets into `text`), or None."""
    p = parser(lang)
    if p is None:
        return None
    data = text.encode("utf-8", "surrogatepass")
    at = _char_mapper(text, data)
    out: List[Func] = []
    stack = [p.parse(data).root_node]
    while stack:
        node = stack.pop()
        stack.extend(reversed(node.children))
        if node.type not in _FUNCS[lang]:
            continue
        name, params, body = (node.child_by_field_name(f) for f in ("name", "parameters", "body"))
        if name is None or params is None or body is None or params.has_error:
            continue
        start = at(node.start_byte)
        if lang == "rust":  # the scanners anchor a Rust function at `fn`, after `pub` / `async` / `unsafe`
            start = text.rfind("fn", start, at(name.start_byte))
        out.append((text[at(name.start_byte):at(name.end_byte)], start, at(params.start_byte),
                    at(params.end_byte) - 1, at(body.start_byte), at(body.end_byte)))
    return out


def js_functions(lang: str, text: str) -> Optional[List[JsFunc]]:
    """JS/TS/TSX function, method, arrow, and assigned-function index in character offsets, or None."""
    p = parser(lang)
    if p is None:
        return None
    data = text.encode("utf-8", "surrogatepass")
    at = _char_mapper(text, data)

    def _param_span(fn_node: Any) -> Optional[Tuple[int, int]]:
        params = fn_node.child_by_field_name("parameters")
        if params is not None and not params.has_error:
            return at(params.start_byte), at(params.end_byte) - 1
        param = fn_node.child_by_field_name("parameter")
        if param is not None and not param.has_error:
            return at(param.start_byte), at(param.end_byte)
        return None

    out: List[JsFunc] = []
    stack = [p.parse(data).root_node]
    while stack:
        node = stack.pop()
        stack.extend(reversed(node.children))
        ntype = node.type
        if ntype in _JS_DECL_FUNCS:
            name = node.child_by_field_name("name")
            body = node.child_by_field_name("body")
            pspan = _param_span(node)
            if name is None or body is None or pspan is None:
                continue
            fn_name = text[at(name.start_byte):at(name.end_byte)]
            if fn_name:
                out.append((fn_name, at(node.start_byte), pspan[0], pspan[1], at(node.end_byte)))
        elif ntype == "variable_declarator":
            name = node.child_by_field_name("name")
            val = node.child_by_field_name("value")
            if name is None or name.type != "identifier" or val is None or val.type not in _JS_VAL_FUNCS:
                continue
            pspan = _param_span(val)
            if pspan is None:
                continue
            start_node = node
            parent = node.parent
            if parent is not None and parent.type in ("lexical_declaration", "variable_declaration"):
                decls = sum(1 for ch in parent.named_children if ch.type == "variable_declarator")
                if decls == 1:
                    start_node = parent
            fn_name = text[at(name.start_byte):at(name.end_byte)]
            if fn_name:
                out.append((fn_name, at(start_node.start_byte), pspan[0], pspan[1], at(val.end_byte)))
        elif ntype == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or left.type != "member_expression" or right is None or right.type not in _JS_VAL_FUNCS:
                continue
            obj = left.child_by_field_name("object")
            prop = left.child_by_field_name("property")
            if obj is None or prop is None:
                continue
            if text[at(obj.start_byte):at(obj.end_byte)] not in ("exports", "module.exports"):
                continue
            pspan = _param_span(right)
            if pspan is None:
                continue
            fn_name = text[at(prop.start_byte):at(prop.end_byte)]
            if fn_name:
                out.append((fn_name, at(node.start_byte), pspan[0], pspan[1], at(node.end_byte)))
        elif ntype == "pair":
            key = node.child_by_field_name("key")
            val = node.child_by_field_name("value")
            if key is None or key.type not in ("property_identifier", "identifier") or val is None or val.type not in _JS_VAL_FUNCS:
                continue
            pspan = _param_span(val)
            if pspan is None:
                continue
            fn_name = text[at(key.start_byte):at(key.end_byte)]
            if fn_name:
                out.append((fn_name, at(node.start_byte), pspan[0], pspan[1], at(val.end_byte)))
    return out


def spans_by_name(funcs: List[Func], bare: str) -> Dict[str, List[Func]]:
    """Group by name, dropping functions the lexer blanked out (comments, `#[cfg(test)]` modules)."""
    out: Dict[str, List[Func]] = {}
    for f in funcs:
        if bare[f[1]:f[1] + 1].strip():
            out.setdefault(f[0], []).append(f)
    return out
