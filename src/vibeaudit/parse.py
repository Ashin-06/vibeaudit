"""Optional tree-sitter function index for Go, Rust and Java (`pip install vibeaudit[parse]`).

The lexer-based scanners find functions with regular expressions, and routes and cross-function data flow are
built on that index. A real parser finds the declarations those patterns miss (Rust generics with nested `<>`
bounds, Go results that span lines, unusual Java layouts). When tree-sitter or a grammar does not import, or
VIBEAUDIT_PARSER=regex is set, every function here returns None and the scanners keep their regex index, so the
core package stays dependency free.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

GRAMMARS = {"go": "tree_sitter_go", "rust": "tree_sitter_rust", "java": "tree_sitter_java"}
_FUNCS = {"go": ("function_declaration", "method_declaration"), "rust": ("function_item",),
          "java": ("method_declaration", "constructor_declaration")}

# (name, decl start, "(" of the parameters, ")" of the parameters, "{" of the body, offset after the closing "}")
Func = Tuple[str, int, int, int, int, int]


@lru_cache(maxsize=None)
def parser(lang: str) -> Optional[Any]:
    if os.environ.get("VIBEAUDIT_PARSER", "").lower() == "regex":
        return None
    try:
        import importlib

        import tree_sitter

        grammar = importlib.import_module(GRAMMARS[lang])
        return tree_sitter.Parser(tree_sitter.Language(grammar.language()))
    except Exception:  # missing package, old binding or ABI mismatch: fall back to the regex index
        return None


def mode() -> Dict[str, str]:
    """Language -> "tree-sitter" or "regex", for `vibeaudit doctor`."""
    return {lang: "tree-sitter" if parser(lang) is not None else "regex" for lang in GRAMMARS}


def functions(lang: str, text: str) -> Optional[List[Func]]:
    """Every function or method with a body, in document order (character offsets into `text`), or None."""
    p = parser(lang)
    if p is None:
        return None
    data = text.encode("utf-8", "surrogatepass")
    if len(data) == len(text):
        def at(b: int) -> int:
            return b
    else:  # tree-sitter reports byte offsets; the scanners index characters
        def at(b: int) -> int:
            return len(data[:b].decode("utf-8", "ignore"))
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


def spans_by_name(funcs: List[Func], bare: str) -> Dict[str, List[Func]]:
    """Group by name, dropping functions the lexer blanked out (comments, `#[cfg(test)]` modules)."""
    out: Dict[str, List[Func]] = {}
    for f in funcs:
        if bare[f[1]:f[1] + 1].strip():
            out.setdefault(f[0], []).append(f)
    return out
