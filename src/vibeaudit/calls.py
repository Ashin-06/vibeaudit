"""Cross-function taint for the lexer-based scanners (Go, Java/Kotlin, C#, Rust, PHP), as pyscan and jsscan do it:
a call that passes request data to a function of the project is followed, and that function is checked again with
those parameters tainted, up to CALL_DEPTH calls deep. A sink reached that way is reported where it is, with the
call it came through.

A call is resolved by its name only: to a function of the same file, or to the one function of the project with
that name. Overloads, interfaces and names defined more than once elsewhere are not followed.
"""
from __future__ import annotations

import re
from typing import Callable, Dict, List, NamedTuple, Optional, Set, Tuple

from .files import SourceFile
from .guard import GUARD, finditer
from .lexer import match_close

CALL_DEPTH = 3
# `helper(x)`, `this.helper(x)`, `$this->helper($x)`, `Self::helper(x)`, `svc.Helper(x)`
CALL = re.compile(r"(?<![\w$])([A-Za-z_]\w{0,80})\s*\(")
NOT_CALLS = frozenset({"if", "for", "foreach", "while", "switch", "match", "catch", "return", "new", "fn", "func", "function",
                       "sizeof", "typeof", "nameof", "using", "lock", "synchronized", "else", "elseif", "do", "try",
                       "isset", "empty", "unset", "array", "list", "echo", "print", "assert", "await", "loop", "when"})


class Fn(NamedTuple):
    sf: SourceFile
    start: int  # offset of the declaration
    params: str  # the parameter list text
    body: Tuple[int, int]  # the body's [start, end) offsets


class Follower:
    def __init__(self, param_names: Callable[[str], List[str]]):
        self.param_names = param_names
        self.funcs: Dict[str, List[Fn]] = {}
        self.queue: List[Tuple[str, frozenset, str, int, str]] = []
        self.seen: Set[tuple] = set()

    def define(self, name: str, fn: Fn) -> None:
        self.funcs.setdefault(name, []).append(fn)

    def resolve(self, name: str, caller: str) -> Optional[Fn]:
        found = self.funcs.get(name, [])
        same = [f for f in found if f.sf.rel == caller]
        if len(same) == 1:
            return same[0]
        return found[0] if len(found) == 1 else None

    def note(self, sf: SourceFile, code: str, bare: str, base: int, is_tainted: Callable[[str], bool], depth: int,
             via: Optional[str]) -> None:
        """Queue every call in `code` (a body starting at `base`) that passes a tainted argument to a known function."""
        if depth >= CALL_DEPTH:
            return
        for m in finditer(CALL, bare):
            name = m.group(1)
            if name in NOT_CALLS or name not in self.funcs:
                continue
            close = match_close(bare, m.end() - 1)
            if close < 0:
                continue
            from .goscan import _split_top  # goscan imports this module

            argv = _split_top(code[m.end():close])
            idx = frozenset(i for i, a in enumerate(argv) if a.strip() and is_tainted(a))
            if idx:
                self.queue.append((name, idx, sf.rel, depth + 1, via or f"{sf.rel}:{sf.line_at(base + m.start())}"))

    def follow(self, run: Callable[[Fn, Set[str], int, str], None]) -> None:
        """Check each queued callee with the parameters at the tainted positions tainted; running one may queue more."""
        i = 0
        while i < len(self.queue):
            name, idx, caller, depth, via = self.queue[i]
            i += 1
            GUARD.tick()
            fn = self.resolve(name, caller)
            if fn is None:
                continue
            params = self.param_names(fn.params)
            seed = {params[k] for k in idx if k < len(params) and params[k]}
            key = (fn.sf.rel, fn.start, frozenset(seed))
            if not seed or key in self.seen:
                continue
            self.seen.add(key)
            run(fn, seed, depth, via)


def via_note(via: Optional[str]) -> str:
    return f" (passed in through the call at {via})" if via else ""


def split_params(params: str) -> List[str]:
    from .goscan import _split_top

    return [p.strip() for p in _split_top(params)] if params.strip() else []


# ------------------------------------------------------------ parameter names
def go_params(params: str) -> List[str]:
    """`a, b string, c *T` -> [a, b, c]; `ctx context.Context` -> [ctx]."""
    out = []
    for p in split_params(params):
        m = re.match(r"([A-Za-z_]\w*)\b", p)
        out.append(m.group(1) if m else "")
    return out


def rust_params(params: str) -> List[str]:
    """`&self, id: i64, mut body: Json<T>` -> [id, body] (self is the receiver, not an argument)."""
    out = []
    for p in split_params(params):
        if re.fullmatch(r"&?\s*(?:'\w+\s+)?(?:mut\s+)?self(?:\s*:.*)?", p, re.S):
            continue
        m = re.match(r"(?:mut\s+)?([a-z_]\w*)\s*:", p)
        out.append(m.group(1) if m else "")
    return out


def jvm_params(params: str) -> List[str]:
    """Java `final String a` / `@X Long id` -> last name; Kotlin `a: String` -> the name before the colon."""
    out = []
    for p in split_params(params):
        p = re.sub(r"@\w+(?:\([^)]*\))?\s*", "", p)
        kotlin = re.match(r"(?:va[lr]\s+)?(\w+)\s*:", p)
        java = re.search(r"(\w+)\s*$", p)
        hit = kotlin or java
        out.append(hit.group(1) if hit else "")
    return out


def cs_params(params: str) -> List[str]:
    """`[FromBody] string name = null` -> name."""
    out = []
    for p in split_params(params):
        p = re.sub(r"\s*=[^,]*$", "", re.sub(r"\[[^\]]{0,200}\]\s*", "", p))
        m = re.search(r"(\w+)\s*$", p)
        out.append(m.group(1) if m else "")
    return out


def php_params(params: str) -> List[str]:
    """`Request $request, ?int $id = null` -> [$request, $id] (PHP names keep their `$`)."""
    out = []
    for p in split_params(params):
        m = re.search(r"\$\w+", p)
        out.append(m.group(0) if m else "")
    return out
