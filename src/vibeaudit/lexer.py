"""Tiny lexers that produce offset-preserving "views" of source files.

`code`  - comments replaced by spaces (strings kept)
`bare`  - comments and string contents replaced by spaces (quotes kept)

Both views have exactly the same length and line breaks as the original, so a match offset in
any view maps to the same line in the file. With string contents blanked, bracket matching is a
plain depth count.
"""
from __future__ import annotations

import re
import threading
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple

REGEX_PREV = set("(,=:[!&|?{};+-*%>~^")
REGEX_KEYWORDS = {"return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw", "yield",
                  "await", "instanceof"}


class Views:
    __slots__ = ("code", "bare", "comments")

    def __init__(self, code: str, bare: str, comments: List[Tuple[int, int]]):
        self.code = code
        self.bare = bare
        self.comments = comments


def _blank(arr: list, a: int, b: int) -> None:
    for k in range(a, b):
        if arr[k] != "\n":
            arr[k] = " "


def js_views(src: str) -> Views:
    n = len(src)
    code = list(src)
    bare = list(src)
    comments: List[Tuple[int, int]] = []
    modes = ["C"]  # C = code, T = template literal text
    depths = [0]
    i = 0
    while i < n:
        c = src[i]
        if modes[-1] == "T":
            if c == "\\":
                _blank(bare, i, min(i + 2, n))
                i += 2
                continue
            if c == "`":
                modes.pop()
                depths.pop()
                i += 1
                continue
            if c == "$" and i + 1 < n and src[i + 1] == "{":
                modes.append("C")
                depths.append(0)
                i += 2
                continue
            if c != "\n":
                bare[i] = " "
            i += 1
            continue
        # code mode
        if c == "`":
            modes.append("T")
            depths.append(0)
            i += 1
            continue
        if c == "{":
            depths[-1] += 1
        elif c == "}":
            if depths[-1] == 0 and len(modes) > 1:
                modes.pop()
                depths.pop()
                i += 1
                continue
            depths[-1] -= 1
        elif c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j == -1 else j
            _blank(code, i, j)
            _blank(bare, i, j)
            comments.append((i, j))
            i = j
            continue
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            _blank(code, i, j)
            _blank(bare, i, j)
            comments.append((i, j))
            i = j
            continue
        elif c in "'\"":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            end = min(j, n)
            _blank(bare, i + 1, end)
            i = end + 1 if end < n and src[end] == c else end
            continue
        elif c == "/" and not (i + 1 < n and src[i + 1] == ">") and _regex_allowed(bare, i):
            j = i + 1
            in_class = False
            while j < n and src[j] != "\n":
                ch = src[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == "[":
                    in_class = True
                elif ch == "]":
                    in_class = False
                elif ch == "/" and not in_class:
                    break
                j += 1
            if j < n and src[j] == "/":
                _blank(bare, i + 1, j)
                i = j + 1
                while i < n and src[i].isalpha():
                    i += 1
                continue
        i += 1
    return Views("".join(code), "".join(bare), comments)


def _regex_allowed(bare: list, i: int) -> bool:
    k = i - 1
    while k >= 0 and bare[k] in " \t\n":
        k -= 1
    if k < 0:
        return True
    ch = bare[k]
    if ch == "<":
        return False  # JSX closing tag: </div>
    if ch in REGEX_PREV:
        return True
    if ch.isalnum() or ch in "_$":
        j = k
        while j >= 0 and (bare[j].isalnum() or bare[j] in "_$"):
            j -= 1
        return "".join(bare[j + 1:k + 1]) in REGEX_KEYWORDS
    return False


def py_views(src: str) -> Views:
    """Linear scan for Python comments and string literals.

    The standard tokenize module is avoided on purpose: on Python 3.12+ every token carries its whole
    physical line, which makes a large single-line file quadratic. Unterminated strings end at the end of
    the line (single quotes) or of the file (triple quotes), so broken code still gets usable views.
    """
    n = len(src)
    code = list(src)
    bare = list(src)
    comments: List[Tuple[int, int]] = []
    i = 0
    while i < n:
        c = src[i]
        if c == "#":
            j = src.find("\n", i)
            j = n if j == -1 else j
            _blank(code, i, j)
            _blank(bare, i, j)
            comments.append((i, j))
            i = j
        elif c in "'\"":
            triple = src[i:i + 3] == c * 3
            q = c * 3 if triple else c
            j = i + len(q)
            while j < n:
                ch = src[j]
                if ch == "\\":
                    j += 2
                    continue
                if not triple and ch == "\n":
                    break
                if src.startswith(q, j):
                    break
                j += 1
            end = min(j, n)
            _blank(bare, i + len(q), end)
            i = end + len(q) if end < n and src.startswith(q, end) else end
        else:
            i += 1
    return Views("".join(code), "".join(bare), comments)


OPEN = {"(": ")", "[": "]", "{": "}"}
CLOSE = {")", "]", "}"}


_BRACKET = re.compile(r"[()\[\]{}]")
_PAIRS: "OrderedDict[int, Tuple[str, Dict[int, int]]]" = OrderedDict()
_PAIRS_LOCK = threading.Lock()


def _pairs(bare: str) -> Dict[int, int]:
    """Every bracket of `bare` -> its closing bracket, in one pass. Brackets of all kinds share one depth, as in
    match_close's loop. Cached for the last few strings, so many lookups in one file stay linear."""
    with _PAIRS_LOCK:
        hit = _PAIRS.get(id(bare))
        if hit is not None and hit[0] is bare:
            _PAIRS.move_to_end(id(bare))
            return hit[1]
    stack: List[int] = []
    pairs: Dict[int, int] = {}
    for m in _BRACKET.finditer(bare):
        if m.group() in OPEN:
            stack.append(m.start())
        elif stack:
            pairs[stack.pop()] = m.start()
    with _PAIRS_LOCK:
        _PAIRS[id(bare)] = (bare, pairs)
        while len(_PAIRS) > 16:
            _PAIRS.popitem(last=False)
    return pairs


def match_close(bare: str, i: int) -> int:
    """Index of the bracket closing the one at `i`, or -1."""
    if len(bare) > 4000 and 0 <= i < len(bare) and bare[i] in OPEN:
        # one pass for the whole string: an unclosed bracket would otherwise cost a scan to the end each time
        return _pairs(bare).get(i, -1)
    depth = 0
    n = len(bare)
    j = i
    while j < n:
        ch = bare[j]
        if ch in OPEN:
            depth += 1
        elif ch in CLOSE:
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return -1


def split_args(bare: str, a: int, b: int) -> List[Tuple[int, int]]:
    """Split the range (a, b) at top-level commas; returns (start, end) spans."""
    spans = []
    depth = 0
    start = a
    for j in range(a, b):
        ch = bare[j]
        if ch in OPEN:
            depth += 1
        elif ch in CLOSE:
            depth -= 1
        elif ch == "," and depth == 0:
            spans.append((start, j))
            start = j + 1
    if bare[start:b].strip():
        spans.append((start, b))
    return spans


_CONT_START = re.compile(r"(?<![ \t])[ \t]*(?:\.|\?|:|&&|\|\||\+|-|\*|/|\?\?|=>)")


def stmt_end(bare: str, i: int) -> int:
    """End offset of the expression/statement starting at `i` (JS-ish rules)."""
    depth = 0
    n = len(bare)
    pairs = _pairs(bare) if n > 4000 else None
    j = i
    while j < n:
        ch = bare[j]
        if ch in OPEN:
            if pairs is not None and depth == 0:
                close = pairs.get(j)
                if close is None:  # an unclosed bracket: broken code, so end at the line instead of the file
                    nl = bare.find("\n", j)
                    return nl if nl >= 0 else n
                j = close + 1  # the same as counting through the group: nothing inside it can end the statement
                continue
            depth += 1
        elif ch in CLOSE:
            if depth == 0:
                return j
            depth -= 1
        elif depth == 0 and ch in ";,":
            return j
        elif depth == 0 and ch == "\n":
            before = bare[i:j].rstrip()
            if before and before[-1] not in "=(,+-*/&|?:{[" and not before.endswith("=>"):
                if not _CONT_START.match(bare, j + 1):
                    return j
        j += 1
    return n


def first_arg(bare: str, open_paren: int) -> Optional[Tuple[int, int]]:
    close = match_close(bare, open_paren)
    if close < 0:
        return None
    spans = split_args(bare, open_paren + 1, close)
    return spans[0] if spans else None
