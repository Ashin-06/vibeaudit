"""C# data flow: request data from ASP.NET Core action and endpoint parameters (and Request.Query / Form / Headers)
followed through local assignments in the same method into BE001, BE002, BE005, BE006 and BE008.

A per-method approximation: values passed to other methods are not followed.
"""
from __future__ import annotations

import re
from typing import Callable, List, Set, Tuple

from .csharp import _body_end
from .files import SourceFile
from .guard import finditer
from .jvmsinks import _split
from .lexer import Views, match_close
from .polyscan import CS_CMDI, CS_SQLI

Add = Callable[..., None]

BOUND = re.compile(r"\[\s*From(?:Query|Route|Body|Form|Header)\b")
REQUEST_TYPE = re.compile(r"^(?:string|Uri|IFormFile|[A-Z]\w{0,60}(?:Request|Dto|DTO|Model|Input|Command|Form))\??$")
ACTION = re.compile(r"(?m)^[ \t]*(?:(?:public|static|async|virtual|override|new)\s+){1,5}[\w<>\[\],.? ]{1,120}?\s(\w+)\s*\(")
LAMBDA = re.compile(r"\.\s*Map(?:Get|Post|Put|Delete|Patch|Methods)\s*\(\s*\"[^\"\n]{0,200}\"\s*,\s*(?:async\s+)?\(")
SOURCE = re.compile(r"\bRequest\s*\.\s*(?:Query|Form|Headers|Cookies|RouteValues)\b")
DECL = re.compile(r"(?m)^[ \t]*(?:var|string|[\w<>\[\],.?]{1,60})\s+(\w+)\s*=\s*([^;\n]{1,400})")
BUILT = re.compile(r"\$@?\"|@\$\"|\+\s*\w|\w\s*\+|string\s*\.\s*(?:Format|Concat)\s*\(|\.Append\s*\(")
SQL_WORD = re.compile(r"(?i)\b(?:select|insert|update|delete|where)\b")
# the receiver of GetAsync and friends: an HttpClient, not a repository or service that has a GetAsync of its own
CLIENT_NAME = re.compile(r"(?i)http|client")
CLIENT_DECL = re.compile(r"\bHttpClient\??\s+(\w+)|\b(\w+)\s*=\s*(?:new\s+HttpClient\b|[\w.]{1,80}\.\s*CreateClient\s*\()")
FIXED_START = re.compile(r"^(?:\$@?|@\$|@)?\"[^{\"]")  # a literal that starts the URL: the host is fixed

SINKS: List[Tuple["re.Pattern[str]", str, str, str, str]] = [
    # (call, rule, what, severity, which arguments: "built-first" | "first" | "any" | "url" (any, skipping a fixed host))
    (re.compile(r"\.\s*(?:FromSqlRaw|FromSql|ExecuteSqlRaw|ExecuteSqlRawAsync|SqlQueryRaw)\s*\(|\bnew\s+(?:SqlCommand|NpgsqlCommand|MySqlCommand|SqliteCommand)\s*\("
                r"|\.\s*(?:Query|QueryAsync|QueryFirst\w{0,20}|QuerySingle\w{0,20}|Execute|ExecuteAsync|ExecuteScalar\w{0,10})\s*(?:<[^<>()]{0,80}>)?\s*\("),
     "BE001", "a SQL query", "high", "built-first"),
    (re.compile(r"\bProcess\s*\.\s*Start\s*\(|\bnew\s+ProcessStartInfo\s*\("), "BE002", "a command", "critical", "any"),
    (re.compile(r"\b(\w+)\s*\.\s*(?:GetAsync|GetStringAsync|GetStreamAsync|GetByteArrayAsync|PostAsync|PutAsync|DeleteAsync|GetFromJsonAsync|PostAsJsonAsync)\s*(?:<[^<>()]{0,80}>)?\s*\("
                r"|\bnew\s+HttpRequestMessage\s*\(\s*HttpMethod\s*\.\s*\w+\s*,"),
     "BE005", "an outbound HTTP request URL", "high", "first"),
    (re.compile(r"\bFile\s*\.\s*(?:ReadAll\w{0,10}|OpenRead|OpenWrite|Open|WriteAll\w{0,10}|Delete|Copy|Move|ReadLines|Create)\s*\("
                r"|\bnew\s+FileStream\s*\(|\bPhysicalFile\s*\(|\bResults\s*\.\s*File\s*\(|\bDirectory\s*\.\s*(?:Delete|GetFiles|EnumerateFiles)\s*\("),
     "BE006", "a file system path", "high", "any"),
    (re.compile(r"(?<![\w.])Redirect(?:Permanent)?\s*\(|\bResults\s*\.\s*Redirect\s*\(|\bResponse\s*\.\s*Redirect\s*\("),
     "BE008", "a redirect target", "medium", "first"),
]


def check(sf: SourceFile, v: Views, add: Add) -> None:
    code, bare = v.code, v.bare
    seen: Set[Tuple[str, int]] = set()

    def report(rule: str, offset: int, msg: str, sev: str) -> None:
        line = sf.line_at(offset)
        if (rule, line) not in seen:
            seen.add((rule, line))
            add(sf, rule, line, msg, sev)

    controller = bool(re.search(r"\bControllerBase\b|\bController\b|\[\s*ApiController\b", code))
    clients = {n for m in finditer(CLIENT_DECL, code) for n in m.groups() if n}
    opens = [m.end() - 1 for m in finditer(ACTION, bare) if controller and "public" in m.group(0)]
    opens += [m.end() - 1 for m in finditer(LAMBDA, bare)]
    for open_paren in opens:
        close = match_close(bare, open_paren)
        end = _body_end(bare, close) if close >= 0 else -1
        if end < 0:
            continue
        tainted = _params(code[open_paren + 1:close])
        start = close + 1
        if tainted or SOURCE.search(code, start, end):
            _method(code[start:end + 1], bare[start:end + 1], start, tainted, report, clients)
    # SQL or a shell command built from a string in place, whatever the data (the earlier polyglot patterns)
    for m in finditer(CS_SQLI, code):
        report("BE001", m.start(), "A raw SQL query is built with string interpolation or concatenation.", "high")
    for m in finditer(CS_CMDI, code):
        report("BE002", m.start(), "A shell process is started with a formatted command string.", "critical")


def _params(params: str) -> Set[str]:
    out: Set[str] = set()
    for part in _split(params):
        p = re.sub(r"\s*=[^,]*$", "", part.strip())  # a default value
        bound = bool(BOUND.search(p))
        p = re.sub(r"\[[^\]]{0,200}\]\s*", "", p).strip()
        m = re.match(r"(?:(?:ref|out|in|params)\s+)?([\w<>\[\],.?]+)\s+(\w+)$", p)
        if m and (bound or REQUEST_TYPE.match(m.group(1))):
            out.add(m.group(2))
    return out


def _method(code: str, bare: str, base: int, tainted: Set[str], report: Callable[..., None], clients: Set[str]) -> None:
    def is_tainted(text: str) -> bool:
        return bool(SOURCE.search(text) or any(re.search(r"\b%s\b" % re.escape(t), text) for t in tainted))

    decls = [(m.group(1), code[m.start(2):m.end(2)]) for m in finditer(DECL, bare)]
    for _ in range(4):
        grew = False
        for name, rhs in decls:
            if name not in tainted and is_tainted(rhs):
                tainted.add(name)
                grew = True
        if not grew:
            break
    built = {name for name, rhs in decls if BUILT.search(rhs) and SQL_WORD.search(rhs)}
    local_check = "IsLocalUrl" in code
    for rx, rule, what, sev, which in SINKS:
        if rule == "BE008" and local_check:
            continue
        for m in finditer(rx, bare):
            close = match_close(bare, m.end() - 1)
            if close < 0:
                continue
            receiver = m.group(1) if rx.groups else None
            if receiver and receiver not in clients and not CLIENT_NAME.search(receiver):
                continue
            argv = [a.strip() for a in _split(code[m.end():close])]
            if which == "built-first":
                first = argv[0] if argv else ""
                # EF Core's FromSql($"...") turns the holes into parameters; FromSql(query) with a built string does not
                inline = bool(re.search(r"\bFromSql\s*\($",bare[m.start():m.end()])) and first.startswith("$")
                picked = [first] if first and not inline and (BUILT.search(first) or first in built) else []
            elif which in ("first", "url"):
                picked = [a for a in (argv[:1] if which == "first" else argv) if not FIXED_START.match(a)]
            else:
                picked = argv
            if any(is_tainted(a) for a in picked):
                report(rule, base + m.start(), f"Request data flows into {what}.", sev)
