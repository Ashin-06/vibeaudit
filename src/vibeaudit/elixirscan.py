"""Elixir and Phoenix checks (preview): Phoenix router discovery (AUTH001-003),
Ecto SQL interpolation (BE001), OS command injection (BE002), unsafe binary_to_term (BE004),
raw HTML output (FE001), and TLS verify_none (BE013).
"""
from __future__ import annotations

import re
from typing import Callable, List, Optional, Tuple

from . import heuristics as H
from .files import Project, SourceFile
from .guard import GUARD, finditer
from .model import Finding, Route, join_path

Emit = Callable[[Finding], None]

ELIXIR_TEST_RE = re.compile(r"(?:^|/)tests?/|_(?:test|spec)\.exs$", re.I)
_EX_STR_OR_COMMENT = re.compile(r'"(?:\\.|[^"\\\n])*"|(#[^\n]*)')

PHOENIX_ROUTER_MARK = re.compile(r"\bPhoenix\.Router\b|\buse\s+[A-Z][\w.]*,\s*:router\b")
SCOPE_OPEN_RE = re.compile(r'^[ \t]*scope\s+"([^"\n]{0,120})"[^\n]*\bdo\b[ \t]*$')
DO_LINE_RE = re.compile(r"(?:\bdo\b[ \t]*$|,\s*do:)")
END_LINE_RE = re.compile(r"^[ \t]*end\b")
PIPE_THROUGH_RE = re.compile(r"^[ \t]*pipe_through\s+(?:\[([^\]]{0,240})\]|:(\w+))")
PHOENIX_ROUTE_RE = re.compile(
    r'^[ \t]*(get|post|put|patch|delete)\s+"([^"\n]{1,120})"\s*,\s*([A-Z][\w.]*)\s*,\s*:(\w+)'
)
EX_AUTH_PIPE = re.compile(
    r"(?i)\b[\w]*(?:auth|authenticated|require_authenticated|ensure_auth|protected|admin|session|jwt|bearer|token)\w*\b"
)

EX_SQL_QUERY = re.compile(
    r"""\b(?:Ecto\.Adapters\.)?SQL\.query!?\s*\([^\n]{0,120}(?:"[^"\n]{0,240}#\{|"[^"\n]{0,200}"\s*<>)"""
)
EX_ECTO_FRAG = re.compile(r"""\bfragment\s*\(\s*"[^"\n]{0,240}#\{""")
EX_OS_CMD = re.compile(r":os\.cmd\s*\([^\n]{0,200}(?:#\{|\+\+|<>|interpolation)")
EX_SYS_CMD = re.compile(r"""\bSystem\.cmd\s*\(\s*"(?:sh|bash)"\s*,\s*\[\s*"-c"\s*,\s*"[^"\n]{0,200}#\{""")
EX_BINARY_TO_TERM = re.compile(r":erlang\.binary_to_term\s*\(")
EX_RAW_HTML = re.compile(r"""(?:Phoenix\.HTML\.)?\braw\s*\(\s*(?!["'][^"'#\n]{0,120}["']\s*\))([^)\n]{1,120})""")
EX_TLS_NONE = re.compile(r"\bverify\s*:\s*:verify_none\b")
EX_MUT_ACTION = re.compile(r"^(?:create|update|delete|destroy|remove|reset|invite|grant|revoke)\w*$")


def _strip_comments(text: str) -> str:
    return _EX_STR_OR_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(1)) if m.group(1) else m.group(0), text)


def _custom_helper(name: str) -> bool:
    return H.CUSTOM.is_auth(name)


def _auth_pipeline(pipelines: List[str]) -> str:
    for p in pipelines:
        if EX_AUTH_PIPE.search(p):
            return f"pipe_through :{p}"
        if _custom_helper(p):
            return f"requireAuth({p})"
    return ""


class ElixirScanner:
    """Checks for Elixir and Phoenix applications (preview)."""

    def __init__(self, project: Project, emit: Emit):
        self.p = project
        self.emit = emit
        self.routes: List[Route] = []

    def add(self, sf: SourceFile, off: int, rule: str, msg: str, sev: str = "") -> None:
        line = sf.line_at(off)
        self.emit(Finding(rule, sf.rel, line, msg, sev, sf.line(line).strip()[:200]))

    def run(self) -> List[Route]:
        files = [
            f for f in self.p.files
            if f.rel.lower().endswith((".ex", ".exs", ".heex")) and f.text is not None
            and not f.is_test and not f.is_example and not f.is_vendored
            and not ELIXIR_TEST_RE.search(f.rel)
        ]
        has_mix = any(f.rel.rsplit("/", 1)[-1] == "mix.exs" for f in self.p.files)
        if not files and not has_mix:
            return []
        for sf in files:
            GUARD.run(sf.rel, "Elixir checks", self._file, sf)
        return self.routes

    def _file(self, sf: SourceFile) -> None:
        raw = sf.text or ""
        low = sf.rel.lower()
        code = raw if low.endswith(".heex") else _strip_comments(raw)
        if not low.endswith(".heex") and (low.endswith("router.ex") or PHOENIX_ROUTER_MARK.search(code)):
            self._phoenix_routes(sf, code)

        for m in finditer(EX_SQL_QUERY, code):
            if "Ecto" in code or "Repo" in code or "SQL.query" in m.group(0):
                self.add(sf, m.start(), "BE001",
                         "Ecto SQL.query interpolates a dynamic Elixir string; pass parameterized `$1` arguments.", "high")
        for m in finditer(EX_ECTO_FRAG, code):
            self.add(sf, m.start(), "BE001",
                     "Ecto fragment() interpolates an Elixir expression; use `?` placeholders.", "high")
        for m in finditer(EX_OS_CMD, code):
            self.add(sf, m.start(), "BE002",
                     "Dynamic value passed into `:os.cmd` (OS command injection).", "high")
        for m in finditer(EX_SYS_CMD, code):
            self.add(sf, m.start(), "BE002",
                     "Shell `-c` command built with Elixir string interpolation (command injection).", "high")
        for m in finditer(EX_BINARY_TO_TERM, code):
            close = code.find(")", m.end(), m.end() + 160)
            nl = code.find("\n", m.end(), m.end() + 160)
            end_arg = close if close >= 0 else (nl if nl >= 0 else m.end() + 160)
            if ":safe" not in code[m.end():end_arg]:
                self.add(sf, m.start(), "BE004",
                         "`:erlang.binary_to_term` called without `[:safe]` can deserialize arbitrary atoms/terms.",
                         "high")
        if "Phoenix.HTML.raw" in code or low.endswith(".heex"):
            for m in finditer(EX_RAW_HTML, code):
                if "Phoenix.HTML.raw" in m.group(0) or low.endswith(".heex"):
                    self.add(sf, m.start(), "FE001",
                             "Raw unescaped HTML rendered via `raw()` / `Phoenix.HTML.raw` (XSS).", "high")
        for m in finditer(EX_TLS_NONE, code):
            self.add(sf, m.start(), "BE013",
                     "HTTP/TLS client configured with `verify: :verify_none`, disabling certificate verification.",
                     "high")

    def _phoenix_routes(self, sf: SourceFile, code: str) -> None:
        # Stack of (scope_prefix_or_None, pipelines_in_scope) for tracking do/end nesting
        stack: List[Tuple[Optional[str], List[str]]] = []
        off = 0
        for line in code.splitlines(keepends=True):
            stripped = line.strip()
            sm = SCOPE_OPEN_RE.match(line)
            if sm:
                stack.append((sm.group(1), []))
            elif DO_LINE_RE.search(stripped) and not stripped.startswith(("get ", "post ", "put ", "patch ", "delete ")):
                if ", do:" not in stripped:  # one-line `, do:` closes itself
                    stack.append((None, []))
            elif END_LINE_RE.match(line):
                if stack:
                    stack.pop()
            else:
                pm = PIPE_THROUGH_RE.match(line)
                if pm:
                    names = re.findall(r":(\w+)", pm.group(1)) if pm.group(1) else ([pm.group(2)] if pm.group(2) else [])
                    if stack:
                        stack[-1][1].extend(names)
                rm = PHOENIX_ROUTE_RE.match(line)
                if rm:
                    verb, sub, ctrl, action = rm.group(1).upper(), rm.group(2), rm.group(3), rm.group(4)
                    pref = ""
                    pipes: List[str] = []
                    for sp, pl in stack:
                        if sp:
                            pref = join_path(pref, sp)
                        pipes.extend(pl)
                    full_path = join_path(pref, sub)
                    ev = _auth_pipeline(pipes)
                    has_auth = bool(ev)
                    body = f"{ev + ' ' if ev else ''}{ctrl}.{action}()"
                    if verb in ("POST", "PUT", "PATCH", "DELETE") or EX_MUT_ACTION.match(action):
                        body = f"{body} save() delete() conn.params"
                    params = re.findall(r":(\w+)", full_path)
                    self.routes.append(Route(
                        file=sf.rel, line=sf.line_at(off), path=full_path, methods=[verb],
                        body=body, framework="phoenix", lang="elixir", has_auth=has_auth,
                        calls_llm=False, reads_body=verb in ("POST", "PUT", "PATCH"), params=params,
                    ))
            off += len(line)
