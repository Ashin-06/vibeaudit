"""Swift, iOS and Vapor checks (preview): Vapor routes (AUTH001-003), SQL interpolation (BE001),
shell command injection (BE002), TLS verification bypass (BE013), tokens in UserDefaults (FE005),
client-side LLM calls (FE002), and iOS Info.plist App Transport Security flags.
"""
from __future__ import annotations

import re
from typing import Callable, Dict, List, Tuple

from . import heuristics as H
from .files import Project, SourceFile
from .guard import GUARD, finditer
from .model import Finding, Route, join_path

Emit = Callable[[Finding], None]

SWIFT_TEST_RE = re.compile(r"(?:^|/)(?:Tests?|UITests)/|Tests?\.swift$", re.I)
_STR_OR_COMMENT = re.compile(r"""'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|(//[^\n]*|/\*[\s\S]*?\*/)""")

VAPOR_MARK = re.compile(r"\bimport\s+Vapor\b|\bRoutesBuilder\b|\bapp\s*\.\s*(?:get|post|put|patch|delete)\s*\(")
VAPOR_GROUP_RE = re.compile(r"\b(?:let|var)\s+(\w+)\s*=\s*(\w+)\s*\.\s*grouped\s*\(([^)\n]{0,200})\)")
VAPOR_MW_RE = re.compile(r"\b(\w+)\s*\.\s*middleware\s*\.\s*use\s*\(([^)\n]{0,200})\)")
VAPOR_ROUTE_RE = re.compile(r"\b(\w+)\s*\.\s*(get|post|put|patch|delete)\s*\(([^)\n]{0,240})\)")
SWIFT_AUTH_RE = re.compile(
    r"(?i)\b\w*(?:auth|authenticator|guard|session|jwt|bearer|protected|middleware|token|role|admin)\w*\b"
    r"|\breq\s*\.\s*auth\s*\.\s*(?:require|get|has)\b"
)
SWIFT_BODY_LLM = re.compile(r"(?i)\b(?:openai|anthropic|gemini|generativelanguage|ChatCompletion)\b")
SWIFT_BODY_READ = re.compile(r"\breq\s*\.\s*content\s*\.\s*decode\b")
SWIFT_STR_LIT = re.compile(r'"([^"\n]{0,120})"')

SWIFT_SQLI = re.compile(
    r"""(?:\.\s*raw|SQLQueryString|sqlite3_exec|sqlite3_prepare(?:_v2)?)\s*\([^"\n]{0,80}"[^"\n]{0,240}\\\("""
)
SWIFT_CMDI = re.compile(r"""arguments\s*=\s*\[\s*"-c"\s*,\s*"[^"\n]{0,200}\\\(""")
SWIFT_PROCESS_CTX = re.compile(r"\bProcess\s*\(\s*\)|/bin/(?:sh|bash)\b")
SWIFT_TLS = re.compile(
    r"\bURLCredential\s*\(\s*trust\s*:|\ballowsInvalidCertificates\s*=\s*true\b|\bDisabledTrustEvaluator\s*\(\s*\)"
)
USER_DEFAULTS_SECRET = re.compile(
    r"\bUserDefaults\s*\.\s*standard\s*\.\s*set\s*\([^)\n]{0,120}\bforKey\s*:\s*\""
    r"[^\"\n]{0,60}(?:token|jwt|auth|secret|password|passwd|api_?key|session|refresh|credential)"
    r"[^\"\n]{0,60}\"",
    re.I,
)
CLIENT_LLM = re.compile(
    r"https?://(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com)/",
    re.I,
)
IOS_ATS_ARBITRARY = re.compile(r"<key>\s*NSAllowsArbitraryLoads\s*</key>\s*<true\s*/>")


def _strip_comments(text: str) -> str:
    return _STR_OR_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(1)) if m.group(1) else m.group(0), text)


def _brace_block(code: str, start: int, limit: int = 4000) -> str:
    if start < 0 or start >= len(code) or code[start] != "{":
        return ""
    depth, i, end = 0, start, min(len(code), start + limit)
    while i < end:
        c = code[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return code[start:i + 1]
        i += 1
    return code[start:end]


def _func_body(code: str, name: str) -> str:
    if not name or not re.fullmatch(r"\w+", name):
        return ""
    m = re.search(r"\bfunc\s+" + re.escape(name) + r"\s*\([^)\n]{0,200}\)[^{\n]{0,120}\{", code)
    return _brace_block(code, m.end() - 1) if m else ""


def _custom_match(text: str) -> str:
    m = H.CUSTOM.auth_rx.search(text) if H.CUSTOM.auth_rx else None
    return m.group(0) if m else ""


def _auth_token(text: str) -> str:
    m = SWIFT_AUTH_RE.search(text)
    if m:
        return m.group(0)
    custom = _custom_match(text)
    return f"requireAuth({custom})" if custom else ""


def _vapor_path(args: str) -> str:
    head = args.split("use:", 1)[0]
    parts = [s.strip("/") for s in SWIFT_STR_LIT.findall(head) if s.strip("/")]
    return "/" + "/".join(parts) if parts else "/"


class SwiftScanner:
    """Checks for Swift iOS apps and Vapor backends (preview)."""

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
            if f.rel.lower().endswith(".swift") and f.text is not None
            and not f.is_test and not f.is_example and not f.is_vendored
            and not SWIFT_TEST_RE.search(f.rel)
        ]
        has_pkg = any(f.rel.rsplit("/", 1)[-1] == "Package.swift" for f in self.p.files)
        has_pubspec = any(f.rel.rsplit("/", 1)[-1] == "pubspec.yaml" for f in self.p.files)
        if not files and not has_pkg:
            return []
        for sf in files:
            GUARD.run(sf.rel, "Swift checks", self._file, sf)
        if not has_pubspec:  # DartScanner already checks Info.plist when pubspec.yaml exists
            for sf in self.p.files:
                if sf.text is None or sf.is_test or sf.is_example:
                    continue
                if sf.rel.rsplit("/", 1)[-1] == "Info.plist":
                    GUARD.run(sf.rel, "iOS plist checks", self._ios_plist, sf)
        return self.routes

    def _file(self, sf: SourceFile) -> None:
        code = _strip_comments(sf.text or "")
        is_vapor = bool(VAPOR_MARK.search(code))
        if is_vapor:
            self._vapor_routes(sf, code)
        for m in finditer(SWIFT_SQLI, code):
            self.add(sf, m.start(), "BE001",
                     "Raw SQL query interpolates a Swift expression (`\\(...)`); bind parameters safely.", "high")
        for m in finditer(SWIFT_CMDI, code):
            window = code[max(0, m.start() - 350):m.end() + 100]
            if SWIFT_PROCESS_CTX.search(window):
                self.add(sf, m.start(), "BE002",
                         "Shell command constructed with Swift string interpolation (`\\(...)`).", "high")
        for m in finditer(SWIFT_TLS, code):
            self.add(sf, m.start(), "BE013",
                     "TLS certificate trust validation is bypassed (accepts untrusted certificates).", "high")
        for m in finditer(USER_DEFAULTS_SECRET, code):
            self.add(sf, m.start(), "FE005",
                     "Sensitive token or credential stored in UserDefaults (unencrypted); use the iOS Keychain.", "medium")
        if not is_vapor:
            for m in finditer(CLIENT_LLM, code):
                self.add(sf, m.start(), "FE002",
                         "Client Swift app calls an LLM provider API directly; proxy requests through a backend so API keys stay on the server.",
                         "high")

    def _vapor_routes(self, sf: SourceFile, code: str) -> None:
        groups: Dict[str, Tuple[str, str]] = {}  # var -> (prefix, auth_evidence)
        for m in finditer(VAPOR_GROUP_RE, code):
            var, parent, args = m.group(1), m.group(2), m.group(3)
            parent_pref, parent_auth = groups.get(parent, ("", ""))
            sub = "/".join(s.strip("/") for s in SWIFT_STR_LIT.findall(args) if s.strip("/"))
            pref = join_path(parent_pref, sub) if sub else parent_pref
            ev = _auth_token(args) or parent_auth
            groups[var] = (pref, ev)
        for m in finditer(VAPOR_MW_RE, code):
            var, args = m.group(1), m.group(2)
            ev = _auth_token(args)
            if ev:
                pref, prev = groups.get(var, ("", ""))
                groups[var] = (pref, prev or ev)

        for m in finditer(VAPOR_ROUTE_RE, code):
            var, verb, args = m.group(1), m.group(2).upper(), m.group(3)
            pref, grp_auth = groups.get(var, ("", ""))
            path = join_path(pref, _vapor_path(args))
            line_end = code.find("\n", m.start())
            end_pos = line_end if line_end >= 0 else len(code)
            route_line = code[m.start():end_pos]
            brace = code.find("{", m.end() - 1, min(len(code), end_pos + 80))
            handler_name = ""
            use_m = re.search(r"\buse\s*:\s*(?:self\s*\.)?(\w+)", args)
            if use_m:
                handler_name = use_m.group(1)
            body = _brace_block(code, brace) if brace >= 0 else _func_body(code, handler_name)
            if not body:
                body = route_line
            ev = grp_auth or _auth_token(body)
            has_auth = bool(ev)
            if ev:
                body = f"{ev} {body}"
            params = re.findall(r":(\w+)", path)
            self.routes.append(Route(
                file=sf.rel, line=sf.line_at(m.start()), path=path, methods=[verb],
                body=body, framework="vapor", lang="swift", has_auth=has_auth,
                calls_llm=bool(SWIFT_BODY_LLM.search(body)),
                reads_body=bool(SWIFT_BODY_READ.search(body)), params=params,
            ))

    def _ios_plist(self, sf: SourceFile) -> None:
        text = sf.text or ""
        for m in finditer(IOS_ATS_ARBITRARY, text):
            self.add(sf, m.start(), "BE013",
                     "Info.plist sets NSAllowsArbitraryLoads=true, disabling iOS App Transport Security (TLS) globally.",
                     "high")
