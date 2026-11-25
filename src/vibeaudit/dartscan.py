"""Flutter and Dart checks (preview): TLS bypass (BE013), raw SQLite interpolation (BE001),
secrets/tokens stored in SharedPreferences (FE004), unsafe WebView JavaScript execution (FE001),
client-side LLM calls (FE002), outbound HTTP calls without a timeout (REL001), and Android/iOS manifest TLS/debug flags.
"""
from __future__ import annotations

import re
from typing import Callable, List

from .files import Project, SourceFile
from .guard import GUARD, finditer
from .model import Finding

Emit = Callable[[Finding], None]

DART_TEST_RE = re.compile(r"(?:^|/)(?:test|integration_test)/|_test\.dart$", re.I)

# Comments stripped outside string literals (offset-preserving) so URLs like https://... stay intact
_STR_OR_COMMENT = re.compile(r"""'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|(//[^\n]*|/\*[\s\S]*?\*/)""")

BAD_CERT = re.compile(
    r"\bbadCertificateCallback\s*=\s*\([^)]{0,120}\)\s*(?:=>\s*true\b|\{\s*return\s+true\s*;)")
RAW_SQL = re.compile(
    r"""\.\s*(?:rawQuery|rawInsert|rawUpdate|rawDelete|execute)\s*\(\s*(?:"[^"\n]{0,240}(?:\$[A-Za-z_]\w*|\$\{)|'[^'\n]{0,240}(?:\$[A-Za-z_]\w*|\$\{))""")
SHARED_PREFS_SECRET = re.compile(
    r"\b(?:prefs|sharedPreferences|sharedPrefs|preferences|sp)\s*\.\s*setString\s*\(\s*['\"]"
    r"[^'\"\n]{0,60}(?:token|jwt|auth|secret|password|passwd|api_?key|session|refresh|credential)"
    r"[^'\"\n]{0,60}['\"]", re.I)
WEBVIEW_JS = re.compile(
    r"""\.\s*(?:runJavaScript(?:ReturningResult)?|evaluateJavascript)\s*\(\s*(?:"[^"\n]{0,200}(?:\$[A-Za-z_]\w*|\$\{)|'[^'\n]{0,200}(?:\$[A-Za-z_]\w*|\$\{)|[a-z_]\w*\s*\+)""")
WEBVIEW_UNRESTRICTED = re.compile(r"\bJavaScriptMode\s*\.\s*unrestricted\b")
WEBVIEW_URL = re.compile(r"\b(?:loadRequest|initialUrl|Uri\.parse)\b")
CLIENT_LLM = re.compile(
    r"https?://(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com)/", re.I)
HTTP_CALL = re.compile(
    r"\bhttp\s*\.\s*(?:get|post|put|patch|delete|head)\s*\(")
HAS_TIMEOUT = re.compile(r"\.\s*timeout\s*\(|connectTimeout|receiveTimeout|sendTimeout")
ANDROID_CLEARTEXT = re.compile(r"""android:usesCleartextTraffic\s*=\s*["']true["']""")
ANDROID_DEBUGGABLE = re.compile(r"""android:debuggable\s*=\s*["']true["']""")
IOS_ATS_ARBITRARY = re.compile(r"<key>\s*NSAllowsArbitraryLoads\s*</key>\s*<true\s*/>")


def _strip_comments(text: str) -> str:
    return _STR_OR_COMMENT.sub(
        lambda m: re.sub(r"[^\n]", " ", m.group(1)) if m.group(1) else m.group(0), text)


class DartScanner:
    def __init__(self, project: Project, emit: Emit):
        self.p = project
        self.emit = emit

    def add(self, sf: SourceFile, off: int, rule: str, msg: str, sev: str = "") -> None:
        line = sf.line_at(off)
        self.emit(Finding(rule, sf.rel, line, msg, sev, sf.line(line).strip()[:200]))

    def run(self) -> List:
        files = [f for f in self.p.files if f.rel.endswith(".dart") and f.text is not None
                 and not f.is_test and not f.is_example and not DART_TEST_RE.search(f.rel)]
        has_pubspec = any(f.rel.rsplit("/", 1)[-1] == "pubspec.yaml" for f in self.p.files)
        if not files and not has_pubspec:
            return []
        for sf in files:
            GUARD.run(sf.rel, "Dart checks", self._file, sf)
        if has_pubspec or files:
            for sf in self.p.files:
                if sf.text is None or sf.is_test or sf.is_example:
                    continue
                name = sf.rel.rsplit("/", 1)[-1]
                if name == "AndroidManifest.xml" and not re.search(r"/(?:debug|profile)/", "/" + sf.rel):
                    GUARD.run(sf.rel, "Android manifest checks", self._android_manifest, sf)
                elif name == "Info.plist":
                    GUARD.run(sf.rel, "iOS plist checks", self._ios_plist, sf)
        return []

    def _file(self, sf: SourceFile) -> None:
        code = _strip_comments(sf.text or "")
        for m in finditer(BAD_CERT, code):
            self.add(sf, m.start(), "BE013",
                     "badCertificateCallback unconditionally returns true, disabling TLS certificate verification.", "high")
        for m in finditer(RAW_SQL, code):
            self.add(sf, m.start(), "BE001",
                     "SQLite raw query interpolates a Dart expression; pass values in the arguments list (`?`).", "high")
        for m in finditer(SHARED_PREFS_SECRET, code):
            self.add(sf, m.start(), "FE004",
                     "Sensitive token or credential stored in SharedPreferences (unencrypted); use flutter_secure_storage.", "medium")
        for m in finditer(WEBVIEW_JS, code):
            self.add(sf, m.start(), "FE001",
                     "WebView executes dynamically interpolated JavaScript (XSS / script injection).", "high")
        if WEBVIEW_URL.search(code):
            for m in finditer(WEBVIEW_UNRESTRICTED, code):
                self.add(sf, m.start(), "FE001",
                         "WebView sets JavaScriptMode.unrestricted; restrict JavaScript or validate loaded URLs against an allow-list.", "medium")
        for m in finditer(CLIENT_LLM, code):
            self.add(sf, m.start(), "FE002",
                     "Flutter client calls an LLM provider API directly; proxy requests through a backend so API keys are not shipped in the app binary.", "high")
        for m in finditer(HTTP_CALL, code):
            window = code[m.start():m.start() + 300]
            if not HAS_TIMEOUT.search(window):
                self.add(sf, m.start(), "REL001",
                         "Outbound HTTP request has no .timeout() call and can hang indefinitely.", "medium")

    def _android_manifest(self, sf: SourceFile) -> None:
        text = sf.text or ""
        for m in finditer(ANDROID_CLEARTEXT, text):
            self.add(sf, m.start(), "BE013",
                     "AndroidManifest.xml enables android:usesCleartextTraffic=\"true\", allowing unencrypted HTTP traffic.", "high")
        for m in finditer(ANDROID_DEBUGGABLE, text):
            self.add(sf, m.start(), "BE011",
                     "AndroidManifest.xml sets android:debuggable=\"true\" in a non-debug manifest.", "high")

    def _ios_plist(self, sf: SourceFile) -> None:
        text = sf.text or ""
        for m in finditer(IOS_ATS_ARBITRARY, text):
            self.add(sf, m.start(), "BE013",
                     "Info.plist sets NSAllowsArbitraryLoads=true, disabling iOS App Transport Security (TLS) globally.", "high")
