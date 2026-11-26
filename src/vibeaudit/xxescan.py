"""Multi-language XML external entity (XXE) checks (BE021, preview): Python, Java/Kotlin, C#, PHP and JS/TS."""
from __future__ import annotations

import re
from typing import Callable

from .files import Project, SourceFile
from .guard import GUARD, finditer
from .lexer import js_views, py_views
from .model import Finding

Emit = Callable[[Finding], None]

XXE_TEST_RE = re.compile(r"(?:Test|Tests|Spec)\.(?:java|kt|cs|php)$|(^|/)(?:src/test|tests?)/", re.I)
_C_STR_OR_COMMENT = re.compile(r"""'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|(//[^\n]*|/\*[\s\S]*?\*/)""")
_PHP_STR_OR_COMMENT = re.compile(r"""'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|((?://|#)[^\n]*|/\*[\s\S]*?\*/)""")

PY_LXML_XXE = re.compile(r"\bXMLParser\s*\([^)]{0,300}\bresolve_entities\s*=\s*True\b")
PY_SAX_XXE = re.compile(r"\bfeature_external_[gp]es\b[^\n]{0,80}\bTrue\b")

JVM_XML_FACTORY = re.compile(
    r"\b(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)\s*\.\s*(?:newInstance|newFactory)\s*\("
)
JVM_XXE_SAFE = re.compile(
    r"disallow-doctype-decl|FEATURE_SECURE_PROCESSING|ACCESS_EXTERNAL_DTD|"
    r"IS_SUPPORTING_EXTERNAL_ENTITIES|SUPPORT_DTD|external-general-entities|"
    r"LOAD_EXTERNAL_DTD|setExpandEntityReferences\s*\(\s*false\s*\)"
)

CS_DTD_PARSE = re.compile(r"\bDtdProcessing\s*\.\s*Parse\b")
CS_XML_RESOLVER = re.compile(r"\bXmlResolver\s*=\s*new\s+XmlUrlResolver\s*\(")

PHP_ENTITY_LOADER = re.compile(r"\blibxml_disable_entity_loader\s*\(\s*false\s*\)")
PHP_LIBXML_NOENT = re.compile(r"\bLIBXML_NOENT\b")

JS_LIBXML = re.compile(r"\blibxmljs2?\b")
JS_NOENT = re.compile(r"\bnoent\s*:\s*true\b")


def _strip_comments(text: str, rx: re.Pattern) -> str:
    return rx.sub(lambda m: re.sub(r"[^\n]", " ", m.group(1)) if m.group(1) else m.group(0), text)


class XxeScanner:
    """Checks for unsafe XML parser configurations enabling DTD / external entities (BE021)."""

    def __init__(self, project: Project, emit: Emit):
        self.p = project
        self.emit = emit

    def add(self, sf: SourceFile, off: int, msg: str) -> None:
        line = sf.line_at(off)
        self.emit(Finding("BE021", sf.rel, line, msg, "high", sf.line(line).strip()[:200]))

    def run(self) -> None:
        for sf in self.p.files:
            if sf.text is None or sf.is_test or sf.is_example or sf.is_vendored or XXE_TEST_RE.search(sf.rel):
                continue
            low = sf.rel.lower()
            if sf.kind == "py":
                GUARD.run(sf.rel, "XXE checks (Python)", self._py, sf)
            elif low.endswith((".java", ".kt", ".kts")):
                GUARD.run(sf.rel, "XXE checks (JVM)", self._jvm, sf)
            elif low.endswith(".cs"):
                GUARD.run(sf.rel, "XXE checks (C#)", self._cs, sf)
            elif low.endswith(".php"):
                GUARD.run(sf.rel, "XXE checks (PHP)", self._php, sf)
            elif sf.kind == "js":
                GUARD.run(sf.rel, "XXE checks (JS)", self._js, sf)

    def _py(self, sf: SourceFile) -> None:
        text = sf.text or ""
        if "resolve_entities" not in text and "feature_external_" not in text:
            return
        code = py_views(text).code
        for m in finditer(PY_LXML_XXE, code):
            self.add(sf, m.start(), "lxml XMLParser enables resolve_entities=True, allowing XXE.")
        for m in finditer(PY_SAX_XXE, code):
            self.add(sf, m.start(), "xml.sax parser enables external entity processing (XXE).")

    def _jvm(self, sf: SourceFile) -> None:
        text = sf.text or ""
        if "Factory" not in text:
            return
        code = _strip_comments(text, _C_STR_OR_COMMENT)
        for m in finditer(JVM_XML_FACTORY, code):
            window = code[max(0, m.start() - 200):m.start() + 1400]
            if not JVM_XXE_SAFE.search(window):
                self.add(sf, m.start(), f"{m.group(1)} created without disallowing DOCTYPE/external entities (XXE).")

    def _cs(self, sf: SourceFile) -> None:
        text = sf.text or ""
        if "DtdProcessing" not in text and "XmlUrlResolver" not in text:
            return
        code = _strip_comments(text, _C_STR_OR_COMMENT)
        for m in finditer(CS_DTD_PARSE, code):
            self.add(sf, m.start(), "XmlReaderSettings sets DtdProcessing.Parse, enabling DTD/XXE processing.")
        for m in finditer(CS_XML_RESOLVER, code):
            self.add(sf, m.start(), "XmlResolver set to new XmlUrlResolver(), allowing external XML entity fetches.")

    def _php(self, sf: SourceFile) -> None:
        text = sf.text or ""
        if "LIBXML_NOENT" not in text and "libxml_disable_entity_loader" not in text:
            return
        code = _strip_comments(text, _PHP_STR_OR_COMMENT)
        for m in finditer(PHP_ENTITY_LOADER, code):
            self.add(sf, m.start(), "libxml_disable_entity_loader(false) enables external entity loading (XXE).")
        for m in finditer(PHP_LIBXML_NOENT, code):
            self.add(sf, m.start(), "LIBXML_NOENT substitutes external entities during XML parsing (XXE).")

    def _js(self, sf: SourceFile) -> None:
        text = sf.text or ""
        if "libxmljs" not in text or "noent" not in text:
            return
        code = js_views(text).code
        if not JS_LIBXML.search(code):
            return
        for m in finditer(JS_NOENT, code):
            self.add(sf, m.start(), "libxmljs parsed XML with noent: true, expanding external entities (XXE).")
