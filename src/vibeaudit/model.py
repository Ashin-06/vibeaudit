"""Core data types shared by every scanner."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import List, Optional

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # lower is worse


def worse(a: str, b: str) -> str:
    return a if SEVERITY_RANK[a] <= SEVERITY_RANK[b] else b


def at_least(sev: str, threshold: str) -> bool:
    """True when `sev` is as bad as or worse than `threshold`."""
    return SEVERITY_RANK[sev] <= SEVERITY_RANK[threshold]


@dataclass
class Finding:
    rule_id: str
    file: str  # posix path relative to the scan root
    line: int  # 1-based; 0 when the finding is about the file as a whole
    message: str
    severity: str = ""  # empty means "use the rule default"
    snippet: str = ""
    source: str = "vibeaudit"  # or the external tool that produced it
    # filled in by the scanner from the rule catalog
    title: str = ""
    category: str = ""
    why: str = ""
    fix: str = ""
    cwe: str = ""
    owasp: str = ""
    fingerprint: str = ""
    preview: bool = False  # from a preview rule: reported, but not counted in --fail-on or the score by default
    llm_verdict: Optional[str] = None
    llm_reason: Optional[str] = None

    def compute_fingerprint(self) -> str:
        # Line numbers move when code is edited, so the fingerprint uses the
        # normalized line text instead. That keeps baselines stable.
        text = re.sub(r"\s+", " ", self.snippet).strip()
        raw = "|".join([self.rule_id, self.file, text or str(self.line), self.message if not text else ""])
        self.fingerprint = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:32]
        return self.fingerprint

    def to_dict(self) -> dict:
        d = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "snippet": self.snippet,
            "why": self.why,
            "fix": self.fix,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "source": self.source,
            "fingerprint": self.fingerprint,
        }
        if self.preview:
            d["preview"] = True
        if self.llm_verdict:
            d["llm_verdict"] = self.llm_verdict
            d["llm_reason"] = self.llm_reason or ""
        return d


@dataclass
class Route:
    """An HTTP entry point found in the code, used by the auth and rate-limit checks."""

    file: str
    line: int
    path: str
    methods: List[str]
    body: str  # source text of the handler (plus decorators / middleware args)
    framework: str
    lang: str  # "py" or "js"
    has_auth: bool = False
    calls_llm: bool = False
    reads_body: bool = False
    params: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        from .heuristics import MUTATION_EVIDENCE

        return {
            "methods": self.methods, "path": self.path, "file": self.file, "line": self.line,
            "framework": self.framework, "authenticated": self.has_auth, "calls_llm": self.calls_llm,
            "writes_data": bool(MUTATION_EVIDENCE.search(self.body)), "reads_body": self.reads_body,
        }

    @property
    def mutating(self) -> bool:
        return any(m in ("POST", "PUT", "PATCH", "DELETE", "ALL") for m in self.methods)
