"""Persistent content-hash scan cache and per-file secret scan cache."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__, feed, store
from .files import Project, SourceFile
from .model import Finding, Route

CACHE_FORMAT = 1
MAX_SECRET_CACHE_ENTRIES = 10_000
MAX_SNAPSHOT_FINDINGS = 50_000


def _finding_to_cache(f: Finding) -> Dict[str, Any]:
    return {
        "rule_id": f.rule_id, "file": f.file, "line": f.line, "message": f.message,
        "severity": f.severity, "snippet": f.snippet, "source": f.source,
        "title": f.title, "category": f.category, "why": f.why, "fix": f.fix,
        "cwe": f.cwe, "owasp": f.owasp, "fingerprint": f.fingerprint,
        "preview": f.preview, "gates_in_preview": f.gates_in_preview,
        "llm_verdict": f.llm_verdict, "llm_reason": f.llm_reason, "confirmed": f.confirmed,
    }


def _finding_from_cache(d: Dict[str, Any]) -> Finding:
    return Finding(
        rule_id=str(d["rule_id"]), file=str(d["file"]), line=int(d["line"]),
        message=str(d["message"]), severity=str(d.get("severity", "")),
        snippet=str(d.get("snippet", "")), source=str(d.get("source", "vibeaudit")),
        title=str(d.get("title", "")), category=str(d.get("category", "")),
        why=str(d.get("why", "")), fix=str(d.get("fix", "")),
        cwe=str(d.get("cwe", "")), owasp=str(d.get("owasp", "")),
        fingerprint=str(d.get("fingerprint", "")),
        preview=bool(d.get("preview", False)),
        gates_in_preview=bool(d.get("gates_in_preview", False)),
        llm_verdict=d.get("llm_verdict"), llm_reason=d.get("llm_reason"),
        confirmed=d.get("confirmed"),
    )


def _route_to_cache(r: Route) -> Dict[str, Any]:
    return {
        "file": r.file, "line": r.line, "path": r.path, "methods": list(r.methods),
        "body": r.body, "framework": r.framework, "lang": r.lang,
        "has_auth": r.has_auth, "calls_llm": r.calls_llm, "reads_body": r.reads_body,
        "params": list(r.params),
    }


def _route_from_cache(d: Dict[str, Any]) -> Route:
    return Route(
        file=str(d["file"]), line=int(d["line"]), path=str(d["path"]),
        methods=[str(m) for m in d.get("methods", ())],
        body=str(d.get("body", "")), framework=str(d.get("framework", "")),
        lang=str(d.get("lang", "")), has_auth=bool(d.get("has_auth", False)),
        calls_llm=bool(d.get("calls_llm", False)), reads_body=bool(d.get("reads_body", False)),
        params=[str(p) for p in d.get("params", ())],
    )


def _digest_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def project_fingerprint(project: Project, opts: Any, parser_mode: Dict[str, str]) -> str:
    """Deterministic SHA-256 fingerprint over options, parser mode, threat feed, and all scanned files."""
    h = hashlib.sha256()
    cached_feed = feed.cached()
    feed_ver = str(cached_feed.get("version")) if cached_feed else "shipped"
    header = "|".join([
        str(CACHE_FORMAT),
        __version__,
        repr(sorted(parser_mode.items())),
        str(opts.max_file_bytes),
        str(opts.file_timeout),
        repr(list(opts.auth_helpers)),
        repr(list(opts.sanitizers)),
        repr(list(opts.public_paths)),
        repr(sorted(opts.excludes)),
        feed_ver,
        repr(sorted(
            (str(item.get("file", "")), str(item.get("reason", "")))
            for item in getattr(project, "skipped_files", ())
        )),
    ])
    h.update(header.encode("utf-8", "replace"))
    for sf in sorted(project.files, key=lambda s: s.rel):
        content = sf.raw_text if sf.raw_text is not None else (sf.text or "")
        text_hash = _digest_hex(content)
        rec = (
            f"\n{sf.rel}\0{sf.skip_reason or ''}\0{len(content)}\0"
            f"{int(sf.is_test)}\0{int(sf.is_example)}\0{int(sf.secrets_only)}\0{int(sf.is_vendored)}\0{text_hash}"
        )
        h.update(rec.encode("utf-8", "replace"))
    return h.hexdigest()


def _snapshot_path(root: Path) -> Path:
    try:
        key = _digest_hex(str(root.resolve()))[:24]
    except OSError:
        key = _digest_hex(str(root))[:24]
    return store.cache_dir() / "scans" / f"{key}.json"


def load_snapshot(root: Path, fingerprint: str) -> Optional[Tuple[List[Finding], List[Route]]]:
    """Load cached built-in findings and routes for `root` if `fingerprint` matches."""
    if not store.ENABLED:
        return None
    doc = store.read_json(_snapshot_path(root))
    if not isinstance(doc, dict) or doc.get("format") != CACHE_FORMAT or doc.get("fingerprint") != fingerprint:
        return None
    raw_findings = doc.get("findings")
    raw_routes = doc.get("routes")
    if not isinstance(raw_findings, list) or not isinstance(raw_routes, list):
        return None
    try:
        findings = [_finding_from_cache(item) for item in raw_findings]
        routes = [_route_from_cache(item) for item in raw_routes]
    except (KeyError, TypeError, ValueError):
        return None
    return findings, routes


def save_snapshot(root: Path, fingerprint: str, findings: List[Finding], routes: List[Route]) -> None:
    """Persist built-in findings and routes for `root` atomically."""
    if not store.ENABLED or len(findings) > MAX_SNAPSHOT_FINDINGS:
        return
    doc = {
        "format": CACHE_FORMAT,
        "version": __version__,
        "fingerprint": fingerprint,
        "findings": [_finding_to_cache(f) for f in findings],
        "routes": [_route_to_cache(r) for r in routes],
    }
    store.write_json(_snapshot_path(root), doc)


def _secret_cache_path() -> Path:
    return store.cache_dir() / "scans" / "secret_files.json"


def secret_file_key(sf: SourceFile, text: str, bundle: bool, bare_public: bool) -> str:
    content_hash = _digest_hex(text)
    raw = (
        f"{CACHE_FORMAT}|{__version__}|{sf.rel}|{sf.kind}|"
        f"{int(sf.is_test)}|{int(sf.is_example)}|{int(sf.is_one_off)}|"
        f"{int(bundle)}|{int(bare_public)}|{content_hash}"
    )
    return _digest_hex(raw)[:32]


def load_secret_cache() -> Dict[str, List[Dict[str, Any]]]:
    if not store.ENABLED:
        return {}
    doc = store.read_json(_secret_cache_path())
    if not isinstance(doc, dict) or doc.get("format") != CACHE_FORMAT or not isinstance(doc.get("entries"), dict):
        return {}
    out: Dict[str, List[Dict[str, Any]]] = {}
    for k, v in doc["entries"].items():
        if isinstance(k, str) and isinstance(v, list):
            out[k] = [item for item in v if isinstance(item, dict)]
    return out


def save_secret_cache(entries: Dict[str, List[Dict[str, Any]]]) -> None:
    if not store.ENABLED:
        return
    if len(entries) > MAX_SECRET_CACHE_ENTRIES:
        keys = list(entries.keys())[-MAX_SECRET_CACHE_ENTRIES:]
        entries = {k: entries[k] for k in keys}
    store.write_json(_secret_cache_path(), {"format": CACHE_FORMAT, "entries": entries})
