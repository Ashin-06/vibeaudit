"""Formal machine-readable scan coverage reporting across language, domain, and history analyzers."""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from .files import Project, SourceFile

LANG_EXTS: Dict[str, Tuple[str, ...]] = {
    "python": (".py",),
    "javascript": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".html", ".htm"),
    "go": (".go",),
    "jvm": (".java", ".kt", ".kts"),
    "csharp": (".cs", ".cshtml", ".razor"),
    "rust": (".rs",),
    "php": (".php", ".phtml"),
    "ruby": (".rb", ".erb"),
    "swift": (".swift",),
    "elixir": (".ex", ".exs", ".heex"),
    "dart": (".dart",),
}

GUARD_LANG_MAP = {
    "Python analysis": "python",
    "Python taint": "python",
    "JavaScript lexing": "javascript",
    "function index": "javascript",
    "data flow": "javascript",
    "JavaScript checks": "javascript",
    "Go analysis": "go",
    "JVM analysis": "jvm",
    "C# analysis": "csharp",
    "Rust analysis": "rust",
    "PHP analysis": "php",
    "Ruby analysis": "ruby",
    "Swift analysis": "swift",
    "Elixir analysis": "elixir",
    "Dart analysis": "dart",
    "secret scan": "secrets",
    "git history secrets": "git_history",
    "dependency checks": "deps",
}


def _ext(rel: str) -> str:
    return os.path.splitext(rel.lower())[1]


def _parser_for(bucket: str, parser_mode: Dict[str, str]) -> str:
    if bucket == "python":
        return "ast"
    if bucket == "go":
        return parser_mode.get("go", "regex")
    if bucket == "jvm":
        return parser_mode.get("java", "regex")
    if bucket == "rust":
        return parser_mode.get("rust", "regex")
    if bucket == "javascript":
        js_modes = {parser_mode.get(k, "regex") for k in ("js", "ts", "tsx")}
        return "lexer+tree-sitter" if "tree-sitter" in js_modes else "lexer"
    if bucket in ("csharp", "php", "ruby", "swift", "elixir", "dart"):
        return "lexer"
    if bucket == "git_history":
        return "git-log-stream"
    return "rules"


def _bucket_matches(sf: SourceFile, exts: Tuple[str, ...]) -> bool:
    return _ext(sf.rel) in exts


def _parse_guard(entry: Any) -> Tuple[str, str]:
    if isinstance(entry, dict):
        return str(entry.get("file", "")), str(entry.get("step", ""))
    text = str(entry)
    rel, sep, rest = text.partition(": ")
    if not sep:
        return "", text
    for step_name in GUARD_LANG_MAP:
        if rest.startswith(step_name):
            return rel, step_name
    return rel, rest.split(":", 1)[0].strip()


def build(
    project: Project,
    opts: Any,
    guard_skipped: list,
    guard_errors: list,
    parser_mode: Dict[str, str],
    history_info: Optional[Dict[str, Any]],
    scan_timed_out: bool = False,
) -> Dict[str, Any]:
    """Summarize exact analyzer coverage, skipped inputs, errors, and incomplete reasons."""
    skipped_size = [sf.rel for sf in project.files if sf.skip_reason == "size_limit"]
    skipped_read = [sf.rel for sf in project.files if sf.skip_reason == "read_error"]
    skipped_binary = [sf.rel for sf in project.files if sf.skip_reason == "binary"]
    skipped_symlink = [item["file"] for item in getattr(project, "skipped_files", []) if item.get("reason") == "symlink_escape"]

    guard_skip_by_bucket: Dict[str, List[str]] = {}
    for entry in guard_skipped:
        rel, step = _parse_guard(entry)
        b = GUARD_LANG_MAP.get(step, "other")
        guard_skip_by_bucket.setdefault(b, []).append(rel)

    guard_err_by_bucket: Dict[str, List[str]] = {}
    for entry in guard_errors:
        rel, step = _parse_guard(entry)
        b = GUARD_LANG_MAP.get(step, "other")
        guard_err_by_bucket.setdefault(b, []).append(rel)

    scanners: Dict[str, Dict[str, Any]] = {}
    for bucket, exts in LANG_EXTS.items():
        matched = [sf for sf in project.files if _bucket_matches(sf, exts)]
        analyzed = [sf for sf in matched if sf.text is not None]
        g_skips = sorted(set(guard_skip_by_bucket.get(bucket, [])))
        g_errs = sorted(set(guard_err_by_bucket.get(bucket, [])))
        size_or_io_skips = [sf.rel for sf in matched if sf.skip_reason in ("size_limit", "read_error")]
        if not matched:
            status = "not_applicable"
        elif g_errs and not analyzed:
            status = "failed"
        elif size_or_io_skips or g_skips or g_errs:
            status = "partial"
        else:
            status = "complete"
        scanners[bucket] = {
            "status": status,
            "parser": _parser_for(bucket, parser_mode),
            "files_matched": len(matched),
            "files_analyzed": max(0, len(analyzed) - len(g_skips)),
            "skipped_files": sorted(set(size_or_io_skips + g_skips)),
            "errors": g_errs,
        }

    sec_skips = sorted(set(guard_skip_by_bucket.get("secrets", [])))
    sec_errs = sorted(set(guard_err_by_bucket.get("secrets", [])))
    sec_io = [sf.rel for sf in project.files if sf.skip_reason in ("size_limit", "read_error")]
    scanners["secrets"] = {
        "status": "partial" if (sec_skips or sec_errs or sec_io) else ("complete" if project.files else "not_applicable"),
        "parser": "rules",
        "files_matched": len(project.files),
        "files_analyzed": max(0, len(project.files) - len(sec_io) - len(sec_skips) - len(skipped_binary)),
        "skipped_files": sorted(set(sec_io + sec_skips)),
        "errors": sec_errs,
    }

    if history_info is None:
        scanners["git_history"] = {"status": "not_applicable", "parser": "git-log-stream", "commits_scanned": 0}
    else:
        hst = str(history_info.get("status", "complete"))
        if hst in ("truncated_commits", "truncated_size", "timeout"):
            mapped = "partial"
        elif hst == "git_error":
            mapped = "failed"
        elif hst == "not_git":
            mapped = "skipped"
        else:
            mapped = "complete"
        scanners["git_history"] = {
            "status": mapped,
            "detail": hst,
            "parser": "git-log-stream",
            "commits_scanned": history_info.get("commits_scanned", 0),
            "bytes_scanned": history_info.get("bytes_scanned", 0),
        }

    incomplete_reasons: List[str] = []
    if skipped_size:
        incomplete_reasons.append(f"{len(skipped_size)} files skipped (size > {opts.max_file_bytes} bytes)")
    if skipped_read:
        incomplete_reasons.append(f"{len(skipped_read)} files unreadable (OS I/O error)")
    if guard_skipped:
        incomplete_reasons.append(f"{len(guard_skipped)} analyzer steps skipped (timeout or recursion guard)")
    if guard_errors:
        incomplete_reasons.append(f"{len(guard_errors)} internal analyzer errors")
    if history_info and scanners["git_history"]["status"] in ("partial", "failed"):
        incomplete_reasons.append(f"git history scan {history_info.get('status')}")
    if scan_timed_out:
        incomplete_reasons.append(f"scan_timeout ({opts.scan_timeout}s limit reached; remaining stages skipped)")

    return {
        "overall_status": "partial" if incomplete_reasons else "complete",
        "config_mode": "ignored (--no-config)" if getattr(opts, "no_config", False) else "project",
        "files_discovered": len(project.files),
        "files_analyzed": len(project.files) - len(skipped_size) - len(skipped_read),
        "files_skipped_size": len(skipped_size),
        "files_skipped_timeout": len(guard_skipped),
        "files_skipped_symlink": len(skipped_symlink),
        "files_read_error": len(skipped_read),
        "internal_errors": len(guard_errors),
        "scan_timed_out": scan_timed_out,
        "incomplete_reasons": incomplete_reasons,
        "scanners": scanners,
    }
