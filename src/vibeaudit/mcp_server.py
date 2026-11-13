"""`vibeaudit mcp`: a Model Context Protocol server over stdio, so coding agents can audit their own work.

Transport: newline-delimited JSON-RPC 2.0 on stdin/stdout (the MCP stdio transport). Logs go to stderr.
Tools: scan_project, scan_file, audit_current_file, list_routes, check_package, verify_package,
simulate_migration, explain_rule, auto_repair. All are read-only: auto_repair returns a diff and never writes
a file, and audit_current_file scans unsaved content in memory.
"""
from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path
from typing import IO, Any, Callable, Dict, List, Optional

from . import __version__
from .store import loads_json

SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
MAX_FINDINGS = 200

TOOLS = [
    {
        "name": "scan_project",
        "description": ("Audit a project directory for security, AI and quality issues typical of AI-generated code "
                        "(secrets, missing auth, injection, unsafe model output, hallucinated packages, ...). Returns "
                        "findings with file, line, severity, why it matters and how to fix it."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Project directory (absolute, or relative to the server's working directory)."},
                "min_severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"], "default": "low"},
                "offline": {"type": "boolean", "default": True, "description": "Skip package registry and vulnerability lookups."},
                "changes": {"type": "string", "description": "Only report changed lines: 'staged', or a git revision such as 'origin/main'."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "scan_file",
        "description": "Audit one file in the context of its project (auth middleware and helpers elsewhere still count).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "The file to report on."},
                "project": {"type": "string", "description": "Project root; defaults to the git repository containing the file."},
            },
            "required": ["file"],
        },
    },
    {
        "name": "list_routes",
        "description": "List every HTTP entry point with method, path, location and whether it has a visible auth check, writes data or calls a paid AI API.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
    },
    {
        "name": "check_package",
        "description": ("Before adding a dependency: check that it exists on PyPI or npm, is not brand new, is not one "
                        "keystroke away from a popular package, and (with a version) has no known vulnerabilities."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "ecosystem": {"type": "string", "enum": ["PyPI", "npm"]},
                "version": {"type": "string", "description": "Exact version to check against OSV (optional)."},
            },
            "required": ["name", "ecosystem"],
        },
    },
    {
        "name": "explain_rule",
        "description": "Explain a vibeaudit rule id (for example AUTH001): what it means, why it matters and how to fix it.",
        "inputSchema": {"type": "object", "properties": {"rule_id": {"type": "string"}}, "required": ["rule_id"]},
    },
    {
        "name": "auto_repair",
        "description": ("Propose deterministic fixes as a unified diff for findings that have one obvious repair "
                        "(request timeouts, output token limits, guarded JSON parsing of model output, pinned JWT "
                        "algorithms, Decimal money columns, CORS origins with credentials, Redis key expiries). Nothing is written: "
                        "review the diff and apply it yourself. Findings it cannot rewrite are listed with the reason."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Project directory."},
                "file": {"type": "string", "description": "Only fix this file (relative to the project, or absolute)."},
                "rules": {"type": "array", "items": {"type": "string"}, "description": "Only fix these rule ids."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "audit_current_file",
        "description": ("Audit the file you are editing, optionally from its unsaved or not yet written content, in "
                        "the context of its project. Fast on repeated calls: unchanged files are not analysed again."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "The file (it may not exist yet when content is given)."},
                "content": {"type": "string", "description": "The file's current text, used instead of what is on disk."},
                "project": {"type": "string", "description": "Project root; defaults to the git repository containing the file."},
            },
            "required": ["file"],
        },
    },
    {
        "name": "verify_package",
        "description": ("Before installing or importing a package: whether it exists, is brand new, looks like a "
                        "typosquat, has known vulnerabilities (with a version), whether a Python import name belongs to "
                        "a differently named package (cv2 is opencv-python), and whether the project already declares "
                        "it. Ends with a verdict: ok, caution or block."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Package name, or a Python import name."},
                "ecosystem": {"type": "string", "enum": ["PyPI", "npm"]},
                "version": {"type": "string", "description": "Exact version to check against OSV (optional)."},
                "project": {"type": "string", "description": "Project directory, to report whether it already declares the package."},
            },
            "required": ["name", "ecosystem"],
        },
    },
    {
        "name": "simulate_migration",
        "description": ("Dry-run a PostgreSQL migration without a database: for each statement, the table lock it "
                        "takes, what that lock blocks, whether it rewrites the table or destroys data, and a safer way "
                        "to do it (CREATE INDEX CONCURRENTLY, NOT VALID constraints, batched backfills)."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "A .sql migration file."},
                "sql": {"type": "string", "description": "The SQL itself, instead of a path."},
            },
        },
    },
]


class ToolError(Exception):
    pass


def _dir(path: Any) -> str:
    if not isinstance(path, str) or not path:
        raise ToolError("path must be a non-empty string")
    p = Path(path).expanduser()
    if not p.is_dir():
        raise ToolError(f"not a directory: {path}")
    return str(p)


def _summary(res, findings) -> Dict[str, Any]:
    return {
        "root": res.root, "files_scanned": res.meta.get("files_scanned"), "score": res.score, "grade": res.grade,
        "counts": res.counts, "notes": res.meta.get("notes", []),
        "findings": [{k: f.to_dict()[k] for k in ("rule_id", "severity", "title", "file", "line", "message", "snippet", "why", "fix")}
                     for f in findings[:MAX_FINDINGS]],
        "truncated": len(findings) > MAX_FINDINGS,
    }


def _options(root: str, **overrides: Any):
    """The project's own settings (auth helpers, exclusions, disabled rules), with the tool's overrides."""
    from .config import ConfigError, project_options

    try:
        return project_options(root, **overrides)
    except ConfigError as e:
        raise ToolError(str(e)) from None


PROJECT_MARKERS = (".git", ".vibeaudit.toml", "pyproject.toml", "package.json", "setup.py", "requirements.txt")


def tool_scan_project(args: Dict[str, Any]) -> Dict[str, Any]:
    from .gitdiff import DiffError, changed
    from .scanner import scan

    from .model import SEVERITIES

    root = _dir(args.get("path"))
    # arguments come from a model: check them against the schema instead of trusting their types
    severity = args.get("min_severity", "low")
    if severity not in SEVERITIES:
        raise ToolError(f"min_severity must be one of {', '.join(SEVERITIES)}")
    offline = args.get("offline", True)
    if not isinstance(offline, bool):
        raise ToolError("offline must be true or false")
    changes_arg = args.get("changes")
    if changes_arg is not None and (not isinstance(changes_arg, str) or not changes_arg.strip()):
        raise ToolError("changes must be 'staged' or a git revision such as 'origin/main'")
    changes = None
    if changes_arg:
        try:
            changes = changed(Path(root), staged=changes_arg == "staged", base=None if changes_arg == "staged" else changes_arg)
        except DiffError as e:
            raise ToolError(f"cannot compute changes: {e}") from None
    res = scan(root, _options(root, offline=offline, external="none", min_severity=severity, changes=changes))
    return _summary(res, res.findings)


def tool_scan_file(args: Dict[str, Any]) -> Dict[str, Any]:
    from .scanner import scan

    file = args.get("file")
    if not isinstance(file, str) or not Path(file).is_file():
        raise ToolError(f"not a file: {file}")
    target = Path(file).resolve()
    root = _root_for(target, args.get("project"))
    try:
        rel = target.relative_to(root).as_posix()
    except ValueError:
        raise ToolError("the file is not inside the project") from None
    res = scan(str(root), _options(str(root), offline=True, external="none"))
    return _summary(res, [f for f in res.findings if f.file == rel])


def tool_list_routes(args: Dict[str, Any]) -> Dict[str, Any]:
    from .scanner import scan

    root = _dir(args.get("path"))
    res = scan(root, _options(root, offline=True, external="none"))
    return {"routes": [r.to_dict() for r in sorted(res.routes, key=lambda r: (r.file, r.line))]}


def tool_check_package(args: Dict[str, Any]) -> Dict[str, Any]:
    return _package_report(args)


def _package_report(args: Dict[str, Any]) -> Dict[str, Any]:
    from . import deps

    name, eco = args.get("name"), args.get("ecosystem")
    if not isinstance(name, str) or not name or eco not in ("PyPI", "npm"):
        raise ToolError("name (string) and ecosystem (PyPI or npm) are required")
    version = args.get("version")
    if version is not None and not isinstance(version, str):
        raise ToolError("version must be a string such as \"2.31.0\"")
    dep = deps.Dep(name, eco, "", 0, version or None)
    deps.BREAKER.reset()  # the server lives long: one network blip must not disable lookups for good
    status, first, note = deps.registry_info(dep)
    out: Dict[str, Any] = {"name": name, "ecosystem": eco, "registry": status,
                           "first_release": first.isoformat() if first else None,
                           "similar_popular_package": deps.typosquat_target(name, eco)}
    if note:
        out["note"] = note
    if status == "missing":
        out["advice"] = "This package does not exist. Do not install it; an attacker could register the name."
    elif status == "error":
        out["advice"] = "The registry could not be reached; the package was not verified."
    if dep.version and status == "ok":
        try:
            vulns = deps.osv_lookup([dep]).get((eco, name, dep.version), [])
            out["vulnerabilities"] = [v.get("id") for v in vulns]
        except ConnectionError:
            out["vulnerabilities"] = None
    deps.save_caches()
    return out


def tool_explain_rule(args: Dict[str, Any]) -> Dict[str, Any]:
    from .rules import CATEGORIES, RULES

    rule = RULES.get(str(args.get("rule_id", "")).upper())
    if rule is None:
        raise ToolError(f"unknown rule: {args.get('rule_id')}")
    return {"id": rule.id, "title": rule.title, "category": CATEGORIES[rule.category], "severity": rule.severity,
            "why": rule.why, "fix": rule.fix, "cwe": rule.cwe, "owasp": rule.owasp}


def tool_auto_repair(args: Dict[str, Any]) -> Dict[str, Any]:
    from . import fix
    from .rules import RULES

    root = _dir(args.get("path"))
    rules = args.get("rules", [])
    if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
        raise ToolError("rules must be a list of rule ids")
    unknown = [r for r in rules if r.upper() not in RULES]
    if unknown:
        raise ToolError(f"unknown rule: {', '.join(unknown)}")
    only = args.get("file")
    if only is not None:
        if not isinstance(only, str) or not only:
            raise ToolError("file must be a non-empty string")
        target = Path(only) if Path(only).is_absolute() else Path(root) / only
        try:
            only = target.resolve().relative_to(Path(root).resolve()).as_posix()
        except ValueError:
            raise ToolError("the file is not inside the project") from None
    plan = fix.plan(root, rules, _options(root, offline=True, external="none"))
    if only is not None:
        plan.changes = [c for c in plan.changes if c.file == only]
        plan.skipped = [(f, r) for f, r in plan.skipped if f.file == only]

    def brief(f) -> Dict[str, Any]:
        return {"rule_id": f.rule_id, "file": f.file, "line": f.line, "message": f.message}

    return {"diff": plan.diff(), "files": [c.file for c in plan.changes], "fixed": [brief(f) for f in plan.fixed][:MAX_FINDINGS],
            "not_fixed": [dict(brief(f), reason=r) for f, r in plan.skipped if f.rule_id in fix.FIXERS][:MAX_FINDINGS]}


def _root_for(target: Path, project: Any) -> Path:
    if project:
        return Path(_dir(project)).resolve()
    # the nearest folder that looks like a project root; a git root wins over a nested manifest
    return next((p for p in target.parents if (p / ".git").exists()), None) or \
        next((p for p in target.parents if any((p / m).exists() for m in PROJECT_MARKERS)), target.parent)


MAX_CONTENT = 2_000_000
_WATCHERS: Dict[str, Any] = {}  # project root -> watch.Watcher, so repeated calls reuse unchanged files
MAX_WATCHERS = 4


def tool_audit_current_file(args: Dict[str, Any]) -> Dict[str, Any]:
    from .watch import Watcher

    file, content = args.get("file"), args.get("content")
    if content is not None and (not isinstance(content, str) or len(content) > MAX_CONTENT):
        raise ToolError(f"content must be a string of at most {MAX_CONTENT} characters")
    if not isinstance(file, str) or not file or (content is None and not Path(file).is_file()):
        raise ToolError(f"not a file: {file}")
    target = Path(file).resolve()
    if target.exists() and not target.is_file():
        raise ToolError(f"not a file: {file}")
    root = _root_for(target, args.get("project"))
    try:
        rel = target.relative_to(root).as_posix()
    except ValueError:
        raise ToolError("the file is not inside the project") from None
    opts = _options(str(root), offline=True, external="none")
    w = _WATCHERS.pop(str(root), None)
    if w is None or w.opts != opts:  # a changed configuration file changes the options: start again
        w = Watcher(str(root), opts)
    _WATCHERS[str(root)] = w  # most recently used last
    while len(_WATCHERS) > MAX_WATCHERS:
        _WATCHERS.pop(next(iter(_WATCHERS)))
    w.project.overlays = {rel: content.encode("utf-8")} if content is not None else {}
    w.changed()
    if w.project.get(rel) is None:
        raise ToolError("the file is excluded from the scan (configuration, .vibeauditignore or a skipped folder)")
    from .scanner import scan

    res = scan(str(root), opts, w.project)
    w.findings = {f.fingerprint: f for f in res.findings}
    out = _summary(res, [f for f in res.findings if f.file == rel])
    out["file"], out["unsaved_content"] = rel, content is not None
    return out


def tool_verify_package(args: Dict[str, Any]) -> Dict[str, Any]:
    from . import deps
    from .qualityscan import IMPORT_TO_DIST

    name, eco = args.get("name"), args.get("ecosystem")
    if not isinstance(name, str) or not name or eco not in ("PyPI", "npm"):
        raise ToolError("name (string) and ecosystem (PyPI or npm) are required")
    out: Dict[str, Any] = {"requested": name}
    reasons: List[str] = []
    checked = name
    dists = IMPORT_TO_DIST.get(name) if eco == "PyPI" else None
    if dists and deps.pep503(name) not in dists:
        checked = dists[0]
        out["import_name_of"] = list(dists)
        reasons.append(f"`{name}` is an import name; the package to install is `{dists[0]}`"
                       + (f" (or {', '.join(dists[1:])})" if len(dists) > 1 else "") + ".")
    out.update(_package_report({"name": checked, "ecosystem": eco, "version": args.get("version")}))
    verdict = "ok"
    if out.get("registry") == "missing":
        verdict = "block"
        reasons.append("It does not exist on the registry: an attacker could register the name.")
    if out.get("vulnerabilities"):
        verdict = "block"
        reasons.append(f"This version has known vulnerabilities: {', '.join(out['vulnerabilities'])}.")
    first = out.get("first_release")
    if first:
        import datetime as dt

        age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(first)).days
        if age < deps.NEW_PACKAGE_DAYS:
            verdict = "block" if verdict == "block" else "caution"
            reasons.append(f"Its first release is only {age} days old.")
    if out.get("similar_popular_package"):
        verdict = "block" if verdict == "block" else "caution"
        reasons.append(f"The name is one keystroke away from the popular `{out['similar_popular_package']}`.")
    if out.get("registry") == "error":
        verdict = "block" if verdict == "block" else "caution"
        reasons.append("The registry could not be reached; the package was not verified.")
    if args.get("project"):
        from .files import Project

        root = Path(_dir(args["project"]))
        key = deps.pep503(checked) if eco == "PyPI" else checked
        out["declared_in_project"] = [
            {"file": d.file, "line": d.line, "version": d.version}
            for d in deps.collect(Project(root)) if d.ecosystem == eco and (deps.pep503(d.name) if eco == "PyPI" else d.name) == key]
    out["verdict"], out["reasons"] = verdict, reasons
    return out


def tool_simulate_migration(args: Dict[str, Any]) -> Dict[str, Any]:
    from . import migrations

    path, sql = args.get("path"), args.get("sql")
    if (path is None) == (sql is None):
        raise ToolError("give either path (a .sql file) or sql")
    if path is not None:
        if not isinstance(path, str) or not path.lower().endswith(".sql") or not Path(path).is_file():
            raise ToolError("path must be an existing .sql file")
        if Path(path).stat().st_size > migrations.MAX_SQL:
            raise ToolError(f"the migration is larger than {migrations.MAX_SQL} bytes")
        sql = Path(path).read_text(encoding="utf-8", errors="replace")
    if not isinstance(sql, str):
        raise ToolError("sql must be a string")
    try:
        out = migrations.analyse(sql)
    except ValueError as e:
        raise ToolError(str(e)) from None
    if path is not None:
        out["path"] = path
    return out


HANDLERS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "scan_project": tool_scan_project, "scan_file": tool_scan_file, "list_routes": tool_list_routes,
    "check_package": tool_check_package, "explain_rule": tool_explain_rule, "auto_repair": tool_auto_repair,
    "audit_current_file": tool_audit_current_file, "verify_package": tool_verify_package,
    "simulate_migration": tool_simulate_migration,
}


def handle(msg: Any) -> Optional[Dict[str, Any]]:
    """Process one JSON-RPC message; return the response, or None for notifications."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        return {"jsonrpc": "2.0", "id": msg.get("id") if isinstance(msg, dict) else None,
                "error": {"code": -32600, "message": "Invalid Request"}}
    method, mid = msg["method"], msg.get("id")
    if "id" not in msg:
        return None  # notification (notifications/initialized, notifications/cancelled, ...)
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

    def ok(result: Dict[str, Any]) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    if method == "initialize":
        wanted = params.get("protocolVersion")
        return ok({
            "protocolVersion": wanted if wanted in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS[0],
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "vibeaudit", "version": __version__},
            "instructions": ("Call scan_project (or scan_file) after writing or changing code, and check_package before "
                             "adding a dependency. Fix critical and high findings before handing work back."),
        })
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name")
        handler = HANDLERS.get(name) if isinstance(name, str) else None
        if handler is None:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"Unknown tool: {name}"}}
        args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        try:
            data = handler(args)
            return ok({"content": [{"type": "text", "text": json.dumps(data, indent=2)}], "structuredContent": data, "isError": False})
        except ToolError as e:
            return ok({"content": [{"type": "text", "text": str(e)}], "isError": True})
        except Exception as e:  # noqa: BLE001 - report tool failures to the client instead of dying
            traceback.print_exc(file=sys.stderr)
            return ok({"content": [{"type": "text", "text": f"internal error: {type(e).__name__}: {e}"}], "isError": True})
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Method not found: {method}"}}


def serve(stdin: IO[str], stdout: IO[str]) -> int:
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = loads_json(line)
        except ValueError:
            response: Optional[Dict[str, Any]] = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        else:
            if isinstance(msg, list):  # batches (older protocol versions)
                responses = [r for r in (handle(m) for m in msg) if r is not None]
                response = responses or None  # type: ignore[assignment]
            else:
                response = handle(msg)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()
    return 0


def main() -> int:
    os.environ.setdefault("NO_COLOR", "1")
    return serve(sys.stdin, sys.stdout)
