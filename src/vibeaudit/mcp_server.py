"""`vibeaudit mcp`: a Model Context Protocol server over stdio, so coding agents can audit their own work.

Transport: newline-delimited JSON-RPC 2.0 on stdin/stdout (the MCP stdio transport). Logs go to stderr.
Tools: scan_project, scan_file, list_routes, check_package, explain_rule. All are read-only.
"""
from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path
from typing import IO, Any, Callable, Dict, Optional

from . import __version__

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

    root = _dir(args.get("path"))
    changes = None
    if args.get("changes"):
        try:
            changes = changed(Path(root), staged=args["changes"] == "staged",
                              base=None if args["changes"] == "staged" else str(args["changes"]))
        except DiffError as e:
            raise ToolError(f"cannot compute changes: {e}") from None
    res = scan(root, _options(root, offline=bool(args.get("offline", True)), external="none",
                              min_severity=str(args.get("min_severity", "low")), changes=changes))
    return _summary(res, res.findings)


def tool_scan_file(args: Dict[str, Any]) -> Dict[str, Any]:
    from .scanner import scan

    file = args.get("file")
    if not isinstance(file, str) or not Path(file).is_file():
        raise ToolError(f"not a file: {file}")
    target = Path(file).resolve()
    project = args.get("project")
    if project:
        root = Path(_dir(project)).resolve()
    else:
        # the nearest folder that looks like a project root; a git root wins over a nested manifest
        root = next((p for p in target.parents if (p / ".git").exists()), None) or \
            next((p for p in target.parents if any((p / m).exists() for m in PROJECT_MARKERS)), target.parent)
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
    from . import deps

    name, eco = args.get("name"), args.get("ecosystem")
    if not isinstance(name, str) or not name or eco not in ("PyPI", "npm"):
        raise ToolError("name (string) and ecosystem (PyPI or npm) are required")
    dep = deps.Dep(name, eco, "", 0, args.get("version") if isinstance(args.get("version"), str) else None)
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


HANDLERS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "scan_project": tool_scan_project, "scan_file": tool_scan_file, "list_routes": tool_list_routes,
    "check_package": tool_check_package, "explain_rule": tool_explain_rule,
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
            msg = json.loads(line)
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
