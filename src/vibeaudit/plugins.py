"""Custom rules: company or project checks written in a few lines of Python.

    from vibeaudit import route_rule

    @route_rule("ORG001", "Billing route without audit log", severity="high")
    def billing_audit(route):
        if route.path.startswith("/api/billing") and "audit_log(" not in route.body:
            return f"{route.path} changes billing without calling audit_log()."

Load them with `vibeaudit scan --plugin my_rules.py` (a file) or `--plugin my_company.rules` (a module), or
register them in-process before calling `vibeaudit.scan()`.

Plugins are Python code and run with your permissions, so they are loaded only when you name them on the
command line or import them yourself, never from the scanned repository's configuration.
"""
from __future__ import annotations

import importlib
import importlib.util
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

from .files import Project, SourceFile
from .model import SEVERITIES, Finding, Route
from .rules import CATEGORIES, RULES, Rule

ID_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,15}$")


@dataclass
class Context:
    project: Project
    routes: List[Route]

    @property
    def files(self) -> List[SourceFile]:
        return self.project.files

    def finding(self, file: str, line: int, message: str, severity: str = "") -> Finding:
        sf = self.project.get(file)
        return Finding("", file, line, message, severity, sf.line(line).strip() if sf and line else "")


CheckFn = Callable[[Context], Iterable]
REGISTRY: Dict[str, CheckFn] = {}


def _register(rule_id: str, title: str, category: str, severity: str, why: str, fix: str, cwe: str, owasp: str, fn: CheckFn) -> None:
    if not ID_RE.match(rule_id):
        raise ValueError(f"rule id {rule_id!r} must be 2-16 upper-case letters, digits or underscores")
    existing = RULES.get(rule_id)
    if existing is not None and rule_id not in REGISTRY:
        raise ValueError(f"rule id {rule_id} is a built-in rule")
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
    if category not in CATEGORIES:
        raise ValueError(f"category must be one of {', '.join(CATEGORIES)}")
    RULES[rule_id] = Rule(rule_id, title, category, severity, why or title, fix or "See the rule's documentation.", cwe, owasp)
    REGISTRY[rule_id] = fn


def rule(rule_id: str, title: str, *, category: str = "custom", severity: str = "medium", why: str = "", fix: str = "",
         cwe: str = "", owasp: str = "") -> Callable[[CheckFn], CheckFn]:
    """Register a project-wide check: fn(ctx) yields Findings, (file, line, message) tuples or dicts."""
    def deco(fn: CheckFn) -> CheckFn:
        _register(rule_id, title, category, severity, why, fix, cwe, owasp, fn)
        return fn
    return deco


def route_rule(rule_id: str, title: str, **kw) -> Callable[[Callable[[Route], Optional[str]]], Callable]:
    """Register a per-route check: fn(route) returns a message (a finding) or None."""
    def deco(fn: Callable[[Route], Optional[str]]) -> Callable:
        def check(ctx: Context):
            for r in ctx.routes:
                msg = fn(r)
                if msg:
                    yield (r.file, r.line, str(msg))
        rule(rule_id, title, **kw)(check)
        return fn
    return deco


def file_rule(rule_id: str, title: str, *, kinds: Iterable[str] = ("py", "js"), **kw) -> Callable:
    """Register a per-file check: fn(source_file) yields (line, message) pairs."""
    wanted = set(kinds)

    def deco(fn: Callable[[SourceFile], Iterable]) -> Callable:
        def check(ctx: Context):
            for sf in ctx.files:
                if sf.kind in wanted and sf.text is not None and not sf.is_test:
                    for line, msg in fn(sf) or ():
                        yield (sf.rel, int(line), str(msg))
        rule(rule_id, title, **kw)(check)
        return fn
    return deco


def unregister(rule_id: str) -> None:
    if rule_id in REGISTRY:
        REGISTRY.pop(rule_id)
        RULES.pop(rule_id, None)


def load(spec: str) -> None:
    """Import a plugin from a .py file path or a dotted module name; its decorators register the rules."""
    path = Path(spec)
    if spec.endswith(".py") or path.is_file():
        if not path.is_file():
            raise ImportError(f"plugin file not found: {spec}")
        name = "vibeaudit_plugin_" + re.sub(r"\W", "_", str(path.resolve()))
        module_spec = importlib.util.spec_from_file_location(name, path)
        if module_spec is None or module_spec.loader is None:
            raise ImportError(f"cannot load plugin: {spec}")
        module = importlib.util.module_from_spec(module_spec)
        sys.modules[name] = module
        module_spec.loader.exec_module(module)
    else:
        importlib.import_module(spec)


def run(project: Project, routes: List[Route], emit: Callable[[Finding], None]) -> None:
    from .guard import GUARD

    ctx = Context(project, routes)
    for rule_id, fn in list(REGISTRY.items()):
        def one(rule_id: str = rule_id, fn: CheckFn = fn) -> None:
            for item in fn(ctx) or ():
                if isinstance(item, Finding):
                    f = item
                elif isinstance(item, dict):
                    f = ctx.finding(str(item.get("file", "")), int(item.get("line", 0)), str(item.get("message", "")),
                                    str(item.get("severity", "")))
                else:
                    file, line, message = item
                    f = ctx.finding(str(file), int(line), str(message))
                f.rule_id = rule_id
                f.source = "plugin"
                emit(f)
        GUARD.run("<plugin>", f"custom rule {rule_id}", one)
