"""Command line interface."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from pathlib import Path

from . import __version__
from .config import ConfigError
from .config import load as load_config
from .model import SEVERITIES, at_least
from .report import EXTENSIONS, RENDERERS, Result, render_text, write_report
from .rules import CATEGORIES, RULES


def _reconfigure_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass  # a replaced or non-text stream cannot be reconfigured; keep its defaults


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vibeaudit",
        description="Security and quality audit for AI-generated (vibe-coded) and LLM-powered apps.")
    p.add_argument("--version", action="version", version=f"vibeaudit {__version__}")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan a project directory")
    s.add_argument("path", nargs="?", default=".", help="project directory (default: current directory)")
    s.add_argument("-r", "--report", action="append", default=[], metavar="FORMAT[:PATH]",
                   help="write a report: json, sarif, md, html, prompt (a fix brief for AI assistants) or badge (SVG), optionally with a path ('-' for stdout). Repeatable.")
    s.add_argument("--fail-on", default=None, choices=SEVERITIES[:4] + ["none"],
                   help="exit with code 1 if any finding is at least this severe (default: high)")
    s.add_argument("--min-severity", default=None, choices=SEVERITIES, help="hide findings below this severity (default: low)")
    s.add_argument("--offline", action="store_true", default=None, help="no network: skip registry and vulnerability lookups")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching GLOB (repeatable)")
    s.add_argument("--disable", action="append", default=[], metavar="RULE_OR_CATEGORY",
                   help="disable a rule id (e.g. QA002) or a category (e.g. quality). Repeatable, comma lists allowed.")
    s.add_argument("--external", default=None,
                   help="third-party scanners to run: auto (those installed), none, or a list like gitleaks,bandit")
    s.add_argument("--baseline", metavar="FILE", help="hide findings already present in this JSON report")
    s.add_argument("--write-baseline", metavar="FILE", help="save all current findings as a baseline and exit 0")
    s.add_argument("--max-file-size", type=int, default=None, help="skip files larger than this many bytes (default: 1000000)")
    s.add_argument("--file-timeout", type=float, default=None,
                   help="seconds each analysis step may spend on one file before it is stopped (default: 30)")
    s.add_argument("--llm", choices=["gemini", "openai", "anthropic"],
                   help="use an LLM to triage findings (needs GEMINI_API_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY)")
    s.add_argument("--llm-model", help="model name for the LLM provider")
    s.add_argument("--llm-review", action="store_true", help="also ask the LLM to review the riskiest files for missed issues")
    s.add_argument("--llm-max-requests", type=int, default=None, help="hard cap on LLM requests per scan (default: 10)")
    s.add_argument("--plugin", action="append", default=[], metavar="FILE_OR_MODULE",
                   help="load custom rules from a Python file or module (repeatable; runs that code)")
    s.add_argument("--staged", action="store_true", help="report only findings on lines staged for commit (pre-commit hooks)")
    s.add_argument("--diff", metavar="REV", help="report only findings on lines changed since REV, e.g. origin/main (pull requests)")
    s.add_argument("--config", metavar="FILE", help="read settings from this TOML file instead of .vibeaudit.toml / pyproject.toml")
    s.add_argument("--no-config", action="store_true",
                   help="ignore configuration and feedback files in the scanned project")
    s.add_argument("--no-cache", action="store_true", help="do not read or write cached registry and vulnerability answers")
    s.add_argument("-q", "--quiet", action="store_true", help="print only the summary")
    s.add_argument("--no-color", action="store_true", help="disable colored output")

    m = sub.add_parser("routes", help="list every HTTP entry point with its auth, data-write and AI-call status")
    m.add_argument("path", nargs="?", default=".", help="project directory (default: current directory)")
    m.add_argument("--format", choices=["text", "json", "md"], default="text")
    m.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching GLOB (repeatable)")

    sub.add_parser("mcp", help="run a Model Context Protocol server on stdio for coding agents")

    r = sub.add_parser("rules", help="list every rule")
    r.add_argument("--format", choices=["text", "json", "md"], default="text")

    u = sub.add_parser("update", help="refresh package lists and retired model ids, or upgrade vibeaudit itself")
    u.add_argument("--self", dest="upgrade_self", action="store_true", help="upgrade the installed package with pip")

    f = sub.add_parser("feedback", help="record that a finding is a false positive or confirmed, or list feedback")
    f.add_argument("verdict", nargs="?", choices=["false-positive", "confirmed", "list"], default="list")
    f.add_argument("rule", nargs="?", help="rule id, for example AUTH001")
    f.add_argument("location", nargs="?", help="FILE:LINE as shown in the report")
    f.add_argument("--note", default="", help="why (kept with the entry)")
    f.add_argument("--path", default=".", help="project directory (default: current directory)")
    f.add_argument("--config", metavar="FILE", help="settings file, as for scan")
    f.add_argument("--plugin", action="append", default=[], metavar="FILE_OR_MODULE",
                   help="load custom rules, as for scan, so their findings can be marked")
    return p


def cmd_update(a: argparse.Namespace) -> int:
    from . import updater

    def log(msg: str) -> None:
        print(f"vibeaudit: {msg}")

    if a.upgrade_self:
        return 0 if updater.update_self(log) == 0 else 1
    return 0 if updater.update_data(log) == 0 else 1


def cmd_feedback(a: argparse.Namespace) -> int:
    from . import feedback

    root = Path(a.path)
    if not root.is_dir():
        print(f"vibeaudit: not a directory: {a.path}", file=sys.stderr)
        return 2
    if a.verdict == "list":
        entries = feedback.load(root)
        for e in entries:
            note = f"  ({e.get('note')})" if e.get("note") else ""
            print(f"{e['verdict']:15} {e.get('rule', '?'):8} {e.get('file', '?')}:{e.get('line', '?')}{note}")
        for rule, counts in feedback.summary(root).items():
            print(f"{rule}: {counts['false-positive']} false positive, {counts['confirmed']} confirmed")
        if not entries:
            print("no feedback recorded")
        return 0
    file, _, line = (a.location or "").rpartition(":")
    if not a.rule or not file or not line.isdigit():
        print("vibeaudit: usage: vibeaudit feedback false-positive|confirmed RULE FILE:LINE [--note TEXT]", file=sys.stderr)
        return 2
    from . import plugins

    for spec in a.plugin:
        try:
            plugins.load(spec)
        except Exception as e:  # noqa: BLE001 - any import failure is a usage error here
            print(f"vibeaudit: cannot load plugin {spec}: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
    try:
        entry = feedback.record(root, a.rule, file, int(line), a.verdict, a.note, a.config)
    except ConfigError as e:
        print(f"vibeaudit: {e}", file=sys.stderr)
        return 2
    if entry is None:
        print(f"vibeaudit: no {a.rule.upper()} finding at {file}:{line}", file=sys.stderr)
        return 1
    print(f"recorded {a.verdict} for {entry['rule']} at {entry['file']}:{entry['line']} in {root / feedback.FILE}")
    return 0


def cmd_rules(fmt: str) -> int:
    rules = sorted(RULES.values(), key=lambda r: (list(CATEGORIES).index(r.category), r.id))
    if fmt == "json":
        print(json.dumps([r.__dict__ for r in rules], indent=2))
    elif fmt == "md":
        print("| ID | Severity | Category | Rule | References |\n| --- | --- | --- | --- | --- |")
        for r in rules:
            refs = ", ".join(x for x in (r.cwe, r.owasp) if x)
            print(f"| {r.id} | {r.severity} | {CATEGORIES[r.category]} | {r.title} | {refs} |")
    else:
        for r in rules:
            print(f"{r.id:8} {r.severity:9} {r.category:13} {r.title}")
    return 0


def cmd_routes(a: argparse.Namespace) -> int:
    from .scanner import scan

    if not os.path.isdir(a.path):
        print(f"vibeaudit: not a directory: {a.path}", file=sys.stderr)
        return 2
    from .config import project_options

    try:
        opts = project_options(a.path, offline=True, external="none")
    except ConfigError as e:
        print(f"vibeaudit: {e}", file=sys.stderr)
        return 2
    opts.excludes += a.exclude
    res = scan(a.path, opts)
    rows =[r.to_dict() for r in sorted(res.routes, key=lambda r: (r.file, r.line))]
    if a.format == "json":
        print(json.dumps(rows, indent=2))
        return 0

    def yn(v: bool) -> str:
        return "yes" if v else "no"

    if a.format == "md":
        print("| Method | Path | Auth | Writes | AI call | Location | Framework |\n| --- | --- | --- | --- | --- | --- | --- |")
        for r in rows:
            print(f"| {'/'.join(r['methods'])} | `{r['path']}` | {yn(r['authenticated'])} | {yn(r['writes_data'])} | "
                  f"{yn(r['calls_llm'])} | {r['file']}:{r['line']} | {r['framework']} |")
        return 0
    width = max([len(r["path"]) for r in rows] + [4])
    print(f"{'METHOD':10} {'PATH':{width}}  AUTH  WRITES  AI   LOCATION")
    for r in rows:
        print(f"{'/'.join(r['methods']):10} {r['path']:{width}}  {yn(r['authenticated']):4}  {yn(r['writes_data']):6}  "
              f"{yn(r['calls_llm']):3}  {r['file']}:{r['line']}")
    exposed = [r for r in rows if not r["authenticated"] and (r["writes_data"] or r["calls_llm"])]
    print(f"\n{len(rows)} routes; {len(exposed)} write data or call a paid AI API without a visible auth check.")
    return 0


def cmd_scan(a: argparse.Namespace) -> int:
    from .scanner import Options, scan

    if not os.path.isdir(a.path):
        print(f"vibeaudit: not a directory: {a.path}", file=sys.stderr)
        return 2
    try:
        cfg, cfg_path = ({}, None) if a.no_config else load_config(Path(a.path), a.config)
    except ConfigError as e:
        print(f"vibeaudit: {e}", file=sys.stderr)
        return 2

    def pick(flag, key, default):
        return flag if flag is not None else cfg.get(key, default)

    fail_on = pick(a.fail_on, "fail_on", "high")
    from . import plugins

    for spec in a.plugin:
        try:
            plugins.load(spec)
        except Exception as e:  # noqa: BLE001 - any import failure is a usage error here
            print(f"vibeaudit: cannot load plugin {spec}: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
    changes = None
    if a.staged or a.diff:
        if a.staged and a.diff:
            print("vibeaudit: use either --staged or --diff, not both", file=sys.stderr)
            return 2
        from .gitdiff import DiffError, changed

        try:
            changes = changed(Path(a.path), staged=a.staged, base=a.diff)
        except DiffError as e:
            print(f"vibeaudit: cannot compute changes: {e}", file=sys.stderr)
            return 2
    reports = []
    for spec in a.report:
        fmt, _, path = spec.partition(":")
        if len(fmt) == 1 and path.startswith(("\\", "/")):  # a bare Windows path like C:\x.json is not a format
            fmt, path = "", spec
        fmt = fmt.lower()
        if fmt not in RENDERERS:
            print(f"vibeaudit: unknown report format {fmt!r} (use json, sarif, md, html, prompt, badge)", file=sys.stderr)
            return 2
        reports.append((fmt, path or f"vibeaudit-report.{EXTENSIONS[fmt]}"))
    disabled = {x.strip() for d in list(a.disable) + list(cfg.get("disable", [])) for x in d.split(",") if x.strip()}
    unknown = [d for d in disabled if d not in RULES and d not in CATEGORIES and ":" not in d]
    if unknown:
        print(f"vibeaudit: unknown rule or category: {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    to_stdout = any(p == "-" for _f, p in reports)
    log_stream = sys.stderr

    def log(msg: str) -> None:
        if not a.quiet:
            print(f"vibeaudit: {msg}", file=log_stream)

    baseline = a.baseline
    if baseline is None and cfg.get("baseline"):
        baseline = str(Path(cfg_path).parent / str(cfg["baseline"])) if cfg_path else str(cfg["baseline"])
    opts = Options(offline=bool(pick(a.offline, "offline", False)), excludes=list(a.exclude) + list(cfg.get("exclude", [])),
                   disabled=disabled, min_severity=pick(a.min_severity, "min_severity", "low"),
                   external=pick(a.external, "external", "auto"), baseline=baseline,
                   max_file_bytes=pick(a.max_file_size, "max_file_size", 1_000_000), llm=pick(a.llm, "llm", None),
                   llm_model=pick(a.llm_model, "llm_model", None), llm_review=a.llm_review,
                   llm_max_requests=max(0, pick(a.llm_max_requests, "llm_max_requests", 10)),
                   file_timeout=max(0.1, float(pick(a.file_timeout, "file_timeout", 30.0))),
                   auth_helpers=list(cfg.get("auth_helpers", [])), sanitizers=list(cfg.get("sanitizers", [])),
                   public_paths=list(cfg.get("public_paths", [])), changes=changes, log=log,
                   feedback=not a.no_config,  # the feedback file lives in the repository, like the config
                   cache=not a.no_cache)
    if cfg_path:
        log(f"using settings from {cfg_path}")
    try:
        res: Result = scan(a.path, opts)
    except KeyboardInterrupt:
        return 130
    if a.write_baseline:
        write_report(res, "json", a.write_baseline)
        print(f"vibeaudit: baseline with {len(res.findings)} findings written to {a.write_baseline}", file=sys.stderr)
        return 0
    for fmt, path in reports:
        write_report(res, fmt, path)
    color = not a.no_color and not os.environ.get("NO_COLOR") and (sys.stderr if to_stdout else sys.stdout).isatty()
    text = render_text(res, color, verbose=not a.quiet)
    (sys.stderr if to_stdout else sys.stdout).write(text)
    for fmt, path in reports:
        if path != "-":
            print(f"vibeaudit: wrote {fmt} report to {path}", file=sys.stderr)
    if fail_on != "none" and any(at_least(f.severity, fail_on) for f in res.findings):
        return 1
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    _reconfigure_streams()
    parser = build_parser()
    a = parser.parse_args(argv)
    if a.command == "rules":
        return cmd_rules(a.format)
    if a.command == "routes":
        return cmd_routes(a)
    if a.command == "mcp":
        from .mcp_server import main as mcp_main

        return mcp_main()
    if a.command == "scan":
        return cmd_scan(a)
    if a.command == "update":
        return cmd_update(a)
    if a.command == "feedback":
        return cmd_feedback(a)
    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
