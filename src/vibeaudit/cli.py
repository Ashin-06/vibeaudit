"""Command line interface."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
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
                   help="write a report: json, sarif, md or html, optionally with a path ('-' for stdout). Repeatable.")
    s.add_argument("--fail-on", default="high", choices=SEVERITIES[:4] + ["none"],
                   help="exit with code 1 if any finding is at least this severe (default: high)")
    s.add_argument("--min-severity", default="low", choices=SEVERITIES, help="hide findings below this severity (default: low)")
    s.add_argument("--offline", action="store_true", help="no network: skip registry and vulnerability lookups")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching GLOB (repeatable)")
    s.add_argument("--disable", action="append", default=[], metavar="RULE_OR_CATEGORY",
                   help="disable a rule id (e.g. QA002) or a category (e.g. quality). Repeatable, comma lists allowed.")
    s.add_argument("--external", default="auto",
                   help="third-party scanners to run: auto (those installed), none, or a list like gitleaks,bandit")
    s.add_argument("--baseline", metavar="FILE", help="hide findings already present in this JSON report")
    s.add_argument("--write-baseline", metavar="FILE", help="save all current findings as a baseline and exit 0")
    s.add_argument("--max-file-size", type=int, default=1_000_000, help="skip files larger than this many bytes")
    s.add_argument("--llm", choices=["gemini", "openai", "anthropic"],
                   help="use an LLM to triage findings (needs GEMINI_API_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY)")
    s.add_argument("--llm-model", help="model name for the LLM provider")
    s.add_argument("--llm-review", action="store_true", help="also ask the LLM to review the riskiest files for missed issues")
    s.add_argument("--llm-max-requests", type=int, default=10, help="hard cap on LLM requests per scan (default: 10)")
    s.add_argument("-q", "--quiet", action="store_true", help="print only the summary")
    s.add_argument("--no-color", action="store_true", help="disable colored output")

    r = sub.add_parser("rules", help="list every rule")
    r.add_argument("--format", choices=["text", "json", "md"], default="text")
    return p


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


def cmd_scan(a: argparse.Namespace) -> int:
    from .scanner import Options, scan

    if not os.path.isdir(a.path):
        print(f"vibeaudit: not a directory: {a.path}", file=sys.stderr)
        return 2
    reports = []
    for spec in a.report:
        fmt, _, path = spec.partition(":")
        if len(fmt) == 1 and path.startswith(("\\", "/")):  # a bare Windows path like C:\x.json is not a format
            fmt, path = "", spec
        fmt = fmt.lower()
        if fmt not in RENDERERS:
            print(f"vibeaudit: unknown report format {fmt!r} (use json, sarif, md, html)", file=sys.stderr)
            return 2
        reports.append((fmt, path or f"vibeaudit-report.{EXTENSIONS[fmt]}"))
    disabled = {x.strip() for d in a.disable for x in d.split(",") if x.strip()}
    unknown = [d for d in disabled if d not in RULES and d not in CATEGORIES]
    if unknown:
        print(f"vibeaudit: unknown rule or category: {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    to_stdout = any(p == "-" for _f, p in reports)
    log_stream = sys.stderr

    def log(msg: str) -> None:
        if not a.quiet:
            print(f"vibeaudit: {msg}", file=log_stream)

    opts = Options(offline=a.offline, excludes=a.exclude, disabled=disabled, min_severity=a.min_severity,
                   external=a.external, baseline=a.baseline, max_file_bytes=a.max_file_size, llm=a.llm,
                   llm_model=a.llm_model, llm_review=a.llm_review, llm_max_requests=max(0, a.llm_max_requests), log=log)
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
    if a.fail_on != "none" and any(at_least(f.severity, a.fail_on) for f in res.findings):
        return 1
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    _reconfigure_streams()
    parser = build_parser()
    a = parser.parse_args(argv)
    if a.command == "rules":
        return cmd_rules(a.format)
    if a.command == "scan":
        return cmd_scan(a)
    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
