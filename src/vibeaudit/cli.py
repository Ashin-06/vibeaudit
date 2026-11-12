"""Command line interface."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from pathlib import Path

from . import __version__, compliance
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
                   help="write a report: json, sarif, md, html, prompt (a fix brief for AI assistants), badge (SVG), junit (test report XML), codeclimate (GitLab Code Quality) or compliance:FRAMEWORK (an HTML compliance aid for owasp, owasp-llm, eu-ai-act, soc2, hipaa or gdpr; not a certification), optionally with a path ('-' for stdout). Repeatable.")
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
    s.add_argument("--fail-on-regression", type=int, default=None, metavar="N",
                   help="exit with code 1 if the whole project's score is more than N points below the score in the "
                        "--baseline report (computed before --baseline, --diff and --staged hide findings)")
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
    s.add_argument("--no-cache", action="store_true", help="do not read or write cached registry, vulnerability and LLM answers")
    s.add_argument("--monorepo", action="store_true", default=None,
                   help="scan every package (a folder with its own package.json, pyproject.toml or requirements file) "
                        "as a project of its own, against its own manifest, with a score per package")
    s.add_argument("--include-preview", action="store_true", default=None,
                   help="count findings of preview rules toward --fail-on and the score (they are always reported)")
    s.add_argument("--no-gate-severe-preview", action="store_true", default=None,
                   help="do not count severe preview rules (injection, eval, deserialization, open redirect, XSS) "
                        "toward --fail-on and the score; by default they count")
    s.add_argument("-q", "--quiet", action="store_true", help="print only the summary")
    s.add_argument("--no-color", action="store_true", help="disable colored output")

    m = sub.add_parser("routes", help="list every HTTP entry point with its auth, data-write and AI-call status")
    m.add_argument("path", nargs="?", default=".", help="project directory (default: current directory)")
    m.add_argument("--format", choices=["text", "json", "md"], default="text")
    m.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching GLOB (repeatable)")

    w = sub.add_parser("watch", help="re-scan whenever a file changes and print new and fixed findings",
                       description="Scan once, then poll the project and re-scan after every change, reusing what "
                                   "is unchanged. Prints the findings that appeared (+) or went away (-). Offline, "
                                   "no external tools; stop with Ctrl+C.")
    w.add_argument("path", nargs="?", default=".", help="project directory (default: current directory)")
    w.add_argument("--interval", type=float, default=1.0, help="seconds between checks for changes (default: 1)")
    w.add_argument("--min-severity", default=None, choices=SEVERITIES, help="hide findings below this severity")
    w.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching GLOB (repeatable)")
    w.add_argument("--config", metavar="FILE", help="read settings from this TOML file, as for scan")

    v = sub.add_parser("review", help="pull request review comments (with suggested fixes) for findings on changed lines",
                       description="Scan as `scan --diff BASE` does and turn each finding on a changed line into a "
                                   "review comment, with a GitHub suggestion when a `vibeaudit fix` codemod applies. "
                                   "Prints the review as JSON; --post sends it to the pull request (GitHub Actions, "
                                   "GITHUB_TOKEN with pull-requests: write).")
    v.add_argument("path", nargs="?", default=".", help="project directory (default: current directory)")
    v.add_argument("--diff", required=True, metavar="REV", help="base revision of the pull request, e.g. origin/main")
    v.add_argument("--post", action="store_true", help="post the review to the pull request instead of printing it")
    v.add_argument("--max-comments", type=int, default=30, help="most severe findings to comment on (default: 30)")
    v.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching GLOB (repeatable)")
    v.add_argument("--config", metavar="FILE", help="read settings from this TOML file, as for scan")

    x = sub.add_parser("fix", help="show (or --apply) deterministic fixes for findings that have one obvious repair",
                       description="Print a unified diff that fixes every finding a codemod covers: request timeouts "
                                   "(REL001), output token limits (LLM003), guarded JSON parsing of model output (LLM011), "
                                   "pinned JWT algorithms (BE016, AUTH011), Decimal money columns (DATA004) and CORS "
                                   "origins with credentials (BE012) and Redis key expiries (DATA013). Nothing is written without --apply. With --llm, "
                                   "findings without a codemod get a model-written patch in a .patch file, never applied.")
    x.add_argument("path", nargs="?", default=".", help="project directory (default: current directory)")
    x.add_argument("--apply", action="store_true", help="write the fixes to the files instead of printing the diff")
    x.add_argument("--rule", action="append", default=[], metavar="RULE",
                   help="fix only these rules (repeatable, comma lists allowed)")
    x.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching GLOB (repeatable)")
    x.add_argument("--config", metavar="FILE", help="read settings from this TOML file, as for scan")
    x.add_argument("--llm", choices=["gemini", "openai", "anthropic"],
                   help="ask an LLM for patches for findings without a codemod (auth, transactions, ...); needs an API key")
    x.add_argument("--llm-model", help="model name for the LLM provider")
    x.add_argument("--llm-max-requests", type=int, default=10, help="hard cap on LLM requests (default: 10)")
    x.add_argument("--patch", default="vibeaudit-fix.patch", metavar="FILE",
                   help="where --llm writes its patch (default: vibeaudit-fix.patch); it is never applied")
    x.add_argument("-q", "--quiet", action="store_true", help="do not list skipped findings")

    sub.add_parser("mcp", help="run a Model Context Protocol server on stdio for coding agents")
    sub.add_parser("lsp", help="run a Language Server Protocol server on stdio (diagnostics and fix code actions for editors)")

    st = sub.add_parser("studio", help="open a local web UI: routes, data flows and the score of one project",
                        description="Scan the project and serve a web UI on 127.0.0.1 only, with a random token in "
                                    "the link: routes with auth, write and AI badges, data flows from user input and "
                                    "model output to sinks, and the score by domain, category and rule.")
    st.add_argument("path", nargs="?", default=".", help="project directory (default: current directory)")
    st.add_argument("--port", type=int, default=0, help="port on 127.0.0.1 (default: any free port)")
    st.add_argument("--no-browser", action="store_true", help="print the link instead of opening a browser")
    st.add_argument("--config", metavar="FILE", help="read settings from this TOML file, as for scan")

    e = sub.add_parser("explain", help="explain one finding: the rule, the code and the data flow that led to it",
                       description="Scan the project and explain the findings that match FINDING: FILE:LINE, "
                                   "FILE:LINE:RULE or a fingerprint prefix (from a JSON or SARIF report).")
    e.add_argument("finding", help="FILE:LINE, FILE:LINE:RULE or a fingerprint prefix")
    e.add_argument("--path", default=".", help="project directory (default: current directory)")
    e.add_argument("--format", choices=["text", "json"], default="text")
    e.add_argument("--config", metavar="FILE", help="read settings from this TOML file, as for scan")

    r = sub.add_parser("rules", help="list every rule")
    r.add_argument("--format", choices=["text", "json", "md"], default="text")

    u = sub.add_parser("update", help="refresh package lists, retired model ids and the signed threat feed, or upgrade vibeaudit itself")
    u.add_argument("--self", dest="upgrade_self", action="store_true", help="upgrade the installed package with pip")
    u.add_argument("--export", metavar="FILE",
                   help="write a data bundle for a machine without network (see --osv), instead of refreshing")
    u.add_argument("--osv", metavar="ECOSYSTEMS", default="",
                   help="with --export: also bundle a vulnerability index built from OSV's dumps, e.g. PyPI,npm")
    u.add_argument("--import", dest="import_bundle", metavar="FILE",
                   help="install a bundle made with --export (no network needed); then scan with --offline")

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
    if a.export or a.import_bundle:
        from . import bundle

        try:
            if a.export:
                bundle.export(Path(a.export), [e.strip() for e in a.osv.split(",") if e.strip()], log)
            if a.import_bundle:
                bundle.import_bundle(Path(a.import_bundle), log)
        except (bundle.BundleError, OSError, ValueError) as e:
            print(f"vibeaudit: {e}", file=sys.stderr)
            return 1
        return 0
    if a.osv:
        print("vibeaudit: --osv goes with --export", file=sys.stderr)
        return 2
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


def cmd_explain(a: argparse.Namespace) -> int:
    from . import explain
    from .config import project_options
    from .scanner import scan

    if not os.path.isdir(a.path):
        print(f"vibeaudit: not a directory: {a.path}", file=sys.stderr)
        return 2
    try:
        opts = project_options(a.path, a.config, offline=True, external="none", min_severity="info", include_preview=True)
    except ConfigError as e:
        print(f"vibeaudit: {e}", file=sys.stderr)
        return 2
    res = scan(a.path, opts)
    chosen = explain.select(res.findings, a.finding)
    if not chosen:
        print(f"vibeaudit: no finding matches {a.finding!r} (use FILE:LINE, FILE:LINE:RULE or a fingerprint prefix "
              "from `vibeaudit scan`)", file=sys.stderr)
        return 1
    out = []
    for f in chosen[:10]:
        sf_path = Path(res.root) / f.file
        try:
            text = sf_path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
        except OSError:
            text = ""
        out.append(explain.explain(f, text))
    if a.format == "json":
        print(json.dumps(out, indent=2))
    else:
        print("\n\n".join(explain.render(e) for e in out))
    return 0


def cmd_rules(fmt: str) -> int:
    rules = sorted(RULES.values(), key=lambda r: (list(CATEGORIES).index(r.category), r.id))
    if fmt == "json":
        print(json.dumps([r.__dict__ for r in rules], indent=2))
    elif fmt == "md":
        print("| ID | Severity | Category | Rule | References |\n| --- | --- | --- | --- | --- |")
        for r in rules:
            refs = ", ".join(x for x in (r.cwe, r.owasp) if x)
            print(f"| {r.id} | {r.severity} | {CATEGORIES[r.category]} | {r.title}{' (preview)' if r.preview else ''} | {refs} |")
    else:
        for r in rules:
            print(f"{r.id:8} {r.severity:9} {r.category:13} {r.title}{' (preview)' if r.preview else ''}")
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


def write_raw(text: str) -> None:
    """Write a diff byte for byte: text-mode stdout on Windows would turn every LF into CRLF."""
    buf = getattr(sys.stdout, "buffer", None)
    if buf is None:
        sys.stdout.write(text)
        return
    sys.stdout.flush()
    buf.write(text.encode("utf-8"))
    buf.flush()


def cmd_fix(a: argparse.Namespace) -> int:
    from . import fix
    from .config import project_options

    if not os.path.isdir(a.path):
        print(f"vibeaudit: not a directory: {a.path}", file=sys.stderr)
        return 2
    rules = [r.strip().upper() for spec in a.rule for r in spec.split(",") if r.strip()]
    unknown = [r for r in rules if r not in RULES]
    if unknown:
        print(f"vibeaudit: unknown rule: {', '.join(unknown)}", file=sys.stderr)
        return 2
    try:
        opts = project_options(a.path, a.config, offline=True, external="none")
    except ConfigError as e:
        print(f"vibeaudit: {e}", file=sys.stderr)
        return 2
    opts.excludes += a.exclude
    plan = fix.plan(a.path, rules, opts)
    if a.apply:
        written = plan.apply()
        for rel in written:
            print(f"vibeaudit: fixed {rel}", file=sys.stderr)
    else:
        write_raw(plan.diff())
    fixable = [(f, r) for f, r in plan.skipped if f.rule_id in fix.FIXERS]
    if not a.quiet:
        for f, reason in fixable:
            print(f"vibeaudit: not fixed: {f.rule_id} {f.file}:{f.line}: {reason}", file=sys.stderr)
    verb = "applied" if a.apply else "proposed"
    print(f"vibeaudit: {len(plan.fixed)} fixes {verb} in {len(plan.changes)} files; {len(fixable)} findings of fixable "
          f"rules could not be rewritten; {len(plan.skipped) - len(fixable)} findings have no codemod.", file=sys.stderr)
    if a.llm:
        from .llm import LLMError, Provider

        try:
            provider = Provider(a.llm, a.llm_model)
        except LLMError as e:
            print(f"vibeaudit: {e}", file=sys.stderr)
            return 2
        text, n = fix.patches(Path(a.path), plan.skipped, provider, max(0, a.llm_max_requests),
                              lambda m: print(f"vibeaudit: {m}", file=sys.stderr))
        if n:
            Path(a.patch).write_bytes(text.encode("utf-8"))
            print(f"vibeaudit: wrote {n} model-generated patches to {a.patch}; review it, then `git apply {a.patch}`",
                  file=sys.stderr)
        else:
            print("vibeaudit: the model produced no usable patch", file=sys.stderr)
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
        default = f"vibeaudit-report.{EXTENSIONS.get(fmt, '')}"
        if fmt == "compliance":
            framework, _, path = path.partition(":")
            fmt, default = f"compliance:{framework.lower()}", f"vibeaudit-compliance-{framework.lower()}.html"
            if fmt not in RENDERERS:
                print(f"vibeaudit: unknown compliance framework {framework!r} (use {', '.join(compliance.FRAMEWORKS)})", file=sys.stderr)
                return 2
        if fmt not in RENDERERS:
            print(f"vibeaudit: unknown report format {fmt!r} (use json, sarif, md, html, prompt, badge, junit, codeclimate, compliance:FRAMEWORK)", file=sys.stderr)
            return 2
        reports.append((fmt, path or default))
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
                   cache=not a.no_cache, include_preview=bool(pick(a.include_preview, "include_preview", False)),
                   gate_severe_preview=False if a.no_gate_severe_preview else bool(cfg.get("gate_severe_preview", True)))
    if cfg_path:
        log(f"using settings from {cfg_path}")
    regression = None
    if a.fail_on_regression is not None:
        from .scanner import read_baseline

        got = read_baseline(baseline) if baseline else None
        if a.fail_on_regression < 0 or got is None or got[1] is None:
            print("vibeaudit: --fail-on-regression needs N >= 0 and a --baseline JSON report with a score "
                  "(write one with --write-baseline or --report json)", file=sys.stderr)
            return 2
        # the score is the whole project's: scan without hiding anything, then hide for the report
        regression = (got[0], got[1], opts.changes)
        opts.baseline, opts.changes = None, None
    try:
        if pick(a.monorepo, "monorepo", False):
            from . import monorepo

            res: Result = monorepo.scan(a.path, opts)
        else:
            res = scan(a.path, opts)
    except KeyboardInterrupt:
        return 130
    if regression is not None:
        from .gitdiff import keep

        known, base_score, only = regression
        full_score = res.score
        res.findings = [f for f in res.findings if f.fingerprint not in known and (only is None or keep(only, f.file, f.line))]
        res.meta["score_whole_project"], res.meta["baseline_score"] = full_score, base_score
        if only is not None:
            res.meta["changed_files"] = len(only)
        drop = base_score - full_score
        print(f"vibeaudit: whole-project score {full_score}, baseline {base_score} "
              f"({'down ' + str(drop) if drop > 0 else 'no drop'}; allowed {a.fail_on_regression})", file=sys.stderr)
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
    if fail_on != "none" and any(at_least(f.severity, fail_on) for f in res.gating):  # preview rules excluded
        return 1
    if regression is not None and res.meta["baseline_score"] - res.meta["score_whole_project"] > a.fail_on_regression:
        return 1
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    _reconfigure_streams()
    parser = build_parser()
    a = parser.parse_args(argv)
    if a.command == "rules":
        return cmd_rules(a.format)
    if a.command == "explain":
        return cmd_explain(a)
    if a.command == "studio":
        from . import studio
        from .config import project_options

        if not os.path.isdir(a.path):
            print(f"vibeaudit: not a directory: {a.path}", file=sys.stderr)
            return 2
        if not 0 <= a.port <= 65535:
            print("vibeaudit: --port must be between 0 and 65535", file=sys.stderr)
            return 2
        try:
            opts = project_options(a.path, a.config, offline=True, external="none")
        except ConfigError as e:
            print(f"vibeaudit: {e}", file=sys.stderr)
            return 2
        return studio.main(a.path, opts, a.port, not a.no_browser)
    if a.command == "routes":
        return cmd_routes(a)
    if a.command == "lsp":
        from .lsp import main as lsp_main

        return lsp_main()
    if a.command == "mcp":
        from .mcp_server import main as mcp_main

        return mcp_main()
    if a.command == "scan":
        return cmd_scan(a)
    if a.command == "fix":
        return cmd_fix(a)
    if a.command == "review":
        from . import review
        from .config import project_options

        if not os.path.isdir(a.path):
            print(f"vibeaudit: not a directory: {a.path}", file=sys.stderr)
            return 2
        try:
            opts = project_options(a.path, a.config, offline=True, external="none")
        except ConfigError as e:
            print(f"vibeaudit: {e}", file=sys.stderr)
            return 2
        opts.excludes += a.exclude
        return review.run(a.path, a.diff, opts, a.post, max(0, a.max_comments), print,
                          lambda m: print(f"vibeaudit: {m}", file=sys.stderr))
    if a.command == "watch":
        from . import watch

        if not os.path.isdir(a.path):
            print(f"vibeaudit: not a directory: {a.path}", file=sys.stderr)
            return 2
        try:
            opts = watch.main_options(a.path, a.config, a.exclude, a.min_severity)
        except ConfigError as e:
            print(f"vibeaudit: {e}", file=sys.stderr)
            return 2
        return watch.run(a.path, opts, sys.stdout, max(0.1, a.interval))
    if a.command == "update":
        return cmd_update(a)
    if a.command == "feedback":
        return cmd_feedback(a)
    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
