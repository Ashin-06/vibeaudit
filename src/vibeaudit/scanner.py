"""Run every check over a project and return a cleaned-up, prioritised result."""
from __future__ import annotations

import hashlib
import re
import threading
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from . import correlate, coverage, external, parallel, parse, plugins, rpcscan, scancache, store
from .deps import DepScanner
from . import heuristics as H
from .files import Project
from .guard import GUARD
from .jsscan import JsScanner
from .csharp import CsScanner
from .jvm import JvmScanner
from .model import SEVERITY_RANK, SUPPRESS, TEST_FILE_RULES, Finding, at_least
from .projectscan import ProjectScanner
from .goscan import GoScanner
from .dartscan import DartScanner
from .elixirscan import ElixirScanner
from .phpscan import PhpScanner
from .rubyscan import RubyScanner
from .rustscan import RustScanner
from .swiftscan import SwiftScanner
from .xxescan import XxeScanner
from .polyscan import POLY_SEVERE, POLY_STABLE, PolyScanner, _lang_of as poly_lang
from .pyscan import PyScanner
from .qualityscan import QualityScanner
from .datascan import DataScanner
from .relscan import ReliabilityScanner
from .aiscan import AiScanner
from .uiscan import UiScanner
from .contracts import ContractScanner
from .report import Result
from .rules import RULES
from .secretscan import SecretScanner, scan_git_history
from .store import loads_json

FOLLOWED = "(passed in through the call at "

STACK_MARKERS = {
    "flask": "Flask", "fastapi": "FastAPI", "django": "Django", "streamlit": "Streamlit", "gradio": "Gradio",
    "openai": "OpenAI SDK", "anthropic": "Anthropic SDK", "google-genai": "Google GenAI SDK",
    "google-generativeai": "Google GenAI SDK", "langchain": "LangChain", "llama-index": "LlamaIndex",
    "litellm": "LiteLLM", "crewai": "CrewAI", "next": "Next.js", "react": "React", "vue": "Vue",
    "svelte": "Svelte", "@sveltejs/kit": "SvelteKit", "express": "Express", "fastify": "Fastify", "hono": "Hono",
    "@supabase/supabase-js": "Supabase", "supabase": "Supabase", "firebase": "Firebase", "@prisma/client": "Prisma",
    "mongoose": "MongoDB", "drizzle-orm": "Drizzle", "stripe": "Stripe", "ai": "Vercel AI SDK",
    "@anthropic-ai/sdk": "Anthropic SDK", "@google/generative-ai": "Google GenAI SDK", "@google/genai": "Google GenAI SDK",
    "@langchain/core": "LangChain", "@modelcontextprotocol/sdk": "MCP",
}


@dataclass
class Options:
    offline: bool = False
    excludes: List[str] = field(default_factory=list)
    disabled: Set[str] = field(default_factory=set)
    min_severity: str = "info"
    external: str = "auto"  # auto | none | comma list
    baseline: Optional[str] = None
    max_file_bytes: int = 1_000_000
    llm: Optional[str] = None
    llm_model: Optional[str] = None
    llm_review: bool = False
    llm_max_requests: int = 10
    file_timeout: float = 30.0
    scan_timeout: Optional[float] = None
    auth_helpers: List[str] = field(default_factory=list)
    sanitizers: List[str] = field(default_factory=list)
    public_paths: List[str] = field(default_factory=list)
    changes: Optional[dict] = None  # from gitdiff.changed(): report only findings on changed lines
    feedback: bool = True  # hide findings marked false positive in .vibeaudit/feedback.json
    cache: bool = True  # read and write the user cache (registry, OSV, LLM verdicts) during this scan
    include_preview: bool = False  # count findings of preview rules toward --fail-on and the score
    gate_severe_preview: bool = True  # count severe preview rules (injection, XSS) even without include_preview
    history: bool = False  # scan recent git history commits for high-confidence leaked credentials
    history_commits: int = 200
    no_config: bool = False
    score_model: str = "diminishing-v2"
    jobs: int = 1
    profile: Optional[str] = None
    config_path: Optional[str] = None
    config_disabled: List[str] = field(default_factory=list)
    log: Callable[[str], None] = lambda s: None


def _stack(project: Project) -> List[str]:
    found = []
    names = set(project.all_js_deps())
    for f in project.files:
        if re.search(r"(?:^|/)(?:requirements[\w.-]*\.txt|pyproject\.toml)$", f.rel) and f.text:
            names |= {m.lower() for m in re.findall(r"(?m)^\s*\"?([A-Za-z0-9][A-Za-z0-9._-]*)", f.text)}
        elif f.rel.rsplit("/", 1)[-1] == "go.mod" and f.text:
            if "Go" not in found:
                found.append("Go")
            for mod, lbl in (("github.com/gin-gonic/gin", "Gin"), ("github.com/gofiber/fiber", "Fiber"),
                             ("github.com/go-chi/chi", "Chi"), ("gorm.io/gorm", "GORM")):
                if mod in f.text and lbl not in found:
                    found.append(lbl)
        elif f.rel.rsplit("/", 1)[-1] in ("pom.xml", "build.gradle", "build.gradle.kts") and f.text:
            for mod, lbl in (("spring-boot", "Spring Boot"), ("quarkus", "Quarkus")):
                if mod in f.text and lbl not in found:
                    found.append(lbl)
        elif f.rel.lower().endswith(".csproj") and f.text:
            for mod, lbl in (("Microsoft.AspNetCore", "ASP.NET Core"), ("EntityFrameworkCore", "EF Core")):
                if mod in f.text and lbl not in found:
                    found.append(lbl)
        elif f.rel.rsplit("/", 1)[-1] == "Cargo.toml" and f.text:
            for mod, lbl in (("actix-web", "Actix"), ("axum", "Axum")):
                if mod in f.text and lbl not in found:
                    found.append(lbl)
        elif f.rel.rsplit("/", 1)[-1] == "composer.json" and f.text:
            for mod, lbl in (("laravel/framework", "Laravel"), ("symfony/", "Symfony")):
                if mod in f.text and lbl not in found:
                    found.append(lbl)
        elif f.rel.rsplit("/", 1)[-1] == "pubspec.yaml" and f.text:
            if "Dart" not in found:
                found.append("Dart")
            for mod, lbl in (("flutter:", "Flutter"), ("firebase_core", "Firebase"), ("cloud_firestore", "Firebase")):
                if mod in f.text and lbl not in found:
                    found.append(lbl)
        elif f.rel.rsplit("/", 1)[-1] == "Package.swift" and f.text:
            if "Swift" not in found:
                found.append("Swift")
            if "vapor" in f.text.lower() and "Vapor" not in found:
                found.append("Vapor")
        elif f.rel.rsplit("/", 1)[-1] == "mix.exs" and f.text:
            if "Elixir" not in found:
                found.append("Elixir")
            if ":phoenix" in f.text.lower() and "Phoenix" not in found:
                found.append("Phoenix")
    for key, label in STACK_MARKERS.items():
        if key in names and label not in found:
            found.append(label)
    return found


def suppressed(project: Project, f: Finding) -> bool:
    sf = project.get(f.file)
    if not sf or not f.line:
        return False
    # parsed once per line: one long line with thousands of findings must not be searched thousands of times
    memo: dict = sf.cache.setdefault("suppress", {})
    for ln in (f.line, f.line - 1):
        if ln not in memo:
            m = SUPPRESS.search(sf.line(ln))
            memo[ln] = None if m is None else ("*" if not m.group(1) else {x.strip().upper() for x in m.group(1).split(",")})
        rules = memo[ln]
        if rules == "*" or (rules and f.rule_id.upper() in rules):
            return True
    return False


_SCAN_LOCK = threading.RLock()


def scan(root: str, opts: Optional[Options] = None, project: Optional[Project] = None) -> Result:
    """Scan `root` (a project directory or a single file). Without `opts`, the project's own .vibeaudit.toml /
    [tool.vibeaudit] settings apply.

    Safe to call from several threads: scans run one at a time, because the time budget, the custom auth
    helpers and the cache switch are process-wide (scans are CPU-bound, so threads would not speed them up).

    `project` lets a long-lived caller (`vibeaudit watch`, the language server) reuse files it already read and
    parsed: pass the same Project again after `Project.refresh()`."""
    single_target: Optional[Path] = None
    if project is None:
        cand = Path(root)
        if cand.is_file():
            single_target = cand.resolve()
    if opts is None:
        from .config import project_options

        opts = project_options(str(single_target.parent) if single_target is not None else root)
    with _SCAN_LOCK, warnings.catch_warnings():
        # ast.parse() warns about the scanned code (invalid escape sequences); that is not vibeaudit's output
        warnings.simplefilter("ignore", SyntaxWarning)
        warnings.filterwarnings("ignore", "invalid escape sequence", DeprecationWarning)  # the same before 3.12
        if opts.cache:
            return _scan(root, opts, project, single_target=single_target)
        from . import store

        previous, store.ENABLED = store.ENABLED, False
        try:  # only this scan skips the cache; a long-lived caller keeps its own setting
            return _scan(root, opts, project, single_target=single_target)
        finally:
            store.ENABLED = previous


def _scan(root: str, opts: Options, project: Optional[Project] = None,
          single_target: Optional[Path] = None) -> Result:
    start = time.time()
    GUARD.reset(opts.file_timeout)
    H.CUSTOM.reset(opts.auth_helpers, opts.sanitizers, opts.public_paths)
    if project is None:
        if single_target is not None:
            project = Project(single_target.parent, opts.excludes, opts.max_file_bytes, single_file=single_target)
        else:
            project = Project(Path(root), opts.excludes, opts.max_file_bytes)
    raw: List[Finding] = []
    memo = project.step_memo
    if memo is None:
        emit = raw.append
    else:
        def emit(f: Finding) -> None:
            raw.append(f)
            memo.record(f)

        memo.emit, memo.project, memo.replayed, memo.ran = raw.append, project, 0, 0
        memo.start_scan()
    GUARD.memo = memo
    try:
        return _scan_project(root, opts, project, raw, emit, start)
    finally:
        GUARD.memo = None


def _scan_project(root: str, opts: Options, project: Project, raw: List[Finding], emit: Callable[[Finding], None],
                  start: float) -> Result:
    notes: List[str] = []
    deadline = (time.perf_counter() + opts.scan_timeout) if (opts.scan_timeout and opts.scan_timeout > 0) else None
    scan_timed_out = False

    def _expired() -> bool:
        nonlocal scan_timed_out
        if deadline is not None and time.perf_counter() >= deadline:
            scan_timed_out = True
            return True
        return False

    js_routes: list = []
    py_routes: list = []
    go_routes: list = []
    poly_routes: list = []
    all_routes: list = []
    history_info = None
    ran: List[str] = []
    parser_modes = parse.mode()
    effective_jobs = parallel.resolve_jobs(opts.jobs)
    has_overlays = bool(getattr(project, "overlays", None))
    single_rel = getattr(project, "single_file", None)
    can_cache = opts.cache and store.ENABLED and project.step_memo is None and deadline is None and not has_overlays and single_rel is None
    snap_fp = scancache.project_fingerprint(project, opts, parser_modes) if can_cache else ""
    cached_hit = False
    parallel_used = False
    parallel_fallback: Optional[Dict[str, Any]] = None
    save_info: Dict[str, Any] = {"written": False, "write_ms": 0.0, "snapshot_bytes": 0, "cached_findings": 0}
    if can_cache:
        loaded, cache_info = scancache.load_snapshot_info(project.root, snap_fp)
    else:
        loaded, cache_info = None, {
            "hit": False, "reason": "disabled", "read_ms": 0.0, "snapshot_bytes": 0, "cached_findings": 0,
        }
    if loaded is not None:
        cached_hit = True
        c_raw, c_routes = loaded
        raw.extend(c_raw)
        all_routes.extend(c_routes)
    else:
        if effective_jobs > 1 and len(project.files) >= parallel.PARALLEL_MIN_FILES and project.step_memo is None and deadline is None and not has_overlays:
            par_out = parallel.run_parallel(project, opts, effective_jobs)
            if par_out.ok:
                raw.extend(par_out.findings)
                all_routes.extend(par_out.routes)
                GUARD.skipped.extend(par_out.skipped)
                GUARD.internal_errors.extend(par_out.internal_errors)
                parallel_used = True
            elif par_out.error:
                opts.log(f"warning: {par_out.error}")
                notes.append(par_out.error)
                parallel_fallback = {
                    "reason": par_out.fallback_reason,
                    "task": par_out.failed_task,
                    "error": par_out.error,
                }
        if not parallel_used:
            stages = [
                lambda: js_routes.extend(JsScanner(project, emit).run()),
                lambda: py_routes.extend(PyScanner(project, emit).run() + JvmScanner(project, emit).run()),
                lambda: go_routes.extend(GoScanner(project, emit).run()),
                lambda: go_routes.extend(RustScanner(project, emit).run()),
                lambda: go_routes.extend(CsScanner(project, emit).run()),
                lambda: go_routes.extend(PhpScanner(project, emit).run()),
                lambda: go_routes.extend(RubyScanner(project, emit).run()),
                lambda: go_routes.extend(SwiftScanner(project, emit).run()),
                lambda: go_routes.extend(ElixirScanner(project, emit).run()),
                lambda: DartScanner(project, emit).run(),
                lambda: XxeScanner(project, emit).run(),
                lambda: poly_routes.extend(PolyScanner(project, emit).run()),
                lambda: all_routes.extend(js_routes + py_routes + go_routes + poly_routes + rpcscan.routes(project)),
                lambda: SecretScanner(project, emit).run(),
            ]
            for stage in stages:
                if _expired():
                    break
                stage()
            if not all_routes and (js_routes or py_routes or go_routes or poly_routes):
                all_routes = js_routes + py_routes + go_routes + poly_routes
            post_route_builtin = [
                lambda: ProjectScanner(project, emit, all_routes).run(),
                lambda: QualityScanner(project, emit).run(),
                lambda: DataScanner(project, emit, all_routes).run(),
                lambda: ReliabilityScanner(project, emit, all_routes).run(),
                lambda: AiScanner(project, emit, all_routes).run(),
                lambda: UiScanner(project, emit).run(),
                lambda: ContractScanner(project, emit, all_routes).run(),
            ]
            for stage in post_route_builtin:
                if _expired():
                    break
                stage()
        if can_cache and not scan_timed_out and not GUARD.skipped and not GUARD.internal_errors:
            save_info = scancache.save_snapshot_info(project.root, snap_fp, list(raw), list(all_routes))
    if opts.history and not _expired():
        history_info = GUARD.run("<project>", "git history secrets", scan_git_history, project.root, emit, opts.history_commits)
    if not _expired():
        plugins.run(project, all_routes, emit)
    if not _expired():
        deps = DepScanner(project, emit, opts.offline)
        GUARD.run("<project>", "dependency checks", deps.run)
        notes += deps.notes

    ext_configs: Dict[str, List[str]] = {}
    ext_coverage: Dict[str, Dict[str, str]] = {}
    if opts.external != "none" and not _expired():
        wanted = external.TOOLS if opts.external == "auto" else [t.strip() for t in opts.external.split(",") if t.strip()]
        detected = external.detect_repo_configs(project.root)
        ext_configs = {t: detected[t] for t in wanted if t in detected}
        if ext_configs and not opts.no_config:
            desc = ", ".join(f"{t}: {', '.join(paths)}" for t, paths in sorted(ext_configs.items()))
            msg = f"Repo-local external scanner config(s) detected ({desc}); they may suppress external findings (use --no-config to isolate untrusted repos)."
            notes.append(msg)
            opts.log(f"warning: {msg}")
        for tool in wanted:
            if _expired():
                break
            if tool not in external.TOOLS:
                notes.append(f"Unknown external tool {tool!r} ignored.")
                continue
            if opts.offline and tool in external.NEEDS_NETWORK:
                continue
            if not external.available(tool):
                if opts.external != "auto":
                    notes.append(f"{tool} is not installed; skipped.")
                continue
            opts.log(f"running {tool} ...")
            external.LAST_ISOLATION.pop(tool, None)
            if opts.no_config:
                res = GUARD.run("<project>", tool, external.run_tool, tool, project.root, True)
            else:
                res = GUARD.run("<project>", tool, external.run_tool, tool, project.root)
            if res is None:
                notes.append(f"{tool} failed to run or produced no readable output.")
                ext_coverage[tool] = {
                    "status": "failed",
                    "isolation": "none",
                    "detail": "failed to run or produced no readable output",
                }
                continue
            iso = external.LAST_ISOLATION.get(tool) or {
                "isolation": "full" if opts.no_config else "none",
                "detail": "",
            }
            tool_status = "partial" if iso["isolation"] == "partial" else "complete"
            ext_coverage[tool] = {
                "status": tool_status,
                "isolation": iso["isolation"],
                "detail": iso.get("detail", ""),
            }
            if iso["isolation"] == "partial":
                msg = f"{tool} isolation under --no-config is partial ({iso.get('detail') or 'repo ignore files may apply'})."
                notes.append(msg)
                opts.log(f"warning: {msg}")
            ran.append(tool)
            raw.extend(res)

    findings = finalize(project, raw, opts)
    if opts.changes is not None:
        from .gitdiff import keep

        findings = [f for f in findings if keep(opts.changes, f.file, f.line)]
    if single_rel is not None:
        findings = [f for f in findings if f.file == single_rel]
    hidden = 0
    demoted: Dict[str, Dict[str, object]] = {}
    if opts.feedback:
        from .feedback import false_positives, noisy_rules

        reviewed = false_positives(project.root)
        if reviewed:
            before = len(findings)
            findings = [f for f in findings if f.fingerprint not in reviewed]
            hidden = before - len(findings)
            if hidden:
                notes.append(f"{hidden} findings marked as false positives in .vibeaudit/feedback.json are hidden.")
        noisy = noisy_rules(project.root)
        if noisy:
            demoted_hits: Set[str] = set()
            for f in findings:
                if f.rule_id in noisy and not f.preview:
                    f.preview = True
                    f.gates_in_preview = False
                    demoted_hits.add(f.rule_id)
            for rule in sorted(demoted_hits):
                fp, total, rate = noisy[rule]
                demoted[rule] = {"false_positive": fp, "total": total, "rate": round(rate, 3)}
                notes.append(
                    f"{rule} was demoted to preview for this repository ({fp} of {total} reviewed findings, "
                    f"{rate:.0%}, were marked false positive in .vibeaudit/feedback.json)."
                )
    if GUARD.skipped:
        notes.append(f"{len(GUARD.skipped)} file checks were skipped (time budget or nesting); see meta.skipped.")
    if GUARD.internal_errors:
        notes.append(f"{len(GUARD.internal_errors)} internal errors; results may be incomplete. Please report them.")

    if opts.llm and not _expired():
        from . import llm
        try:
            provider = llm.Provider(opts.llm, opts.llm_model)
            llm.triage(project, findings, provider, opts.llm_max_requests, notes.append)
            if opts.llm_review and not _expired():
                risky = _risky_files(project, findings, all_routes)
                extra = llm.review(project, findings, risky, provider, opts.llm_max_requests, notes.append)
                findings = finalize(project, findings + extra, opts, already=True)
            notes.append(f"LLM ({provider.name}/{provider.model}) used {provider.requests} requests.")
        except llm.LLMError as e:
            notes.append(f"LLM checks skipped: {e}")

    if scan_timed_out:
        notes.append(f"Scan timed out after {opts.scan_timeout}s (--scan-timeout); remaining analyzers were skipped.")
    if len(project.files) == 0:
        notes.append("No files were scanned (directory is empty or all files were excluded).")
    if opts.config_disabled:
        dis_list = sorted(opts.config_disabled)
        notes.append(
            f"Project config disables {len(dis_list)} rule(s)/category(ies): {', '.join(dis_list)} "
            "(use --no-config to audit untrusted code)."
        )
    stack = _stack(project)
    if history_info and history_info.get("timeline"):
        current_pairs = {(f.file, f.rule_id) for f in findings if "git history" not in f.message}
        for entry in history_info["timeline"]:
            if (entry["file"], entry["rule_id"]) in current_pairs:
                entry["current_exposure"] = True
    cov = coverage.build(project, opts, GUARD.skipped, GUARD.internal_errors, parser_modes, history_info,
                         scan_timed_out=scan_timed_out, external_status=ext_coverage)
    scan_cache_meta: Dict[str, Any] = {
        "hit": cached_hit,
        "reason": cache_info["reason"],
        "jobs": effective_jobs,
        "parallel_used": parallel_used,
        "read_ms": cache_info["read_ms"],
        "write_ms": save_info["write_ms"],
        "snapshot_bytes": cache_info["snapshot_bytes"] if cached_hit else save_info["snapshot_bytes"],
        "cached_findings": cache_info["cached_findings"] if cached_hit else save_info["cached_findings"],
    }
    if parallel_fallback is not None:
        scan_cache_meta["parallel_fallback"] = parallel_fallback
    meta = {
        "files_scanned": len(project.files), "duration_seconds": round(time.time() - start, 2),
        **({"single_file": single_rel} if single_rel is not None else {}),
        **({"profile": opts.profile} if opts.profile else {}),
        "score_model": opts.score_model,
        "scan_cache": scan_cache_meta,
        "stack": stack, "external_tools": ran, "offline": opts.offline, "notes": notes,
        "routes_found": len(all_routes), "git": project.is_git,
        "skipped": list(GUARD.skipped), "internal_errors": list(GUARD.internal_errors),
        "feedback_hidden": hidden, "feedback_demoted": demoted, "include_preview": opts.include_preview,
        "gate_severe_preview": opts.gate_severe_preview, "disabled": sorted(opts.disabled),
        "config_disabled": sorted(opts.config_disabled),
        **({"external_configs_detected": ext_configs} if ext_configs else {}),
        "attack_paths": correlate.attack_paths(findings, all_routes),
        "ai_risk_profile": correlate.ai_risk_profile(findings),
        "coverage": cov,
    }
    if history_info is not None:
        meta["history"] = history_info
        meta["history_commits_scanned"] = history_info.get("commits_scanned", 0)
        h_status = history_info.get("status", "complete")
        if h_status == "truncated_commits":
            notes.append(f"Git history scan stopped after {history_info['commits_scanned']} commits (--history-commits limit); older history was not checked.")
        elif h_status == "truncated_size":
            notes.append("Git history scan stopped at the 20 MB patch stream limit; remaining commits were not checked.")
        elif h_status == "timeout":
            notes.append("Git history scan timed out before reaching older commits.")
        elif h_status == "git_error":
            notes.append("Git history scan failed; commit history was not checked.")
        elif h_status == "not_git":
            notes.append("Git history scan skipped: target directory has no .git repository.")
    if opts.changes is not None:
        meta["changed_files"] = len(opts.changes)
    res = Result(str(project.root), findings, meta, all_routes)
    if opts.baseline:
        base_info = read_baseline(opts.baseline)
        if base_info is not None and base_info[1] is not None:
            meta["baseline_score"] = base_info[1]
            if res.score is not None:
                meta["score_delta"] = res.score - base_info[1]
    return res


def _risky_files(project: Project, findings: List[Finding], routes) -> List[str]:
    score: Dict[str, int] = {}
    for r in routes:
        score[r.file] = score.get(r.file, 0) + 2 + (3 if r.calls_llm else 0)
    for f in findings:
        score[f.file] = score.get(f.file, 0) + 1
    return [f for f, _ in sorted(score.items(), key=lambda kv: -kv[1]) if project.get(f)][:5]


def read_baseline(path: str) -> "Optional[tuple[Set[str], Optional[int]]]":
    """The fingerprints in a JSON report used as a baseline, and its score (None in reports without one)."""
    try:
        data = loads_json(Path(path).read_text(encoding="utf-8"))
        fingerprints = {f["fingerprint"] for f in data.get("findings", []) if "fingerprint" in f}
    except (OSError, ValueError, AttributeError, TypeError):
        return None
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    score = summary.get("score")
    return fingerprints, (score if isinstance(score, int) and not isinstance(score, bool) else None)


def finalize(project: Project, raw: List[Finding], opts: Options, already: bool = False) -> List[Finding]:
    out: List[Finding] = []
    occurrences: dict = {}
    seen = set()
    builtin_locs = set()
    baseline: Set[str] = set()
    if opts.baseline:
        got = read_baseline(opts.baseline)
        if got is None:
            opts.log(f"could not read baseline {opts.baseline}")
        else:
            baseline = got[0]
    # a secret in an MCP config is reported once, by the more specific LLM014
    mcp_secrets = {(f.file, f.line) for f in raw if f.rule_id == "LLM014"}
    # built-in findings first so that duplicates from external tools are the ones dropped
    for f in sorted(raw, key=lambda x: x.source != "vibeaudit"):
        if f.rule_id.startswith("SEC") and (f.file, f.line) in mcp_secrets:
            continue
        meta = RULES.get(f.rule_id)
        if meta and not already:
            f.title = f.title or meta.title
            f.category = f.category or meta.category
            f.severity = f.severity or meta.severity
            f.why = f.why or meta.why
            f.fix = f.fix or meta.fix
            f.cwe = f.cwe or meta.cwe
            f.owasp = f.owasp or meta.owasp
        if meta is not None:
            f.preview = meta.preview
            f.gates_in_preview = meta.preview and meta.gates_in_preview
        if f.source == "vibeaudit" and poly_lang(f.file) and not f.rule_id.startswith(("SEC", "DEP")) \
                and (poly_lang(f.file), f.rule_id) not in POLY_STABLE:
            # Go, Java/Kotlin, C#, Rust and PHP stay preview until their held-out precision clears the bar
            # (STABILITY.md); injection and XSS still gate, as for other severe preview rules
            f.preview = True
            f.gates_in_preview = f.rule_id in POLY_SEVERE
        f.severity = f.severity or "medium"
        f.category = f.category or "backend"
        if f.rule_id in opts.disabled or (meta and meta.category in opts.disabled) or f.category in opts.disabled:
            continue
        sf = project.get(f.file)
        if sf is not None and (sf.is_test or sf.is_example) and f.rule_id not in TEST_FILE_RULES \
                and f.source == "vibeaudit":
            continue
        if not at_least(f.severity, opts.min_severity) or suppressed(project, f):
            continue
        key = (f.rule_id, f.file, f.line, f.message)
        if key in seen:
            continue
        loc = (f.file, f.line)
        if f.source not in ("vibeaudit", "llm-review", "plugin") and loc in builtin_locs:
            continue
        seen.add(key)
        if f.source == "vibeaudit":
            builtin_locs.add(loc)
        if not f.fingerprint:
            f.compute_fingerprint()
            # the same rule on two identical lines of one file (two `return True` stubs) must not share a
            # fingerprint, or baselining one would hide the other
            n = occurrences.get(f.fingerprint, 0)
            occurrences[f.fingerprint] = n + 1
            if n:
                f.fingerprint = hashlib.sha256(f"{f.fingerprint}#{n}".encode()).hexdigest()[:32]
        if f.fingerprint in baseline:
            continue
        out.append(f)
    # taint followed through a call (pyscan) replaces the plain finding of the same rule on the same line
    followed = {(f.rule_id, f.file, f.line) for f in out if FOLLOWED in f.message}
    out = [f for f in out if FOLLOWED in f.message or (f.rule_id, f.file, f.line) not in followed]
    out.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.category, f.file, f.line, f.rule_id))
    return out
