"""Parallel two-wave multi-core execution for independent static analysis stages."""
from __future__ import annotations

import concurrent.futures
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import heuristics as H
from . import rpcscan, store
from .aiscan import AiScanner
from .contracts import ContractScanner
from .csharp import CsScanner
from .dartscan import DartScanner
from .datascan import DataScanner
from .elixirscan import ElixirScanner
from .files import Project
from .goscan import GoScanner
from .guard import GUARD
from .jsscan import JsScanner
from .jvm import JvmScanner
from .model import Finding, Route
from .phpscan import PhpScanner
from .polyscan import PolyScanner
from .projectscan import ProjectScanner
from .pyscan import PyScanner
from .qualityscan import QualityScanner
from .relscan import ReliabilityScanner
from .rubyscan import RubyScanner
from .rustscan import RustScanner
from .secretscan import SecretScanner
from .swiftscan import SwiftScanner
from .uiscan import UiScanner
from .xxescan import XxeScanner
from .goscan import go_views
from .lexer import js_views, py_views

PARALLEL_MIN_FILES = 64
MAX_WORKERS = 4
WAVE1_TASKS = ("js", "py_jvm", "other_langs", "secrets")
WAVE2_TASKS = ("project", "quality_ui", "data_rel_ai_contracts")


def _prime_file_state(project: Project) -> None:
    """Rebuild the per-file state wave-1 scanners leave on each SourceFile (comment/string-blanked views and the
    JS client flag). Wave-2 checks read it; a sequential scan shares one Project so it is always there, but a
    worker builds a fresh Project and would otherwise fall back to raw text or skip the file."""
    js = JsScanner(project, lambda _f: None)
    for sf in project.files:
        text = sf.text
        if text is None:
            continue
        if sf.kind in ("js", "html"):
            sf.cache["views"] = sf.cache["js_views"] = v = js_views(text)
            sf.is_client = js.is_client(sf, v)
        elif sf.kind == "py":
            sf.cache["views"] = sf.cache["py_views"] = py_views(text)
        elif sf.kind == "go":
            sf.cache["views"] = sf.cache["go_views"] = go_views(text)


@dataclass
class ParallelOutcome:
    """Result and diagnostic metadata from attempting multi-process analysis."""

    ok: bool
    findings: List[Finding] = field(default_factory=list)
    routes: List[Route] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    internal_errors: List[str] = field(default_factory=list)
    fallback_reason: Optional[str] = None
    failed_task: Optional[str] = None
    error: Optional[str] = None


def resolve_jobs(jobs: int) -> int:
    """Resolve user-supplied `--jobs` (0 -> auto up to 4 workers, else >= 1)."""
    if jobs == 0:
        return min(os.cpu_count() or 1, MAX_WORKERS)
    return max(1, jobs)


def _run_wave_task(
    task_name: str,
    root_str: str,
    worker_opts: Dict[str, Any],
    routes: Optional[List[Route]] = None,
) -> Tuple[str, List[Finding], List[Route], List[str], List[str]]:
    """Execute one wave task inside a worker process."""
    GUARD.reset(float(worker_opts["file_timeout"]))
    H.CUSTOM.reset(
        list(worker_opts["auth_helpers"]),
        list(worker_opts["sanitizers"]),
        list(worker_opts["public_paths"]),
    )
    previous_cache = store.ENABLED
    store.ENABLED = bool(worker_opts["cache"])
    try:
        project = Project(
            Path(root_str),
            list(worker_opts["excludes"]),
            int(worker_opts["max_file_bytes"]),
        )
        raw: List[Finding] = []
        emit = raw.append
        found_routes: List[Route] = []
        if task_name in WAVE2_TASKS:
            GUARD.run("<project>", "file views", _prime_file_state, project)
        if task_name == "js":
            found_routes.extend(JsScanner(project, emit).run())
        elif task_name == "py_jvm":
            found_routes.extend(PyScanner(project, emit).run() + JvmScanner(project, emit).run())
        elif task_name == "other_langs":
            found_routes.extend(GoScanner(project, emit).run())
            found_routes.extend(RustScanner(project, emit).run())
            found_routes.extend(CsScanner(project, emit).run())
            found_routes.extend(PhpScanner(project, emit).run())
            found_routes.extend(RubyScanner(project, emit).run())
            found_routes.extend(SwiftScanner(project, emit).run())
            found_routes.extend(ElixirScanner(project, emit).run())
            DartScanner(project, emit).run()
            XxeScanner(project, emit).run()
            found_routes.extend(PolyScanner(project, emit).run())
            found_routes.extend(rpcscan.routes(project))
        elif task_name == "secrets":
            SecretScanner(project, emit).run()
        elif task_name == "project":
            ProjectScanner(project, emit, routes or []).run()
        elif task_name == "quality_ui":
            QualityScanner(project, emit).run()
            UiScanner(project, emit).run()
        elif task_name == "data_rel_ai_contracts":
            all_routes = routes or []
            DataScanner(project, emit, all_routes).run()
            ReliabilityScanner(project, emit, all_routes).run()
            AiScanner(project, emit, all_routes).run()
            ContractScanner(project, emit, all_routes).run()
        return task_name, raw, found_routes, list(GUARD.skipped), list(GUARD.internal_errors)
    finally:
        store.ENABLED = previous_cache


def run_parallel(
    project: Project,
    opts: Any,
    jobs: int,
) -> ParallelOutcome:
    """Run built-in Wave 1 and Wave 2 analyzers in parallel across up to 4 processes.

    When worker execution or pool creation fails, discards any partial parallel results and returns
    `ParallelOutcome(ok=False, ...)` with diagnostics so callers fall back cleanly to sequential mode.
    """
    main_file = getattr(sys.modules.get("__main__"), "__file__", None)
    if main_file in (None, "<stdin>", "<string>"):
        return ParallelOutcome(ok=False, fallback_reason="non_file_main")
    worker_opts: Dict[str, Any] = {
        "excludes": list(opts.excludes),
        "max_file_bytes": int(opts.max_file_bytes),
        "file_timeout": float(opts.file_timeout),
        "auth_helpers": list(opts.auth_helpers),
        "sanitizers": list(opts.sanitizers),
        "public_paths": list(opts.public_paths),
        "cache": bool(opts.cache and store.ENABLED),
    }
    root_str = str(project.root)
    workers = min(max(1, jobs), MAX_WORKERS)
    raw: List[Finding] = []
    all_routes: List[Route] = []
    skipped: List[str] = []
    internal_errors: List[str] = []

    def _collect_wave(
        futs: Dict[str, concurrent.futures.Future],
    ) -> Tuple[Optional[Dict[str, Tuple[str, List[Finding], List[Route], List[str], List[str]]]], Optional[Tuple[str, Exception]]]:
        results: Dict[str, Tuple[str, List[Finding], List[Route], List[str], List[str]]] = {}
        for name, fut in futs.items():
            try:
                results[name] = fut.result()
            except Exception as exc:
                for pending in futs.values():
                    pending.cancel()
                return None, (name, exc)
        return results, None

    try:
        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as pool:
            wave1_futs = {
                name: pool.submit(_run_wave_task, name, root_str, worker_opts, None)
                for name in WAVE1_TASKS
            }
            wave1_results, wave1_err = _collect_wave(wave1_futs)
            if wave1_err is not None or wave1_results is None:
                task_name, exc = wave1_err or ("wave1", RuntimeError("unknown wave 1 failure"))
                return ParallelOutcome(
                    ok=False,
                    fallback_reason="worker_error",
                    failed_task=task_name,
                    error=f"parallel worker task {task_name!r} failed ({type(exc).__name__}: {exc}); fell back to sequential execution",
                )
            for name in WAVE1_TASKS:
                _t, w_raw, w_routes, w_skip, w_err = wave1_results[name]
                raw.extend(w_raw)
                all_routes.extend(w_routes)
                skipped.extend(w_skip)
                internal_errors.extend(w_err)

            wave2_futs = {
                name: pool.submit(_run_wave_task, name, root_str, worker_opts, all_routes)
                for name in WAVE2_TASKS
            }
            wave2_results, wave2_err = _collect_wave(wave2_futs)
            if wave2_err is not None or wave2_results is None:
                task_name, exc = wave2_err or ("wave2", RuntimeError("unknown wave 2 failure"))
                return ParallelOutcome(
                    ok=False,
                    fallback_reason="worker_error",
                    failed_task=task_name,
                    error=f"parallel worker task {task_name!r} failed ({type(exc).__name__}: {exc}); fell back to sequential execution",
                )
            for name in WAVE2_TASKS:
                _t, w_raw, _w_routes, w_skip, w_err = wave2_results[name]
                raw.extend(w_raw)
                skipped.extend(w_skip)
                internal_errors.extend(w_err)
    except Exception as exc:
        return ParallelOutcome(
            ok=False,
            fallback_reason="pool_error",
            error=f"parallel worker pool failed ({type(exc).__name__}: {exc}); fell back to sequential execution",
        )
    return ParallelOutcome(
        ok=True,
        findings=raw,
        routes=all_routes,
        skipped=skipped,
        internal_errors=internal_errors,
    )
