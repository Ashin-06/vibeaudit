"""Parallel two-wave multi-core execution for independent static analysis stages."""
from __future__ import annotations

import concurrent.futures
import os
import sys
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

PARALLEL_MIN_FILES = 64
MAX_WORKERS = 4
WAVE1_TASKS = ("js", "py_jvm", "other_langs", "secrets")
WAVE2_TASKS = ("project", "quality_ui", "data_rel_ai_contracts")


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
) -> Optional[Tuple[List[Finding], List[Route], List[str], List[str]]]:
    """Run built-in Wave 1 and Wave 2 analyzers in parallel across up to 4 processes.

    Returns None when process pool creation is unavailable so callers can fall back to sequential mode.
    """
    main_file = getattr(sys.modules.get("__main__"), "__file__", None)
    if main_file in (None, "<stdin>", "<string>"):
        return None
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

    try:
        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as pool:
            wave1_futs = {
                name: pool.submit(_run_wave_task, name, root_str, worker_opts, None)
                for name in WAVE1_TASKS
            }
            wave1_results = {name: fut.result() for name, fut in wave1_futs.items()}
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
            wave2_results = {name: fut.result() for name, fut in wave2_futs.items()}
            for name in WAVE2_TASKS:
                _t, w_raw, _w_routes, w_skip, w_err = wave2_results[name]
                raw.extend(w_raw)
                skipped.extend(w_skip)
                internal_errors.extend(w_err)
    except (OSError, PermissionError, RuntimeError, concurrent.futures.BrokenExecutor):
        return None
    return raw, all_routes, skipped, internal_errors
