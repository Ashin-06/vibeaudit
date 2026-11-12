"""Monorepo mode (`vibeaudit scan --monorepo`): every package is scanned as a project of its own.

In a normal scan the whole repository is one project: a rate limiter, CSRF middleware or a dependency
declared in one package counts for every other package too. In monorepo mode each folder with its own
manifest (package.json, pyproject.toml, requirements*.txt, setup.py, setup.cfg, Pipfile) is scanned
separately, against its own manifest and with only its own code as evidence. Files outside every package
(root scripts, CI workflows, infrastructure) form one more unit. Folders under tests or examples are not
packages: they stay test code of the unit around them.

Three rules are about the repository rather than a package (CI configuration, the example env file and a
workspace lockfile live at the root): they come from one scan of the whole repository, which makes this mode
cost about two normal scans. Findings and routes get their package's path back, fingerprints are computed on the full path (so baselines
and feedback written by a normal scan still match), and the baseline, feedback and --diff/--staged filters
apply once to the merged result. The report lists every package with its own score.
"""
from __future__ import annotations

import dataclasses
import hashlib
import time
from pathlib import Path
from typing import Dict, List

from .files import EXAMPLE_PATH_RE, TEST_PATH_RE, Project, read_ignore_file
from .model import SEVERITY_RANK, Finding
from .report import Result

MANIFESTS = ("package.json", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile")
# Rules about the repository rather than a package: CI configuration and the example env file live at the root,
# and a workspace lockfile at the root locks every package. They come from one scan of the whole repository.
REPOSITORY_RULES = frozenset({"QA002", "DATA007", "DEP005"})


def _manifest(name: str) -> bool:
    return name in MANIFESTS or (name.startswith("requirements") and name.endswith((".txt", ".in")))


def package_dirs(project: Project) -> List[str]:
    """Folders (relative to the root, never the root itself) that have their own manifest."""
    dirs = set()
    for f in project.files:
        if "/" not in f.rel:
            continue
        folder, name = f.rel.rsplit("/", 1)
        if _manifest(name) and not TEST_PATH_RE.search(folder + "/x") and not EXAMPLE_PATH_RE.search(folder + "/x"):
            dirs.add(folder)
    return sorted(dirs)


def unit_of(rel: str, units: List[str]) -> str:
    """The deepest package containing `rel` ("" for files outside every package)."""
    best = ""
    for u in units:
        if u and rel.startswith(u + "/") and len(u) > len(best):
            best = u
    return best


def scan(root: str, opts) -> Result:
    from . import scanner

    start = time.time()
    base = Path(root).resolve()
    top = Project(base, opts.excludes, opts.max_file_bytes)
    pkgs = package_dirs(top)
    if not pkgs:
        res = scanner.scan(root, opts)
        res.meta["notes"] = list(res.meta.get("notes", [])) + ["Monorepo mode: no package folders found; scanned as one project."]
        res.meta["packages"] = []
        return res
    outer = list(opts.excludes) + read_ignore_file(base / ".vibeauditignore")
    # each unit alone: the filters that need the whole repository's paths run once, after merging
    sub = dataclasses.replace(opts, baseline=None, changes=None, feedback=False, llm=None, llm_review=False)
    findings: List[Finding] = [f for f in scanner.scan(root, sub).findings if f.rule_id in REPOSITORY_RULES]
    routes = []
    metas: Dict[str, dict] = {}
    for unit in [""] + pkgs:
        if unit:
            nested = [p[len(unit) + 1:] for p in pkgs if p.startswith(unit + "/")]
            project = Project(base / unit, nested, opts.max_file_bytes, outer=(unit + "/", outer))
        else:
            project = Project(base, list(opts.excludes) + pkgs, opts.max_file_bytes)
        if not project.files:
            continue
        res = scanner.scan(str(project.root), sub, project)
        prefix = unit + "/" if unit else ""
        for f in res.findings:
            f.file = prefix + f.file
        for r in res.routes:
            r.file = prefix + r.file
        findings += [f for f in res.findings if f.rule_id not in REPOSITORY_RULES]
        routes += res.routes
        metas[unit] = res.meta
    _fingerprint(findings)
    notes: List[str] = []
    hidden = 0
    if opts.baseline:
        got = scanner.read_baseline(opts.baseline)
        if got is None:
            opts.log(f"could not read baseline {opts.baseline}")
        else:
            findings = [f for f in findings if f.fingerprint not in got[0]]
    if opts.changes is not None:
        from .gitdiff import keep

        findings = [f for f in findings if keep(opts.changes, f.file, f.line)]
    if opts.feedback:
        from .feedback import false_positives

        reviewed = false_positives(base)
        before = len(findings)
        findings = [f for f in findings if f.fingerprint not in reviewed]
        hidden = before - len(findings)
        if hidden:
            notes.append(f"{hidden} findings marked as false positives in .vibeaudit/feedback.json are hidden.")
    if opts.llm:
        notes.append("LLM triage and review are not run in monorepo mode.")
    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.category, f.file, f.line, f.rule_id))
    packages = []
    for unit, m in metas.items():
        mine = [f for f in findings if unit_of(f.file, list(metas)) == unit]
        part = Result(str(base / unit), mine, {"include_preview": opts.include_preview,
                                               "gate_severe_preview": opts.gate_severe_preview})
        packages.append({"path": unit or ".", "files_scanned": m.get("files_scanned", 0), "findings": len(mine),
                         "score": part.score, "grade": part.grade, "stack": m.get("stack", [])})
        notes += [f"{unit or '.'}: {n}" for n in m.get("notes", [])]
    first = next(iter(metas.values()))
    meta = dict(first)
    meta.update({
        "files_scanned": sum(m.get("files_scanned", 0) for m in metas.values()),
        "duration_seconds": round(time.time() - start, 2),
        "stack": sorted({s for m in metas.values() for s in m.get("stack", [])}),
        "routes_found": len(routes), "git": top.is_git, "notes": notes, "feedback_hidden": hidden,
        "skipped": [s for m in metas.values() for s in m.get("skipped", [])],
        "internal_errors": [s for m in metas.values() for s in m.get("internal_errors", [])],
        "external_tools": sorted({t for m in metas.values() for t in m.get("external_tools", [])}),
        "monorepo": True, "packages": packages,
    })
    if opts.changes is not None:
        meta["changed_files"] = len(opts.changes)
    return Result(str(base), findings, meta, routes)


def _fingerprint(findings: List[Finding]) -> None:
    """Fingerprints on the repository-relative path, numbered like scanner.finalize() for identical lines."""
    seen: Dict[str, int] = {}
    for f in findings:
        f.fingerprint = ""
        fp = f.compute_fingerprint()
        n = seen.get(fp, 0)
        seen[fp] = n + 1
        if n:
            f.fingerprint = hashlib.sha256(f"{fp}#{n}".encode()).hexdigest()[:32]
