"""`vibeaudit watch`: re-scan a project whenever a file changes and print what appeared or went away.

The Project is kept between scans. `Project.refresh()` keeps every unchanged file with what the scanners
cached for it (text, parse trees, lexer views, exported names), and a StepMemo replays the findings of
per-file steps whose inputs did not change (guard.REPLAYABLE). Steps that build project-wide state (routes,
call graphs) run on every scan, so the result is always the same as a fresh `vibeaudit scan`.

Known limits: polling with os.stat every --interval seconds (no inotify/FSEvents dependency); the JS and Python
check steps re-run on every change, which bounds the speed-up (about 35% on a 300-file repo). Making them
replayable needs a fingerprint of the project-wide state they read (call graph, auth mounts).
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, TextIO

from .files import Project
from .guard import StepMemo
from .model import Finding
from .scanner import Options, scan


def _line(f: Finding) -> str:
    preview = " (preview)" if f.preview else ""
    return f"{f.severity:8} {f.rule_id:8} {f.file}:{f.line}  {f.title}{preview}"


class Watcher:
    def __init__(self, root: str, opts: Options):
        self.root = root
        self.opts = opts
        self.project = Project(Path(root), opts.excludes, opts.max_file_bytes)
        self.project.step_memo = StepMemo()
        self.findings: Dict[str, Finding] = {}

    def scan(self) -> "tuple[List[Finding], List[Finding], float]":
        """Scan (again); returns the findings that appeared, those that went away, and the seconds it took."""
        t = time.perf_counter()
        res = scan(self.root, self.opts, self.project)
        now = {f.fingerprint: f for f in res.findings}
        added = [f for k, f in now.items() if k not in self.findings]
        gone = [f for k, f in self.findings.items() if k not in now]
        self.findings = now
        return added, gone, time.perf_counter() - t

    def changed(self) -> List[str]:
        return sorted(self.project.refresh())


def run(root: str, opts: Options, out: TextIO, interval: float = 1.0,
        keep_going: Callable[[], bool] = lambda: True, sleep: Callable[[float], None] = time.sleep) -> int:
    w = Watcher(root, opts)
    added, _gone, took = w.scan()
    for f in sorted(added, key=lambda f: (f.file, f.line)):
        out.write(_line(f) + "\n")
    out.write(f"vibeaudit: {len(w.findings)} findings in {w.project.root} ({took * 1000:.0f} ms). "
              f"Watching for changes; press Ctrl+C to stop.\n")
    out.flush()
    try:
        while keep_going():
            sleep(interval)
            changed = w.changed()
            if not changed:
                continue
            added, gone, took = w.scan()
            what = ", ".join(changed[:3]) + (f" and {len(changed) - 3} more" if len(changed) > 3 else "")
            out.write(f"\nchanged: {what}\n")
            for f in sorted(added, key=lambda f: (f.file, f.line)):
                out.write("+ " + _line(f) + "\n")
            for f in sorted(gone, key=lambda f: (f.file, f.line)):
                out.write("- " + _line(f) + "\n")
            out.write(f"vibeaudit: {len(w.findings)} findings, {len(added)} new, {len(gone)} fixed "
                      f"(re-scan {took * 1000:.0f} ms)\n")
            out.flush()
    except KeyboardInterrupt:
        pass
    return 0


def main_options(path: str, config: Optional[str], excludes: List[str], min_severity: Optional[str]) -> Options:
    from .config import project_options

    overrides = {"offline": True, "external": "none"}
    if min_severity:
        overrides["min_severity"] = min_severity
    opts = project_options(path, config, **overrides)
    opts.excludes += excludes
    return opts
