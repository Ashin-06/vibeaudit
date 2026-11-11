"""`vibeaudit-hook`: the pre-commit fast path. Checks the staged lines of a commit for secrets in well under
a second, without scanning the whole project.

`vibeaudit scan --staged` analyses the whole project (auth middleware, imported helpers and data flow live in
files that did not change) and reports findings on staged lines; on a medium project that takes seconds.
This hook runs only the secret checks, which need nothing but the file itself, on the staged content of the
changed files: one `git diff --cached` call gives both the staged text and the added lines. It imports only
what it uses, so most of its time is Python starting and git running.

Settings, inline `vibeaudit: ignore` comments, the baseline and feedback apply as for `scan`.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .files import (BINARY_EXTS, LOCKFILES, SKIP_DIRS, SourceFile, _generated, _matches,
                    read_ignore_file)
from .guard import GUARD
from .model import SEVERITIES, SUPPRESS, TEST_FILE_RULES, Finding, at_least

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
Staged = Dict[str, Tuple[str, Set[int]]]  # rel -> (staged text, added line numbers)


class HookError(Exception):
    pass


def staged(root: Path) -> Staged:
    """Every added, copied, modified or renamed file in the index: its staged text and the added lines."""
    try:
        out = subprocess.run(
            ["git", "-c", "core.quotePath=false", "-C", str(root), "diff", "--cached", "--no-color", "--no-ext-diff",
             "--no-prefix", "--relative", "--diff-filter=ACMR", "-U2147483647"],
            capture_output=True, stdin=subprocess.DEVNULL, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        raise HookError(f"git is not available: {e}") from None
    if out.returncode != 0:
        raise HookError(out.stderr.decode("utf-8", "replace").strip() or "git diff failed")
    return parse(out.stdout.decode("utf-8", "replace"))


def parse(diff: str) -> Staged:
    files: Staged = {}
    rel: Optional[str] = None
    lines: List[str] = []
    added: Set[int] = set()
    in_hunk = False

    def done() -> None:
        if rel is not None and added:
            files[rel] = ("\n".join(lines) + "\n", added)

    for raw in diff.split("\n"):
        if raw.startswith("diff --git "):
            done()
            rel, lines, added, in_hunk = None, [], set(), False
            continue
        if not in_hunk:
            if raw.startswith("+++ "):
                path = raw[4:]
                if path.startswith('"') and path.endswith('"'):
                    path = path[1:-1].replace('\\"', '"').replace("\\\\", "\\")
                rel = None if path == "/dev/null" else path
            elif raw.startswith("@@") and HUNK.match(raw):
                in_hunk = True
            continue
        if raw.startswith("+"):
            lines.append(raw[1:])
            added.add(len(lines))
        elif raw.startswith(" "):
            lines.append(raw[1:])
        elif raw.startswith("@@") and HUNK.match(raw):
            continue  # with unlimited context there is one hunk per file; tolerate more
    done()
    return files


class StagedProject:
    """The little of Project that the secret checks use: the staged files, plus production settings files
    from the working tree so that base settings overridden in production are recognised."""

    def __init__(self, root: Path, files: List[SourceFile]):
        self.root = root
        self.files = list(files)
        known = {f.rel for f in files}
        for f in files:
            if f.kind == "py" and re.search(r"(?:^|/)(?:settings|base|common)[\w]*\.py$", f.rel):
                folder = f.rel.rsplit("/", 1)[0] + "/" if "/" in f.rel else ""
                for name in ("production.py", "prod.py", "live.py"):
                    rel = folder + name
                    if rel not in known and (root / rel).is_file():
                        self.files.append(SourceFile(root, rel))
                        known.add(rel)
        self._by_rel = {f.rel: f for f in self.files}

    def get(self, rel: str) -> Optional[SourceFile]:
        return self._by_rel.get(rel)


def _skipped(rel: str, excludes: List[str]) -> bool:
    parts = rel.split("/")
    return (any(p in SKIP_DIRS for p in parts[:-1]) or os.path.splitext(rel)[1].lower() in BINARY_EXTS
            or parts[-1] in LOCKFILES or _matches(rel, excludes))


def check(root: Path, changes: Staged, cfg: dict) -> List[Finding]:
    from .rules import RULES
    from .secretscan import SecretScanner

    excludes = list(cfg.get("exclude", [])) + read_ignore_file(root / ".vibeauditignore") + ["vibeaudit-report*"]
    sfs = []
    for rel, (text, _added) in sorted(changes.items()):
        if not _skipped(rel, excludes):
            sfs.append(SourceFile.from_text(root, rel, text))
    project = StagedProject(root, sfs)
    raw: List[Finding] = []
    scanner = SecretScanner(project, raw.append)  # type: ignore[arg-type]
    GUARD.reset(float(cfg.get("file_timeout", 30.0)))  # type: ignore[arg-type]
    for sf in sfs:
        if sf.rel.endswith((".map", ".svg")):
            continue
        text = sf.text or ""
        bundle = sf.rel.endswith(".min.js") or (sf.kind in ("js", "html") and len(text) > 5000 and _generated(text, sf.kind))
        GUARD.run(sf.rel, "secret scan", scanner.scan_file, sf, text, bundle)
    disabled = {x.strip() for d in cfg.get("disable", []) for x in str(d).split(",") if x.strip()}
    min_sev = str(cfg.get("min_severity", "low"))
    out, seen = [], set()
    for f in raw:
        rule = RULES.get(f.rule_id)
        sf = project.get(f.file)
        if rule is None or sf is None or f.file not in changes or f.line not in changes[f.file][1]:
            continue
        f.severity = f.severity or rule.severity
        f.title, f.category, f.preview = rule.title, rule.category, rule.preview
        if f.rule_id in disabled or rule.category in disabled or not at_least(f.severity, min_sev):
            continue
        if (sf.is_test or sf.is_example) and f.rule_id not in TEST_FILE_RULES:
            continue
        if _suppressed(sf, f) or (f.rule_id, f.file, f.line, f.message) in seen:
            continue
        seen.add((f.rule_id, f.file, f.line, f.message))
        f.compute_fingerprint()
        out.append(f)
    hidden = _known(root, cfg)
    return sorted((f for f in out if f.fingerprint not in hidden), key=lambda f: (f.file, f.line, f.rule_id))


def _suppressed(sf: SourceFile, f: Finding) -> bool:
    for ln in (f.line, f.line - 1):
        m = SUPPRESS.search(sf.line(ln))
        if m and (not m.group(1) or f.rule_id.upper() in {x.strip().upper() for x in m.group(1).split(",")}):
            return True
    return False


def _known(root: Path, cfg: dict) -> Set[str]:
    """Fingerprints to hide: the baseline file and findings marked as false positives."""
    import json

    from .feedback import false_positives

    hidden = set(false_positives(root))
    if cfg.get("baseline"):
        try:
            data = json.loads((root / str(cfg["baseline"])).read_text(encoding="utf-8"))
            hidden |= {f["fingerprint"] for f in data.get("findings", []) if isinstance(f, dict) and "fingerprint" in f}
        except (OSError, ValueError, AttributeError, TypeError):
            pass
    return hidden


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="vibeaudit-hook",
                                description="Pre-commit fast path: check the staged lines for secrets (see vibeaudit scan --staged for every check).")
    p.add_argument("path", nargs="?", default=".", help="repository (default: current directory)")
    p.add_argument("--fail-on", default=None, choices=SEVERITIES[:4] + ["none"],
                   help="exit with code 1 if any finding is at least this severe (default: high)")
    p.add_argument("--config", metavar="FILE", help="read settings from this TOML file")
    a = p.parse_args(argv)
    root = Path(a.path).resolve()
    from .config import ConfigError, load

    try:
        cfg, _path = load(root, a.config)
        changes = staged(root)
    except (ConfigError, HookError) as e:
        print(f"vibeaudit: {e}", file=sys.stderr)
        return 2
    findings = check(root, changes, cfg)  # type: ignore[arg-type]
    fail_on = a.fail_on or str(cfg.get("fail_on", "high"))
    for f in findings:
        print(f"{f.file}:{f.line}: {f.severity} {f.rule_id} {f.title}: {f.message}")
    blocking = [f for f in findings if fail_on != "none" and not f.preview and at_least(f.severity, fail_on)]
    if findings:
        print(f"vibeaudit: {len(findings)} findings in {len(changes)} staged files"
              + (f"; commit blocked ({len(blocking)} at or above {fail_on})" if blocking else ""), file=sys.stderr)
    return 1 if blocking else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
