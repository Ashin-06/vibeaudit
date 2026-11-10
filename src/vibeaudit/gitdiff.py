"""Which lines changed: for pre-commit hooks (--staged) and pull requests (--diff REV).

The whole project is still analysed, because auth middleware, imported helpers and data flow live in
files that did not change. Only findings on added or modified lines are reported.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Dict, Optional, Set

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

# rel path -> changed line numbers in the new version, or None for "every line" (a new untracked file)
Changes = Dict[str, Optional[Set[int]]]


class DiffError(Exception):
    pass


def _git(root: Path, *args: str) -> str:
    try:
        out = subprocess.run(["git", "-c", "core.quotePath=false", "-C", str(root), *args],
                             capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        raise DiffError(f"git is not available: {e}") from None
    if out.returncode != 0:
        raise DiffError(out.stderr.decode("utf-8", "replace").strip() or "git failed")
    return out.stdout.decode("utf-8", "replace")


def parse_diff(text: str) -> Changes:
    changes: Changes = {}
    current: Optional[str] = None
    for line in text.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith('"') and path.endswith('"'):  # git quotes paths with quotes or backslashes
                path = path[1:-1].replace('\\"', '"').replace("\\\\", "\\")
            current = None if path == "/dev/null" else path
            if current is not None:
                changes.setdefault(current, set())
            continue
        m = HUNK.match(line)
        if m and current is not None:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            lines = changes[current]
            if lines is not None:
                lines.update(range(start, start + count))
    return changes


def changed(root: Path, staged: bool = False, base: Optional[str] = None) -> Changes:
    if _git(root, "rev-parse", "--is-inside-work-tree").strip() != "true":
        raise DiffError("not a git repository")
    common = ["--relative", "-U0", "--no-color", "--no-ext-diff", "--no-prefix", "--diff-filter=ACMR"]
    if staged:
        return parse_diff(_git(root, "diff", "--cached", *common))
    assert base is not None
    try:
        point = _git(root, "merge-base", base, "HEAD").strip()
    except DiffError:
        point = base  # no common history (or base is a plain commit): compare directly
    changes = parse_diff(_git(root, "diff", *common, point))
    for rel in _git(root, "ls-files", "--others", "--exclude-standard").splitlines():
        if rel.strip():
            changes[rel.strip()] = None  # a new file that is not committed yet: every line is new
    return changes


def keep(changes: Changes, file: str, line: int) -> bool:
    if file not in changes:
        return False
    lines = changes[file]
    return lines is None or line == 0 or line in lines
