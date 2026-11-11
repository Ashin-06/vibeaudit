"""Per-file isolation and a cooperative time budget.

A repository is untrusted input. One malformed or hostile file must neither crash the whole scan nor
hang it. Every per-file phase runs through `GUARD.run`; long loops call `GUARD.tick()` (directly or via
`finditer`), which raises once the file's budget is spent. The budget is cooperative: it is checked
between regex matches and AST statements, and every module-level regex is tested for linear behaviour
(tests/test_redos.py), so a single step cannot run away.
"""
from __future__ import annotations

import copy
import re
import time
import traceback
from typing import Any, Callable, Dict, Iterator, List, Optional, Pattern, Tuple, Union


class FileTimeout(Exception):
    pass


# Per-file steps whose only effect is emitting findings, and whose findings depend only on the files they read
# (recorded through files.READS) and on their plain arguments. Other steps also build state for later steps
# (routes, call graphs, report-once sets) or read state derived from every file, so they always run.
REPLAYABLE = frozenset({"secret scan", "UI checks", "data checks"})


class StepMemo:
    """Findings of replayable steps from the previous scan of a long-lived Project (vibeaudit watch)."""

    def __init__(self) -> None:
        self.entries: Dict[Tuple[Any, ...], Tuple[Dict[str, Any], List[Any]]] = {}
        self.capture: Optional[List[Any]] = None
        self.emit: Optional[Callable[[Any], None]] = None
        self.project: Any = None
        self.replayed = 0
        self.ran = 0

    def clear(self) -> None:
        self.entries.clear()

    def record(self, finding: Any) -> None:
        if self.capture is not None:
            self.capture.append(copy.copy(finding))  # before finalize() fills in and changes the original


class Guard:
    def __init__(self) -> None:
        self.memo: Optional[StepMemo] = None
        self.budget = 30.0
        self.deadline: Optional[float] = None
        self.skipped: List[str] = []
        self.internal_errors: List[str] = []

    def reset(self, budget: float) -> None:
        self.budget = budget
        self.deadline = None
        self.skipped = []
        self.internal_errors = []

    def tick(self) -> None:
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise FileTimeout()

    def run(self, where: str, phase: str, fn: Callable, *args):
        """Run fn(*args) for one file (or one project-wide step); never raise."""
        memo = self.memo
        if memo is not None and self.deadline is None and phase in REPLAYABLE and memo.capture is None:
            return self._memoized(memo, where, phase, fn, args)
        return self._run(where, phase, fn, *args)

    def _memoized(self, memo: StepMemo, where: str, phase: str, fn: Callable, args: tuple):
        from . import files

        key = (phase, where) + tuple(a for a in args if isinstance(a, (bool, int, type(None))))
        hit = memo.entries.get(key)
        if hit is not None and all(memo.project._by_rel.get(rel) is sf for rel, sf in hit[0].items()):
            memo.replayed += 1
            for f in hit[1]:
                memo.emit(copy.copy(f))  # type: ignore[misc]
            return None
        memo.ran += 1
        problems = len(self.skipped) + len(self.internal_errors)
        # the step's own file and any file passed in are inputs even when the step only uses text handed to it
        reads = {a.rel: a for a in args if isinstance(a, files.SourceFile)}
        own = memo.project._by_rel.get(where)
        if own is not None:
            reads[where] = own
        memo.capture, files.READS = [], reads
        try:
            result = self._run(where, phase, fn, *args)
            if len(self.skipped) + len(self.internal_errors) == problems:  # a stopped step is not remembered
                memo.entries[key] = (files.READS, memo.capture)
            return result
        finally:
            memo.capture, files.READS = None, None

    def _run(self, where: str, phase: str, fn: Callable, *args):
        outer = self.deadline
        if outer is None:
            self.deadline = time.monotonic() + self.budget
        try:
            return fn(*args)
        except FileTimeout:
            self.skipped.append(f"{where}: {phase} took longer than {self.budget:g}s and was stopped")
        except RecursionError:
            self.skipped.append(f"{where}: {phase} skipped, the code is too deeply nested")
        except MemoryError:
            self.skipped.append(f"{where}: {phase} skipped, out of memory")
        except Exception as e:  # noqa: BLE001 - isolation is the point; the error is reported, not hidden
            frame = traceback.extract_tb(e.__traceback__)[-1]
            self.internal_errors.append(
                f"{where}: {phase}: {type(e).__name__}: {str(e)[:200]} (at {frame.filename.rsplit('vibeaudit', 1)[-1]}:{frame.lineno})")
        finally:
            if outer is None:
                self.deadline = None
        return None


GUARD = Guard()


def finditer(pattern: Union[str, Pattern[str]], text: str, flags: int = 0) -> Iterator["re.Match[str]"]:
    """re.finditer that respects the current file's time budget."""
    it = re.finditer(pattern, text, flags) if isinstance(pattern, str) else pattern.finditer(text)
    for m in it:
        GUARD.tick()
        yield m
