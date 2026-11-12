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


# Per-file steps that can be replayed on the next scan of the same Project. Their findings (and the routes
# they publish through Guard.publish) depend only on the files they read (recorded through files.READS), on
# their plain arguments and, for the steps in NEEDS_CONTEXT, on a value the scanner sets in StepMemo.context
# that sums up the project-wide state they read (call graph, auth middleware, settings). Other steps build
# state for later steps or read state derived from every file in ways not captured here, so they always run.
REPLAYABLE = frozenset({"secret scan", "UI checks", "data checks", "JavaScript checks", "Python checks",
                        "API file checks", "agent file checks", "JavaScript completeness checks"})
NEEDS_CONTEXT = frozenset({"JavaScript checks", "Python checks"})


class StepMemo:
    """Findings of replayable steps from the previous scan of a long-lived Project (vibeaudit watch)."""

    def __init__(self) -> None:
        self.entries: Dict[Tuple[Any, ...], Tuple[Dict[str, Any], List[Any], List[Tuple[str, Any]]]] = {}
        self.capture: Optional[List[Any]] = None
        self.effects: Optional[List[Tuple[str, Any]]] = None  # (sink, object) published by the running step
        self.context: Dict[str, Any] = {}  # phase -> hashable summary of the project-wide state it reads
        self.sinks: Dict[str, List[Any]] = {}  # sink name -> this scan's list (routes)
        self.values: Dict[tuple, Any] = {}  # value dependencies already computed in this scan
        self.ran_steps: set = set()  # (phase, file) of the replayable steps that ran (not replayed) in this scan
        self.emit: Optional[Callable[[Any], None]] = None
        self.project: Any = None
        self.replayed = 0
        self.ran = 0

    def clear(self) -> None:
        self.entries.clear()

    def start_scan(self) -> None:
        self.context, self.sinks, self.values, self.ran_steps = {}, {}, {}, set()

    def value(self, key: tuple) -> Any:
        """The current value of a recorded value dependency, computed once per scan (it cannot change
        during one)."""
        from . import files

        if key not in self.values:
            self.values[key] = files.VALUES[key[0]](self.project, *key[1:])
        return self.values[key]

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
        # also inside a project-wide step (it is not replayed itself); never inside a step being recorded
        if memo is not None and phase in REPLAYABLE and memo.capture is None \
                and (phase not in NEEDS_CONTEXT or phase in memo.context):
            return self._memoized(memo, where, phase, fn, args)
        return self._run(where, phase, fn, *args)

    def publish(self, sink: str, target: List[Any], obj: Any) -> None:
        """Append obj to a list that later steps read (routes); a replayed step publishes it again."""
        target.append(obj)
        memo = self.memo
        if memo is not None:
            memo.sinks[sink] = target
            if memo.effects is not None:
                memo.effects.append((sink, copy.deepcopy(obj)))

    def sink(self, name: str, target: List[Any]) -> None:
        """Register this scan's list for a sink before any step that publishes to it can be replayed."""
        if self.memo is not None:
            self.memo.sinks[name] = target

    def _memoized(self, memo: StepMemo, where: str, phase: str, fn: Callable, args: tuple):
        from . import files

        key = (phase, where, memo.context.get(phase)) + tuple(a for a in args if isinstance(a, (bool, int, type(None))))
        hit = memo.entries.get(key)
        if hit is not None and all(memo.value(k) == v if isinstance(k, tuple)
                                   else memo.project._by_rel.get(k) is v for k, v in hit[0].items()) \
                and all(sink in memo.sinks for sink, _obj in hit[2]):
            memo.replayed += 1
            for f in hit[1]:
                memo.emit(copy.copy(f))  # type: ignore[misc]
            for sink, obj in hit[2]:
                memo.sinks[sink].append(copy.deepcopy(obj))
            return None
        memo.ran += 1
        memo.ran_steps.add((phase, where))
        problems = len(self.skipped) + len(self.internal_errors)
        # the step's own file and any file passed in are inputs even when the step only uses text handed to it
        reads = {a.rel: a for a in args if isinstance(a, files.SourceFile)}
        own = memo.project._by_rel.get(where)
        if own is not None:
            reads[where] = own
        memo.capture, memo.effects, files.READS = [], [], reads
        try:
            result = self._run(where, phase, fn, *args)
            if len(self.skipped) + len(self.internal_errors) == problems:  # a stopped step is not remembered
                memo.entries[key] = (files.READS, memo.capture, memo.effects)
            return result
        finally:
            memo.capture, memo.effects, files.READS = None, None, None

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
