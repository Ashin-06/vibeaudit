"""Per-file isolation and a cooperative time budget.

A repository is untrusted input. One malformed or hostile file must neither crash the whole scan nor
hang it. Every per-file phase runs through `GUARD.run`; long loops call `GUARD.tick()` (directly or via
`finditer`), which raises once the file's budget is spent. The budget is cooperative: it is checked
between regex matches and AST statements, and every module-level regex is tested for linear behaviour
(tests/test_redos.py), so a single step cannot run away.
"""
from __future__ import annotations

import re
import time
import traceback
from typing import Callable, Iterator, List, Optional, Pattern, Union


class FileTimeout(Exception):
    pass


class Guard:
    def __init__(self) -> None:
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
