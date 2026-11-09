"""Every regular expression the scanner compiles must run in roughly linear time on hostile input.

A repository is untrusted input. One file shaped to trigger catastrophic backtracking must not be able to
hang a scan, so each module-level pattern is timed against long runs of the characters that typically
cause it. Inline patterns are exercised end to end by tests/test_fuzz.py.
"""
import importlib
import pkgutil
import re
import time

import pytest

import vibeaudit

LIMIT_SECONDS = 1.5
SIZE = 40000


def _patterns():
    out = []
    for info in pkgutil.iter_modules(vibeaudit.__path__):
        if info.name == "__main__":
            continue
        mod = importlib.import_module(f"vibeaudit.{info.name}")
        for name, value in vars(mod).items():
            if isinstance(value, re.Pattern):
                out.append((f"{info.name}.{name}", value))
            elif isinstance(value, (list, tuple)):
                for i, item in enumerate(value):
                    pat = item[1] if isinstance(item, tuple) and len(item) > 1 else item
                    if isinstance(pat, re.Pattern):
                        out.append((f"{info.name}.{name}[{i}]", pat))
    return out


def _hostile_inputs():
    runs = ["a", "A", "_", "1", " ", "\t", ".", "-", "/", "\\", "'", '"', "`", "(", "{", "[", ",", ":", "=", "$", "@", "#", "<", "\n"]
    out = [ch * SIZE for ch in runs]
    out += [
        "a." * (SIZE // 2), "a-" * (SIZE // 2), "a " * (SIZE // 2), "a=" * (SIZE // 2), "a:" * (SIZE // 2), "aa_" * (SIZE // 3),
        "password" * (SIZE // 8), "secret_" * (SIZE // 7), "token " * (SIZE // 6), "key=" * (SIZE // 4),
        "req.body." * (SIZE // 9), "'x' + " * (SIZE // 6), "${" * (SIZE // 2), "{{" * (SIZE // 2), "(( " * (SIZE // 3),
        "role: " * (SIZE // 6), "You are a " * (SIZE // 10), "create policy p on t " * (SIZE // 21),
        "allow read, " * (SIZE // 12), "sk-" + "a" * SIZE, "eyJ" + "a" * SIZE + ".eyJ" + "a" * 100,
        "postgres://" + "a" * SIZE, "process.env." + "A" * SIZE, "NEXT_PUBLIC_" + "A_" * (SIZE // 2),
        "TODO " + "x" * SIZE, "function " + "isAuth" * (SIZE // 6), "const isAdmin = (" + "a, " * (SIZE // 3),
        "@" + "a." * (SIZE // 2), "Depends(" + "a" * SIZE, "-----BEGIN " + "A " * (SIZE // 2),
    ]
    return out


PATTERNS = _patterns()
HOSTILE = _hostile_inputs()


def test_patterns_were_collected():
    assert len(PATTERNS) > 40


@pytest.mark.parametrize("name,pattern", PATTERNS, ids=[n for n, _ in PATTERNS])
def test_pattern_is_linear_on_hostile_input(name, pattern):
    for text in HOSTILE:
        start = time.perf_counter()
        for _ in pattern.finditer(text):
            pass
        elapsed = time.perf_counter() - start
        assert elapsed < LIMIT_SECONDS, f"{name} took {elapsed:.1f}s on {text[:30]!r}... ({len(text)} chars)"
