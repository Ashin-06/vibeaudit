"""Fail if any tracked text file (or the given files) contains non-ASCII or control characters."""
import subprocess
import sys
from pathlib import Path

ALLOWED = {9, 10, 13}


def check(paths):
    bad = []
    for p in paths:
        path = Path(p)
        if not path.is_file() or path.suffix in (".gz",):
            continue
        data = path.read_bytes()
        for i, b in enumerate(data):
            if b > 126 or (b < 32 and b not in ALLOWED):
                line = data[:i].count(b"\n") + 1
                bad.append(f"{p}:{line}: byte 0x{b:02x}")
                break
    return bad


if __name__ == "__main__":
    files = sys.argv[1:] or subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout.split()
    problems = check(files)
    print("\n".join(problems) or f"ok: {len(files)} files are plain ASCII")
    sys.exit(1 if problems else 0)
