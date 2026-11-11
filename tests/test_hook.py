"""The pre-commit fast path (`vibeaudit-hook`): secrets on staged lines only, from the staged content."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from vibeaudit import hook

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

KEY = "sk-" + "proj-" + "aB3dE5fG7hJ9kL2mN4pQ6rS8tU" * 2
LEAK = f'OPENAI_API_KEY = "{KEY}"\n'


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "core.autocrlf=false", *args],
                   cwd=root, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / "app.py").write_text("x = 1\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "init")
    return tmp_path


def run(root: Path, capsys, *args: str):
    code = hook.main([str(root), *args])
    out, err = capsys.readouterr()
    return code, out, err


def test_staged_secret_blocks_the_commit(repo, capsys):
    (repo / "app.py").write_text("x = 1\n" + LEAK)
    git(repo, "add", "app.py")
    code, out, err = run(repo, capsys)
    assert code == 1 and "app.py:2: critical SEC001" in out and "commit blocked" in err


def test_only_added_lines_and_only_staged_content(repo, capsys):
    (repo / "old.py").write_text(LEAK)
    git(repo, "add", "old.py")
    git(repo, "commit", "-q", "-m", "an old leak")
    (repo / "old.py").write_text(LEAK + "y = 2\n")  # the old leak is not on a staged line
    git(repo, "add", "old.py")
    assert run(repo, capsys)[0] == 0
    (repo / "new.py").write_text(LEAK)  # in the working tree but not staged
    assert run(repo, capsys)[0] == 0
    git(repo, "add", "new.py")
    (repo / "new.py").write_text("clean = True\n")  # staged leak, cleaned only in the working tree
    code, out, _ = run(repo, capsys)
    assert code == 1 and "new.py:1:" in out


def test_ignores_config_and_tests(repo, capsys):
    (repo / "a.py").write_text(f'K = "{KEY}"  # vibeaudit: ignore[SEC001]\n')
    (repo / "tests").mkdir()
    (repo / "tests" / "test_x.py").write_text('password = "hunter2hunter2"\n')
    git(repo, "add", "-A")
    assert run(repo, capsys)[0] == 0
    (repo / "b.py").write_text(LEAK)
    (repo / ".vibeaudit.toml").write_text('disable = ["SEC001"]\n')
    git(repo, "add", "-A")
    assert run(repo, capsys)[0] == 0
    assert run(repo, capsys, "--fail-on", "none")[0] == 0


def test_crlf_unicode_and_renames(repo, capsys):
    (repo / "w.py").write_bytes(("# é中\r\n" + LEAK.replace("\n", "\r\n")).encode("utf-8"))
    git(repo, "add", "w.py")
    code, out, _ = run(repo, capsys)
    assert code == 1 and "w.py:2:" in out
    git(repo, "commit", "-q", "-m", "w")
    git(repo, "mv", "w.py", "moved dir name.py")
    assert run(repo, capsys)[0] == 0  # a rename adds no line


def test_agrees_with_the_full_staged_scan(repo, capsys):
    from vibeaudit.gitdiff import changed
    from vibeaudit.scanner import Options, scan

    (repo / "web").mkdir()
    (repo / "web" / "client.ts").write_text(f'const k = "{KEY}";\nexport default k;\n')
    (repo / "app.py").write_text("x = 1\n" + 'DATABASE_URL = "postgres://admin:Zq8wX2vR7nP4tL9@db.example.com/app"\n')
    git(repo, "add", "-A")
    full = scan(str(repo), Options(offline=True, external="none", changes=changed(repo, staged=True))).findings
    expected = sorted((f.file, f.line, f.rule_id) for f in full if f.rule_id.startswith("SEC"))
    fast = hook.check(repo, hook.staged(repo), {})
    assert sorted((f.file, f.line, f.rule_id) for f in fast) == expected and expected


def test_not_a_repository(tmp_path, capsys):
    assert run(tmp_path, capsys)[0] == 2


def test_parse_handles_quoted_paths_and_no_newline():
    diff = ('diff --git "a/x\\"y.py" "b/x\\"y.py"\nnew file mode 100644\n--- /dev/null\n+++ "x\\"y.py"\n@@ -0,0 +1,2 @@\n'
            "+a = 1\n+b = 2\n\\ No newline at end of file\n")
    assert hook.parse(diff) == {'x"y.py': ("a = 1\nb = 2\n", {1, 2})}


def test_latency_on_a_typical_commit(tmp_path):
    """Wall time of the hook process on a 3-file commit in a 300-file repository. The stress job (Linux) sets
    VIBEAUDIT_HOOK_BUDGET_MS=150; elsewhere only a loose bound applies (Windows starts processes slowly)."""
    import os
    import statistics
    import sys
    import time

    git(tmp_path, "init", "-q")
    for i in range(300):
        sub = tmp_path / f"pkg{i % 10}"
        sub.mkdir(exist_ok=True)
        (sub / f"mod{i}.py").write_text("".join(f"def f{j}(x):\n    return x * {j}\n\n\n" for j in range(30)))
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "base")
    for i in (3, 150, 299):
        with open(tmp_path / f"pkg{i % 10}" / f"mod{i}.py", "a") as fh:
            fh.write("\ndef added(x):\n    return x - 1\n")
    git(tmp_path, "add", "-A")
    env = dict(os.environ)
    times = []
    for _ in range(7):
        t = time.perf_counter()
        done = subprocess.run([sys.executable, "-m", "vibeaudit.hook"], cwd=tmp_path, env=env, capture_output=True)
        times.append((time.perf_counter() - t) * 1000)
        assert done.returncode == 0, done.stderr
    t = time.perf_counter()
    subprocess.run([sys.executable, "-c", "pass"], env=env, capture_output=True)
    start = (time.perf_counter() - t) * 1000
    median = statistics.median(times)
    print(f"\npre-commit fast path: median {median:.0f} ms over {len(times)} runs (python start {start:.0f} ms)")
    budget = float(os.environ.get("VIBEAUDIT_HOOK_BUDGET_MS", "2000"))
    assert median < budget, f"{median:.0f} ms is over the {budget:.0f} ms budget"
