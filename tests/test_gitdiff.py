"""--staged and --diff: findings are limited to changed lines while the whole project is analysed."""
import json
import shutil
import subprocess

import pytest

from vibeaudit.cli import main
from vibeaudit.gitdiff import keep, parse_diff

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "user.email", "t@example.com")
    git(tmp_path, "config", "user.name", "t")
    (tmp_path / "app.py").write_text("import os\n\n\ndef old(x):\n    os.system('ls ' + x)\n")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "base")
    return tmp_path


def findings(tmp_path, capsys, *args):
    code = main(["scan", str(tmp_path), "--offline", "--external", "none", "--report", "json:-", *args])
    out = capsys.readouterr().out
    return code, sorted((f["file"], f["line"], f["rule_id"]) for f in json.loads(out)["findings"]) if out.strip() else []


def test_parse_diff_handles_additions_deletions_and_quoted_paths():
    text = ("+++ app.py\n@@ -3,0 +4,2 @@\n+a\n+b\n@@ -9 +11 @@\n-x\n+y\n@@ -20,3 +22,0 @@\n"
            "+++ /dev/null\n@@ -1 +0,0 @@\n+++ \"we\\\"ird.py\"\n@@ -0,0 +1 @@\n")
    assert parse_diff(text) == {"app.py": {4, 5, 11}, 'we"ird.py': {1}}
    assert keep({"a.py": None}, "a.py", 7) and keep({"a.py": {2}}, "a.py", 0) and not keep({"a.py": {2}}, "a.py", 3)


def test_staged_reports_only_staged_lines(tmp_path, capsys):
    root = repo(tmp_path)
    (root / "app.py").write_text("import os\n\n\ndef old(x):\n    os.system('ls ' + x)\n\n\ndef new(y):\n    eval(y)\n")
    git(root, "add", "app.py")
    (root / "unstaged.py").write_text("eval(z)\n")
    assert findings(root, capsys)[1] == [("app.py", 5, "BE002"), ("app.py", 9, "BE003"), ("unstaged.py", 1, "BE003")]
    assert findings(root, capsys, "--staged")[1] == [("app.py", 9, "BE003")]


def test_diff_against_a_base_includes_commits_working_tree_and_new_files(tmp_path, capsys):
    root = repo(tmp_path)
    git(root, "checkout", "-q", "-b", "feature")
    (root / "app.py").write_text("import os\n\n\ndef old(x):\n    os.system('ls ' + x)\n    eval(x)\n")
    git(root, "commit", "-qam", "change")
    (root / "fresh.py").write_text("exec(code)\n")
    assert findings(root, capsys, "--diff", "main")[1] == [("app.py", 6, "BE003"), ("fresh.py", 1, "BE003")]


def test_a_cross_file_fact_still_counts_in_diff_mode(tmp_path, capsys):
    root = repo(tmp_path)
    (root / "auth.py").write_text("from typing import Annotated\nfrom fastapi import Depends\nAuthedUser = Annotated[User, Depends(auth_user)]\n")
    git(root, "add", ".")
    git(root, "commit", "-qm", "auth")
    (root / "api.py").write_text("@router.delete('/{aid}')\nasync def remove(user: AuthedUser, aid: str):\n    await storage.delete(aid)\n")
    rules = [r for f, _ln, r in findings(root, capsys, "--diff", "HEAD")[1] if f == "api.py"]
    assert "AUTH001" not in rules and "AUTH003" in rules  # authenticated through an unchanged file; ownership unchecked


def test_errors(tmp_path, capsys):
    plain = tmp_path / "plain"
    plain.mkdir()
    assert main(["scan", str(plain), "--staged"]) == 2
    assert "cannot compute changes" in capsys.readouterr().err
    (tmp_path / "r").mkdir()
    root = repo(tmp_path / "r")
    assert main(["scan", str(root), "--staged", "--diff", "main"]) == 2
    assert main(["scan", str(root), "--diff", "no-such-branch"]) == 2
