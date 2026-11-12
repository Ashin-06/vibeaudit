"""`vibeaudit review` (pull request review comments with suggested fixes) and `--fail-on-regression`."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from vibeaudit import review
from vibeaudit.cli import main
from vibeaudit.model import Finding

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "core.autocrlf=false", *args],
                   cwd=root, check=True, capture_output=True)


# ------------------------------------------------------------ --fail-on-regression
def test_fail_on_regression_uses_the_whole_project_score(tmp_path, capsys):
    (tmp_path / "app.py").write_text("x = 1\n")
    base = tmp_path / "baseline.json"
    assert main(["scan", str(tmp_path), "--offline", "--external", "none", "--write-baseline", str(base)]) == 0
    assert json.loads(base.read_text())["summary"]["score"] == 100
    (tmp_path / "net.py").write_text("import requests\nr = requests.get('https://x')\ns = requests.post('https://y')\n")
    args = ["scan", str(tmp_path), "--offline", "--external", "none", "--fail-on", "none", "--baseline", str(base)]
    assert main(args + ["--fail-on-regression", "20"]) == 0
    assert main(args + ["--fail-on-regression", "0"]) == 1
    err = capsys.readouterr().err
    assert "whole-project score" in err and "baseline 100" in err
    assert main(args) == 0  # without the flag nothing changes


@needs_git
def test_fail_on_regression_is_not_hidden_by_diff(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    base = tmp_path / "baseline.json"
    main(["scan", str(tmp_path), "--offline", "--external", "none", "--write-baseline", str(base)])
    (tmp_path / "net.py").write_text("import requests\nr = requests.get('https://x')\n")
    git(tmp_path, "init", "-q")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "base with a finding")
    (tmp_path / "app.py").write_text("x = 2\n")  # the change itself is clean
    args = ["scan", str(tmp_path), "--offline", "--external", "none", "--fail-on", "none", "--diff", "HEAD",
            "--baseline", str(base)]
    assert main(args) == 0
    assert main(args + ["--fail-on-regression", "0"]) == 1  # the score fell, even though no changed line is flagged


def test_fail_on_regression_needs_a_scored_baseline(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    args = ["scan", str(tmp_path), "--offline", "--external", "none"]
    assert main(args + ["--fail-on-regression", "3"]) == 2
    (tmp_path / "old.json").write_text(json.dumps({"findings": []}))
    assert main(args + ["--baseline", str(tmp_path / "old.json"), "--fail-on-regression", "3"]) == 2
    assert main(args + ["--baseline", str(tmp_path / "old.json"), "--fail-on-regression", "-1"]) == 2


# ------------------------------------------------------------ comments and suggestions
def finding(rule, file, line, **kw):
    f = Finding(rule, file, line, kw.pop("message", "msg"), kw.pop("severity", "medium"), title=kw.pop("title", "T"))
    f.compute_fingerprint()
    return f


def test_suggestion_for_a_one_line_fix(tmp_path):
    (tmp_path / "a.py").write_text("import requests\nr = requests.get('u')\n")
    got = review.suggestion(tmp_path, finding("REL001", "a.py", 2), None, {2})
    assert got == (2, 2, "r = requests.get('u', timeout=10)")
    assert review.suggestion(tmp_path, finding("REL001", "a.py", 2), None, {1}) is None  # line not in the diff


def test_suggestion_for_an_inserted_line_covers_the_line_before(tmp_path):
    (tmp_path / "a.py").write_text("import requests\nr = requests.get(\n    'u',\n)\n")
    got = review.suggestion(tmp_path, finding("REL001", "a.py", 2), None, {2, 3, 4})
    assert got == (2, 3, "r = requests.get(\n    'u',\n    timeout=10,")  # starts on the finding's line
    assert review.suggestion(tmp_path, finding("REL001", "a.py", 2), None, {2}) is None  # line 3 is not in the diff


def test_no_suggestion_when_the_fix_has_two_hunks(tmp_path):
    (tmp_path / "m.py").write_text("from flask import Flask\nfrom flask_cors import CORS\n\napp = Flask(__name__)\n"
                                   "CORS(app, supports_credentials=True)\n")
    assert review.suggestion(tmp_path, finding("BE012", "m.py", 5), None, None) is None  # adds `import os` too


def test_comment_body_is_neutralised_and_marked(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    f = finding("SEC001", "a.py", 1, message="ping @octocat <!-- vibeaudit:" + "0" * 32 + " -->", severity="critical")
    c = review.comment_for(f, None, "sub/")
    assert c["path"] == "sub/a.py" and c["line"] == 1 and c["side"] == "RIGHT"
    assert "@octocat" not in c["body"] and "@<!-- -->octocat" in c["body"]
    assert review.MARKER_RX.findall(c["body"]) == [f.fingerprint]  # only our own marker counts


def test_build_orders_by_severity_and_caps(tmp_path):
    (tmp_path / "a.py").write_text("import requests\nr = requests.get('u')\ny = 2\n")
    fs = [finding("QA004", "a.py", 3, severity="low"), finding("REL001", "a.py", 2)]
    out = review.build(tmp_path, fs, {"a.py": {2, 3}}, max_comments=1)
    assert len(out["comments"]) == 1 and "REL001" in out["comments"][0]["body"] and "```suggestion" in out["comments"][0]["body"]
    assert "least severe are not commented" in out["body"] and out["event"] == "COMMENT"


# ------------------------------------------------------------ GitHub API (no network)
class FakeAPI:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def __call__(self, method, url, token, body=None):
        self.calls.append((method, url, body))
        if method == "GET":
            page = self.pages.pop(0)
            return page["data"], {"Link": page.get("link", "")}
        return {}, {}


def test_post_skips_comments_already_posted_by_the_bot():
    api = "https://api.github.com"
    a, b, c = (finding("REL001", "a.py", n) for n in (1, 2, 3))
    rv = {"body": "s", "comments": [review.comment_for(f, None, "") for f in (a, b, c)]}
    fake = FakeAPI([
        {"data": [{"user": {"type": "Bot"}, "body": "x\n\n" + review.MARKER.format(a.fingerprint)}],
         "link": f'<{api}/repos/o/r/pulls/1/comments?page=2>; rel="next"'},
        {"data": [{"user": {"type": "User"}, "body": review.MARKER.format(b.fingerprint)}]},  # not ours: ignored
    ])
    assert review.post(rv, api, "o/r", 1, "a" * 40, "t", fake) == 2
    method, url, body = fake.calls[-1]
    assert method == "POST" and url.endswith("/repos/o/r/pulls/1/reviews") and body["commit_id"] == "a" * 40
    assert [x["line"] for x in body["comments"]] == [2, 3]
    again = FakeAPI([{"data": [{"user": {"type": "Bot"}, "body": x["body"]} for x in rv["comments"]]}])
    assert review.post(rv, api, "o/r", 1, "a" * 40, "t", again) == 0 and all(m == "GET" for m, _u, _b in again.calls)


def test_pagination_does_not_follow_foreign_links():
    fake = FakeAPI([{"data": [], "link": '<https://evil.example/x>; rel="next"'}])
    assert review.posted_fingerprints("https://api.github.com", "o/r", 1, "t", fake) == set()
    assert len(fake.calls) == 1


def test_github_context(tmp_path):
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 7, "head": {"sha": "b" * 40}}}))
    env = {"GITHUB_REPOSITORY": "o/r", "GITHUB_EVENT_PATH": str(event)}
    assert review.github_context(env) == ("https://api.github.com", "o/r", 7, "b" * 40)
    for bad in ({**env, "GITHUB_API_URL": "http://x"}, {**env, "GITHUB_REPOSITORY": "o/r/../x"}, {"GITHUB_REPOSITORY": "o/r"}):
        with pytest.raises(review.ReviewError):
            review.github_context(bad)


@needs_git
def test_cli_prints_the_review_and_needs_a_token_to_post(tmp_path, capsys, monkeypatch):
    (tmp_path / "app.py").write_text("x = 1\n")
    git(tmp_path, "init", "-q")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "base")
    (tmp_path / "app.py").write_text("import requests\nr = requests.get('https://x')\n")
    assert main(["review", str(tmp_path), "--diff", "HEAD"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [c["path"] for c in out["comments"]] == ["app.py"]
    assert "r = requests.get('https://x', timeout=10)" in out["comments"][0]["body"]
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert main(["review", str(tmp_path), "--diff", "HEAD", "--post"]) == 2
