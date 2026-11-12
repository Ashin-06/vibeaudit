"""`vibeaudit review`: pull request review comments on changed lines, with suggested fixes.

The project is scanned as `vibeaudit scan --diff BASE` does (whole project analysed, findings on changed lines
only). Each finding becomes a review comment on its line; when a `vibeaudit fix` codemod rewrites it with one
contiguous edit inside the diff, the comment carries a GitHub suggestion the author can apply with a click.

Without --post the review is printed as JSON (the GitHub "create a review" payload). With --post it is sent to
the GitHub REST API with GITHUB_TOKEN. Comments already posted by an earlier run (recognised by a hidden marker
with the finding's fingerprint) are not posted again. A token without write access, as on pull requests from
forks, produces a warning, not a failure.

The comment text quotes the repository's own code and messages, which a pull request author controls, so
@mentions and HTML comments in it are neutralised.
"""
from __future__ import annotations

import difflib
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from .model import SEVERITY_RANK, Finding

MARKER = "<!-- vibeaudit:{} -->"
MARKER_RX = re.compile(r"<!-- vibeaudit:([0-9a-f]{32}) -->\s*$")  # only at the very end of our own comments
MAX_BODY = 4000
API_TIMEOUT = 30


class ReviewError(Exception):
    pass


def neutralise(text: str) -> str:
    """Untrusted text for a comment: no @mentions (they notify people) and no HTML comments (our marker)."""
    return text.replace("<!--", "&lt;!--").replace("@", "@<!-- -->")


def suggestion(root: Path, f: Finding, project, changed_lines) -> Optional[Tuple[int, int, str]]:
    """(first line, last line, replacement) when a codemod fixes `f` with one contiguous edit whose lines
    are all changed lines of the pull request (GitHub only accepts suggestions inside the diff)."""
    from . import fix

    if f.rule_id not in fix.FIXERS:
        return None
    plan = fix.plan_findings(root, [f], project)
    if not plan.changes:
        return None
    before, after = plan.changes[0].before.split("\n"), plan.changes[0].after.split("\n")
    ops = [op for op in difflib.SequenceMatcher(None, before, after, autojunk=False).get_opcodes() if op[0] != "equal"]
    if len(ops) != 1:
        return None  # an import added at the top and a call changed further down: not one suggestion
    _tag, i1, i2, j1, j2 = ops[0]
    if i1 == i2:  # a pure insertion: replace the line before it with itself plus the new lines
        if i1 == 0:
            return None
        i1, j1 = i1 - 1, j1 - 1
    # widen the suggestion over unchanged lines so that it starts or ends on the finding's own line, where
    # the comment belongs (a multi-line call is reported on its first line, the new argument goes further down)
    if f.line - 1 < i1:
        j1 -= i1 - (f.line - 1)
        i1 = f.line - 1
    if f.line > i2:
        j2 += f.line - i2
        i2 = f.line
    first, last = i1 + 1, i2
    if last - first > 20 or (changed_lines is not None and not all(n in changed_lines for n in range(first, last + 1))):
        return None
    return first, last, "\n".join(after[j1:j2])


def comment_for(f: Finding, fix_lines: Optional[Tuple[int, int, str]], prefix: str) -> Dict:
    title = f"**{f.severity} {f.rule_id}: {neutralise(f.title)}**" + (" (preview)" if f.preview else "")
    body = [title, "", neutralise(f.message)]
    if f.why:
        body += ["", neutralise(f.why)]
    if fix_lines is not None:
        new = fix_lines[2]
        fence = "````" if "```" in new else "```"
        body += ["", "Suggested fix (from `vibeaudit fix`):", "", f"{fence}suggestion", new, fence]
    elif f.fix:
        body += ["", "Fix: " + neutralise(f.fix)]
    text = "\n".join(body)
    if len(text) > MAX_BODY:
        text = text[:MAX_BODY] + "\n..."
    c: Dict = {"path": prefix + f.file, "side": "RIGHT", "body": text + "\n\n" + MARKER.format(f.fingerprint)}
    if fix_lines is not None:
        c["line"] = fix_lines[1]
        if fix_lines[0] != fix_lines[1]:
            c["start_line"], c["start_side"] = fix_lines[0], "RIGHT"
    else:
        c["line"] = max(f.line, 1)
    return c


def build(root: Path, findings: List[Finding], changes, prefix: str = "", max_comments: int = 30, project=None) -> Dict:
    """The review payload for `findings` (already limited to changed lines)."""
    ordered = sorted((f for f in findings if f.line), key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.file, f.line))
    comments = []
    for f in ordered[:max_comments]:
        lines = changes.get(f.file) if changes is not None else None
        comments.append(comment_for(f, suggestion(root, f, project, lines), prefix))
    extra = len(ordered) - len(comments)
    summary = (f"vibeaudit found {len(ordered)} issue{'s' if len(ordered) != 1 else ''} on the changed lines."
               + (f" The {extra} least severe are not commented; run `vibeaudit scan --diff` to see them." if extra > 0 else ""))
    return {"event": "COMMENT", "body": summary, "comments": comments}


# ------------------------------------------------------------------ GitHub
def _request(method: str, url: str, token: str, body: Optional[dict] = None) -> Tuple[object, Dict[str, str]]:
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                          "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "vibeaudit-review",
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:  # noqa: S310 - the GitHub API URL
            return json.loads(resp.read().decode("utf-8") or "null"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        raise ReviewError(f"GitHub API {method} {url.split('?')[0]}: HTTP {e.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise ReviewError(f"GitHub API request failed: {e}") from None


def posted_fingerprints(api: str, repo: str, pr: int, token: str, request=_request, max_pages: int = 20) -> set:
    seen: set = set()
    url: Optional[str] = f"{api}/repos/{repo}/pulls/{pr}/comments?per_page=100"
    for _ in range(max_pages):
        if not url:
            break
        data, headers = request("GET", url, token)
        for c in data if isinstance(data, list) else []:
            # only comments by a bot account (the Actions token posts as github-actions[bot]): a pull request
            # author could otherwise post our marker themselves to keep a finding from being commented
            if isinstance(c, dict) and isinstance(c.get("user"), dict) and c["user"].get("type") == "Bot":
                seen.update(MARKER_RX.findall(str(c.get("body", ""))))
        m = re.search(r'<([^>]+)>;\s*rel="next"', headers.get("Link", "") or headers.get("link", ""))
        url = m.group(1) if m and m.group(1).startswith(api) else None
    return seen


def post(review: Dict, api: str, repo: str, pr: int, commit: str, token: str, request=_request) -> int:
    """Post the comments that are not there yet; returns how many were posted."""
    seen = posted_fingerprints(api, repo, pr, token, request)
    new = [c for c in review["comments"] if not (set(MARKER_RX.findall(c["body"])) & seen)]
    if not new:
        return 0
    request("POST", f"{api}/repos/{repo}/pulls/{pr}/reviews", token,
            {"commit_id": commit, "event": "COMMENT", "body": review["body"], "comments": new})
    return len(new)


def github_context(env: Dict[str, str]) -> Tuple[str, str, int, str]:
    """(API URL, owner/repo, pull request number, head commit) from the Actions environment."""
    repo = env.get("GITHUB_REPOSITORY", "")
    api = env.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    try:
        event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
        pr = event["pull_request"]
        number, head = int(pr["number"]), str(pr["head"]["sha"])
    except (KeyError, OSError, ValueError, TypeError):
        raise ReviewError("not running for a pull request (GITHUB_EVENT_PATH has no pull_request)") from None
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo) or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ReviewError("GITHUB_REPOSITORY or the head commit is missing")
    if not api.startswith("https://"):
        raise ReviewError("GITHUB_API_URL must be https")
    return api, repo, number, head


def repo_prefix(root: Path) -> str:
    """The scanned folder relative to the repository root ("" at the root), for review comment paths."""
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-prefix"], capture_output=True,
                             stdin=subprocess.DEVNULL, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.decode("utf-8", "replace").strip() if out.returncode == 0 else ""


def run(path: str, base: str, opts, do_post: bool, max_comments: int, out: Callable[[str], None],
        log: Callable[[str], None], env: Optional[Dict[str, str]] = None) -> int:
    from .files import Project
    from .gitdiff import DiffError, changed
    from .scanner import scan

    env = dict(os.environ) if env is None else env
    root = Path(path)
    try:
        changes = changed(root, base=base)
    except DiffError as e:
        log(f"cannot compute changes: {e}")
        return 2
    opts.changes = changes
    res = scan(path, opts)
    review = build(root, res.findings, changes, repo_prefix(root), max_comments,
                   Project(root, opts.excludes, opts.max_file_bytes))
    if not do_post:
        out(json.dumps(review, indent=2))
        return 0
    token = env.get("GITHUB_TOKEN", "")
    if not token:
        log("GITHUB_TOKEN is not set; nothing posted")
        return 2
    try:
        api, repo, pr, head = github_context(env)
        n = post(review, api, repo, pr, head, token)
    except ReviewError as e:
        log(f"review not posted: {e} (a pull request from a fork gets a read-only token)")
        return 0
    log(f"posted {n} new review comments ({len(review['comments']) - n} already there)")
    return 0
