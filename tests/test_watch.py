"""`vibeaudit watch`: incremental re-scans reuse unchanged files and replay findings, and always give the same
result as a fresh scan, also when a replayed step depends on another file."""
from __future__ import annotations

import io
import os
from pathlib import Path

from vibeaudit import watch
from vibeaudit.files import Project
from vibeaudit.guard import StepMemo
from vibeaudit.scanner import Options, scan

SECRET = "SECRET_KEY = 'q8Zr" + "Lw2Xv9Tn4Pk7Hs1Jd6Fy3Bm5Gc0'\n"


def opts() -> Options:
    return Options(offline=True, external="none", feedback=False, cache=False, include_preview=True)


def keys(res):
    return sorted((f.rule_id, f.file, f.line, f.message) for f in res.findings)


def write(path: Path, text: str) -> None:
    """Write and move the modification time forward, as a later edit would (some file systems are coarse)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    old = path.stat().st_mtime_ns if path.exists() else 0
    path.write_text(text, encoding="utf-8")
    st = path.stat()
    if st.st_mtime_ns <= old:
        os.utime(path, ns=(st.st_atime_ns, old + 1_000_000))


def test_refresh_keeps_unchanged_files_and_reports_changes(tmp_path):
    write(tmp_path / "a.py", "x = 1\n")
    write(tmp_path / "b.py", "y = 2\n")
    p = Project(tmp_path)
    a, b = p.get("a.py"), p.get("b.py")
    assert a is not None and a.text == "x = 1\n"
    assert p.refresh() == set()
    assert p.get("a.py") is a
    write(tmp_path / "b.py", "y = 3\n")
    write(tmp_path / "c.py", "z = 1\n")
    (tmp_path / "a.py").unlink()
    assert p.refresh() == {"a.py", "b.py", "c.py"}
    assert p.get("a.py") is None and p.get("b.py") is not b and p.get("b.py").text == "y = 3\n"


def test_replayed_steps_rerun_when_a_file_they_read_changes(tmp_path):
    """settings.py's SECRET_KEY is not reported while production.py sets it again. The secret scan step of
    settings.py read production.py, so editing only production.py must re-run it (no replay)."""
    write(tmp_path / "mysite/settings.py", SECRET)
    write(tmp_path / "mysite/production.py", "import os\nSECRET_KEY = os.environ['SECRET_KEY']\n")
    p = Project(tmp_path)
    p.step_memo = StepMemo()
    first = scan(str(tmp_path), opts(), p)
    assert "SEC004" not in {f.rule_id for f in first.findings}
    p.refresh()
    again = scan(str(tmp_path), opts(), p)
    assert p.step_memo.replayed > 0 and keys(again) == keys(first)
    write(tmp_path / "mysite/production.py", "import os\nDEBUG = False\n")
    assert p.refresh() == {"mysite/production.py"}
    after = scan(str(tmp_path), opts(), p)
    assert "SEC004" in {f.rule_id for f in after.findings}
    assert keys(after) == keys(scan(str(tmp_path), opts()))


def test_incremental_matches_fresh_scan_through_edits(tmp_path):
    write(tmp_path / "app.py", "import requests\n\n\ndef f():\n    return requests.get('https://x')\n")
    write(tmp_path / "web/page.tsx", "export default function P() {\n  return <img src='/a.png' />;\n}\n")
    write(tmp_path / "web/package.json", '{"dependencies": {"next": "15.0.0"}}')
    p = Project(tmp_path)
    p.step_memo = StepMemo()
    scan(str(tmp_path), opts(), p)
    edits = [
        ("app.py", "import requests\n\n\ndef f():\n    return requests.get('https://x', timeout=5)\n"),
        ("web/page.tsx", "export default function P() {\n  return <div dangerouslySetInnerHTML={{ __html: location.hash }} />;\n}\n"),
        ("web/package.json", '{"dependencies": {"next": "15.0.0", "lodash": "4.0.0"}}'),
        ("app.py", SECRET.replace("SECRET_KEY", "API_KEY")),
    ]
    for rel, text in edits:
        write(tmp_path / rel, text)
        assert rel in p.refresh()
        assert keys(scan(str(tmp_path), opts(), p)) == keys(scan(str(tmp_path), opts())), rel


def test_watch_prints_new_and_fixed_findings(tmp_path):
    write(tmp_path / "app.py", "x = 1\n")
    out = io.StringIO()
    rounds = iter(range(3))
    steps = [
        lambda: write(tmp_path / "app.py", "import requests\nr = requests.get('https://x')\n"),
        lambda: None,  # nothing changed: nothing printed
        lambda: write(tmp_path / "app.py", "import requests\nr = requests.get('https://x', timeout=5)\n"),
    ]

    def keep_going():
        return next(rounds, None) is not None

    def sleep(_s):
        steps.pop(0)()

    assert watch.run(str(tmp_path), opts(), out, 0.01, keep_going, sleep) == 0
    text = out.getvalue()
    assert "0 findings in" in text
    assert "+ medium   REL001   app.py:2" in text
    assert "- medium   REL001   app.py:2" in text
    assert text.count("changed: app.py") == 2


def test_cli_rejects_a_missing_directory(tmp_path):
    from vibeaudit.cli import main

    assert main(["watch", str(tmp_path / "nope")]) == 2


# ------------------------------------------------------------ replayed checks and their dependencies
def routes_of(res):
    return sorted((r.file, r.line, r.path, tuple(r.methods), r.has_auth, r.calls_llm) for r in res.routes)


def incremental(tmp_path, files, edits, expect=None):
    """Apply `edits` one by one; after each, the incremental scan must equal a fresh scan (findings and
    routes). `expect` maps an edit index to a (rule, file) that must then be reported, proving the edit
    changed the result (so equality is not trivially true)."""
    for rel, text in files.items():
        write(tmp_path / rel, text)
    p = Project(tmp_path)
    p.step_memo = StepMemo()
    scan(str(tmp_path), opts(), p)
    p.refresh()
    first = scan(str(tmp_path), opts(), p)
    assert p.step_memo.replayed > 0
    assert keys(first) == keys(scan(str(tmp_path), opts()))
    for i, (rel, text) in enumerate(edits):
        if text is None:
            (tmp_path / rel).unlink()
        else:
            write(tmp_path / rel, text)
        p.refresh()
        warm, fresh = scan(str(tmp_path), opts(), p), scan(str(tmp_path), opts())
        assert keys(warm) == keys(fresh), (i, rel)
        assert routes_of(warm) == routes_of(fresh), (i, rel)
        if expect and i in expect:
            rule, file = expect[i]
            assert (rule, file) in {(f.rule_id, f.file) for f in warm.findings}, (i, keys(warm))
    return p


def test_js_checks_rerun_when_the_call_graph_changes(tmp_path):
    """The route in api.js calls ask() from lib.js. Once ask() calls a model, the route calls a paid API
    with no rate limit (LLM004), although api.js itself did not change."""
    files = {
        "package.json": '{"dependencies": {"express": "4.0.0", "openai": "4.0.0"}}',
        "lib.js": "function ask(q) {\n  return q.trim();\n}\nmodule.exports = { ask };\n",
        "api.js": ("const express = require('express');\nconst { ask } = require('./lib');\nconst app = express();\n"
                   "app.post('/api/ask', async (req, res) => {\n  res.json(await ask(req.body.q));\n});\n"),
    }
    llm = ("const OpenAI = require('openai');\nconst openai = new OpenAI();\n"
           "async function ask(q) {\n  return openai.chat.completions.create({ model: 'm', messages: [], max_tokens: 5 });\n}\n"
           "module.exports = { ask };\n")
    incremental(tmp_path, files, [("lib.js", llm), ("lib.js", files["lib.js"])], expect={0: ("LLM004", "api.js")})


def test_js_import_checks_follow_the_exported_names(tmp_path):
    files = {
        "package.json": '{"dependencies": {}}',
        "a.ts": "export function foo() {\n  return 1;\n}\nexport const bar = 2;\n",
        "b.ts": "import { foo, bar } from './a';\nexport const x = foo() + bar;\n",
    }
    step = ("JavaScript completeness checks", "b.ts")
    p = incremental(tmp_path, files, [("a.ts", files["a.ts"] + "// a comment changes no export\n")])
    assert step not in p.step_memo.ran_steps  # same exports: b.ts's import checks are replayed
    p = incremental(tmp_path / "x", files, [("a.ts", "export function foo() {\n  return 1;\n}\n")],  # bar is gone
                    expect={0: ("QA006", "b.ts")})
    assert step in p.step_memo.ran_steps


def test_missing_package_reported_once_per_package_after_edits(tmp_path):
    files = {
        "package.json": '{"dependencies": {}}',
        "a.js": "const lp = require('left-pad');\nmodule.exports = lp;\n",
        "b.js": "const lp = require('left-pad');\nmodule.exports = lp;\n",
    }
    incremental(tmp_path, files, [("a.js", "module.exports = 1;\n"), ("a.js", files["a.js"])],
                expect={0: ("QA007", "b.js"), 1: ("QA007", "a.js")})


def test_import_of_a_file_outside_the_scan_follows_the_disk(tmp_path):
    """gen.ts is excluded from the scan but exists on disk, so `./gen` resolves. When it is deleted the
    import no longer resolves, though no scanned file changed: the recorded disk probe catches it."""
    files = {"package.json": '{"dependencies": {}}', ".vibeauditignore": "gen.ts\n",
             "gen.ts": "export const g = 1;\n", "use.ts": "import { g } from './gen';\nexport const h = g;\n"}
    p = incremental(tmp_path, files, [])
    (tmp_path / "gen.ts").unlink()
    p.refresh()
    warm = scan(str(tmp_path), opts(), p)
    assert keys(warm) == keys(scan(str(tmp_path), opts()))
    assert ("QA006", "use.ts") in {(f.rule_id, f.file) for f in warm.findings}


def test_python_checks_rerun_when_project_auth_changes(tmp_path):
    files = {
        "main.py": ("from fastapi import FastAPI, Depends\nfrom routes import router\nfrom auth import current_user\n"
                    "app = FastAPI()\napp.include_router(router, dependencies=[Depends(current_user)])\n"),
        "auth.py": "def current_user():\n    return 1\n",
        "routes.py": ("from fastapi import APIRouter\nrouter = APIRouter()\n\n\n@router.delete('/items/{item_id}')\n"
                      "def delete_item(item_id: int):\n    db.execute('DELETE FROM items WHERE id = %s', (item_id,))\n"),
    }
    unprotected = files["main.py"].replace(", dependencies=[Depends(current_user)]", "")
    incremental(tmp_path, files, [("main.py", unprotected), ("main.py", files["main.py"])],
                expect={0: ("AUTH001", "routes.py")})


def test_git_listing_marks_untracked_files(tmp_path):
    import shutil
    import subprocess

    if shutil.which("git") is None:
        return
    write(tmp_path / "sub" / "a.py", "x = 1\n")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "sub/a.py"], cwd=tmp_path, check=True)
    write(tmp_path / "b.py", "y = 1\n")
    p = Project(tmp_path)
    assert p.is_git and p.tracked == {"sub/a.py"} and p.untracked == {"b.py"}
    sub = Project(tmp_path / "sub")
    assert sub.tracked == {"a.py"} and sub.untracked == set()
