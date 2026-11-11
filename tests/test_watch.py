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
