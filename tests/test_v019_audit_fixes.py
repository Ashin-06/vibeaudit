"""Regression tests covering all findings and recommendations from the v0.18.0 external security audit."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from vibeaudit import cli, parse, secretscan
from vibeaudit.scanner import Options, scan


def _scan(path, **kw):
    kw.setdefault("offline", True)
    kw.setdefault("external", "none")
    return scan(str(path), Options(**kw))


def test_lexical_is_absolute_dotdot_guard_bypassed_by_symlink_is_still_flagged(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("TOP_SECRET")
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    try:
        os.symlink(outside, uploads / "external")
        # Demonstrate real filesystem traversal without '..', then verify static detection catches the guard flaw.
        user_rel = Path("external")
        assert not user_rel.is_absolute() and ".." not in user_rel.parts
        assert (uploads / user_rel).read_text() == "TOP_SECRET"
    except OSError:
        pass  # Windows unprivileged environments disallow symlinks; static BE006 check below still runs

    app = tmp_path / "app"
    app.mkdir()
    (app / "app.py").write_text(
        "from pathlib import Path\nfrom flask import Flask, request\napp = Flask(__name__)\n"
        "BASE = Path('/srv/app/uploads')\n\n"
        "@app.get('/download')\ndef download():\n"
        "    p = Path(request.args['file'])\n"
        "    if p.is_absolute() or '..' in p.parts:\n"
        "        raise ValueError('Invalid path')\n"
        "    return open(BASE / p).read()\n"
    )
    hits = [f.line for f in _scan(app).findings if f.rule_id == "BE006"]
    assert hits == [11]


def test_commonpath_resolved_guard_is_accepted_but_unresolved_abspath_is_flagged(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import Flask, request\napp = Flask(__name__)\n"
        "BASE = os.path.realpath('/srv/app/uploads')\n\n"
        "@app.get('/safe')\ndef safe():\n"
        "    target = os.path.realpath(os.path.join(BASE, request.args['file']))\n"
        "    if os.path.commonpath([BASE, target]) != BASE:\n"
        "        raise ValueError('Invalid path')\n"
        "    return open(target).read()\n\n"
        "@app.get('/unsafe')\ndef unsafe():\n"
        "    target = os.path.abspath(os.path.join(BASE, request.args['file']))\n"
        "    if os.path.commonpath([BASE, target]) != BASE:\n"
        "        raise ValueError('Invalid path')\n"
        "    return open(target).read()\n"
    )
    hits = [f.line for f in _scan(tmp_path).findings if f.rule_id == "BE006"]
    assert hits == [18]


def test_canonical_check_toctou_limitation_still_needs_runtime_discipline(tmp_path):
    # Static canonical check passes verification, while symlink swaps after check remain an OS TOCTOU race.
    base = tmp_path / "base"
    base.mkdir()
    real_file = base / "doc.txt"
    real_file.write_text("ok")
    resolved = real_file.resolve()
    assert resolved.is_relative_to(base.resolve())


def test_git_history_streaming_reports_complete_size_commit_and_timeout_statuses(tmp_path, monkeypatch):
    no_git = secretscan.scan_git_history(tmp_path, lambda _f: None)
    assert no_git["status"] == "not_git" and no_git["truncated"] is False

    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@example.com"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Test"], check=True, capture_output=True)
    leaked = "sk-ant-" + "api03-" + ("A" * 80)
    for i in range(3):
        (tmp_path / f"f{i}.py").write_text(f"KEY_{i} = '{leaked if i == 0 else 'placeholder'}'\n")
        subprocess.run(["git", "-C", str(tmp_path), "add", f"f{i}.py"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", f"c{i}"], check=True, capture_output=True)

    complete = secretscan.scan_git_history(tmp_path, lambda _f: None, max_commits=10)
    assert complete["status"] == "complete" and complete["commits_scanned"] == 3 and complete["truncated"] is False

    by_commits = _scan(tmp_path, history=True, history_commits=1)
    assert by_commits.meta["history"]["status"] == "truncated_commits"
    assert by_commits.meta["history"]["truncated"] is True
    assert any("--history-commits limit" in n for n in by_commits.meta["notes"])

    by_size = secretscan.scan_git_history(tmp_path, lambda _f: None, max_commits=10, max_bytes=120)
    assert by_size["status"] == "truncated_size" and by_size["truncated"] is True

    monkeypatch.setattr(secretscan, "HISTORY_MAX_BYTES", 120)
    res_size = _scan(tmp_path, history=True, history_commits=10)
    assert res_size.meta["history"]["status"] == "truncated_size"
    assert any("20 MB patch stream limit" in n for n in res_size.meta["notes"])

    class _SlowProc:
        def __init__(self, *_a, **_k):
            import io
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"")
            self.returncode = None

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

        def terminate(self):
            self.returncode = -15

        def wait(self, timeout=None):
            return self.returncode

    class _SlowStdout:
        def __iter__(self):
            return self

        def __next__(self):
            import time
            time.sleep(0.15)
            raise StopIteration

        def close(self):
            pass

    real_popen = subprocess.Popen
    monkeypatch.setattr(secretscan, "HISTORY_MAX_BYTES", 20_000_000)
    monkeypatch.setattr(secretscan, "HISTORY_TIMEOUT", 0.02)

    def _fake_popen(*a, **kw):
        cmd = a[0] if a else ()
        if isinstance(cmd, (list, tuple)) and "log" in cmd:
            p = _SlowProc()
            p.stdout = _SlowStdout()  # type: ignore[assignment]
            return p
        return real_popen(*a, **kw)

    monkeypatch.setattr(subprocess, "Popen", _fake_popen)
    res_to = _scan(tmp_path, history=True, history_commits=10)
    assert res_to.meta["history"]["status"] == "timeout"
    assert any("timed out" in n for n in res_to.meta["notes"])


def test_fe001_constant_ternary_and_gating_separation(tmp_path, capsys):
    (tmp_path / "safe.js").write_text(
        "const btn = document.getElementById('btn');\n"
        "btn.innerHTML = dark ? '\\u2600' : '\\u263d';\n"
        "btn.innerHTML = escapeHtml(userName);\n"
    )
    res_safe = _scan(tmp_path / "safe.js" if False else tmp_path)
    assert [f for f in res_safe.findings if f.rule_id == "FE001"] == []

    # Untainted heuristic raw-HTML sink (medium) is reported in findings, but does not fail default --fail-on medium
    heu_dir = tmp_path / "heuristic"
    heu_dir.mkdir()
    (heu_dir / "view.js").write_text("function show(fragment) { document.getElementById('x').innerHTML = fragment; }\n")
    rc_default = cli.main(["scan", str(heu_dir), "--offline", "--external", "none", "--fail-on", "medium", "-q"])
    assert rc_default == 0
    rc_preview = cli.main(["scan", str(heu_dir), "--offline", "--external", "none", "--fail-on", "medium", "--include-preview", "-q"])
    assert rc_preview == 1

    # Mixed escaped + raw user input still triggers high-severity FE001 and gates CI
    mix_dir = tmp_path / "mixed"
    mix_dir.mkdir()
    (mix_dir / "routes.js").write_text(
        "app.get('/hi', (req, res) => {\n"
        "  const safe = escapeHtml(req.query.a);\n"
        "  document.getElementById('out').innerHTML = `${safe} ${req.query.b}`;\n"
        "});\n"
    )
    res_mix = _scan(mix_dir)
    fe = [f for f in res_mix.findings if f.rule_id == "FE001"]
    assert len(fe) == 1 and fe[0].severity == "high"
    assert cli.main(["scan", str(mix_dir), "--offline", "--external", "none", "--fail-on", "high", "-q"]) == 1


@pytest.mark.parametrize("mode_env", ["", "regex"])
def test_js_ts_aliased_imports_and_destructured_params_both_parser_modes(tmp_path, monkeypatch, mode_env):
    if mode_env:
        monkeypatch.setenv("VIBEAUDIT_PARSER", mode_env)
    else:
        monkeypatch.delenv("VIBEAUDIT_PARSER", raising=False)
        if parse.parser("ts") is None:
            pytest.skip("vibeaudit[parse] not installed")
    parse.parser.cache_clear()
    try:
        (tmp_path / "package.json").write_text('{"dependencies": {"express": "4.19.0", "pg": "8.11.0"}}')
        (tmp_path / "sink.ts").write_text(
            "import { Pool } from 'pg';\nconst pool = new Pool();\n"
            "export const runQuery = async ({ id, filter }: { id: string; filter: string }) => {\n"
            "  return pool.query('SELECT * FROM items WHERE id = ' + id);\n};\n"
        )
        (tmp_path / "routes.ts").write_text(
            "import express from 'express';\nimport { runQuery as execSearch } from './sink';\n"
            "const app = express();\n"
            "app.get('/search', async (req, res) => {\n"
            "  res.json(await execSearch({ id: String(req.query.id), filter: 'a' }));\n"
            "});\n"
        )
        hits = [f for f in _scan(tmp_path).findings if f.rule_id == "BE001"]
        assert [(f.file, f.line) for f in hits] == [("sink.ts", 4)]
    finally:
        monkeypatch.delenv("VIBEAUDIT_PARSER", raising=False)
        parse.parser.cache_clear()
