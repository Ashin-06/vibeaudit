"""Monorepo mode: every package is scanned against its own manifest and evidence."""
from __future__ import annotations

import json
from pathlib import Path

from vibeaudit import monorepo
from vibeaudit.cli import main
from vibeaudit.files import Project
from vibeaudit.scanner import Options, scan

LIMITED_API = ("from flask import Flask\nfrom flask_limiter import Limiter\napp = Flask(__name__)\nlimiter = Limiter(app)\n\n\n"
               "@app.get('/health')\ndef health():\n    return 'ok'\n")
LLM_API = ("from flask import Flask, request\nfrom openai import OpenAI\napp = Flask(__name__)\nclient = OpenAI()\n\n\n"
           "@app.post('/chat')\ndef chat():\n    r = client.chat.completions.create(model='m', messages=[], max_tokens=5)\n"
           "    return r.choices[0].message.content\n")


def write(root: Path, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def opts(**kw):
    return Options(offline=True, external="none", feedback=False, cache=False, **kw)


def rules(res, rule):
    return sorted(f.file for f in res.findings if f.rule_id == rule)


REPO = {
    "apps/api/requirements.txt": "flask\nflask-limiter\nrequests\n",
    "apps/api/app.py": LIMITED_API,
    "apps/chat/requirements.txt": "flask\nopenai\n",
    "apps/chat/app.py": LLM_API,
    "apps/chat/fetch.py": "import requests\n\n\ndef get(u):\n    return requests.get(u, timeout=5)\n",
    "scripts/deploy.py": "import subprocess\nsubprocess.run('deploy ' + input(), shell=True)\n",
    "tests/fixtures/demo/package.json": "{}",
    "tests/fixtures/demo/server.js": "app.post('/x', (req, res) => db.query('SELECT ' + req.body.q));\n",
}


def test_each_package_is_judged_on_its_own_evidence(tmp_path):
    write(tmp_path, REPO)
    whole, mono = scan(str(tmp_path), opts()), monorepo.scan(str(tmp_path), opts())
    # the rate limiter in apps/api does not protect the model route in apps/chat
    assert rules(whole, "LLM004") == [] and rules(mono, "LLM004") == ["apps/chat/app.py"]
    # requests is declared by apps/api only: apps/chat imports it without declaring it
    assert "apps/chat/fetch.py" not in rules(whole, "QA007") and rules(mono, "QA007") == ["apps/chat/fetch.py"]
    # files outside every package are a unit of their own; test fixtures stay test code
    assert rules(mono, "BE002") == rules(whole, "BE002") == ["scripts/deploy.py"]
    assert not [f for f in mono.findings if f.file.startswith("tests/")]
    packages = {p["path"]: p for p in mono.meta["packages"]}
    assert set(packages) == {".", "apps/api", "apps/chat"} and packages["apps/chat"]["findings"] >= 2
    assert {r.file for r in mono.routes} == {"apps/api/app.py", "apps/chat/app.py"}


def test_fingerprints_match_a_normal_scan(tmp_path):
    write(tmp_path, REPO)
    whole, mono = scan(str(tmp_path), opts()), monorepo.scan(str(tmp_path), opts())
    same = {(f.rule_id, f.file, f.line): f.fingerprint for f in whole.findings}
    shared = [f for f in mono.findings if (f.rule_id, f.file, f.line) in same]
    assert shared and all(f.fingerprint == same[(f.rule_id, f.file, f.line)] for f in shared)
    baseline = tmp_path / "base.json"
    main(["scan", str(tmp_path), "--offline", "--external", "none", "--write-baseline", str(baseline)])
    assert {f.file for f in monorepo.scan(str(tmp_path), opts(baseline=str(baseline))).findings} == {"apps/chat/app.py", "apps/chat/fetch.py"}


def test_root_excludes_apply_inside_packages(tmp_path):
    write(tmp_path, dict(REPO, **{".vibeauditignore": "apps/chat/fetch.py\n"}))
    mono = monorepo.scan(str(tmp_path), opts(excludes=["scripts/*"]))
    assert "apps/chat/fetch.py" not in {f.file for f in mono.findings}
    assert rules(mono, "BE002") == []
    assert monorepo.unit_of("apps/chat/x.py", ["", "apps", "apps/chat"]) == "apps/chat"


def test_package_detection_and_no_packages(tmp_path):
    write(tmp_path, REPO)
    assert monorepo.package_dirs(Project(tmp_path)) == ["apps/api", "apps/chat"]
    single = tmp_path / "single"
    write(single, {"requirements.txt": "flask\n", "app.py": LLM_API})
    res = monorepo.scan(str(single), opts())
    assert res.meta["packages"] == [] and "no package folders" in " ".join(res.meta["notes"])
    assert rules(res, "LLM004") == ["app.py"]


def test_cli_flag_config_and_reports(tmp_path, capsys):
    write(tmp_path, REPO)
    out = tmp_path / "r.json"
    main(["scan", str(tmp_path), "--offline", "--external", "none", "--monorepo", "--fail-on", "none", "-r", f"json:{out}"])
    text = capsys.readouterr().out
    assert "Packages (monorepo mode" in text and "apps/chat" in text
    assert json.loads(out.read_text())["meta"]["monorepo"] is True
    (tmp_path / ".vibeaudit.toml").write_text("monorepo = true\n")
    main(["scan", str(tmp_path), "--offline", "--external", "none", "--fail-on", "none", "-q"])
    assert "Packages (monorepo mode" in capsys.readouterr().out


def test_repository_rules_use_the_root(tmp_path):
    """CI and the example env file live at the root: packages are not told they have no CI, and an env var
    missing from the root .env.example is still reported (DATA007 is preview, so include it)."""
    files = dict(REPO, **{".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pytest\n",
                          ".env.example": "OPENAI_API_KEY=\n",
                          "apps/chat/settings.py": "import os\nREGION = os.environ['DEPLOY_REGION']\n"})
    write(tmp_path, files)
    mono = monorepo.scan(str(tmp_path), opts(include_preview=True))
    assert rules(mono, "QA002") == []
    assert rules(mono, "DATA007") == rules(scan(str(tmp_path), opts(include_preview=True)), "DATA007") == ["apps/chat/settings.py"]
