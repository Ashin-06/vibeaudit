"""The GitLab CI and CircleCI templates and the report formats they use (junit, codeclimate)."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

import vibeaudit
from vibeaudit.model import Finding
from vibeaudit.report import RENDERERS, Result, render_codeclimate, render_junit

ROOT = Path(__file__).parent.parent
TEMPLATES = [ROOT / "ci" / "gitlab-ci.yml", ROOT / "ci" / "circleci.yml"]


def finding(rule, sev, preview=False, msg="m"):
    f = Finding(rule, "src/a & <b>.py", 3, msg, sev, title=f"T {rule}", category="backend", why="w", fix="f")
    f.preview = preview
    f.compute_fingerprint()
    return f


# ------------------------------------------------------------ report formats
def test_codeclimate_report():
    res = Result("/r", [finding("BE001", "critical"), finding("QA004", "low")], {})
    issues = json.loads(render_codeclimate(res))
    assert [i["severity"] for i in issues] == ["blocker", "minor"]
    assert issues[0]["location"] == {"path": "src/a & <b>.py", "lines": {"begin": 3}}
    assert issues[0]["categories"] == ["Security"] and issues[0]["fingerprint"] == res.findings[0].fingerprint
    assert len({i["fingerprint"] for i in issues}) == 2
    assert json.loads(render_codeclimate(Result("/r", [], {}))) == []


def test_junit_report():
    res = Result("/r", [finding("BE001", "high", msg='x "<&>" y'), finding("UI006", "medium", preview=True)], {})
    root = ET.fromstring(render_junit(res))  # parses: XML special characters are escaped
    suite = root.find("testsuite")
    assert (suite.get("tests"), suite.get("failures"), suite.get("skipped")) == ("2", "1", "1")
    first, second = suite.findall("testcase")
    assert first.find("failure").get("type") == "high" and 'x "<&>" y' in first.find("failure").get("message")
    assert second.find("skipped") is not None  # a preview rule does not gate the build
    empty = ET.fromstring(render_junit(Result("/r", [], {}))).find("testsuite")
    assert empty.get("tests") == "1" and empty.find("testcase").find("failure") is None


# ------------------------------------------------------------ templates
def test_templates_pin_this_version_and_use_real_flags_and_formats():
    from test_docs import _all_flags

    flags = _all_flags()
    for path in TEMPLATES:
        text = path.read_text(encoding="utf-8")
        assert set(re.findall(r"\bv(\d+\.\d+\.\d+)\b", text)) == {vibeaudit.__version__}, path.name
        commands = re.findall(r"vibeaudit scan [^\n]*", text)
        assert commands, path.name
        for cmd in commands:
            for flag in re.findall(r"(?<![\w-])(--[a-z][a-z-]+)", cmd):
                assert flag in flags, (path.name, flag)
            for fmt in re.findall(r"--report ([a-z]+):", cmd):
                assert fmt in RENDERERS, (path.name, fmt)


def _git(cwd, *args):
    subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "core.autocrlf=false", *args],
                   cwd=cwd, check=True, capture_output=True)


@pytest.mark.skipif(not (shutil.which("bash") and shutil.which("git")), reason="needs bash and git")
def test_templates_run(tmp_path):
    """Run the templates' shell steps in a scratch repository, with this checkout as `vibeaudit`."""
    yaml = pytest.importorskip("yaml")
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q")
    _git(origin, "checkout", "-q", "-b", "main")
    (origin / "app.py").write_text("x = 1\n")
    _git(origin, "add", "-A")
    _git(origin, "commit", "-q", "-m", "base")
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", str(origin), str(work))
    _git(work, "checkout", "-q", "-b", "feature")
    (work / "net.py").write_text("import requests\nr = requests.get('https://y')\n")
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "-m", "change")
    env = dict(os.environ, VIBEAUDIT_ARGS="--offline --external none", VIBEAUDIT_FAIL_ON="medium")
    shim = f'vibeaudit() {{ "{Path(sys.executable).as_posix()}" -m vibeaudit "$@"; }}\nset -eo pipefail\n'

    def run(script, **extra):
        return subprocess.run([shutil.which("bash"), "-c", shim + script], cwd=work, env=dict(env, **extra), capture_output=True, text=True)

    gitlab = yaml.safe_load(TEMPLATES[0].read_text(encoding="utf-8"))["vibeaudit"]
    assert gitlab["artifacts"]["when"] == "always"
    r = run(gitlab["script"][1], CI_MERGE_REQUEST_TARGET_BRANCH_NAME="main")
    assert r.returncode == 1, r.stderr  # REL001 is medium
    issues = json.loads((work / "gl-code-quality-report.json").read_text())
    assert [(i["check_name"], i["location"]["path"]) for i in issues] == [("REL001", "net.py")]
    assert ET.parse(work / "vibeaudit-junit.xml").getroot().get("failures") == "1"

    circle = yaml.safe_load(TEMPLATES[1].read_text(encoding="utf-8"))["jobs"]["vibeaudit"]
    steps = {s["run"]["name"]: s["run"]["command"] for s in circle["steps"] if isinstance(s, dict) and "run" in s}
    base = {k: str(v) for k, v in circle["environment"].items() if k not in env}
    assert run(steps["Scan"], CIRCLE_BRANCH="feature", **base).returncode == 0  # the reports are stored first
    assert (work / "vibeaudit-exit-code").read_text().strip() == "1"
    assert sorted(p.name for p in (work / "vibeaudit-reports").iterdir()) == ["vibeaudit.json", "vibeaudit.sarif", "vibeaudit.xml"]
    assert run(steps["Fail on findings"], **base).returncode == 1
