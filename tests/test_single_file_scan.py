"""Tests for scanning a single file (`vibeaudit scan app.py` and `scan("app.py")`)."""
from __future__ import annotations

import importlib.resources
import json

from vibeaudit import cli, scan
from vibeaudit.scanner import Options


def test_single_file_cli_and_api_detects_vuln_without_project_absence_noise(tmp_path, capsys):
    target = tmp_path / "app.py"
    target.write_text(
        "import os\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
        "@app.post('/run')\ndef run():\n    os.system(request.args['cmd'])\n    return 'ok'\n",
        encoding="utf-8",
    )
    sibling = tmp_path / "other.py"
    sibling.write_text("API_KEY = 'sk-test123456789012345678901234567890'\n", encoding="utf-8")

    res = scan(str(target), Options(offline=True, external="none", cache=False))
    assert res.meta["files_scanned"] == 1
    assert res.meta["single_file"] == "app.py"
    rule_ids = {f.rule_id for f in res.findings}
    assert "BE002" in rule_ids
    # Project-wide absence rules (no tests / no CI / no health endpoint) must not fire for a single file
    assert not (rule_ids & {"QA001", "QA002", "REL006", "DEP005"})
    # Sibling files in the same directory must not be scanned
    assert all(f.file == "app.py" for f in res.findings)

    out_json = tmp_path / "single.json"
    rc = cli.main(["scan", str(target), "--offline", "--external", "none", "-r", f"json:{out_json}", "-q"])
    assert rc == 1
    doc = json.loads(out_json.read_text(encoding="utf-8"))
    assert doc["meta"]["files_scanned"] == 1
    assert doc["meta"]["single_file"] == "app.py"
    schema = json.loads(
        importlib.resources.files("vibeaudit").joinpath("data", "report.schema.json").read_text(encoding="utf-8")
    )
    try:
        import jsonschema  # type: ignore[import-untyped]
    except ImportError:
        jsonschema = None
    if jsonschema is not None:
        jsonschema.Draft202012Validator(schema).validate(doc)


def test_single_clean_file_scores_100_and_various_languages(tmp_path):
    clean_py = tmp_path / "clean.py"
    clean_py.write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    assert cli.main(["scan", str(clean_py), "--offline", "--external", "none", "-q"]) == 0
    clean_res = scan(str(clean_py), Options(offline=True, external="none", cache=False))
    assert clean_res.score == 100 and clean_res.grade == "A"

    vuln_js = tmp_path / "server.js"
    vuln_js.write_text(
        "const express = require('express');\nconst app = express();\n"
        "app.get('/q', (req, res) => { res.send(req.query.msg); });\n",
        encoding="utf-8",
    )
    js_res = scan(str(vuln_js), Options(offline=True, external="none", cache=False))
    assert js_res.meta["files_scanned"] == 1 and js_res.meta["single_file"] == "server.js"

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.12\nCOPY . /app\n", encoding="utf-8")
    docker_res = scan(str(dockerfile), Options(offline=True, external="none", cache=False))
    assert docker_res.meta["files_scanned"] == 1
    assert any(f.file == "Dockerfile" for f in docker_res.findings)


def test_single_file_partial_coverage_and_usage_errors(tmp_path):
    huge = tmp_path / "big.py"
    huge.write_text("x = '" + ("a" * 256) + "'\n", encoding="utf-8")
    rc = cli.main(["scan", str(huge), "--offline", "--external", "none", "--max-file-size", "32", "--fail-on-partial", "-q"])
    assert rc == 1

    assert cli.main(["scan", str(tmp_path / "missing.py"), "-q"]) == 2
    assert cli.main(["scan", str(huge), "--monorepo", "-q"]) == 2
