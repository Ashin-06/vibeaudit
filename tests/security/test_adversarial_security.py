"""Dedicated adversarial security regression suite covering the 11 threat-model vectors."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import zipfile
from pathlib import Path

import pytest

from vibeaudit import bundle, config, cli, fix, llm, report, store
from vibeaudit.model import Finding
from vibeaudit.scanner import Options, scan

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))


# 1. Malicious symlinks (escape + circular loop)
def test_threat_1_malicious_symlinks_blocked(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text('AWS_KEY = "AKIA' + '1234567890ABCDEF"\n')
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text("x = 1\n")
    try:
        (proj / "leak.py").symlink_to(outside / "secret.py")
        (proj / "loop_a").symlink_to(proj / "loop_b")
        (proj / "loop_b").symlink_to(proj / "loop_a")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform")
    res = scan(str(proj), Options(offline=True, external="none"))
    assert all(f.file != "leak.py" for f in res.findings)
    assert res.meta["coverage"]["files_skipped_symlink"] >= 1


# 2. Oversized file DoS
def test_threat_2_oversized_file_skipped_and_reported(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    (tmp_path / "huge.py").write_text("x = 1\n" * 50_000)
    res = scan(str(tmp_path), Options(offline=True, external="none", max_file_bytes=4096))
    assert res.meta["coverage"]["overall_status"] == "partial"
    assert res.meta["coverage"]["files_skipped_size"] == 1
    assert "huge.py" in res.meta["coverage"]["scanners"]["python"]["skipped_files"]


# 3. Deep AST nesting DoS
def test_threat_3_deep_ast_nesting_does_not_crash(tmp_path):
    depth = 3500
    (tmp_path / "deep.py").write_text("x = " + ("(" * depth) + "1" + (")" * depth) + "\n")
    (tmp_path / "deep.js").write_text("const y = " + ("[" * depth) + "1" + ("]" * depth) + ";\n")
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    assert json.loads(report.render_json(res))["tool"] == "vibeaudit"


# 4. Malformed & hostile project config
def test_threat_4_malformed_and_hostile_project_config(tmp_path, capsys):
    (tmp_path / "bad.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.get('/run')\n"
        "def run():\n"
        "    return str(eval(request.args['x']))\n"
    )
    (tmp_path / ".vibeaudit.toml").write_text('disable = ["BE003"]\n')
    assert cli.main(["scan", str(tmp_path), "--offline", "--external", "none", "--no-config", "-q"]) == 1
    assert cli.main(["scan", str(tmp_path), "--offline", "--external", "none", "-q"]) == 0
    err = capsys.readouterr().err
    assert "disables BE003" in err and "--no-config" in err

    (tmp_path / ".vibeaudit.toml").write_text("unknown-key = true\n")
    assert cli.main(["scan", str(tmp_path), "--offline", "--external", "none", "-q"]) == 2


# 5. Malicious git history / invalid repo handling
def test_threat_5_history_handles_non_git_safely(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    res = scan(str(tmp_path), Options(offline=True, external="none", history=True))
    assert res.meta["history"]["status"] == "not_git"


# 6. Regex ReDoS resilience
def test_threat_6_pathological_redos_inputs_bound_runtime(tmp_path):
    (tmp_path / "redos.py").write_text("s = '" + ("a1=" * 50_000) + "!'\n")
    (tmp_path / "redos.js").write_text("const q = `" + ("${x} + " * 10_000) + "0`;\n")
    t0 = time.perf_counter()
    scan(str(tmp_path), Options(offline=True, external="none"))
    assert time.perf_counter() - t0 < 10.0


# 7. Malicious filenames (HTML/shell injection payloads)
def test_threat_7_malicious_filenames_escaped_and_never_executed(tmp_path):
    names = ["$(echo pwned).py", "a;b.js"]
    if os.name != "nt":
        names.append("<script>alert(1)</script>.py")
    for name in names:
        try:
            (tmp_path / name).write_text("eval(req.body.code)\n" if name.endswith(".js") else "eval(x)\n")
        except OSError:
            continue
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    html = report.render_html(res)
    assert "<script>alert(1)" not in html
    assert json.loads(report.render_sarif(res))["version"] == "2.1.0"


# 8. Plugin opt-in boundary (repo code never imported or run by scan)
def test_threat_8_untrusted_repo_plugin_key_rejected_and_code_not_executed(tmp_path):
    marker = tmp_path / "pwned.txt"
    (tmp_path / "evil.py").write_text(f"open({str(marker)!r}, 'w').write('owned')\n")
    (tmp_path / ".vibeaudit.toml").write_text('plugin = ["evil.py"]\n')
    with pytest.raises(config.ConfigError, match="unknown setting"):
        config.load(tmp_path)
    scan(str(tmp_path), Options(offline=True, external="none", no_config=True))
    assert not marker.exists()


# 9. Hostile URL schemes blocked
@pytest.mark.parametrize("bad_url", [
    "file:///etc/passwd",
    "ftp://example.com/feed.json",
    "data:text/plain,evil",
    "http://example.com/api",
    "javascript:alert(1)",
    "not-a-url",
])
def test_threat_9_hostile_url_schemes_rejected(bad_url):
    with pytest.raises(ValueError):
        store.validate_http_url(bad_url)


# 10. Untrusted LLM responses rejected safely
def test_threat_10_untrusted_llm_responses_never_corrupt_or_leak(tmp_path):
    (tmp_path / "app.py").write_text("def f(req):\n    return req\n")
    finding = Finding("AUTH001", "app.py", 1, "missing auth", "high", title="t", category="auth")
    finding.compute_fingerprint()

    class HostileProvider:
        requests = 0

        def complete(self, prompt: str) -> str:
            self.requests += 1
            return json.dumps({
                "start_line": 1,
                "end_line": 1,
                "replacement": "def f(req): # [REDACTED_API_KEY]",
                "explanation": "ok",
            })

    diff, n = fix.patches(tmp_path, [(finding, "none")], HostileProvider(), 5, lambda _m: None)
    assert n == 0 and diff == ""
    with pytest.raises(llm.LLMError):
        llm.parse_json("not valid json {{{")


# 11. Malicious zip-bomb / path-traversal / bloated archive bundles
@pytest.mark.filterwarnings("ignore:Duplicate name")
def test_threat_11_malicious_archive_and_zip_bomb_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(bundle, "cache_dir", lambda: tmp_path / "cache")

    # Compression ratio > MAX_COMPRESSION_RATIO (e.g. 2 MB zeros compressed with DEFLATED)
    zeros = b"\x00" * 2_000_000
    bomb = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as z:
        manifest = {"format": bundle.FORMAT, "files": {
            "data/pypi_top.txt.gz": {"sha256": hashlib.sha256(zeros).hexdigest(), "size": len(zeros)}
        }}
        z.writestr("manifest.json", json.dumps(manifest))
        z.writestr("data/pypi_top.txt.gz", zeros)
    with pytest.raises(bundle.BundleError, match="compression ratio"):
        bundle.import_bundle(bomb, lambda _m: None)

    # Disallowed / path-traversal member
    trav = tmp_path / "trav.zip"
    with zipfile.ZipFile(trav, "w") as z:
        z.writestr("manifest.json", json.dumps({"format": bundle.FORMAT, "files": {"../evil.txt": {"sha256": "x", "size": 1}}}))
        z.writestr("../evil.txt", b"x")
    with pytest.raises(bundle.BundleError):
        bundle.import_bundle(trav, lambda _m: None)

    # Duplicate zip entry names
    dup = tmp_path / "dup.zip"
    with zipfile.ZipFile(dup, "w") as z:
        z.writestr("manifest.json", json.dumps({"format": bundle.FORMAT, "files": {"data/pypi_top.txt.gz": {"sha256": "x", "size": 1}}}))
        z.writestr("data/pypi_top.txt.gz", b"a")
        z.writestr("data/pypi_top.txt.gz", b"b")
    with pytest.raises(bundle.BundleError, match="duplicate"):
        bundle.import_bundle(dup, lambda _m: None)
