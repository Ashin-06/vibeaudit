"""Regression tests for bugs found by the multi-pass audit before 0.5.2 (each failed on 0.5.1)."""
import subprocess

import pytest

from vibeaudit import mcp_server
from vibeaudit.config import project_options
from vibeaudit.gitdiff import DiffError, changed, parse_diff


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _call(tool, args):
    r = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}})
    return r["result"]["isError"], r["result"]["content"][0]["text"]


# pass (a): fresh read ----------------------------------------------------------
def test_mcp_arguments_are_checked_against_the_schema(tmp_path):
    write(tmp_path, "app.py", "x = 1\n")
    for args, message in [({"min_severity": "urgent"}, "min_severity must be one of"),
                          ({"offline": "no"}, "offline must be true or false"),
                          ({"changes": 5}, "changes must be")]:
        is_error, text = _call("scan_project", {"path": str(tmp_path), **args})
        assert is_error and text.startswith(message), (args, text)
    is_error, text = _call("check_package", {"name": "flask", "ecosystem": "PyPI", "version": 5})
    assert is_error and "version must be a string" in text


def test_api_and_cli_default_to_the_same_minimum_severity(tmp_path):
    assert project_options(str(tmp_path)).min_severity == "low"


def test_added_line_that_looks_like_a_file_header_is_content():
    diff = ("diff --git a/a.md b/a.md\n--- a/a.md\n+++ a.md\n@@ -1,0 +2,2 @@\n+++ counter\n+x\n@@ -9 +10 @@\n+y\n"
            "diff --git a/b.py b/b.py\n--- a/b.py\n+++ b.py\n@@ -0,0 +1 @@\n+z\n")
    assert parse_diff(diff) == {"a.md": {2, 3, 10}, "b.py": {1}}


def test_revision_cannot_inject_git_options(tmp_path):
    if subprocess.run(["git", "--version"], capture_output=True).returncode != 0:
        pytest.skip("git is not installed")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    out = tmp_path / "written-by-git.txt"
    with pytest.raises(DiffError, match="not a git revision"):
        changed(tmp_path, base=f"--output={out}")
    assert not out.exists()
    is_error, text = _call("scan_project", {"path": str(tmp_path), "changes": f"--output={out}"})
    assert is_error and "not a git revision" in text and not out.exists()


# pass (b): adversarial inputs ---------------------------------------------------
def test_thousands_of_findings_on_one_long_line_stay_linear(tmp_path):
    import time

    from vibeaudit.scanner import Options, scan

    write(tmp_path, "m.sql", "CREATE TABLE t (" + ", ".join(f"c{i}_at timestamp" for i in range(8000)) + ");\n")
    start = time.perf_counter()
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    assert len(res.findings) == 8000
    assert time.perf_counter() - start < 4  # 0.3 s now, 9 s on 0.5.1 (the ignore comment was searched per finding)


def test_cache_entries_with_a_non_numeric_timestamp_are_dropped(tmp_path, monkeypatch):
    from vibeaudit import store

    monkeypatch.setenv("VIBEAUDIT_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(store, "ENABLED", True)
    (tmp_path / "t.json").write_text('{"bad": ["x", 1], "flag": [true, 1], "good": [9e18, 2]}')
    c = store.TimedCache("t.json", ttl=60)
    assert c.get("bad") is None and c.get("flag") is None
    c.put("new", 3)
    c.save()  # crashed on 0.5.1: float - str
    assert set(__import__("json").loads((tmp_path / "t.json").read_text())) == {"good", "new"}


# pass (c): real-repository sweep (pallets/flask, pallets/werkzeug) ---------------
def _found(tmp_path, prefix):
    from vibeaudit.scanner import Options, scan

    res = scan(str(tmp_path), Options(offline=True, external="none"))
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id.startswith(prefix))


def test_secret_in_a_docstring_example_is_not_a_secret(tmp_path):
    write(tmp_path, "config.py", 'class Config:\n    """Use it like this::\n\n        SECRET_KEY = \'development key\'\n    """\n\n'
          "SECRET_KEY = 'hardcoded-production-key-123'\n")
    assert _found(tmp_path, "SEC004") == [("config.py", 7, "SEC004")]


def test_version_and_platform_gated_imports_are_optional(tmp_path):
    write(tmp_path, "pyproject.toml", "[project]\nname = 'x'\ndependencies = []\n")
    write(tmp_path, "prof.py", "import sys\nif sys.version_info >= (3, 15):\n    from profiling.tracing import Profile\n"
          "if sys.platform == 'win32':\n    import winreg_helper\nimport requests\n")
    assert _found(tmp_path, "QA007") == [("prof.py", 6, "QA007")]


def test_not_implemented_in_a_subclassed_base_is_an_interface(tmp_path):
    write(tmp_path, "views.py", "class View:\n    def dispatch_request(self):\n        raise NotImplementedError\n\n"
          "class MethodView(View):\n    def dispatch_request(self):\n        return 1\n\n"
          "class PaymentService:\n    def charge(self):\n        raise NotImplementedError\n")
    assert _found(tmp_path, "QA005") == [("views.py", 10, "QA005")]


def test_examples_and_docs_do_not_need_declared_dependencies(tmp_path):
    write(tmp_path, "pyproject.toml", "[project]\nname = 'x'\ndependencies = []\n")
    write(tmp_path, "examples/demo.py", "import redis\n")
    write(tmp_path, "docs/conf.py", "import docutils\n")
    write(tmp_path, "src/app.py", "import redis\n")
    assert _found(tmp_path, "QA007") == [("src/app.py", 1, "QA007")]


def test_request_url_reaches_a_template_sink(tmp_path):
    """False negative found on we45/Vulnerable-Flask-App: request.url was not a taint source."""
    write(tmp_path, "app.py",
          "from flask import Flask, request, render_template_string, redirect\napp = Flask(__name__)\n\n"
          "@app.errorhandler(404)\ndef missing(e):\n    page = '<h3>%s</h3>' % request.url\n    return render_template_string(page), 404\n\n"
          "@app.before_request\ndef https():\n    if not request.is_secure:\n"
          "        return redirect(request.url.replace('http://', 'https://', 1), 301)\n")
    assert [(ln, r) for _f, ln, r in _found(tmp_path, "BE")] == [(7, "BE007")]


# pass (d): long-lived process and concurrency ------------------------------------
def test_concurrent_scans_do_not_share_settings(tmp_path):
    """Two threads scanning at once: one scan's auth helpers were wiped by the other's reset (20 of 20 runs)."""
    import threading

    from vibeaudit.scanner import Options, scan

    route = "".join(f"@app.post('/api/i{i}')\ndef i{i}():\n    require_team(request)\n    db.execute('DELETE FROM t')\n    return ''\n\n"
                    for i in range(40))
    write(tmp_path / "a", "app.py", route)
    write(tmp_path / "b", "app.py", route)
    results = {}

    def run(name, helpers):
        res = scan(str(tmp_path / name), Options(offline=True, external="none", auth_helpers=helpers))
        results[name] = sum(1 for f in res.findings if f.rule_id == "AUTH001")

    for _ in range(5):
        threads = [threading.Thread(target=run, args=("a", ["require_team"])), threading.Thread(target=run, args=("b", []))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results == {"a": 0, "b": 40}


def test_project_wide_checks_read_each_file_once_not_once_per_route(tmp_path, monkeypatch):
    """Found by the 10,000-file scale run: the ATOMIC_REQUESTS check re-read every file for every route,
    so scan time grew with routes x files (98 s instead of 59 s at 10,000 files)."""
    from vibeaudit import datascan
    from vibeaudit.files import SourceFile
    from vibeaudit.scanner import Options, scan

    for i in range(60):
        write(tmp_path, f"app/r{i}.py", f"@app.post('/r{i}')\ndef r{i}():\n    Order.objects.create(a=1)\n    return ''\n")
    reads = {"n": 0}
    real_text = SourceFile.text
    real_tx = datascan.DataScanner._transactions

    def counting_tx(self):
        monkeypatch.setattr(SourceFile, "text", property(lambda sf: reads.__setitem__("n", reads["n"] + 1) or real_text.fget(sf)))
        try:
            return real_tx(self)
        finally:
            monkeypatch.setattr(SourceFile, "text", real_text)

    monkeypatch.setattr(datascan.DataScanner, "_transactions", counting_tx)
    scan(str(tmp_path), Options(offline=True, external="none"))
    assert reads["n"] <= 3 * 60, reads  # about one read per file; 0.5.1 made 60 routes x 60 files


# found on Rubicon (the peer project) while preparing 0.5.2 ----------------------
def test_sql_fragment_of_constants_and_placeholders_is_not_injection(tmp_path):
    write(tmp_path, "store.py",
          "def drop(db, ids, last=None):\n    for i in range(0, len(ids), 500):\n        chunk = ids[i:i + 500]\n"
          "        where = f\"tx IN ({','.join('?' * len(chunk))})\" + (\"\" if last is None else \" AND id <= ?\")\n"
          "        db.execute(f\"DELETE FROM journal WHERE {where}\", chunk)\n\n"
          "def find(db, column, value):\n    where = f\"{column} = ?\"\n    db.execute(f\"SELECT * FROM t WHERE {where}\", (value,))\n")
    assert [(ln, r) for _f, ln, r in _found(tmp_path, "BE001")] == [(9, "BE001")]  # column comes from the caller


def test_expected_exception_check_is_not_a_swallowed_error(tmp_path):
    write(tmp_path, "checks.py",
          "def check(fn):\n    try:\n        fn('positional')\n        raise AssertionError('must be refused')\n    except Exception:\n        pass\n"
          "    try:\n        fn(1)\n    except Exception:\n        pass\n")
    assert [(ln, r) for _f, ln, r in _found(tmp_path, "QA003")] == [(9, "QA003")]


def test_specific_exception_ignored_on_purpose_is_not_swallowed(tmp_path):
    # benchmark: werkzeug and starlette ignore KeyError or NoMatchFound as a deliberate fallback
    write(tmp_path, "m.py", "def f(d, k):\n    try:\n        return d[k]\n    except KeyError:\n        pass\n"
          "    try:\n        g()\n    except (OSError, Exception):\n        pass\n    try:\n        g()\n    except:\n        pass\n")
    assert [ln for _f, ln, _r in _found(tmp_path, "QA003")] == [8, 12]
