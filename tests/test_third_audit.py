"""Regression tests for the third external audit (0.5.0) and for the testing blind spots it exposed.

Each finding test was run against 0.5.0 first and failed there; findings that did not reproduce are
listed in the CHANGELOG with the reason."""
import gzip
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from vibeaudit import aiscan, deps, feedback, mcp_server, plugins, store, updater
from vibeaudit.cli import main
from vibeaudit.scanner import Options, scan


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _rules(tmp_path, prefix=""):
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    assert res.meta.get("internal_errors", []) == []
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id.startswith(prefix))


@pytest.fixture
def cache_on(tmp_path, monkeypatch):
    monkeypatch.setenv("VIBEAUDIT_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(store, "ENABLED", True)
    return tmp_path / "cache"


# 1 ------------------------------------------------------------------ cache
def test_1_timed_cache_is_safe_under_concurrent_put_get_and_save(cache_on):
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)  # switch threads as often as possible so races actually happen
    try:
        _stress(cache_on)
    finally:
        sys.setswitchinterval(old)


def _stress(cache_on):
    c = store.TimedCache("stress.json", ttl=3600)
    errors = []

    def writer(n):
        try:
            for i in range(3000):
                c.put(f"{n}-{i}", i)
                c.get(f"{n}-{i // 2}")
        except Exception as e:  # noqa: BLE001 - the point is that nothing escapes
            errors.append(repr(e))

    def saver():
        try:
            for _ in range(300):
                c.save()
        except Exception as e:  # noqa: BLE001
            errors.append(repr(e))

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)] + [threading.Thread(target=saver) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    c.save()
    saved = json.loads((cache_on / "stress.json").read_text())
    assert len(saved) == 8 * 3000


# 2 ------------------------------------------------------------- --no-cache
def test_2_no_cache_applies_to_one_scan_only(tmp_path, cache_on):
    write(tmp_path, "app.py", "x = 1\n")
    assert main(["scan", str(tmp_path), "--no-cache", "--offline", "--external", "none", "--fail-on", "none", "-q"]) == 0
    assert store.ENABLED is True  # a long-lived caller (tests, an editor plugin) keeps its cache
    scan(str(tmp_path), Options(offline=True, external="none", cache=False))
    assert store.ENABLED is True


# 3 ------------------------------------------------------------------ update
def test_3_update_takes_effect_in_a_running_process(cache_on):
    aiscan.retired_models()  # compiled from the shipped list, as in a long-lived MCP server
    deps.popular("npm")
    top = gzip.compress("\n".join(["brand-new-popular-pkg"] + [f"p{i}" for i in range(1500)]).encode())
    files = {"pypi_top.txt.gz": top, "npm_top.txt.gz": top, "retired_models.txt": b"m-1\nm-2\nm-3\nm-4\nsunset-model\n"}
    assert updater.update_data(lambda m: None, fetch=lambda url: files[url.rsplit("/", 1)[1]]) == 0
    assert aiscan.retired_models().search('"sunset-model"')
    assert "brand-new-popular-pkg" in deps.popular("npm")[0]


# 4 ---------------------------------------------------------------- feedback
def test_4_feedback_can_mark_online_dependency_findings(tmp_path, monkeypatch):
    write(tmp_path, "requirements.txt", "flask==3.0.0\nreqeusts-helper==1.0\n")
    monkeypatch.setattr(deps, "_registry_lookup", lambda d: ("missing", None, ""))
    monkeypatch.setattr(deps, "osv_lookup", lambda d: {})
    assert feedback.record(tmp_path, "DEP001", "requirements.txt", 2, "confirmed") is not None


def test_4_feedback_accepts_config_and_plugins(tmp_path):
    write(tmp_path, "app.py", "print('debug')\n")
    write(tmp_path, "settings/audit.toml", "disable = ['QA001']\n")
    write(tmp_path, "org_rules.py",
          "from vibeaudit import file_rule\n\n@file_rule('ORG777', 'print call', severity='low', kinds=['py'])\n"
          "def no_print(sf):\n    for n, line in enumerate(sf.lines, 1):\n        if line.startswith('print('):\n"
          "            yield n, 'Use the logger.'\n")
    try:
        assert main(["feedback", "false-positive", "ORG777", "app.py:1", "--path", str(tmp_path),
                     "--plugin", str(tmp_path / "org_rules.py"), "--config", str(tmp_path / "settings/audit.toml")]) == 0
    finally:
        plugins.unregister("ORG777")


# 5 -------------------------------------------------- tests without an install
def test_5_child_processes_can_import_vibeaudit_from_the_checkout():
    src = str(Path(__file__).parent.parent / "src")
    out = subprocess.run([sys.executable, "-c", "import vibeaudit, os; print(os.path.dirname(vibeaudit.__file__))"],
                         capture_output=True, text=True, cwd=str(Path(__file__).parent.parent.parent))
    assert out.returncode == 0, out.stderr
    assert src.lower() in os.environ.get("PYTHONPATH", "").lower()


# 7 ------------------------------------------------------------------ LLM010
def test_7_vector_filter_defined_before_the_call_and_line_of_the_call(tmp_path):
    write(tmp_path, "app.py",
          "@app.post('/ask')\n@login_required\ndef ask():\n    opts = {'k': 4}\n    scoped = {'filter': {'owner': current_user.id}}\n"
          "    return store.similarity_search(request.json['q'], **scoped)\n\n"
          "@app.post('/ask2')\n@login_required\ndef ask2():\n    q = request.json['q']\n    log(q)\n"
          "    return store.similarity_search(q, k=4)\n")
    assert _rules(tmp_path, "LLM010") == [("app.py", 13, "LLM010")]


# 9 ------------------------------------------------------------------ contracts
def test_9_template_literals_with_quotes_and_a_missing_api_prefix(tmp_path):
    write(tmp_path, "app.py", "@app.get('/users')\ndef users():\n    return []\n\n@app.post('/orders/<oid>')\ndef order(oid):\n    return {}\n")
    write(tmp_path, "web/api.js",
          "export const a = () => fetch(`/orders/${id || 'new'}`, { method: 'DELETE' });\n"   # 1 API002
          "export const b = () => fetch('/api/users');\n"                                       # 2 API001: /users exists
          "export const c = () => fetch('/api/weather');\n")                                    # no backend route looks like it
    assert _rules(tmp_path, "API") == [("web/api.js", 1, "API002"), ("web/api.js", 2, "API001")]


# 10 ----------------------------------------------------------------- DATA010
def test_10_writes_through_a_transaction_client_are_transactional(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next": "14.0.0"}}')
    write(tmp_path, "app/api/checkout/route.ts",
          "export async function POST(req: Request) {\n  await withTx(async (tx) => {\n"
          "    await tx.order.create({ data: {} });\n    await tx.payment.create({ data: {} });\n  });\n"
          "  return Response.json({});\n}\n")
    assert _rules(tmp_path, "DATA010") == []


# 12 ------------------------------------------------------------ leftover markers
def test_12_no_leftover_working_markers_in_the_repository():
    root = Path(__file__).parent.parent
    marker = "pony" + "tail"
    hits = [str(p.relative_to(root)) for p in list((root / "src").rglob("*.py")) + list(root.glob("*.md")) + list(root.glob("*.yml"))
            if marker in p.read_text(encoding="utf-8", errors="replace").lower()]
    assert hits == []


# ------------------------------------------------------------ blind spots
def test_blind_spot_repeated_mcp_calls_do_not_leak_state(tmp_path):
    """A long-lived MCP server scans many projects: one project's config must not leak into the next."""
    route = "@app.post('/api/items')\ndef items():\n    require_team(request)\n    db.execute('DELETE FROM items')\n    return ''\n"
    write(tmp_path / "a", "app.py", route)
    write(tmp_path / "a", ".vibeaudit.toml", "auth-helpers = ['require_team']\n")
    write(tmp_path / "b", "app.py", route)
    for _ in range(2):
        a = mcp_server.tool_scan_project({"path": str(tmp_path / "a")})
        b = mcp_server.tool_scan_project({"path": str(tmp_path / "b")})
        assert not [f for f in a["findings"] if f["rule_id"] == "AUTH001"]
        assert [f for f in b["findings"] if f["rule_id"] == "AUTH001"]


def test_blind_spot_files_the_scanner_never_loads(tmp_path):
    """Ignored, excluded and binary files are not loaded, but they exist: nothing may call them missing."""
    if subprocess.run(["git", "--version"], capture_output=True).returncode != 0:
        pytest.skip("git is not installed")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    write(tmp_path, ".gitignore", "generated/\nsrc/gen.ts\n")
    write(tmp_path, "package.json", '{"name": "x", "dependencies": {"next": "14.0.0"}}')
    write(tmp_path, "src/gen.ts", "export const g = 1;\n")
    write(tmp_path, "src/main.ts", "import { g } from './gen';\nexport const m = g;\n")
    write(tmp_path, "pkg/__init__.py", "")
    write(tmp_path, "pkg/generated/__init__.py", "x = 1\n")
    write(tmp_path, "pkg/use.py", "from .generated import x\n")
    (tmp_path / "public").mkdir()
    (tmp_path / "public" / "resume.pdf").write_bytes(b"%PDF-1.4\n")
    write(tmp_path, "app/page.tsx", 'export default function P() { return <a href="/resume.pdf">CV</a> }\n')
    write(tmp_path, "app/about/page.tsx", "export default function A() { return null }\n")
    found = _rules(tmp_path)
    assert not [f for f in found if f[2] in ("QA006", "UI013")], found


# 6 ------------------------------------------------------------ test isolation
def test_6_every_cache_is_reset_between_tests_including_llm_verdicts():
    from vibeaudit import llm

    assert llm.VERDICT_CACHE in store.TimedCache.instances
    assert all(c._data is None for c in store.TimedCache.instances)


# 8 and 11 did not reproduce; kept as guards ----------------------------------
def test_8_parallel_slots_intercepting_routes_and_files_in_public(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next": "14.0.0"}}')
    write(tmp_path, "app/layout.tsx", "export const metadata = {};\nexport default function L({ children }) { return children }\n")
    write(tmp_path, "app/error.tsx", "export default function E() { return null }\n")
    for p in ("page.tsx", "photo/[id]/page.tsx", "@modal/(.)photo/[id]/page.tsx", "@modal/default.tsx"):
        write(tmp_path, "app/" + p, "export default function P() { return null }\n")
    (tmp_path / "public").mkdir()
    (tmp_path / "public" / "resume.pdf").write_bytes(b"%PDF-1.4\n")
    write(tmp_path, "components/Nav.tsx", 'export function Nav() {\n  return (<nav><a href="/photo/1">Photo</a>'
          '<a href="/resume.pdf">CV</a><a href="/missing">Missing</a></nav>)\n}\n')
    assert _rules(tmp_path, "UI013") == [("components/Nav.tsx", 2, "UI013")]


def test_11_content_length_header_counts_as_a_size_limit(tmp_path):
    write(tmp_path, "api.py",
          "from fastapi import UploadFile, Request\n\n@app.post('/up')\nasync def up(request: Request, file: UploadFile):\n"
          "    if int(request.headers.get('Content-Length', 0)) > 10_000_000:\n        raise ValueError()\n"
          "    data = await file.read()\n    return {}\n")
    assert _rules(tmp_path, "REL004") == []
