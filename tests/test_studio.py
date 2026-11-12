"""`vibeaudit studio`: the API data, and the server's defences (localhost only, token, Host check, no paths
from requests, safe rendering, CSP)."""
from __future__ import annotations

import http.client
import json
import re
import threading
from pathlib import Path

import pytest

from vibeaudit import studio
from vibeaudit.cli import main
from vibeaudit.scanner import Options

APP = '''from flask import Flask, request
from openai import OpenAI
import os

app = Flask(__name__)
client = OpenAI()


@app.post("/api/run")
def run():
    data = request.get_json()
    plan = client.chat.completions.create(model="m", max_tokens=5, messages=[{"role": "user", "content": data["q"]}])
    script = plan.choices[0].message.content
    exec(script)
    return "ok"


@app.get("/files")
def files():
    os.system("ls " + request.args.get("dir", ""))
    return "ok"
'''
ASSETS = Path(studio.__file__).parent / "studio_assets"


@pytest.fixture
def server(tmp_path):
    (tmp_path / "app.py").write_text(APP)
    (tmp_path / "secret.txt").write_text("not served")
    st = studio.Studio(str(tmp_path), Options(offline=True, external="none", feedback=False, cache=False))
    srv = studio.make_server(st, 0, token="t0ken-for-tests")
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv, tmp_path
    srv.shutdown()
    srv.server_close()


def request(srv, method, path, token="t0ken-for-tests", host=None):
    port = srv.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    headers = {"Host": host or f"127.0.0.1:{port}"}
    if token:
        headers["X-Studio-Token"] = token
    conn.request(method, path, headers=headers)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, dict(resp.getheaders()), body


def test_binds_localhost_and_serves_the_page_with_strict_headers(server):
    srv, _ = server
    assert srv.server_address[0] == "127.0.0.1"
    for path in ("/", "/app.js", "/app.css"):
        status, headers, body = request(srv, "GET", path, token=None)
        assert status == 200 and body
        assert "script-src 'self'" in headers["Content-Security-Policy"] and headers["X-Frame-Options"] == "DENY"
        assert headers["X-Content-Type-Options"] == "nosniff" and headers["Referrer-Policy"] == "no-referrer"


def test_api_needs_the_token_and_a_local_host(server):
    srv, _ = server
    assert request(srv, "GET", "/api/scan", token=None)[0] == 403
    assert request(srv, "GET", "/api/scan", token="wrong")[0] == 403
    assert request(srv, "GET", "/api/scan", host="evil.example:80")[0] == 403  # DNS rebinding
    assert request(srv, "GET", "/", token=None, host="evil.example")[0] == 403
    assert request(srv, "POST", "/api/rescan", token=None)[0] == 403
    assert request(srv, "PUT", "/api/scan")[0] == 405
    assert request(srv, "GET", "/api/nope")[0] == 404 and request(srv, "GET", "/etc/passwd")[0] == 404
    port = srv.server_address[1]
    assert request(srv, "GET", "/api/scan", host=f"localhost:{port}")[0] == 200


def test_scan_data_routes_flows_and_score(server):
    srv, _ = server
    status, _h, body = request(srv, "GET", "/api/scan")
    data = json.loads(body)
    assert status == 200 and data["files_scanned"] >= 1
    paths = {r["path"]: r for r in data["routes"]}
    assert paths["/api/run"]["calls_llm"] and not paths["/api/run"]["authenticated"] and paths["/api/run"]["findings"]
    flows = {f["rule_id"]: f for f in data["flows"]}
    assert flows["LLM002"]["source"] == "model output" and flows["LLM002"]["sink"] == "code, shell or SQL"
    assert [s["role"] for s in flows["LLM002"]["steps"]][-1] == "sink" and flows["BE002"]["source"] == "user input"
    security = next(d for d in data["domains"] if d["domain"] == "Security")
    assert security["score"] < 100 and security["categories"][0]["rules"][0]["findings"]


def test_code_view_serves_only_scanned_files(server):
    srv, root = server
    status, _h, body = request(srv, "GET", "/api/code?file=app.py&line=14")
    assert status == 200 and any(c["current"] and "exec(script)" in c["code"] for c in json.loads(body)["lines"])
    outside = root.parent / "outside.txt"
    outside.write_text("private")
    for bad in ("../outside.txt", "..%2Foutside.txt", "%2e%2e/outside.txt", str(outside), "C:/Windows/win.ini",
                "/etc/passwd", "app.py%00", "", "app.py&line=abc"):
        assert request(srv, "GET", f"/api/code?file={bad}&line=1")[0] == 404, bad
    assert request(srv, "GET", "/api/code?file=app.py&line=-1")[0] == 404


def test_explain_and_rescan(server):
    srv, root = server
    data = json.loads(request(srv, "GET", "/api/scan")[2])
    fp = next(f["fingerprint"] for f in data["findings"] if f["rule_id"] == "LLM002")
    status, _h, body = request(srv, "GET", f"/api/explain?fingerprint={fp}")
    assert status == 200 and json.loads(body)["flow"][0]["role"] == "source"
    assert request(srv, "GET", "/api/explain?fingerprint=" + "0" * 32)[0] == 404
    assert request(srv, "GET", "/api/explain?fingerprint=../x")[0] == 404
    (root / "net.py").write_text("import requests\nr = requests.get('https://x')\n")
    status, _h, body = request(srv, "POST", "/api/rescan")
    assert status == 200 and "REL001" in {f["rule_id"] for f in json.loads(body)["findings"]}


def test_page_never_renders_repository_text_as_html():
    js = (ASSETS / "studio.js").read_text(encoding="utf-8")
    for unsafe in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert unsafe not in js, unsafe
    html = (ASSETS / "studio.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)", html) and " style=" not in html and "http" not in html  # nothing inline or external
    css = (ASSETS / "studio.css").read_text(encoding="utf-8")
    assert "url(" not in css and "@import" not in css
    assert '"studio_assets/*"' in (Path(__file__).parent.parent / "pyproject.toml").read_text(encoding="utf-8")


def test_cli_rejects_bad_input(tmp_path):
    assert main(["studio", str(tmp_path / "missing"), "--no-browser"]) == 2
    assert main(["studio", str(tmp_path), "--port", "70000", "--no-browser"]) == 2
