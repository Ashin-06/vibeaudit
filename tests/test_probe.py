"""vibeaudit probe: dynamic checks against a running app, with the safety limits that keep it non-destructive."""
import http.server
import sqlite3
import threading
import urllib.parse
import urllib.request

import pytest

from vibeaudit.exploit import ExploitError
from vibeaudit.files import Project  # noqa: F401  (route model comes from the scanner)
from vibeaudit.probe import Prober, Target, merge
from vibeaudit.scanner import Options, scan

SOURCE = """from flask import Flask, request, redirect
from flask_login import login_required
import sqlite3, urllib.request
app = Flask(__name__)

@app.route("/search")
def search():
    q = request.args.get("q")
    return str(sqlite3.connect(":memory:").execute("SELECT '" + q + "'").fetchall())

@app.route("/file")
def file():
    name = request.args.get("name")
    return open("docs/" + name).read()

@app.route("/hello")
def hello():
    name = request.args.get("name")
    return "<p>Hello " + name + "</p>"

@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return urllib.request.urlopen(url).read()

@app.route("/go")
def go():
    return redirect(request.args.get("next"))

@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("username")
    return "bad credentials", 401

@app.route("/admin/stats")
@login_required
def stats():
    return "revenue: 12345, users: 678 and some more private numbers here"
"""


class Vulnerable(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, status, body, ctype="text/html", headers=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):  # noqa: N802
        u = urllib.parse.urlsplit(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        origin = self.headers.get("Origin", "")
        if u.path == "/":
            return self.reply(200, "home", headers=[("Access-Control-Allow-Origin", origin),
                                                    ("Access-Control-Allow-Credentials", "true")] if origin else [])
        if u.path == "/search":
            try:
                return self.reply(200, str(sqlite3.connect(":memory:").execute("SELECT '" + q.get("q", "") + "'").fetchall()))
            except sqlite3.Error as e:
                return self.reply(500, f"sqlite3.OperationalError: {e}")
        if u.path == "/file":
            return self.reply(200, "root:x:0:0:root:/root:/bin/sh" if ".." in q.get("name", "") else "doc", "text/plain")
        if u.path == "/hello":
            return self.reply(200, "<p>Hello " + q.get("name", "") + "</p>")
        if u.path == "/fetch":
            if q.get("url", "").startswith("http://127.0.0.1"):
                urllib.request.urlopen(q["url"], timeout=2).read()
            return self.reply(200, "ok")
        if u.path == "/go":
            return self.reply(302, "", headers=[("Location", q.get("next", "/"))])
        if u.path == "/admin/stats":
            return self.reply(200, "revenue: 12345, users: 678 and some more private numbers here")
        return self.reply(404, "not found")

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        return self.reply(401, "bad credentials")

    def do_DELETE(self):  # noqa: N802
        raise AssertionError("probe must never send DELETE")


@pytest.fixture()
def app(tmp_path):
    (tmp_path / "app.py").write_text(SOURCE)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Vulnerable)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield tmp_path, f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_probe_confirms_each_class(app):
    root, url = app
    res = scan(str(root), Options(offline=True, external="none", include_preview=True, min_severity="info"))
    found = Prober(Target(url, False, 200, 500), res.routes, {"Cookie": "session=abc"}).run()
    rules = sorted({f.rule_id for f in found})
    assert rules == ["AUTH002", "BE001", "BE005", "BE006", "BE008", "BE012", "CFG019", "FE001"]
    merged = merge(res.findings, found)
    assert any(f.confirmed and f.source == "vibeaudit" for f in merged)  # a static finding marked confirmed


def test_login_without_rate_limit(app):
    root, url = app
    res = scan(str(root), Options(offline=True, external="none", include_preview=True, min_severity="info"))
    found = Prober(Target(url, False, 200, 500), [r for r in res.routes if r.path == "/login"]).run()
    assert sorted(f.rule_id for f in found) == ["AUTH010", "BE012", "CFG019"]  # site-wide: CORS, headers


def test_targets_are_limited():
    with pytest.raises(ExploitError):
        Target("http://example.com", False, 10, 10)
    with pytest.raises(ExploitError):
        Target("http://user:pw@127.0.0.1:1", False, 10, 10)
    t = Target("http://127.0.0.1:1", False, 10, 1)
    with pytest.raises(ExploitError):
        t.request("DELETE", "/x")
    t.request("GET", "/")  # nothing listens: status 0, budget spent
    with pytest.raises(ExploitError):
        t.request("GET", "/")
    assert Target("http://example.com", True, 10, 10).host == "example.com"  # only with --i-own-this-target
