"""probe, third round (setup gaps found when re-measuring): plain-PHP pages as routes, token keys such as auth_token,
HTML form sign-in with a CSRF token, and a loud warning when the credentials did not take effect."""
import http.server
import json
import sqlite3
import threading
import urllib.parse

import pytest

from vibeaudit.exploit import ExploitError
from vibeaudit.files import Project
from vibeaudit.probe import Prober, Target, _token, login, login_form, plain_php_routes
from vibeaudit.scanner import Options, scan

INDEX = "<?php\nrequire_once 'source/low.php';\n?>\n<form><input name='id'><input type='submit' name='Submit'></form>\n"
LOW = "<?php\n$id = $_GET['id'];\n$q = \"SELECT first_name FROM users WHERE user_id = '$id'\";\n"


class Dvwa(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, status, body, headers=()):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def signed_in(self):
        return "PHPSESSID=good" in self.headers.get("Cookie", "") and "security=low" in self.headers.get("Cookie", "")

    def do_GET(self):  # noqa: N802
        u = urllib.parse.urlsplit(self.path)
        if u.path == "/login.php":
            return self.reply(200, "<form action='login.php' method='post'><input type='text' name='username'>"
                                   "<input type='password' name='password'><input type='hidden' name='user_token' "
                                   "value='csrf123'><input type='submit' name='Login' value='Login'></form>",
                              [("Set-Cookie", "PHPSESSID=fresh; path=/"), ("Set-Cookie", "security=low; path=/")])
        if not self.signed_in():
            return self.reply(302, "", [("Location", "/login.php")])
        if u.path == "/vulnerabilities/sqli/index.php":
            q = dict(urllib.parse.parse_qsl(u.query))
            try:
                rows = sqlite3.connect(":memory:").execute("SELECT '" + q.get("id", "") + "'").fetchall()
                return self.reply(200, f"<pre>{rows}</pre><form><input name='id'></form>")
            except sqlite3.Error as e:
                return self.reply(200, f"sqlite3.OperationalError: {e}")
        return self.reply(200, "<p>home</p>")

    def do_POST(self):  # noqa: N802
        form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()))
        if self.path.startswith("/login.php") and form.get("user_token") == "csrf123" and form.get("Login") == "Login" \
                and form.get("username") == "admin" and form.get("password") == "password":
            return self.reply(302, "", [("Location", "/index.php"), ("Set-Cookie", "PHPSESSID=good; path=/")])
        return self.reply(302, "", [("Location", "/login.php")])


@pytest.fixture()
def dvwa(tmp_path):
    (tmp_path / "vulnerabilities" / "sqli" / "source").mkdir(parents=True)
    (tmp_path / "vulnerabilities" / "sqli" / "index.php").write_text(INDEX)
    (tmp_path / "vulnerabilities" / "sqli" / "source" / "low.php").write_text(LOW)
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.php").write_text("<?php $x = $_GET['x'];")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Dvwa)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield tmp_path, f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_plain_php_pages_are_routes(dvwa):
    root, _url = dvwa
    routes = plain_php_routes(Project(root), [])
    paths = {r.path for r in routes}
    assert "/vulnerabilities/sqli/index.php" in paths and "/vendor/lib.php" not in paths
    page = next(r for r in routes if r.path == "/vulnerabilities/sqli/index.php")
    assert "$_GET['id']" in page.body  # parameters come from the included source file


def test_form_login_with_csrf_then_sqli(dvwa):
    root, url = dvwa
    t = Target(url, False, 200, 300)
    auth = login_form(t, "/login.php", {"username": "admin", "password": "password"})
    assert "PHPSESSID=good" in auth["Cookie"] and "security=low" in auth["Cookie"]
    with pytest.raises(ExploitError):
        login_form(t, "/login.php", {"username": "admin", "password": "wrong"})
    res = scan(str(root), Options(offline=True, external="none", include_preview=True, min_severity="info"))
    routes = res.routes + plain_php_routes(Project(root), res.routes)
    prober = Prober(t, routes, auth)
    found = {f.rule_id for f in prober.run()}
    assert "BE001" in found and not prober.auth_failed


def test_credentials_that_did_not_take_effect(dvwa):
    root, url = dvwa
    res = scan(str(root), Options(offline=True, external="none", include_preview=True, min_severity="info"))
    routes = res.routes + plain_php_routes(Project(root), res.routes)
    for r in routes:
        r.params = r.params or []
    extra = [type(routes[0])(f"p{i}.php", 1, f"/p{i}.php", ["GET"], "$_GET['a']", "php-plain", "php") for i in range(5)]
    prober = Prober(Target(url, False, 200, 300), routes + extra, {"Cookie": "PHPSESSID=stale"})
    prober.run()
    assert prober.auth_failed


def test_token_keys():
    assert _token({"auth_token": "eyJhbGciOi.x.y", "status": "success"}) == "eyJhbGciOi.x.y"
    assert _token({"data": {"accessToken": "abcdefgh123"}}) == "abcdefgh123"
    assert _token({"user": {"id_token": "abcdefgh123"}}) == "abcdefgh123"
    assert _token({"tokens": "x", "message": "token expired soon"}) == ""
    assert _token({"a": {"b": {"token": "too-deep-123"}}}) == ""


class Vampi(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = json.dumps({"auth_token": "eyJ0eXAiOiJKV1Qi.payload.sig", "message": "Successfully logged in.",
                           "status": "success"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


def test_login_reads_auth_token():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Vampi)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        t = Target(f"http://127.0.0.1:{server.server_address[1]}", False, 200, 10)
        assert login(t, "/users/v1/login", '{"username": "name1", "password": "pass1"}') == \
            {"Authorization": "Bearer eyJ0eXAiOiJKV1Qi.payload.sig"}
    finally:
        server.shutdown()
