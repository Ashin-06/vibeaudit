"""probe, second round (follow-ups of docs/PROBE_EVAL.md): JSON bodies, routers registered through a function,
stricter AUTH010 evidence, GraphQL through introspection, and signing in for a token."""
import http.server
import json
import sqlite3
import threading
import urllib.parse

import pytest

from vibeaudit.probe import Prober, Target, login
from vibeaudit.scanner import Options, scan

EXPRESS_PKG = '{"dependencies": {"express": "4"}}'
ROUTES_JS = """module.exports = (app, db) => {
  app.post("/api/search", (req, res) => {
    const { term } = req.body;
    db.all("SELECT * FROM items WHERE name = '" + term + "'", (e, rows) => res.json(rows));
  });
  app.post("/api/login", (req, res) => {
    const { username, password } = req.body;
    res.status(401).json({ error: "bad credentials" });
  });
  app.post("/api/otp/missing", (req, res) => {
    const { code } = req.body;
    res.json({});
  });
};
"""
SERVER_JS = "const express = require('express');\nconst app = express();\napp.use(express.json());\nrequire('./routes')(app, db);\n"


class JsonApi(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        return self.reply(200, {"ok": True})

    def do_POST(self):  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        if "json" not in self.headers.get("Content-Type", ""):
            return self.reply(415, {"error": "JSON only"})
        data = json.loads(raw or "{}")
        if self.path == "/api/search":
            try:
                return self.reply(200, sqlite3.connect(":memory:").execute("SELECT '" + str(data.get("term", "")) + "'").fetchall())
            except sqlite3.Error as e:
                return self.reply(500, {"error": f"sqlite3.OperationalError: {e}"})
        if self.path == "/api/login":
            if data == {"username": "alice", "password": "s3cret"}:
                return self.reply(200, {"data": {"token": "tok-alice"}})
            return self.reply(401, {"error": "bad credentials"})
        return self.reply(404, {"error": "not found"})


@pytest.fixture()
def json_app(tmp_path):
    (tmp_path / "package.json").write_text(EXPRESS_PKG)
    (tmp_path / "server.js").write_text(SERVER_JS)
    (tmp_path / "routes.js").write_text(ROUTES_JS)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), JsonApi)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield tmp_path, f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_routes_registered_through_a_function_and_json_bodies(json_app):
    root, url = json_app
    res = scan(str(root), Options(offline=True, external="none", include_preview=True, min_severity="info"))
    assert {r.path for r in res.routes} >= {"/api/search", "/api/login", "/api/otp/missing"}
    found = {f.rule_id: f for f in Prober(Target(url, False, 200, 500), res.routes).run()}
    assert "BE001" in found  # the quote reached SQL only as JSON
    # AUTH010 only for the sign-in that processed the attempts (401), not for the one answering 404
    assert found["AUTH010"].confirmed and found["AUTH010"].file.endswith("routes.js") and found["AUTH010"].line == 6


def test_login_for_a_token(json_app):
    _root, url = json_app
    t = Target(url, False, 200, 50)
    assert login(t, "/api/login", '{"username": "alice", "password": "s3cret"}') == {"Authorization": "Bearer tok-alice"}
    with pytest.raises(Exception):
        login(t, "/api/login", '{"username": "alice", "password": "wrong"}')


GRAPHQL_SOURCE = """import graphene
class Query(graphene.ObjectType):
    paste = graphene.String(title=graphene.String())
    def resolve_paste(root, info, title):
        return db.execute("SELECT content FROM pastes WHERE title = '%s'" % title)
class DeleteAll(graphene.Mutation):
    def mutate(root, info, confirm):
        return Paste.query.delete()
"""
SCHEMA = {"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"}, "types": [
    {"name": "Query", "kind": "OBJECT", "fields": [
        {"name": "paste", "args": [{"name": "title", "type": {"kind": "SCALAR", "name": "String", "ofType": None}}],
         "type": {"kind": "SCALAR", "name": "String", "ofType": None}}]},
    {"name": "Mutation", "kind": "OBJECT", "fields": [
        {"name": "deleteAll", "args": [{"name": "confirm", "type": {"kind": "SCALAR", "name": "String", "ofType": None}}],
         "type": {"kind": "SCALAR", "name": "String", "ofType": None}}]}]}}}


class GraphQL(http.server.BaseHTTPRequestHandler):
    queries = []

    def log_message(self, *a):
        pass

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()

    def do_POST(self):  # noqa: N802
        q = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))["query"]
        GraphQL.queries.append(q)
        if self.path != "/graphql":
            self.send_response(404)
            self.end_headers()
            return
        if "__schema" in q:
            out = SCHEMA
        elif "paste(" in q and "'" in q:
            out = {"errors": [{"message": "sqlite3.OperationalError: unrecognized token"}]}
        else:
            out = {"data": {}}
        body = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


def test_graphql_introspection_and_arguments(tmp_path):
    (tmp_path / "schema.py").write_text(GRAPHQL_SOURCE)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), GraphQL)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        res = scan(str(tmp_path), Options(offline=True, external="none", include_preview=True, min_severity="info"))
        url = f"http://127.0.0.1:{server.server_address[1]}"
        found = {f.rule_id for f in Prober(Target(url, False, 200, 300), res.routes).run()}
        assert "BE001" in found
        assert not any("deleteAll" in q for q in GraphQL.queries)  # destructive mutations are never sent
    finally:
        server.shutdown()


def test_form_then_json_after_415(json_app):
    _root, url = json_app
    from vibeaudit.model import Route
    r = Route("routes.js", 2, "/api/search", ["POST"], "db.all(q + req.query.term)", "express", "js", params=[])
    p = Prober(Target(url, False, 200, 50), [r])
    p.json = False
    st = p.send("POST", "/api/search", {"term": "x"})[0]
    assert st == 200 and p.json  # retried as JSON after the 415, and remembers it
