"""`vibeaudit studio`: a local web UI for one project (standard library only, no external assets).

It shows the routes with their auth, write and AI badges, the data flows from user input and model output to
model, database, shell, HTTP and HTML sinks, and the score broken down by domain, category and rule, with
the code and explanation of every finding.

The server is for the person running it and nobody else:
- it binds 127.0.0.1 only (there is no option to listen elsewhere), exclusively: no other process can bind the
  same port and answer in its place;
- every data request needs the random token printed in the URL at start (compared in constant time), so other
  local users and web pages cannot read the results;
- the Host header must be 127.0.0.1 or localhost with this port, which stops DNS-rebinding pages;
- the code view serves only files the scan listed in the project (no path from the request reaches the disk);
- responses carry a strict Content-Security-Policy (scripts from this server only), and the page renders every
  text from the repository with textContent, never as HTML;
- it reads the project and never writes to it. "Re-scan" re-runs the scan (POST, with the token).
"""
from __future__ import annotations

import hmac
import json
import re
import secrets
import socket
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from . import __version__

HOST = "127.0.0.1"
FLOW_RULES = {"BE001": "database", "BE010": "database", "BE002": "shell", "BE003": "code execution",
              "BE005": "HTTP request", "BE008": "redirect", "FE001": "HTML", "LLM001": "model prompt",
              "LLM002": "code, shell or SQL", "LLM011": "JSON parser"}
MAX_FLOWS = 500
STATIC = {"/": ("studio.html", "text/html; charset=utf-8"), "/app.js": ("studio.js", "text/javascript; charset=utf-8"),
          "/app.css": ("studio.css", "text/css; charset=utf-8")}
HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                               "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store", "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-origin",
}


class Studio:
    """The scanned project and the API answers built from it."""

    def __init__(self, path: str, opts):
        from .watch import Watcher

        self.path = path
        self.watcher = Watcher(path, opts)
        self.lock = threading.Lock()
        self.data: Dict[str, Any] = {}
        self.rescan()

    def rescan(self) -> Dict[str, Any]:
        from .scanner import scan

        with self.lock:
            w = self.watcher
            w.changed()
            res = scan(self.path, w.opts, w.project)
            w.findings = {f.fingerprint: f for f in res.findings}
            self.res = res
            self.data = build(res, w.project)
            return self.data

    def code(self, rel: str, line: int) -> Optional[Dict[str, Any]]:
        """A window of a file the scan listed; None for anything else (no request path reaches the disk)."""
        from .explain import context

        sf = self.watcher.project._by_rel.get(rel) if isinstance(rel, str) else None
        if sf is None or sf.text is None:
            return None
        return {"file": rel, "lines": context(sf.text, max(1, line), 12)}

    def explain(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        from . import explain

        f = self.watcher.findings.get(fingerprint)
        if f is None:
            return None
        sf = self.watcher.project._by_rel.get(f.file)
        return explain.explain(f, sf.text if sf is not None and sf.text is not None else "")


def build(res, project) -> Dict[str, Any]:
    from .explain import trace
    from .report import DOMAINS, WEIGHTS

    gating_ids = {id(f) for f in res.gating}
    findings = [dict(f.to_dict(), gating=id(f) in gating_ids) for f in res.findings]
    by_file: Dict[str, List[dict]] = {}
    for f in findings:
        by_file.setdefault(f["file"], []).append(f)
    routes = []
    for r in sorted(res.routes, key=lambda r: (r.file, r.line)):
        d = r.to_dict()
        d["findings"] = [f["fingerprint"] for f in by_file.get(r.file, []) if f["line"] >= r.line
                         and f["line"] <= r.line + r.body.count("\n") + 1]
        routes.append(d)
    flows = []
    for f in res.findings:
        if f.rule_id not in FLOW_RULES or not f.line or len(flows) >= MAX_FLOWS:
            continue
        sf = project._by_rel.get(f.file)
        steps = trace(f.file, sf.text, f.line) if sf is not None and sf.text else []
        origin = next((s for s in steps if s.role in ("source", "parameter")), None)
        note = (origin.note if origin else steps[0].note if steps else "")
        source = "model output" if "model output" in note else "user input" if ("user input" in note or "route parameter" in note) \
            else "function parameter" if origin is not None and origin.role == "parameter" else "not traced"
        flows.append({"fingerprint": f.fingerprint, "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
                      "file": f.file, "line": f.line, "source": source, "sink": FLOW_RULES[f.rule_id],
                      "steps": [s.to_dict() for s in steps]})
    domains = []
    gating = res.gating
    for name, cats in DOMAINS.items():
        mine = [f for f in gating if f.category in cats]
        categories = {}
        for f in mine:
            c = categories.setdefault(f.category, {"category": f.category, "points": 0, "rules": {}})
            c["points"] += WEIGHTS[f.severity]
            rule = c["rules"].setdefault(f.rule_id, {"rule_id": f.rule_id, "title": f.title, "points": 0, "findings": []})
            rule["points"] += WEIGHTS[f.severity]
            rule["findings"].append(f.fingerprint)
        domains.append({"domain": name, "score": max(0, 100 - sum(WEIGHTS[f.severity] for f in mine)),
                        "categories": sorted(({**c, "rules": sorted(c["rules"].values(), key=lambda r: -r["points"])}
                                              for c in categories.values()), key=lambda c: -c["points"])})
    return {"version": __version__, "root": res.root, "score": res.score, "grade": res.grade, "counts": res.counts,
            "files_scanned": res.meta.get("files_scanned"), "notes": res.meta.get("notes", []),
            "findings": findings, "routes": routes, "flows": flows, "domains": domains}


class Handler(BaseHTTPRequestHandler):
    studio: Studio
    token: str
    port: int
    server_version = "vibeaudit-studio"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - the base class's name
        pass  # quiet: the console shows only the URL

    def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code: int, data: Any) -> None:
        self._send(code, json.dumps(data).encode("utf-8"))

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        return host in (f"127.0.0.1:{self.port}", f"localhost:{self.port}")

    def _token_ok(self) -> bool:
        got = self.headers.get("X-Studio-Token") or ""
        return bool(got) and hmac.compare_digest(got.encode("utf-8", "replace"), self.token.encode())

    def do_GET(self) -> None:  # noqa: N802 - http.server's name
        if not self._host_ok():
            return self._json(403, {"error": "unexpected Host header"})
        url = urlparse(self.path)
        if url.path in STATIC:
            name, ctype = STATIC[url.path]
            return self._send(200, resources.files("vibeaudit").joinpath("studio_assets", name).read_bytes(), ctype)
        if not url.path.startswith("/api/"):
            return self._json(404, {"error": "not found"})
        if not self._token_ok():
            return self._json(403, {"error": "missing or wrong token"})
        try:
            q = parse_qs(url.query, max_num_fields=10)
        except ValueError:
            return self._json(400, {"error": "too many query parameters"})
        if url.path == "/api/scan":
            return self._json(200, self.studio.data)
        if url.path == "/api/code":
            rel, line = (q.get("file") or [""])[0], (q.get("line") or ["1"])[0]
            got = self.studio.code(rel, int(line)) if re.fullmatch(r"\d{1,7}", line) else None
            return self._json(200, got) if got else self._json(404, {"error": "not a file of this project"})
        if url.path == "/api/explain":
            fp = (q.get("fingerprint") or [""])[0]
            got = self.studio.explain(fp) if re.fullmatch(r"[0-9a-f]{32}", fp) else None
            return self._json(200, got) if got else self._json(404, {"error": "no such finding"})
        return self._json(404, {"error": "not found"})

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        if not self._host_ok():
            return self._json(403, {"error": "unexpected Host header"})
        if not self._token_ok():
            return self._json(403, {"error": "missing or wrong token"})
        if urlparse(self.path).path != "/api/rescan":
            return self._json(404, {"error": "not found"})
        try:
            data = self.studio.rescan()
        except Exception as e:  # noqa: BLE001 - report, keep serving
            return self._json(500, {"error": f"scan failed: {type(e).__name__}"})
        return self._json(200, data)

    def do_PUT(self) -> None:  # noqa: N802
        self._json(405, {"error": "method not allowed"})

    do_DELETE = do_PATCH = do_PUT  # noqa: N815


class ExclusiveServer(ThreadingHTTPServer):
    """http.server sets SO_REUSEADDR, which on Windows lets another local process bind the same address and port
    and receive the browser's requests (and the token in the page it serves). Bind exclusively instead."""
    allow_reuse_address = False
    daemon_threads = True

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):  # Windows
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def make_server(studio: Studio, port: int = 0, token: Optional[str] = None) -> ThreadingHTTPServer:
    """A server bound to 127.0.0.1 (port 0: any free port). The token is attached to the handler class."""
    handler = type("StudioHandler", (Handler,), {"studio": studio, "token": token or secrets.token_urlsafe(24)})
    server = ExclusiveServer((HOST, port), handler)
    handler.port = server.server_address[1]
    return server


def main(path: str, opts, port: int, open_browser: bool) -> int:
    print("vibeaudit studio: scanning ...", file=sys.stderr)
    studio = Studio(path, opts)
    server = make_server(studio, port)
    url = f"http://{HOST}:{server.server_address[1]}/#token={server.RequestHandlerClass.token}"  # type: ignore[attr-defined]
    print(f"vibeaudit studio: {url}\n(only this computer can open it; press Ctrl+C to stop)", file=sys.stderr)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
