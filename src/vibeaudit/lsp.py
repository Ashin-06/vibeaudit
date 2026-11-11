"""`vibeaudit lsp`: a Language Server Protocol server on stdio (standard library only).

- Diagnostics: the whole workspace is scanned like `vibeaudit scan` (offline, no external tools) and every
  finding is published on its line. The Project and its step memo are kept between scans, as in `vibeaudit
  watch`, and unsaved editor buffers are scanned instead of the files on disk.
- Code actions: the `vibeaudit fix` codemods for the findings in the requested range, as text edits, plus a
  "fix all" source action. The server never writes a file; the editor applies the edits.

Input is untrusted (a client may be buggy or hostile): messages are size-capped, every handler error is
answered rather than raised, and only file: URIs inside the workspace root are accepted.
"""
from __future__ import annotations

import difflib
import json
import os
import queue
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import IO, Any, Callable, Dict, List, Optional

from . import __version__

MAX_MESSAGE = 32 * 1024 * 1024  # bytes in one JSON-RPC message
MAX_HEADER = 8192
DEBOUNCE = 0.25  # seconds without edits before a re-scan
SEVERITY = {"critical": 1, "high": 1, "medium": 2, "low": 3, "info": 4}  # Error, Warning, Information, Hint


class ProtocolError(Exception):
    pass


def read_message(stream: IO[bytes]) -> Optional[dict]:
    """One framed message, or None at end of input. Raises ProtocolError on a malformed frame."""
    length = None
    total = 0
    while True:
        line = stream.readline(MAX_HEADER + 1)
        if not line:
            return None
        total += len(line)
        if total > MAX_HEADER or not line.endswith(b"\n"):
            raise ProtocolError("header too long")
        line = line.strip()
        if not line:
            break
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            try:
                length = int(value.strip())
            except ValueError:
                raise ProtocolError("bad Content-Length") from None
    if length is None or not 0 <= length <= MAX_MESSAGE:
        raise ProtocolError("missing or too large Content-Length")
    body = stream.read(length)
    if len(body) != length:
        return None
    try:
        msg = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ProtocolError("body is not JSON") from None
    if not isinstance(msg, dict):
        raise ProtocolError("message is not an object")
    return msg


def write_message(stream: IO[bytes], msg: dict) -> None:
    body = json.dumps(msg, ensure_ascii=False).encode("utf-8")
    stream.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
    stream.flush()


def utf16_col(line: str, col: int) -> int:
    """LSP positions count UTF-16 code units."""
    return len(line[:col].encode("utf-16-le")) // 2


class Server:
    def __init__(self, out: IO[bytes], log: Callable[[str], None] = lambda s: None):
        self.out = out
        self.log = log
        self.lock = threading.Lock()
        self.root: Optional[Path] = None
        self.watcher = None
        self.docs: Dict[str, str] = {}  # rel -> buffer text of open documents
        self.uris: Dict[str, str] = {}  # rel -> the URI the client used
        self.published: Dict[str, List[dict]] = {}
        self.findings: Dict[str, list] = {}  # rel -> findings of the last scan
        self.dirty = False
        self.shutdown = False
        self.last_scan_ms = 0.0

    # ------------------------------------------------------------ helpers
    def send(self, msg: dict) -> None:
        with self.lock:
            write_message(self.out, msg)

    def rel_of(self, uri: Any) -> Optional[str]:
        """The workspace-relative path of a file: URI inside the root, else None (never a path outside it)."""
        if self.root is None or not isinstance(uri, str) or not uri.startswith("file:"):
            return None
        parsed = urllib.parse.urlparse(uri)
        if parsed.netloc not in ("", "localhost"):
            return None  # UNC and remote hosts are not workspace files
        try:
            path = Path(urllib.request.url2pathname(urllib.parse.unquote(parsed.path))).resolve()
            rel = path.relative_to(self.root)
        except (ValueError, OSError):
            return None
        return rel.as_posix() if rel.parts else None

    def uri_of(self, rel: str) -> str:
        return self.uris.get(rel) or (self.root / rel).as_uri()  # type: ignore[operator]

    # ------------------------------------------------------------ scanning
    def scan(self) -> None:
        from .watch import Watcher

        if self.watcher is None or self.root is None:
            return
        w: Watcher = self.watcher
        w.project.overlays = {rel: text.encode("utf-8") for rel, text in self.docs.items()}
        w.changed()
        t = time.perf_counter()
        w.scan()
        self.last_scan_ms = (time.perf_counter() - t) * 1000
        by_file: Dict[str, list] = {}
        for f in w.findings.values():
            by_file.setdefault(f.file, []).append(f)
        self.findings = by_file
        for rel in sorted(set(by_file) | set(self.published)):
            diags = [self.diagnostic(rel, f) for f in sorted(by_file.get(rel, []), key=lambda f: (f.line, f.rule_id))]
            if diags != self.published.get(rel):
                self.send({"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics",
                           "params": {"uri": self.uri_of(rel), "diagnostics": diags}})
            if diags:
                self.published[rel] = diags
            else:
                self.published.pop(rel, None)

    def line_text(self, rel: str, n: int) -> str:
        sf = self.watcher.project.get(rel) if self.watcher else None
        return sf.line(n) if sf is not None else ""

    def diagnostic(self, rel: str, f) -> dict:
        line = max(f.line, 1) - 1
        text = self.line_text(rel, f.line) if f.line else ""
        start = len(text) - len(text.lstrip())
        d = {"range": {"start": {"line": line, "character": utf16_col(text, start)},
                       "end": {"line": line, "character": utf16_col(text, len(text))}},
             "severity": SEVERITY.get(f.severity, 2), "code": f.rule_id, "source": "vibeaudit",
             "message": f"{f.title}: {f.message}" + (" (preview)" if f.preview else "") + (f"\nFix: {f.fix}" if f.fix else ""),
             "data": {"fingerprint": f.fingerprint}}
        return d

    # ------------------------------------------------------------ code actions
    def code_actions(self, params: dict) -> List[dict]:
        from . import fix

        rel = self.rel_of((params.get("textDocument") or {}).get("uri"))
        if rel is None or self.root is None:
            return []
        rng = params.get("range") or {}
        try:
            first = int(rng["start"]["line"]) + 1
            last = int(rng["end"]["line"]) + 1
        except (KeyError, TypeError, ValueError):
            return []
        mine = [f for f in self.findings.get(rel, []) if f.rule_id in fix.FIXERS]
        texts = {rel: self.docs[rel]} if rel in self.docs else None
        project = self.watcher.project if self.watcher else None
        actions = []
        for f in mine:
            if first <= max(f.line, 1) <= last:
                plan = fix.plan_findings(self.root, [f], project, texts)
                if plan.changes:
                    actions.append(self.action(f"Fix {f.rule_id}: {f.title}", "quickfix", plan.changes[0], [f]))
        if mine:
            plan = fix.plan_findings(self.root, mine, project, texts)
            if plan.changes:
                actions.append(self.action(f"Fix all {len(plan.fixed)} vibeaudit findings in this file",
                                           "source.fixAll.vibeaudit", plan.changes[0], plan.fixed))
        return actions

    def action(self, title: str, kind: str, change, fixed: list) -> dict:
        diags = [d for d in self.published.get(change.file, []) if d["data"]["fingerprint"] in {f.fingerprint for f in fixed}]
        return {"title": title, "kind": kind, "diagnostics": diags,
                "edit": {"changes": {self.uri_of(change.file): text_edits(change.before, change.after)}}}

    # ------------------------------------------------------------ dispatch
    def handle(self, msg: dict) -> None:
        method, mid = msg.get("method"), msg.get("id")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if not isinstance(method, str):
            if mid is not None and "result" not in msg and "error" not in msg:
                self.send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32600, "message": "Invalid Request"}})
            return  # a response to a request we never made: ignore
        try:
            result = self.dispatch(method, params)
        except ValueError as e:
            if mid is not None:
                self.send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": str(e)[:300]}})
            return
        except Exception as e:  # noqa: BLE001 - one bad request must not stop the server
            self.log(f"error in {method}: {type(e).__name__}: {e}")
            if mid is not None:
                self.send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": f"internal error: {type(e).__name__}"}})
            return
        if mid is not None:
            if result is NotImplemented:
                self.send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Method not found: {method}"}})
            else:
                self.send({"jsonrpc": "2.0", "id": mid, "result": result})

    def dispatch(self, method: str, params: dict) -> Any:
        if method == "initialize":
            return self.initialize(params)
        if method in ("initialized", "$/cancelRequest", "$/setTrace", "workspace/didChangeConfiguration",
                      "workspace/didChangeWatchedFiles"):
            if method == "workspace/didChangeWatchedFiles":
                self.dirty = True
            return None
        if method == "shutdown":
            self.shutdown = True
            return None
        if method.startswith("textDocument/did"):
            return self.document(method, params)
        if method == "textDocument/codeAction":
            return self.code_actions(params)
        return NotImplemented

    def initialize(self, params: dict) -> dict:
        from .watch import Watcher, main_options

        folders = params.get("workspaceFolders")
        uri = (folders[0].get("uri") if isinstance(folders, list) and folders and isinstance(folders[0], dict)
               else params.get("rootUri"))
        path = None
        if isinstance(uri, str) and uri.startswith("file:"):
            path = Path(urllib.request.url2pathname(urllib.parse.unquote(urllib.parse.urlparse(uri).path)))
        elif isinstance(params.get("rootPath"), str):
            path = Path(params["rootPath"])
        if path is not None and path.is_dir():
            self.root = path.resolve()
            try:
                self.watcher = Watcher(str(self.root), main_options(str(self.root), None, [], None))
            except Exception as e:  # noqa: BLE001 - a broken config file: run without diagnostics, say why
                self.log(f"cannot scan {self.root}: {e}")
                self.watcher = None
            self.dirty = True
        return {"capabilities": {"textDocumentSync": {"openClose": True, "change": 1, "save": {"includeText": False}},
                                 "codeActionProvider": {"codeActionKinds": ["quickfix", "source.fixAll.vibeaudit"]}},
                "serverInfo": {"name": "vibeaudit", "version": __version__}}

    def document(self, method: str, params: dict) -> None:
        doc = params.get("textDocument") or {}
        rel = self.rel_of(doc.get("uri"))
        if rel is None:
            return None
        self.uris[rel] = doc["uri"]
        if method == "textDocument/didOpen":
            text = doc.get("text")
            if isinstance(text, str) and len(text) <= MAX_MESSAGE:
                self.docs[rel] = text
        elif method == "textDocument/didChange":
            changes = params.get("contentChanges")
            if isinstance(changes, list) and changes and isinstance(changes[-1], dict) and isinstance(changes[-1].get("text"), str) \
                    and "range" not in changes[-1]:
                self.docs[rel] = changes[-1]["text"]  # full sync: the last change is the whole document
        elif method == "textDocument/didClose":
            self.docs.pop(rel, None)
        self.dirty = True
        return None


def text_edits(before: str, after: str) -> List[dict]:
    """Line-based TextEdits that turn `before` into `after` (both with LF line endings)."""
    a, b = before.split("\n"), after.split("\n")
    edits = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        new = "".join(line + "\n" for line in b[j1:j2])
        edits.append({"range": {"start": {"line": i1, "character": 0}, "end": {"line": i2, "character": 0}}, "newText": new})
    return edits


def serve(stdin: IO[bytes], stdout: IO[bytes], log: Callable[[str], None] = lambda s: None) -> int:
    server = Server(stdout, log)
    inbox: "queue.Queue[Optional[dict]]" = queue.Queue()

    def reader() -> None:
        while True:
            try:
                msg = read_message(stdin)
            except ProtocolError as e:
                log(f"dropped a malformed message: {e}")
                server.send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(e)}})
                inbox.put(None)  # the stream is out of sync after a bad frame: stop
                return
            inbox.put(msg)
            if msg is None:
                return

    threading.Thread(target=reader, daemon=True).start()
    while True:
        try:
            msg = inbox.get(timeout=DEBOUNCE) if server.dirty else inbox.get()
        except queue.Empty:
            server.dirty = False
            try:
                server.scan()
            except Exception as e:  # noqa: BLE001
                log(f"scan failed: {type(e).__name__}: {e}")
            continue
        if msg is None:
            return 0 if server.shutdown else 1
        if msg.get("method") == "exit":
            return 0 if server.shutdown else 1
        server.handle(msg)


def main() -> int:
    code = serve(sys.stdin.buffer, sys.stdout.buffer, lambda s: print(f"vibeaudit lsp: {s}", file=sys.stderr))
    sys.stdout.flush()
    sys.stderr.flush()
    # the reader thread may still be blocked reading stdin; interpreter shutdown with it alive can crash on
    # Windows, and there is nothing left to clean up
    os._exit(code)
