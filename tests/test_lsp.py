"""`vibeaudit lsp`: framing, diagnostics (also for unsaved buffers), fix code actions, and hostile input."""
from __future__ import annotations

import io
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from vibeaudit import lsp

BAD = "import requests\nr = requests.get('https://x')\n"


def frame(msg: dict) -> bytes:
    body = json.dumps(msg).encode()
    return b"Content-Length: %d\r\n\r\n" % len(body) + body


def messages(buf: bytes):
    stream = io.BytesIO(buf)
    out = []
    while True:
        m = lsp.read_message(stream)
        if m is None:
            return out
        out.append(m)


def server(root: Path):
    out = io.BytesIO()
    s = lsp.Server(out)
    s.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"rootUri": root.as_uri()}})
    return s, out


def published(out: io.BytesIO):
    return {m["params"]["uri"]: m["params"]["diagnostics"] for m in messages(out.getvalue())
            if m.get("method") == "textDocument/publishDiagnostics"}


def test_framing_round_trip_and_limits():
    buf = io.BytesIO()
    lsp.write_message(buf, {"a": "é"})
    assert lsp.read_message(io.BytesIO(buf.getvalue())) == {"a": "é"}
    for bad in (b"Content-Length: abc\r\n\r\n{}", b"Content-Length: 999999999999\r\n\r\n",
                b"Content-Length: 2\r\n\r\n[]", b"Content-Length: 3\r\n\r\n{x}", b"X" * 9000 + b"\r\n\r\n"):
        with pytest.raises(lsp.ProtocolError):
            lsp.read_message(io.BytesIO(bad))
    assert lsp.read_message(io.BytesIO(b"")) is None
    assert lsp.read_message(io.BytesIO(b"Content-Length: 10\r\n\r\n{}")) is None  # truncated body


def test_initialize_and_diagnostics_on_disk_files(tmp_path):
    (tmp_path / "app.py").write_text(BAD)
    s, out = server(tmp_path)
    init = messages(out.getvalue())[0]["result"]
    assert init["capabilities"]["codeActionProvider"] and init["serverInfo"]["name"] == "vibeaudit"
    s.scan()
    diags = published(out)[(tmp_path / "app.py").resolve().as_uri()]
    assert [d["code"] for d in diags] == ["REL001"]
    assert diags[0]["range"]["start"] == {"line": 1, "character": 0} and diags[0]["severity"] == 2


def test_unsaved_buffer_is_scanned_and_cleared(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    s, out = server(tmp_path)
    uri = (tmp_path / "app.py").as_uri()
    s.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen",
              "params": {"textDocument": {"uri": uri, "languageId": "python", "version": 1, "text": BAD}}})
    s.scan()
    assert [d["code"] for d in published(out)[uri]] == ["REL001"]
    assert (tmp_path / "app.py").read_text() == "x = 1\n"  # the buffer was scanned, the file left alone
    s.handle({"jsonrpc": "2.0", "method": "textDocument/didChange",
              "params": {"textDocument": {"uri": uri, "version": 2}, "contentChanges": [{"text": "x = 2\n"}]}})
    out.seek(0)
    out.truncate()
    s.scan()
    assert published(out)[uri] == []  # the fixed file's diagnostics are cleared


def test_code_actions_fix_the_buffer(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    s, out = server(tmp_path)
    uri = (tmp_path / "app.py").as_uri()
    text = "import requests\né = 1\nr = requests.get('https://x')\n"
    s.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen",
              "params": {"textDocument": {"uri": uri, "languageId": "python", "version": 1, "text": text}}})
    s.scan()
    out.seek(0)
    out.truncate()
    s.handle({"jsonrpc": "2.0", "id": 7, "method": "textDocument/codeAction",
              "params": {"textDocument": {"uri": uri}, "range": {"start": {"line": 2, "character": 0}, "end": {"line": 2, "character": 5}},
                         "context": {"diagnostics": []}}})
    actions = messages(out.getvalue())[0]["result"]
    assert [a["kind"] for a in actions] == ["quickfix", "source.fixAll.vibeaudit"]
    edits = actions[0]["edit"]["changes"][uri]
    assert edits == [{"range": {"start": {"line": 2, "character": 0}, "end": {"line": 3, "character": 0}},
                      "newText": "r = requests.get('https://x', timeout=10)\n"}]
    assert actions[0]["diagnostics"][0]["code"] == "REL001"
    assert (tmp_path / "app.py").read_text() == "x = 1\n"


def test_paths_outside_the_workspace_are_ignored(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    (tmp_path / "secret.py").write_text(BAD)
    s, out = server(root)
    for uri in ((tmp_path / "secret.py").as_uri(), root.as_uri() + "/../secret.py", "file://evil.example/x.py",
                "http://x/app.py", "file:" + "%2e%2e/" * 10 + "etc/passwd", None, 42):
        assert s.rel_of(uri) is None
        s.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen",
                  "params": {"textDocument": {"uri": uri, "text": BAD}}})
    assert s.docs == {}
    s.handle({"jsonrpc": "2.0", "id": 3, "method": "textDocument/codeAction",
              "params": {"textDocument": {"uri": (tmp_path / "secret.py").as_uri()}, "range": {}}})
    assert messages(out.getvalue())[-1]["result"] == []


def test_bad_requests_get_errors_not_crashes(tmp_path):
    s, out = server(tmp_path)
    out.seek(0)
    out.truncate()
    s.handle({"jsonrpc": "2.0", "id": 4, "method": "nope/unknown"})
    s.handle({"jsonrpc": "2.0", "id": 5, "method": "textDocument/codeAction", "params": {"textDocument": "x", "range": 3}})
    s.handle({"jsonrpc": "2.0", "id": 6, "params": {}})
    s.handle({"jsonrpc": "2.0", "method": "textDocument/didChange", "params": {"contentChanges": "x"}})
    replies = {m["id"]: m for m in messages(out.getvalue())}
    assert replies[4]["error"]["code"] == -32601
    assert replies[5].get("result") == [] or "error" in replies[5]
    assert replies[6]["error"]["code"] == -32600


def test_stdio_session_end_to_end(tmp_path):
    (tmp_path / "app.py").write_text(BAD)
    proc = subprocess.Popen([sys.executable, "-m", "vibeaudit", "lsp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    got = []

    def read():
        while True:
            m = lsp.read_message(proc.stdout)
            if m is None:
                return
            got.append(m)

    t = threading.Thread(target=read, daemon=True)
    t.start()

    def send(msg):
        proc.stdin.write(frame(msg))
        proc.stdin.flush()

    def wait(pred, timeout=30.0):
        end = time.time() + timeout
        while time.time() < end:
            hit = next((m for m in got if pred(m)), None)
            if hit:
                return hit
            time.sleep(0.02)
        raise AssertionError(f"no matching message in {got}")

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"rootUri": tmp_path.as_uri(), "capabilities": {}}})
        wait(lambda m: m.get("id") == 1)
        send({"jsonrpc": "2.0", "method": "initialized", "params": {}})
        diag = wait(lambda m: m.get("method") == "textDocument/publishDiagnostics")
        assert diag["params"]["diagnostics"][0]["code"] == "REL001"
        send({"jsonrpc": "2.0", "id": 2, "method": "shutdown"})
        wait(lambda m: m.get("id") == 2)
        send({"jsonrpc": "2.0", "method": "exit"})
        assert proc.wait(timeout=10) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.stdin.close()
        proc.stdout.close()
        proc.stderr.close()


def test_vscode_extension_is_safe_and_versioned():
    import vibeaudit

    root = Path(__file__).parent.parent / "editors" / "vscode"
    pkg = json.loads((root / "package.json").read_text(encoding="utf-8"))
    assert pkg["version"] == vibeaudit.__version__
    assert pkg["capabilities"]["untrustedWorkspaces"]["supported"] is False
    props = pkg["contributes"]["configuration"]["properties"]
    assert all(p["scope"] == "machine" for p in props.values())  # a repository cannot pick the program run
    assert props["vibeaudit.serverArgs"]["default"] == ["lsp"]
    lock = json.loads((root / "package-lock.json").read_text(encoding="utf-8"))
    assert lock["packages"][""]["dependencies"] == pkg["dependencies"]
    assert all("^" not in v and "~" not in v for v in list(pkg["dependencies"].values()) + list(pkg["devDependencies"].values()))


def test_vscode_module_is_provided_to_editor_extensions(tmp_path):
    from vibeaudit.scanner import Options, scan

    (tmp_path / "package.json").write_text(json.dumps({"engines": {"vscode": "^1.82.0"}, "dependencies": {}}))
    (tmp_path / "extension.js").write_text("const vscode = require('vscode');\nconst x = require('left-pad');\nmodule.exports = { vscode, x };\n")
    found = [f.message for f in scan(str(tmp_path), Options(offline=True, external="none")).findings if f.rule_id == "QA007"]
    assert found == ["`left-pad` is imported but not listed in package.json."]
