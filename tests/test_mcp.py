"""The MCP server, driven end to end over stdio in a real subprocess, plus protocol edge cases."""
import io
import json
import subprocess
import sys

from helpers import materialize
from vibeaudit.mcp_server import handle, serve


def rpc(proc, msg):
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    if "id" not in msg:
        return None
    return json.loads(proc.stdout.readline())


def test_stdio_session_with_a_real_client_sequence(tmp_path):
    root = materialize("vuln_flask_llm", tmp_path)
    proc = subprocess.Popen([sys.executable, "-m", "vibeaudit", "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        init = rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                          "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}})
        assert init["result"]["protocolVersion"] == "2025-06-18"
        assert init["result"]["serverInfo"]["name"] == "vibeaudit" and "tools" in init["result"]["capabilities"]
        assert rpc(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
        tools = rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
        assert {t["name"] for t in tools} == {"scan_project", "scan_file", "list_routes", "check_package", "explain_rule", "auto_repair",
                                               "audit_current_file", "verify_package", "simulate_migration"}
        assert all(t["inputSchema"]["type"] == "object" for t in tools)

        res = rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": "scan_project", "arguments": {"path": str(root)}}})["result"]
        assert res["isError"] is False
        data = res["structuredContent"]
        assert json.loads(res["content"][0]["text"]) == data
        assert ("app.py", 49, "LLM002") in {(f["file"], f["line"], f["rule_id"]) for f in data["findings"]}

        one = rpc(proc, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                         "params": {"name": "scan_file", "arguments": {"file": str(root / "app.py"), "project": str(root)}}})
        assert {f["file"] for f in one["result"]["structuredContent"]["findings"]} == {"app.py"}

        routes = rpc(proc, {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                            "params": {"name": "list_routes", "arguments": {"path": str(root)}}})["result"]["structuredContent"]
        assert any(r["path"] == "/api/chat" and not r["authenticated"] for r in routes["routes"])

        rule = rpc(proc, {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                          "params": {"name": "explain_rule", "arguments": {"rule_id": "auth001"}}})["result"]["structuredContent"]
        assert rule["id"] == "AUTH001" and rule["fix"]
        assert rpc(proc, {"jsonrpc": "2.0", "id": 7, "method": "ping"})["result"] == {}
    finally:
        proc.stdin.close()
        proc.wait(timeout=30)
    assert proc.returncode == 0


def test_tool_errors_are_reported_not_raised(tmp_path):
    bad = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "scan_project", "arguments": {"path": str(tmp_path / "nope")}}})
    assert bad["result"]["isError"] is True and "not a directory" in bad["result"]["content"][0]["text"]
    assert handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "explain_rule", "arguments": {"rule_id": "X9"}}})["result"]["isError"]
    assert handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "nope"}})["error"]["code"] == -32602
    assert handle({"jsonrpc": "2.0", "id": 4, "method": "nope/nope"})["error"]["code"] == -32601
    assert handle({"id": 5, "method": "ping"})["error"]["code"] == -32600
    assert handle({"jsonrpc": "2.0", "id": 6, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}})["result"]["protocolVersion"] == "2025-06-18"


def test_check_package_with_stubbed_registry(monkeypatch):
    from vibeaudit import deps

    monkeypatch.setattr(deps, "registry_info", lambda d: ("missing", None, "") if d.name == "fake-ai-sdk" else ("ok", None, ""))
    gone = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "check_package", "arguments": {"name": "fake-ai-sdk", "ecosystem": "PyPI"}}})
    assert gone["result"]["structuredContent"]["registry"] == "missing" and "Do not install" in gone["result"]["structuredContent"]["advice"]
    squat = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "check_package", "arguments": {"name": "reqeusts", "ecosystem": "PyPI"}}})
    assert squat["result"]["structuredContent"]["similar_popular_package"] == "requests"


def test_serve_handles_garbage_batches_and_blank_lines():
    out = io.StringIO()
    serve(io.StringIO('\nnot json\n[{"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"jsonrpc": "2.0", "method": "notifications/x"}]\n'), out)
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert lines[0]["error"]["code"] == -32700
    assert lines[1] == [{"jsonrpc": "2.0", "id": 1, "result": {}}]
