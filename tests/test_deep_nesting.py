"""Input nested deeper than Python's parsers recurse (a RecursionError, not a ValueError) is treated like any
other malformed input: the scan, the LSP and MCP servers, bundles and the feed must not crash or hang."""
import io
import json
import threading
import zipfile

import pytest

from vibeaudit import bundle, config, feed, lsp, mcp_server, store
from vibeaudit.scanner import Options, scan

DEPTH = 100_000
DEEP_JSON = '{"a":' * DEPTH + "1" + "}" * DEPTH
DEEP_TOML = "a = " + "[" * DEPTH + "]" * DEPTH + "\n"


def test_helpers_turn_recursion_into_value_errors(tmp_path):
    with pytest.raises(ValueError, match="nested too deeply"):
        store.loads_json(DEEP_JSON)
    with pytest.raises(ValueError, match="nested too deeply"):
        store.loads_toml(DEEP_TOML)
    (tmp_path / "x.json").write_text(DEEP_JSON)
    assert store.read_json(tmp_path / "x.json") is None
    assert store.loads_json('{"a": [1]}') == {"a": [1]} and store.loads_toml("a = [1]") == {"a": [1]}


@pytest.mark.parametrize("rel", ["package.json", "tsconfig.json", "pyproject.toml", ".vibeaudit/feedback.json"])
def test_a_scanned_project_with_deep_files_still_scans(tmp_path, rel):
    text = DEEP_TOML if rel.endswith(".toml") else DEEP_JSON
    (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / rel).write_text(text)
    (tmp_path / "app.py").write_text('import os\nos.system("ls " + input())\nKEY = "ghp_' + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5" + '"\n')
    res = scan(str(tmp_path), Options(offline=True, external="none", min_severity="low"))
    assert any(f.rule_id == "SEC001" for f in res.findings)  # the rest of the scan still ran


def test_deep_config_is_a_config_error(tmp_path):
    (tmp_path / ".vibeaudit.toml").write_text(DEEP_TOML)
    with pytest.raises(config.ConfigError, match="nested too deeply"):
        config.load(tmp_path, None)


def test_mcp_answers_a_deep_line_and_keeps_serving():
    inp = io.StringIO(DEEP_JSON + "\n" + json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}) + "\n")
    out = io.StringIO()
    assert mcp_server.serve(inp, out) == 0
    replies = [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]
    assert replies[0]["error"]["code"] == -32700 and replies[-1]["id"] == 7


def test_lsp_stops_cleanly_on_a_deep_message():
    body = DEEP_JSON.encode()
    stream = io.BytesIO(b"Content-Length: %d\r\n\r\n" % len(body) + body)
    out = io.BytesIO()
    box = {}
    t = threading.Thread(target=lambda: box.setdefault("rc", lsp.serve(stream, out)), daemon=True)
    t.start()
    t.join(30)
    assert not t.is_alive(), "the server hung after a message it could not parse"
    assert box["rc"] == 1 and b"-32700" in out.getvalue()


def test_deep_bundle_manifest_and_feed_are_rejected(tmp_path, monkeypatch):
    z = tmp_path / "b.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("manifest.json", DEEP_JSON)
    with pytest.raises(bundle.BundleError, match="manifest"):
        bundle.import_bundle(z, lambda m: None)
    key = {"n": "c5", "e": 3}
    for raw in (DEEP_JSON.encode(), json.dumps({"payload": DEEP_JSON, "signature": "AA=="}).encode()):
        with pytest.raises(feed.FeedError):
            feed.open_feed(raw, key)
