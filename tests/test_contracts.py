"""Frontend-backend contract rules (API001, API002) and per-domain scores."""
import json

from vibeaudit.contracts import matches, segments
from vibeaudit.report import Result, render_html, render_json, render_markdown, render_text
from vibeaudit.model import Finding
from vibeaudit.scanner import Options, scan


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _rules(tmp_path):
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    assert res.meta.get("internal_errors", []) == []
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id.startswith("API"))


def test_segments_and_matching():
    assert segments("/api/chat?id=${id}") == ["api", "chat"]
    assert segments("/api/users/${user.id}/posts") == ["api", "users", "*", "posts"]
    for route in ("/api/users/[id]/posts", "/api/users/:id/posts", "/api/users/{id}/posts", "/api/users/<int:id>/posts"):
        assert matches(segments(route), ["api", "users", "42", "posts"]), route
    assert matches(segments("/api/docs/[...path]"), ["api", "docs", "a", "b"])
    assert not matches(segments("/api/users/[id]"), ["api", "users"])
    assert not matches(segments("/api/users"), ["api", "users", "1"])


NEXT_CLIENT = (
    'export const a = () => fetch("/api/orders", { method: "POST", body: "{}" });\n'
    'export const b = () => fetch("/api/orders");\n'                                      # 2 API002
    'export const c = () => fetch(`/api/orders/${id}`, { method: "DELETE" });\n'
    'export const d = () => fetch("/api/setings");\n'                                     # 4 API001
    'export const e = () => fetch("/api/orders", { method: verb });\n'                    # computed: unknown
    'export const f = () => axios.put("/api/orders/7", {});\n'                            # 6 API002
    "export const g = () => useSWR<Order[]>(`${process.env.NEXT_PUBLIC_BASE_PATH}/api/settings`);\n"  # 7 API001
    'export const h = () => fetch("https://api.example.com/v1/x");\n'
    'export const i = () => fetch("/static/thing");\n'                                    # not a prefix we own
)


def test_next_routes(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next": "14.0.0"}}')
    write(tmp_path, "app/api/orders/route.ts", "export async function POST(req: Request) { return Response.json({}) }\n")
    write(tmp_path, "app/api/orders/[id]/route.ts", "export async function DELETE(req: Request) { return Response.json({}) }\n")
    write(tmp_path, "lib/client.ts", NEXT_CLIENT)
    assert _rules(tmp_path) == [("lib/client.ts", 2, "API002"), ("lib/client.ts", 4, "API001"),
                                ("lib/client.ts", 6, "API002"), ("lib/client.ts", 7, "API001")]
    # with a rewrite, a missing path may be served elsewhere; a wrong method on a known route is still wrong
    write(tmp_path, "next.config.js", "module.exports = { async rewrites() { return [] } };\n")
    assert _rules(tmp_path) == [("lib/client.ts", 2, "API002"), ("lib/client.ts", 6, "API002")]


def test_code_defined_routes_only_count_without_router_prefixes(tmp_path):
    write(tmp_path, "app.py", "from flask import Flask\napp = Flask(__name__)\n\n@app.post('/api/notes')\ndef notes():\n    return ''\n")
    write(tmp_path, "web/notes.js", 'export const list = () => fetch("/api/notes");\nexport const old = () => fetch("/api/note");\n')
    assert _rules(tmp_path) == [("web/notes.js", 1, "API002"), ("web/notes.js", 2, "API001")]
    # a blueprint may add a prefix the scanner does not resolve: stay quiet rather than guess
    write(tmp_path, "admin.py", "from flask import Blueprint\nbp = Blueprint('admin', __name__, url_prefix='/admin')\n")
    assert _rules(tmp_path) == []


def test_domain_scores_in_reports():
    findings = [Finding("SEC001", "a.py", 1, "m", "critical", category="secrets"),
                Finding("UI001", "a.tsx", 1, "m", "low", category="ui"),
                Finding("API001", "a.ts", 1, "m", "medium", category="contracts")]
    res = Result(".", findings, {"files_scanned": 1})
    assert res.domain_scores == {"Security": 75, "AI": 100, "Quality": 97, "Data": 100, "Reliability": 100, "UI": 99}
    assert json.loads(render_json(res))["summary"]["domains"]["Security"] == 75
    assert "Domains: Security 75  AI 100  Quality 97" in render_text(res, color=False)
    assert "| Quality | 97/100 |" in render_markdown(res)
    assert ">Quality</span><b>97</b>" in render_html(res)
