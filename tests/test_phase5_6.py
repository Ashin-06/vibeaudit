"""Phase 5 (Go, Java/Kotlin, C#/.NET, Rust, PHP) and Phase 6 (test-exploit, staging runtime middleware) tests."""
from __future__ import annotations

import asyncio
import http.server
import json
import threading

import pytest

from vibeaudit import exploit, runtime
from vibeaudit.cli import main
from vibeaudit.scanner import Options, scan


def write(root, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _rules(root, prefix=""):
    res = scan(str(root), Options(offline=True, external="none", include_preview=True))
    assert res.meta.get("internal_errors", []) == []
    return res, sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id.startswith(prefix))


# ---------------------------------------------------------------- Phase 5: Go
def test_phase5_go_gin_gorm_nethttp_chi_fiber(tmp_path):
    write(tmp_path, "go.mod", "module example.com/app\nrequire github.com/gin-gonic/gin v1.10.0\nrequire gorm.io/gorm v1.25.0\n")
    write(tmp_path, "main.go",
          'package main\n'
          'import ("fmt"; "net/http"; "os/exec"; "github.com/gin-gonic/gin")\n'
          'func createOrder(c *gin.Context) {\n'
          '  var input string\n'
          '  c.BindJSON(&input)\n'
          '  db.Create(&order)\n'
          '  db.Raw(fmt.Sprintf("SELECT * FROM users WHERE name = %s", input))\n'
          '  http.Get("https://api.example.com/rate")\n'
          '}\n'
          'func main() {\n'
          '  r := gin.Default()\n'
          '  r.POST("/api/orders", createOrder)\n'
          '  priv := r.Group("/private", AuthMiddleware())\n'
          '  priv.POST("/notes", createNote)\n'
          '  for _, id := range ids {\n'
          '    db.First(&u, id)\n'
          '  }\n'
          '  exec.Command("sh", "-c", userCmd)\n'
          '}\n'
          'func createNote(c *gin.Context) { db.Create(&note) }\n')
    res, all_r = _rules(tmp_path)
    ids = {r for _f, _ln, r in all_r}
    assert {"AUTH001", "BE001", "BE002", "DATA001", "REL001"} <= ids
    assert "Go" in res.meta["stack"] and "Gin" in res.meta["stack"] and "GORM" in res.meta["stack"]
    orders_route = next(r for r in res.routes if r.path == "/api/orders")
    priv_route = next(r for r in res.routes if r.path == "/private/notes")
    assert not orders_route.has_auth and priv_route.has_auth
    assert "BE018" not in ids  # Py/JS validation libraries must not be demanded for Go


# -------------------------------------------------------- Phase 5: Java/Kotlin
def test_phase5_java_spring_and_quarkus(tmp_path):
    write(tmp_path, "pom.xml", "<project><dependency><artifactId>spring-boot-starter-web</artifactId></dependency></project>\n")
    write(tmp_path, "OrderController.java",
          '@RestController\n@RequestMapping("/api/orders")\n'
          'public class OrderController {\n'
          '  @PostMapping("/charge")\n'
          '  public void charge(@RequestBody String req) {\n'
          '    orderRepository.save(order);\n'
          '    jdbcTemplate.query("SELECT * FROM orders WHERE id = " + req, rowMapper);\n'
          '    new RestTemplate();\n'
          '    for (Long id : ids) { userRepository.findById(id); }\n'
          '    Runtime.getRuntime().exec(req);\n'
          '  }\n'
          '}\n')
    write(tmp_path, "AdminResource.kt",
          'import jakarta.ws.rs.*\n@Path("/quarkus")\nclass AdminResource {\n'
          '  @GET @Path("/items") fun list() { return "ok" }\n}\n')
    res, all_r = _rules(tmp_path)
    ids = {r for _f, _ln, r in all_r}
    assert {"JAVA001", "BE001", "BE002", "DATA001", "REL001"} <= ids  # no Spring Security at all: JAVA001, not AUTH001
    assert "Spring Boot" in res.meta["stack"]
    assert any(r.path == "/api/orders/charge" and not r.has_auth for r in res.routes)
    assert any(r.path == "/quarkus/items" and r.framework == "jax-rs" for r in res.routes)


# ----------------------------------------------------------- Phase 5: C#/.NET
def test_phase5_csharp_aspnet_efcore(tmp_path):
    write(tmp_path, "App.csproj", '<Project><PackageReference Include="Microsoft.EntityFrameworkCore" /></Project>\n')
    write(tmp_path, "OrdersController.cs",
          '[ApiController]\n[Route("api/[controller]")]\n'
          'public class OrdersController : ControllerBase {\n'
          '  [HttpPost("create")]\n'
          '  public async Task<IActionResult> Create([FromBody] Req req) {\n'
          '    await _db.SaveChangesAsync();\n'
          '    _db.Orders.FromSqlRaw($"SELECT * FROM Orders WHERE name = {req.Name}");\n'
          '    Process.Start("cmd.exe", $"/c {req.Cmd}");\n'
          '    var client = new HttpClient();\n'
          '    foreach (var id in ids) { await _db.Users.FirstOrDefaultAsync(); }\n'
          '    return Ok();\n'
          '  }\n'
          '}\n')
    write(tmp_path, "Views/Home.cshtml", "<div>@Html.Raw(Model.Bio)</div>\n")
    res, all_r = _rules(tmp_path)
    ids = {r for _f, _ln, r in all_r}
    assert {"CSHARP001", "BE001", "BE002", "DATA001", "FE001"} <= ids  # no authorization anywhere
    assert any(r.path == "/api/orders/create" and r.framework.startswith("aspnet") for r in res.routes)


# -------------------------------------------------------------- Phase 5: Rust
def test_phase5_rust_actix_and_axum(tmp_path):
    write(tmp_path, "Cargo.toml", '[dependencies]\nactix-web = "4"\naxum = "0.7"\n')
    write(tmp_path, "main.rs",
          'use actix_web::{post, web};\n'
          '#[post("/api/items")]\n'
          'async fn create_item(body: web::Json<Item>) {\n'
          '  db.execute(&query);\n'
          '  let q = sqlx::query(&format!("SELECT * FROM items WHERE id = {}", id));\n'
          '  Command::new("sh").arg("-c").arg(user_arg);\n'
          '  let c = reqwest::Client::new();\n'
          '  for id in ids { let r = sqlx::query("SELECT 1"); }\n'
          '}\n'
          'fn router() { Router::new().route("/axum/ping", get(ping_fn)); }\n'
          'async fn ping_fn() -> &str { "ok" }\n')
    res, all_r = _rules(tmp_path)
    ids = {r for _f, _ln, r in all_r}
    assert {"AUTH001", "BE001", "BE002", "DATA001", "REL001"} <= ids
    assert "Actix" in res.meta["stack"] and "Axum" in res.meta["stack"]
    assert any(r.path == "/api/items" and r.framework == "actix" for r in res.routes)
    assert any(r.path == "/axum/ping" and r.framework == "axum" for r in res.routes)


# --------------------------------------------------------------- Phase 5: PHP
def test_phase5_php_laravel_and_symfony(tmp_path):
    write(tmp_path, "composer.json", '{"require": {"laravel/framework": "^11.0"}}')
    write(tmp_path, "routes/api.php",
          "<?php\n"
          "Route::post('/api/orders', function (Request $request) {\n"
          "  Order::create($request->all());\n"
          "  DB::select(\"SELECT * FROM orders WHERE id = $id\");\n"
          "  shell_exec(\"ls \" . $path);\n"
          "  Http::get('https://slow.example.com');\n"
          "  foreach ($ids as $id) { User::find($id); }\n"
          "});\n"
          "Http::timeout(5)->get('https://safe.example.com');\n")
    write(tmp_path, "resources/views/profile.blade.php", "<div>{!! $bio !!}</div>\n")
    res, all_r = _rules(tmp_path)
    ids = {r for _f, _ln, r in all_r}
    assert {"AUTH001", "BE001", "BE002", "DATA001", "REL001", "FE001"} <= ids
    assert "Laravel" in res.meta["stack"]
    rel_lines = [ln for _f, ln, r in all_r if r == "REL001"]
    assert rel_lines == [6]  # line 9 uses Http::timeout(5)->get(...) so it is not flagged


# ----------------------------------------------------- Phase 6: test-exploit
def test_phase6_test_exploit_localhost_enforcement_and_live_probe(tmp_path, capsys):
    write(tmp_path, "app.py",
          "from flask import Flask, request\napp = Flask(__name__)\n\n"
          "@app.post('/api/items')\ndef create_item():\n    db.execute('INSERT INTO items VALUES (1)')\n    return ''\n")
    for bad in ("https://example.com", "http://169.254.169.254", "http://192.168.1.5", "http://0.0.0.0:8000", "file:///etc/passwd"):
        with pytest.raises(exploit.ExploitError):
            exploit.validate_localhost(bad)

    # Dry-run via CLI
    assert main(["test-exploit", "app.py:5:AUTH001", "--path", str(tmp_path), "--format", "json"]) == 0
    dry = json.loads(capsys.readouterr().out)[0]
    assert dry["sent"] is False and dry["verdict"] == "dry-run" and dry["method"] == "POST"
    assert "/api/items" in dry["url"]

    # Real localhost HTTP server confirming non-redirecting, non-destructive verification
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            _ = self.rfile.read(length)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"created": false}')

        def log_message(self, fmt, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        assert main(["test-exploit", "app.py:5:AUTH001", "--path", str(tmp_path),
                     "--url", f"http://127.0.0.1:{port}", "--send", "--format", "json"]) == 0
        sent = json.loads(capsys.readouterr().out)[0]
        assert sent["sent"] is True and sent["verdict"] == "confirmed" and sent["status"] == 200
    finally:
        srv.shutdown()
        srv.server_close()


# -------------------------------------------- Phase 6: runtime observability
def test_phase6_runtime_middleware_double_gate_and_observation(tmp_path, monkeypatch):
    monkeypatch.delenv("VIBEAUDIT_RUNTIME", raising=False)
    with pytest.raises(RuntimeError):
        runtime.FastAPIMiddleware(lambda *a: None)

    monkeypatch.setenv("VIBEAUDIT_RUNTIME", "1")
    monkeypatch.setenv("NODE_ENV", "production")
    with pytest.raises(RuntimeError):
        runtime.FastAPIMiddleware(lambda *a: None)

    monkeypatch.delenv("NODE_ENV", raising=False)
    log_file = tmp_path / "runtime.jsonl"

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = runtime.FastAPIMiddleware(app, log_path=str(log_file))
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/orders\nFORGED_LINE",
        "headers": [(b"cookie", b"other=1")],
    }
    asyncio.run(mw(scope, lambda: None, lambda _m: asyncio.sleep(0)))
    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert "\n" not in rec["route"] and rec["has_auth"] is False and "unauthenticated_mutation" in rec["anomalies"]
    js = runtime.express_middleware_js()
    assert "VIBEAUDIT_RUNTIME" in js and "NODE_ENV" in js and "Object.create(null)" in js


def test_phase5_findings_are_preview_and_only_injection_gates(tmp_path):
    write(tmp_path, "main.go",
          'package main\n'
          'import ("fmt"; "net/http")\n'
          'func h(w http.ResponseWriter, r *http.Request) {\n'
          '  name := r.URL.Query().Get("name")\n'
          '  db.Raw(fmt.Sprintf("SELECT * FROM users WHERE name = %s", name))\n'
          '  http.Get("https://api.example.com/rate")\n'
          '}\n')
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    got = {f.rule_id: f for f in res.findings if f.file == "main.go"}
    assert got and all(f.preview for f in got.values())  # no labelled corpus for Go yet
    assert got["BE001"].gates_in_preview and got["BE001"] in res.gating
    assert "REL001" not in got or got["REL001"] not in res.gating
