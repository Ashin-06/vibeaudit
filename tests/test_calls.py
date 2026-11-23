"""Cross-function taint for Go, Java/Kotlin, C#, Rust and PHP: request data passed to a helper is followed into it,
up to three calls deep, and the sink is reported where it is with the call it came through."""
from pathlib import Path

import pytest

from vibeaudit import calls
from vibeaudit.scanner import Options, scan

CASES = {
    "go": ("main.go", '''package main

import (
	"database/sql"
	"fmt"
	"github.com/gin-gonic/gin"
)

var db *sql.DB

func main() {
	r := gin.Default()
	r.POST("/notes", create)
}

func create(c *gin.Context) {
	title := c.PostForm("title")
	save(title)
}

func save(t string) {
	store(t)
}

func store(t string) {
	db.Exec(fmt.Sprintf("INSERT INTO notes VALUES ('%s')", t))
}
''', 26),
    "java": ("src/main/java/x/C.java", '''package x;
@RestController
public class C {
    @PostMapping("/notes")
    public void add(@RequestParam String title) { save(title); }
    private void save(String t) { store("note", t); }
    private void store(String kind, String t) { jdbcTemplate.execute("INSERT INTO notes VALUES ('" + t + "')"); }
}
''', 7),
    "cs": ("NotesController.cs", '''public class NotesController : ControllerBase {
    [HttpPost("/notes")]
    public IActionResult Add([FromBody] string title) { Save(title); return Ok(); }
    private void Save(string t) { _db.Database.ExecuteSqlRaw("INSERT INTO notes VALUES ('" + t + "')"); }
}
''', 4),
    "rust": ("src/main.rs", '''use actix_web::{post, web};
#[post("/notes")]
async fn add(body: web::Json<Note>) -> &'static str {
    save(&body.text);
    "ok"
}
fn save(text: &str) { store(text); }
fn store(t: &str) {
    let q = format!("INSERT INTO notes VALUES ('{}')", t);
    sqlx::query(&q).execute(&pool);
}
''', 10),
    "php": ("app/NoteController.php", '''<?php
class NoteController extends Controller {
    public function store(Request $request) { $this->save($request->input('text')); }
    private function save($text) { DB::select("SELECT * FROM notes WHERE t = '$text'"); }
}
''', 4),
}


def found(root: Path, rule: str):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low", include_preview=True))
    assert res.meta.get("internal_errors", []) == []
    return [(f.file, f.line, f.severity, f.message) for f in res.findings if f.rule_id == rule]


@pytest.mark.parametrize("lang", sorted(CASES))
def test_request_data_is_followed_into_helpers(tmp_path, lang):
    rel, src, line = CASES[lang]
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    got = found(tmp_path, "BE001")
    assert [(f, ln, sev) for f, ln, sev, _m in got] == [(rel, line, "high")], got
    assert "passed in through the call at " in got[0][3]


def test_at_most_three_calls_deep(tmp_path):
    hops = "".join(f"fn h{i}(t: &str) {{ h{i + 1}(t); }}\n" for i in range(1, 4))
    src = ('use actix_web::{post, web};\n#[post("/n")]\nasync fn add(body: web::Json<N>) -> &\'static str { h1(&body.t); "ok" }\n'
           + hops + 'fn h4(t: &str) { sqlx::query(&format!("SELECT {}", t)).execute(&pool); }\n')
    (tmp_path / "src").mkdir()
    (tmp_path / "src/main.rs").write_text(src, encoding="utf-8")
    assert [sev for _f, _ln, sev, _m in found(tmp_path, "BE001")] == ["medium"]  # four calls away: only the untraced report


def test_a_name_defined_twice_elsewhere_is_not_followed():
    f = calls.Follower(calls.go_params)
    a, b = object(), object()
    f.define("save", calls.Fn(type("S", (), {"rel": "a.go"})(), 0, "t string", (0, 1)))
    f.define("save", calls.Fn(type("S", (), {"rel": "b.go"})(), 0, "t string", (0, 1)))
    assert f.resolve("save", "c.go") is None and f.resolve("save", "a.go").sf.rel == "a.go"
    del a, b


@pytest.mark.parametrize("parse, params, names", [
    (calls.go_params, "c *gin.Context, a, b string", ["c", "a", "b"]),
    (calls.rust_params, "&mut self, id: i64, mut body: Json<T>", ["id", "body"]),
    (calls.jvm_params, "@RequestParam final String q, int n", ["q", "n"]),
    (calls.jvm_params, "q: String, n: Int = 1", ["q", "n"]),
    (calls.cs_params, "[FromBody] string name, int page = 1", ["name", "page"]),
    (calls.php_params, "Request $request, ?int $id = null", ["$request", "$id"]),
])
def test_parameter_names(parse, params, names):
    assert parse(params) == names
