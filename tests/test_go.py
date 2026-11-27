"""Go support (0.10.0): lexer, routes, data flow into the generic sinks, and GO001-GO004."""
import random
import string
import time

from vibeaudit.goscan import go_views
from vibeaudit.rules import RULES
from vibeaudit.scanner import Options, scan

GIN = '''package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"

	"github.com/gin-gonic/gin"
)

var db *sql.DB
var hits = map[string]int{}

func main() {
	r := gin.Default()
	r.POST("/api/notes", createNote)
	api := r.Group("/api/admin")
	api.Use(AuthRequired())
	api.DELETE("/notes/:id", deleteNote)
	r.GET("/files", func(c *gin.Context) {
		c.File("/srv/files/" + c.Query("name"))
	})
	r.Run()
}

func createNote(c *gin.Context) {
	title := c.PostForm("title")
	db.Exec("INSERT INTO notes (title) VALUES ('" + title + "')")
	hits[title]++
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func deleteNote(c *gin.Context) {
	id := c.Param("id")
	q := fmt.Sprintf("DELETE FROM notes WHERE id = %d", 42)
	db.Exec(q)
	db.Exec("DELETE FROM notes WHERE id = ?", id)
	c.Status(204)
}

func run(c *gin.Context) {
	cmd := exec.Command("sh", "-c", c.Query("cmd"))
	_ = cmd.Run()
	resp, err := http.Get(c.Query("url"))
	if err != nil {
		return
	}
	fmt.Println(resp.Status)
	c.Redirect(302, c.Query("next"))
	os.ReadFile(c.Param("path"))
}

func AuthRequired() gin.HandlerFunc { return func(c *gin.Context) { c.Next() } }
'''

WORKER = '''package worker

import (
	"context"
	"net/http"
	"time"
)

const apiKey = "KEY_PLACEHOLDER"

func Start() {
	go func() {
		for {
			poll()
			time.Sleep(time.Second)
		}
	}()
}

func StartWithContext(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				poll()
			}
		}
	}()
}

func poll() {
	resp, err := http.Get("https://example.com/health")
	if err != nil {
		return
	}
	defer resp.Body.Close()
}
'''

CHI = '''package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func routes() http.Handler {
	r := chi.NewRouter()
	r.Post("/public/signup", signup)
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Authenticator)
		r.Put("/users/{userID}", updateUser)
	})
	r.Route("/orders", func(r chi.Router) {
		r.Delete("/{orderID}", deleteOrder)
	})
	mux := http.NewServeMux()
	mux.HandleFunc("POST /webhooks/stripe", stripeHook)
	return r
}
'''


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def scan_all(root):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low"))
    assert res.meta.get("internal_errors", []) == []
    return res


def test_go_rules_are_preview():
    assert all(RULES[r].preview and RULES[r].preview_reason for r in ("GO001", "GO002", "GO003", "GO004"))


def test_lexer_blanks_comments_and_strings():
    v = go_views('x := "a // b" // c\ny := `raw\n/* not a comment */` /* d */ + \'q\'\n')
    assert "// c" not in v.code and "d */" not in v.code and "a // b" in v.code
    assert "a // b" not in v.bare and "not a comment" not in v.bare and v.bare.count("\n") == 3


def test_gin_sinks_and_go_rules(tmp_path):
    write(tmp_path, "go.mod", "module example.com/app\n\ngo 1.22\n")
    write(tmp_path, "main.go", GIN)
    rnd = random.Random(5)  # a key built at run time: no secret-shaped literal in this file
    key = "sk_" + "live_" + "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(40))
    write(tmp_path, "worker/worker.go", WORKER.replace("KEY_PLACEHOLDER", key))
    found = {(f.file, f.line, f.rule_id) for f in scan_all(tmp_path).findings}
    expected = {
        ("main.go", 30, "BE001"),   # request data concatenated into SQL
        ("main.go", 38, "GO004"),   # Sprintf-built SQL, no request data
        ("main.go", 31, "GO003"),   # package-level map written in a handler
        ("main.go", 23, "BE006"),   # c.File with a query value
        ("main.go", 44, "BE002"),   # sh -c with request data
        ("main.go", 46, "BE005"),   # http.Get of a query value
        ("main.go", 46, "GO002"),   # response body never closed
        ("main.go", 51, "BE008"),   # redirect to a query value
        ("main.go", 52, "BE006"),   # os.ReadFile of a path param
        ("main.go", 18, "AUTH001"),  # POST /api/notes without auth
        ("worker/worker.go", 9, "SEC001"),
    }
    missing = expected - found
    assert not missing, sorted(missing)
    unexpected = {x for x in found if x[2] in ("GO001", "GO002", "GO003", "GO004", "BE001")} - expected
    assert not unexpected, sorted(unexpected)


def test_routes_with_groups_middleware_and_chi(tmp_path):
    write(tmp_path, "go.mod", "module example.com/app\n\ngo 1.22\n")
    write(tmp_path, "main.go", GIN)
    write(tmp_path, "routes.go", CHI)
    from vibeaudit.files import Project
    from vibeaudit.goscan import GoScanner
    got = {(r.path, tuple(r.methods)): r.has_auth for r in GoScanner(Project(tmp_path), lambda f: None).run()}
    assert got[("/api/notes", ("POST",))] is False
    assert got[("/api/admin/notes/:id", ("DELETE",))] is True
    assert got[("/public/signup", ("POST",))] is False
    assert got[("/users/{userID}", ("PUT",))] is True
    assert got[("/orders/{orderID}", ("DELETE",))] is False
    assert got[("/webhooks/stripe", ("POST",))] is False


def test_go_checks_are_linear_on_hostile_input(tmp_path):
    write(tmp_path, "a.go", "package a\n" + "func f() {\n" * 3000 + "go func() {\n" * 3000 + 'x := "' * 3000)
    write(tmp_path, "b.go", "package b\nvar m = map[string]int{}\n" + ("func h(c *gin.Context) {\n\tm[c.Query(\"k\")] = 1\n}\n") * 3000)
    start = time.time()
    scan_all(tmp_path)
    assert time.time() - start < 30


def test_go_modules_offline_vulnerabilities(tmp_path, monkeypatch):
    from test_offline import osv_dump
    from vibeaudit import bundle
    dump = osv_dump(
        {"id": "GO-2021-0052", "database_specific": {"severity": "HIGH"},
         "affected": [{"package": {"ecosystem": "Go", "name": "github.com/gin-gonic/gin"},
                       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.7.7"}]}]}]},
        {"id": "GO-2022-0236", "affected": [{"package": {"ecosystem": "Go", "name": "golang.org/x/net"},
                                             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.7.0"}]}]}]},
    )
    monkeypatch.setattr(bundle, "_download", lambda url: dump if "/Go/" in url else osv_dump())
    path = tmp_path / "bundle.zip"
    bundle.export(path, ["Go"], lambda m: None)
    bundle.import_bundle(path, lambda m: None)
    app = tmp_path / "app"
    write(app, "go.mod", "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.7.0\n"
                         "\tgithub.com/gin-gonic/gim v1.0.0\n\tgolang.org/x/net v0.0.0-20220127200216-cd36cc0744dd // indirect\n)\n")
    write(app, "main.go", "package main\n\nfunc main() {}\n")
    found = sorted((f.file, f.line, f.rule_id) for f in scan(str(app), Options(offline=True, external="none")).findings
                   if f.rule_id.startswith("DEP"))
    assert ("go.mod", 6, "DEP004") in found and ("go.mod", 8, "DEP009") in found
    assert not [x for x in found if x[2] == "DEP002"]  # npm's popular names are not compared with Go modules


GOROUTINES = """package main

import "github.com/gin-gonic/gin"

func cleanup() {
	for {
		sweep()
	}
}

func main() {
	go cleanup()
	r := gin.Default()
	r.POST("/jobs", func(c *gin.Context) {
		go func() {
			for {
				poll()
			}
		}()
		c.JSON(200, nil)
	})
	r.Run()
}
"""


def test_goroutines_started_per_request_leak_and_startup_loops_do_not(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.10.0\n")
    (tmp_path / "main.go").write_text(GOROUTINES)
    res = scan(str(tmp_path), Options(offline=True, external="none", include_preview=True, min_severity="low"))
    assert sorted(f.line for f in res.findings if f.rule_id == "GO001") == [15]  # the handler's goroutine, not cleanup



SQL_LINE = """package main

import (
	"fmt"
	"net/http"
)

func h(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	db.Where(fmt.Sprintf("name = '%s'", name)).Find(&users).Exec(fmt.Sprintf("SELECT %s", name))
	db.Exec(fmt.Sprintf("SELECT * FROM %s", table))
}

func main() {
	http.HandleFunc("/u", h)
}
"""


def test_go004_never_on_a_line_with_be001(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n\ngo 1.22\n")
    (tmp_path / "main.go").write_text(SQL_LINE)
    res = scan(str(tmp_path), Options(offline=True, external="none", include_preview=True, min_severity="low"))
    got = sorted((f.line, f.rule_id) for f in res.findings if f.rule_id in ("BE001", "GO004"))
    assert set(got) == {(10, "BE001"), (11, "GO004")}  # line 10 has two sinks (a clause and a query), both BE001


def test_a_router_group_path_is_not_sql(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n\ngo 1.22\n")
    (tmp_path / "main.go").write_text('package main\n\nfunc main() {\n\tg := base.Group("/" + s.URL)\n\tdb.Where("name = " + name).Find(&u)\n}\n')
    res = scan(str(tmp_path), Options(offline=True, external="none", include_preview=True, min_severity="low"))
    assert sorted(f.line for f in res.findings if f.rule_id == "GO004") == [5]
