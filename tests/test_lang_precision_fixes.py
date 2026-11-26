"""Regression tests for precision fixes across Go, Java/Kotlin, C#, Rust, and PHP."""
from __future__ import annotations

from pathlib import Path

from vibeaudit.scanner import Options, scan


def _scan(tmp_path: Path, files: dict[str, str], **opt_kw):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    opts = Options(offline=True, external="none", min_severity="low", include_preview=True, **opt_kw)
    return scan(str(tmp_path), opts)


def test_go_chi_mount_inherits_group_auth_and_role(tmp_path: Path):
    res = _scan(tmp_path, {
        "go.mod": "module app\ngo 1.22\nrequire github.com/go-chi/chi/v5 v5.0.0\n",
        "main.go": """package main
import "github.com/go-chi/chi/v5"

func setupRouter() chi.Router {
    r := chi.NewRouter()
    r.Group(func(r chi.Router) {
        r.Use(jwtAuth)
        r.Use(requireAdmin)
        r.Mount("/admin", adminRoutes())
    })
    return r
}

func adminRoutes() chi.Router {
    r := chi.NewRouter()
    r.Delete("/users/{id}", deleteUser)
    return r
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
    db.Exec("DELETE FROM users WHERE id = $1", r.PathValue("id"))
}
""",
    })
    rules = {f.rule_id for f in res.findings}
    assert "AUTH001" not in rules
    assert "AUTH002" not in rules


def test_go_prepared_statement_not_flagged_as_sqli(tmp_path: Path):
    res = _scan(tmp_path, {
        "go.mod": "module app\ngo 1.22\n",
        "repo.go": """package main
import (
    "database/sql"
    "net/http"
)

func getUser(db *sql.DB, r *http.Request) {
    id := r.URL.Query().Get("id")
    stmt, err := db.Prepare("SELECT name FROM users WHERE id = ?")
    if err != nil { return }
    defer stmt.Close()
    _ = stmt.QueryRow(id)
}
""",
    })
    rules = {f.rule_id for f in res.findings}
    assert "BE001" not in rules
    assert "GO004" not in rules


def test_jvm_custom_auth_annotation_and_static_http_method(tmp_path: Path):
    res = _scan(tmp_path, {
        "SecurityConfig.java": """package app;
import static org.springframework.http.HttpMethod.GET;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class SecurityConfig {
    void configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a
            .requestMatchers(GET, "/articles/**").permitAll()
            .anyRequest().authenticated());
    }
}
""",
        "ApiKeySecured.kt": """package app
@Target(AnnotationTarget.FUNCTION, AnnotationTarget.CLASS)
annotation class ApiKeySecured
""",
        "ArticleController.java": """package app;
import org.springframework.web.bind.annotation.*;

@RestController
public class ArticleController {
    @PostMapping("/articles")
    public void create(@RequestBody String body) {
        repo.save(body);
    }

    @ApiKeySecured
    @DeleteMapping("/keys/{id}")
    public void revoke(@PathVariable String id) {
        repo.deleteById(id);
    }
}
""",
    })
    rules = {f.rule_id for f in res.findings}
    assert "AUTH001" not in rules
    assert "JAVA001" not in rules


def test_csharp_service_layer_ownership_check_avoids_auth003(tmp_path: Path):
    res = _scan(tmp_path, {
        "AccountsController.cs": """using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[Authorize]
[Route("api/accounts")]
public class AccountsController : ControllerBase {
    private readonly AccountUseCase _useCase;

    [HttpDelete("{id}")]
    public async Task<IActionResult> Close(Guid id) {
        await _useCase.CloseAccountAsync(id);
        return NoContent();
    }
}
""",
        "AccountUseCase.cs": """public class AccountUseCase {
    public async Task CloseAccountAsync(Guid accountId) {
        var acc = await _repo.Find(accountId, _current.UserId);
        await _repo.SaveChangesAsync();
    }
}
""",
    })
    assert "AUTH003" not in {f.rule_id for f in res.findings}


def test_rust_module_qualified_handler_and_public_signup(tmp_path: Path):
    res = _scan(tmp_path, {
        "Cargo.toml": '[package]\nname = "app"\nversion = "0.1.0"\n[dependencies]\naxum = "0.7"\n',
        "src/handlers/auth.rs": """pub async fn register(Json(body): Json<Signup>) {
    db.execute("INSERT INTO users VALUES ($1)", body.email);
}
""",
        "src/handlers/user.rs": """pub async fn delete(auth: AuthUser, Path(id): Path<i64>) {
    db.execute("DELETE FROM users WHERE id = $1 AND user_id = $2", id, auth.user_id);
}
""",
        "src/handlers/other.rs": """pub async fn delete(Path(id): Path<i64>) {
    db.execute("DELETE FROM items WHERE id = $1", id);
}
""",
        "src/main.rs": """use axum::{Router, routing::{post, delete}};
fn app() -> Router {
    Router::new()
        .route("/api/users", post(handlers::auth::register))
        .route("/api/users/:id", delete(handlers::user::delete))
}
""",
    })
    assert "AUTH001" not in {f.rule_id for f in res.findings}


def test_php_blade_model_escaped_method_not_flagged(tmp_path: Path):
    res = _scan(tmp_path, {
        "app/Models/Link.php": """<?php
class Link {
    public function formattedDescription(): string {
        return nl2br(e($this->description));
    }
    public function rawBody(): string {
        return $this->description;
    }
}
""",
        "resources/views/link.blade.php": """<div>{!! $link->formattedDescription() !!}</div>
<div>{!! $link->rawBody() !!}</div>
""",
    })
    fe001 = [f for f in res.findings if f.rule_id == "FE001"]
    assert len(fe001) == 1
    assert fe001[0].line == 2


def test_go_sub_router_mounted_once_without_auth_is_public(tmp_path: Path):
    res = _scan(tmp_path, {
        "go.mod": "module app\ngo 1.22\nrequire github.com/go-chi/chi/v5 v5.0.0\n",
        "main.go": """package main
import "github.com/go-chi/chi/v5"
func setupRouter() chi.Router {
    r := chi.NewRouter()
    r.Group(func(r chi.Router) {
        r.Use(jwtAuth)
        r.Mount("/admin", adminRoutes())
    })
    r.Mount("/legacy", adminRoutes())
    return r
}
func adminRoutes() chi.Router {
    r := chi.NewRouter()
    r.Delete("/users/{id}", deleteUser)
    return r
}
func deleteUser(w http.ResponseWriter, r *http.Request) {
    db.Exec("DELETE FROM users WHERE id = $1", r.PathValue("id"))
}
""",
    })
    assert "AUTH001" in {f.rule_id for f in res.findings}


def test_rust_method_named_query_is_still_a_sql_sink(tmp_path: Path):
    res = _scan(tmp_path, {"src/main.rs": (
        'use actix_web::{post, web};\n#[post("/notes")]\n'
        'async fn add(body: web::Json<Note>) -> &\'static str {\n'
        '    client.query(&format!("SELECT * FROM notes WHERE t = \'{}\'", body.text), &[]).await;\n'
        '    "ok"\n}\n')})
    assert [f.line for f in res.findings if f.rule_id == "BE001"] == [4]  # tokio-postgres Client::query takes SQL


def test_rust_module_path_matches_whole_file_name(tmp_path: Path):
    from vibeaudit.files import Project
    from vibeaudit.rustscan import RustScanner
    fn = "pub async fn list() -> String { String::new() }\n"
    _scan(tmp_path, {"src/admin_user.rs": fn, "src/user.rs": fn, "src/main.rs": "fn main() {}\n"})
    s = RustScanner(Project(tmp_path), lambda f: None)
    s.run()
    main = s.funcs["main"][0][0]
    assert s._fn("crate::user::list", main)[0].rel == "src/user.rs"


def test_java_annotation_named_author_is_not_auth(tmp_path: Path):
    res = _scan(tmp_path, {
        "src/main/java/a/Author.java": "package a;\npublic @interface Author { String value(); }\n",
        "src/main/java/a/C.java": ('package a;\nimport org.springframework.web.bind.annotation.*;\n@Author("x")\n'
                                   '@RestController\npublic class C {\n  @DeleteMapping("/admin/users/{id}")\n'
                                   '  public void del(@PathVariable Long id) { repo.deleteById(id); }\n}\n'),
    })
    assert "AUTH002" in {f.rule_id for f in res.findings}
