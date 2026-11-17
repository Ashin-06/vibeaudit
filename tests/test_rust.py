"""Rust (Actix, Axum): the lexer, routes and auth, data flow into the generic sinks, test modules, Cargo."""
import time
from pathlib import Path

from vibeaudit import deps
from vibeaudit.rustscan import RustScanner, rust_views, without_test_modules
from vibeaudit.files import Project
from vibeaudit.scanner import Options, scan

ACTIX = r'''use actix_web::{delete, get, post, web, App, HttpResponse, HttpServer};

/* a "comment" with { braces */
#[get("/items/{id}")]
async fn get_item(id: web::Path<i64>) -> HttpResponse { HttpResponse::Ok().body("}") }

#[delete("/items/{name}")]
#[actix_web_grants::protect("ADMIN")]
async fn delete_item(name: web::Path<String>) -> HttpResponse { HttpResponse::Ok().finish() }

#[post("/search")]
async fn search(body: web::Json<Search>) -> HttpResponse {
    let q = format!("SELECT * FROM items WHERE name = '{}'", body.name);
    sqlx::query(&q).fetch_all(&pool).await;
    let raw = r#"a raw "string" with { "#;
    HttpResponse::Ok().finish()
}

#[get("/files/{file}")]
async fn serve(file: web::Path<String>) -> HttpResponse {
    if file.contains('/') || file.contains('\\') {
        return HttpResponse::NotFound().finish();
    }
    let path = format!("/srv/files/{}", file);
    let body = std::fs::read_to_string(&path).unwrap();
    HttpResponse::Ok().body(body)
}

#[get("/raw/{file}")]
async fn raw(file: web::Path<String>) -> HttpResponse {
    let body = std::fs::read_to_string(format!("/srv/files/{}", file)).unwrap();
    HttpResponse::Ok().body(body)
}

async fn dashboard() -> HttpResponse { HttpResponse::Ok().finish() }
async fn publish(form: web::Form<Post>) -> HttpResponse {
    std::process::Command::new("sh").arg("-c").arg(&form.cmd).output().unwrap();
    HttpResponse::Ok().finish()
}

fn app() {
    App::new()
        .service(get_item).service(delete_item).service(search).service(serve).service(raw)
        .service(
            web::scope("/admin")
                .wrap(from_fn(reject_anonymous_users))
                .route("/dashboard", web::get().to(dashboard))
                .route("/publish", web::post().to(publish)),
        );
}

#[cfg(test)]
mod tests {
    use super::*;
    fn seed() { for i in 0..5 { sqlx::query("INSERT INTO items VALUES ($1)").bind(i); } }
}
'''
AXUM = '''use axum::{routing::{get, post}, Json, Router};

async fn list() -> Json<Vec<Item>> { Json(vec![]) }
async fn create(Json(body): Json<NewItem>) -> Json<Item> { Json(body.into()) }
async fn me(claims: Claims) -> Json<User> { Json(claims.user) }

fn api() -> Router { Router::new().route("/items", get(list).post(create)).route("/me", get(me)) }

pub fn app() -> Router { Router::new().nest("/api", api()) }
'''


def write(root: Path, files: dict) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def found(root, *rules):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low", include_preview=True))
    assert res.meta.get("internal_errors", []) == []
    return sorted((f.rule_id, f.file.rsplit("/", 1)[-1], f.line) for f in res.findings if not rules or f.rule_id in rules)


def test_lexer_views_keep_offsets_and_blank_comments_and_strings():
    v = rust_views(ACTIX)
    assert len(v.code) == len(v.bare) == len(ACTIX) and v.code.count("\n") == ACTIX.count("\n")
    assert "comment" not in v.code and '"/items/{id}"' in v.code and '"/items/{id}"' not in v.bare
    assert "raw" in v.bare and 'a raw "string"' not in v.bare and v.bare.count("{") == v.bare.count("}")


def test_test_modules_are_blanked():
    v = rust_views(ACTIX)
    out = without_test_modules(v.code, v.bare)
    assert len(out) == len(ACTIX) and "INSERT INTO items" not in out and "fn app()" in out


def test_routes_prefixes_and_auth(tmp_path):
    root = write(tmp_path, {"src/main.rs": ACTIX, "src/api.rs": AXUM})
    routes = {(tuple(r.methods), r.path): r for r in RustScanner(Project(root), lambda f: None).run()}
    assert {("GET", "/items/{id}"), ("DELETE", "/items/{name}"), ("POST", "/search"), ("GET", "/admin/dashboard"),
            ("POST", "/admin/publish"), ("GET", "/api/items"), ("POST", "/api/items"), ("GET", "/api/me")} <= {
        (m[0], p) for m, p in routes}
    assert routes[(("DELETE",), "/items/{name}")].has_auth  # #[protect(...)] on the handler
    assert routes[(("POST",), "/admin/publish")].has_auth  # the scope wraps reject_anonymous_users
    assert routes[(("GET",), "/api/me")].has_auth and not routes[(("POST",), "/api/items")].has_auth  # a Claims extractor
    assert routes[(("GET",), "/admin/dashboard")].framework == "actix" and routes[(("GET",), "/api/items")].framework == "axum"


def test_data_flow(tmp_path):
    root = write(tmp_path, {"src/main.rs": ACTIX})
    got = found(root, "BE001", "BE002", "BE006", "DATA001")
    assert ("BE001", "main.rs", 14) in got  # format! with the request body
    assert ("BE002", "main.rs", 37) in got  # sh -c with a form field
    assert ("BE006", "main.rs", 31) in got  # an unchecked file name
    assert not [g for g in got if g[0] == "BE006" and g[2] < 31]  # serve() rejects separators first
    assert not [g for g in got if g[0] == "DATA001"]  # the loop is in #[cfg(test)]


def test_admin_scope_without_any_roles_needs_no_role_check(tmp_path):
    root = write(tmp_path / "plain", {"src/main.rs": ACTIX})
    assert found(root, "AUTH002", "AUTH017") == []  # one kind of user: every account is the admin
    roles = write(tmp_path / "roles", {"src/main.rs": ACTIX, "src/user.rs": "pub struct User { pub roles: Vec<String> }\n"})
    assert found(roles, "AUTH002") == [("AUTH002", "main.rs", 47), ("AUTH002", "main.rs", 48)]


def test_cargo_dependencies_and_lock(tmp_path):
    toml = ('[package]\nname = "app"\n\n[dependencies]\nserde = "1"\nweb = { package = "actix-web", version = "4" }\n'
            'local = { path = "../local" }\nshared = { workspace = true }\n\n[dev-dependencies]\nmockito = "1"\n')
    assert deps.cargo_dependencies(toml) == [("serde", 5), ("actix-web", 6)]
    lock = ('[[package]]\nname = "serde"\nversion = "1.0.200"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
            '[[package]]\nname = "app"\nversion = "0.1.0"\n')
    root = write(tmp_path, {"Cargo.lock": lock, "crates/app/Cargo.toml": toml})
    assert deps.cargo_locked(Project(root), "crates/app/Cargo.toml") == {"serde": "1.0.200"}


def test_env_files_without_values_are_not_reported_by_cfg009(tmp_path):
    docker = "FROM rust:1.80\nCOPY . .\nRUN cargo build --release\n"
    empty = write(tmp_path / "empty", {"Dockerfile": docker, ".envrc": "use flake\n", ".env": "AUTH_TOKEN=\n# KEY=x\n"})
    assert found(empty, "CFG009") == []
    real = write(tmp_path / "real", {"Dockerfile": docker, ".env": "AUTH_TOKEN=abc123\n"})
    assert found(real, "CFG009") == [("CFG009", "Dockerfile", 2)]


def test_pathological_input_is_fast():
    for src in ("/*" * 50000, '"' * 100000, "r#\"" * 30000, "'" * 100000, "{" * 100000, "#[get(\"" * 20000,
                "#[cfg(test)] mod t {" * 20000, "#[x]\n" * 30000 + "fn a() {}"):
        t = time.perf_counter()
        v = rust_views(src)
        without_test_modules(v.code, v.bare)
        assert len(v.bare) == len(src)
        assert time.perf_counter() - t < 2
