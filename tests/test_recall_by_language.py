"""Recall floor per language: each snippet hides a real bug the scanner must keep reporting.

Language-specific tricky cases (name collisions, mixed mounts, annotation names) live in
test_lang_precision_fixes.py; this file makes sure no language silently goes quiet.
"""
from pathlib import Path

import pytest

from test_lang_precision_fixes import _scan

CASES = {
 "csharp": {"Api/C.cs": 'using Microsoft.AspNetCore.Mvc;\n[ApiController]\n[Route("api/admin/users")]\npublic class UsersController : ControllerBase {\n  [HttpDelete("{id}")]\n  public IActionResult Del(int id) { _db.Database.ExecuteSqlRaw("DELETE FROM users WHERE id = " + id); return Ok(); }\n}\n'},
 "php": {"index.php": '<?php\n$id = $_GET["id"];\n$r = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);\necho $_GET["name"];\n'},
 "java": {"src/main/java/a/C.java": 'package a;\nimport org.springframework.web.bind.annotation.*;\n@RestController\npublic class C {\n  @DeleteMapping("/admin/users/{id}")\n  public void del(@PathVariable String id, JdbcTemplate jdbc) { jdbc.execute("DELETE FROM users WHERE id = " + id); }\n}\n'},
 "kotlin": {"src/main/kotlin/a/C.kt": 'package a\nimport org.springframework.web.bind.annotation.*\n@RestController\nclass C(val jdbc: JdbcTemplate) {\n  @DeleteMapping("/admin/users/{id}")\n  fun del(@PathVariable id: String) { jdbc.execute("DELETE FROM users WHERE id = " + id) }\n}\n'},
 "go": {"go.mod": "module app\ngo 1.22\n", "main.go": 'package main\nimport ("fmt"; "net/http")\nfunc main() { http.HandleFunc("/admin/users", h) }\nfunc h(w http.ResponseWriter, r *http.Request) {\n    db.Query(fmt.Sprintf("DELETE FROM users WHERE id = %s", r.URL.Query().Get("id")))\n}\n'},
 "rust": {"src/main.rs": 'use actix_web::{delete, web, HttpResponse};\n#[delete("/admin/users/{id}")]\nasync fn del(id: web::Path<String>) -> HttpResponse {\n    sqlx::query(&format!("DELETE FROM users WHERE id = {}", id)).execute(&pool).await;\n    HttpResponse::Ok().finish()\n}\n'},
 "ruby": {"config/routes.rb": "Rails.application.routes.draw do\n  delete '/admin/users/:id', to: 'users#destroy'\nend\n", "app/controllers/users_controller.rb": "class UsersController < ApplicationController\n  def destroy\n    User.where(\"id = #{params[:id]}\")\n  end\nend\n"},
 "python": {"app.py": 'from flask import Flask, request\nimport sqlite3\napp = Flask(__name__)\n@app.route("/admin/users/<id>", methods=["DELETE"])\ndef delete(id):\n    sqlite3.connect("x").execute("DELETE FROM users WHERE id = %s" % id)\n    return "ok"\n'},
 "js": {"server.js": 'const express = require("express");\nconst app = express();\napp.delete("/admin/users/:id", (req, res) => { db.query("DELETE FROM users WHERE id = " + req.params.id); res.send("ok"); });\n'},
 "dart": {"pubspec.yaml": "name: a\ndependencies:\n  flutter:\n    sdk: flutter\n", "lib/main.dart": 'import "package:http/http.dart" as http;\nconst apiKey = "sk_' 'live_51HxQ2bL8tYv3kPzR9mN4wE7a";\nvoid f() { http.get(Uri.parse("http://api.example.com/api?key=" + apiKey)); }\n'},
}

EXPECT = {
    'csharp': {'AUTH002', 'BE001'},
    'php': {'BE001', 'FE001'},
    'java': {'AUTH002', 'BE001'},
    'kotlin': {'AUTH002', 'BE001'},
    'go': {'BE001'},
    'rust': {'AUTH002', 'BE001'},
    'ruby': {'BE001'},
    'python': {'AUTH002', 'BE001'},
    'js': {'AUTH002', 'BE001'},
    'dart': {'SEC001'},
}


@pytest.mark.parametrize("lang", sorted(CASES))
def test_each_language_still_reports_its_planted_bug(tmp_path: Path, lang: str):
    res = _scan(tmp_path, CASES[lang])
    assert res.meta.get("internal_errors", []) == []
    assert EXPECT[lang] <= {f.rule_id for f in res.findings}


CROSS_FILE_GO = {"go.mod": "module app\ngo 1.22\n",
 "main.go": 'package main\nimport "net/http"\nfunc main() { http.HandleFunc("/u", get) }\nfunc get(w http.ResponseWriter, r *http.Request) {\n    id := r.URL.Query().Get("id")\n    store.FindUser(id)\n}\n',
 "store/store.go": 'package store\nimport "fmt"\nfunc FindUser(id string) {\n    db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))\n}\n'}
CROSS_FILE_RS = {"src/main.rs": 'use axum::{extract::Query, routing::get, Router};\nmod db;\nasync fn h(Query(q): Query<P>) -> String {\n    db::find(&q.id).await\n}\nfn app() -> Router { Router::new().route("/u", get(h)) }\n',
 "src/db.rs": 'pub async fn find(id: &str) -> String {\n    sqlx::query(&format!("SELECT * FROM users WHERE id = {}", id)).fetch_one(&pool).await;\n    String::new()\n}\n'}


@pytest.mark.parametrize("files,sink", [(CROSS_FILE_GO, "store/store.go"), (CROSS_FILE_RS, "src/db.rs")])
def test_request_data_is_followed_into_another_file(tmp_path: Path, files, sink):
    hits = [f for f in _scan(tmp_path, files).findings if f.rule_id == "BE001"]
    assert [f.file for f in hits] == [sink] and "passed in through the call" in hits[0].message
