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
 "kotlin": {"src/main/kotlin/a/C.kt": 'package a\nimport org.springframework.web.bind.annotation.*\n@RestController\nclass C(val jdbc: JdbcTemplate) {\n  @DeleteMapping("/admin/users/{id}")\n  fun del(@PathVariable id: String) { jdbc.execute("DELETE FROM users WHERE id = " + id) }\n}\n'},
 "python": {"app.py": 'from flask import Flask, request\nimport sqlite3\napp = Flask(__name__)\n@app.route("/admin/users/<id>", methods=["DELETE"])\ndef delete(id):\n    sqlite3.connect("x").execute("DELETE FROM users WHERE id = %s" % id)\n    return "ok"\n'},
 "js": {"server.js": 'const express = require("express");\nconst app = express();\napp.delete("/admin/users/:id", (req, res) => { db.query("DELETE FROM users WHERE id = " + req.params.id); res.send("ok"); });\n'},
 "dart": {"pubspec.yaml": "name: a\ndependencies:\n  flutter:\n    sdk: flutter\n", "lib/main.dart": 'import "package:http/http.dart" as http;\nconst apiKey = "sk_' 'live_51HxQ2bL8tYv3kPzR9mN4wE7a";\nvoid f() { http.get(Uri.parse("http://api.example.com/api?key=" + apiKey)); }\n'},
}

EXPECT = {'csharp': {'AUTH002', 'BE001'}, 'php': {'BE001', 'FE001'}, 'kotlin': {'AUTH002', 'BE001'}, 'python': {'AUTH002', 'BE001'}, 'js': {'AUTH002', 'BE001'}, 'dart': {'SEC001'}}


@pytest.mark.parametrize("lang", sorted(CASES))
def test_each_language_still_reports_its_planted_bug(tmp_path: Path, lang: str):
    res = _scan(tmp_path, CASES[lang])
    assert res.meta.get("internal_errors", []) == []
    assert EXPECT[lang] <= {f.rule_id for f in res.findings}
