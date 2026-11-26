"""Tests for v0.14.0 features: feedback demotion/export/suggest-helpers, init, report top-5/fix tip,
doctor install_fix, LSP route hover + Studio auth_evidence, PHP caching, Ruby inline group, Go variable mount, C# minimal APIs.
"""
from __future__ import annotations

import json
from pathlib import Path

from vibeaudit import __version__, cli, deps, doctor, feedback, init, lsp, phpscan, studio
from vibeaudit.model import Finding
from vibeaudit.report import Result, render_text
from vibeaudit.scanner import Options, scan


def _write_tree(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return tmp_path


def test_feedback_demotion_export_and_suggest_helpers(tmp_path):
    root = _write_tree(tmp_path, {
        "app.py": (
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n"
            "def require_org_member(): pass\n"
            "@app.post('/a')\ndef a():\n    require_org_member()\n    db.save(request.get_json())\n    return {'ok': 1}\n"
            "@app.post('/b')\ndef b():\n    require_org_member()\n    db.save(request.get_json())\n    return {'ok': 2}\n"
            "@app.post('/c')\ndef c():\n    require_org_member()\n    db.save(request.get_json())\n    return {'ok': 3}\n"
            "@app.post('/d')\ndef d():\n    db.save(request.get_json())\n    return {'ok': 4}\n"
        ),
    })
    pre = scan(str(root), Options(offline=True, external="none", feedback=False, include_preview=False))
    auth_lines = sorted(f.line for f in pre.findings if f.rule_id == "AUTH001")
    assert len(auth_lines) >= 3
    assert feedback.record(root, "AUTH001", "app.py", auth_lines[0], "false-positive", "org guard") is not None
    assert feedback.record(root, "AUTH001", "app.py", auth_lines[1], "false-positive", "org guard") is not None
    assert feedback.record(root, "AUTH001", "app.py", auth_lines[2], "confirmed", "missed guard") is not None

    noisy = feedback.noisy_rules(root)
    assert "AUTH001" in noisy and noisy["AUTH001"][0] == 2 and noisy["AUTH001"][1] == 3

    res = scan(str(root), Options(offline=True, external="none", feedback=True, include_preview=False))
    assert "AUTH001" in res.meta["feedback_demoted"]
    assert all(f.preview and not f.gates_in_preview for f in res.findings if f.rule_id == "AUTH001")
    assert any("was demoted to preview" in n for n in res.meta["notes"])

    exported = feedback.export_tests(root)
    assert "def test_auth001_" in exported
    compile(exported, "test_feedback_regressions.py", "exec")

    suggested = feedback.suggest_auth_helpers(root)
    assert any(c["name"] == "require_org_member" for c in suggested["candidates"])
    assert "auth-helpers" in suggested["diff"] and "require_org_member" in suggested["diff"]


def test_vibeaudit_init_variants(tmp_path, capsys):
    app = _write_tree(tmp_path / "pyapp", {
        "requirements.txt": "flask\n",
        "app.py": "import requests\nrequests.get('https://example.com')\n",
    })
    assert cli.main(["init", str(app)]) == 0
    out = capsys.readouterr().out
    assert "created .vibeaudit.toml" in out
    assert (app / ".vibeaudit.toml").is_file()
    assert (app / ".pre-commit-config.yaml").is_file()
    assert (app / ".github" / "workflows" / "vibeaudit.yml").is_file()
    assert f"v{__version__}" in (app / ".pre-commit-config.yaml").read_text()

    # second run preserves existing files without --force
    res2 = init.run(app)
    assert res2["created"] == [] and len(res2["skipped"]) == 3

    gl = _write_tree(tmp_path / "glapp", {"x.py": "x = 1\n"})
    res3 = init.run(gl, ci="gitlab", hook=False)
    assert ".gitlab-ci.yml" in res3["created"] and ".pre-commit-config.yaml" not in res3["created"]


def test_render_text_top5_and_fix_tip():
    findings = [
        Finding("REL001", "a.py", i + 1, "no timeout", "medium", title="Missing timeout", category="reliability")
        for i in range(6)
    ]
    res = Result("/p", findings, {"files_scanned": 1, "stack": ["Python"]})
    txt = render_text(res, color=False, verbose=True)
    assert "Top 5 findings" in txt
    assert "6 findings can be fixed automatically with `vibeaudit fix`." in txt


def test_doctor_install_fix_when_mismatched(monkeypatch):
    monkeypatch.setattr(doctor.importlib.metadata, "version", lambda _pkg: "0.0.1")
    info = doctor.report()
    assert info["status"] == "warn"
    assert info["install_fix"] and "pip install" in info["install_fix"]
    assert info["install_fix"] in doctor.render_text(info)


def test_lsp_hover_and_studio_auth_evidence(tmp_path):
    _write_tree(tmp_path, {
        "app.py": (
            "from flask import Flask\napp = Flask(__name__)\n"
            "def login_required(fn): return fn\n"
            "@app.post('/items')\n@login_required\ndef create_item(): return 'ok'\n"
        ),
    })
    import io

    out = io.BytesIO()
    srv = lsp.Server(out)
    init_res = srv.dispatch("initialize", {"rootUri": tmp_path.as_uri()})
    assert init_res["capabilities"]["hoverProvider"] is True
    srv.scan()
    assert srv.watcher is not None and srv.watcher.routes
    route_line = srv.watcher.routes[0].line
    uri = (tmp_path / "app.py").as_uri()
    hover = srv.dispatch("textDocument/hover", {"textDocument": {"uri": uri}, "position": {"line": route_line - 1, "character": 0}})
    assert hover is not None
    assert "POST /items" in hover["contents"]["value"] and "login_required" in hover["contents"]["value"]

    data = studio.build(scan(str(tmp_path), Options(offline=True, external="none")), srv.watcher.project)
    assert data["routes"][0]["auth_evidence"]
    js_src = (Path(studio.__file__).parent / "studio_assets" / "studio.js").read_text(encoding="utf-8")
    assert "auth_evidence" in js_src


def test_section2_fixes_php_ruby_go_and_csharp_minimal_api(tmp_path):
    # Ruby single-line group :production kept, group :test skipped
    gems = deps.gemfile_dependencies(
        "source 'https://rubygems.org'\n"
        "group :production do gem 'puma', '6.4.2' end\n"
        "group :test do gem 'rspec-rails' end\n"
    )
    assert [(g, v) for g, v, _ln in gems] == [("puma", "6.4.2")]

    # PHP _index_safe_methods runs only once even when no safe methods exist
    calls = {"n": 0}
    orig = phpscan.PhpScanner._index_safe_methods

    def counted(self):
        calls["n"] += 1
        return orig(self)

    php_root = _write_tree(tmp_path / "php", {
        "app/Foo.php": "<?php\nfunction plainHelper($x) { return $x; }\n",
        "views/a.blade.php": "{!! $a !!}\n",
        "views/b.blade.php": "{!! $b !!}\n",
    })
    old_fn = phpscan.PhpScanner._index_safe_methods
    phpscan.PhpScanner._index_safe_methods = counted  # type: ignore[method-assign]
    try:
        scan(str(php_root), Options(offline=True, external="none", include_preview=True))
    finally:
        phpscan.PhpScanner._index_safe_methods = old_fn  # type: ignore[method-assign]
    assert calls["n"] == 1

    # Go r.Mount("/admin", subVar) inherits auth middleware
    go_root = _write_tree(tmp_path / "go", {
        "go.mod": "module app\ngo 1.22\n",
        "main.go": (
            'package main\nimport "github.com/go-chi/chi/v5"\n'
            'func main() {\n'
            '    r := chi.NewRouter()\n'
            '    sub := chi.NewRouter()\n'
            '    sub.Delete("/users", delUser)\n'
            '    r.Group(func(r chi.Router) { r.Use(RequireAuth); r.Mount("/admin", sub) })\n'
            '}\n'
            'func delUser(w http.ResponseWriter, r *http.Request) {}\n'
        ),
    })
    go_res = scan(str(go_root), Options(offline=True, external="none", include_preview=True))
    assert go_res.routes and go_res.routes[0].has_auth is True

    # C# Minimal APIs: MapPost without auth triggers AUTH001, with RequireAuthorization does not
    cs_root = _write_tree(tmp_path / "cs", {
        "Program.cs": (
            'var builder = WebApplication.CreateBuilder(args);\n'
            'var app = builder.Build();\n'
            'app.MapPost("/open", () => db.SaveChanges());\n'
            'app.MapPost("/locked", () => db.SaveChanges()).RequireAuthorization();\n'
        ),
    })
    cs_res = scan(str(cs_root), Options(offline=True, external="none", include_preview=True))
    auth_routes = {r.path: r.has_auth for r in cs_res.routes}
    assert auth_routes == {"/open": False, "/locked": True}
