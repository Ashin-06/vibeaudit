"""JavaScript taint followed into functions of the same file and named imports from project files."""
import shutil
from pathlib import Path

from vibeaudit.files import Project
from vibeaudit.guard import StepMemo
from vibeaudit.scanner import Options, scan

SEEDED = Path(__file__).parent.parent / "benchmark" / "seeded" / "js_layers_app"
RULES = ("BE001", "BE002", "LLM002")


def found(root, project=None):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low", include_preview=True), project)
    assert res.meta.get("internal_errors", []) == []
    return {(f.rule_id, f.file, f.line): f.message for f in res.findings if f.rule_id in RULES}


def test_sinks_in_helpers_and_imported_modules():
    got = found(SEEDED)
    assert got[("BE001", "lib/orders.js", 4)].startswith("Request data flows into")
    assert got[("BE002", "lib/orders.js", 12)].startswith("Request data flows into")  # through an alias, two calls deep
    assert got[("LLM002", "server.js", 9)].startswith("Model output flows into")
    assert not any(k[1] == "lib/orders.js" and k[2] == 16 for k in got)  # a parameterised query


def test_a_reused_project_reports_the_same_and_drops_stale_taint(tmp_path):
    root = tmp_path / "app"
    shutil.copytree(SEEDED, root)
    project = Project(root)
    project.step_memo = StepMemo()  # as vibeaudit watch and the LSP server
    first = found(root, project)
    project.refresh()
    assert found(root, project) == first
    server = root / "server.js"
    server.write_text(server.read_text().replace("exportAll(req.body.format)", 'exportAll("csv")'))
    project.refresh()
    again = found(root, project)
    assert not again.get(("BE002", "lib/orders.js", 12), "").startswith("Request data")  # the caller no longer passes it


def test_unrelated_and_recursive_calls(tmp_path):
    (tmp_path / "a.js").write_text(
        'const express = require("express");\nconst { exec } = require("child_process");\nconst app = express();\n'
        'function a(v) { return b(v); }\nfunction b(v) { exec("x" + v); return a(v); }\n'
        'function c(v) { exec("y" + v); }\n'
        'app.post("/x", (req, res) => { a(req.body.v); c("fixed"); res.send("ok"); });\n')
    got = found(tmp_path)
    assert any(k[0] == "BE002" and k[2] == 5 and m.startswith("Request data") for k, m in got.items())
    assert not any(k[2] == 6 and m.startswith("Request data") for k, m in got.items())


def test_redirect_to_what_an_api_returned_is_not_an_open_redirect(tmp_path):
    (tmp_path / "pay.ts").write_text(
        'import Stripe from "stripe";\nimport { redirect } from "next/navigation";\nconst stripe = new Stripe("k");\n'
        'export async function checkout({ priceId }: { priceId: string }) {\n'
        '  const session = await stripe.checkout.sessions.create({ line_items: [{ price: priceId }] });\n'
        '  redirect(session.url!);\n}\n')
    (tmp_path / "server.ts").write_text(
        'import express from "express";\nimport { checkout } from "./pay";\nconst app = express();\n'
        'app.post("/buy", async (req, res) => { await checkout({ priceId: req.body.priceId }); });\n'
        'app.get("/go", (req, res) => { const next = req.query.next.toString(); res.redirect(next); });\n'
        'app.get("/to", (req, res) => { const u = new URL(req.query.u); res.redirect(u.href); });\n')
    res = scan(str(tmp_path), Options(offline=True, external="none", min_severity="low", include_preview=True))
    lines = sorted((f.file, f.line) for f in res.findings if f.rule_id == "BE008")
    assert lines == [("server.ts", 5), ("server.ts", 6)]
