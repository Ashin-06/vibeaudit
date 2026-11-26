"""Optional tree-sitter index (vibeaudit[parse]): it finds declarations the regex index misses, and without it
(or with VIBEAUDIT_PARSER=regex) the scanners fall back to the regex index."""
from pathlib import Path

import pytest

from vibeaudit import doctor, parse
from test_lang_precision_fixes import _scan

GO = {"go.mod": "module app\ngo 1.22\n",
 "main.go": 'package main\nimport "net/http"\nfunc main() { http.HandleFunc("/u", get) }\nfunc get(w http.ResponseWriter, r *http.Request) {\n    store.FindUser(r.URL.Query().Get("id"))\n}\n',
 "store/store.go": 'package store\nimport "fmt"\nfunc FindUser(id string) (\n    n int,\n    err error,\n) {\n    db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))\n    return 0, nil\n}\n'}
RS = {"src/main.rs": 'use axum::{extract::Query, routing::get, Router};\nmod db;\nasync fn h(Query(q): Query<P>) -> String {\n    db::find(q.id).await\n}\nfn app() -> Router { Router::new().route("/u", get(h)) }\n',
 "src/db.rs": 'pub async fn find<T: Into<String>>(id: T) -> String {\n    let id: String = id.into();\n    conn.execute(&format!("SELECT * FROM users WHERE id = {}", id), []);\n    String::new()\n}\n'}
JAVA = {"src/main/java/a/C.java": 'package a;\nimport org.springframework.web.bind.annotation.*;\n@RestController\npublic class C {\n  @GetMapping("/u")\n  public String get(@RequestParam String id) { return Repo.find(id); }\n}\n',
 "src/main/java/a/Repo.java": 'package a;\npublic class Repo {\n  public static <T extends Comparable<? super T>> String find(\n      String id) {\n    jdbc.queryForList("SELECT * FROM users WHERE id = " + id);\n    return "";\n  }\n}\n'}
TS = {"package.json": '{"dependencies": {"express": "4.19.0", "pg": "8.11.0"}}\n',
 "server.ts": 'import express from "express";\nimport { findUser } from "./repo";\nconst app = express();\napp.get("/u", async (req, res) => { res.send(await findUser(req.query.id as string)); });\n',
 "repo.ts": 'import { Pool } from "pg";\nconst pool = new Pool();\nexport const findUser = async <T extends Record<string, (x: number) => boolean>>(id: string): Promise<string> => {\n  const r = await pool.query(`SELECT * FROM users WHERE id = ${id}`);\n  return JSON.stringify(r.rows);\n};\n'}


@pytest.mark.parametrize("lang,files,sink", [("go", GO, "store/store.go"), ("rust", RS, "src/db.rs"),
                                             ("java", JAVA, "src/main/java/a/Repo.java"), ("ts", TS, "repo.ts")])
def test_parser_finds_functions_the_regex_index_misses(tmp_path: Path, lang, files, sink):
    if parse.parser(lang) is None:
        pytest.skip("vibeaudit[parse] not installed")
    hits = [f for f in _scan(tmp_path, files).findings if f.rule_id == "BE001"]
    assert [f.file for f in hits] == [sink]
    if lang != "ts":
        assert "passed in through the call" in hits[0].message


def test_regex_fallback_when_parser_is_off(monkeypatch):
    monkeypatch.setenv("VIBEAUDIT_PARSER", "regex")
    parse.parser.cache_clear()
    try:
        assert parse.functions("go", "package a\nfunc f() {}\n") is None
        assert parse.js_functions("ts", "export const f = (x: string) => x;\n") is None
        rep = doctor.report()["parser"]
        assert set(rep) == {"go", "rust", "java", "js", "ts", "tsx"}
        assert set(rep.values()) == {"regex"}
    finally:
        monkeypatch.delenv("VIBEAUDIT_PARSER")
        parse.parser.cache_clear()


def test_parser_offsets_are_characters_not_bytes():
    if parse.parser("go") is None or parse.parser("ts") is None:
        pytest.skip("vibeaudit[parse] not installed")
    text = 'package a\n// caf\u00e9 \u00fc\nfunc f(x int) { g(x) }\n'
    (name, start, po, pc, bo, end), = parse.functions("go", text)
    assert (name, text[start:start + 4], text[po], text[pc], text[bo], text[end - 1]) == ("f", "func", "(", ")", "{", "}")
    ts_text = '// caf\u00e9 \u00fc\nexport const fn = (x: string) => x;\n'
    jname, jstart, jpo, jpc, jend = parse.js_functions("ts", ts_text)[0]
    assert (jname, ts_text[jstart:jstart + 5], ts_text[jpo], ts_text[jpc], ts_text[jend - 1]) == ("fn", "const", "(", ")", "x")
