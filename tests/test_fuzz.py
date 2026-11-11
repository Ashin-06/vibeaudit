"""Robustness fuzzing: random and malformed inputs must never crash, hang or produce invalid reports.

Seeds are fixed, so every run is reproducible. Set VIBEAUDIT_FUZZ_ROUNDS (default 6) for deeper runs,
for example VIBEAUDIT_FUZZ_ROUNDS=200 python -m pytest tests/test_fuzz.py.
"""
import json
import os
import random
import string
import sys
import time
from pathlib import Path

import pytest

from helpers import FIXTURES, fake_values
from vibeaudit.report import render_html, render_json, render_markdown, render_sarif, render_text
from vibeaudit.scanner import Options, scan

ROUNDS = int(os.environ.get("VIBEAUDIT_FUZZ_ROUNDS", "6"))


def _budget() -> float:
    """Seconds one scan may take, scaled to this machine. The slowest shape (120,000 statements on one line)
    is linear but costs about 80 times this calibration loop; shared CI runners (macOS) are 3 to 4 times
    slower than a laptop and ran it in 31 to 32 s against a fixed 30 s limit. A super-linear path takes
    minutes, so 250 calibration units still catch it."""
    import ast

    start = time.perf_counter()
    sum(1 for _ in ast.walk(ast.parse("x = 1; " * 20000)))
    return max(30.0, 250 * (time.perf_counter() - start))


PER_SCAN_SECONDS = _budget()

CODE_NAMES = [
    "app.py", "main.py", "server.js", "index.ts", "route.ts", "page.tsx", "Comp.vue", "Page.svelte", "index.html",
    "app/api/x/route.ts", "pages/api/y.js", "supabase/functions/f/index.ts", "settings.py", "views.py",
    "package.json", "package-lock.json", "requirements.txt", "pyproject.toml", ".mcp.json", "firestore.rules",
    "database.rules.json", "supabase/migrations/1.sql", "Dockerfile", "docker-compose.yml", ".github/workflows/a.yml",
    ".env", ".env.local", "next.config.js", "vite.config.ts", "actions.ts",
]
TOKENS = [
    "def ", "class ", "async ", "await ", "return ", "lambda ", "(", ")", "[", "]", "{", "}", ":", ",", ".", "=",
    "==", "+", "%", "*", "f\"", "\"", "'", "`", "${", "#", "//", "/*", "*/", "\n", "\t", "    ", "\\",
    "request.args", "req.body", "eval(", "exec(", "os.system(", "execute(", "SELECT * FROM t WHERE ",
    "innerHTML = ", "dangerouslySetInnerHTML={{ __html: ", "app.post('/x', ", "@app.route(\"/a\", methods=[\"POST\"])",
    "export async function POST(req) {", "'use server'", "\"use client\"", "role: 'system', content: ",
    "{\"role\": \"system\", \"content\": f\"", "openai.chat.completions.create(", "client.messages.create(",
    "create table ", "create policy p on t for update using (true);", "allow read, write: if true;", "while True:",
    "while (true) {", "subprocess.run(", "shell=True", "NEXT_PUBLIC_OPENAI_API_KEY", "sk-", "eyJ", "AIza", "-----BEGIN ",
    "postgres://u:p@h.x.y/db", "\"mcpServers\": {", "\"dependencies\": {", "==1.0", "FROM x", "USER y", "${{ github.event.issue.title }}",
    chr(0xE9), chr(0x4E2D), chr(0xFEFF), "\x00", "\r", "\r\n", chr(0x2028),
]


def _random_text(rng: random.Random, n: int) -> str:
    parts = []
    for _ in range(n):
        r = rng.random()
        if r < 0.6:
            parts.append(rng.choice(TOKENS))
        elif r < 0.85:
            parts.append("".join(rng.choice(string.ascii_letters + "_") for _ in range(rng.randint(1, 8))))
        else:
            parts.append(rng.choice(string.printable))
    return "".join(parts)


def _fixture_texts():
    values = fake_values()
    out = []
    for p in FIXTURES.rglob("*"):
        if p.is_file() and p.suffix != ".expected":
            t = p.read_text(encoding="utf-8")
            for k, v in values.items():
                t = t.replace("{{" + k + "}}", v)
            out.append((p.name, t))
    return out


def _check_result(res):
    assert res.meta.get("internal_errors", []) == [], res.meta.get("internal_errors")
    json.loads(render_json(res))
    sarif = json.loads(render_sarif(res))
    assert sarif["version"] == "2.1.0"
    for r in sarif["runs"][0]["results"]:
        assert r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
    render_html(res).encode("ascii")
    render_markdown(res)
    render_text(res, color=False)


def _scan(root):
    start = time.monotonic()
    res = scan(str(root), Options(offline=True, external="none"))
    assert time.monotonic() - start < PER_SCAN_SECONDS
    _check_result(res)
    return res


@pytest.mark.parametrize("seed", range(ROUNDS))
def test_random_projects(tmp_path, seed):
    rng = random.Random(1000 + seed)
    for i in range(25):
        name = rng.choice(CODE_NAMES)
        path = tmp_path / f"d{i % 4}" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        text = _random_text(rng, rng.randint(0, 400))
        mode = rng.random()
        if mode < 0.2:
            path.write_bytes(text.encode("utf-8", "surrogatepass")[: rng.randint(0, 2000)])  # possibly cut mid-character
        elif mode < 0.3:
            path.write_bytes(bytes(rng.randrange(256) for _ in range(rng.randint(0, 3000))))
        elif mode < 0.4:
            path.write_bytes(text.encode("latin-1", "replace"))
        elif mode < 0.45:
            path.write_bytes(text.encode("utf-16"))
        else:
            path.write_text(text, encoding="utf-8", errors="replace")
    _scan(tmp_path)


@pytest.mark.parametrize("seed", range(ROUNDS))
def test_mutated_fixture_files(tmp_path, seed):
    rng = random.Random(2000 + seed)
    for name, text in _fixture_texts():
        for k in range(3):
            target = tmp_path / f"m{k}" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            op = rng.random()
            if op < 0.3 and text:
                cut = rng.randint(0, len(text))
                mutated = text[:cut]
            elif op < 0.6 and text:
                chars = list(text)
                for _ in range(rng.randint(1, 20)):
                    chars[rng.randrange(len(chars))] = rng.choice(TOKENS)
                mutated = "".join(chars)
            elif op < 0.8 and text:
                a, b = sorted(rng.randrange(len(text) + 1) for _ in range(2))
                mutated = text[:a] + text[b:] + text[a:b]
            else:
                mutated = text.replace("\n", rng.choice(["", " ", "\r\n", "\r", "\n\n\n"]))
            target.write_text(mutated, encoding="utf-8", errors="replace")
    _scan(tmp_path)


def test_pathological_shapes(tmp_path):
    deep = 3000
    (tmp_path / "deep_parens.py").write_text("x = " + "(" * deep + "1" + ")" * deep + "\n")
    (tmp_path / "deep_binop.py").write_text("q = " + " + ".join(["a"] * 20000) + "\nexecute(q)\n")
    (tmp_path / "deep_attr.py").write_text("y = a" + ".b" * 5000 + "\n")
    (tmp_path / "deep_lists.py").write_text("z = " + "[" * 90 + "]" * 90 + "\n")
    (tmp_path / "deep.js").write_text("const f = " + "(" * deep + "1" + ")" * deep + ";\n" + "{" * deep + "}" * deep)
    (tmp_path / "unclosed.js").write_text("const a = `${" * 2000 + "\nfunction f( { [ \" ' /*")
    (tmp_path / "unclosed.ts").write_text("app.post('/x', (req, res) => {" * 500)
    (tmp_path / "one_line.py").write_text("x = 1; " * 120000)
    (tmp_path / "one_line_big.js").write_text("eval(a);" * 120000)
    (tmp_path / "long_string.py").write_text("s = '" + "a" * 900000 + "'\n")
    (tmp_path / "many_lines.py").write_text("x = 1\n" * 150000)
    (tmp_path / "empty.py").write_text("")
    (tmp_path / "empty.js").write_text("")
    (tmp_path / "only_bom.py").write_bytes(b"\xef\xbb\xbf")
    (tmp_path / "binary.py").write_bytes(b"\x00\x01\x02eval(x)" * 100)
    (tmp_path / "null_in_middle.js").write_bytes(b"a" * 9000 + b"\x00" + b"eval(x)")
    (tmp_path / "regexy.js").write_text("const r = /" + "a" * 50000 + "\n/ / / / // / * /*/ */")
    (tmp_path / "sql.sql").write_text("create policy p on t " + "x " * 50000 + "\n" + "create table t (\n" * 3000)
    (tmp_path / "huge.rules").write_text("allow read, write" + ", read" * 40000)
    (tmp_path / "secrets.txt").write_text(("sk-" + "a" * 47 + " ") * 20000)
    (tmp_path / "redos_like.js").write_text("const a = 'x' + " * 5000 + "1;\nconst { " + "a, " * 20000 + "} = req.body;\n")
    (tmp_path / "py_redos.py").write_text("password = '" + "a" * 100000 + "\n" + "api_key=" + "\"" * 50000)
    _scan(tmp_path)


def test_malformed_manifests_and_configs(tmp_path):
    cases = {
        "package.json": ["", "[]", "null", "1", "{", '{"dependencies": []}', '{"dependencies": {"a": null, "b": 1, "": ""}}',
                         '{"dependencies": "x", "scripts": []}', '{"scripts": {"postinstall": 5}}', '{"name": {"x": 1}}'],
        "package-lock.json": ["", "[]", '{"packages": []}', '{"packages": {"node_modules/a": 5}}', '{"dependencies": "x"}'],
        "requirements.txt": ["", "\x00", "-e .", "==1.0", "a==", "[extra]", "a @", "a==1.0 \\\n b==2", "-r missing.txt", "a" * 5000],
        "pyproject.toml": ["", "[project", "project = 5", "[project]\ndependencies = 5", "[project]\ndependencies = [1, 2]",
                           "[project]\noptional-dependencies = 5", "[tool.poetry]\ndependencies = 5",
                           "[tool.poetry.group.dev]\ndependencies = []", "dependency-groups = 5", "[dependency-groups]\na = 5"],
        ".mcp.json": ["", "[]", '{"mcpServers": []}', '{"mcpServers": {"a": 5}}', '{"mcpServers": {"a": {"command": 5, "args": 5}}}',
                      '{"mcpServers": {"a": {"command": "npx", "args": {"x": 1}}}}', '{"mcpServers": {"a": {"command": "npx", "args": []}}}',
                      '{"servers": {"a": {"command": "uvx", "args": [null, 1, "-y"]}}}', '{"mcp": 5}', '{"mcp": {"servers": 5}}'],
        "database.rules.json": ["", "{", '{"rules": 5}', '{".read": true'],
        "firestore.rules": ["allow", "allow ;", "allow read, write: if", "match /{x=**} { allow read: if request.time < timestamp.date(" * 50],
        "supabase/migrations/a.sql": ["create table", "alter table enable row level security", "create policy on t;",
                                      "create policy \"p\" on public.t for update using (true)", "-- create table x (", "/* unterminated"],
        "Dockerfile": ["FROM", "FROM a AS", "ENV", "ENV A", "COPY", "USER", "\\\n\\\n"],
        "docker-compose.yml": ["POSTGRES_PASSWORD:", ":", "- POSTGRES_PASSWORD=postgres"],
        ".github/workflows/a.yml": ["run:", "- run: |\n  ${{ github.event.issue.title", "on: pull_request_target\nref: ${{"],
        ".env": ["=", "A=", "KEY_SECRET=" + "x" * 10000, "export", "\x00"],
    }
    rng = random.Random(7)
    for rnd in range(max(3, ROUNDS)):
        root = tmp_path / f"r{rnd}"
        for name, variants in cases.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(rng.choice(variants), encoding="utf-8")
        _scan(root)


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks and chmod need a POSIX file system")
def test_symlink_loops_unreadable_files_and_escapes(tmp_path):
    root = tmp_path / "proj"
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "loop").symlink_to(root / "a", target_is_directory=True)
    (root / "self").symlink_to(root, target_is_directory=True)
    (root / "dangling.py").symlink_to(root / "missing.py")
    secret_outside = tmp_path / "outside.py"
    secret_outside.write_text('KEY = "' + fake_values()["FAKE_OPENAI_KEY"] + '"\n')
    (root / "escape.py").symlink_to(secret_outside)
    locked = root / "locked.py"
    locked.write_text("eval(x)\n")
    locked.chmod(0)
    try:
        res = _scan(root)
    finally:
        locked.chmod(0o644)
    assert not [f for f in res.findings if f.file == "escape.py"], "followed a symlink out of the project"
