"""One test per bug fixed in the 0.2.0 hardening pass. Each fails if its fix is reverted."""
import shutil
import subprocess
import sys
import time

import pytest

from helpers import fake_values
from vibeaudit import deps
from vibeaudit.files import Project
from vibeaudit.lexer import py_views
from vibeaudit.model import Finding
from vibeaudit.report import Result, render_html
from vibeaudit.scanner import Options, scan


def _scan(path, **kw):
    kw.setdefault("offline", True)
    kw.setdefault("external", "none")
    return scan(str(path), Options(**kw))


def _rules(res, rule=None):
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if rule is None or f.rule_id == rule)


# ------------------------------------------------------------- robustness
def test_html_report_is_ascii_whatever_the_code_contains():
    snippet = "el.innerHTML = '" + chr(0x4E2D) + chr(0x6587) + " " + chr(0xE9) + "'"
    f = Finding("FE001", "a.js", 1, "m", "high", snippet, title="t", category="frontend")
    f.compute_fingerprint()
    out = render_html(Result("/p", [f], {}))
    out.encode("ascii")
    assert "&#20013;" in out


def test_python_lexer_is_linear_on_a_huge_single_line():
    src = "x = 1; " * 100000  # 700 KB on one line; the tokenize-based lexer took minutes on Python 3.12
    start = time.perf_counter()
    v = py_views(src + "# c\ns = 'a # not a comment'\n")
    assert time.perf_counter() - start < 3
    assert v.comments and "not a comment" in v.code and "not a comment" not in v.bare


def test_utf16_source_files_are_decoded(tmp_path):
    (tmp_path / "a.py").write_bytes("import os\nos.system('ls ' + x)\n".encode("utf-16"))
    assert [r for _, _, r in _rules(_scan(tmp_path))] == ["BE002"]


def test_one_crashing_check_does_not_lose_the_rest(tmp_path, monkeypatch):
    from vibeaudit.jsscan import JsScanner

    (tmp_path / "a.py").write_text("eval(x)\n")
    (tmp_path / "b.js").write_text("eval(y);\n")

    def boom(self, fs):
        raise ValueError("simulated bug")

    monkeypatch.setattr(JsScanner, "check_sinks", boom)
    res = _scan(tmp_path)
    assert ("a.py", 1, "BE003") in _rules(res)  # the Python side still ran
    assert len(res.meta["internal_errors"]) == 1 and "simulated bug" in res.meta["internal_errors"][0]
    assert any("internal errors" in n for n in res.meta["notes"])


def test_per_file_time_budget_stops_a_slow_file_and_carries_on(tmp_path):
    (tmp_path / "big.js").write_text("const a = req.body.x;\n" * 40000)  # under the 1 MB size limit
    (tmp_path / "small.py").write_text("eval(x)\n")
    start = time.perf_counter()
    res = _scan(tmp_path, file_timeout=0.05)
    assert time.perf_counter() - start < 60
    assert any("big.js" in s and "longer than" in s for s in res.meta["skipped"])
    assert ("small.py", 1, "BE003") in _rules(res)


def test_pyproject_before_package_json_does_not_break_dependency_checks(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = 5\n')
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "package.json").write_text('{"dependencies": {"left-pad": "^1.3.0"}}')
    (tmp_path / "b" / "package-lock.json").write_text('{"packages": {"node_modules/left-pad": {"version": "1.3.0"}}}')
    found = deps.collect(Project(tmp_path))
    assert [(d.name, d.version) for d in found] == [("left-pad", "1.3.0")]
    assert _scan(tmp_path).meta["internal_errors"] == []


def test_mcp_config_with_odd_types_is_ignored(tmp_path):
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"a": {"command": "npx", "args": 5}}, "mcp": 3}')
    res = _scan(tmp_path)
    assert res.meta["internal_errors"] == [] and res.findings == []


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need a POSIX file system")
def test_symlink_out_of_the_project_is_not_followed(tmp_path):
    outside = tmp_path / "home_secret.py"
    outside.write_text('KEY = "' + fake_values()["FAKE_OPENAI_KEY"] + '"\n')
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "link.py").symlink_to(outside)
    (proj / "inside.py").write_text("eval(x)\n")
    (proj / "alias.py").symlink_to(proj / "inside.py")
    assert {f.file for f in _scan(proj).findings} == {"inside.py", "alias.py"}


def test_nested_gitignore_is_honoured_outside_git(tmp_path):
    svc = tmp_path / "services" / "api"
    svc.mkdir(parents=True)
    (svc / ".gitignore").write_text(".env\n")
    (svc / ".env").write_text("OPENAI_API_KEY=" + fake_values()["FAKE_OPENAI_KEY"] + "\n")
    (tmp_path / "services" / "web").mkdir()
    (tmp_path / "services" / "web" / ".env").write_text("TOKEN=x\n")
    assert _rules(_scan(tmp_path)) == [("services/web/.env", 0, "SEC007")]


# ---------------------------------------------------------- rule accuracy
def test_argument_lists_only_matter_when_the_program_is_controlled(tmp_path):
    (tmp_path / "app.py").write_text(
        "import subprocess\nfrom flask import request\n\n@app.get('/a')\ndef a():\n"
        "    subprocess.run(['echo', request.args['m']], check=True)\n"
        "    subprocess.run([request.args['prog'], '-v'], check=True)\n")
    (tmp_path / "s.js").write_text(
        "const { execFile } = require('child_process');\nconst express = require('express');\nconst app = express();\n"
        "app.get('/p', (req, res) => {\n  execFile('ping', ['-c', '1', req.query.host]);\n  execFile(req.query.bin, []);\n});\n")
    assert [(f, ln) for f, ln, r in _rules(_scan(tmp_path), "BE002")] == [("app.py", 7), ("s.js", 6)]


def test_id_path_parameter_is_not_ownership_evidence(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask_login import login_required\n\n@app.route('/api/users/<user_id>', methods=['DELETE'])\n@login_required\n"
        "def delete_user(user_id):\n    db.execute('DELETE FROM users WHERE id = ?', (user_id,))\n    return ''\n")
    assert [r for _, _, r in _rules(_scan(tmp_path), "AUTH003")] == ["AUTH003"]


def test_aws_key_id_alone_is_medium_and_with_its_secret_is_critical(tmp_path):
    key_id = "AKIA" + "QX7Z2LMN4PR6TV8W"
    (tmp_path / "a.py").write_text(f"sample = {{'credential': '{key_id}/20220405/s3'}}\n")
    assert [f.severity for f in _scan(tmp_path).findings] == ["medium"]
    (tmp_path / "a.py").write_text(f"ID = '{key_id}'\naws_secret_access_key = '{'Zq8wX2vR7nP4tL9k' * 2 + 'Ab12Cd34'}'\n")
    assert [f.severity for f in _scan(tmp_path).findings if f.line == 1] == ["critical"]


def test_password_defaults_and_enum_values_are_not_hardcoded_passwords(tmp_path):
    (tmp_path / "settings.py").write_text('DATABASES = {"default": {"PASSWORD": "postgres"}}\nuser_create(password="user")\n')
    (tmp_path / "tokens.js").write_text("const tokenTypes = { RESET_PASSWORD: 'resetPassword' };\n")
    (tmp_path / "real.py").write_text('ADMIN_PASSWORD = "hunter2-admin"\n')
    assert _rules(_scan(tmp_path), "SEC011") == [("real.py", 1, "SEC011")]


def test_comparing_two_submitted_passwords_is_not_plaintext_storage(tmp_path):
    (tmp_path / "a.py").write_text(
        "def change(body, user, password):\n    if body.current_password == body.new_password:\n        return 1\n"
        "    if user.password == password:\n        return 2\n")
    assert [ln for _, ln, _ in _rules(_scan(tmp_path), "BE014")] == [4]


def test_html_response_of_rendered_template_output(tmp_path):
    (tmp_path / "a.py").write_text(
        "from fastapi.responses import HTMLResponse\n\n@router.post('/preview/{email}')\ndef preview(email: str):\n"
        "    data = render_email(email=email)\n    return HTMLResponse(content=data.html)\n\n"
        "@router.post('/echo/{name}')\ndef echo(name: str):\n    return HTMLResponse(content=f'<h1>{name}</h1>')\n")
    assert [ln for _, ln, _ in _rules(_scan(tmp_path), "FE001")] == [10]


def test_fastapi_auth_through_an_annotated_dependency_alias(tmp_path):
    (tmp_path / "auth.py").write_text("from typing import Annotated\nfrom fastapi import Depends\n\n"
                                      "AuthedUser = Annotated[User, Depends(auth_user)]\n")
    (tmp_path / "api.py").write_text("@router.delete('/{aid}')\nasync def remove(user: AuthedUser, aid: str):\n    await storage.delete(aid)\n\n"
                                     "@router.delete('/open/{aid}')\nasync def remove_open(aid: str):\n    await storage.delete(aid)\n")
    assert _rules(_scan(tmp_path), "AUTH001") == [("api.py", 6, "AUTH001")]


def test_browser_client_pointed_at_own_backend(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"vite": "5.0.0"}}')
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.ts").write_text(
        "const local = new OpenAI({ apiKey: 'sk-fake', baseURL: `${host()}/v1`, dangerouslyAllowBrowser: true });\n"
        "const direct = new OpenAI({ apiKey: key, baseURL: 'https://api.openai.com/v1', dangerouslyAllowBrowser: true });\n")
    assert [ln for _, ln, _ in _rules(_scan(tmp_path), "FE002")] == [2]


def test_spreading_request_data_into_a_model_call_is_not_mass_assignment(tmp_path):
    (tmp_path / "a.py").write_text("@app.post('/chat')\nasync def chat(request: Request):\n    data = await request.json()\n"
                                   "    await client.chat.completions.create(**data)\n    User(**data)\n")
    assert [ln for _, ln, _ in _rules(_scan(tmp_path), "BE009")] == [5]


def test_allow_list_membership_sanitises(tmp_path):
    (tmp_path / "a.py").write_text(
        "@app.get('/f/{p}')\ndef f(p: str):\n    if p in FILES:\n        return FileResponse(DIST / p)\n    return FileResponse(DIST / p)\n\n"
        "@app.get('/g/{p}')\ndef g(p: str):\n    if p not in FILES:\n        raise HTTPException(404)\n    return FileResponse(DIST / p)\n")
    assert [ln for _, ln, _ in _rules(_scan(tmp_path), "BE006")] == [5]


def test_dotted_scope_names_are_not_secrets(tmp_path):
    (tmp_path / "theme.ts").write_text("const t = { token: 'support.constant.color.w3c-standard-color-name.css' };\n"
                                       "const k = { token: 'q8Zr2LmX9vB4tN7pK3sD' };\n")
    assert [ln for _, ln, _ in _rules(_scan(tmp_path), "SEC003")] == [2]


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_committed_env_template_with_placeholders_is_fine(tmp_path):
    def git(*a):
        subprocess.run(["git", *a], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    (tmp_path / ".env").write_text("SECRET_KEY=changethis\nPOSTGRES_PASSWORD=\nOPENAI_API_KEY=your-key-here\nDEBUG=true\n")
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / ".env").write_text("OPENAI_API_KEY=" + fake_values()["FAKE_OPENAI_KEY"] + "\n")
    git("add", "-f", ".env", "backend/.env")
    assert [f for f, _, r in _rules(_scan(tmp_path)) if r == "SEC006"] == ["backend/.env"]


def test_supabase_edge_function_behind_the_jwt_gateway(tmp_path):
    fn = tmp_path / "supabase" / "functions"
    for name in ("chat", "open"):
        (fn / name).mkdir(parents=True)
        (fn / name / "index.ts").write_text(
            "serve(async (req) => {\n  const authorization = req.headers.get('Authorization');\n"
            "  if (!authorization) return new Response('missing', { status: 400 });\n"
            "  const r = await fetch('https://api.openai.com/v1/chat/completions', { body: '{\"max_tokens\": 5}' });\n"
            "  return r;\n});\n")
    (tmp_path / "supabase" / "config.toml").write_text("[functions.open]\nverify_jwt = false\n")
    assert [f for f, _, r in _rules(_scan(tmp_path)) if r == "AUTH001"] == ["supabase/functions/open/index.ts"]


# ------------------------------------------- 0.2.1: issues from the external code audit
def test_jsx_self_closing_tag_after_an_expression_is_not_a_regex(tmp_path):
    (tmp_path / "page.tsx").write_text("const a = <C p={1} /> <D q={eval(x)} />;\n")
    assert [r for _, _, r in _rules(_scan(tmp_path))] == ["BE003"]


def test_lambda_bodies_are_analysed(tmp_path):
    (tmp_path / "a.py").write_text(
        "import subprocess\nfrom flask import request\nfrom langchain.tools import Tool\n\n@app.get('/a')\ndef a():\n"
        "    f = lambda: eval(request.args['x'])\n    return f()\n\n"
        "shell = Tool(name='bash', func=lambda cmd: subprocess.run(cmd, shell=True), description='d')\n")
    assert [(ln, r) for _, ln, r in _rules(_scan(tmp_path))] == [(7, "BE003"), (10, "LLM005")]


def test_env_folders_are_source_unless_they_are_virtualenvs(tmp_path):
    (tmp_path / "src" / "env").mkdir(parents=True)
    (tmp_path / "src" / "env" / "server.ts").write_text("eval(code);\n")
    (tmp_path / "env" / "lib").mkdir(parents=True)
    (tmp_path / "env" / "pyvenv.cfg").write_text("home = /usr/bin\n")
    (tmp_path / "env" / "lib" / "site.py").write_text("eval(x)\n")
    assert [f for f, _, _ in _rules(_scan(tmp_path))] == ["src/env/server.ts"]


def test_llm_redaction_covers_signing_secrets_and_passwords():
    from vibeaudit.llm import redact

    out = redact('app.secret_key = "dev-secret-change-me"\nADMIN_PASSWORD = "hunter2-admin"\n'
                 'jwt.sign(payload, "s3cr3t-signing-value")\nconfig = {"api_secret": "q8Zr2LmX9vB4tN7pK3sD"}\n')
    for value in ("dev-secret-change-me", "hunter2-admin", "s3cr3t-signing-value", "q8Zr2LmX9vB4tN7pK3sD"):
        assert value not in out


def test_extra_index_url_keeps_dependency_checks(tmp_path):
    (tmp_path / "requirements.txt").write_text("--extra-index-url https://download.pytorch.org/whl/cu121\nreqeusts==1.0\n")
    # the extra index itself is DEP008 (the 2022 torchtriton attack came through exactly this index)
    assert sorted(r for _, _, r in _rules(_scan(tmp_path))) == ["DEP002", "DEP008"]
    (tmp_path / "requirements.txt").write_text("--index-url https://pypi.internal.example/simple\nreqeusts==1.0\n")
    assert _scan(tmp_path).findings == []


def test_the_word_places_does_not_hide_a_gemini_key(tmp_path):
    (tmp_path / "ai.py").write_text("# replaces the old client\nGEMINI_KEY = '" + fake_values()["FAKE_GOOGLE_KEY"] + "'\n")
    assert [(r, f.severity) for f in _scan(tmp_path).findings for r in [f.rule_id]] == [("SEC001", "critical")]


def test_aws_secret_ending_in_base64_padding(tmp_path):
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzz9QnP4m+="
    (tmp_path / "aws.py").write_text(f"aws_secret_access_key = '{secret}'\n")
    assert [(f.rule_id, f.severity) for f in _scan(tmp_path).findings] == [("SEC001", "critical")]


def test_a_comment_mentioning_rate_limits_is_not_rate_limiting(tmp_path):
    (tmp_path / "app.py").write_text("# TODO: add rate limit\n@app.post('/chat')\ndef chat():\n"
                                     "    return client.chat.completions.create(model='m', max_tokens=5, messages=[])\n")
    assert ("app.py", 3, "LLM004") in _rules(_scan(tmp_path))


def test_disable_accepts_ai001_and_external_ids_and_ignore_is_case_insensitive(tmp_path):
    from vibeaudit.cli import main

    (tmp_path / "a.py").write_text("eval(x)  # vibeaudit: ignore[be003]\n")
    assert _scan(tmp_path).findings == []
    assert main(["scan", str(tmp_path), "--offline", "--external", "none", "-q", "--disable", "AI001,bandit:B608"]) == 0


def test_identical_lines_get_distinct_fingerprints(tmp_path):
    (tmp_path / "a.py").write_text("def verify_token(t):\n    return True\n\n\ndef verify_token(t):\n    return True\n")
    fps = [f.fingerprint for f in _scan(tmp_path).findings if f.rule_id == "AUTH008"]
    assert len(fps) == 2 and len(set(fps)) == 2


def test_js_taint_is_scoped_to_the_function(tmp_path):
    (tmp_path / "server.js").write_text(
        "const express = require('express');\nconst app = express();\n"
        "function a(req, res) {\n  const data = req.query.q;\n  res.send(`<p>${data}</p>`);\n}\n"
        "function b(req, res) {\n  const data = 'static';\n  res.send(`<p>${data}</p>`);\n}\n")
    assert [(ln, r) for _, ln, r in _rules(_scan(tmp_path)) if r == "FE001"] == [(5, "FE001")]


def test_server_action_parameters_are_request_data(tmp_path):
    (tmp_path / "actions.ts").write_text(
        '"use server";\nexport async function search(term: string) {\n'
        "  return db.$queryRawUnsafe(`SELECT * FROM t WHERE name = '${term}'`);\n}\n"
        "async function helper(x: string) {\n  return db.$queryRawUnsafe(`SELECT * FROM t WHERE name = '${x}'`);\n}\n")
    assert [(f.line, f.severity) for f in _scan(tmp_path).findings if f.rule_id == "BE001"] == [(3, "high"), (6, "medium")]


@pytest.mark.parametrize("lock,manifest,text,name,version", [
    ("poetry.lock", ("pyproject.toml", '[tool.poetry.dependencies]\npython = "^3.11"\njinja2 = "^2.4"\n'),
     '[[package]]\nname = "Jinja2"\nversion = "2.4.1"\n', "jinja2", "2.4.1"),
    ("uv.lock", ("pyproject.toml", '[project]\nname = "x"\ndependencies = ["requests>=2"]\n'),
     'version = 1\n[[package]]\nname = "requests"\nversion = "2.19.0"\n', "requests", "2.19.0"),
    ("Pipfile.lock", ("requirements.txt", "flask\n"), '{"default": {"flask": {"version": "==0.12"}}}', "flask", "0.12"),
    ("pnpm-lock.yaml", ("package.json", '{"dependencies": {"@scope/x": "^1.0.0"}}'),
     "importers:\n  .:\n    dependencies:\n      '@scope/x':\n        specifier: ^1.0.0\n        version: 1.2.3\n", "@scope/x", "1.2.3"),
    ("yarn.lock", ("package.json", '{"dependencies": {"minimist": "^1.2.0"}}'),
     '"minimist@^1.2.0":\n  version "1.2.0"\n', "minimist", "1.2.0"),
    ("bun.lock", ("package.json", '{"dependencies": {"axios": "^0.21.0"}}'),
     '{\n  "packages": {\n    "axios": ["axios@0.21.0", "", {}],\n  }\n}', "axios", "0.21.0"),
])
def test_versions_come_from_every_supported_lockfile(tmp_path, lock, manifest, text, name, version):
    (tmp_path / manifest[0]).write_text(manifest[1])
    (tmp_path / lock).write_text(text)
    assert [(d.name, d.version) for d in deps.collect(Project(tmp_path))] == [(name, version)]


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_committed_virtualenv_is_skipped_in_git_mode(tmp_path):
    def git(*a):
        subprocess.run(["git", *a], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    (tmp_path / "env" / "lib").mkdir(parents=True)
    (tmp_path / "env" / "pyvenv.cfg").write_text("home = /usr/bin\n")
    (tmp_path / "env" / "lib" / "site.py").write_text("eval(x)\n")
    (tmp_path / "src" / "env").mkdir(parents=True)
    (tmp_path / "src" / "env" / "client.ts").write_text("eval(code);\n")
    git("add", ".")
    res = _scan(tmp_path)
    assert res.meta["git"] and [f for f, _, _ in _rules(res)] == ["src/env/client.ts"]
