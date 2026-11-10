"""False positives found by labelling the benchmark corpus (benchmark/labels); each test failed before its fix."""
from vibeaudit.scanner import Options, scan


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def found(root, prefix=""):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low"))
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id.startswith(prefix))


def test_django_tests_module_and_library_examples_are_not_app_code(tmp_path):
    # djangoproject.com dashboard/tests.py, express examples/auth/index.js
    loop = "def setUp(self):\n    for i in range(3):\n        Release.objects.create(version=i)\n"
    write(tmp_path, "dashboard/tests.py", loop)
    write(tmp_path, "examples/auth/index.js", "app.use(session({ secret: 'keyboard cat' }));\n")
    write(tmp_path, "app/views.py", loop)
    assert [r for r in found(tmp_path) if r[2] in ("DATA001", "SEC004")] == [("app/views.py", 3, "DATA001")]
    # a tests.py file counts as having tests
    assert not [r for r in found(tmp_path, "QA001")]


def test_minified_with_short_lines_and_vendored_readable_bundle_are_generated(tmp_path):
    # Vulnerable-Flask-App loader.js (average line 480 chars), opengpts json-refs.js (prettified dist bundle)
    line = "function a" + "x" * 300 + "(){try{b()}catch(e){}}" + ";var q=1" * 60
    write(tmp_path, "static/loader.js", "\n".join([line, "x=1"] * 20))
    write(tmp_path, "src/utils/refs.js", "// Original source: https://github.com/o/r/blob/master/dist/refs-min.js\n"
          + "export const R = (function () {\n  try { r() } catch (e) {}\n})();\n" * 200)
    write(tmp_path, "src/app.js", "try { r() } catch (e) {}\n")
    assert found(tmp_path, "QA003") == [("src/app.js", 1, "QA003")]


def test_wildcard_cors_without_credentials_is_not_reported(tmp_path):
    # 34 of 35 BE012 findings: Access-Control-Allow-Origin '*' with no cookies involved
    write(tmp_path, "supabase/functions/chat/index.ts",
          "const corsHeaders = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization' };\n")
    write(tmp_path, "server.js", "app.use(cors());\napp.use(cors({ origin: '*' }));\n")
    write(tmp_path, "main.py", "from fastapi.middleware.cors import CORSMiddleware\n"
          "app.add_middleware(CORSMiddleware, allow_origins=['*'])\n"
          "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n")
    write(tmp_path, "api.js", "res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n"
          "res.setHeader('Access-Control-Allow-Credentials', 'true');\n")
    assert found(tmp_path, "BE012") == [("api.js", 1, "BE012"), ("main.py", 3, "BE012")]


def test_syntax_warnings_from_the_scanned_code_are_not_printed(tmp_path, recwarn):
    # openui backend/app/main.py: an invalid escape sequence made every scan print a SyntaxWarning
    write(tmp_path, "main.py", "import re\nPAT = re.compile('\\.html$')\n")
    found(tmp_path)
    assert not [w for w in recwarn if issubclass(w.category, SyntaxWarning)]


def test_one_off_scripts_and_parameterized_tagged_templates(tmp_path):
    # bakerydemo management command, sec-insights alembic migration, next-learn seed route (postgres.js sql``)
    loop = "for i in range(9):\n    Country.objects.create(title=i)\n"
    write(tmp_path, "base/management/commands/create_random_data.py", loop)
    write(tmp_path, "alembic/versions/1b0b_replace.py", "def upgrade():\n    op.execute(f'DROP TYPE public.\"{enum_name}Old\"')\n")
    write(tmp_path, "app/seed/route.ts", "const done = await Promise.all(\n  rows.map((r) => sql`INSERT INTO t (id) VALUES (${r.id})`),\n);\n"
          "const more = await Promise.all(users.map(async (u) => { return sql`DELETE FROM t WHERE id = ${u.id}`; }));\n")
    write(tmp_path, "app/views.py", loop + "def f(db, name):\n    db.execute(f'SELECT * FROM t WHERE n = {name}')\n")
    assert [r for r in found(tmp_path) if r[2] in ("DATA001", "BE001")] == [("app/views.py", 2, "DATA001"), ("app/views.py", 4, "BE001")]


def test_optional_environment_variables_are_not_undocumented_settings(tmp_path):
    # bakerydemo `if "X" in os.environ`, opengpts `if not x: x = default`, chat-langchain `process.env.X ? {...} : {}`
    write(tmp_path, ".env.example", "OPENAI_API_KEY=\n")
    write(tmp_path, "settings.py", "import os\nif 'CSP_FONT_SRC' in os.environ:\n    CSP = os.environ.get('CSP_FONT_SRC').split(',')\n"
          "name = os.environ.get('OLLAMA_MODEL')\nif not name:\n    name = 'llama2'\n"
          "redis = os.environ.get('REDIS_URL')\nif redis:\n    CACHES = redis\n"
          "PROMPT = \"use os.environ['EXAMPLE_KEY'] in your code\"\n"
          "dsn = f\"postgresql://{os.environ['POSTGRES_HOST']}/db\"\n")
    write(tmp_path, "route.ts", "const c = new Client({ ...(process.env.LANGSMITH_ENDPOINT ? { apiUrl: process.env.LANGSMITH_ENDPOINT } : {}) });\n"
          "const secret = process.env.GUEST_AUTH_SECRET\nif (!secret) {\n  return Response.json({}, { status: 503 })\n}\n")
    assert [(f, ln) for f, ln, _r in found(tmp_path, "DATA007")] == [("route.ts", 2), ("settings.py", 11)]


def test_same_site_redirects_are_not_open_redirects(tmp_path):
    write(tmp_path, "routes.py", "from flask import redirect, request, url_for\n@bp.route('/follow/<username>')\n"
          "def follow(username):\n    return redirect(url_for('main.user', username=request.args['u']))\n\n"
          "@bp.route('/go')\ndef go():\n    return redirect(request.args.get('next'))\n")
    write(tmp_path, "app/auth/callback/route.ts", "export async function GET(request) {\n  const requestUrl = new URL(request.url);\n"
          "  return NextResponse.redirect(getErrorRedirect(`${requestUrl.origin}/signin`, request.nextUrl.searchParams.get('e')));\n}\n")
    assert found(tmp_path, "BE008") == [("routes.py", 8, "BE008")]


def test_supabase_policies_for_service_role_and_rls_enabled_by_a_script(tmp_path):
    write(tmp_path, "supabase/migrations/1.sql", "create table public.notes (id int);\ncreate table public.logs (id int);\n"
          "create policy \"svc\" on public.notes for all to service_role using (true);\n"
          "create policy \"any\" on public.logs for insert with check (true);\n")
    write(tmp_path, "scripts/enable-rls.js", "await sql`ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY`; // supabase\n")
    assert [(ln, r) for _f, ln, r in found(tmp_path, "AUTH00")] == [(2, "AUTH005"), (4, "AUTH006")]


def test_dev_settings_strings_local_eval_and_system_random(tmp_path):
    write(tmp_path, "proj/settings/base.py", "SECRET_KEY = 'dev-insecure-x8f2k1m9q7w3e5r6t'\nDEBUG = True\nALLOWED_HOSTS = ['*']\n")
    write(tmp_path, "proj/settings/production.py", "import os, random\nfrom .base import *\nDEBUG = False\n"
          "SECRET_KEY = os.environ.get('K') or ''.join(random.SystemRandom().choice('abc') for _ in range(50))\n"
          "ALLOWED_HOSTS = os.environ['HOSTS'].split(',')\n")
    write(tmp_path, "proj/settings/dev.py", "ALLOWED_HOSTS = ['*']\n")
    write(tmp_path, "lib/response.js", "if (signed && !secret) { throw new Error('cookieParser(\"secret\") required for signed cookies'); }\n")
    write(tmp_path, "evals/run.py", "async def eval(model, data):\n    return 1\n\nasync def main(m, d):\n    await eval(m, d)\n")
    assert [r for r in found(tmp_path) if r[2] in ("SEC003", "SEC004", "BE011", "CFG006", "BE003", "BE015")] == []


def test_worker_messages_markup_comments_and_declared_imports(tmp_path):
    write(tmp_path, "lib/hooks/use-pipeline.ts", "worker.addEventListener('message', onMessageReceived);\n")
    write(tmp_path, "lib/workers/pipeline.ts", "self.addEventListener(\n  'message',\n  async (event) => { run(event.data) }\n);\n")
    write(tmp_path, "templates/home.html", "<!-- <img src=\"a.png\"> -->\n{% comment %}<p>Lorem ipsum dolor sit amet</p>{% endcomment %}\n<img src=\"b.png\">\n")
    write(tmp_path, "requirements/dev.txt", "django-money==3.6.2\ndjango-push @ git+https://github.com/o/django-push.git@22fd\n")
    write(tmp_path, "app/models.py", "import djmoney\nfrom django_push.subscriber.models import Subscription\nimport left_pad\n")
    rules = [r for r in found(tmp_path) if r[2] in ("FE004", "UI001", "UI010", "QA007")]
    assert rules == [("app/models.py", 3, "QA007"), ("templates/home.html", 3, "UI001")]


def test_cms_html_constants_and_converting_migrations(tmp_path):
    write(tmp_path, "templates/blog.html", "<h1>{{ object.headline|safe }}</h1>\n<div>{{ comment.body|safe }}</div>\n")
    write(tmp_path, "templates/registration/password_reset_email.html", "{% autoescape off %}Reset: {{ url }}{% endautoescape %}\n")
    write(tmp_path, "static/debugger.js", "el.innerHTML =\n  \"<p>To switch between views \" +\n  'click the \"Traceback\" headline.';\n")
    write(tmp_path, "migrations/000003_user.up.sql", "ALTER TABLE thread ALTER COLUMN user_id TYPE UUID USING user_id::UUID;\nDROP TABLE old_tags;\n")
    rules = [r for r in found(tmp_path) if r[2] in ("FE001", "DATA003")]
    assert rules == [("migrations/000003_user.up.sql", 2, "DATA003"), ("templates/blog.html", 2, "FE001")]


def test_backdrops_comments_above_pass_and_read_only_containers(tmp_path):
    write(tmp_path, "Modal.tsx", "export function M({ close }) {\n  return (<>\n"
          "    <div className=\"fixed inset-0 bg-black/50\" onClick={() => setOpen(false)} />\n"
          "    <div className=\"card\" onClick={() => select(1)}>x</div>\n  </>);\n}\n")
    write(tmp_path, "config.py", "def load(v):\n    try:\n        return loads(v)\n    except Exception:\n"
          "        # keep the value as a string\n        pass\n")
    write(tmp_path, "urls.py", "class Hosts(dict):\n    def __setitem__(self, key, value):\n        raise NotImplementedError\n")
    rules = [r for r in found(tmp_path) if r[2] in ("UI002", "QA003", "QA005")]
    assert rules == [("Modal.tsx", 4, "UI002")]


def test_ownership_admin_and_token_routes(tmp_path):
    write(tmp_path, "routes.ts", "router.put('/articles/:slug', auth.required, async (req, res) => {\n"
          "  const a = await updateArticle(req.body.article, req.params.slug, req.auth?.user?.id);\n  res.json(a);\n});\n")
    write(tmp_path, "login.py", "from fastapi import APIRouter, Depends\nrouter = APIRouter()\n\n"
          "@router.post('/login/test-token')\ndef test_token(current_user: CurrentUser):\n    return current_user\n\n"
          "@router.post('/reset-password/')\ndef reset_password(body: NewPassword):\n"
          "    email = verify_password_reset_token(token=body.token)\n    user.hashed = hash(body.new_password)\n    session.add(user)\n\n"
          "@router.post('/login/access-token')\ndef login(form_data: Form):\n    user = authenticate(form_data.username, form_data.password)\n"
          "    session.add(user)\n    return user\n")
    rules = [r for r in found(tmp_path) if r[2] in ("AUTH003", "AUTH010")]
    assert rules == [("login.py", 15, "AUTH010")]


def test_imported_auth_helper_constant_time_webhook_and_deno_zod(tmp_path):
    write(tmp_path, "supabase/functions/voices/index.ts",
          "import { getAuthedUser } from '../_shared/auth.ts';\nDeno.serve(async (req) => {\n"
          "  const user = await getAuthedUser(req);\n  if (!user) return new Response('no', { status: 401 });\n"
          "  const body = await req.json();\n  await supabase.from('voices').insert(body);\n  return new Response('ok');\n});\n")
    write(tmp_path, "supabase/functions/payment-webhook/index.ts",
          "Deno.serve(async (req) => {\n  const sig = req.headers.get('x-webhook-signature');\n"
          "  if (!constantTimeEqual(sig, Deno.env.get('WEBHOOK_SECRET'))) return new Response('no', { status: 401 });\n"
          "  await supabase.from('payments').insert(await req.json());\n  return new Response('ok');\n});\n")
    write(tmp_path, "supabase/functions/chat/index.ts", "import { z } from 'npm:zod@4';\n")
    assert [r for r in found(tmp_path) if r[2] in ("AUTH001", "AUTH004", "BE018")] == []


def test_webauthn_ids_public_client_keys_and_seed_passwords(tmp_path):
    write(tmp_path, "src/lib/webauthn.ts", "'use client'\nwindow.localStorage.setItem('credentialID', credential.id)\n"
          "window.localStorage.setItem('access_token', token)\n")
    write(tmp_path, ".env", "COPILOT_KEY=ck_pub_8f2k1m9q7w3e5r6t2y4u8i0o\nSTRIPE_SECRET=sk9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4\n")
    write(tmp_path, "app/lib/placeholder-data.ts", "const users = [{ email: 'user@nextmail.com', password: 'q7w3e5r6t2' }];\n")
    rules = [r for r in found(tmp_path) if r[2] in ("FE005", "SEC003", "SEC011")]
    assert rules == [(".env", 2, "SEC003"), ("src/lib/webauthn.ts", 3, "FE005")]


def test_new_heuristics_stay_linear_on_hostile_input(tmp_path):
    # found by the Phase 0 audit: these took minutes before the fix
    import time

    from vibeaudit.datascan import DataScanner
    from vibeaudit.jsscan import is_static_string

    start = time.time()
    assert not is_static_string("'a'   " * 40 + "x")
    code = "q" * 200000 + " = process.env.X\n"
    assert not DataScanner._optional_env(code, code.index("process"), "X", set())
    write(tmp_path, ".env.example", "A=\n")
    write(tmp_path, "p.py", "import os\nP = '''" + "os.environ['K'] " * 20000 + "'''\n")
    found(tmp_path, "DATA007")
    assert time.time() - start < 20


def test_agent_tools_and_api_versions_are_not_one_off_scripts(tmp_path):
    loop = "for u in users:\n    Order.objects.filter(user=u).first()\n"
    write(tmp_path, "src/tools/search.py", loop)
    write(tmp_path, "api/versions/v1/views.py", loop)
    assert [r[0] for r in found(tmp_path, "DATA001")] == ["api/versions/v1/views.py", "src/tools/search.py"]


def test_backdrop_pattern_is_linear_on_long_class_lists():
    import time

    from vibeaudit.uiscan import BACKDROP

    start = time.time()
    assert not BACKDROP.search("fixed " * 20000)
    assert time.time() - start < 1.5
