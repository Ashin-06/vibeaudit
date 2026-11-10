"""Data and database rules (DATA001-DATA010), including the false alarms found on real repositories."""
from vibeaudit.scanner import Options, scan


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _rules(tmp_path, prefix="DATA"):
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id.startswith(prefix))


def test_python_n_plus_one_but_not_retry_loops_or_fixed_lists(tmp_path):
    write(tmp_path, "a.py",
          "import time\n\ndef sync(orders):\n    for o in orders:\n        Order.objects.get(id=o.id)\n\n"
          "def wait_for_db(conn):\n    for _ in range(30):\n        try:\n            conn.execute('SELECT 1')\n            return\n"
          "        except Exception:\n            time.sleep(1)\n\n"
          "def setup(cursor):\n    for table in ('a', 'b'):\n        cursor.execute('ANALYZE ' + table)\n")
    assert _rules(tmp_path) == [("a.py", 5, "DATA001")]


def test_chunked_batches_are_not_n_plus_one(tmp_path):
    write(tmp_path, "a.py",
          "def drop(db, ids):\n    for i in range(0, len(ids), 500):\n        chunk = ids[i:i + 500]\n"
          "        db.execute('DELETE FROM t WHERE id IN (%s)' % ','.join('?' * len(chunk)), chunk)\n\n"
          "def each(db, ids):\n    for i in range(len(ids)):\n        db.execute('DELETE FROM t WHERE id = ?', (ids[i],))\n")
    assert _rules(tmp_path) == [("a.py", 8, "DATA001")]


def test_js_n_plus_one_in_loops_and_async_map(tmp_path):
    write(tmp_path, "a.ts",
          "export async function f(ids: string[]) {\n  for (const id of ids) {\n    await prisma.user.findUnique({ where: { id } });\n  }\n"
          "  await Promise.all(ids.map(async (id) => await db.query('select 1')));\n"
          "  const all = await prisma.user.findMany({ where: { id: { in: ids } } });\n  return all;\n}\n")
    assert _rules(tmp_path) == [("a.ts", 3, "DATA001"), ("a.ts", 5, "DATA001")]


def test_whole_user_record_but_not_a_selection(tmp_path):
    write(tmp_path, "a.ts",
          "export async function GET() {\n  const user = await prisma.user.findUnique({ where: { id } });\n  return Response.json(user);\n}\n"
          "export async function POST() {\n  const user = await prisma.user.findUnique({ where: { id }, select: { name: true } });\n  return Response.json(user);\n}\n"
          "export async function PUT() {\n  const post = await prisma.post.findUnique({ where: { id } });\n  return Response.json(post);\n}\n")
    assert _rules(tmp_path) == [("a.ts", 2, "DATA002")]


def test_naive_datetimes_only_where_they_matter(tmp_path):
    write(tmp_path, "a.py",
          "from datetime import datetime, timedelta, timezone\n"
          "print('started', datetime.now())\n"
          "token.expires_at = datetime.now() + timedelta(hours=1)\n"
          "created = Column(DateTime, default=datetime.now())\n"
          "ok = datetime.now(timezone.utc)\n"
          "legacy = datetime.utcnow()\n")
    assert _rules(tmp_path) == [("a.py", 3, "DATA006"), ("a.py", 4, "DATA006"), ("a.py", 6, "DATA006")]


def test_env_documentation_scope_flags_fallbacks_and_platform_names(tmp_path):
    write(tmp_path, "frontend/.env.example", "NEXT_PUBLIC_API_URL=http://localhost:3000\n")
    write(tmp_path, "frontend/app/a.ts",
          "const a = process.env.NEXT_PUBLIC_API_URL;\nconst b = process.env.STRIPE_SECRET_KEY;\nconst c = process.env.IS_DEMO;\n"
          "const d = process.env.NEXT_PUBLIC_VERCEL_URL;\nconst e = process.env.FEATURE_X || 'off';\nconst f = process.env.APP_ENV === 'dev';\n")
    write(tmp_path, ".env.example", "DATABASE_URL=postgres://user:password@localhost/db\n")
    write(tmp_path, "backend/app.py", "import os\nURL = os.environ['DATABASE_URL']\n")
    # edge function secrets live in Supabase, not in the root .env.example
    write(tmp_path, "supabase/functions/chat/index.ts", "const k = Deno.env.get('RESEND_API_KEY');\n")
    assert _rules(tmp_path) == [("frontend/app/a.ts", 2, "DATA007")]


def test_python_serverless_requires_explicit_config(tmp_path):
    write(tmp_path, "web/package.json", '{"dependencies": {"next": "14.0.0"}}')
    write(tmp_path, "api/app.py", "import sqlite3\nconn = sqlite3.connect('app.db')\n")
    assert _rules(tmp_path) == []
    write(tmp_path, "vercel.json", "{}")
    assert _rules(tmp_path) == [("api/app.py", 2, "DATA009")]


def test_prisma_singleton_is_fine(tmp_path):
    write(tmp_path, "lib/db.ts", "export function getPrisma() {\n  return globalThis.prisma ?? (globalThis.prisma = new PrismaClient());\n}\n")
    write(tmp_path, "app/api/x/route.ts", "export async function GET() {\n  const prisma = new PrismaClient();\n  return Response.json({});\n}\n")
    assert _rules(tmp_path) == [("app/api/x/route.ts", 2, "DATA008")]


def test_sql_rules(tmp_path):
    write(tmp_path, "db/migrations/001.sql",
          "create table orders (id int, total float, created_at timestamp, paid_at timestamptz);\n"
          "create policy p on public.orders for select using (true);\n"
          "create policy q on public.posts for select using (true);\n"
          "create policy r on public.orders for select to authenticated using (true);\n"
          "drop table legacy;\n")
    write(tmp_path, "db/seed.sql", "truncate table orders;\n")
    assert _rules(tmp_path) == [("db/migrations/001.sql", 1, "DATA004"), ("db/migrations/001.sql", 1, "DATA006"),
                                ("db/migrations/001.sql", 2, "DATA005"), ("db/migrations/001.sql", 5, "DATA003")]
