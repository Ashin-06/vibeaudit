"""Access-control rules added in 0.8.7 (AUTH015-AUTH017, FE008)."""
import time

from vibeaudit.rules import RULES
from vibeaudit.scanner import Options, scan

NEW = ("AUTH015", "AUTH016", "AUTH017", "FE008")


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def found(root, *rules):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low"))
    assert res.meta.get("internal_errors", []) == []
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id in (rules or NEW))


def test_new_rules_start_as_preview():
    assert all(RULES[r].preview and RULES[r].preview_reason for r in NEW)


EXPRESS = """const express = require('express');
const bcrypt = require('bcrypt');
const app = express();
app.use(express.json());

app.post('/api/reset-password', requireAuth, async (req, res) => {
  const user = await User.findById(req.user.id);
  user.passwordHash = await bcrypt.hash(req.body.password, 12);
  await user.save();
  res.json({ ok: true });
});

app.post('/api/admin/flags', requireAuth, async (req, res) => {
  await Flag.updateOne({ name: req.body.name }, { enabled: req.body.enabled });
  res.json({ ok: true });
});

app.post('/api/admin/maintenance', requireAuth, requireRole('admin'), async (req, res) => {
  await Setting.updateOne({ key: 'maintenance' }, { value: req.body.on });
  res.json({ ok: true });
});

app.get('/api/projects', requireAuth, async (req, res) => {
  res.json(await prisma.project.findMany());
});

app.get('/api/projects/mine', requireAuth, async (req, res) => {
  res.json(await prisma.project.findMany({ where: { orgId: req.user.orgId } }));
});

app.listen(3000);
"""

PRISMA = """model Project {
  id    String @id
  name  String
  orgId String
}

model Flag {
  name    String @id
  enabled Boolean
}
"""


def test_express_routes(tmp_path):
    write(tmp_path, "server.js", EXPRESS)
    write(tmp_path, "prisma/schema.prisma", PRISMA)
    write(tmp_path, "package.json", '{"dependencies": {"express": "4.0.0", "bcrypt": "5.0.0", "@prisma/client": "5.0.0"}}')
    assert found(tmp_path) == [("server.js", 6, "AUTH015"), ("server.js", 13, "AUTH017"), ("server.js", 23, "AUTH016")]


def test_revocation_and_self_revoking_frameworks(tmp_path):
    write(tmp_path, "server.js", EXPRESS.replace("  await user.save();\n", "  await user.save();\n  await Session.deleteMany({ userId: user.id });\n"))
    write(tmp_path, "package.json", '{"dependencies": {"express": "4.0.0", "bcrypt": "5.0.0"}}')
    assert found(tmp_path, "AUTH015") == []
    write(tmp_path, "server.js", EXPRESS.replace("const app = express();", "const app = express();\nconst admin = require('firebase-admin');"))
    assert found(tmp_path, "AUTH015") == []


def test_supabase_tables_under_row_level_security(tmp_path):
    write(tmp_path, "supabase/migrations/1_init.sql",
          "create table projects (id uuid primary key, org_id uuid not null);\nalter table projects enable row level security;\n")
    write(tmp_path, "app/api/projects/route.ts",
          "import { createClient } from '@/lib/supabase';\nimport { auth } from '@/auth';\n"
          "export async function GET() {\n  const session = await auth();\n  if (!session) return new Response(null, { status: 401 });\n"
          "  const { data } = await createClient().from('projects').select('*');\n  return Response.json(data);\n}\n")
    write(tmp_path, "package.json", '{"dependencies": {"next": "15.0.0", "@supabase/supabase-js": "2.0.0"}}')
    assert found(tmp_path, "AUTH016") == []


def test_server_actions_leaking_secrets(tmp_path):
    write(tmp_path, "app/actions.ts",
          "'use server';\n\nexport async function getConfig() {\n  return { key: process.env.STRIPE_SECRET_KEY };\n}\n"   # 4
          "export async function getPublic() {\n  return { url: process.env.NEXT_PUBLIC_SITE_URL };\n}\n")
    write(tmp_path, "app/page.tsx",
          "export default function Page() {\n  const apiKey = process.env.OPENAI_API_KEY;\n"
          "  async function ask(formData: FormData) {\n    'use server';\n    await callModel(apiKey, formData.get('q'));\n  }\n"  # 3
          "  async function ok(formData: FormData) {\n    'use server';\n    await callModel(process.env.OPENAI_API_KEY, formData.get('q'));\n  }\n"
          "  return <form action={ask} />;\n}\n")
    write(tmp_path, "package.json", '{"dependencies": {"next": "15.0.0"}}')
    assert found(tmp_path, "FE008") == [("app/actions.ts", 4, "FE008"), ("app/page.tsx", 3, "FE008")]


def test_access_checks_are_linear_on_hostile_input(tmp_path):
    write(tmp_path, "schema.sql", "create table t (\n" + "  org_id int,\n" * 20000 + ");\n" + "create table x (" * 3000)
    write(tmp_path, "models.py", "class A(Model):\n" + "    org_id = 1\n" * 20000)
    write(tmp_path, "app/a.ts", "'use server';\n" + "async function f() { 'use server'; return k; }\n" * 5000 + "const k = process.env.A_KEY;\n" * 5000)
    start = time.time()
    found(tmp_path)
    assert time.time() - start < 30


def test_password_reset_with_a_hashed_field_and_unrelated_invalidation(tmp_path):
    write(tmp_path, "app/api/routes/login.py",
          "from fastapi import APIRouter\nfrom app.core.security import get_password_hash\nrouter = APIRouter()\n\n"
          "@router.post('/reset-password/')\ndef reset_password(session: SessionDep, body: NewPassword, current_user: CurrentUser):\n"   # 5
          "    user = session.get(User, current_user.id)\n    hashed_password = get_password_hash(body.new_password)\n"
          "    user.hashed_password = hashed_password\n    session.add(user)\n    session.commit()\n    return {'ok': True}\n")
    write(tmp_path, "web/src/hooks.ts", "export const done = () => queryClient.invalidateQueries({ queryKey: ['me'] });\n")
    write(tmp_path, "requirements.txt", "fastapi\n")
    assert found(tmp_path, "AUTH015") == [("app/api/routes/login.py", 6, "AUTH015")]


def test_orm_session_deletes_are_not_revocation(tmp_path):
    write(tmp_path, "app/api/routes/login.py",
          "from fastapi import APIRouter\nrouter = APIRouter()\n\n"
          "@router.post('/reset-password/')\ndef reset_password(session: SessionDep, body: NewPassword, current_user: CurrentUser):\n"
          "    current_user.hashed_password = get_password_hash(body.new_password)\n    session.commit()\n\n"
          "@router.delete('/items/{id}')\ndef delete_item(session: SessionDep, id: int, current_user: CurrentUser):\n"
          "    session.delete(session.get(Item, id))\n    session.commit()\n")
    write(tmp_path, "requirements.txt", "fastapi\n")
    assert found(tmp_path, "AUTH015") == [("app/api/routes/login.py", 5, "AUTH015")]
