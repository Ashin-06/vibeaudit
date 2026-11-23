"""Causes behind the AUTH005, DATA006, SEC001 and SEC004 demotions (seen on held-out repositories, so these
rules stay in preview until a fresh held-out batch measures them); each test failed before its fix."""
from vibeaudit.scanner import Options, scan


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def found(root, rule):
    res = scan(str(root), Options(offline=True, external="none"))
    return sorted((f.file, f.line) for f in res.findings if f.rule_id == rule)


KEY = "ghp_" + "R2kkVxN31PiqsJYXFmTIBmOu5a9gM0042muH"  # split so push protection does not read it as a token


def test_auth005_needs_a_supabase_client_not_the_word(tmp_path):
    write(tmp_path, "src/vendors.rs", 'const NAME: &str = "Supabase secret key";\n')
    write(tmp_path, "migrations/001.sql", "create table history (id bigserial primary key);\n")
    assert found(tmp_path, "AUTH005") == []
    write(tmp_path, "web/db.ts", "import { createClient } from '@supabase/supabase-js';\n")
    assert found(tmp_path, "AUTH005") == [("migrations/001.sql", 1)]


def test_data006_sql_columns_only_for_postgres(tmp_path):
    table = "create table history (\n  id integer,\n  created_at timestamp not null\n);\n"
    write(tmp_path, "db/mysql/migrations/1.sql", table)
    write(tmp_path, "db/sqlite/migrations/1.sql", table)
    write(tmp_path, "src/main/resources/schema.sql", table.replace("integer", "integer auto_increment"))
    write(tmp_path, "db/postgres/migrations/1.sql", table)
    write(tmp_path, "other/1.sql", table)
    assert found(tmp_path, "DATA006") == [("db/postgres/migrations/1.sql", 3)]
    write(tmp_path, "requirements.txt", "psycopg[binary]==3.2\n")
    assert found(tmp_path, "DATA006") == [("db/postgres/migrations/1.sql", 3), ("other/1.sql", 3)]


def test_sec001_skips_test_vectors_of_a_redactor(tmp_path):
    write(tmp_path, "src/secrets.rs",
          "pub fn redact(s: &str) -> String { s.into() }\n"
          "static P: &[Case] = &[Case {\n    #[cfg(test)]\n    input: \"" + KEY + "\",\n}];\n"
          "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() { redact(\"" + KEY + "\"); }\n}\n")
    write(tmp_path, "src/client.rs", "const TOKEN: &str = \"" + KEY + "\";\n")
    write(tmp_path, "src/other.rs", "#[cfg(test)]\nmod tests {\n    const T: &str = \"" + KEY + "\";\n}\n")
    # a key in an app file, or in the tests of code that is not a redactor, is still reported
    assert found(tmp_path, "SEC001") == [("src/client.rs", 1), ("src/other.rs", 3)]


def test_sec004_session_helpers_and_template_placeholders(tmp_path):
    write(tmp_path, "src/worker.rs", "fn t() { tx.send(Request::Preview(session(\"s0\"))); }\n")
    write(tmp_path, "{{cookiecutter.project_slug}}/app/security.py", 'SECRET_KEY = "{{cookiecutter.secret_key}}"\n')
    write(tmp_path, "app.js", "app.use(session({ secret: 'keyboard cat' }));\n")
    assert found(tmp_path, "SEC004") == [("app.js", 1)]
