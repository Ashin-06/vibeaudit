"""Data, storage and container rules added in 0.8.3 (DATA011-DATA013, CFG017)."""
import time

from vibeaudit.rules import RULES
from vibeaudit.scanner import Options, scan

NEW = ("DATA011", "DATA012", "DATA013", "CFG017")


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


def test_index_without_concurrently_and_foreign_keys_without_index(tmp_path):
    write(tmp_path, "db/schema.sql",
          "create table users (id uuid primary key default gen_random_uuid(), email text unique);\n"
          "create table orders (\n  id bigserial primary key,\n  user_id uuid references users(id) on delete cascade,\n"   # 4
          "  coupon_id uuid references coupons(id)\n);\n"                                                              # 5
          "create index orders_coupon_idx on orders (coupon_id);\n")
    write(tmp_path, "migrations/0002_add_index.sql",
          "create index orders_created_idx on orders (created_at);\n"                                                  # 1
          "create index concurrently orders_status_idx on orders (status);\n"
          "create table events (id bigserial primary key, kind text);\ncreate index events_kind_idx on events (kind);\n")
    write(tmp_path, "supabase/migrations/20240101_idx.sql", "create index notes_user_idx on notes (user_id);\n")
    assert found(tmp_path, "DATA011", "DATA012") == [("db/schema.sql", 4, "DATA012"), ("migrations/0002_add_index.sql", 1, "DATA011")]


def test_table_constraints_report_the_key_column_once(tmp_path):
    write(tmp_path, "schema.sql", "create table users (id uuid primary key default gen_random_uuid());\n"
          "create table orders (\n  id bigserial primary key,\n  user_id uuid not null,\n"
          "  CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id),\n"   # 5
          "  FOREIGN KEY (id) REFERENCES users(id)\n);\n")
    res = scan(str(tmp_path), Options(offline=True, external="none", min_severity="low"))
    assert [(f.line, f.message.split("`")[1]) for f in res.findings if f.rule_id == "DATA012"] == [(5, "orders.user_id")]


def test_mysql_projects_are_not_checked_for_foreign_key_indexes(tmp_path):
    write(tmp_path, "schema.sql", "CREATE TABLE orders (\n  id INT AUTO_INCREMENT PRIMARY KEY,\n"
          "  user_id INT,\n  FOREIGN KEY (user_id) REFERENCES users(id)\n) ENGINE=InnoDB;\n")
    assert found(tmp_path, "DATA012") == []


def test_redis_keys_without_expiry(tmp_path):
    write(tmp_path, "cache.py", "import redis\nr = redis.Redis()\n"
          "def save(k, v):\n    r.set(k, v)\n"                                    # 4
          "    r.set(k, v, ex=60)\n    r.setex(k, 60, v)\n"
          "    r.set('a', 1)\n    r.expire('a', 60)\n"
          "c = redis.Redis.from_url(URL)\nc.hset('h', 'k', 1)\n")   # 10
    write(tmp_path, "cache.ts", "import { createClient } from 'redis';\nconst client = createClient();\n"
          "export async function put(k: string, v: string) {\n  await client.set(k, v);\n"   # 4
          "  await client.set(k, v, { EX: 60 });\n}\n"
          "const memo = new Map();\nmemo.set('k', 1);\n")
    assert found(tmp_path, "DATA013") == [("cache.py", 4, "DATA013"), ("cache.py", 10, "DATA013"), ("cache.ts", 4, "DATA013")]


def test_secrets_in_the_final_image(tmp_path):
    write(tmp_path, "Dockerfile",
          "FROM node:22 AS build\nARG NPM_TOKEN\nCOPY .npmrc ./\nRUN npm ci && rm .npmrc\nCOPY . .\nRUN npm run build\n\n"
          "FROM node:22-slim\nARG GITHUB_TOKEN\nRUN git clone https://$GITHUB_TOKEN@github.com/o/r\n"   # 9
          "COPY --from=build /app/dist ./dist\nCOPY id_rsa /root/.ssh/id_rsa\nCOPY .env.example ./\n"  # 12
          "COPY certs/rds-ca-bundle.pem /etc/ssl/\nCOPY fullchain.pem ./\nCOPY ca.key ./\n")  # 16
    write(tmp_path, "Dockerfile.whole", "FROM python:3.12 AS base\nCOPY credentials.json /app/\n"
          "FROM python:3.12-slim\nCOPY --from=base /app /app\n")                                            # 4
    assert found(tmp_path, "CFG017") == [("Dockerfile", 9, "CFG017"), ("Dockerfile", 12, "CFG017"), ("Dockerfile", 16, "CFG017"),
                                         ("Dockerfile.whole", 4, "CFG017")]


def test_storage_checks_are_linear_on_hostile_input(tmp_path):
    write(tmp_path, "a.sql", "create table t (\n" + "  c uuid references u(id),\n" * 8000 + ");\n" + "create index i on t (x);\n" * 3000)
    write(tmp_path, "b.py", "import redis\nr = redis.Redis()\n" + "r.set(" * 5000 + "\n" + "r.set(k, v)\n" * 5000)
    write(tmp_path, "Dockerfile", "FROM a AS b\n" + "COPY .npmrc ./\n" * 5000 + "FROM c\n" + "ARG TOKEN\n" * 5000)
    start = time.time()
    found(tmp_path)
    assert time.time() - start < 15
