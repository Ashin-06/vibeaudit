"""MCP harness tools: audit_current_file, verify_package (no network) and simulate_migration."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from vibeaudit import mcp_server, migrations
from vibeaudit.mcp_server import handle

BAD = "import requests\nr = requests.get('https://x')\n"


def call(name, args):
    res = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}})["result"]
    return res.get("structuredContent"), res["isError"], res["content"][0]["text"]


# ------------------------------------------------------------ simulate_migration
def kinds(sql):
    return {s["kind"]: s for s in migrations.analyse(sql)["statements"]}


def test_index_and_column_changes():
    got = kinds("""
        CREATE INDEX idx_orders_user ON orders (user_id);
        CREATE INDEX CONCURRENTLY idx_orders_at ON public.orders (created_at);
        ALTER TABLE orders ADD COLUMN note text;
        ALTER TABLE "Orders" ADD COLUMN placed_at timestamptz DEFAULT now();
        ALTER TABLE orders ALTER COLUMN total TYPE numeric(12, 2);
        ALTER TABLE orders ALTER COLUMN user_id SET NOT NULL;
        ALTER TABLE orders DROP COLUMN legacy;
    """)
    assert got["create index"]["lock"] == "SHARE" and got["create index"]["blocks"] == "writes"
    assert got["create index"]["risk"] == "high" and "CONCURRENTLY" in got["create index"]["advice"]
    assert got["create index concurrently"]["risk"] == "low" and got["create index concurrently"]["table"] == "public.orders"
    assert got["alter table: add column"]["risk"] == "low" and not got["alter table: add column"]["rewrites_table"]
    assert got["alter table: add column with a volatile default"]["rewrites_table"]
    assert got["alter table: add column with a volatile default"]["table"] == '"Orders"'
    assert got["alter table: change column type"]["rewrites_table"]
    assert got["alter table: set not null"]["scans_table"] and got["alter table: set not null"]["blocks"] == "reads and writes"
    assert got["alter table: drop column"]["destructive"]


def test_constraints_data_changes_and_drops():
    got = kinds("""
        ALTER TABLE items ADD CONSTRAINT fk_owner FOREIGN KEY (owner_id) REFERENCES users (id);
        ALTER TABLE items ADD CONSTRAINT fk_shop FOREIGN KEY (shop_id) REFERENCES shops (id) NOT VALID;
        ALTER TABLE items VALIDATE CONSTRAINT fk_shop;
        ALTER TABLE items ADD CONSTRAINT price_pos CHECK (price > 0);
        UPDATE items SET price = 0;
        DELETE FROM items WHERE id = 3;
        TRUNCATE audit_log;
        DROP TABLE IF EXISTS old_items;
        DROP INDEX idx_x;
    """)
    assert got["alter table: add foreign key"]["risk"] == "high" and "NOT VALID" in got["alter table: add foreign key"]["advice"]
    assert got["alter table: add foreign key not valid"]["risk"] == "low"
    assert got["alter table: validate constraint"]["lock"] == "SHARE UPDATE EXCLUSIVE"
    assert got["alter table: add check"]["risk"] == "high"
    assert got["update (every row)"]["risk"] == "high" and not got["update (every row)"]["destructive"]
    assert got["delete from"]["risk"] == "low" and got["delete from"]["destructive"]
    assert got["truncate"]["destructive"] and got["drop table"]["destructive"] and got["drop table"]["table"] == "old_items"
    assert got["drop index"]["lock"] == "ACCESS EXCLUSIVE"


def test_statement_splitting_respects_quotes_comments_and_dollar_bodies():
    sql = ("-- a comment; with a semicolon\nINSERT INTO t VALUES ('a;b', 'it''s');\n/* block; comment */\n"
           "CREATE FUNCTION f() RETURNS void AS $body$ BEGIN PERFORM 1; END; $body$ LANGUAGE plpgsql;\n"
           'ALTER TABLE "we;ird" ADD COLUMN x int\n')
    parts = migrations.split_statements(sql)
    assert [line for line, _t in parts] == [2, 4, 5]
    assert "'a;b'" in parts[0][1] and "$body$ BEGIN PERFORM 1; END; $body$" in parts[1][1]
    assert migrations.classify(parts[2][1])["table"] == '"we;ird"'


def test_summary_notes_and_combined_alter():
    out = migrations.analyse("BEGIN;\nALTER TABLE a ADD COLUMN b int, ALTER COLUMN c SET NOT NULL;\n"
                             "CREATE INDEX CONCURRENTLY i ON a (b);\nDROP INDEX j;\nCOMMIT;\n")
    combined = out["statements"][1]
    assert combined["risk"] == "high" and combined["scans_table"] and "add column" in combined["kind"]
    assert out["risk"] == "high" and out["blocks_writes"] == 2
    joined = " ".join(out["notes"])
    assert "lock_timeout" in joined and "held until COMMIT" in joined and "fails inside a transaction" in joined
    assert not any("lock_timeout" in n for n in migrations.analyse("SET lock_timeout = '5s'; DROP INDEX j;")["notes"])


def test_simulate_migration_tool(tmp_path):
    (tmp_path / "001.sql").write_text("CREATE INDEX i ON t (a);\n")
    out, err, _ = call("simulate_migration", {"path": str(tmp_path / "001.sql")})
    assert not err and out["statements"][0]["kind"] == "create index" and out["path"].endswith("001.sql")
    (tmp_path / "secret.txt").write_text("x")
    for bad in ({"path": str(tmp_path / "secret.txt")}, {"path": str(tmp_path / "nope.sql")}, {},
                {"sql": "SELECT 1", "path": str(tmp_path / "001.sql")}, {"sql": 5}):
        assert call("simulate_migration", bad)[1], bad
    assert call("simulate_migration", {"sql": "x" * (migrations.MAX_SQL + 1)})[1]


# ------------------------------------------------------------ audit_current_file
def test_audit_current_file_scans_unsaved_and_new_content(tmp_path):
    mcp_server._WATCHERS.clear()
    (tmp_path / ".git").mkdir()
    (tmp_path / "app.py").write_text("x = 1\n")
    out, err, _ = call("audit_current_file", {"file": str(tmp_path / "app.py")})
    assert not err and out["findings"] == [] and out["unsaved_content"] is False
    out, err, _ = call("audit_current_file", {"file": str(tmp_path / "app.py"), "content": BAD})
    assert [f["rule_id"] for f in out["findings"]] == ["REL001"] and out["file"] == "app.py"
    assert (tmp_path / "app.py").read_text() == "x = 1\n"
    watcher = mcp_server._WATCHERS[str(tmp_path.resolve())]
    out, err, _ = call("audit_current_file", {"file": str(tmp_path / "app.py")})
    assert out["findings"] == [] and mcp_server._WATCHERS[str(tmp_path.resolve())] is watcher  # reused, disk again
    out, err, _ = call("audit_current_file", {"file": str(tmp_path / "new" / "client.py"), "content": BAD})
    assert not err and [f["file"] for f in out["findings"]] == ["new/client.py"]
    assert not (tmp_path / "new").exists()


def test_audit_current_file_rejects_bad_input(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / ".vibeauditignore").write_text("skip.py\n")
    other = tmp_path.parent / (tmp_path.name + "-other.py")
    other.write_text("x = 1\n")
    try:
        cases = [{"file": str(tmp_path / "missing.py")}, {"file": 3}, {"file": str(tmp_path)},
                 {"file": str(other), "project": str(tmp_path)},
                 {"file": str(tmp_path / "app.py"), "content": 7},
                 {"file": str(tmp_path / "app.py"), "content": "x" * (mcp_server.MAX_CONTENT + 1)},
                 {"file": str(tmp_path / "skip.py"), "content": BAD}]
        for args in cases:
            assert call("audit_current_file", args)[1], args
    finally:
        other.unlink()


# ------------------------------------------------------------ verify_package (no network)
@pytest.fixture
def registry(monkeypatch):
    from vibeaudit import deps

    known = {"opencv-python": dt.datetime(2015, 1, 1, tzinfo=dt.timezone.utc), "requests": dt.datetime(2011, 1, 1, tzinfo=dt.timezone.utc),
             "brand-new-pkg": dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=3)}

    def info(dep):
        return ("ok", known[dep.name], "") if dep.name in known else ("missing", None, "")

    monkeypatch.setattr(deps, "registry_info", info)
    monkeypatch.setattr(deps, "osv_lookup", lambda ds: {("PyPI", "requests", "2.0.0"): [{"id": "GHSA-x"}]})
    monkeypatch.setattr(deps, "save_caches", lambda: None)


def test_verify_package_verdicts(registry, tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    out, err, _ = call("verify_package", {"name": "requests", "ecosystem": "PyPI", "project": str(tmp_path)})
    assert not err and out["verdict"] == "ok" and out["declared_in_project"] == [
        {"file": "requirements.txt", "line": 1, "version": "2.31.0"}]
    out = call("verify_package", {"name": "cv2", "ecosystem": "PyPI"})[0]
    assert out["name"] == "opencv-python" and out["import_name_of"][0] == "opencv-python" and out["verdict"] == "ok"
    assert call("verify_package", {"name": "reqeusts-pro-max", "ecosystem": "PyPI"})[0]["verdict"] == "block"
    assert call("verify_package", {"name": "brand-new-pkg", "ecosystem": "PyPI"})[0]["verdict"] == "caution"
    vulnerable = call("verify_package", {"name": "requests", "ecosystem": "PyPI", "version": "2.0.0"})[0]
    assert vulnerable["verdict"] == "block" and "GHSA-x" in " ".join(vulnerable["reasons"])
    assert call("verify_package", {"name": "x", "ecosystem": "Maven"})[1]
