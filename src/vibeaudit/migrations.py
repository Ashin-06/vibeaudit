"""Dry-run analysis of a SQL migration (PostgreSQL): which lock each statement takes, what it blocks, whether
it rewrites the table or destroys data, and a safer way to do the same. Static: nothing is executed and no
database is needed, so table sizes are unknown; the analysis says what a statement does to a busy table.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

# what each PostgreSQL table lock blocks for other sessions
BLOCKS = {
    "ACCESS EXCLUSIVE": "reads and writes",
    "EXCLUSIVE": "writes",
    "SHARE ROW EXCLUSIVE": "writes",
    "SHARE": "writes",
    "SHARE UPDATE EXCLUSIVE": "other schema changes and VACUUM (not reads or writes)",
    "ROW EXCLUSIVE": "nothing but conflicting row updates",
    "none": "nothing",
}
RISK_ORDER = ["low", "medium", "high"]
VOLATILE_DEFAULT = re.compile(r"(?i)\bdefault\s+(?:now|clock_timestamp|statement_timestamp|random|gen_random_uuid|uuid_generate_v\d\w*|nextval|timeofday)\s*\(")
IDENT = r'(?:"[^"]+"|[\w$]+)(?:\s*\.\s*(?:"[^"]+"|[\w$]+))?'
MAX_SQL = 2_000_000


def split_statements(sql: str) -> List[Tuple[int, str]]:
    """(1-based line, text) of each statement, split at semicolons outside comments, quoted strings,
    quoted identifiers and $tag$ dollar-quoted bodies. Comments are blanked in the returned text."""
    out: List[Tuple[int, str]] = []
    buf: List[str] = []
    start_line, line, i, n = 1, 1, 0, len(sql)
    started = False
    while i < n:
        c = sql[i]
        if c == "-" and sql.startswith("--", i):
            j = sql.find("\n", i)
            j = n if j < 0 else j
            buf.append(" " * (j - i))
            i = j
            continue
        if c == "/" and sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            j = n if j < 0 else j + 2
            chunk = sql[i:j]
            buf.append(re.sub(r"[^\n]", " ", chunk))
            line += chunk.count("\n")
            i = j
            continue
        if c in "'\"":
            j = i + 1
            while j < n:
                if sql[j] == c:
                    if j + 1 < n and sql[j + 1] == c:  # '' or "" escapes the quote
                        j += 2
                        continue
                    break
                j += 1
            j = min(j + 1, n)
            chunk = sql[i:j]
            if not started:
                started, start_line = True, line
            buf.append(chunk)
            line += chunk.count("\n")
            i = j
            continue
        if c == "$":
            m = re.match(r"\$([A-Za-z_]\w*)?\$", sql[i:])
            if m:
                tag = m.group(0)
                j = sql.find(tag, i + len(tag))
                j = n if j < 0 else j + len(tag)
                chunk = sql[i:j]
                if not started:
                    started, start_line = True, line
                buf.append(chunk)
                line += chunk.count("\n")
                i = j
                continue
        if c == ";":
            text = "".join(buf).strip()
            if text:
                out.append((start_line, text))
            buf, started = [], False
            i += 1
            continue
        if not started and not c.isspace():
            started, start_line = True, line
        if c == "\n":
            line += 1
        buf.append(c)
        i += 1
    text = "".join(buf).strip()
    if text:
        out.append((start_line, text))
    return out


def _item(kind: str, table: Optional[str], lock: str, risk: str, *, rewrites: bool = False, scans: bool = False,
          destructive: bool = False, advice: str = "", note: str = "") -> Dict:
    return {"kind": kind, "table": table, "lock": lock, "blocks": BLOCKS[lock], "rewrites_table": rewrites,
            "scans_table": scans, "destructive": destructive, "risk": risk, "advice": advice, "note": note}


def classify(stmt: str) -> Dict:
    """What one statement does (see analyse())."""
    s = re.sub(r"\s+", " ", stmt).strip()
    low = s.lower()
    m = re.match(r"(?i)create (unique )?index (concurrently )?(?:if not exists )?(?:" + IDENT + r" )?on (?:only )?(" + IDENT + ")", s)
    if m:
        if m.group(2):
            return _item("create index concurrently", m.group(3), "SHARE UPDATE EXCLUSIVE", "low", scans=True,
                         note="Cannot run inside a transaction block; a failed build leaves an INVALID index to drop.")
        return _item("create index", m.group(3), "SHARE", "high", scans=True,
                     advice="Use CREATE INDEX CONCURRENTLY (outside a transaction): writes are blocked until the index is built.")
    m = re.match(r"(?i)drop index (concurrently )?(?:if exists )?(" + IDENT + ")", s)
    if m:
        if m.group(1):
            return _item("drop index concurrently", m.group(2), "SHARE UPDATE EXCLUSIVE", "low")
        return _item("drop index", m.group(2), "ACCESS EXCLUSIVE", "medium",
                     advice="Use DROP INDEX CONCURRENTLY: the table is locked against reads and writes while waiting.")
    m = re.match(r"(?i)drop (table|materialized view|view|schema|database|type|sequence) (?:if exists )?(" + IDENT + ")", s)
    if m:
        return _item("drop " + m.group(1).lower(), m.group(2), "ACCESS EXCLUSIVE", "high", destructive=True,
                     advice="Irreversible: back up first, stop the application using it, and keep a down migration.")
    m = re.match(r"(?i)truncate (?:table )?(?:only )?(" + IDENT + ")", s)
    if m:
        return _item("truncate", m.group(1), "ACCESS EXCLUSIVE", "high", destructive=True,
                     advice="Deletes every row irreversibly.")
    m = re.match(r"(?i)(update|delete from) (?:only )?(" + IDENT + ")", s)
    if m:
        whole = not re.search(r"(?i)\bwhere\b", s)
        kind = m.group(1).lower()
        if whole:
            return _item(kind + " (every row)", m.group(2), "ROW EXCLUSIVE", "high", destructive=kind.startswith("delete"),
                         advice="Touches every row in one transaction (long row locks, table bloat): batch it by key range.")
        return _item(kind, m.group(2), "ROW EXCLUSIVE", "low", destructive=kind.startswith("delete"))
    m = re.match(r"(?i)alter table (?:if exists )?(?:only )?(" + IDENT + ") (.*)", s)
    if m:
        return _alter(m.group(1), m.group(2))
    m = re.match(r"(?i)create (?:temp |temporary |unlogged )?table (?:if not exists )?(" + IDENT + ")", s)
    if m:
        return _item("create table", m.group(1), "none", "low")
    m = re.match(r"(?i)(vacuum full|cluster)\b\s*(" + IDENT + ")?", s)
    if m:
        return _item(m.group(1).lower(), m.group(2), "ACCESS EXCLUSIVE", "high", rewrites=True,
                     advice="Rewrites the table under a lock that blocks reads and writes; consider pg_repack.")
    m = re.match(r"(?i)reindex (?:\(.*?\) )?(?:table|index) (concurrently )?(" + IDENT + ")", s)
    if m:
        if m.group(1):
            return _item("reindex concurrently", m.group(2), "SHARE UPDATE EXCLUSIVE", "low")
        return _item("reindex", m.group(2), "SHARE", "medium", advice="Use REINDEX ... CONCURRENTLY (PostgreSQL 12+).")
    m = re.match(r"(?i)refresh materialized view (concurrently )?(" + IDENT + ")", s)
    if m:
        if m.group(1):
            return _item("refresh materialized view concurrently", m.group(2), "EXCLUSIVE", "low",
                         note="Needs a unique index on the view; reads continue.")
        return _item("refresh materialized view", m.group(2), "ACCESS EXCLUSIVE", "medium",
                     advice="Use REFRESH MATERIALIZED VIEW CONCURRENTLY (needs a unique index) so reads continue.")
    if re.match(r"(?i)(begin|start transaction|commit|end|rollback|set|reset|select|insert|create (or replace )?(function|view|trigger|policy|extension|schema|type|sequence)|comment|grant|revoke)\b", low):
        kind = low.split(" ", 1)[0]
        return _item(kind, None, "none" if kind != "insert" else "ROW EXCLUSIVE", "low")
    return _item("other", None, "none", "low", note="Not recognised; check it by hand.")


def _alter(table: str, rest: str) -> Dict:
    actions = [a.strip() for a in re.split(r",(?![^()]*\))", rest) if a.strip()]
    results = [_alter_action(table, a) for a in actions] or [_item("alter table", table, "ACCESS EXCLUSIVE", "medium")]
    if len(results) == 1:
        return results[0]
    worst = max(results, key=lambda r: RISK_ORDER.index(r["risk"]))
    merged = dict(worst)
    merged["kind"] = "alter table: " + "; ".join(r["kind"].replace("alter table: ", "") for r in results)
    for key in ("rewrites_table", "scans_table", "destructive"):
        merged[key] = any(r[key] for r in results)
    merged["advice"] = " ".join(dict.fromkeys(r["advice"] for r in results if r["advice"]))
    merged["note"] = " ".join(dict.fromkeys(r["note"] for r in results if r["note"]))
    return merged


def _alter_action(table: str, a: str) -> Dict:
    low = a.lower()
    x = "ACCESS EXCLUSIVE"
    if low.startswith("add column") or (low.startswith("add ") and not low.startswith(("add constraint", "add primary", "add unique", "add foreign", "add check"))):
        if VOLATILE_DEFAULT.search(a):
            return _item("alter table: add column with a volatile default", table, x, "high", rewrites=True,
                         advice="A volatile default rewrites the table: add the column without a default, backfill in batches, then set the default.")
        if re.search(r"(?i)\bnot null\b", a) and not re.search(r"(?i)\bdefault\b", a):
            return _item("alter table: add not null column without default", table, x, "high",
                         note="Fails if the table has rows.", advice="Add it nullable (or with a default), backfill, then SET NOT NULL.")
        return _item("alter table: add column", table, x, "low", note="Metadata only (PostgreSQL 11+); the lock is brief.")
    if low.startswith("drop column") or low.startswith("drop ") and not low.startswith(("drop constraint", "drop default", "drop not null")):
        return _item("alter table: drop column", table, x, "high", destructive=True,
                     advice="Deploy code that no longer reads the column first; the data is gone afterwards.")
    if re.match(r"alter (?:column )?\S+ (?:set data )?type\b", low):
        return _item("alter table: change column type", table, x, "high", rewrites=True, scans=True,
                     advice="Usually rewrites the table under a lock that blocks reads and writes: add a new column, backfill, switch, drop the old one.")
    if re.match(r"alter (?:column )?\S+ set not null", low):
        return _item("alter table: set not null", table, x, "high", scans=True,
                     advice="Scans the whole table under a lock that blocks reads and writes: add CHECK (col IS NOT NULL) NOT VALID, VALIDATE CONSTRAINT, then SET NOT NULL (PostgreSQL 12+ skips the scan).")
    if re.match(r"alter (?:column )?\S+ (?:set default|drop default|drop not null|set statistics|set storage)", low):
        return _item("alter table: " + " ".join(low.split()[2:4]) if low.startswith("alter column") else "alter table: column setting",
                     table, x, "low", note="Metadata only; the lock is brief.")
    if low.startswith("add constraint") or low.startswith(("add primary", "add unique", "add foreign", "add check")):
        not_valid = "not valid" in low
        if "foreign key" in low:
            if not_valid:
                return _item("alter table: add foreign key not valid", table, "SHARE ROW EXCLUSIVE", "low",
                             note="Validate later with VALIDATE CONSTRAINT (does not block writes).")
            return _item("alter table: add foreign key", table, "SHARE ROW EXCLUSIVE", "high", scans=True,
                         advice="Blocks writes on both tables while every row is checked: add it NOT VALID, then VALIDATE CONSTRAINT.")
        if "check" in low:
            if not_valid:
                return _item("alter table: add check not valid", table, x, "low", note="The lock is brief; validate later.")
            return _item("alter table: add check", table, x, "high", scans=True,
                         advice="Scans the table under a lock that blocks reads and writes: add it NOT VALID, then VALIDATE CONSTRAINT.")
        if re.search(r"(?i)\busing index\b", a):
            return _item("alter table: add constraint using index", table, x, "low", note="The lock is brief.")
        return _item("alter table: add unique or primary key", table, x, "high", scans=True,
                     advice="Builds an index under a lock that blocks reads and writes: CREATE UNIQUE INDEX CONCURRENTLY, then ADD CONSTRAINT ... USING INDEX.")
    if low.startswith("validate constraint"):
        return _item("alter table: validate constraint", table, "SHARE UPDATE EXCLUSIVE", "low", scans=True)
    if low.startswith("drop constraint"):
        return _item("alter table: drop constraint", table, x, "low", note="The lock is brief.")
    if low.startswith("rename"):
        return _item("alter table: rename", table, x, "medium",
                     advice="Running application code that uses the old name breaks: rename in steps (add, dual-write, switch, drop).")
    if re.match(r"(?:enable|disable|force|no force) row level security", low):
        return _item("alter table: row level security", table, x, "low", note="The lock is brief.")
    if re.match(r"set (?:logged|unlogged)\b", low):
        return _item("alter table: set logged/unlogged", table, x, "high", rewrites=True)
    return _item("alter table", table, x, "medium", note="Not recognised in detail; ALTER TABLE takes ACCESS EXCLUSIVE by default.")


def analyse(sql: str) -> Dict:
    """Every statement of a migration with its lock, what it blocks and how risky it is on a busy table."""
    if len(sql) > MAX_SQL:
        raise ValueError(f"the migration is larger than {MAX_SQL} characters")
    statements = []
    for line, text in split_statements(sql):
        item = classify(text)
        item["line"] = line
        item["statement"] = re.sub(r"\s+", " ", text)[:200]
        statements.append(item)
    kinds = [s["kind"] for s in statements]
    in_transaction = any(k in ("begin", "start") for k in kinds)
    exclusive = [s for s in statements if s["lock"] == "ACCESS EXCLUSIVE"]
    sets_timeout = bool(re.search(r"(?i)\bset\s+(?:local\s+)?lock_timeout\b", sql))
    notes = []
    if exclusive and not sets_timeout:
        notes.append("Set lock_timeout (for example SET lock_timeout = '5s') so a statement waiting for its "
                     "ACCESS EXCLUSIVE lock behind a long query does not queue every other query on the table.")
    if in_transaction and len([s for s in statements if s["lock"] not in ("none", "ROW EXCLUSIVE")]) > 1:
        notes.append("Several locking statements run in one transaction: every lock is held until COMMIT.")
    if any(s["kind"] == "create index concurrently" for s in statements) and in_transaction:
        notes.append("CREATE INDEX CONCURRENTLY fails inside a transaction block.")
    worst = max((s["risk"] for s in statements), key=RISK_ORDER.index, default="low")
    return {"dialect": "postgresql", "statements": statements, "risk": worst,
            "destructive": sum(s["destructive"] for s in statements),
            "blocks_writes": sum(s["lock"] in ("ACCESS EXCLUSIVE", "EXCLUSIVE", "SHARE ROW EXCLUSIVE", "SHARE") for s in statements),
            "rewrites": sum(s["rewrites_table"] for s in statements), "notes": notes}
