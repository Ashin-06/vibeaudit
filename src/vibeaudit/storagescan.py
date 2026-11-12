"""Data, storage and container checks added in 0.8.3: DATA011-DATA013 and CFG017 (all preview)."""
from __future__ import annotations

import re
from typing import Callable, Dict, List, Set, Tuple

from .files import Project, SourceFile
from .guard import GUARD, finditer

Add = Callable[..., None]  # ProjectScanner.add(sf_or_rel, line, rule, message, severity="")

MIGRATION = re.compile(r"(?i)(?:^|/)(?:migrations?|migrate|db/migrate|alembic|versions)(?:/|$)")
# migrations that run inside one transaction, where CREATE INDEX CONCURRENTLY is not allowed
TRANSACTIONAL_RUNNER = re.compile(r"(?i)(?:^|/)(?:supabase/migrations|prisma/migrations)/")
POSTGRES_HINT = re.compile(r"(?i)\b(?:postgres(?:ql)?|psycopg2?|asyncpg|supabase|pg_\w+|jsonb|serial|bigserial|timestamptz|uuid_generate_v4|gen_random_uuid)\b")
CREATE_TABLE = re.compile(r"(?i)\bcreate\s+(?:(?:temp|temporary|unlogged)\s+)?table\s+(?:if\s+not\s+exists\s+)?((?:\"?\w+\"?\.)?\"?\w+\"?)")
CREATE_INDEX = re.compile(
    r"(?i)\bcreate\s+(?:unique\s+)?index\s+(concurrently\s+)?(?:if\s+not\s+exists\s+)?(?:\"?\w+\"?\s+)?on\s+(?:only\s+)?"
    r"((?:\"?\w+\"?\.)?\"?\w+\"?)\s*(?:using\s+\w+\s*)?\(\s*\"?(\w+)")
# a column definition with an inline foreign key: `user_id uuid references users(id)`
INLINE_FK = re.compile(r"(?im)^[ \t]*(?!(?:constraint|foreign|primary|unique|check|add|alter)\b)\"?(\w+)\"?[ \t]+[\w ()]{1,60}?\breferences\b[ \t]+((?:\"?\w+\"?\.)?\"?\w+\"?)")
TABLE_FK = re.compile(r"(?i)\bforeign\s+key\s*\(\s*\"?(\w+)\"?\s*\)\s*references\s+((?:\"?\w+\"?\.)?\"?\w+\"?)")
ALTER_FK = re.compile(r"(?i)\balter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?((?:\"?\w+\"?\.)?\"?\w+\"?)[^;]{0,400}?\bforeign\s+key\s*\(\s*\"?(\w+)")

REDIS_CLIENT = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:new\s+)?(?:(?:redis|aioredis|ioredis)\s*\.\s*)?"
    r"(?:(?:Redis|StrictRedis)\s*\.\s*from_url|Redis|StrictRedis|from_url|createClient|Redis\.fromEnv|Cluster)\s*\(")
TTL_EVIDENCE = re.compile(r"\b(?:ex|px|exat|pxat|keepttl|EX|PX|KEEPTTL)\b|\bexpire\w*\s*\(|\bsetex\s*\(|\bpsetex\s*\(|\bttl\b|\bTTL\b")

SECRET_FILE = re.compile(
    r"(?i)(?:^|/)(?:\.npmrc|\.pypirc|\.netrc|\.git-credentials|id_rsa|id_ed25519|id_ecdsa|credentials(?:\.json)?"
    r"|service[-_]?account[\w.-]*\.json|[\w.-]*\.pem|[\w.-]*\.key|[\w.-]*\.p12|[\w.-]*\.pfx|\.aws(?:/|$)|\.env(?:\.[\w.-]+)?)$")
# public certificates and CA bundles share the .pem extension with private keys
PUBLIC_CERT = re.compile(r"(?i)(?:^|[/_.-])(?:ca|cacert|certs?|bundle|chain|fullchain|public|pub|root)(?:[/_.-][^/]*)?\.pem$|\.(?:example|sample|template|dist)$")
SECRET_ARG =re.compile(r"(?i)^ARG\s+(\w*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|CREDENTIALS?)\w*)\s*$")


def run(project: Project, add: Add) -> None:
    sql = [f for f in project.files if f.kind == "sql" and f.text is not None and not f.is_test]
    if sql:
        GUARD.run("<project>", "foreign key indexes", _sql_checks, project, sql, add)
    for sf in project.files:
        if sf.text is None or sf.is_test:
            continue
        if sf.kind in ("py", "js"):
            GUARD.run(sf.rel, "redis ttl", _redis_ttl, sf, add)
        elif sf.kind == "docker":
            GUARD.run(sf.rel, "docker secrets", _docker_secrets, sf, add)


def _norm(name: str) -> str:
    name = name.replace('"', "").lower()
    return name.split(".", 1)[1] if name.startswith("public.") else name


def _blank_comments(text: str) -> str:
    return re.sub(r"--[^\n]*|/\*[\s\S]*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def _sql_checks(project: Project, files: List[SourceFile], add: Add) -> None:
    joined = "\n".join(f.text or "" for f in files)
    hints = joined + " " + " ".join(sorted(project.js_deps("") if hasattr(project, "js_deps") else []))
    if not POSTGRES_HINT.search(hints) and not any("supabase" in f.rel for f in files):
        return  # MySQL indexes foreign keys by itself, and SQLite has no lock problem to speak of
    cleaned: Dict[str, str] = {f.rel: _blank_comments(f.text or "") for f in files}
    indexed: Set[Tuple[str, str]] = set()
    created_in: Dict[str, str] = {}
    for f in files:
        text = cleaned[f.rel]
        for m in finditer(CREATE_INDEX, text):
            indexed.add((_norm(m.group(2)), m.group(3).lower()))
        for m in finditer(r"(?i)\b(?:primary\s+key|unique)\s*\(\s*\"?(\w+)", text):
            table = _table_before(text, m.start())
            if table:
                indexed.add((table, m.group(1).lower()))
        for m in finditer(CREATE_TABLE, text):
            created_in.setdefault(_norm(m.group(1)), f.rel)
    # DATA011: CREATE INDEX on a table that already existed, in a migration that can use CONCURRENTLY
    for f in files:
        if not MIGRATION.search(f.rel) or TRANSACTIONAL_RUNNER.search(f.rel):
            continue
        text = cleaned[f.rel]
        here = {_norm(m.group(1)) for m in CREATE_TABLE.finditer(text)}
        for m in finditer(CREATE_INDEX, text):
            table = _norm(m.group(2))
            if not m.group(1) and table not in here:
                add(f, f.line_at(m.start()), "DATA011",
                    f"CREATE INDEX on existing table `{table}` without CONCURRENTLY blocks writes to it until the index is built.")
    # DATA012: a foreign key column with no index that starts with it
    for f in files:
        text = cleaned[f.rel]
        fks: List[Tuple[str, str, int]] = []
        for m in finditer(INLINE_FK, text):
            table = _table_before(text, m.start())
            if table:
                fks.append((table, m.group(1).lower(), m.start()))
        for m in finditer(TABLE_FK, text):
            table = _table_before(text, m.start())
            if table:
                fks.append((table, m.group(1).lower(), m.start()))
        for m in finditer(ALTER_FK, text):
            fks.append((_norm(m.group(1)), m.group(2).lower(), m.start()))
        for table, column, off in fks:
            if column in ("id",) or (table, column) in indexed:
                continue
            line = text[text.rfind("\n", 0, off) + 1:text.find("\n", off) if text.find("\n", off) >= 0 else len(text)]
            if re.search(r"(?i)\bprimary\s+key\b|\bunique\b", line):
                continue  # the column is a key itself, which Postgres indexes
            add(f, f.line_at(off), "DATA012",
                f"Foreign key `{table}.{column}` has no index: deletes in the referenced table scan `{table}` and lock it.")


def _table_before(text: str, off: int) -> str:
    """The table of the CREATE TABLE statement that contains `off` (empty when there is none)."""
    start = text.rfind(";", 0, off) + 1
    m = CREATE_TABLE.search(text, start, off)
    return _norm(m.group(1)) if m else ""


def _redis_ttl(sf: SourceFile, add: Add) -> None:
    v = sf.cache.get("views")
    if v is None:
        return
    code, bare = v.code, v.bare  # type: ignore[attr-defined]
    if not re.search(r"\bredis\b|ioredis|@upstash/redis|aioredis", code, re.I):
        return
    clients = {m.group(1) for m in REDIS_CLIENT.finditer(code)}
    if not clients:
        return
    names = "|".join(re.escape(c) for c in sorted(clients))
    for m in finditer(r"\b(?:%s)\s*\.\s*(set|hset|hmset|lpush|rpush|sadd|zadd)\s*\(" % names, bare):
        close = _close_paren(bare, m.end() - 1)
        args = code[m.end():close] if close > 0 else code[m.end():m.end() + 300]
        rest = code[close:close + 600] if close > 0 else ""
        key = args.split(",", 1)[0].strip()
        if TTL_EVIDENCE.search(args):
            continue
        if key and re.search(r"\bexpire\w*\s*\(\s*%s" % re.escape(key[:80]), rest):
            continue  # set first, then expire the same key
        if m.group(1) != "set" and re.search(r"\bexpire\w*\s*\(", rest):
            continue
        add(sf, sf.line_at(m.start()), "DATA013", f"Redis `{m.group(1)}` stores a key with no expiry, so the key lives until it is deleted.")


def _close_paren(bare: str, i: int) -> int:
    depth = 0
    for j in range(i, min(len(bare), i + 4000)):
        c = bare[j]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return j
    return -1


def _docker_secrets(sf: SourceFile, add: Add) -> None:
    stages: List[Dict] = []
    for i, raw in enumerate(sf.lines, 1):
        line = raw.strip()
        m = re.match(r"(?i)^FROM\s+(?:--platform=\S+\s+)?\S+(?:\s+AS\s+(\S+))?", line)
        if m:
            stages.append({"name": (m.group(1) or "").lower(), "secrets": [], "args": [], "copies_from": []})
            continue
        if not stages:
            continue
        st = stages[-1]
        c = re.match(r"(?i)^(?:COPY|ADD)\s+((?:--\S+\s+)*)(.+)$", line)
        if c:
            flags, rest = c.group(1), c.group(2).split()
            src = re.search(r"--from=(\S+)", flags)
            sources = rest[:-1] if len(rest) > 1 else []
            if src:
                st["copies_from"].append((src.group(1).lower(), sources, i))
            elif any(SECRET_FILE.search(s.rstrip("/")) and not PUBLIC_CERT.search(s) for s in sources):
                st["secrets"].append(i)
        a = SECRET_ARG.match(line)
        if a:
            st["args"].append((a.group(1), i))
    if not stages:
        return
    final = stages[-1]
    for line in final["secrets"]:
        add(sf, line, "CFG017", "A secret file is copied into the final image, where anyone who pulls the image can read it.")
    for name, line in final["args"]:
        if re.search(r"\$\{?%s\b" % re.escape(name), "\n".join(sf.lines[line:])):
            add(sf, line, "CFG017", f"Build argument `{name}` holds a secret; build arguments are kept in the image history.")
    by_name = {s["name"]: s for s in stages if s["name"]}
    for stage_name, sources, line in final["copies_from"]:
        src = by_name.get(stage_name)
        if src and src["secrets"] and any(s in ("/", ".", "/app", "/app/", "./") or s.endswith("/") for s in sources):
            add(sf, line, "CFG017", f"The final image copies a whole folder from stage `{stage_name}`, which had a secret file copied into it.")
