"""Data and database checks: N+1 queries, over-fetched records, destructive migrations, money stored as floats,
world-readable private tables, naive timestamps, undocumented env vars, per-request DB clients, SQLite on
serverless hosts and multi-write handlers without a transaction."""
from __future__ import annotations

import ast
import re
from typing import Callable, Dict, List, Optional, Set

from .files import ENV_EXAMPLE_RE, Project, SourceFile
from .guard import GUARD, finditer
from .lexer import match_close
from .model import Finding, Route

Emit = Callable[[Finding], None]

PY_QUERY_SUFFIXES = (
    ".objects.get", ".objects.filter", ".objects.create", ".objects.get_or_create", ".objects.update_or_create",
    ".objects.exclude", ".objects.count", "session.query", "session.get", "session.execute", ".query.get", ".query.filter",
    ".query.filter_by", "cursor.execute", ".find_one", ".find_one_and_update", ".insert_one", ".update_one",
    "supabase.table", ".table", "conn.execute", "connection.execute", "db.execute",
)
JS_QUERY = re.compile(
    r"\bawait\s+(?:[\w$.]+\.)?(?:prisma|db|tx|client|knex|sql|supabase|pool|connection|conn|mongoose|models?)\b[\w$.]*"
    r"(?:\.(?:find\w*|create\w*|update\w*|delete\w*|upsert|count|aggregate|query|execute|select|insert|from|rpc)\s*\()"
    r"|\bawait\s+[A-Z]\w*\.(?:find\w*|create|update\w*|delete\w*|count\w*|aggregate)\s*\("
)
JS_LOOP = re.compile(r"\bfor\s*(?:await\s*)?\(|\bwhile\s*\(|\.\s*(?:forEach|map|flatMap)\s*\(\s*async\b")
JS_WRITE = re.compile(
    r"\bawait\s+[\w$.]*?(?:\.(?:create|createMany|update|updateMany|upsert|delete|deleteMany|insert|insertOne|insertMany|"
    r"updateOne|deleteOne|save|destroy|increment|decrement)\s*\()"
)
SENSITIVE_MODEL = re.compile(r"(?i)^(?:user|users|account|accounts|customer|customers|member|members|admin|admins|profile|profiles)$")
MONEY = r"(?:price|amount|balance|cost|total|fee|fees|salary|subtotal|tax|discount|credit|credits|revenue|payout|refund|wage)\w*"
SENSITIVE_TABLE = re.compile(
    r"(?i)(?:^|\.)(?:users?|profiles?|customers?|orders?|payments?|messages?|api_keys?|secrets?|documents?|invoices?|"
    r"subscriptions?|accounts?|transactions?|notes?|chats?|conversations?|addresses|private\w*)$"
)
API_CLIENTS = re.compile(
    r"(?i)^(?:openai|anthropic|groq|mistral|cohere|replicate|together|stripe|resend|twilio|sgMail|sendgrid|mailgun|"
    r"postmark|slack|octokit|github|cloudinary|s3|s3Client|pusher|ably|clerk|clerkClient|posthog|analytics|sentry)$")
NAIVE_COLUMN = re.compile(r"(?i)\b(\w+_at|created|updated|deleted|timestamp)\s+timestamp(?:\s+without\s+time\s+zone)?\b(?!\s+with\s+time\s+zone)(?!tz)")
PLATFORM_ENV = re.compile(
    r"^(?:NODE_ENV|PORT|HOST|HOSTNAME|HOME|PATH|PWD|USER|SHELL|LANG|TZ|CI|DEBUG|VERCEL\w*|NETLIFY\w*|RENDER\w*|RAILWAY\w*|"
    r"FLY_\w+|HEROKU\w*|GITHUB_\w+|RUNNER_\w+|NEXT_RUNTIME|NEXT_PHASE|PYTHON\w*|VIRTUAL_ENV|AWS_REGION|AWS_LAMBDA_\w+|"
    r"AWS_EXECUTION_ENV|LAMBDA_TASK_ROOT|K_SERVICE|K_REVISION|GOOGLE_CLOUD_PROJECT|WEBSITE_\w+|DENO_\w+|SUPABASE_URL|"
    r"SUPABASE_ANON_KEY|SUPABASE_SERVICE_ROLE_KEY|SUPABASE_DB_URL|DYNO|TERM|MODE|BASE_URL|DEV|PROD|SSR|npm_\w+)$"
)


# Switches and test toggles: optional by nature, so a missing entry cannot break a deploy.
OPTIONAL_FLAG = re.compile(
    r"^(?:IS|ENABLE|DISABLE|USE|SKIP|NO|ALLOW|FORCE|CI|ANALYZE|VERBOSE|LOG|TRACE|PROFILE|DRY_RUN)(?:_|$)|"
    r"_(?:ENABLED|DISABLED|DEBUG|VERBOSE|TEST|TESTS|SMOKE_TEST|FLAG|MODE)$|^(?:ANALYZE|DEBUG|VERBOSE|TESTING|CI)$")


def _example_env_files(project: Project) -> List[SourceFile]:
    return [f for f in project.files if re.search(r"(?:^|/)\.env\.(?:example|sample|template|dist|defaults?)$", f.rel)
            or re.search(r"(?:^|/)\.env\.[\w.-]+\.(?:example|sample|template)$", f.rel) or f.rel.endswith("env.example")]


class DataScanner:
    def __init__(self, project: Project, emit: Emit, routes: List[Route]):
        self.p = project
        self.emit = emit
        self.routes = routes

    def add(self, sf: SourceFile, rule: str, line: int, msg: str, sev: str = "") -> None:
        self.emit(Finding(rule, sf.rel, line, msg, sev, sf.line(line).strip()[:200]))

    def run(self) -> None:
        self.serverless_config = self._serverless_config()
        serverless = self.serverless_config
        for sf in self.p.files:
            if sf.text is None or sf.is_test:
                continue
            if sf.kind == "py":
                GUARD.run(sf.rel, "data checks", self._python, sf, serverless)
            elif sf.kind == "js":
                GUARD.run(sf.rel, "data checks", self._javascript, sf, self._js_serverless(sf))
            elif sf.kind == "sql":
                GUARD.run(sf.rel, "data checks", self._sql, sf)
            elif sf.rel.endswith(".prisma"):  # schema.prisma or a multi-file schema folder
                GUARD.run(sf.rel, "data checks", self._prisma, sf)
        GUARD.run("<project>", "env var documentation", self._env_parity)
        GUARD.run("<project>", "transactions", self._transactions)

    def _serverless_config(self) -> bool:
        names = {f.rel.rsplit("/", 1)[-1] for f in self.p.files}
        return bool(names & {"vercel.json", "netlify.toml", "serverless.yml", "serverless.yaml", "wrangler.toml", "template.yaml"})

    def _js_serverless(self, sf: SourceFile) -> bool:
        """Next.js, Netlify, Vercel and Cloudflare apps run their server code on throw-away instances."""
        return self.serverless_config or bool(self.p.js_deps(sf.rel) & {"next", "@netlify/functions", "@vercel/node", "@cloudflare/workers-types"})

    # ------------------------------------------------------------- python
    def _python(self, sf: SourceFile, serverless: bool) -> None:
        tree = sf.cache.get("ast")
        if tree is None:
            try:
                tree = ast.parse(sf.text or "")
            except (SyntaxError, ValueError, RecursionError):
                return
        from .pyscan import dotted

        parents = {id(child): parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        # `import datetime as dt`, `from datetime import datetime as DT`: resolve the first name of a call
        aliases: Dict[str, str] = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
                for a in n.names:
                    aliases[a.asname or a.name] = f"{n.module}.{a.name}"

        def resolve(d: str) -> str:
            head, _, rest = d.partition(".")
            return aliases.get(head, head) + ("." + rest if rest else "")

        for node in ast.walk(tree):
            GUARD.tick()
            # range(start, stop, step) walks a list in chunks: one batched query per chunk is the fix, not N+1
            chunked = isinstance(getattr(node, "iter", None), ast.Call) and dotted(node.iter.func) == "range" and len(node.iter.args) == 3  # type: ignore[attr-defined]
            if isinstance(node, (ast.For, ast.AsyncFor)) and not isinstance(node.iter, (ast.Tuple, ast.List, ast.Set, ast.Constant)) \
                    and not chunked and not any(isinstance(n, ast.Call) and dotted(n.func).endswith("sleep") for n in self._walk_body(node.body)):
                for inner in self._walk_body(node.body):
                    if isinstance(inner, ast.Call):
                        d = dotted(inner.func)
                        if d.endswith(PY_QUERY_SUFFIXES) and not d.endswith((".executemany", "objects.bulk_create")):
                            self.add(sf, "DATA001", inner.lineno, f"Database call `{d.split('.')[-1]}()` runs once per loop iteration.")
                            break
            elif isinstance(node, ast.Call):
                d = dotted(node.func)
                full = resolve(d)
                no_tz = not node.keywords and (not node.args or (len(node.args) == 1 and isinstance(node.args[0], ast.Constant) and node.args[0].value is None))
                if full in ("datetime.utcnow", "datetime.datetime.utcnow") or (
                        full in ("datetime.now", "datetime.datetime.now") and no_tz and self._persisted(node, parents)):
                    self.add(sf, "DATA006", node.lineno, f"`{d}()` returns a naive datetime without a time zone.")
                # match the call itself, not its unparsed text: closing(sqlite3.connect(...)) is one database
                literals = [a.value for a in list(node.args) + [k.value for k in node.keywords] if isinstance(a, ast.Constant) and isinstance(a.value, str)]
                if serverless and (full == "sqlite3.connect" or any(s.startswith("sqlite:///") for s in literals)) and not self._memory_db(node):
                    self.add(sf, "DATA009", node.lineno, "SQLite file database on a serverless host; the file is lost between requests.")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if any(re.search(r"\.(?:route|api_route|get|post|put|patch|delete|websocket)\(|\bapi_view\b|\baction\(", ast.unparse(dec)) for dec in node.decorator_list):
                    for inner in self._walk_body(node.body):
                        if isinstance(inner, ast.Call) and dotted(inner.func).endswith(("create_engine", "create_async_engine", "MongoClient", "psycopg2.connect", "psycopg.connect")):
                            self.add(sf, "DATA008", inner.lineno, "A database client or engine is created on every request.")
            if isinstance(node, ast.Assign) or isinstance(node, ast.AnnAssign):
                target = ast.unparse(node.targets[0] if isinstance(node, ast.Assign) else node.target)
                value = node.value
                if value is not None and re.fullmatch(MONEY, target.split(".")[-1], re.I) and isinstance(value, ast.Call) and \
                        re.search(r"\b(?:FloatField|Float|Column\(\s*(?:sa\.|db\.)?Float|mapped_column\(\s*(?:sa\.)?Float)\b", ast.unparse(value)):
                    self.add(sf, "DATA004", node.lineno, f"`{target}` stores money as a floating-point number.")

    @staticmethod
    def _persisted(node: ast.AST, parents: Dict[int, ast.AST]) -> bool:
        """The value is stored, compared or used as a default, so its missing time zone matters."""
        parent = parents.get(id(node))
        if isinstance(parent, (ast.Compare, ast.keyword)):
            return not isinstance(parent, ast.keyword) or parent.arg in ("default", "default_factory", "server_default", "onupdate")
        if isinstance(parent, ast.BinOp):
            parent = parents.get(id(parent))  # now() + timedelta(...) is usually an expiry
        if isinstance(parent, (ast.Assign, ast.AnnAssign, ast.keyword)):
            target = ast.unparse(parent.targets[0]) if isinstance(parent, ast.Assign) else (
                ast.unparse(parent.target) if isinstance(parent, ast.AnnAssign) else str(parent.arg))
            return bool(re.search(r"(?i)(?:_at|expires?\w*|expiry|deadline|timestamp|valid_until|created|updated)$", target))
        return False

    @staticmethod
    def _memory_db(node: ast.Call) -> bool:
        return ":memory:" in ast.unparse(node)

    @staticmethod
    def _walk_body(body):
        todo = list(body)
        while todo:
            n = todo.pop()
            yield n
            for child in ast.iter_child_nodes(n):
                if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                    todo.append(child)

    # --------------------------------------------------------- javascript
    def _javascript(self, sf: SourceFile, serverless: bool) -> None:
        v = sf.cache.get("views")
        if v is None:
            return
        code, bare = v.code, v.bare  # type: ignore[attr-defined]
        reported: Set[int] = set()
        for m in finditer(JS_LOOP, bare):
            open_paren = bare.find("(", m.start())
            if m.group(0).startswith(("for", "while")):
                close = match_close(bare, open_paren)
                brace = bare.find("{", close)
                if close < 0 or brace < 0 or bare[close + 1:brace].strip():
                    continue
                end = match_close(bare, brace)
                span = (brace, end)
            else:
                end = match_close(bare, open_paren)
                span = (open_paren, end)
            if span[1] < 0:
                continue
            q = JS_QUERY.search(code, span[0], span[1])
            if q and sf.line_at(q.start()) not in reported:
                reported.add(sf.line_at(q.start()))
                self.add(sf, "DATA001", sf.line_at(q.start()), "Database call runs once per loop iteration.")
        # a full user record fetched without a field selection and sent to the client
        for m in finditer(r"\b(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*await\s+(?:[\w$.]*\.)?(\w+)\s*\.\s*(findUnique|findFirst|findOne|findById|findByPk)\s*\(", bare):
            name, model = m.group(1), m.group(2)
            if not SENSITIVE_MODEL.match(model):
                continue
            close = match_close(bare, m.end() - 1)
            if close < 0:
                continue  # unbalanced call (malformed code)
            args = code[m.end():close]
            if re.search(r"\bselect\s*:|\bomit\s*:|\.select\s*\(|\battributes\s*:|\bprojection\b|['\"]-\w", args + code[close:close + 60]):
                continue
            ret = re.search(r"(?:res\s*\.\s*(?:json|send)|(?:Next)?Response\s*\.\s*json|return)\s*\(?\s*\{?\s*(?:\w+\s*:\s*)?" + re.escape(name) + r"\s*[}),;]",
                            code[close:close + 3000])
            if ret:
                self.add(sf, "DATA002", sf.line_at(m.start()),
                         f"The whole `{model}` record (including password hashes or tokens) is returned without selecting fields.")
        for m in finditer(r"\bnew\s+PrismaClient\s*\(", bare):
            before = code[max(0, m.start() - 400):m.start()]
            if re.search(r"globalThis|global\.|globalForPrisma", before + code[m.end():m.end() + 200]):
                continue
            if self._inside_function(bare, m.start()):
                self.add(sf, "DATA008", sf.line_at(m.start()), "A PrismaClient is created inside a function; each call opens new connections.")
        if serverless:
            for m in finditer(r"""new\s+(?:Database|sqlite3\.Database)\s*\(\s*['"`](?!:memory:)[^'"`]+['"`]|\brequire\s*\(\s*['"]better-sqlite3['"]\)|from\s+['"]better-sqlite3['"]""", code):
                self.add(sf, "DATA009", sf.line_at(m.start()), "SQLite file database on a serverless host; the file is lost between requests.")
                break

    @staticmethod
    def _inside_function(bare: str, pos: int) -> bool:
        depth = 0
        for k in range(pos, -1, -1):
            ch = bare[k]
            if ch == "}":
                depth += 1
            elif ch == "{":
                if depth == 0:
                    head = bare[max(0, k - 200):k]
                    return bool(re.search(r"(?:=>|\))\s*$", head.rstrip()) or re.search(r"\bfunction\b[^{]*$", head))
                depth -= 1
        return False

    # ------------------------------------------------------- sql / prisma
    def _sql(self, sf: SourceFile) -> None:
        text = sf.text or ""
        clean = re.sub(r"--[^\n]*|/\*[\s\S]*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
        migration = bool(re.search(r"(?i)(?:^|/)(?:migrations?|migrate|db/migrate|alembic|versions)(?:/|$)", sf.rel))
        for m in finditer(r"(?i)\b(drop\s+table|drop\s+column|truncate(?:\s+table)?|alter\s+column\s+\S+\s+(?:set\s+data\s+)?type)\b", clean):
            if migration and not re.search(r"(?i)\bdown\b|rollback|revert", sf.rel):
                self.add(sf, "DATA003", sf.line_at(m.start()), f"Migration runs `{m.group(1).upper()}`, which destroys data irreversibly.")
        for m in finditer(r"(?i)\b(" + MONEY + r")\b\s+(float4?|float8|real|double\s+precision|double)\b", clean):
            self.add(sf, "DATA004", sf.line_at(m.start()), f"Column `{m.group(1)}` stores money as `{m.group(2).upper()}`.")
        # only column definitions: `SELECT created_at timestamp` is an alias, not a column type
        for st in finditer(r"(?i)\b(?:create\s+(?:(?:temp|temporary|unlogged)\s+)?table|alter\s+table)\b[^;]*", clean):
            for m in NAIVE_COLUMN.finditer(clean, st.start(), st.end()):
                self.add(sf, "DATA006", sf.line_at(m.start()), f"Column `{m.group(1)}` is a timestamp without time zone.")
        for m in finditer(r"(?is)\bcreate\s+policy\s+(?:\"[^\"]*\"|\w+)\s+on\s+((?:\"?\w+\"?\.)?\"?\w+\"?)([^;]*);", clean):
            body = m.group(2)
            cmd = re.search(r"(?i)\bfor\s+(all|select|insert|update|delete)\b", body)
            table = m.group(1).replace('"', "")
            if cmd and cmd.group(1).lower() == "select" and re.search(r"(?i)\busing\s*\(\s*true\s*\)", body) and SENSITIVE_TABLE.search(table) \
                    and not re.search(r"(?i)\bto\s+(?:authenticated|service_role)\b", body):
                self.add(sf, "DATA005", sf.line_at(m.start()), f"Everyone (including anonymous visitors) can read every row of `{table}`.")

    def _prisma(self, sf: SourceFile) -> None:
        for m in finditer(r"(?m)^[ \t]*(" + MONEY + r")[ \t]+Float\b", sf.text or ""):
            self.add(sf, "DATA004", sf.line_at(m.start()), f"Field `{m.group(1)}` stores money as Float.")

    # ---------------------------------------------------- env documentation
    def _env_parity(self) -> None:
        examples = _example_env_files(self.p)
        if not examples:
            return
        by_dir: Dict[str, Set[str]] = {}
        for f in examples:
            folder = f.rel.rsplit("/", 1)[0] if "/" in f.rel else ""
            by_dir.setdefault(folder, set()).update(
                re.findall(r"(?m)^[ \t]*(?:export[ \t]+)?#?[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=", f.text or ""))
        names = {k: [f.rel for f in examples if (f.rel.rsplit("/", 1)[0] if "/" in f.rel else "") == k][0] for k in by_dir}

        def example_for(rel: str):
            parts = rel.split("/")[:-1]
            edge = rel.startswith("supabase/functions/") or "/supabase/functions/" in rel
            while True:
                key = "/".join(parts)
                if key in by_dir and (not edge or "supabase" in key):
                    return key
                if not parts:
                    return None
                parts.pop()

        seen: Set[str] = set()
        pattern = re.compile(
            r"""\bos\.(?:environ\s*(?:\.get\s*\(|\[)|getenv\s*\()\s*['"]([A-Z][A-Z0-9_]+)['"]"""
            r"""|\bprocess\.env\.([A-Z][A-Z0-9_]+)\b(?!\s*(?:\|\||\?\?))|\bprocess\.env\[\s*['"]([A-Z][A-Z0-9_]+)['"]\s*\](?!\s*(?:\|\||\?\?))"""
            r"""|\bimport\.meta\.env\.([A-Z][A-Z0-9_]+)\b|\bDeno\.env\.get\(\s*['"]([A-Z][A-Z0-9_]+)['"]""")
        for sf in self.p.files:
            if sf.kind not in ("py", "js") or sf.is_test or sf.text is None:
                continue
            v = sf.cache.get("views")
            code = v.code if v is not None else sf.text  # type: ignore[attr-defined]
            for m in finditer(pattern, code):
                name = next(g for g in m.groups() if g)
                after = code[m.end():m.end() + 40]
                if re.match(r"\s*,", after) or re.match(r"\s*[)\]]?\s*(?:==|!=|===|!==|\bor\b|\bin\b)", after):
                    continue  # a default, a fallback or a comparison: a missing value cannot crash the app
                bare_name = re.sub(r"^(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|PUBLIC_)", "", name)
                folder = example_for(sf.rel)
                if folder is None or name in by_dir[folder] or name in seen or PLATFORM_ENV.match(bare_name) or OPTIONAL_FLAG.search(bare_name):
                    continue
                seen.add(name)
                self.add(sf, "DATA007", sf.line_at(m.start()),
                         f"`{name}` is read from the environment but is not in {names[folder]}.")

    # ------------------------------------------------------- transactions
    def _transactions(self) -> None:
        for r in self.routes:
            body = r.body
            # writes through a transaction client (`tx.order.create`, `trx(...)`) are inside a transaction
            # even when the code that opened it is not visible here
            if re.search(r"\$transaction|\.transaction\s*\(|\btransaction\.atomic\b|@atomic\b|\bBEGIN\b|\bbatch\s*\(|\.begin\s*\("
                         r"|\bawait\s+(?:tx|trx|transaction)\s*[.(]", body):
                continue
            if r.lang == "py" and self.atomic_requests:
                continue  # Django ATOMIC_REQUESTS wraps every view in a transaction
            models = self._py_write_models(body) if r.lang == "py" else self._js_write_models(body)
            # writes to two different models (tables) need to succeed or fail together
            if len(set(models)) >= 2:
                sf = self.p.get(r.file)
                if sf is not None:
                    self.add(sf, "DATA010", r.line, f"{'/'.join(r.methods)} {r.path} makes several writes without a transaction.")

    @property
    def atomic_requests(self) -> bool:
        return any(f.kind == "py" and re.search(r"ATOMIC_REQUESTS['\"]?\s*[:=]\s*True", f.text or "") for f in self.p.files)

    @staticmethod
    def _js_write_models(body: str) -> List[str]:
        """The model or table each write in a handler goes to: prisma.order.create -> order, Order.create -> order,
        db.insert(orders) -> orders (Drizzle), order.save() -> order (Mongoose), supabase.from('orders').insert -> orders."""
        out: List[str] = []
        for w in re.finditer(JS_WRITE, body):
            parts = re.sub(r"\s", "", w.group(0))[len("await"):].rstrip("(").split(".")
            method, owner = parts[-1], [p for p in parts[:-1] if p]
            if owner and API_CLIENTS.match(owner[0]):
                continue  # openai.embeddings.create, stripe.checkout.sessions.create: API calls, not database writes
            if method in ("insert", "update", "delete"):
                arg = re.match(r"\s*([A-Za-z_$][\w$]*)\s*\)", body[w.end():w.end() + 80])
                if arg:
                    out.append(arg.group(1).lower())
                    continue
            if owner and owner[-1] not in ("session", "req", "res", "this"):
                out.append(owner[-1].lower())
        out += [m.group(1).lower() for m in re.finditer(r"""\.from\(\s*['"`](\w+)['"`]\s*\)\s*\.\s*(?:insert|update|upsert|delete)\s*\(""", body)]
        return out

    @staticmethod
    def _py_write_models(body: str) -> List[str]:
        """Django ORM writes (autocommit: each is its own transaction) and supabase-py table writes."""
        out = [m.group(1).lower() for m in re.finditer(r"\b([A-Z]\w*)\.objects\.(?:create|bulk_create|get_or_create|update_or_create)\s*\(", body)]
        out += [m.group(1).lower() for m in re.finditer(r"""\.table\(\s*['"](\w+)['"]\s*\)\s*\.\s*(?:insert|update|upsert|delete)\s*\(""", body)]
        return out
