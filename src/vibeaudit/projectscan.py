"""Project-wide checks: config files, deployment, database rules, routes/auth and missing tests or CI."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable, Dict, List, Optional

from . import heuristics as H
from .guard import GUARD, finditer
from .files import ENV_EXAMPLE_RE, ENV_FILE_RE, TEST_PATH_RE, Project, SourceFile, read_ignore_file, _matches
from .lexer import py_views
from .model import Finding, Route

Emit = Callable[[Finding], None]

LOCKS = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock", "npm-shrinkwrap.json")
PY_LOCKS = ("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock", "requirements.lock")
CI_FILES = re.compile(
    r"^(?:\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|\.circleci/config\.ya?ml|azure-pipelines\.ya?ml|Jenkinsfile"
    r"|bitbucket-pipelines\.ya?ml|\.travis\.ya?ml|\.drone\.ya?ml|\.buildkite/.+|cloudbuild\.ya?ml|\.woodpecker\.ya?ml)$"
)
TEST_CONFIG = re.compile(r"(?:^|/)(?:pytest\.ini|tox\.ini|jest\.config\.[\w.]+|vitest\.config\.[\w.]+|playwright\.config\.[\w.]+|cypress\.config\.[\w.]+|karma\.conf\.js)$")
DEFAULT_DB_PW = re.compile(
    r"(?i)\b(?:POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|MARIADB_ROOT_PASSWORD"
    r"|REDIS_PASSWORD|RABBITMQ_DEFAULT_PASS|PGPASSWORD|DB_PASSWORD)\s*[:=]\s*['\"]?(postgres|password|example|admin|root"
    r"|secret|123456|12345678|changeme|pass|mysql|mongo|test)['\"]?\s*$"
)
SECRET_ENV_NAME = re.compile(r"(?i)(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)")
UNTRUSTED_EXPR = re.compile(
    r"\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|discussion_comment|head_commit|commits|pages|workflow_run)"
    r"[\w.\[\]*]*\.(?:title|body|message|name|label|ref|head_ref|default_branch|email|description|page_name)"
    r"|github\.head_ref)\s*\}\}"
)


class ProjectScanner:
    def __init__(self, project: Project, emit: Emit, routes: List[Route]):
        self.p = project
        self.emit = emit
        self.routes = routes
        texts = []
        for f in project.files:
            if f.kind in ("py", "js", "html"):
                views = f.cache.get("views")
                texts.append(views.code if views is not None else (f.text or ""))  # type: ignore[attr-defined]
            elif f.rel.endswith(("package.json", "requirements.txt", "pyproject.toml")):
                texts.append(f.text or "")
        self.all_code = "\n".join(texts)

    def add(self, sf_or_rel, line: int, rule: str, msg: str, sev: str = "") -> None:
        sf = self.p.get(sf_or_rel) if isinstance(sf_or_rel, str) else sf_or_rel
        rel = sf.rel if sf else str(sf_or_rel)
        snippet = sf.line(line).strip() if sf and line else ""
        self.emit(Finding(rule, rel, line, msg, sev, snippet[:200]))

    def run(self) -> None:
        for sf in self.p.files:
            if sf.text is not None:
                GUARD.run(sf.rel, "configuration checks", self._file, sf)
        for step in (self.supabase_sql, self.env_files, self.lockfiles, self.tests_and_ci, self.express_headers, self.route_checks):
            GUARD.run("<project>", step.__name__.replace("_", " "), step)

    def _file(self, sf: SourceFile) -> None:
        k = sf.kind
        name = sf.rel.rsplit("/", 1)[-1]
        if k == "docker":
            self.dockerfile(sf)
        elif k == "compose":
            self.compose(sf)
        elif k == "workflow":
            self.workflow(sf)
        elif k == "sql":
            pass  # handled together below
        elif k == "rules" or name == "database.rules.json":
            self.firebase(sf)
        if name in (".mcp.json", "mcp.json", "claude_desktop_config.json", "mcp_config.json") or sf.rel.endswith((".cursor/mcp.json", ".vscode/mcp.json")):
            self.mcp(sf)
        if name == "package.json":
            self.package_json(sf)
        if k == "py" and not sf.is_test:
            code = sf.cache.get("views") or py_views(sf.text)
            for m in finditer(H.DANGEROUS_AGENT_OPTIONS, code.code):  # type: ignore[attr-defined]
                if code.bare[m.start()] != code.code[m.start()]:  # type: ignore[attr-defined]
                    continue  # inside a string literal
                self.add(sf, sf.line_at(m.start()), "LLM006", f"Dangerous agent option: {m.group(0).strip()[:60]}")

    # ------------------------------------------------------------- docker
    def dockerfile(self, sf: SourceFile) -> None:
        lines = sf.lines
        stages: List[str] = []
        last_from = 0
        has_user = False
        for i, raw in enumerate(lines, 1):
            line = raw.strip()
            m = re.match(r"(?i)^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", line)
            if m:
                image, alias = m.group(1), m.group(2)
                last_from = i
                has_user = False
                if image.lower() != "scratch" and image not in stages and "$" not in image:
                    if "@sha256:" not in image:
                        tag = image.rsplit("/", 1)[-1]
                        if ":" not in tag:
                            self.add(sf, i, "CFG002", f"Base image `{image}` has no tag (implicitly latest).")
                        elif tag.endswith(":latest"):
                            self.add(sf, i, "CFG002", f"Base image `{image}` uses the latest tag.")
                if alias:
                    stages.append(alias)
                continue
            if re.match(r"(?i)^USER\s+(?!root\b|0\b)\S+", line):
                has_user = True
            m = re.match(r"(?i)^(?:ENV|ARG)\s+(\w+)(?:\s*=\s*|\s+)(['\"]?)([^\s'\"$][^\s'\"]*)\2", line)
            if m and SECRET_ENV_NAME.search(m.group(1)) and not H.PLACEHOLDER.search(m.group(3)) and len(m.group(3)) >= 6:
                self.add(sf, i, "CFG003", f"{m.group(1)} is baked into the image.")
            if re.match(r"(?i)^(?:COPY|ADD)\s+(?:--\S+\s+)*\.\s+\S+", line):
                ctx = sf.path.parent
                envs = [p for p in ctx.glob(".env*") if p.is_file() and not ENV_EXAMPLE_RE.search(p.name)]
                ignore = read_ignore_file(ctx / ".dockerignore")
                if envs and not any(_matches(e.name, [p for p in ignore if not p.startswith("!")]) for e in envs):
                    self.add(sf, i, "CFG009", f"`{line[:60]}` copies {envs[0].name} into the image (no .dockerignore entry).")
        image_line = lines[last_from - 1] if last_from else ""
        if last_from and not has_user and not re.search(r"(?i)nonroot|distroless.*:nonroot|scratch", image_line):
            self.add(sf, last_from, "CFG001", "The final image never switches to a non-root USER.")

    def compose(self, sf: SourceFile) -> None:
        for i, line in enumerate(sf.lines, 1):
            m = DEFAULT_DB_PW.search(line.strip().lstrip("- "))
            if m:
                self.add(sf, i, "CFG007", f"Default database password `{m.group(1)}`.")

    def workflow(self, sf: SourceFile) -> None:
        lines = sf.lines
        in_run = False
        run_indent = 0
        for i, raw in enumerate(lines, 1):
            stripped = raw.lstrip()
            indent = len(raw) - len(stripped)
            m = re.match(r"(?:-\s+)?(run|script):\s*(.*)$", stripped)
            if m:
                in_run = True
                run_indent = indent
                content = m.group(2)
            elif in_run and (indent > run_indent or not stripped):
                content = stripped
            else:
                in_run = False
                content = ""
            if in_run and UNTRUSTED_EXPR.search(content):
                self.add(sf, i, "CFG004", "Untrusted event data is expanded directly inside a script.")
        text = sf.text or ""
        if re.search(r"(?m)^\s*(?:on:\s*.*\bpull_request_target\b|pull_request_target\s*:|-\s*pull_request_target\b)", text) or re.search(r"(?m)^on:\s*\[?[^\n]*pull_request_target", text):
            for m in finditer(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs/pull/", text):
                self.add(sf, sf.line_at(m.start()), "CFG005", "pull_request_target workflow checks out the pull request's code.")

    # ---------------------------------------------------------- firebase
    def firebase(self, sf: SourceFile) -> None:
        text = sf.text or ""
        if sf.rel.endswith(".json"):
            for m in finditer(r"\"\.(read|write)\"\s*:\s*(?:true|\"true\")", text):
                self.add(sf, sf.line_at(m.start()), "AUTH007", f"Realtime Database rule allows {m.group(1)} for everyone.",
                         "critical" if m.group(1) == "write" else "high")
            return
        clean = re.sub(r"//[^\n]*", lambda m: " " * len(m.group(0)), text)
        for m in finditer(r"\ballow\s+([\w,\s]+?)\s*(?::\s*if\s+true\s*;|;)", clean):
            ops = m.group(1)
            sev = "critical" if re.search(r"write|create|update|delete", ops) else "high"
            self.add(sf, sf.line_at(m.start()), "AUTH007", f"Rule `allow {ops.strip()}` applies to everyone.", sev)
        for m in finditer(r"request\.time\s*<\s*timestamp\.date\s*\(", clean):
            self.add(sf, sf.line_at(m.start()), "AUTH007", "Test-mode rule: the database is open to everyone until the date passes.", "critical")

    # ---------------------------------------------------------- supabase
    def supabase_sql(self) -> None:
        sql_files = self.p.of_kind("sql")
        if not sql_files:
            return
        joined = "\n".join(f.text or "" for f in sql_files)
        uses_supabase = bool(re.search(r"supabase", self.all_code, re.I)) or any("supabase" in f.rel for f in sql_files) \
            or re.search(r"auth\.uid\(\)|auth\.users", joined)
        if not uses_supabase:
            return

        def norm(name: str) -> str:
            name = name.replace('"', "").lower()
            return name if "." in name else "public." + name

        created: Dict[str, tuple] = {}
        rls = set()
        for sf in sql_files:
            text = sf.text or ""
            clean = re.sub(r"--[^\n]*|/\*[\s\S]*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
            for m in finditer(r"(?i)\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?((?:\"?\w+\"?\.)?\"?\w+\"?)", clean):
                created.setdefault(norm(m.group(1)), (sf, sf.line_at(m.start())))
            for m in finditer(r"(?i)\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?((?:\"?\w+\"?\.)?\"?\w+\"?)\s+(enable|disable|force)\s+row\s+level\s+security", clean):
                if m.group(2).lower() == "disable":
                    self.add(sf, sf.line_at(m.start()), "AUTH005", f"Row Level Security is disabled on {norm(m.group(1))}.")
                else:
                    rls.add(norm(m.group(1)))
            for m in finditer(r"(?is)\bcreate\s+policy\s+(?:\"[^\"]*\"|\w+)\s+on\s+((?:\"?\w+\"?\.)?\"?\w+\"?)(.*?);", clean):
                body = m.group(2)
                cmd = re.search(r"(?i)\bfor\s+(all|select|insert|update|delete)\b", body)
                cmd_name = cmd.group(1).lower() if cmd else "all"
                if cmd_name != "select" and re.search(r"(?i)\b(?:using|with\s+check)\s*\(\s*true\s*\)", body):
                    self.add(sf, sf.line_at(m.start()), "AUTH006", f"Policy on {norm(m.group(1))} allows {cmd_name.upper()} for every row (true).")
        for table, (sf, line) in created.items():
            if table.startswith("public.") and table not in rls:
                self.add(sf, line, "AUTH005", f"Table {table} is created without enabling Row Level Security.")

    # --------------------------------------------------------------- mcp
    def mcp(self, sf: SourceFile) -> None:
        try:
            data = json.loads(sf.text or "")
        except ValueError:
            return
        if not isinstance(data, dict):
            return
        nested = data.get("mcp")
        servers = data.get("mcpServers") or data.get("servers") or (nested.get("servers") if isinstance(nested, dict) else None)
        if not isinstance(servers, dict):
            return
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            cmd = str(cfg.get("command", ""))
            raw_args = cfg.get("args")
            args = [str(a) for a in raw_args if isinstance(a, (str, int))] if isinstance(raw_args, list) else []
            if cmd.rsplit("/", 1)[-1] not in ("npx", "bunx", "pnpx", "uvx", "pipx", "dlx") and not (cmd in ("pnpm", "yarn") and "dlx" in args):
                continue
            pkgs = [a for a in args if not a.startswith("-") and a not in ("dlx", "run")]
            if not pkgs:
                continue
            pkg = pkgs[0]
            if cmd.endswith(("uvx", "pipx")):
                pinned = re.search(r"==|@\d", pkg)
            else:
                pinned = re.search(r"^(?:@[^/]+/)?[^@]+@\d", pkg)
            if not pinned:
                line = next((i for i, ln in enumerate(sf.lines, 1) if f'"{pkg}"' in ln), 1)
                self.add(sf, line, "DEP007", f"MCP server `{name}` runs `{pkg}` without a pinned version.")

    def package_json(self, sf: SourceFile) -> None:
        try:
            data = json.loads(sf.text or "")
        except ValueError:
            return
        scripts = data.get("scripts") if isinstance(data, dict) else None
        if not isinstance(scripts, dict):
            return
        for key in ("preinstall", "install", "postinstall", "prepare"):
            val = str(scripts.get(key, ""))
            if re.search(r"\b(?:curl|wget|iwr|Invoke-WebRequest)\b", val) and re.search(r"\|\s*(?:ba|z)?sh\b|\|\s*node\b|\biex\b|eval", val):
                line = next((i for i, ln in enumerate(sf.lines, 1) if f'"{key}"' in ln), 1)
                self.add(sf, line, "DEP006", f"`{key}` script downloads and executes remote code.")

    # ---------------------------------------------------------- env files
    def env_files(self) -> None:
        root = self.p.root
        candidates = set()
        for f in self.p.files:
            if ENV_FILE_RE.search(f.rel) and not ENV_EXAMPLE_RE.search(f.rel):
                candidates.add(f.rel)
        if not self.p.is_git:
            for path in root.glob("**/.env*"):
                rel = path.relative_to(root).as_posix()
                if path.is_file() and ENV_FILE_RE.search(rel) and not ENV_EXAMPLE_RE.search(rel) and "node_modules" not in rel:
                    candidates.add(rel)
        for rel in sorted(candidates):
            if self.p.is_git:
                if rel in self.p.tracked and self._has_secret_value(rel):
                    self.add(rel, 0, "SEC006", f"{rel} is tracked by git and contains secret values.")
                elif rel in self.p.untracked:
                    self.add(rel, 0, "SEC007", f"{rel} is not covered by .gitignore.")
            else:
                from .files import gitignore_covers
                if not gitignore_covers(root, rel):
                    self.add(rel, 0, "SEC007", f"{rel} is not covered by .gitignore.")

    def _has_secret_value(self, rel: str) -> bool:
        """Committed .env templates with empty or placeholder values are fine; real values are not."""
        sf = self.p.get(rel)
        for line in (sf.text if sf and sf.text else "").splitlines():
            m = re.match(r"\s*(?:export\s+)?([A-Za-z0-9_]+)\s*=\s*(.*)", line)
            if not m:
                continue
            value = m.group(2).split(" #")[0].strip().strip("'\"")
            if value and not H.PLACEHOLDER.search(value) and (H.SECRET_NAME.search(m.group(1)) or H.looks_random(value)):
                if value.lower() not in ("true", "false", "localhost", "postgres", "password", "admin", "root"):
                    return True
        return False

    def lockfiles(self) -> None:
        for f in self.p.files:
            name = f.rel.rsplit("/", 1)[-1]
            d = f.path.parent
            if name == "package.json" and not f.is_test:
                try:
                    data = json.loads(f.text or "")
                except ValueError:
                    continue
                deps = data.get("dependencies") if isinstance(data, dict) else None
                if isinstance(deps, dict) and deps and not any((d / lk).exists() for lk in LOCKS):
                    if not any((p / lk).exists() for p in d.parents for lk in LOCKS if self.p.root in (p, *p.parents)):
                        self.add(f, 1, "DEP005", "package.json has dependencies but no lockfile is committed.")
            elif re.fullmatch(r"requirements[\w.-]*\.txt", name) and not f.is_test:
                reqs = [ln.strip() for ln in f.lines if ln.strip() and not ln.strip().startswith(("#", "-"))]
                unpinned = [r for r in reqs if "==" not in r and "@" not in r]
                if reqs and len(unpinned) * 2 > len(reqs) and not any((d / lk).exists() for lk in PY_LOCKS):
                    self.add(f, 1, "DEP005", f"{len(unpinned)} of {len(reqs)} requirements are not pinned to an exact version.")

    def tests_and_ci(self) -> None:
        sources = [f for f in self.p.files if f.kind in ("py", "js") and not f.is_test and not re.search(r"\.config\.[cm]?[jt]s$|(?:^|/)(?:setup|conftest|manage)\.py$", f.rel)]
        if len(sources) < 3:
            return
        has_tests = any(f.is_test and f.kind in ("py", "js") and not re.search(r"(?:^|/)(?:fixtures?|mocks?|__mocks__|testdata)/", f.rel) for f in self.p.files) \
            or any(TEST_CONFIG.search(f.rel) for f in self.p.files)
        anchor = self.p.anchor()
        if not has_tests:
            self.add(anchor, 1, "QA001", f"No test files found for {len(sources)} source files.")
        if not any(CI_FILES.match(f.rel) for f in self.p.files):
            self.add(anchor, 1, "QA002", "No CI configuration found.")

    def express_headers(self) -> None:
        deps = self.p.all_js_deps()
        if "express" not in deps or "helmet" in deps:
            return
        for f in self.p.files:
            if f.kind == "js" and not f.is_test and f.text and re.search(r"\bexpress\s*\(\s*\)", f.text):
                m = re.search(r"\bexpress\s*\(\s*\)", f.text)
                self.add(f, f.line_at(m.start()), "CFG008", "Express app created without helmet().")
                return

    # -------------------------------------------------------------- routes
    def route_checks(self) -> None:
        rate_limited = bool(H.RATE_LIMIT_EVIDENCE.search(self.all_code))
        reads_body: Optional[Route] = None
        for r in self.routes:
            path = r.path
            public = bool(H.PUBLIC_PATH.search(path)) or H.CUSTOM.is_public(path)
            # PUT/PATCH/DELETE change state by definition; POST and catch-all handlers are often reads, so they
            # need evidence of a write (or a paid model call) before we call them state-changing.
            semantic = any(m in ("PUT", "PATCH", "DELETE") for m in r.methods) and r.framework not in ("next-server-action",)
            writes = semantic or bool(H.MUTATION_EVIDENCE.search(r.body))
            mutating = r.mutating and (writes or r.calls_llm)
            is_admin = bool(re.search(r"(?i)(?:^|/)admin(?:/|$|[-_])", path) or re.search(r"(?i)(?:^|/)admin(?:/|\.|$)", r.file))
            if H.WEBHOOK_PATH.search(path):
                if not H.WEBHOOK_VERIFY.search(r.body):
                    self.add(r.file, r.line, "AUTH004", f"Webhook {path} does not verify the sender's signature.")
            elif is_admin and not H.ADMIN_ROLE_EVIDENCE.search(r.body):
                msg = "has no authentication or role check" if not r.has_auth else "checks login but not the admin role"
                self.add(r.file, r.line, "AUTH002", f"{'/'.join(r.methods)} {path} {msg}.")
            elif mutating and not r.has_auth and not public:
                what = "has no authentication check" if writes else "calls a paid AI API without an authentication check"
                self.add(r.file, r.line, "AUTH001", f"{'/'.join(r.methods)} {path} {what}.")
            elif mutating and r.has_auth and r.params and r.methods != ["POST"]:
                id_params = [p for p in r.params if re.search(r"(?i)id$|^pk$|^slug$", p)]
                handler = r.body.split("\n", 1)[-1]
                without_params = re.sub(r"\b(?:" + "|".join(map(re.escape, r.params)) + r")\b", "_", r.body)
                if id_params and any(re.search(r"\b" + re.escape(p) + r"\b", handler) for p in id_params) \
                        and not H.OWNERSHIP_EVIDENCE.search(without_params):
                    self.add(r.file, r.line, "AUTH003", f"{'/'.join(r.methods)} {path} changes a record by id without checking that it belongs to the caller.")
            if r.calls_llm and not rate_limited:
                self.add(r.file, r.line, "LLM004", f"{path} calls a model and the project has no rate limiting.",
                         "medium" if r.has_auth else "high")
            if H.LOGIN_PATH.search(path) and r.mutating and not rate_limited and not H.WEBHOOK_PATH.search(path):
                self.add(r.file, r.line, "AUTH010", f"{path} has no rate limiting.")
            if r.reads_body and reads_body is None:
                reads_body = r
        if reads_body is not None:
            server_validation = any(
                H.SERVER_VALIDATION_EVIDENCE.search(f.text or "") for f in self.p.files
                if f.kind in ("py", "js") and not f.is_client and not f.is_test)
            if not server_validation:
                client = next((f.rel for f in self.p.files if f.is_client and H.CLIENT_VALIDATION.search(f.text or "")), None)
                extra = f" Validation exists only in browser code ({client})." if client else ""
                self.add(reads_body.file, reads_body.line, "BE018", "Request bodies are read without a server-side validation library." + extra)
