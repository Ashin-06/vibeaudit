"""Access-control checks added in 0.8.7: AUTH015-AUTH017 and FE008 (all preview).

AUTH015: a password change or reset that leaves the other sessions and refresh tokens valid.
AUTH016: a signed-in route that reads or changes a tenant-scoped table without filtering by tenant (extends AUTH003).
AUTH017: an admin or feature-flag endpoint that any signed-in user can call (no role check).
FE008: a server action that returns a server secret, or closes over one (Next.js sends closures to the client).
"""
from __future__ import annotations

import re
from typing import Callable, Dict, List, Set

from .files import Project, SourceFile
from .guard import GUARD, finditer
from .model import Route

Add = Callable[..., None]  # ProjectScanner.add(sf_or_rel, line, rule, message, severity="")

PASSWORD_ROUTE = re.compile(r"(?i)(?:reset|change|update|set|new|forgot)[-_/]?password|password[-_/]?(?:reset|change|update)")
PASSWORD_WRITE = re.compile(
    r"(?i)\bset_password\s*\(|\w{0,20}password\w{0,10}['\"]?\s*[:=]\s*(?:await\s+)?[\w.]{0,40}(?:hash|crypt|argon|make_password)"
    r"|\bpassword\s*[=:]\s*(?:body|data|payload|form|request|req|input|params|values)\w{0,10}\.\w{0,20}password"
    r"|\bupdateUser\s*\(\s*\{[^}]{0,200}\bpassword\b|\bupdate_user\s*\([^)]{0,200}\bpassword\b|\bupdatePassword\s*\(")
REVOKE = re.compile(
    r"(?i)(?:revoke|invalidat\w{0,10}|expire)\w{0,10}[ \t(._]{0,3}\w{0,20}(?:sessions?|tokens?|refresh|all)"
    r"|log_?out_?(?:all|other|everywhere)|sign_?out\s*\(\s*\{?\s*scope|delete\w*sessions?"
    # session records (a Session model, a sessions table or store), not an ORM's database session
    r"|(?-i:Session|Sessions|sessions|sessionStore|session_store|UserSession\w*)\s*\.\s*(?:delete\w*|destroy\w*|remove\w*)\s*\("
    r"|update_session_auth_hash|token_?version|password_?changed_?at|security_?stamp"
    r"|refresh_?tokens?\s*\.\s*(?:delete|destroy|remove)|deny_?list|block_?list|black_?list|logout_user|deleteMany\s*\(\s*\{\s*where\s*:\s*\{\s*userId")
# frameworks that drop the other sessions on a password change by themselves
SELF_REVOKING = re.compile(r"(?i)\bfrom\s+django\b|\bimport\s+django\b|firebase|@clerk/|next-auth.{0,40}database|\bdevise\b")

TENANT_COL = re.compile(r"(?i)\b(?:tenant|org|organi[sz]ation|team|workspace|company)_?id\b|\b(?:tenantId|orgId|organizationId|teamId|workspaceId|companyId)\b")
TENANT_WORD = re.compile(
    r"(?i)tenant|\borg(?:ani[sz]ation)?_?id\b|\borgId\b|organi[sz]ation|team_?id|teamId|workspace|company_?id|companyId"
    r"|current_?org|currentOrg|\.org\b|\.team\b|scoped|for_tenant|forTenant")
SQL_TABLE = re.compile(r"(?is)\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?:\"?\w+\"?\.)?\"?(\w+)\"?\s*\(([^;]{0,6000}?)\)\s*;")
PRISMA_MODEL = re.compile(r"(?m)^model\s+(\w+)\s*\{([^}]{0,6000})\}")
PY_MODEL = re.compile(r"(?m)^class\s+(\w+)\s*\([^)]*(?:Model|Base|SQLModel|Document)[^)]*\)\s*:\n((?:[ \t]+[^\n]*\n|[ \t]*\n){1,200})")
RLS = re.compile(r"(?i)enable\s+row\s+level\s+security")
DB_TOUCH = r"(?:find\w*|filter|get|all|select|update\w*|delete\w*|insert|create\w*|query|exec\w*|raw|aggregate|count)"

ADMIN_ROUTE = re.compile(r"(?i)/admin\b|/feature[-_]?flags?\b|/flags?\b|/toggles?\b|/maintenance\b|/site[-_]?settings\b")
ROLE_CHECK = re.compile(
    r"(?i)admin|\brole|is_?staff|is_?superuser|superuser|permission|\bcan\s*\(|authori[sz]e|ability|polic(?:y|ies)|has_?perm"
    r"|requireRole|require_role|is_?owner|isOwner|owner_?only|staff_?member_required|user_passes_test|\bscopes?\b|\bclaims?\b")

USE_SERVER_FILE = re.compile(r"""\A\s*(?:/\*[\s\S]*?\*/\s*|//[^\n]*\n\s*)*['"]use server['"]""")
SECRET_ENV = re.compile(r"\bprocess\.env\.(?!NEXT_PUBLIC_)(\w*(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE)\w*)")
RETURN_SECRET = re.compile(r"\breturn\b[^;\n]{0,200}?\bprocess\.env\.(?!NEXT_PUBLIC_)(\w*(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE)\w*)")
INLINE_ACTION = re.compile(r"""\b(?:async\s+function\s+\w+\s*\([^)]{0,200}\)|=\s*async\s*\([^)]{0,200}\)\s*=>)\s*\{\s*['"]use server['"]""")


def run(project: Project, routes: List[Route], add: Add) -> None:
    files = [f for f in project.files if f.text is not None and not f.is_test and not f.is_example]
    GUARD.run("<project>", "password changes", _password_changes, project, routes, add)
    GUARD.run("<project>", "tenant scoping", _tenant_scoping, project, files, routes, add)
    for r in routes:
        if ADMIN_ROUTE.search(r.path) and r.has_auth and not ROLE_CHECK.search(r.body) \
                and set(m.upper() for m in r.methods) & {"POST", "PUT", "PATCH", "DELETE"}:
            add(r.file, r.line, "AUTH017", f"{r.path} changes admin or feature-flag state, and any signed-in user can call it: "
                                           "nothing checks a role.")
    for sf in files:
        if sf.kind == "js":
            GUARD.run(sf.rel, "server action secrets", _server_actions, sf, add)


def _password_changes(project: Project, routes: List[Route], add: Add) -> None:
    code = "\n".join(f.text or "" for f in project.files if f.kind in ("py", "js") and not f.is_test)
    if SELF_REVOKING.search(code) or REVOKE.search(code):
        return  # sessions are dropped somewhere (or by the framework); per route that is too fine to tell
    for r in routes:
        if PASSWORD_ROUTE.search(r.path + " " + r.body[:300]) and PASSWORD_WRITE.search(r.body):
            add(r.file, r.line, "AUTH015", f"{r.path} sets a new password but keeps every existing session and refresh token "
                                           "valid, so whoever had the account stays signed in.")


def _tenant_tables(project: Project) -> Set[str]:
    tables: Set[str] = set()
    for sf in project.files:
        text = sf.text or ""
        if sf.kind == "sql" or sf.rel.endswith(".sql"):
            for m in finditer(SQL_TABLE, text):
                if TENANT_COL.search(m.group(2)):
                    tables.add(m.group(1).lower())
        elif sf.rel.endswith(".prisma"):
            for m in finditer(PRISMA_MODEL, text):
                if TENANT_COL.search(m.group(2)):
                    tables.add(m.group(1).lower())
        elif sf.kind == "py" and not sf.is_test:
            for m in finditer(PY_MODEL, text):
                if TENANT_COL.search(m.group(2)):
                    tables.add(m.group(1).lower())
    return tables


def _tenant_scoping(project: Project, files: List[SourceFile], routes: List[Route], add: Add) -> None:
    tables = _tenant_tables(project)
    if not tables:
        return
    rls = any(RLS.search(f.text or "") for f in project.files if f.rel.endswith(".sql"))
    names = "|".join(sorted(re.escape(t) for t in tables))
    touch = re.compile(
        r"(?i)(?:\b(?:%s)s?\s*\.\s*(?:objects\s*\.\s*)?%s\s*\(|\b(?:query|select|filter)\s*\(\s*(?:%s)\b"
        r"|\.from\s*\(\s*['\"`](?:%s)s?['\"`]\s*\)|\b(?:from|into|update)\s+\"?(?:%s)s?\"?\b)"
        % (names, DB_TOUCH, names, names, names))
    for r in routes:
        if not r.has_auth or TENANT_WORD.search(r.body):
            continue
        m = touch.search(r.body)
        if not m or (rls and ".from(" in m.group(0)):
            continue  # Supabase queries under row level security are filtered by the database
        add(r.file, r.line, "AUTH016", f"{r.path} queries a tenant-scoped table without filtering by tenant, so users "
                                       "can read or change other organizations' rows.")


def _server_actions(sf: SourceFile, add: Add) -> None:
    v = sf.cache.get("views")
    if v is None or "use server" not in (sf.text or ""):
        return
    code = v.code  # type: ignore[attr-defined]
    if USE_SERVER_FILE.search(sf.text or ""):
        for m in finditer(RETURN_SECRET, code):
            add(sf, sf.line_at(m.start()), "FE008", f"A server action returns `{m.group(1)}`; every client that calls it "
                                                    "receives the secret.")
    secrets: Dict[str, str] = {}
    for m in finditer(re.compile(r"\b(?:const|let)\s+(\w+)\s*=\s*process\.env\.(?!NEXT_PUBLIC_)(\w*(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE)\w*)"), code):
        secrets[m.group(1)] = m.group(2)
    if not secrets:
        return
    for m in finditer(INLINE_ACTION, code):
        brace = code.find("{", m.start())
        body = code[brace:brace + 2000]
        for name, env in secrets.items():
            if re.search(r"\b%s\b" % re.escape(name), body):
                add(sf, sf.line_at(m.start()), "FE008",
                    f"An inline server action closes over `{name}` ({env}); Next.js sends closed-over values to the "
                    "browser (encrypted) and back. Read the secret inside the action instead.")
                break
