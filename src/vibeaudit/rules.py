"""The rule catalog: every check vibeaudit can report, with why it matters and how to fix it."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

CATEGORIES = {
    "secrets": "Secrets",
    "supply-chain": "Dependencies and supply chain",
    "backend": "Backend security",
    "frontend": "Frontend security",
    "auth": "Authentication and authorization",
    "config": "Configuration and deployment",
    "llm": "LLM and AI-specific risks",
    "quality": "Code quality and tests",
    "llm-review": "LLM review (model-generated, unverified)",
    "data": "Data and database",
    "reliability": "Reliability and performance",
    "ui": "UI, UX and accessibility",
    "contracts": "Frontend-backend contracts",
    "custom": "Custom rules (plugins)",
}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    severity: str
    why: str
    fix: str
    cwe: str = ""
    owasp: str = ""
    # A preview rule is reported but does not count toward --fail-on or the score (unless --include-preview).
    # See STABILITY.md: new rules start as preview, and a rule can be moved back to preview with a reason.
    preview: bool = False
    preview_reason: str = ""


NEW_IN_071 = "New in 0.7.1: not yet measured on enough real-world findings in the benchmark."
NEW_IN_070 = "New in 0.7.0: not yet measured on enough real-world findings in the benchmark."

_R = [
    # ---------------------------------------------------------------- secrets
    Rule("SEC001", "Hardcoded API key or access token", "secrets", "critical",
         "A real credential is committed in source. Anyone with read access to the repo, a fork, a build log "
         "or the shipped bundle can use it, and bots scrape public repos for keys within minutes.",
         "Revoke and rotate the key now (deleting it from the file does not remove it from git history). "
         "Load it from an environment variable or a secret manager on the server only.",
         "CWE-798", "A07:2021"),
    Rule("SEC002", "Private key committed", "secrets", "critical",
         "A private key in the repository lets anyone impersonate the service or decrypt its traffic.",
         "Revoke the key, generate a new one, store it outside the repo (secret manager or mounted file) "
         "and purge it from git history.", "CWE-321", "A02:2021"),
    Rule("SEC003", "High-entropy secret assigned in code", "secrets", "high",
         "A variable named like a secret holds a random-looking literal. This is usually a real token "
         "pasted in while prototyping.",
         "Move the value to an environment variable or secret manager and rotate it if it was ever pushed.",
         "CWE-798", "A07:2021",
         preview=True,
         preview_reason="Benchmark precision 82% (9 of 11): public client keys and documented demo tokens look "
                       "like secrets."),
    Rule("SEC004", "Hardcoded or default signing secret", "secrets", "high",
         "Session cookies and JWTs are signed with this secret. If it is in the code, or falls back to a "
         "default when the env var is missing, anyone can forge a login as any user, including admins.",
         "Read the secret from the environment and fail at startup if it is missing. Never provide a "
         "fallback default. Generate it with a CSPRNG (for example `python -c \"import secrets; "
         "print(secrets.token_urlsafe(48))\"`).", "CWE-321", "A02:2021"),
    Rule("SEC005", "Database URL with embedded password", "secrets", "high",
         "A connection string for a remote database includes the password, giving direct database access "
         "to anyone who reads the code.",
         "Put the full URL in an environment variable (DATABASE_URL) and rotate the password.",
         "CWE-798", "A07:2021"),
    Rule("SEC006", "Environment file committed to git", "secrets", "high",
         ".env files hold the app's real secrets. Once committed they stay in git history even after "
         "deletion.",
         "Remove it with `git rm --cached .env`, add `.env*` (with `!.env.example`) to .gitignore, rotate "
         "every secret it contained, and commit a .env.example with placeholder values instead.",
         "CWE-538", "A05:2021"),
    Rule("SEC007", "Environment file not git-ignored", "secrets", "medium",
         "A .env file exists but .gitignore does not cover it, so the next `git add .` publishes every secret.",
         "Add `.env*` and `!.env.example` to .gitignore.", "CWE-538", "A05:2021"),
    Rule("SEC008", "Secret exposed to the browser through a public env var", "secrets", "critical",
         "Variables prefixed NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_, NUXT_PUBLIC_, PUBLIC_ or GATSBY_ are copied "
         "into the JavaScript bundle that every visitor downloads. A secret here is public.",
         "Rename the variable without the public prefix, use it only in server code (API route, server "
         "action, edge function), and rotate the key because it has already shipped.",
         "CWE-200", "A01:2021"),
    Rule("SEC009", "Supabase service_role key outside the server", "secrets", "critical",
         "The service_role key bypasses every Row Level Security policy. In client code or the repo it "
         "gives anyone full read and write access to the whole database.",
         "Use only the anon key in the browser. Keep service_role in server-only env vars, rotate it in the "
         "Supabase dashboard, and move privileged queries to an API route or edge function.",
         "CWE-798", "A01:2021"),
    Rule("SEC010", "Secret written to logs", "secrets", "medium",
         "Logs are copied to hosting dashboards, log services and screenshots. Printing a key leaks it there.",
         "Remove the log line or log only a masked prefix (first 4 characters).", "CWE-532", "A09:2021"),
    Rule("SEC011", "Hardcoded password", "secrets", "high",
         "A password literal in code (often an admin or database password) is shared with everyone who can "
         "read the repo and cannot be rotated without a deploy.",
         "Read it from an environment variable or secret manager. For user accounts, store only "
         "bcrypt/argon2 hashes.", "CWE-259", "A07:2021"),
    # ------------------------------------------------------------- supply chain
    Rule("DEP001", "Dependency does not exist on the registry", "supply-chain", "critical",
         "AI assistants regularly invent plausible package names. Attackers register those names "
         "(slopsquatting) so the next install runs their code.",
         "Remove the dependency or replace it with the real package you meant. If it is a private package, "
         "configure your private registry (.npmrc scope or pip --index-url) and suppress this finding.",
         "CWE-1357", "LLM03:2025"),
    Rule("DEP002", "Package name looks like a typo of a popular package", "supply-chain", "high",
         "Typosquatted packages copy a popular name with one character changed and ship malware in install "
         "scripts.",
         "Check the spelling against the official package. If this is the package you meant, suppress the "
         "finding.", "CWE-1357", "A06:2021"),
    Rule("DEP003", "Very new package", "supply-chain", "medium",
         "The package was first published only days ago. Freshly registered packages are how hallucinated "
         "names get weaponised.",
         "Confirm the package, its maintainer and its source repository before trusting it. Pin an exact "
         "version.", "CWE-1357", "A06:2021"),
    Rule("DEP004", "Dependency with known vulnerabilities", "supply-chain", "high",
         "The pinned version has published security advisories (from the OSV database).",
         "Upgrade to a fixed version listed in the advisory.", "CWE-1395", "A06:2021"),
    Rule("DEP005", "Dependencies are not locked", "supply-chain", "low",
         "Without a lockfile or pinned versions every install can pull a different, possibly compromised, "
         "version.",
         "Commit a lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock, uv.lock, poetry.lock) or pin "
         "exact versions in requirements.txt.", "CWE-1357", "A08:2021"),
    Rule("DEP006", "Install script downloads and runs remote code", "supply-chain", "high",
         "An npm lifecycle script fetches code from the network at install time, which bypasses lockfiles "
         "and review.",
         "Remove the script or vendor the downloaded file with a checksum.", "CWE-494", "A08:2021"),
    Rule("DEP007", "MCP server launched from an unpinned package", "supply-chain", "medium",
         "The agent config runs `npx -y` / `uvx` on a package without a version, so a malicious update "
         "gets code execution inside your AI assistant.",
         "Pin an exact version, for example `npx -y some-mcp-server@1.2.3`.", "CWE-1357", "LLM03:2025"),
    Rule("DEP008", "Extra package index (dependency confusion)", "supply-chain", "medium",
         "With --extra-index-url pip takes the highest version of a name from any index, so anyone who "
         "publishes your private package's name on PyPI with a higher version gets their code installed.",
         "Use a single index that proxies PyPI (--index-url), or pin each private package to its index "
         "(uv `[[tool.uv.index]]` with `explicit = true`) and use hashes.", "CWE-427", "A08:2021",
         preview=True, preview_reason=NEW_IN_070),
    # ---------------------------------------------------------------- backend
    Rule("BE001", "SQL injection", "backend", "high",
         "Building SQL with string formatting lets an attacker change the query: read other users' data, "
         "bypass login or drop tables.",
         "Use parameterized queries (`cursor.execute(\"... WHERE id = %s\", (id,))`, Prisma `$queryRaw` "
         "tagged templates, or the ORM query builder).", "CWE-89", "A03:2021"),
    Rule("BE002", "Command injection", "backend", "critical",
         "User-controlled data reaches a shell command, giving the attacker remote code execution on the "
         "server.",
         "Avoid the shell: pass an argument list (`subprocess.run([\"tool\", arg])`, `execFile`) and "
         "validate the input against an allow-list.", "CWE-78", "A03:2021"),
    Rule("BE003", "Dynamic code execution", "backend", "critical",
         "eval/exec/new Function runs strings as code. With attacker-influenced input it is remote code "
         "execution.",
         "Remove eval. Parse data with json.loads / JSON.parse or ast.literal_eval, and dispatch through an "
         "explicit allow-list of functions.", "CWE-95", "A03:2021"),
    Rule("BE004", "Unsafe deserialization", "backend", "high",
         "pickle, marshal, dill and yaml.load can execute code while loading. Loading untrusted data is "
         "remote code execution.",
         "Use JSON, or yaml.safe_load. Only unpickle files you created yourself and that nobody else can "
         "write.", "CWE-502", "A08:2021"),
    Rule("BE005", "Server-side request forgery (SSRF)", "backend", "high",
         "The server fetches a URL chosen by the user, which can reach internal services and cloud metadata "
         "endpoints (credentials).",
         "Allow-list hosts, block private and link-local IPs after DNS resolution, and do not follow "
         "redirects to other hosts.", "CWE-918", "A10:2021"),
    Rule("BE006", "Path traversal", "backend", "high",
         "A user-controlled path reaches the file system, so `../../etc/passwd` style input can read or "
         "overwrite any file.",
         "Use `secure_filename` / `path.basename`, resolve the final path and check it is inside the allowed "
         "directory.", "CWE-22", "A01:2021"),
    Rule("BE007", "Server-side template injection", "backend", "high",
         "Rendering a user-controlled string as a template executes template code on the server.",
         "Render a fixed template file and pass user data as variables.", "CWE-1336", "A03:2021"),
    Rule("BE008", "Open redirect", "backend", "medium",
         "Redirecting to a user-supplied URL lets phishing links borrow your domain.",
         "Only redirect to relative paths or an allow-list of hosts.", "CWE-601", "A01:2021"),
    Rule("BE009", "Mass assignment", "backend", "high",
         "The whole request body is written into a database model, so a user can set fields like `role`, "
         "`is_admin` or `credits` by adding them to the request.",
         "Copy only the allowed fields explicitly, or validate with a schema that whitelists fields.",
         "CWE-915", "A04:2021"),
    Rule("BE010", "NoSQL injection", "backend", "high",
         "Passing request values straight into a MongoDB query lets attackers send operators like "
         "`{\"$ne\": null}` and bypass login checks.",
         "Validate types with a schema (zod, joi) or cast to String, and use express-mongo-sanitize.",
         "CWE-943", "A03:2021"),
    Rule("BE011", "Debug mode enabled", "backend", "medium",
         "Debug mode shows stack traces, settings and (in Flask/Werkzeug) an interactive console that gives "
         "remote code execution.",
         "Drive debug from an environment variable that is off by default, and never deploy with it on.",
         "CWE-489", "A05:2021"),
    Rule("BE012", "Insecure CORS policy", "backend", "high",
         "Allowing any or a reflected origin together with credentials lets any website call your API as the "
         "logged-in user. (An open origin without credentials is not reported: no cookies are sent.)",
         "List the exact origins you trust. Never combine a wildcard or reflected origin with "
         "credentials.", "CWE-942", "A05:2021"),
    Rule("BE013", "TLS certificate verification disabled", "backend", "medium",
         "Turning off certificate checks allows man-in-the-middle attackers to read and change traffic, "
         "including API keys.",
         "Remove verify=False / rejectUnauthorized:false. Fix the certificate chain or pass a CA bundle.",
         "CWE-295", "A02:2021"),
    Rule("BE014", "Weak or plaintext password storage", "backend", "high",
         "Passwords compared in plaintext or hashed with fast hashes (MD5/SHA) are cracked in minutes after "
         "a database leak.",
         "Hash with bcrypt, scrypt or argon2 (passlib, bcrypt, argon2-cffi, bcryptjs) and compare with the "
         "library's verify function.", "CWE-916", "A02:2021"),
    Rule("BE015", "Insecure randomness for secrets", "backend", "medium",
         "random / Math.random are predictable. Tokens, OTPs and reset codes made with them can be guessed.",
         "Use `secrets.token_urlsafe()` in Python or `crypto.randomUUID()` / `crypto.randomBytes()` in "
         "JavaScript.", "CWE-338", "A02:2021"),
    Rule("BE016", "JWT signature not verified", "backend", "high",
         "Decoding a JWT without verifying its signature (or allowing alg none) means anyone can mint a "
         "token for any user.",
         "Use jwt.verify / jwt.decode with the secret and an explicit algorithms list, and keep expiry "
         "checks on.", "CWE-347", "A07:2021"),
    Rule("BE017", "Internal error details sent to the client", "backend", "low",
         "Stack traces and exception text reveal file paths, queries and library versions that help an "
         "attacker.",
         "Log the details on the server and return a generic error message with a request id.",
         "CWE-209", "A05:2021"),
    Rule("BE018", "No server-side input validation", "backend", "medium",
         "The backend reads request bodies but no validation library is used on the server. Validation done "
         "only in the browser is bypassed by calling the API directly.",
         "Validate every request body on the server with a schema (zod, valibot, joi, pydantic, "
         "marshmallow): types, lengths, ranges and allowed fields.", "CWE-602", "A04:2021",
         preview=True,
         preview_reason="Benchmark precision 67% (6 of 9): hand-written validation (type checks, 422 responses) is "
                       "not recognised, only known validation libraries."),
    # --------------------------------------------------------------- frontend
    Rule("FE001", "Cross-site scripting through a raw HTML sink", "frontend", "high",
         "Inserting unsanitized data as HTML (innerHTML, dangerouslySetInnerHTML, v-html, {@html}, |safe) "
         "lets an attacker run JavaScript in other users' browsers and steal their sessions.",
         "Render as text, or sanitize with DOMPurify (or bleach on the server) before inserting HTML.",
         "CWE-79", "A03:2021",
         preview=True,
         preview_reason="Benchmark precision 67% (20 of 30): the source of the HTML is often not visible in the "
                       "file (markdown from the repo, CMS content, constants), so trusted content is reported too."),
    Rule("FE002", "LLM or secret API called directly from the browser", "frontend", "critical",
         "Calling OpenAI, Anthropic, Gemini and similar APIs from client code ships the API key to every "
         "visitor, who can then run up your bill or abuse the account.",
         "Call the provider from a server route or edge function that holds the key, and have the browser "
         "call your own endpoint (with auth and rate limiting).", "CWE-522", "LLM02:2025"),
    Rule("FE003", "Authorization state kept in browser storage", "frontend", "high",
         "Roles, admin flags or plan limits read from localStorage/sessionStorage can be edited by any user "
         "in the dev tools.",
         "Decide permissions on the server from the verified session, and treat client-side checks as "
         "display only.", "CWE-602", "A01:2021"),
    Rule("FE004", "postMessage handler without origin check", "frontend", "medium",
         "Any website can send messages to this window. Without checking event.origin the handler trusts "
         "attacker data.",
         "Compare event.origin against an exact allow-list before using event.data.", "CWE-346", "A01:2021"),
    Rule("FE005", "Auth token stored in localStorage", "frontend", "low",
         "Any XSS bug can read localStorage and steal the token, so one script injection becomes account "
         "takeover.",
         "Prefer httpOnly, Secure, SameSite cookies for session tokens.", "CWE-922", "A04:2021"),
    Rule("FE006", "Production source maps enabled", "frontend", "low",
         "Public source maps hand out your original source code, comments and sometimes internal URLs.",
         "Disable browser source maps in production or upload them privately to your error tracker.",
         "CWE-540", "A05:2021"),
    Rule("FE007", "Hardcoded localhost URL in frontend code", "frontend", "low",
         "A localhost API URL works on the developer's machine and silently breaks (or calls the visitor's "
         "own machine) in production.",
         "Read the API base URL from configuration or use relative paths.", "CWE-1188", "",
         preview=True,
         preview_reason="Benchmark precision 86% (6 of 7): a localhost URL used only when the app itself runs on "
                        "localhost is reported too."),
    # ------------------------------------------------------------------- auth
    Rule("AUTH001", "State-changing endpoint without authentication", "auth", "high",
         "This endpoint creates, changes or deletes data but no authentication check was found, so anyone "
         "on the internet can call it directly, whatever the UI shows.",
         "Require a verified session or token in the handler (or in middleware that covers it). If the "
         "endpoint is meant to be public, add rate limiting and suppress the finding with a comment.",
         "CWE-306", "A01:2021"),
    Rule("AUTH002", "Admin endpoint without a role check", "auth", "high",
         "An /admin route that only checks that a user is logged in (or nothing at all) lets any user act "
         "as an administrator.",
         "Check the user's role from the server-side session or database in the handler or middleware.",
         "CWE-285", "A01:2021"),
    Rule("AUTH003", "Possible insecure direct object reference (IDOR)", "auth", "medium",
         "The handler changes a record by the id in the URL but never compares it with the current user, "
         "so any logged-in user can change anyone's data by changing the id.",
         "Scope the query by owner (`where id = ? and user_id = current_user.id`) or check ownership "
         "before writing.", "CWE-639", "A01:2021"),
    Rule("AUTH004", "Webhook without signature verification", "auth", "high",
         "Without verifying the provider's signature anyone can post fake events, for example marking an "
         "order as paid.",
         "Verify the signature with the provider SDK (stripe.webhooks.constructEvent, svix, hmac compare) "
         "using the raw request body.", "CWE-345", "A08:2021"),
    Rule("AUTH005", "Supabase table without Row Level Security", "auth", "high",
         "With RLS off, the public anon key (which ships in every Supabase frontend) can read and write the "
         "entire table.",
         "Run `alter table <name> enable row level security;` and add policies that scope rows to "
         "`auth.uid()`.", "CWE-284", "A01:2021"),
    Rule("AUTH006", "Permissive Supabase policy", "auth", "high",
         "A policy with `using (true)` or `with check (true)` for writes lets every user modify every row.",
         "Scope the policy, for example `using (auth.uid() = user_id)`.", "CWE-284", "A01:2021"),
    Rule("AUTH007", "Open Firebase security rules", "auth", "critical",
         "Rules that allow reads or writes for everyone (or until a date, the default test mode) expose the "
         "whole database to anyone with the public config.",
         "Require `request.auth != null` and match the document owner, for example "
         "`allow read, write: if request.auth.uid == userId;`.", "CWE-284", "A01:2021"),
    Rule("AUTH008", "Auth check stub always succeeds", "auth", "critical",
         "A function that is supposed to verify a token, password or permission just returns true. It is a "
         "placeholder an assistant left behind and it disables security for everything that relies on it.",
         "Implement the real check (verify signature, expiry, user and role) or use a maintained auth "
         "library.", "CWE-287", "A07:2021"),
    Rule("AUTH009", "CSRF protection disabled", "auth", "medium",
         "With CSRF checks off, another website can submit forms to this endpoint using the visitor's "
         "session cookie.",
         "Keep CSRF protection on, or use token (not cookie) auth for the endpoint.", "CWE-352", "A01:2021"),
    Rule("AUTH010", "Login endpoint without rate limiting", "auth", "medium",
         "Without rate limiting, login and reset endpoints can be brute-forced or used for credential "
         "stuffing.",
         "Add rate limiting (flask-limiter, slowapi, express-rate-limit, @upstash/ratelimit) by IP and by "
         "account.", "CWE-307", "A07:2021"),
    # ----------------------------------------------------------------- config
    Rule("CFG001", "Container runs as root", "config", "low",
         "If the app is compromised the attacker is root inside the container, which makes escaping and "
         "tampering easier.",
         "Add a non-root user and `USER app` at the end of the Dockerfile.", "CWE-250", "A05:2021"),
    Rule("CFG002", "Unpinned container base image", "config", "low",
         "`latest` (or no tag) changes under you, so builds are not reproducible and can pull a broken or "
         "compromised image.",
         "Pin a version tag, ideally with a digest (`python:3.12-slim@sha256:...`).", "CWE-1357", "A08:2021"),
    Rule("CFG003", "Secret baked into the container image", "config", "high",
         "ENV and ARG values are stored in the image layers and visible to anyone who can pull the image.",
         "Pass secrets at runtime (environment, secret mounts with `RUN --mount=type=secret`).",
         "CWE-538", "A05:2021"),
    Rule("CFG004", "GitHub Actions script injection", "config", "high",
         "Untrusted event fields (issue titles, PR bodies, branch names) are pasted into a shell script, so "
         "a crafted title runs commands with the workflow's secrets.",
         "Pass the value through an environment variable (`env: TITLE: ${{ github.event.issue.title }}`) "
         "and reference \"$TITLE\" in the script.", "CWE-78", "A03:2021"),
    Rule("CFG005", "pull_request_target checks out untrusted code", "config", "high",
         "pull_request_target runs with repository secrets. Checking out and building the PR head runs "
         "the attacker's code with those secrets.",
         "Use `pull_request` instead, or never check out / execute the PR head in that workflow.",
         "CWE-829", "A08:2021"),
    Rule("CFG006", "Any Host header accepted", "config", "medium",
         "ALLOWED_HOSTS = ['*'] enables host header attacks such as poisoned password-reset links.",
         "List your real domain names.", "CWE-644", "A05:2021"),
    Rule("CFG007", "Default database credentials", "config", "medium",
         "Default passwords like postgres/password/admin are the first thing scanners try, especially on "
         "published ports.",
         "Use a generated password from an env file that is not committed, and do not publish database "
         "ports publicly.", "CWE-1392", "A07:2021"),
    Rule("CFG008", "Express app without security headers", "config", "low",
         "Without helmet (or equivalent) the app sends no CSP, frame or MIME-sniffing protections.",
         "Add `app.use(helmet())` and tune the Content-Security-Policy.", "CWE-693", "A05:2021"),
    Rule("CFG009", ".env file copied into the container image", "config", "medium",
         "`COPY . .` with no .dockerignore entry for .env bakes your local secrets into the image.",
         "Add `.env*` to .dockerignore and pass secrets at runtime.", "CWE-538", "A05:2021"),
    Rule("CFG010", "Third-party GitHub Action not pinned to a commit", "config", "medium",
         "A tag like `@v3` can be moved by whoever controls the action's repository; if it is compromised, "
         "your workflow runs their code with your secrets and token (as in the tj-actions/changed-files "
         "attack).",
         "Pin the full commit SHA and keep the version in a comment: "
         "`uses: owner/action@<40-character sha>  # v3.1.0`. Dependabot can update pinned SHAs.",
         "CWE-829", "A08:2021", preview=True, preview_reason=NEW_IN_070),
    Rule("CFG011", "Workflow token with write access to everything", "config", "medium",
         "`permissions: write-all` gives every step, including third-party actions, write access to the "
         "code, releases, packages and settings the GITHUB_TOKEN can reach.",
         "Set `permissions: contents: read` at the top and grant single write scopes only to the jobs that "
         "need them.", "CWE-250", "A01:2021", preview=True, preview_reason=NEW_IN_070),
    Rule("CFG012", "Privileged or host-mounted Kubernetes container", "config", "high",
         "A privileged container, a hostPath volume or the host's network or PID namespace lets a "
         "compromised container take over the node and every other workload on it.",
         "Remove `privileged: true`, `hostPath`, `hostNetwork` and `hostPID`; use a securityContext with "
         "`allowPrivilegeEscalation: false` and `runAsNonRoot: true`.", "CWE-250", "A05:2021",
         preview=True, preview_reason=NEW_IN_070),
    Rule("CFG013", "Kubernetes container without resource limits", "config", "low",
         "Without CPU and memory limits one runaway or attacked pod can starve every other workload on the "
         "node.", "Set `resources.requests` and `resources.limits` for every container.", "CWE-770", "",
         preview=True, preview_reason=NEW_IN_070),
    Rule("CFG014", "Public S3 bucket", "config", "high",
         "A public-read ACL or disabled public access block exposes every object in the bucket to the "
         "internet; leaked backups and user uploads are among the most common cloud breaches.",
         "Keep the bucket private with all four public access block settings on, and serve public files "
         "through a CDN with an origin access identity.", "CWE-284", "A01:2021",
         preview=True, preview_reason=NEW_IN_070),
    Rule("CFG015", "Admin or database port open to the internet", "config", "high",
         "A security group allowing 0.0.0.0/0 on SSH, RDP or a database port gets scanned and brute-forced "
         "within minutes of going up.",
         "Allow only your own address range or a bastion/VPN security group, or use SSM Session Manager "
         "instead of open SSH.", "CWE-284", "A05:2021", preview=True, preview_reason=NEW_IN_070),
    Rule("CFG016", "Unencrypted database or disk storage", "config", "medium",
         "A database or volume without encryption at rest exposes its data in snapshots, backups and "
         "discarded disks.", "Set `storage_encrypted = true` (RDS) or `encrypted = true` (EBS), with a KMS "
         "key you control.", "CWE-311", "A02:2021", preview=True, preview_reason=NEW_IN_070),
    # -------------------------------------------------------------------- llm
    Rule("LLM001", "Untrusted input placed in the system prompt", "llm", "high",
         "User text inside the system prompt gets system-level authority, which makes prompt injection "
         "trivial (\"ignore previous instructions...\").",
         "Keep the system prompt constant. Put user content in a separate user message, clearly delimited, "
         "and never grant extra privileges based on it.", "CWE-77", "LLM01:2025"),
    Rule("LLM002", "LLM output used in a dangerous operation", "llm", "critical",
         "Model output is attacker-influenced (prompt injection via user input, documents or web pages). "
         "Passing it to code execution, shell, SQL, file paths, URLs or HTML turns a prompt into an exploit.",
         "Treat model output as untrusted input: parse it into a strict schema, validate against "
         "allow-lists, use parameterized queries and argument lists, and sanitize before rendering.",
         "CWE-94", "LLM05:2025"),
    Rule("LLM003", "LLM call without an output token limit", "llm", "medium",
         "Without max tokens a single request (or a prompt-injected loop) can generate very long, expensive "
         "responses.",
         "Set max_tokens / max_output_tokens / maxOutputTokens to what the feature actually needs.",
         "CWE-770", "LLM10:2025"),
    Rule("LLM004", "LLM endpoint without rate limiting", "llm", "high",
         "Anyone can call this endpoint in a loop and spend your model budget (denial of wallet), or use your "
         "app as a free LLM proxy.",
         "Require auth and add per-user and per-IP rate limits and a spending cap on the provider account.",
         "CWE-770", "LLM10:2025"),
    Rule("LLM005", "Agent tool with dangerous capability", "llm", "high",
         "The model chooses the arguments of this tool. A prompt injection in any text the agent reads can "
         "make it run shell commands, code, SQL or file writes.",
         "Restrict tools to narrow, allow-listed operations; validate arguments; run them in a sandbox; and "
         "require human approval for destructive actions.", "CWE-250", "LLM06:2025"),
    Rule("LLM006", "Dangerous agent or framework option enabled", "llm", "high",
         "This option gives the model arbitrary code, shell or network execution (for example "
         "allow_dangerous_code=True or a Python REPL tool).",
         "Remove the option, or run the agent in an isolated sandbox with no secrets and no network.",
         "CWE-94", "LLM06:2025"),
    Rule("LLM007", "System prompt shipped to the browser", "llm", "medium",
         "Prompts in client code are visible to every user, which reveals business logic and makes "
         "jailbreaks easier.",
         "Keep prompts on the server and send only the user's message from the browser.", "CWE-200",
         "LLM07:2025"),
    Rule("LLM008", "Unsafe model loading", "llm", "high",
         "trust_remote_code runs Python from the model repository, and torch.load / pickle model files can "
         "execute code when loaded.",
         "Use safetensors, pass weights_only=True to torch.load, and only enable trust_remote_code for "
         "pinned revisions you have reviewed.", "CWE-502", "LLM03:2025"),
    Rule("LLM009", "Unbounded agent loop", "llm", "medium",
         "A `while True` loop that calls a model has no iteration or budget limit, so a confused or "
         "injected agent can loop forever and burn tokens.",
         "Add a maximum number of steps and a token or cost budget, and stop when either is reached.",
         "CWE-834", "LLM10:2025"),
    # ---------------------------------------------------------------- quality
    Rule("QA001", "No automated tests", "quality", "medium",
         "AI-generated code often looks right and is subtly wrong. Without tests nobody notices until users "
         "do, and every future AI edit can silently break existing behaviour.",
         "Add tests for the critical paths first (auth, payments, data writes) and run them in CI.", "", ""),
    Rule("QA002", "No continuous integration", "quality", "low",
         "Without CI, tests and security checks only run when someone remembers to run them.",
         "Add a CI workflow (for example GitHub Actions) that runs tests and `vibeaudit scan` on every push.",
         "", ""),
    Rule("QA003", "Exception silently swallowed", "quality", "low",
         "An empty except/catch hides failures, including failed auth or payment calls, and makes incidents "
         "very hard to debug.",
         "Log the error and handle it explicitly, or let it propagate.", "CWE-390", "A09:2021",
         preview=True,
         preview_reason="Benchmark precision 33% (2 of 6): a broad except in a library's best-effort cleanup path "
                       "is often deliberate."),
    Rule("QA004", "Security placeholder or TODO left in code", "quality", "medium",
         "Comments like \"TODO: add auth\" or \"in production, use...\" are where assistants leave "
         "unfinished security work that then ships.",
         "Implement the missing control now, or track it as a blocking issue before launch.", "CWE-1188", ""),
    Rule("QA005", "Unfinished stub left in code", "quality", "medium",
         "A route handler or function that only passes, raises NotImplementedError or throws 'not implemented' is "
         "a placeholder an assistant left behind. The feature silently does nothing or crashes when used.",
         "Implement the function, or remove it and every caller until it is ready.", "CWE-1164", ""),
    Rule("QA006", "Import of a file or name that does not exist", "quality", "high",
         "The code imports a local module, file or function that is not in the project. Assistants invent helper "
         "names that sound right; the app crashes on start-up or when that code path runs.",
         "Create the missing module or function, or import the one that actually exists.", "CWE-1164", ""),
    Rule("QA007", "Package imported but not declared as a dependency", "quality", "medium",
         "The package is installed on the author's machine but missing from requirements.txt, pyproject.toml or "
         "package.json, so a clean install (CI, Docker, production) fails with an import error.",
         "Add the package with a pinned version to the project's dependency file.", "CWE-1104", ""),
    Rule("QA008", "TypeScript checking disabled for a whole file", "quality", "low",
         "`// @ts-nocheck` hides every type error in the file, including the ones that would catch broken AI edits.",
         "Remove @ts-nocheck and fix or narrowly suppress the individual errors.", "", ""),
    Rule("DATA001", "Database query inside a loop (N+1)", "data", "medium",
         "One query per item turns a page with 100 rows into 101 round trips: slow pages, timeouts and database "
         "load that grows with your data.",
         "Fetch everything in one query (IN / join / include / select_related / prefetch_related) or batch the "
         "writes (createMany, bulk_create, executemany).", "CWE-1050", "",
         preview=True,
         preview_reason="Benchmark precision 20% (1 of 5): a loop over a few fixed items, a deliberate per-row "
                       "transaction or an offline job looks the same as a request-time N+1."),
    Rule("DATA002", "Whole user record returned to the client", "data", "high",
         "Returning the full user or account row sends every column to the browser, including password hashes, "
         "reset tokens, Stripe ids and other private fields.",
         "Select only the fields the client needs (Prisma `select`, Mongoose projection, a response schema).",
         "CWE-213", "A01:2021"),
    Rule("DATA003", "Destructive database migration", "data", "low",
         "DROP TABLE, DROP COLUMN, TRUNCATE and column type changes destroy data and can lock big tables.",
         "Back up first, deploy in steps (stop writing, copy, then drop) and keep a down migration.", "", ""),
    Rule("DATA004", "Money stored as a floating-point number", "data", "medium",
         "Floats cannot represent most decimal amounts exactly (0.1 + 0.2 != 0.3), so totals, refunds and balances "
         "drift by cents.",
         "Store integer cents or use NUMERIC/DECIMAL columns and Decimal types.", "CWE-1339", ""),
    Rule("DATA005", "Private table readable by everyone", "data", "high",
         "A Supabase policy `for select using (true)` on a table that holds users, orders, messages or keys lets "
         "anyone with the public anon key read every row.",
         "Scope the policy to the owner, for example `using (auth.uid() = user_id)`, or to `authenticated`.",
         "CWE-284", "A01:2021"),
    Rule("DATA006", "Timestamp without time zone", "data", "low",
         "Naive datetimes and `timestamp without time zone` columns silently mix local and UTC times, which breaks "
         "expiry checks, schedules and reports across regions and daylight saving.",
         "Use timezone-aware values: `datetime.now(timezone.utc)` and `timestamptz` columns.", "", ""),
    Rule("DATA007", "Environment variable missing from the example env file", "data", "low",
         "The code reads a variable that .env.example does not document, so the next deploy or teammate setup "
         "crashes or silently runs with a missing setting.",
         "Add the variable (with a placeholder value) to .env.example.", "", "",
         preview=True,
         preview_reason="Benchmark precision 50% (6 of 12): a setting that is optional by design (an SDK default, "
                       "a feature that is simply off) looks the same as a required one."),
    Rule("DATA008", "Database client created per request", "data", "medium",
         "Creating a client, pool or engine inside a handler opens new connections on every request and exhausts "
         "the database's connection limit under load.",
         "Create one client at module level (and reuse it via globalThis in Next.js development).", "CWE-400", ""),
    Rule("DATA009", "SQLite file database on a serverless host", "data", "medium",
         "Serverless platforms give each request a fresh, read-only or throw-away file system, so data written to a "
         "SQLite file disappears or fails to save.",
         "Use a hosted database (Postgres, MySQL, Turso, D1) or a mounted persistent volume.", "", ""),
    Rule("DATA010", "Several writes without a transaction", "data", "low",
         "When one of several related writes fails halfway (for example charge recorded but order not created), "
         "the data is left inconsistent.",
         "Wrap related writes in a transaction (prisma.$transaction, db.transaction, BEGIN/COMMIT).", "CWE-662", "",
         preview=True,
         preview_reason="Benchmark precision 89% (8 of 9): writes in separate webhook event branches or helpers "
                       "are counted as one handler's writes."),
    Rule("REL001", "Outbound HTTP request without a timeout", "reliability", "medium",
         "`requests` and `urlopen` wait forever by default. One slow or dead upstream API ties up a worker per "
         "request until the whole service stops responding.",
         "Always pass a timeout, for example `requests.get(url, timeout=10)`.", "CWE-1088", ""),
    Rule("REL002", "Blocking call inside an async handler", "reliability", "medium",
         "time.sleep, requests and subprocess block the event loop, so every other request on that worker waits "
         "until the call finishes.",
         "Use the async equivalent (asyncio.sleep, httpx.AsyncClient, asyncio.create_subprocess_exec) or run the "
         "call in a thread with asyncio.to_thread.", "CWE-1050", ""),
    Rule("REL003", "Webhook handler is not idempotent", "reliability", "medium",
         "Payment and other providers retry webhooks. Without recording the event id, a retry credits a customer, "
         "creates an order or sends an email twice.",
         "Store each processed event id (unique constraint) and skip events you have already handled.", "CWE-837", ""),
    Rule("REL004", "Upload accepted without a size limit", "reliability", "medium",
         "Reading an upload with no size limit lets one large request exhaust memory or disk and crash the server.",
         "Set a limit (MAX_CONTENT_LENGTH, multer limits.fileSize, a size check before reading) and stream large "
         "files.", "CWE-770", ""),
    Rule("REL005", "In-memory state on a serverless host", "reliability", "medium",
         "Serverless functions run many short-lived instances that do not share memory, so rate limits, sessions and "
         "caches kept in a module-level Map or object silently reset and never apply across instances.",
         "Keep shared state in Redis/Upstash, the database or the platform's KV store.", "", ""),
    Rule("REL006", "No health-check endpoint", "reliability", "low",
         "Load balancers, containers and uptime monitors need a cheap endpoint to tell a dead instance from a live one.",
         "Add GET /health (or /healthz) that returns 200 when the app and its database are reachable.", "", ""),
    Rule("LLM010", "Vector search without a user or tenant filter", "llm", "medium",
         "In a multi-user app, a similarity search over one shared index returns the closest documents from every "
         "user, so one user's question can surface another user's private files in the answer.",
         "Store an owner or tenant id with every embedding and filter on it in every query (metadata filter, "
         "namespace, or a WHERE clause).", "CWE-639", "LLM08:2025"),
    Rule("LLM011", "Model output parsed as JSON without error handling", "llm", "medium",
         "Models regularly return almost-JSON (markdown fences, a trailing sentence, a cut-off answer). Parsing it "
         "without handling the error crashes the request.",
         "Use structured output (response_format / tool calls / generateObject), validate with a schema, and catch "
         "parse errors with a retry or a fallback.", "CWE-20", "LLM05:2025"),
    Rule("LLM012", "Retired or deprecated model hardcoded", "llm", "medium",
         "The provider has retired (or announced the retirement of) this model id, so requests fail or will fail "
         "without warning.",
         "Move to a current model and keep the model id in configuration rather than in code.", "", ""),
    Rule("LLM013", "MCP server with broad access", "llm", "high",
         "An MCP filesystem server rooted at / or the home folder lets the agent (and any prompt injection it reads) "
         "read or change every file, including SSH keys and credentials; a remote server over plain HTTP exposes the "
         "conversation and tokens.",
         "Limit filesystem servers to the project folder and use https for remote servers.", "CWE-250", "LLM06:2025"),
    Rule("LLM014", "Secret in an MCP configuration", "llm", "high",
         "MCP config files are often committed or shared; a key written into `env` or `headers` leaks with them.",
         "Reference an environment variable instead (for example \"${GITHUB_TOKEN}\") and rotate the key.",
         "CWE-798", "LLM02:2025"),
    Rule("LLM015", "Agent combines untrusted input with dangerous tools", "llm", "high",
         "An agent that reads web pages, emails or files and can also run commands, send messages or change data "
         "can be steered by instructions hidden in that content (indirect prompt injection).",
         "Split reading and acting into separate agents, require human approval for actions, and never give an "
         "agent that reads untrusted content access to secrets or destructive tools.", "CWE-77", "LLM01:2025"),
    # ------------------------------------------------------- UI, UX and a11y
    Rule("UI001", "Image without alt text", "ui", "low",
         "Screen-reader users get the file name or nothing, and the image is invisible to search engines.",
         "Add alt text that says what the image shows, or alt=\"\" for purely decorative images.", "CWE-1078"),
    Rule("UI002", "Click handler on a non-interactive element", "ui", "low",
         "A div or span with onClick cannot be focused or triggered with the keyboard, so keyboard and "
         "screen-reader users cannot use it.",
         "Use a <button> (or <a> for navigation); otherwise add role, tabIndex and an onKeyDown handler.", "CWE-1078"),
    Rule("UI003", "Form field without a label", "ui", "low",
         "Without a label, screen readers announce only \"edit text\", and placeholder text disappears as soon as "
         "the user types.",
         "Wrap the field in a <label>, point a <label htmlFor> at its id, or add aria-label.", "CWE-1078"),
    Rule("UI004", "Control that does nothing", "ui", "medium",
         "A button whose handler is empty or only logs, or a link to \"#\", looks finished but does nothing: a "
         "typical sign of generated UI that was never wired up.",
         "Wire the control to its action, or remove it until the feature exists."),
    Rule("UI005", "Array index used as key for a changing list", "ui", "low",
         "When items are added, removed or reordered, React reuses the wrong component state (inputs keep the old "
         "text, the wrong row stays checked).",
         "Use a stable id from the item as the key."),
    Rule("UI006", "Destructive action without confirmation", "ui", "low",
         "A delete or remove that runs on a single click, with no confirmation or undo, loses user data on a "
         "misclick.",
         "Ask for confirmation (a dialog), or offer undo for a few seconds before deleting for good.",
         preview=True,
         preview_reason="Benchmark precision 71% (5 of 7): a confirmation dialog in a parent component, or a "
                       "removal from local state only, is not seen."),
    Rule("UI007", "Hydration mismatch", "ui", "medium",
         "Random numbers or the current time rendered on the server differ on the client, so React reports a "
         "hydration error and re-renders the page.",
         "Compute the value in useEffect after mount, or pass it from the server as a prop."),
    Rule("UI008", "Effect without cleanup", "ui", "medium",
         "An effect that starts a timer, listener or subscription without returning a cleanup function leaks it "
         "on every remount (twice in development), causing duplicate events and memory growth.",
         "Return a function from the effect that clears the timer, removes the listener or unsubscribes.", "CWE-401"),
    Rule("UI009", "Data loaded without loading or error state", "ui", "low",
         "If the request is slow the user sees an empty screen; if it fails the error is swallowed and the screen "
         "stays empty with no explanation.",
         "Track loading and error state (or use a data library such as SWR or React Query) and render both."),
    Rule("UI010", "Placeholder content left in the UI", "ui", "low",
         "Lorem ipsum in shipped pages makes the product look unfinished.",
         "Replace it with real copy, or hide the section until it has content."),
    Rule("UI011", "No error page", "ui", "low",
         "Without app/error.tsx a thrown error replaces the page with the generic Next.js \"Application error\" "
         "screen, with no way back.",
         "Add app/error.tsx (and app/global-error.tsx) with a friendly message and a retry button."),
    Rule("UI012", "Missing page metadata or viewport", "ui", "low",
         "Pages without a title and description look broken in tabs, bookmarks and search results; without a "
         "viewport tag phones show a tiny zoomed-out page.",
         "Export metadata (title, description) from the root layout and include the viewport meta tag."),
    Rule("UI013", "Link to a page that does not exist", "ui", "medium",
         "The link points to a path with no matching page or route, so users land on a 404.",
         "Fix the path, or create the page."),
    Rule("UI014", "Image without width and height", "ui", "low",
         "The browser cannot reserve space for an image without dimensions, so the content below jumps when "
         "it loads (cumulative layout shift, a Core Web Vital).",
         "Set `width` and `height` (the intrinsic size is enough; CSS can still scale it), or give the image "
         "a fixed box with CSS such as `aspect-ratio`.", preview=True, preview_reason=NEW_IN_071),
    Rule("UI015", "Form error not announced to screen readers", "ui", "low",
         "An error message that only appears next to the field is invisible to a screen reader user, who "
         "hears nothing when the form is rejected.",
         "Give the message an id and point the input's `aria-describedby` at it, with `aria-invalid` on the "
         "input, or render it in a `role=\"alert\"` element.", preview=True, preview_reason=NEW_IN_071),
    Rule("UI016", "Focus outline removed", "ui", "medium",
         "`outline: none` with no replacement leaves keyboard users unable to see which control has focus "
         "(WCAG 2.4.7).",
         "Keep the outline, or replace it with a visible `:focus-visible` style such as a ring, border or "
         "box-shadow.", preview=True, preview_reason=NEW_IN_071),
    Rule("UI017", "Link to an asset that does not exist", "ui", "medium",
         "The image, font, icon or file is not in the public folder, so the browser gets a 404: a broken "
         "image or a missing font.",
         "Add the file to the public folder, or fix the path.", preview=True, preview_reason=NEW_IN_071),
    # ------------------------------------------------- frontend-backend contracts
    Rule("API001", "Frontend calls an API path that no route handles", "contracts", "medium",
         "The browser code requests a path that no backend route in this project serves, so the request always "
         "fails with 404: often a renamed route or a route the model forgot to write.",
         "Create the route, or fix the path in the call."),
    Rule("API002", "Frontend calls an API route with the wrong method", "contracts", "medium",
         "The route exists but does not accept this HTTP method, so the request fails with 405 (or reaches a "
         "different handler than intended).",
         "Send the method the route handles, or add a handler for this method."),
    Rule("AI001", "Issue reported by the LLM review (unverified)", "llm-review", "medium",
         "With --llm-review a model reads the riskiest files and reports issues the rules did not cover. These are "
         "suggestions from a model and can be wrong.",
         "Check the issue by hand before acting on it; suppress or disable AI001 if it is a false alarm.", "", ""),
]

RULES: Dict[str, Rule] = {r.id: r for r in _R}

# Used by SARIF / GitHub code scanning to rank results.
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}
