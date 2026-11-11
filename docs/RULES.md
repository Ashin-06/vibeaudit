# vibeaudit rule catalogue

Generated from `src/vibeaudit/rules.py` by `python tools/gen_rules_doc.py`; do not edit by hand.
`vibeaudit rules` prints the same list, and `vibeaudit rules --format json` includes every field.

129 rules. Severity is the default; a finding can be reported lower (for example a pattern without user input reaching it) or higher (model output instead of user input).

21 rules are in preview: they are reported but do not count toward `--fail-on` or the score unless you pass `--include-preview`. See [STABILITY.md](../STABILITY.md) for the policy and [benchmark/RESULTS.md](../benchmark/RESULTS.md) for the measured precision of every rule.

## Secrets

| ID | Severity | Status | Rule |
| --- | --- | --- | --- |
| [SEC001](#sec001) | critical | stable | Hardcoded API key or access token |
| [SEC002](#sec002) | critical | stable | Private key committed |
| [SEC003](#sec003) | high | preview | High-entropy secret assigned in code |
| [SEC004](#sec004) | high | stable | Hardcoded or default signing secret |
| [SEC005](#sec005) | high | stable | Database URL with embedded password |
| [SEC006](#sec006) | high | stable | Environment file committed to git |
| [SEC007](#sec007) | medium | stable | Environment file not git-ignored |
| [SEC008](#sec008) | critical | stable | Secret exposed to the browser through a public env var |
| [SEC009](#sec009) | critical | stable | Supabase service_role key outside the server |
| [SEC010](#sec010) | medium | stable | Secret written to logs |
| [SEC011](#sec011) | high | stable | Hardcoded password |

### SEC001

**Hardcoded API key or access token** (critical)

Why it matters: A real credential is committed in source. Anyone with read access to the repo, a fork, a build log or the shipped bundle can use it, and bots scrape public repos for keys within minutes.

How to fix: Revoke and rotate the key now (deleting it from the file does not remove it from git history). Load it from an environment variable or a secret manager on the server only.

References: CWE-798, A07:2021

### SEC002

**Private key committed** (critical)

Why it matters: A private key in the repository lets anyone impersonate the service or decrypt its traffic.

How to fix: Revoke the key, generate a new one, store it outside the repo (secret manager or mounted file) and purge it from git history.

References: CWE-321, A02:2021

### SEC003

**High-entropy secret assigned in code** (high, preview)

Preview: Benchmark precision 82% (9 of 11): public client keys and documented demo tokens look like secrets.

Why it matters: A variable named like a secret holds a random-looking literal. This is usually a real token pasted in while prototyping.

How to fix: Move the value to an environment variable or secret manager and rotate it if it was ever pushed.

References: CWE-798, A07:2021

### SEC004

**Hardcoded or default signing secret** (high)

Why it matters: Session cookies and JWTs are signed with this secret. If it is in the code, or falls back to a default when the env var is missing, anyone can forge a login as any user, including admins.

How to fix: Read the secret from the environment and fail at startup if it is missing. Never provide a fallback default. Generate it with a CSPRNG (for example `python -c "import secrets; print(secrets.token_urlsafe(48))"`).

References: CWE-321, A02:2021

### SEC005

**Database URL with embedded password** (high)

Why it matters: A connection string for a remote database includes the password, giving direct database access to anyone who reads the code.

How to fix: Put the full URL in an environment variable (DATABASE_URL) and rotate the password.

References: CWE-798, A07:2021

### SEC006

**Environment file committed to git** (high)

Why it matters: .env files hold the app's real secrets. Once committed they stay in git history even after deletion.

How to fix: Remove it with `git rm --cached .env`, add `.env*` (with `!.env.example`) to .gitignore, rotate every secret it contained, and commit a .env.example with placeholder values instead.

References: CWE-538, A05:2021

### SEC007

**Environment file not git-ignored** (medium)

Why it matters: A .env file exists but .gitignore does not cover it, so the next `git add .` publishes every secret.

How to fix: Add `.env*` and `!.env.example` to .gitignore.

References: CWE-538, A05:2021

### SEC008

**Secret exposed to the browser through a public env var** (critical)

Why it matters: Variables prefixed NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_, NUXT_PUBLIC_, PUBLIC_ or GATSBY_ are copied into the JavaScript bundle that every visitor downloads. A secret here is public.

How to fix: Rename the variable without the public prefix, use it only in server code (API route, server action, edge function), and rotate the key because it has already shipped.

References: CWE-200, A01:2021

### SEC009

**Supabase service_role key outside the server** (critical)

Why it matters: The service_role key bypasses every Row Level Security policy. In client code or the repo it gives anyone full read and write access to the whole database.

How to fix: Use only the anon key in the browser. Keep service_role in server-only env vars, rotate it in the Supabase dashboard, and move privileged queries to an API route or edge function.

References: CWE-798, A01:2021

### SEC010

**Secret written to logs** (medium)

Why it matters: Logs are copied to hosting dashboards, log services and screenshots. Printing a key leaks it there.

How to fix: Remove the log line or log only a masked prefix (first 4 characters).

References: CWE-532, A09:2021

### SEC011

**Hardcoded password** (high)

Why it matters: A password literal in code (often an admin or database password) is shared with everyone who can read the repo and cannot be rotated without a deploy.

How to fix: Read it from an environment variable or secret manager. For user accounts, store only bcrypt/argon2 hashes.

References: CWE-259, A07:2021

## Dependencies and supply chain

| ID | Severity | Status | Rule |
| --- | --- | --- | --- |
| [DEP001](#dep001) | critical | stable | Dependency does not exist on the registry |
| [DEP002](#dep002) | high | stable | Package name looks like a typo of a popular package |
| [DEP003](#dep003) | medium | stable | Very new package |
| [DEP004](#dep004) | high | stable | Dependency with known vulnerabilities |
| [DEP005](#dep005) | low | stable | Dependencies are not locked |
| [DEP006](#dep006) | high | stable | Install script downloads and runs remote code |
| [DEP007](#dep007) | medium | stable | MCP server launched from an unpinned package |
| [DEP008](#dep008) | medium | preview | Extra package index (dependency confusion) |

### DEP001

**Dependency does not exist on the registry** (critical)

Why it matters: AI assistants regularly invent plausible package names. Attackers register those names (slopsquatting) so the next install runs their code.

How to fix: Remove the dependency or replace it with the real package you meant. If it is a private package, configure your private registry (.npmrc scope or pip --index-url) and suppress this finding.

References: CWE-1357, LLM03:2025

### DEP002

**Package name looks like a typo of a popular package** (high)

Why it matters: Typosquatted packages copy a popular name with one character changed and ship malware in install scripts.

How to fix: Check the spelling against the official package. If this is the package you meant, suppress the finding.

References: CWE-1357, A06:2021

### DEP003

**Very new package** (medium)

Why it matters: The package was first published only days ago. Freshly registered packages are how hallucinated names get weaponised.

How to fix: Confirm the package, its maintainer and its source repository before trusting it. Pin an exact version.

References: CWE-1357, A06:2021

### DEP004

**Dependency with known vulnerabilities** (high)

Why it matters: The pinned version has published security advisories (from the OSV database).

How to fix: Upgrade to a fixed version listed in the advisory.

References: CWE-1395, A06:2021

### DEP005

**Dependencies are not locked** (low)

Why it matters: Without a lockfile or pinned versions every install can pull a different, possibly compromised, version.

How to fix: Commit a lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock, uv.lock, poetry.lock) or pin exact versions in requirements.txt.

References: CWE-1357, A08:2021

### DEP006

**Install script downloads and runs remote code** (high)

Why it matters: An npm lifecycle script fetches code from the network at install time, which bypasses lockfiles and review.

How to fix: Remove the script or vendor the downloaded file with a checksum.

References: CWE-494, A08:2021

### DEP007

**MCP server launched from an unpinned package** (medium)

Why it matters: The agent config runs `npx -y` / `uvx` on a package without a version, so a malicious update gets code execution inside your AI assistant.

How to fix: Pin an exact version, for example `npx -y some-mcp-server@1.2.3`.

References: CWE-1357, LLM03:2025

### DEP008

**Extra package index (dependency confusion)** (medium, preview)

Preview: New in 0.7.0: not yet measured on enough real-world findings in the benchmark.

Why it matters: With --extra-index-url pip takes the highest version of a name from any index, so anyone who publishes your private package's name on PyPI with a higher version gets their code installed.

How to fix: Use a single index that proxies PyPI (--index-url), or pin each private package to its index (uv `[[tool.uv.index]]` with `explicit = true`) and use hashes.

References: CWE-427, A08:2021

## Backend security

| ID | Severity | Status | Rule |
| --- | --- | --- | --- |
| [BE001](#be001) | high | stable | SQL injection |
| [BE002](#be002) | critical | stable | Command injection |
| [BE003](#be003) | critical | stable | Dynamic code execution |
| [BE004](#be004) | high | stable | Unsafe deserialization |
| [BE005](#be005) | high | stable | Server-side request forgery (SSRF) |
| [BE006](#be006) | high | stable | Path traversal |
| [BE007](#be007) | high | stable | Server-side template injection |
| [BE008](#be008) | medium | stable | Open redirect |
| [BE009](#be009) | high | stable | Mass assignment |
| [BE010](#be010) | high | stable | NoSQL injection |
| [BE011](#be011) | medium | stable | Debug mode enabled |
| [BE012](#be012) | high | stable | Insecure CORS policy |
| [BE013](#be013) | medium | stable | TLS certificate verification disabled |
| [BE014](#be014) | high | stable | Weak or plaintext password storage |
| [BE015](#be015) | medium | stable | Insecure randomness for secrets |
| [BE016](#be016) | high | stable | JWT signature not verified |
| [BE017](#be017) | low | stable | Internal error details sent to the client |
| [BE018](#be018) | medium | preview | No server-side input validation |

### BE001

**SQL injection** (high)

Why it matters: Building SQL with string formatting lets an attacker change the query: read other users' data, bypass login or drop tables.

How to fix: Use parameterized queries (`cursor.execute("... WHERE id = %s", (id,))`, Prisma `$queryRaw` tagged templates, or the ORM query builder).

References: CWE-89, A03:2021

### BE002

**Command injection** (critical)

Why it matters: User-controlled data reaches a shell command, giving the attacker remote code execution on the server.

How to fix: Avoid the shell: pass an argument list (`subprocess.run(["tool", arg])`, `execFile`) and validate the input against an allow-list.

References: CWE-78, A03:2021

### BE003

**Dynamic code execution** (critical)

Why it matters: eval/exec/new Function runs strings as code. With attacker-influenced input it is remote code execution.

How to fix: Remove eval. Parse data with json.loads / JSON.parse or ast.literal_eval, and dispatch through an explicit allow-list of functions.

References: CWE-95, A03:2021

### BE004

**Unsafe deserialization** (high)

Why it matters: pickle, marshal, dill and yaml.load can execute code while loading. Loading untrusted data is remote code execution.

How to fix: Use JSON, or yaml.safe_load. Only unpickle files you created yourself and that nobody else can write.

References: CWE-502, A08:2021

### BE005

**Server-side request forgery (SSRF)** (high)

Why it matters: The server fetches a URL chosen by the user, which can reach internal services and cloud metadata endpoints (credentials).

How to fix: Allow-list hosts, block private and link-local IPs after DNS resolution, and do not follow redirects to other hosts.

References: CWE-918, A10:2021

### BE006

**Path traversal** (high)

Why it matters: A user-controlled path reaches the file system, so `../../etc/passwd` style input can read or overwrite any file.

How to fix: Use `secure_filename` / `path.basename`, resolve the final path and check it is inside the allowed directory.

References: CWE-22, A01:2021

### BE007

**Server-side template injection** (high)

Why it matters: Rendering a user-controlled string as a template executes template code on the server.

How to fix: Render a fixed template file and pass user data as variables.

References: CWE-1336, A03:2021

### BE008

**Open redirect** (medium)

Why it matters: Redirecting to a user-supplied URL lets phishing links borrow your domain.

How to fix: Only redirect to relative paths or an allow-list of hosts.

References: CWE-601, A01:2021

### BE009

**Mass assignment** (high)

Why it matters: The whole request body is written into a database model, so a user can set fields like `role`, `is_admin` or `credits` by adding them to the request.

How to fix: Copy only the allowed fields explicitly, or validate with a schema that whitelists fields.

References: CWE-915, A04:2021

### BE010

**NoSQL injection** (high)

Why it matters: Passing request values straight into a MongoDB query lets attackers send operators like `{"$ne": null}` and bypass login checks.

How to fix: Validate types with a schema (zod, joi) or cast to String, and use express-mongo-sanitize.

References: CWE-943, A03:2021

### BE011

**Debug mode enabled** (medium)

Why it matters: Debug mode shows stack traces, settings and (in Flask/Werkzeug) an interactive console that gives remote code execution.

How to fix: Drive debug from an environment variable that is off by default, and never deploy with it on.

References: CWE-489, A05:2021

### BE012

**Insecure CORS policy** (high)

Why it matters: Allowing any or a reflected origin together with credentials lets any website call your API as the logged-in user. (An open origin without credentials is not reported: no cookies are sent.)

How to fix: List the exact origins you trust. Never combine a wildcard or reflected origin with credentials.

References: CWE-942, A05:2021

### BE013

**TLS certificate verification disabled** (medium)

Why it matters: Turning off certificate checks allows man-in-the-middle attackers to read and change traffic, including API keys.

How to fix: Remove verify=False / rejectUnauthorized:false. Fix the certificate chain or pass a CA bundle.

References: CWE-295, A02:2021

### BE014

**Weak or plaintext password storage** (high)

Why it matters: Passwords compared in plaintext or hashed with fast hashes (MD5/SHA) are cracked in minutes after a database leak.

How to fix: Hash with bcrypt, scrypt or argon2 (passlib, bcrypt, argon2-cffi, bcryptjs) and compare with the library's verify function.

References: CWE-916, A02:2021

### BE015

**Insecure randomness for secrets** (medium)

Why it matters: random / Math.random are predictable. Tokens, OTPs and reset codes made with them can be guessed.

How to fix: Use `secrets.token_urlsafe()` in Python or `crypto.randomUUID()` / `crypto.randomBytes()` in JavaScript.

References: CWE-338, A02:2021

### BE016

**JWT signature not verified** (high)

Why it matters: Decoding a JWT without verifying its signature (or allowing alg none) means anyone can mint a token for any user.

How to fix: Use jwt.verify / jwt.decode with the secret and an explicit algorithms list, and keep expiry checks on.

References: CWE-347, A07:2021

### BE017

**Internal error details sent to the client** (low)

Why it matters: Stack traces and exception text reveal file paths, queries and library versions that help an attacker.

How to fix: Log the details on the server and return a generic error message with a request id.

References: CWE-209, A05:2021

### BE018

**No server-side input validation** (medium, preview)

Preview: Benchmark precision 67% (6 of 9): hand-written validation (type checks, 422 responses) is not recognised, only known validation libraries.

Why it matters: The backend reads request bodies but no validation library is used on the server. Validation done only in the browser is bypassed by calling the API directly.

How to fix: Validate every request body on the server with a schema (zod, valibot, joi, pydantic, marshmallow): types, lengths, ranges and allowed fields.

References: CWE-602, A04:2021

## Frontend security

| ID | Severity | Status | Rule |
| --- | --- | --- | --- |
| [FE001](#fe001) | high | preview | Cross-site scripting through a raw HTML sink |
| [FE002](#fe002) | critical | stable | LLM or secret API called directly from the browser |
| [FE003](#fe003) | high | stable | Authorization state kept in browser storage |
| [FE004](#fe004) | medium | stable | postMessage handler without origin check |
| [FE005](#fe005) | low | stable | Auth token stored in localStorage |
| [FE006](#fe006) | low | stable | Production source maps enabled |
| [FE007](#fe007) | low | preview | Hardcoded localhost URL in frontend code |

### FE001

**Cross-site scripting through a raw HTML sink** (high, preview)

Preview: Benchmark precision 67% (20 of 30): the source of the HTML is often not visible in the file (markdown from the repo, CMS content, constants), so trusted content is reported too.

Why it matters: Inserting unsanitized data as HTML (innerHTML, dangerouslySetInnerHTML, v-html, {@html}, |safe) lets an attacker run JavaScript in other users' browsers and steal their sessions.

How to fix: Render as text, or sanitize with DOMPurify (or bleach on the server) before inserting HTML.

References: CWE-79, A03:2021

### FE002

**LLM or secret API called directly from the browser** (critical)

Why it matters: Calling OpenAI, Anthropic, Gemini and similar APIs from client code ships the API key to every visitor, who can then run up your bill or abuse the account.

How to fix: Call the provider from a server route or edge function that holds the key, and have the browser call your own endpoint (with auth and rate limiting).

References: CWE-522, LLM02:2025

### FE003

**Authorization state kept in browser storage** (high)

Why it matters: Roles, admin flags or plan limits read from localStorage/sessionStorage can be edited by any user in the dev tools.

How to fix: Decide permissions on the server from the verified session, and treat client-side checks as display only.

References: CWE-602, A01:2021

### FE004

**postMessage handler without origin check** (medium)

Why it matters: Any website can send messages to this window. Without checking event.origin the handler trusts attacker data.

How to fix: Compare event.origin against an exact allow-list before using event.data.

References: CWE-346, A01:2021

### FE005

**Auth token stored in localStorage** (low)

Why it matters: Any XSS bug can read localStorage and steal the token, so one script injection becomes account takeover.

How to fix: Prefer httpOnly, Secure, SameSite cookies for session tokens.

References: CWE-922, A04:2021

### FE006

**Production source maps enabled** (low)

Why it matters: Public source maps hand out your original source code, comments and sometimes internal URLs.

How to fix: Disable browser source maps in production or upload them privately to your error tracker.

References: CWE-540, A05:2021

### FE007

**Hardcoded localhost URL in frontend code** (low, preview)

Preview: Benchmark precision 86% (6 of 7): a localhost URL used only when the app itself runs on localhost is reported too.

Why it matters: A localhost API URL works on the developer's machine and silently breaks (or calls the visitor's own machine) in production.

How to fix: Read the API base URL from configuration or use relative paths.

References: CWE-1188

## Authentication and authorization

| ID | Severity | Status | Rule |
| --- | --- | --- | --- |
| [AUTH001](#auth001) | high | stable | State-changing endpoint without authentication |
| [AUTH002](#auth002) | high | stable | Admin endpoint without a role check |
| [AUTH003](#auth003) | medium | stable | Possible insecure direct object reference (IDOR) |
| [AUTH004](#auth004) | high | stable | Webhook without signature verification |
| [AUTH005](#auth005) | high | stable | Supabase table without Row Level Security |
| [AUTH006](#auth006) | high | stable | Permissive Supabase policy |
| [AUTH007](#auth007) | critical | stable | Open Firebase security rules |
| [AUTH008](#auth008) | critical | stable | Auth check stub always succeeds |
| [AUTH009](#auth009) | medium | stable | CSRF protection disabled |
| [AUTH010](#auth010) | medium | stable | Login endpoint without rate limiting |

### AUTH001

**State-changing endpoint without authentication** (high)

Why it matters: This endpoint creates, changes or deletes data but no authentication check was found, so anyone on the internet can call it directly, whatever the UI shows.

How to fix: Require a verified session or token in the handler (or in middleware that covers it). If the endpoint is meant to be public, add rate limiting and suppress the finding with a comment.

References: CWE-306, A01:2021

### AUTH002

**Admin endpoint without a role check** (high)

Why it matters: An /admin route that only checks that a user is logged in (or nothing at all) lets any user act as an administrator.

How to fix: Check the user's role from the server-side session or database in the handler or middleware.

References: CWE-285, A01:2021

### AUTH003

**Possible insecure direct object reference (IDOR)** (medium)

Why it matters: The handler changes a record by the id in the URL but never compares it with the current user, so any logged-in user can change anyone's data by changing the id.

How to fix: Scope the query by owner (`where id = ? and user_id = current_user.id`) or check ownership before writing.

References: CWE-639, A01:2021

### AUTH004

**Webhook without signature verification** (high)

Why it matters: Without verifying the provider's signature anyone can post fake events, for example marking an order as paid.

How to fix: Verify the signature with the provider SDK (stripe.webhooks.constructEvent, svix, hmac compare) using the raw request body.

References: CWE-345, A08:2021

### AUTH005

**Supabase table without Row Level Security** (high)

Why it matters: With RLS off, the public anon key (which ships in every Supabase frontend) can read and write the entire table.

How to fix: Run `alter table <name> enable row level security;` and add policies that scope rows to `auth.uid()`.

References: CWE-284, A01:2021

### AUTH006

**Permissive Supabase policy** (high)

Why it matters: A policy with `using (true)` or `with check (true)` for writes lets every user modify every row.

How to fix: Scope the policy, for example `using (auth.uid() = user_id)`.

References: CWE-284, A01:2021

### AUTH007

**Open Firebase security rules** (critical)

Why it matters: Rules that allow reads or writes for everyone (or until a date, the default test mode) expose the whole database to anyone with the public config.

How to fix: Require `request.auth != null` and match the document owner, for example `allow read, write: if request.auth.uid == userId;`.

References: CWE-284, A01:2021

### AUTH008

**Auth check stub always succeeds** (critical)

Why it matters: A function that is supposed to verify a token, password or permission just returns true. It is a placeholder an assistant left behind and it disables security for everything that relies on it.

How to fix: Implement the real check (verify signature, expiry, user and role) or use a maintained auth library.

References: CWE-287, A07:2021

### AUTH009

**CSRF protection disabled** (medium)

Why it matters: With CSRF checks off, another website can submit forms to this endpoint using the visitor's session cookie.

How to fix: Keep CSRF protection on, or use token (not cookie) auth for the endpoint.

References: CWE-352, A01:2021

### AUTH010

**Login endpoint without rate limiting** (medium)

Why it matters: Without rate limiting, login and reset endpoints can be brute-forced or used for credential stuffing.

How to fix: Add rate limiting (flask-limiter, slowapi, express-rate-limit, @upstash/ratelimit) by IP and by account.

References: CWE-307, A07:2021

## Configuration and deployment

| ID | Severity | Status | Rule |
| --- | --- | --- | --- |
| [CFG001](#cfg001) | low | stable | Container runs as root |
| [CFG002](#cfg002) | low | stable | Unpinned container base image |
| [CFG003](#cfg003) | high | stable | Secret baked into the container image |
| [CFG004](#cfg004) | high | stable | GitHub Actions script injection |
| [CFG005](#cfg005) | high | stable | pull_request_target checks out untrusted code |
| [CFG006](#cfg006) | medium | stable | Any Host header accepted |
| [CFG007](#cfg007) | medium | stable | Default database credentials |
| [CFG008](#cfg008) | low | stable | Express app without security headers |
| [CFG009](#cfg009) | medium | stable | .env file copied into the container image |
| [CFG010](#cfg010) | medium | preview | Third-party GitHub Action not pinned to a commit |
| [CFG011](#cfg011) | medium | preview | Workflow token with write access to everything |
| [CFG012](#cfg012) | high | preview | Privileged or host-mounted Kubernetes container |
| [CFG013](#cfg013) | low | preview | Kubernetes container without resource limits |
| [CFG014](#cfg014) | high | preview | Public S3 bucket |
| [CFG015](#cfg015) | high | preview | Admin or database port open to the internet |
| [CFG016](#cfg016) | medium | preview | Unencrypted database or disk storage |

### CFG001

**Container runs as root** (low)

Why it matters: If the app is compromised the attacker is root inside the container, which makes escaping and tampering easier.

How to fix: Add a non-root user and `USER app` at the end of the Dockerfile.

References: CWE-250, A05:2021

### CFG002

**Unpinned container base image** (low)

Why it matters: `latest` (or no tag) changes under you, so builds are not reproducible and can pull a broken or compromised image.

How to fix: Pin a version tag, ideally with a digest (`python:3.12-slim@sha256:...`).

References: CWE-1357, A08:2021

### CFG003

**Secret baked into the container image** (high)

Why it matters: ENV and ARG values are stored in the image layers and visible to anyone who can pull the image.

How to fix: Pass secrets at runtime (environment, secret mounts with `RUN --mount=type=secret`).

References: CWE-538, A05:2021

### CFG004

**GitHub Actions script injection** (high)

Why it matters: Untrusted event fields (issue titles, PR bodies, branch names) are pasted into a shell script, so a crafted title runs commands with the workflow's secrets.

How to fix: Pass the value through an environment variable (`env: TITLE: ${{ github.event.issue.title }}`) and reference "$TITLE" in the script.

References: CWE-78, A03:2021

### CFG005

**pull_request_target checks out untrusted code** (high)

Why it matters: pull_request_target runs with repository secrets. Checking out and building the PR head runs the attacker's code with those secrets.

How to fix: Use `pull_request` instead, or never check out / execute the PR head in that workflow.

References: CWE-829, A08:2021

### CFG006

**Any Host header accepted** (medium)

Why it matters: ALLOWED_HOSTS = ['*'] enables host header attacks such as poisoned password-reset links.

How to fix: List your real domain names.

References: CWE-644, A05:2021

### CFG007

**Default database credentials** (medium)

Why it matters: Default passwords like postgres/password/admin are the first thing scanners try, especially on published ports.

How to fix: Use a generated password from an env file that is not committed, and do not publish database ports publicly.

References: CWE-1392, A07:2021

### CFG008

**Express app without security headers** (low)

Why it matters: Without helmet (or equivalent) the app sends no CSP, frame or MIME-sniffing protections.

How to fix: Add `app.use(helmet())` and tune the Content-Security-Policy.

References: CWE-693, A05:2021

### CFG009

**.env file copied into the container image** (medium)

Why it matters: `COPY . .` with no .dockerignore entry for .env bakes your local secrets into the image.

How to fix: Add `.env*` to .dockerignore and pass secrets at runtime.

References: CWE-538, A05:2021

### CFG010

**Third-party GitHub Action not pinned to a commit** (medium, preview)

Preview: New in 0.7.0: not yet measured on enough real-world findings in the benchmark.

Why it matters: A tag like `@v3` can be moved by whoever controls the action's repository; if it is compromised, your workflow runs their code with your secrets and token (as in the tj-actions/changed-files attack).

How to fix: Pin the full commit SHA and keep the version in a comment: `uses: owner/action@<40-character sha>  # v3.1.0`. Dependabot can update pinned SHAs.

References: CWE-829, A08:2021

### CFG011

**Workflow token with write access to everything** (medium, preview)

Preview: New in 0.7.0: not yet measured on enough real-world findings in the benchmark.

Why it matters: `permissions: write-all` gives every step, including third-party actions, write access to the code, releases, packages and settings the GITHUB_TOKEN can reach.

How to fix: Set `permissions: contents: read` at the top and grant single write scopes only to the jobs that need them.

References: CWE-250, A01:2021

### CFG012

**Privileged or host-mounted Kubernetes container** (high, preview)

Preview: New in 0.7.0: not yet measured on enough real-world findings in the benchmark.

Why it matters: A privileged container, a hostPath volume or the host's network or PID namespace lets a compromised container take over the node and every other workload on it.

How to fix: Remove `privileged: true`, `hostPath`, `hostNetwork` and `hostPID`; use a securityContext with `allowPrivilegeEscalation: false` and `runAsNonRoot: true`.

References: CWE-250, A05:2021

### CFG013

**Kubernetes container without resource limits** (low, preview)

Preview: New in 0.7.0: not yet measured on enough real-world findings in the benchmark.

Why it matters: Without CPU and memory limits one runaway or attacked pod can starve every other workload on the node.

How to fix: Set `resources.requests` and `resources.limits` for every container.

References: CWE-770

### CFG014

**Public S3 bucket** (high, preview)

Preview: New in 0.7.0: not yet measured on enough real-world findings in the benchmark.

Why it matters: A public-read ACL or disabled public access block exposes every object in the bucket to the internet; leaked backups and user uploads are among the most common cloud breaches.

How to fix: Keep the bucket private with all four public access block settings on, and serve public files through a CDN with an origin access identity.

References: CWE-284, A01:2021

### CFG015

**Admin or database port open to the internet** (high, preview)

Preview: New in 0.7.0: not yet measured on enough real-world findings in the benchmark.

Why it matters: A security group allowing 0.0.0.0/0 on SSH, RDP or a database port gets scanned and brute-forced within minutes of going up.

How to fix: Allow only your own address range or a bastion/VPN security group, or use SSM Session Manager instead of open SSH.

References: CWE-284, A05:2021

### CFG016

**Unencrypted database or disk storage** (medium, preview)

Preview: New in 0.7.0: not yet measured on enough real-world findings in the benchmark.

Why it matters: A database or volume without encryption at rest exposes its data in snapshots, backups and discarded disks.

How to fix: Set `storage_encrypted = true` (RDS) or `encrypted = true` (EBS), with a KMS key you control.

References: CWE-311, A02:2021

## LLM and AI-specific risks

| ID | Severity | Status | Rule |
| --- | --- | --- | --- |
| [LLM001](#llm001) | high | stable | Untrusted input placed in the system prompt |
| [LLM002](#llm002) | critical | stable | LLM output used in a dangerous operation |
| [LLM003](#llm003) | medium | stable | LLM call without an output token limit |
| [LLM004](#llm004) | high | stable | LLM endpoint without rate limiting |
| [LLM005](#llm005) | high | stable | Agent tool with dangerous capability |
| [LLM006](#llm006) | high | stable | Dangerous agent or framework option enabled |
| [LLM007](#llm007) | medium | stable | System prompt shipped to the browser |
| [LLM008](#llm008) | high | stable | Unsafe model loading |
| [LLM009](#llm009) | medium | stable | Unbounded agent loop |
| [LLM010](#llm010) | medium | stable | Vector search without a user or tenant filter |
| [LLM011](#llm011) | medium | stable | Model output parsed as JSON without error handling |
| [LLM012](#llm012) | medium | stable | Retired or deprecated model hardcoded |
| [LLM013](#llm013) | high | stable | MCP server with broad access |
| [LLM014](#llm014) | high | stable | Secret in an MCP configuration |
| [LLM015](#llm015) | high | stable | Agent combines untrusted input with dangerous tools |

### LLM001

**Untrusted input placed in the system prompt** (high)

Why it matters: User text inside the system prompt gets system-level authority, which makes prompt injection trivial ("ignore previous instructions...").

How to fix: Keep the system prompt constant. Put user content in a separate user message, clearly delimited, and never grant extra privileges based on it.

References: CWE-77, LLM01:2025

### LLM002

**LLM output used in a dangerous operation** (critical)

Why it matters: Model output is attacker-influenced (prompt injection via user input, documents or web pages). Passing it to code execution, shell, SQL, file paths, URLs or HTML turns a prompt into an exploit.

How to fix: Treat model output as untrusted input: parse it into a strict schema, validate against allow-lists, use parameterized queries and argument lists, and sanitize before rendering.

References: CWE-94, LLM05:2025

### LLM003

**LLM call without an output token limit** (medium)

Why it matters: Without max tokens a single request (or a prompt-injected loop) can generate very long, expensive responses.

How to fix: Set max_tokens / max_output_tokens / maxOutputTokens to what the feature actually needs.

References: CWE-770, LLM10:2025

### LLM004

**LLM endpoint without rate limiting** (high)

Why it matters: Anyone can call this endpoint in a loop and spend your model budget (denial of wallet), or use your app as a free LLM proxy.

How to fix: Require auth and add per-user and per-IP rate limits and a spending cap on the provider account.

References: CWE-770, LLM10:2025

### LLM005

**Agent tool with dangerous capability** (high)

Why it matters: The model chooses the arguments of this tool. A prompt injection in any text the agent reads can make it run shell commands, code, SQL or file writes.

How to fix: Restrict tools to narrow, allow-listed operations; validate arguments; run them in a sandbox; and require human approval for destructive actions.

References: CWE-250, LLM06:2025

### LLM006

**Dangerous agent or framework option enabled** (high)

Why it matters: This option gives the model arbitrary code, shell or network execution (for example allow_dangerous_code=True or a Python REPL tool).

How to fix: Remove the option, or run the agent in an isolated sandbox with no secrets and no network.

References: CWE-94, LLM06:2025

### LLM007

**System prompt shipped to the browser** (medium)

Why it matters: Prompts in client code are visible to every user, which reveals business logic and makes jailbreaks easier.

How to fix: Keep prompts on the server and send only the user's message from the browser.

References: CWE-200, LLM07:2025

### LLM008

**Unsafe model loading** (high)

Why it matters: trust_remote_code runs Python from the model repository, and torch.load / pickle model files can execute code when loaded.

How to fix: Use safetensors, pass weights_only=True to torch.load, and only enable trust_remote_code for pinned revisions you have reviewed.

References: CWE-502, LLM03:2025

### LLM009

**Unbounded agent loop** (medium)

Why it matters: A `while True` loop that calls a model has no iteration or budget limit, so a confused or injected agent can loop forever and burn tokens.

How to fix: Add a maximum number of steps and a token or cost budget, and stop when either is reached.

References: CWE-834, LLM10:2025

### LLM010

**Vector search without a user or tenant filter** (medium)

Why it matters: In a multi-user app, a similarity search over one shared index returns the closest documents from every user, so one user's question can surface another user's private files in the answer.

How to fix: Store an owner or tenant id with every embedding and filter on it in every query (metadata filter, namespace, or a WHERE clause).

References: CWE-639, LLM08:2025

### LLM011

**Model output parsed as JSON without error handling** (medium)

Why it matters: Models regularly return almost-JSON (markdown fences, a trailing sentence, a cut-off answer). Parsing it without handling the error crashes the request.

How to fix: Use structured output (response_format / tool calls / generateObject), validate with a schema, and catch parse errors with a retry or a fallback.

References: CWE-20, LLM05:2025

### LLM012

**Retired or deprecated model hardcoded** (medium)

Why it matters: The provider has retired (or announced the retirement of) this model id, so requests fail or will fail without warning.

How to fix: Move to a current model and keep the model id in configuration rather than in code.

### LLM013

**MCP server with broad access** (high)

Why it matters: An MCP filesystem server rooted at / or the home folder lets the agent (and any prompt injection it reads) read or change every file, including SSH keys and credentials; a remote server over plain HTTP exposes the conversation and tokens.

How to fix: Limit filesystem servers to the project folder and use https for remote servers.

References: CWE-250, LLM06:2025

### LLM014

**Secret in an MCP configuration** (high)

Why it matters: MCP config files are often committed or shared; a key written into `env` or `headers` leaks with them.

How to fix: Reference an environment variable instead (for example "${GITHUB_TOKEN}") and rotate the key.

References: CWE-798, LLM02:2025

### LLM015

**Agent combines untrusted input with dangerous tools** (high)

Why it matters: An agent that reads web pages, emails or files and can also run commands, send messages or change data can be steered by instructions hidden in that content (indirect prompt injection).

How to fix: Split reading and acting into separate agents, require human approval for actions, and never give an agent that reads untrusted content access to secrets or destructive tools.

References: CWE-77, LLM01:2025

## Code quality and tests

| ID | Severity | Status | Rule |
| --- | --- | --- | --- |
| [QA001](#qa001) | medium | stable | No automated tests |
| [QA002](#qa002) | low | stable | No continuous integration |
| [QA003](#qa003) | low | preview | Exception silently swallowed |
| [QA004](#qa004) | medium | stable | Security placeholder or TODO left in code |
| [QA005](#qa005) | medium | stable | Unfinished stub left in code |
| [QA006](#qa006) | high | stable | Import of a file or name that does not exist |
| [QA007](#qa007) | medium | stable | Package imported but not declared as a dependency |
| [QA008](#qa008) | low | stable | TypeScript checking disabled for a whole file |

### QA001

**No automated tests** (medium)

Why it matters: AI-generated code often looks right and is subtly wrong. Without tests nobody notices until users do, and every future AI edit can silently break existing behaviour.

How to fix: Add tests for the critical paths first (auth, payments, data writes) and run them in CI.

### QA002

**No continuous integration** (low)

Why it matters: Without CI, tests and security checks only run when someone remembers to run them.

How to fix: Add a CI workflow (for example GitHub Actions) that runs tests and `vibeaudit scan` on every push.

### QA003

**Exception silently swallowed** (low, preview)

Preview: Benchmark precision 33% (2 of 6): a broad except in a library's best-effort cleanup path is often deliberate.

Why it matters: An empty except/catch hides failures, including failed auth or payment calls, and makes incidents very hard to debug.

How to fix: Log the error and handle it explicitly, or let it propagate.

References: CWE-390, A09:2021

### QA004

**Security placeholder or TODO left in code** (medium)

Why it matters: Comments like "TODO: add auth" or "in production, use..." are where assistants leave unfinished security work that then ships.

How to fix: Implement the missing control now, or track it as a blocking issue before launch.

References: CWE-1188

### QA005

**Unfinished stub left in code** (medium)

Why it matters: A route handler or function that only passes, raises NotImplementedError or throws 'not implemented' is a placeholder an assistant left behind. The feature silently does nothing or crashes when used.

How to fix: Implement the function, or remove it and every caller until it is ready.

References: CWE-1164

### QA006

**Import of a file or name that does not exist** (high)

Why it matters: The code imports a local module, file or function that is not in the project. Assistants invent helper names that sound right; the app crashes on start-up or when that code path runs.

How to fix: Create the missing module or function, or import the one that actually exists.

References: CWE-1164

### QA007

**Package imported but not declared as a dependency** (medium)

Why it matters: The package is installed on the author's machine but missing from requirements.txt, pyproject.toml or package.json, so a clean install (CI, Docker, production) fails with an import error.

How to fix: Add the package with a pinned version to the project's dependency file.

References: CWE-1104

### QA008

**TypeScript checking disabled for a whole file** (low)

Why it matters: `// @ts-nocheck` hides every type error in the file, including the ones that would catch broken AI edits.

How to fix: Remove @ts-nocheck and fix or narrowly suppress the individual errors.

## LLM review (model-generated, unverified)

| ID | Severity | Status | Rule |
| --- | --- | --- | --- |
| [AI001](#ai001) | medium | stable | Issue reported by the LLM review (unverified) |

### AI001

**Issue reported by the LLM review (unverified)** (medium)

Why it matters: With --llm-review a model reads the riskiest files and reports issues the rules did not cover. These are suggestions from a model and can be wrong.

How to fix: Check the issue by hand before acting on it; suppress or disable AI001 if it is a false alarm.

## Data and database

| ID | Severity | Status | Rule |
| --- | --- | --- | --- |
| [DATA001](#data001) | medium | preview | Database query inside a loop (N+1) |
| [DATA002](#data002) | high | stable | Whole user record returned to the client |
| [DATA003](#data003) | low | stable | Destructive database migration |
| [DATA004](#data004) | medium | stable | Money stored as a floating-point number |
| [DATA005](#data005) | high | stable | Private table readable by everyone |
| [DATA006](#data006) | low | stable | Timestamp without time zone |
| [DATA007](#data007) | low | preview | Environment variable missing from the example env file |
| [DATA008](#data008) | medium | stable | Database client created per request |
| [DATA009](#data009) | medium | stable | SQLite file database on a serverless host |
| [DATA010](#data010) | low | preview | Several writes without a transaction |

### DATA001

**Database query inside a loop (N+1)** (medium, preview)

Preview: Benchmark precision 20% (1 of 5): a loop over a few fixed items, a deliberate per-row transaction or an offline job looks the same as a request-time N+1.

Why it matters: One query per item turns a page with 100 rows into 101 round trips: slow pages, timeouts and database load that grows with your data.

How to fix: Fetch everything in one query (IN / join / include / select_related / prefetch_related) or batch the writes (createMany, bulk_create, executemany).

References: CWE-1050

### DATA002

**Whole user record returned to the client** (high)

Why it matters: Returning the full user or account row sends every column to the browser, including password hashes, reset tokens, Stripe ids and other private fields.

How to fix: Select only the fields the client needs (Prisma `select`, Mongoose projection, a response schema).

References: CWE-213, A01:2021

### DATA003

**Destructive database migration** (low)

Why it matters: DROP TABLE, DROP COLUMN, TRUNCATE and column type changes destroy data and can lock big tables.

How to fix: Back up first, deploy in steps (stop writing, copy, then drop) and keep a down migration.

### DATA004

**Money stored as a floating-point number** (medium)

Why it matters: Floats cannot represent most decimal amounts exactly (0.1 + 0.2 != 0.3), so totals, refunds and balances drift by cents.

How to fix: Store integer cents or use NUMERIC/DECIMAL columns and Decimal types.

References: CWE-1339

### DATA005

**Private table readable by everyone** (high)

Why it matters: A Supabase policy `for select using (true)` on a table that holds users, orders, messages or keys lets anyone with the public anon key read every row.

How to fix: Scope the policy to the owner, for example `using (auth.uid() = user_id)`, or to `authenticated`.

References: CWE-284, A01:2021

### DATA006

**Timestamp without time zone** (low)

Why it matters: Naive datetimes and `timestamp without time zone` columns silently mix local and UTC times, which breaks expiry checks, schedules and reports across regions and daylight saving.

How to fix: Use timezone-aware values: `datetime.now(timezone.utc)` and `timestamptz` columns.

### DATA007

**Environment variable missing from the example env file** (low, preview)

Preview: Benchmark precision 50% (6 of 12): a setting that is optional by design (an SDK default, a feature that is simply off) looks the same as a required one.

Why it matters: The code reads a variable that .env.example does not document, so the next deploy or teammate setup crashes or silently runs with a missing setting.

How to fix: Add the variable (with a placeholder value) to .env.example.

### DATA008

**Database client created per request** (medium)

Why it matters: Creating a client, pool or engine inside a handler opens new connections on every request and exhausts the database's connection limit under load.

How to fix: Create one client at module level (and reuse it via globalThis in Next.js development).

References: CWE-400

### DATA009

**SQLite file database on a serverless host** (medium)

Why it matters: Serverless platforms give each request a fresh, read-only or throw-away file system, so data written to a SQLite file disappears or fails to save.

How to fix: Use a hosted database (Postgres, MySQL, Turso, D1) or a mounted persistent volume.

### DATA010

**Several writes without a transaction** (low, preview)

Preview: Benchmark precision 89% (8 of 9): writes in separate webhook event branches or helpers are counted as one handler's writes.

Why it matters: When one of several related writes fails halfway (for example charge recorded but order not created), the data is left inconsistent.

How to fix: Wrap related writes in a transaction (prisma.$transaction, db.transaction, BEGIN/COMMIT).

References: CWE-662

## Reliability and performance

| ID | Severity | Status | Rule |
| --- | --- | --- | --- |
| [REL001](#rel001) | medium | stable | Outbound HTTP request without a timeout |
| [REL002](#rel002) | medium | stable | Blocking call inside an async handler |
| [REL003](#rel003) | medium | stable | Webhook handler is not idempotent |
| [REL004](#rel004) | medium | stable | Upload accepted without a size limit |
| [REL005](#rel005) | medium | stable | In-memory state on a serverless host |
| [REL006](#rel006) | low | stable | No health-check endpoint |

### REL001

**Outbound HTTP request without a timeout** (medium)

Why it matters: `requests` and `urlopen` wait forever by default. One slow or dead upstream API ties up a worker per request until the whole service stops responding.

How to fix: Always pass a timeout, for example `requests.get(url, timeout=10)`.

References: CWE-1088

### REL002

**Blocking call inside an async handler** (medium)

Why it matters: time.sleep, requests and subprocess block the event loop, so every other request on that worker waits until the call finishes.

How to fix: Use the async equivalent (asyncio.sleep, httpx.AsyncClient, asyncio.create_subprocess_exec) or run the call in a thread with asyncio.to_thread.

References: CWE-1050

### REL003

**Webhook handler is not idempotent** (medium)

Why it matters: Payment and other providers retry webhooks. Without recording the event id, a retry credits a customer, creates an order or sends an email twice.

How to fix: Store each processed event id (unique constraint) and skip events you have already handled.

References: CWE-837

### REL004

**Upload accepted without a size limit** (medium)

Why it matters: Reading an upload with no size limit lets one large request exhaust memory or disk and crash the server.

How to fix: Set a limit (MAX_CONTENT_LENGTH, multer limits.fileSize, a size check before reading) and stream large files.

References: CWE-770

### REL005

**In-memory state on a serverless host** (medium)

Why it matters: Serverless functions run many short-lived instances that do not share memory, so rate limits, sessions and caches kept in a module-level Map or object silently reset and never apply across instances.

How to fix: Keep shared state in Redis/Upstash, the database or the platform's KV store.

### REL006

**No health-check endpoint** (low)

Why it matters: Load balancers, containers and uptime monitors need a cheap endpoint to tell a dead instance from a live one.

How to fix: Add GET /health (or /healthz) that returns 200 when the app and its database are reachable.

## UI, UX and accessibility

| ID | Severity | Status | Rule |
| --- | --- | --- | --- |
| [UI001](#ui001) | low | stable | Image without alt text |
| [UI002](#ui002) | low | stable | Click handler on a non-interactive element |
| [UI003](#ui003) | low | stable | Form field without a label |
| [UI004](#ui004) | medium | stable | Control that does nothing |
| [UI005](#ui005) | low | stable | Array index used as key for a changing list |
| [UI006](#ui006) | low | preview | Destructive action without confirmation |
| [UI007](#ui007) | medium | stable | Hydration mismatch |
| [UI008](#ui008) | medium | stable | Effect without cleanup |
| [UI009](#ui009) | low | stable | Data loaded without loading or error state |
| [UI010](#ui010) | low | stable | Placeholder content left in the UI |
| [UI011](#ui011) | low | stable | No error page |
| [UI012](#ui012) | low | stable | Missing page metadata or viewport |
| [UI013](#ui013) | medium | stable | Link to a page that does not exist |
| [UI014](#ui014) | low | preview | Image without width and height |
| [UI015](#ui015) | low | preview | Form error not announced to screen readers |
| [UI016](#ui016) | medium | preview | Focus outline removed |
| [UI017](#ui017) | medium | preview | Link to an asset that does not exist |

### UI001

**Image without alt text** (low)

Why it matters: Screen-reader users get the file name or nothing, and the image is invisible to search engines.

How to fix: Add alt text that says what the image shows, or alt="" for purely decorative images.

References: CWE-1078

### UI002

**Click handler on a non-interactive element** (low)

Why it matters: A div or span with onClick cannot be focused or triggered with the keyboard, so keyboard and screen-reader users cannot use it.

How to fix: Use a <button> (or <a> for navigation); otherwise add role, tabIndex and an onKeyDown handler.

References: CWE-1078

### UI003

**Form field without a label** (low)

Why it matters: Without a label, screen readers announce only "edit text", and placeholder text disappears as soon as the user types.

How to fix: Wrap the field in a <label>, point a <label htmlFor> at its id, or add aria-label.

References: CWE-1078

### UI004

**Control that does nothing** (medium)

Why it matters: A button whose handler is empty or only logs, or a link to "#", looks finished but does nothing: a typical sign of generated UI that was never wired up.

How to fix: Wire the control to its action, or remove it until the feature exists.

### UI005

**Array index used as key for a changing list** (low)

Why it matters: When items are added, removed or reordered, React reuses the wrong component state (inputs keep the old text, the wrong row stays checked).

How to fix: Use a stable id from the item as the key.

### UI006

**Destructive action without confirmation** (low, preview)

Preview: Benchmark precision 71% (5 of 7): a confirmation dialog in a parent component, or a removal from local state only, is not seen.

Why it matters: A delete or remove that runs on a single click, with no confirmation or undo, loses user data on a misclick.

How to fix: Ask for confirmation (a dialog), or offer undo for a few seconds before deleting for good.

### UI007

**Hydration mismatch** (medium)

Why it matters: Random numbers or the current time rendered on the server differ on the client, so React reports a hydration error and re-renders the page.

How to fix: Compute the value in useEffect after mount, or pass it from the server as a prop.

### UI008

**Effect without cleanup** (medium)

Why it matters: An effect that starts a timer, listener or subscription without returning a cleanup function leaks it on every remount (twice in development), causing duplicate events and memory growth.

How to fix: Return a function from the effect that clears the timer, removes the listener or unsubscribes.

References: CWE-401

### UI009

**Data loaded without loading or error state** (low)

Why it matters: If the request is slow the user sees an empty screen; if it fails the error is swallowed and the screen stays empty with no explanation.

How to fix: Track loading and error state (or use a data library such as SWR or React Query) and render both.

### UI010

**Placeholder content left in the UI** (low)

Why it matters: Lorem ipsum in shipped pages makes the product look unfinished.

How to fix: Replace it with real copy, or hide the section until it has content.

### UI011

**No error page** (low)

Why it matters: Without app/error.tsx a thrown error replaces the page with the generic Next.js "Application error" screen, with no way back.

How to fix: Add app/error.tsx (and app/global-error.tsx) with a friendly message and a retry button.

### UI012

**Missing page metadata or viewport** (low)

Why it matters: Pages without a title and description look broken in tabs, bookmarks and search results; without a viewport tag phones show a tiny zoomed-out page.

How to fix: Export metadata (title, description) from the root layout and include the viewport meta tag.

### UI013

**Link to a page that does not exist** (medium)

Why it matters: The link points to a path with no matching page or route, so users land on a 404.

How to fix: Fix the path, or create the page.

### UI014

**Image without width and height** (low, preview)

Preview: New in 0.7.1: not yet measured on enough real-world findings in the benchmark.

Why it matters: The browser cannot reserve space for an image without dimensions, so the content below jumps when it loads (cumulative layout shift, a Core Web Vital).

How to fix: Set `width` and `height` (the intrinsic size is enough; CSS can still scale it), or give the image a fixed box with CSS such as `aspect-ratio`.

### UI015

**Form error not announced to screen readers** (low, preview)

Preview: New in 0.7.1: not yet measured on enough real-world findings in the benchmark.

Why it matters: An error message that only appears next to the field is invisible to a screen reader user, who hears nothing when the form is rejected.

How to fix: Give the message an id and point the input's `aria-describedby` at it, with `aria-invalid` on the input, or render it in a `role="alert"` element.

### UI016

**Focus outline removed** (medium, preview)

Preview: New in 0.7.1: not yet measured on enough real-world findings in the benchmark.

Why it matters: `outline: none` with no replacement leaves keyboard users unable to see which control has focus (WCAG 2.4.7).

How to fix: Keep the outline, or replace it with a visible `:focus-visible` style such as a ring, border or box-shadow.

### UI017

**Link to an asset that does not exist** (medium, preview)

Preview: New in 0.7.1: not yet measured on enough real-world findings in the benchmark.

Why it matters: The image, font, icon or file is not in the public folder, so the browser gets a 404: a broken image or a missing font.

How to fix: Add the file to the public folder, or fix the path.

## Frontend-backend contracts

| ID | Severity | Status | Rule |
| --- | --- | --- | --- |
| [API001](#api001) | medium | stable | Frontend calls an API path that no route handles |
| [API002](#api002) | medium | stable | Frontend calls an API route with the wrong method |

### API001

**Frontend calls an API path that no route handles** (medium)

Why it matters: The browser code requests a path that no backend route in this project serves, so the request always fails with 404: often a renamed route or a route the model forgot to write.

How to fix: Create the route, or fix the path in the call.

### API002

**Frontend calls an API route with the wrong method** (medium)

Why it matters: The route exists but does not accept this HTTP method, so the request fails with 405 (or reaches a different handler than intended).

How to fix: Send the method the route handles, or add a handler for this method.
