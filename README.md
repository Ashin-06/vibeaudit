# vibeaudit

[![CI](https://github.com/Ashin-06/vibeaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/Ashin-06/vibeaudit/actions/workflows/ci.yml)
![Python 3.9 to 3.13](https://img.shields.io/badge/python-3.9%20to%203.13-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

**A security and quality audit for apps built with AI coding assistants, and for apps that use LLMs.**

vibeaudit reads a whole repository (frontend, backend, database rules, CI config and the AI parts) and
gives you a prioritised list of what is actually dangerous or broken, each with file and line, why it
matters and how to fix it.

It targets the mistakes that AI-generated ("vibe-coded") apps keep shipping: API keys in the browser
bundle, API routes with no auth check, Supabase tables without Row Level Security, packages the assistant
invented, model output piped into `exec`, unbounded token spend and security placeholders that were never
finished. Beyond security it catches what makes generated apps break in production: unfinished stubs and
missing imports, N+1 queries and money stored as floats, requests without timeouts, buttons that do
nothing, inaccessible forms and frontend calls to API routes that do not exist.

- Works offline with no API key. The network is used only for package-registry and vulnerability
  lookups (`--offline` turns that off); an LLM is used only if you ask for it.
- Pure Python, no dependencies on 3.11+ (`tomli` on 3.9 and 3.10). Linux, macOS and Windows.
- 144 rules in 12 categories, mapped to CWE, the OWASP Top 10 and the OWASP Top 10 for LLM Applications.
- Terminal output plus JSON, SARIF 2.1.0 (GitHub code scanning), Markdown, HTML, an SVG badge and a fix
  brief you can paste into an AI assistant.
- Fits into CI (GitHub Action, `--diff`), pre-commit (`--staged`) and coding agents (an MCP server).

Contents: [Quickstart](#quickstart) - [Example output](#example-output) - [What it checks](#what-it-checks) -
[Install](#install) - [Commands](#commands) - [Automatic fixes](#automatic-fixes-vibeaudit-fix) - [Configuration](#configuration) - [CI and pre-commit](#ci-and-pre-commit) -
[Editors](#editors-vs-code-cursor-and-other-lsp-clients) - [MCP server](#mcp-server-for-coding-agents) - [Scoring](#scoring) - [False positives](#false-positives-and-suppressing-findings) -
[Limits](#limits-and-what-is-not-covered) - [Contributing](#contributing-security-and-license)

## Quickstart

```bash
pip install "vibeaudit @ git+https://github.com/Ashin-06/vibeaudit.git@v0.8.4"
```

```bash
vibeaudit scan path/to/your/project
```

```bash
vibeaudit scan path/to/your/project --report html
```

The first command installs it, the second prints findings in the terminal, the third also writes
`vibeaudit-report.html`, a self-contained page you can open in a browser. The exit code is 1 when there is
a finding at `high` or above, so the same command works as a CI gate.

## Example output

```
$ vibeaudit scan tests/fixtures/vuln_flask_llm
Stack: Flask, OpenAI SDK

[CRITICAL] AUTH008 Auth check stub always succeeds
  app.py:24  `verify_token()` always returns True.
    > def verify_token(token):
  Why: A function that is supposed to verify a token, password or permission just returns true...
  Fix: Implement the real check (verify signature, expiry, user and role) or use a maintained auth library.

[CRITICAL] BE002 Command injection
  app.py:50  Request data flows into a shell command.
    > os.system("echo " + request.args.get("name", ""))
...
Summary
  critical: 3  high: 20  medium: 15  low: 7   total: 45
  ...
  Score: 0/100  Grade: F
  Domains: Security 0  AI 42  Quality 66  Data 93  Reliability 99  UI 100
```

That project is one of the deliberately vulnerable sample apps in `tests/fixtures/`.

## What it checks

| Category | What it finds |
| --- | --- |
| Secrets (SEC) | provider keys and tokens, private keys, high-entropy secrets, hard-coded or default signing secrets, database URLs with passwords, committed or un-ignored `.env` files, secrets in `NEXT_PUBLIC_`/`VITE_` variables, a Supabase `service_role` key outside the server, secrets in logs, hard-coded passwords, keys baked into committed bundles |
| Supply chain (DEP) | packages that do not exist (hallucinated names), typosquats of popular packages, packages first published in the last 30 days, known vulnerabilities (OSV) for pinned versions, missing lockfiles, install scripts that run remote code, unpinned MCP servers, extra package indexes (dependency confusion; preview) |
| Backend (BE) | SQL, NoSQL and command injection, `eval`/`exec`, unsafe deserialization, SSRF, path traversal, server-side template injection, open redirects, mass assignment, debug mode, permissive CORS, disabled TLS verification, weak password hashing, insecure randomness, unverified JWTs, leaked error details, no server-side validation; in preview: payment amounts taken from the client, email header injection |
| Frontend (FE) | XSS through raw HTML sinks, LLM APIs called from the browser, authorization decisions in browser storage, `postMessage` without origin checks, tokens in `localStorage`, production source maps, hard-coded localhost URLs |
| Auth (AUTH) | endpoints that change data or spend money without authentication, admin routes without a role check, IDOR-shaped handlers, unverified webhooks, tables without Row Level Security, permissive policies, open Firebase rules, auth functions that always return true, CSRF disabled, login without rate limiting; in preview: JWTs accepted without pinned algorithms, session cookies without SameSite or CSRF protection, webhook signatures without replay protection, rate limits keyed on X-Forwarded-For |
| Config (CFG) | containers running as root, unpinned base images, secrets in images, GitHub Actions script injection, unsafe `pull_request_target`, any Host header accepted, default database passwords, missing security headers, `.env` copied into an image; in preview: third-party GitHub Actions not pinned to a commit, `permissions: write-all`, privileged or host-mounted Kubernetes containers and missing resource limits, public S3 buckets, admin and database ports open to the internet, unencrypted RDS and EBS storage (Terraform and CloudFormation) |
| LLM and agents (LLM) | untrusted input in the system prompt, model output in a dangerous sink, no token limit, LLM endpoints without rate limiting, agent tools with dangerous capabilities, dangerous agent options, system prompts shipped to the browser, unsafe model loading, unbounded agent loops, vector search without a tenant filter, model output parsed as JSON without error handling, retired model ids, MCP servers with whole-disk access or plain HTTP, secrets in MCP configs, agents that read untrusted content and also have dangerous tools; in preview: coding agents configured to act without asking, streamed completions not cancelled on disconnect, prompts and completions written to logs |
| Code completeness (QA) | no tests, no CI, swallowed exceptions, security TODOs, unfinished stubs, imports of files or names that do not exist, packages imported but not declared, TypeScript checking disabled |
| Data (DATA) | N+1 queries, whole user records returned to the client, destructive migrations, money as float, private tables readable by everyone, timestamps without time zone, env vars missing from the example env file, a database client per request, SQLite on a serverless host, several writes without a transaction |
| Reliability (REL) | HTTP requests without a timeout, blocking calls in async handlers, webhooks that are not idempotent, uploads without a size limit, in-memory state on serverless hosts, no health-check endpoint |
| UI, UX and accessibility (UI) | images without alt text, click handlers the keyboard cannot reach, unlabeled form fields, controls that do nothing, index keys on changing lists, deletes without confirmation, hydration mismatches, effects without cleanup, no loading or error state, lorem ipsum, no error page, missing metadata or viewport, links to pages that do not exist; in preview: images without width and height, form errors that screen readers do not hear, focus outlines removed without a replacement, links to assets that are not in the public folder |
| Frontend-backend contracts (API) | frontend calls to API paths no route handles, and calls with a method the route does not accept |

Every rule, with its severity, why it matters and how to fix it, is in the
**[rule catalogue (docs/RULES.md)](docs/RULES.md)**; `vibeaudit rules` prints the same list.

Routes are found for Flask, FastAPI, Django REST framework, Express, Fastify, Hono, Next.js (app and pages
routers, server actions), SvelteKit, Supabase edge functions and Firebase functions. Python is analysed on
its syntax tree with taint tracking (request data, model output and agent-tool arguments are followed into
SQL, shell, `eval`, file paths, URLs, templates, redirects and HTML); JavaScript and TypeScript get the same
checks on a lexer that keeps exact offsets.

### Why another scanner

Good tools exist, and vibeaudit runs them when they are installed instead of replacing them:

| Tool | Great at | Misses in AI-built apps |
| --- | --- | --- |
| gitleaks, trufflehog | secrets in files and history | secrets exposed by design: `NEXT_PUBLIC_OPENAI_API_KEY`, a `service_role` key in a client component, `dangerouslyAllowBrowser: true` |
| npm audit, pip-audit, OSV-Scanner | known CVEs in real packages | packages that do not exist (hallucinated) or appeared last week (slopsquatting) |
| Bandit, Semgrep, CodeQL | classic injection patterns | whether a route has any auth, whether model output reaches `exec`/SQL/HTML, RLS policies, Firebase rules |
| garak, promptfoo | red-teaming a running model | static code: user input in the system prompt, agent tools with shell access, missing `max_tokens` |

## Install

vibeaudit is installed from this repository (it is not on PyPI yet). Python 3.9 or newer:

```bash
pip install "vibeaudit @ git+https://github.com/Ashin-06/vibeaudit.git@v0.8.4"
```

or, to keep it in its own environment:

```bash
pipx install "git+https://github.com/Ashin-06/vibeaudit.git@v0.8.4"
```

Optional: if [gitleaks](https://github.com/gitleaks/gitleaks), [bandit](https://github.com/PyCQA/bandit),
[osv-scanner](https://github.com/google/osv-scanner) or [semgrep](https://github.com/semgrep/semgrep) are on
your `PATH`, their findings are merged into the report and de-duplicated.

## Commands

| Command | What it does |
| --- | --- |
| `vibeaudit scan [PATH]` | Audit a project (default: the current directory). |
| `vibeaudit watch [PATH]` | Scan, then re-scan after every change and print the findings that appeared (`+`) or were fixed (`-`); see [Watch mode](#watch-mode). |
| `vibeaudit review [PATH] --diff REV` | Pull request review comments, with suggested fixes, for the findings on changed lines; `--post` sends them to GitHub (see [Pull request review](#pull-request-review)). |
| `vibeaudit fix [PATH]` | Print a diff that fixes the findings with one obvious repair; `--apply` writes it (see [Automatic fixes](#automatic-fixes-vibeaudit-fix)). |
| `vibeaudit explain FINDING` | Explain one finding (`FILE:LINE`, `FILE:LINE:RULE` or a fingerprint prefix): the rule, the code and the data flow that led to it (`--format json`). |
| `vibeaudit routes [PATH]` | List every HTTP entry point with method, path, location and whether it has a visible auth check, writes data or calls a paid AI API (`--format text\|json\|md`). |
| `vibeaudit rules` | List every rule (`--format text\|json\|md`; JSON includes the why and fix text). |
| `vibeaudit feedback` | Record that a finding is a false positive or confirmed, or list recorded feedback (see [False positives](#false-positives-and-suppressing-findings)). |
| `vibeaudit update` | Refresh the popular-package lists and the retired-model list; `--self` upgrades vibeaudit with pip; `--export FILE [--osv PyPI,npm]` and `--import FILE` carry the data to a machine without network (see [Offline and air-gapped use](#offline-and-air-gapped-use)). |
| `vibeaudit lsp` | Run the language server for editors: diagnostics and fix code actions (see [Editors](#editors-vs-code-cursor-and-other-lsp-clients)). |
| `vibeaudit mcp` | Run the MCP server for coding agents (see [MCP server](#mcp-server-for-coding-agents)). |

Every command has `--help`.

### `vibeaudit scan` options

| Option | Meaning |
| --- | --- |
| `-r`, `--report FORMAT[:PATH]` | Also write a report: `json`, `sarif`, `md`, `html`, `prompt` (a fix brief for AI assistants) or `badge` (SVG). Repeatable; `-` as the path writes to stdout, as in `-r json:-`. Default path `vibeaudit-report.<ext>`. |
| `--fail-on SEVERITY` | Exit 1 when a finding is at least `critical`, `high` (default), `medium` or `low`; `none` never fails. |
| `--min-severity SEVERITY` | Hide findings below this severity (default `low`). |
| `--monorepo` | Scan every package as a project of its own, against its own manifest, with a score per package (see [Monorepos](#monorepos)). |
| `--include-preview` | Count findings of preview rules toward `--fail-on` and the score; they are always reported (see [STABILITY.md](STABILITY.md)). |
| `--no-gate-severe-preview` | Leave out the severe preview rules (command injection, `eval`, unsafe deserialization, open redirect, XSS), which by default count toward `--fail-on` and the score. |
| `--offline` | No network: skip registry and new-package lookups, and check known vulnerabilities against an imported OSV index if there is one (the typosquat check still runs). |
| `--exclude GLOB` | Skip matching paths (repeatable). A `.vibeauditignore` file with one glob per line works too. |
| `--disable RULE_OR_CATEGORY` | Switch off a rule (`QA002`) or a category (`quality`); repeatable, comma lists allowed. |
| `--baseline FILE` | Hide findings already present in an earlier JSON report. |
| `--write-baseline FILE` | Save all current findings as a baseline and exit 0. |
| `--fail-on-regression N` | Exit 1 if the whole project's score is more than N points below the score in the `--baseline` report. The score is computed before `--baseline`, `--diff` and `--staged` hide findings. |
| `--external auto\|none\|LIST` | Third-party scanners to run: those installed (default), none, or a list such as `gitleaks,bandit`. |
| `--staged` | Report only findings on lines staged for commit (pre-commit hooks). |
| `--diff REV` | Report only findings on lines changed since `REV`, for example `origin/main` (pull requests). |
| `--config FILE` | Read settings from this file instead of `.vibeaudit.toml` / `pyproject.toml`. |
| `--no-config` | Ignore the scanned project's settings and feedback files (use this for code you do not trust). |
| `--plugin FILE_OR_MODULE` | Load custom rules (repeatable; this runs that Python code). |
| `--llm gemini\|openai\|anthropic` | Ask an LLM to triage findings (see [LLM-assisted checks](#llm-assisted-checks-optional)). |
| `--llm-model NAME`, `--llm-review`, `--llm-max-requests N` | Model name; also review the riskiest files for missed issues; hard cap on requests (default 10). |
| `--max-file-size BYTES` | Skip larger files (default 1,000,000). |
| `--file-timeout SECONDS` | Time each analysis step may spend on one file before it is stopped (default 30). |
| `--no-cache` | Do not read or write cached registry, vulnerability and LLM answers for this scan. |
| `-q`, `--quiet` / `--no-color` | Print only the summary / plain text. |

Exit codes: `0` nothing at the `--fail-on` level, `1` findings at that level, `2` usage error.

What is scanned: in a git checkout, tracked and untracked files that are not git-ignored (a local, ignored
`.env` is where secrets belong). Dependency and build folders (`node_modules`, `.venv`, `dist`, `build`,
`.next`, ...) are skipped, except that committed bundles under `dist/`, `build/` and `out/` and minified
files are still checked for secrets. In test files only real credentials are reported. Pinned versions
for the vulnerability check come from `requirements*.txt` and from lockfiles next to each manifest
(`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `poetry.lock`, `uv.lock`, `pdm.lock`,
`Pipfile.lock`).

A repository is untrusted input, so the scan is built to finish whatever it contains. A file that triggers
a bug is listed under `meta.internal_errors` in the JSON report while every other file is still scanned;
a file that exceeds `--file-timeout` or is nested too deeply to parse is listed under `meta.skipped`.
Symbolic links out of the project are not followed. Registry lookups retry timeouts and rate limits, stop
calling a host that is down, and never report a package as missing unless the registry said 404 or 410.

### LLM-assisted checks (optional)

```bash
GEMINI_API_KEY=... vibeaudit scan . --llm gemini --llm-review --llm-max-requests 10
```

- **Triage** adds a verdict and a reason to medium and higher findings. The model can never remove or
  downgrade a finding, because the audited code is untrusted and may contain text aimed at the model.
  Secrets are redacted before anything is sent.
- **Review** adds issues the rules did not cover as `AI001`, labelled model-generated and unverified.
- Providers: `gemini` (`GEMINI_API_KEY` or `GOOGLE_API_KEY`), `openai` (`OPENAI_API_KEY`; `OPENAI_BASE_URL`
  for any compatible server such as Ollama) and `anthropic` (`ANTHROPIC_API_KEY`). Verdicts are cached, so
  an unchanged finding costs no request the next time.

### Monorepos

```bash
vibeaudit scan . --monorepo          # or `monorepo = true` in .vibeaudit.toml
```

By default the whole repository is one project, so a rate limiter, CSRF middleware or a dependency declared in
one package counts for every package. With `--monorepo` every folder with its own manifest (`package.json`,
`pyproject.toml`, `requirements*.txt`, `setup.py`, `setup.cfg`, `Pipfile`) is scanned on its own, against
its own manifest and with only its own code as evidence; files outside every package (root scripts, CI,
infrastructure) are one more unit, and folders under tests or examples stay test code. Three rules are about
the repository, not a package (CI configuration QA002, the example env file DATA007 and a workspace lockfile
DEP005), so they come from one scan of the whole repository; the mode costs about two normal scans. Findings
keep their repository paths and fingerprints (baselines and feedback carry over), and the report adds a score
per package.

### Explaining a finding

```bash
vibeaudit explain app.py:19            # or app.py:19:LLM002, or a fingerprint prefix from a JSON report
```

`explain` shows the rule (what it means, why it matters, how to fix it), the code around the line and, when
the line uses request data or model output, the data flow traced back from it: each assignment the value
went through, up to where it came from (a request field, a route parameter, a model call, or in Python the
parameter of an ordinary function, whose callers are not followed). The trace follows
variables within the function (Python) or the file (JavaScript and TypeScript), not calls into other
functions, and shows only the steps that lead to a source.

```
Data flow (traced back from the line, best effort):
  from  app.py:15  plan = client.chat.completions.create(...)   (`plan` comes from model output)
  via   app.py:18  script = plan.choices[0].message.content     (`script`)
  to    app.py:19  exec(script)
```

### Watch mode

```bash
vibeaudit watch .                     # Ctrl+C to stop
vibeaudit watch . --interval 2 --min-severity medium
```

`watch` scans once, then checks for changed files every `--interval` seconds (default 1) and re-scans. It
keeps every unchanged file's text, parse trees, lexer state and per-file analysis between scans, and replays
the findings (and the routes) of per-file checks when nothing they depend on changed: the files they read,
the facts about other files they use (the names a module exports, whether an excluded path exists on disk)
and the project-wide facts they rely on (which functions call a model, which files sit behind auth
middleware, the configured helpers). Everything else runs again, so the result is always the same as a
fresh `scan`. A changed manifest or config file, or an added or removed file, replays nothing. On the
benchmark repositories a re-scan after one edit takes 0.13 to 0.46 s (median per repository; under 0.3 s on
four of five), against 0.5 to 4 s for a cold scan (`tools/watch_latency.py`). It runs offline, without
external tools, and honours the configuration, `--exclude` and `--config` like `scan`.

## Automatic fixes (`vibeaudit fix`)

```bash
vibeaudit fix .                  # print a unified diff, change nothing
vibeaudit fix . --apply          # write the changes
vibeaudit fix . --rule REL001    # only some rules (repeatable)
vibeaudit fix . > fixes.patch && git apply fixes.patch
```

`fix` scans the project the same way `scan` does (configuration, suppressions, baseline and feedback apply)
and rewrites the findings that have one obvious, deterministic repair:

| Rule | Codemod |
| --- | --- |
| REL001 | Adds `timeout=10` to `requests` and `urlopen` calls. |
| LLM003 | Adds an output token limit of 4096: `max_completion_tokens` (Chat Completions), `max_output_tokens` (Responses, Gemini config, `ChatGoogleGenerativeAI`), `max_tokens` (LangChain and LiteLLM), `maxOutputTokens` or `maxTokens` for the AI SDK by its major version in package.json. |
| LLM011 | Wraps the assignment or `return` that parses model output in `try`/`except ValueError` (Python) or `try`/`catch` (JavaScript); the fallback value is `None` / `null`, which the caller must handle. |
| BE016, AUTH011 | Removes `'none'` from an algorithms list, turns `ignoreExpiration: true` off, adds `algorithms=[...]` to PyJWT `jwt.decode()` (the algorithm the file signs with, else HS256), and narrows a mixed HMAC and RSA list to the algorithm the file signs with. |
| DATA004 | Float money columns become `Numeric(12, 2)` (SQLAlchemy), `DecimalField(max_digits=12, decimal_places=2)` (Django), `Decimal` (Prisma) or `numeric(12, 2)` (SQL). Create a migration afterwards; SQL files in migration folders are never edited. |
| BE012 | Replaces the wildcard or reflected CORS origin with an allow-list read from the `CORS_ORIGINS` environment variable (comma-separated), keeping credentials. |
| DATA013 | Gives a Redis key an expiry of one hour: `ex=3600` (redis-py), `{ EX: 3600 }` (node-redis), `"EX", 3600` (ioredis) or `{ ex: 3600 }` (Upstash) on `set`, added to an existing options object; for `hset`, `lpush`, `sadd` and the like, an `expire(key, 3600)` on the next line when the key is a plain name or string. Review the expiry in the diff. |

A file's change is kept only when the file still parses (`ast.parse` for Python, balanced brackets for
JavaScript and TypeScript). Files keep their line endings and byte order mark; files that are not UTF-8 or
mix line endings are left alone, and so is a file that changed on disk after it was read. Running `fix`
twice changes nothing the second time. Every finding a codemod could not rewrite is listed with the reason.

**Patches from a model (optional).** For findings without a codemod (auth checks, transactions, unverified
tokens), `--llm` asks the provider (see [LLM-assisted checks](#llm-assisted-checks-optional)) for the smallest
fix and writes it to `--patch` (default `vibeaudit-fix.patch`). It is never applied: a patch that does not
parse, reaches outside the lines the model was shown or contains redacted text is dropped, and the rest are
marked model-generated and unverified. `--llm-model` and `--llm-max-requests` work as for `scan`.

```bash
ANTHROPIC_API_KEY=... vibeaudit fix . --llm anthropic --patch auth-fixes.patch
```

## Configuration

Settings live in `.vibeaudit.toml` or in a `[tool.vibeaudit]` table of `pyproject.toml`. Command-line flags
win over the file. Unknown keys and wrong types are errors, so a typo cannot quietly weaken a scan.

```toml
# .vibeaudit.toml
fail-on = "high"
min-severity = "low"
exclude = ["legacy/**", "scripts/one_off_*.py"]
disable = ["QA002"]
baseline = ".vibeaudit-baseline.json"   # relative to this file
offline = false
external = "auto"

# Teach vibeaudit your project's own conventions
auth-helpers = ["require_org_member", "withWorkspaceAuth"]   # count as an auth check in a route
sanitizers = ["clean_sql_input"]                               # their output is not tainted
public-paths = ["/api/public/*", "/api/survey-*"]              # intentionally unauthenticated routes
```

Other keys: `include-preview`, `gate-severe-preview`, `monorepo`, `llm`, `llm-model`, `llm-max-requests`, `max-file-size`, `file-timeout`. The same settings apply
to `vibeaudit scan`, `vibeaudit routes`, `vibeaudit feedback`, the MCP server and the Python API. The file is
part of the scanned repository and can switch rules off: when you audit code you do not trust, use
`--no-config`.

## CI and pre-commit

`--diff` and `--staged` still analyse the whole project (auth middleware and helpers in unchanged files
count) but report only findings on added or changed lines.

**GitHub Action**, with results in the code scanning tab:

```yaml
name: vibeaudit
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0                  # needed for --diff
      - uses: Ashin-06/vibeaudit@v0.8.4
        with:
          fail-on: high
          args: --diff origin/main        # optional: only changed lines
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: vibeaudit.sarif
```

Inputs: `path` (default `.`), `fail-on` (default `high`), `sarif` (default `vibeaudit.sarif`), `args` (extra
flags, split on spaces), `setup-python` (`true`/`false`), `python-version`, `review` (`true` posts review
comments on pull requests) and `github-token` (default: the workflow token).

### Pull request review

With `review: "true"` the action also comments on the pull request: one review comment per finding on a
changed line (the 30 most severe), with why it matters, and a one-click GitHub suggestion when a
`vibeaudit fix` codemod rewrites it inside the diff. A re-run does not repeat comments it already posted.
The job needs `pull-requests: write`; on pull requests from forks the token is read-only and the review is
skipped with a warning. Use `pull_request`, not `pull_request_target`, so the pull request's code never runs
with a write token.

```yaml
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - uses: Ashin-06/vibeaudit@v0.8.4
        with:
          review: "true"
          args: --diff origin/${{ github.base_ref }} --baseline .vibeaudit-baseline.json --fail-on-regression 5
```

`vibeaudit review . --diff origin/main` prints the same review as JSON without posting it. To keep the
overall score from slipping, commit a baseline (`vibeaudit scan . --write-baseline .vibeaudit-baseline.json`)
and pass `--fail-on-regression N`: the build fails when the whole project's score drops more than N points
below the baseline's, even if every new finding is below `--fail-on`.

**Any other CI**: run `vibeaudit scan . --fail-on high -r sarif:results.sarif` and keep the exit code.

**pre-commit**:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Ashin-06/vibeaudit
    rev: v0.8.4
    hooks:
      - id: vibeaudit
```

The `vibeaudit` hook analyses the whole project and reports findings on the staged lines, which takes a
few seconds on a medium project. For a hook that never slows a commit down, use `vibeaudit-secrets`
instead (or as well, with `vibeaudit` in CI): it runs only the secret checks, which need nothing but the
file itself, on the staged content of the changed files, with one `git diff` call and without scanning the
rest of the project. On a 300-file repository it takes about 0.2 s on Windows, most of it Python and git
starting, against 1 to 5.5 s for the full hook on medium corpus repositories (`tools/hook_latency.py`). The
same command is `vibeaudit-hook`. Settings, `vibeaudit: ignore` comments, the baseline and feedback apply.

## Editors (VS Code, Cursor and other LSP clients)

`vibeaudit lsp` is a [Language Server Protocol](https://microsoft.github.io/language-server-protocol/) server
on stdio, written with the standard library only. It scans the workspace like `vibeaudit scan` (offline,
no external tools, with the workspace's configuration) and publishes every finding as a diagnostic, also for
unsaved changes. It keeps unchanged files between scans as `watch` does, and re-scans 0.25 seconds after the
last edit. The `vibeaudit fix` codemods are offered as quick fixes, plus a "fix all" action per file. The
server never writes a file: the editor applies the edits you accept. It accepts only `file:` URIs inside
the workspace folder and caps message sizes.

`editors/vscode` is a thin VS Code / Cursor extension that starts the server. CI builds it as a `.vsix`
artifact (it is not published); install it with **Extensions: Install from VSIX...**. Its
`vibeaudit.serverCommand` and `vibeaudit.serverArgs` settings are machine-scoped and it does not run in
untrusted workspaces, so a cloned repository cannot make it start another program. Other editors can run
`vibeaudit lsp` directly, for example in Neovim:

```lua
vim.lsp.start({ name = "vibeaudit", cmd = { "vibeaudit", "lsp" }, root_dir = vim.fn.getcwd() })
```

## MCP server for coding agents

`vibeaudit mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io) server on stdio, so Claude
Code, Cursor and other agents can audit their own changes before handing them back. All tools are
read-only:

| Tool | What it does |
| --- | --- |
| `scan_project` | Audit a directory (optionally only changed lines: `changes: "staged"` or a git revision). |
| `scan_file` | Audit one file in the context of its project. |
| `audit_current_file` | Audit the file being edited, also from unsaved or not yet written `content`; repeated calls reuse unchanged files. |
| `list_routes` | The routes inventory. |
| `check_package` | Before adding a dependency: does it exist, is it brand new, is it a typosquat, known vulnerabilities. |
| `verify_package` | `check_package` plus a verdict (ok, caution, block) with reasons, the real package for a Python import name (`cv2` is `opencv-python`) and whether the `project` already declares it. |
| `simulate_migration` | Dry-run a PostgreSQL migration (`path` to a .sql file, or `sql`): per statement the lock, what it blocks, table rewrites, data loss and a safer alternative. |
| `explain_rule` | What a rule means and how to fix it. |
| `auto_repair` | The `vibeaudit fix` diff for a directory (optionally one `file` or some `rules`); it writes nothing. |

```json
{ "mcpServers": { "vibeaudit": { "command": "vibeaudit", "args": ["mcp"] } } }
```

```bash
claude mcp add vibeaudit -- vibeaudit mcp
```

## Custom rules and the Python API

```python
# org_rules.py
from vibeaudit import route_rule, file_rule

@route_rule("ORG001", "Billing route without audit log", severity="high", fix="Call audit_log().")
def billing_audit(route):
    if route.path.startswith("/api/billing") and "audit_log(" not in route.body:
        return f"{route.path} changes billing without calling audit_log()."

@file_rule("ORG002", "print() in production code", severity="low", kinds=["py"])
def no_print(source_file):
    for number, line in enumerate(source_file.lines, 1):
        if line.strip().startswith("print("):
            yield number, "Use the logger instead of print()."
```

```bash
vibeaudit scan . --plugin org_rules.py
```

`rule(...)` registers a project-wide check that receives the project and the route table. Custom findings
appear in every report format and can be suppressed and baselined like built-in ones. Plugins run Python
code, so they are loaded only from `--plugin` or your own imports, never from the scanned repository.

```python
from vibeaudit import scan, project_options

result = scan("path/to/project", project_options("path/to/project", offline=True))
print(result.score, result.grade, result.domain_scores)
for f in result.findings:
    print(f.severity, f.rule_id, f.file, f.line, f.message)
for r in result.routes:
    print(r.methods, r.path, r.has_auth)
```

`scan(path)` without options, and `project_options(path, **overrides)`, apply the project's configuration;
an explicit `Options(...)` is used exactly as given. `scan()` may be called from several threads; scans
then run one at a time.

## Scoring

Each finding has a severity. The overall score is 100 minus 25 per critical, 10 per high, 3 per medium and
1 per low finding, floored at 0. The grade is F if there is any critical finding, otherwise A (90 and up),
B (75), C (60), D (40) or F.

The same formula gives a score per domain, so you can see where the problems are:

| Domain | Categories |
| --- | --- |
| Security | secrets, supply chain, backend, frontend, auth, config |
| AI | LLM and agents, LLM review |
| Quality | code completeness, frontend-backend contracts, custom rules |
| Data, Reliability, UI | one category each |

The terminal, JSON (`summary.domains`), Markdown and HTML reports all show them. A score is a summary for
tracking progress, not a security guarantee: read the findings.

Findings of **preview** rules (marked `(preview)`, `"preview": true` in JSON) are reported but left out of
the score, the grade and `--fail-on`, unless you pass `--include-preview`. The exception is the severe
preview rules (command injection, `eval`, unsafe deserialization, open redirect and XSS, marked
`"gates_in_preview": true`): a miss there costs more than a false alarm, so they count by default;
`--no-gate-severe-preview` leaves them out. A rule is in preview while its
measured precision is below 90% or it is new; see [STABILITY.md](STABILITY.md).

## False positives and suppressing findings

Static analysis guesses, and some findings will be wrong for your project. In order of preference:

- **Teach it your conventions** in the configuration file: `auth-helpers` for your own auth checks,
  `sanitizers` for your own cleaning functions, `public-paths` for routes that are meant to be open.
- **Record a verdict**, shared with your team through git:

  ```bash
  vibeaudit feedback false-positive AUTH001 app/api/internal.py:12 --note "only reachable from the VPN"
  ```

  ```bash
  vibeaudit feedback list
  ```

  Verdicts live in `.vibeaudit/feedback.json`. Later scans hide findings marked as false positives (the
  report says how many); entries follow the code when lines move. Absolute paths and paths copied from an
  editor work; `--config` and `--plugin` work as for `scan`.
- **Inline**: `# vibeaudit: ignore[AUTH001]` (or `// vibeaudit: ignore[AUTH001]`, or without the bracket
  for every rule) on the line or the line above.
- **Paths, rules, existing debt**: `--exclude` or `.vibeauditignore`, `--disable`, and `--baseline` to see
  only new findings.

An empty `except`/`catch` with an explanatory comment is treated as deliberate. If a rule is wrong in a way
that is not specific to your code, please open an issue with a minimal example.

## Offline and air-gapped use

`--offline` makes no network connection (a test runs every offline command with the network disabled). Only
`--llm`, which you ask for explicitly, still sends code to its model provider. The popular-package lists used
by the typosquat check ship with vibeaudit. To use fresh data and check known vulnerabilities without network,
make a bundle on a connected machine and import it:

```bash
vibeaudit update --export vibeaudit-data.zip --osv PyPI,npm   # connected machine (downloads OSV's dumps)
vibeaudit update --import vibeaudit-data.zip                  # air-gapped machine
vibeaudit scan . --offline
```

The bundle has the data files and, with `--osv`, a vulnerability index per ecosystem built from
[OSV](https://osv.dev)'s public dumps: for every package, each advisory's listed affected versions and fixed
ranges. An offline scan reports a pinned version that an advisory lists (DEP004, with the version to upgrade
to) and says in its notes which index date it used, or that vulnerabilities were not checked. Advisories that
give only version ranges and no version list are left out of the index (the export says how many). `--import`
checks every file against the SHA-256 in the bundle's manifest, accepts only vibeaudit's own data files and
validates their contents before it writes anything.

## Caching and updates

Registry answers and vulnerability advisories are cached for a day ("package does not exist" for an hour,
because a name can be registered at any time); failed lookups are never cached. The cache is in
`%LOCALAPPDATA%\vibeaudit`, `~/Library/Caches/vibeaudit` or `~/.cache/vibeaudit` (`VIBEAUDIT_CACHE_DIR`
overrides it). `--no-cache` or `VIBEAUDIT_NO_CACHE=1` turns it off.

`vibeaudit update` downloads the latest popular-package lists (used for typosquat checks) and retired-model
list (LLM012) from this repository; a file is used only if it passes validation. Set `GITHUB_TOKEN` if you
hit GitHub's rate limit.

## Limits and what is not covered

How it reads code:

- Data flow is followed inside a function (plus one level of helper functions for auth checks), not across
  the whole program.
- JavaScript and TypeScript are read with a lexer and patterns, not a full parser.
- "Authenticated" means an auth check is visible in the route or its helpers, not that the check is correct.
- Rate limiting and input validation are detected project-wide, so one limiter anywhere counts.
- Router prefixes (FastAPI `include_router`, Express `app.use("/api", router)`, Flask blueprints, Django
  URLconfs) are not resolved yet, so the frontend-backend contract rules only run when routes are
  file-based (Next.js, SvelteKit) or the project has no prefixes. Django URLconf views, NestJS and Remix
  routes are only partly covered.
- UI rules cover React, Next.js and HTML templates; Vue, Svelte and Astro files get only the alt-text and
  placeholder checks.
- The per-file time budget is checked between regex matches and statements; a single regex step cannot be
  interrupted, which is why every pattern is tested for linear time.

Not covered (see [ROADMAP.md](ROADMAP.md); contributions welcome):

- Languages other than Python and JavaScript/TypeScript: Go, Java, Kotlin, Rust, Ruby, PHP, C#.
- Infrastructure as code beyond the checks listed above (AWS only for Terraform and CloudFormation; no Azure or
  GCP resources, no Terraform modules or variables resolved, Helm templates read as plain YAML).
- XML external entities (XXE) and other XML parser settings.
- Automatic fixes (a fix command that edits code) and a gate on score drift between commits.
- Runtime testing: vibeaudit reads code, it does not attack a running app or a model. For prompt injection
  and jailbreaks against a live model, use promptfoo or garak.

## Accuracy

Every rule is measured on a labelled benchmark: 53 public repositories pinned to exact commits (AI-built
Lovable/Supabase apps, LLM apps, well-maintained Python and JavaScript projects, infrastructure code,
projects at the commit before a published security fix, and deliberately vulnerable training apps), where
each of the 1,472 findings was read in the code and labelled true or false, plus seeded examples for
recall. 41 repositories were used to find and fix false positives; 12 are held out and never used for
tuning. Stable rules (the ones `--fail-on` acts on) are 95% precise on the tuned split and 94% on the
held-out one; preview rules, reported but not gating, are lower. Precision per rule
on both splits, seeded recall and the status of every rule are in
[benchmark/RESULTS.md](benchmark/RESULTS.md). Every stable rule with at least 5 labelled findings is at
90% or above; rules below that are in preview, and a rule leaves preview only on its held-out precision.
CI fails when a rule's precision drops, a labelled true positive disappears or seeded recall drops.

Reproduce it (the repositories are cloned into `~/.cache/vibeaudit-bench`, never into this one):

```bash
python tools/benchmark.py run --json results.json
```

How the corpus was chosen and how findings are labelled: [benchmark/README.md](benchmark/README.md).

## How it was validated

- **Sample apps.** Five deliberately vulnerable apps (Flask + OpenAI, Next.js + Supabase, Express + MongoDB,
  FastAPI + LangChain agent with an MCP config, config files only) and one clean app. Every expected
  finding is marked in the code; the tests compare the exact set of (file, line, rule), so a missed finding
  or a false alarm fails, and the clean app must produce nothing. Fake credentials are generated at test
  time.
- **Property tests.** Each vulnerable app is changed in ways that keep it vulnerable (lines shifted,
  variables renamed, CRLF, moved into a monorepo, routes moved into a blueprint) and every finding must
  stay; 33 safe rewrites (parameterise the query, add the auth check, ...) must each remove exactly the
  targeted finding.
- **Fuzzing and hostile input.** Random and malformed files with fixed seeds (garbage code, binary files,
  odd encodings, 3,000-level nesting, 1 MB single lines, broken manifests and lockfiles, symlink loops,
  unreadable files): the scan must not crash, hang or write invalid JSON or SARIF. Every regular expression
  is timed against input designed to make it backtrack.
- **Scale.** A generated 10,000-file repository scans in about a minute (59 s on a Windows laptop, 130 MB
  peak traced memory); CI runs 2,000 files on every platform and 10,000 on Linux.
- **Real projects.** The rules were run on 19 public repositories, from AI chat apps and Next.js SaaS
  templates to Flask and Werkzeug themselves and a deliberately vulnerable Flask app, and every finding was
  read. False alarms were fixed at the root with a regression test; confirmed problems included an
  unauthenticated route in a popular chat UI that loads any user's API key by id with the service-role key.
- **Four external audits.** Each finding was reproduced with a failing test before it was fixed; see the
  [CHANGELOG](CHANGELOG.md).
- **Packaging.** The built wheel was installed in fresh environments on Python 3.9, 3.11, 3.12 and 3.13 and
  every command was run; CI runs the tests on 3.9 to 3.13 on Linux, macOS and Windows, and also from a plain
  checkout without installing.

## Verifying a release

Each [GitHub release](https://github.com/Ashin-06/vibeaudit/releases) has the wheel, the sdist and a
CycloneDX SBOM (`vibeaudit-VERSION.cdx.json`), built by the release workflow from the tagged commit. Their
build provenance is signed with GitHub artifact attestations (Sigstore). With the GitHub CLI:

```bash
gh attestation verify vibeaudit-0.8.4-py3-none-any.whl --repo Ashin-06/vibeaudit
```

Run the same for the `.tar.gz` and the `.cdx.json` file. The check passes only if the file was built by
this repository's release workflow; `--format json` shows the commit and workflow it came from. The SBOM
lists what the wheel installs (vibeaudit has no runtime dependencies on Python 3.11 and later, and
`tomli` before that). vibeaudit is not published to PyPI by this project yet; install a verified wheel
with `pip install vibeaudit-0.8.4-py3-none-any.whl`.

## Contributing, security and license

- Contributing: see [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports with a minimal example are the most
  useful contribution, especially false positives and missed findings.
- Security issues in vibeaudit itself: see [SECURITY.md](SECURITY.md); please do not open a public issue.
- License: MIT, see [LICENSE](LICENSE). Popular-package lists derive from
  [top-pypi-packages](https://github.com/hugovk/top-pypi-packages) and
  [npm-high-impact](https://github.com/wooorm/npm-high-impact); vulnerability data comes from
  [OSV.dev](https://osv.dev).
