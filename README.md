# vibeaudit

**A security and quality audit for apps built with AI coding assistants and for apps that use LLMs.**

vibeaudit scans a repository from the frontend to the database rules to the AI parts and gives a
prioritised list of what is actually dangerous, with file and line, why it matters and how to fix it.
It targets the failure modes that AI-generated ("vibe-coded") apps keep shipping: keys in the browser
bundle, API routes with no auth check, Supabase tables without Row Level Security, packages the
assistant invented, model output piped into `exec`, unbounded token spend, and placeholder security
that was never finished.

```
$ vibeaudit scan .
Stack: Flask, OpenAI SDK

[CRITICAL] AUTH008 Auth check stub always succeeds
  app.py:24  `verify_token()` always returns True.
  Why: A function that is supposed to verify a token, password or permission just returns true...
  Fix: Implement the real check (verify signature, expiry, user and role) or use a maintained auth library.

[CRITICAL] BE002 Command injection
  app.py:50  Request data flows into a shell command.
...
Summary
  critical: 5  high: 19  medium: 11  low: 4   total: 39
  Score: 0/100  Grade: F
```

(Output from the `vuln_flask_llm` test fixture.)

- Works fully offline with no API key. Network is used only for package registry and vulnerability
  lookups (`--offline` turns that off); an LLM is used only if you ask for it (`--llm`).
- One `pip install`, pure Python, 3.9 to 3.13 on Linux, macOS and Windows.
- Terminal summary plus JSON, SARIF 2.1.0 (GitHub code scanning), Markdown and self-contained HTML.
- 75 static rules in 8 categories (plus AI001 for the optional LLM review), mapped to CWE, OWASP Top 10
  and the OWASP Top 10 for LLM Applications 2025.

## Why another scanner

Excellent tools exist and vibeaudit runs them when installed instead of competing with them:

| Tool | Great at | Misses for AI-built apps |
| --- | --- | --- |
| gitleaks, trufflehog | Secrets in files and history | Secrets exposed by design: `NEXT_PUBLIC_OPENAI_API_KEY`, a Supabase `service_role` key in a client component, `dangerouslyAllowBrowser: true` |
| npm audit, pip-audit, OSV-Scanner | Known CVEs in real packages | Packages that do not exist (hallucinated names) or appeared last week (slopsquatting) |
| Bandit, Semgrep, CodeQL | Classic injection patterns | Whether a route has any auth, whether a server action is callable by anyone, whether model output reaches `exec`/SQL/HTML, RLS policies, Firebase rules |
| garak, promptfoo | Red-teaming a running model | Static code: user input in the system prompt, agent tools with shell access, missing `max_tokens`, no rate limit in front of a paid model |

What vibeaudit adds:

1. **Route-level reasoning.** Finds HTTP entry points (Flask, FastAPI, Django REST, Express, Fastify,
   Hono, Next.js app and pages routers, server actions, SvelteKit, Supabase edge functions, Firebase
   functions), follows middleware, router mounts and imported helpers, and reports endpoints that write
   data or spend money without auth, admin routes without role checks, IDOR-shaped handlers and webhooks
   without signature verification.
2. **LLM data flow.** Python is analysed on the AST with taint tracking: request data, model output and
   agent-tool arguments are followed into SQL, shell, `eval`, file paths, URLs, templates, redirects and
   HTML. JS/TS gets the same treatment on offset-preserving lexer views.
3. **Supply chain for invented packages.** Unknown dependencies are checked on PyPI/npm: missing
   packages, npm security-holding (removed malware) packages, packages younger than 30 days, names one
   keystroke from a top package, and OSV advisories for pinned versions.
4. **Backend-as-a-service config.** Supabase migrations, Firebase rules, MCP server configs, GitHub
   Actions script injection, Dockerfiles that bake in `.env`.
5. **Unfinished work.** Auth functions that `return true`, `TODO: add auth` comments, no tests, no CI.

## Install

The repository is private, so install from a clone:

```bash
git clone https://github.com/Ashin-06/vibeaudit.git
```

```bash
pip install ./vibeaudit
```

## Usage

```bash
vibeaudit scan path/to/project --report html --report sarif:results.sarif
```

| Option | Meaning |
| --- | --- |
| `--report FORMAT[:PATH]` | `json`, `sarif`, `md`, `html`, `prompt` (a fix brief to paste into an AI assistant) or `badge` (SVG). Repeatable; `json:-` writes to stdout. |
| `--fail-on SEVERITY` | Exit 1 when a finding is at least this severe (default `high`; `none` never fails). |
| `--min-severity SEVERITY` | Hide findings below this severity (default `low`). |
| `--offline` | No network: skip registry, new-package and CVE lookups (typosquat check still runs). |
| `--exclude GLOB` | Skip paths (repeatable); `.vibeauditignore` is read too. |
| `--disable RULE_OR_CATEGORY` | For example `--disable QA002` or `--disable quality`. |
| `--baseline FILE` / `--write-baseline FILE` | Report only findings that are new since the baseline. |
| `--external auto\|none\|LIST` | Run installed gitleaks, bandit, osv-scanner, semgrep and merge results. |
| `--llm gemini\|openai\|anthropic` | Model triage of findings; `--llm-review` adds a review of the riskiest files. |
| `--file-timeout SECONDS` | Time each analysis step may spend on one file before it is stopped (default 30). |
| `--staged` / `--diff REV` | Report only findings on staged lines (pre-commit) or lines changed since `REV` (pull requests). |
| `--plugin FILE_OR_MODULE` | Load custom rules (see below). |
| `--config FILE` / `--no-config` | Use another settings file, or ignore the scanned project's settings. |

With `--external auto` (the default), gitleaks, bandit, osv-scanner and semgrep are run when they are
installed, and their findings are merged and de-duplicated. Bandit checks that a built-in rule covers
with data flow (exec/eval, shell, SQL strings, pickle/yaml, debug mode, `verify=False`) are left to the
built-in rule, so a line vibeaudit has judged safe is not reported again.

Exit codes: `0` clean at the `--fail-on` level, `1` findings, `2` usage error. In a git checkout,
ignored files are not scanned (a local ignored `.env` is where secrets belong). Vendor folders, build
output and minified bundles are skipped. In test files only real credentials are reported.

`vibeaudit rules` lists every rule (`--format json` includes the full why and fix text).

Pinned versions for the vulnerability check come from `requirements.txt` pins and from lockfiles next to
the manifest: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `poetry.lock`, `uv.lock`,
`pdm.lock` and `Pipfile.lock`. A requirements file that uses `--index-url` (replacing PyPI) is not checked
against PyPI; `--extra-index-url` (for example PyTorch wheels) keeps every check.

A repository is untrusted input, so the scan is built to finish whatever it contains. Each file is
analysed in isolation: a file that triggers a bug is listed under `meta.internal_errors` (and in a note)
while every other file is still scanned, and a file that exceeds `--file-timeout` or is nested too deeply
to parse is listed under `meta.skipped`. Symbolic links that point outside the project are not followed.
Registry and OSV lookups retry timeouts and rate limits (honouring `Retry-After`), stop calling a host that
is down, and never report a package as missing unless the registry answered 404 or 410.

## What it checks

| Category | Rules |
| --- | --- |
| Secrets | SEC001 provider keys, SEC002 private keys, SEC003 high-entropy secrets, SEC004 hardcoded or default signing secrets, SEC005 DB URLs with passwords, SEC006 `.env` committed, SEC007 `.env` not ignored, SEC008 secrets in `NEXT_PUBLIC_`/`VITE_`/... vars, SEC009 Supabase service_role outside the server, SEC010 secrets in logs, SEC011 hardcoded passwords |
| Supply chain | DEP001 package does not exist, DEP002 typosquat, DEP003 very new package, DEP004 known vulnerabilities, DEP005 no lockfile, DEP006 install script runs remote code, DEP007 unpinned MCP server |
| Backend | BE001 SQL injection, BE002 command injection, BE003 eval/exec, BE004 unsafe deserialization, BE005 SSRF, BE006 path traversal, BE007 SSTI, BE008 open redirect, BE009 mass assignment, BE010 NoSQL injection, BE011 debug mode, BE012 insecure CORS, BE013 TLS verification off, BE014 plaintext or fast-hash passwords, BE015 insecure randomness, BE016 unverified JWT, BE017 error details leaked, BE018 no server-side validation |
| Frontend | FE001 XSS through raw HTML sinks, FE002 LLM API called from the browser, FE003 authorization in browser storage, FE004 postMessage without origin check, FE005 token in localStorage, FE006 production source maps, FE007 hardcoded localhost URL |
| Auth | AUTH001 unauthenticated state-changing or paid-API endpoint, AUTH002 admin route without role check, AUTH003 IDOR, AUTH004 unverified webhook, AUTH005 table without RLS, AUTH006 permissive policy, AUTH007 open Firebase rules, AUTH008 auth stub returns true, AUTH009 CSRF disabled, AUTH010 login without rate limit |
| Config | CFG001 root container, CFG002 unpinned base image, CFG003 secret in image, CFG004 Actions script injection, CFG005 pull_request_target checkout, CFG006 any Host accepted, CFG007 default DB password, CFG008 no security headers, CFG009 `.env` copied into image |
| LLM | LLM001 untrusted input in system prompt, LLM002 model output in a dangerous sink, LLM003 no token limit, LLM004 LLM endpoint without rate limiting, LLM005 agent tool with dangerous capability, LLM006 dangerous agent option, LLM007 system prompt in the browser, LLM008 unsafe model loading, LLM009 unbounded agent loop |
| Quality | QA001 no tests, QA002 no CI, QA003 swallowed exception, QA004 security TODO left in code |
| LLM review | AI001 issue reported by the optional `--llm-review` (model-generated, unverified) |

OWASP LLM Top 10 coverage: LLM01, LLM02, LLM03, LLM05, LLM06, LLM07, LLM10. LLM04 (poisoning), LLM08
(vector stores) and LLM09 (misinformation) are runtime properties; test them with promptfoo or garak.

## LLM-assisted checks (optional)

```bash
GEMINI_API_KEY=... vibeaudit scan . --llm gemini --llm-review --llm-max-requests 10
```

- **Triage** annotates medium and higher findings with a verdict and reason. Findings are never removed
  or downgraded by the model, because the audited code is untrusted and could contain text aimed at the
  model. Secrets are redacted before sending and are not triaged.
- **Review** adds extra issues as `AI001`, labelled `[model-generated, unverified]`.
- Providers: `gemini` (`GEMINI_API_KEY`/`GOOGLE_API_KEY`), `openai` (`OPENAI_API_KEY`, `OPENAI_BASE_URL`
  for any compatible server such as Ollama), `anthropic` (`ANTHROPIC_API_KEY`). `--llm-model` picks the
  model; `--llm-max-requests` is a hard cap.

## Configuration file

Settings can live in `.vibeaudit.toml` or in a `[tool.vibeaudit]` table of `pyproject.toml`. Flags on the
command line win. Unknown keys and wrong types are errors, so a typo cannot quietly weaken a scan.

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

The file is part of the scanned repository, so it can switch rules off. When you audit code you do not
trust, run with `--no-config`.

## Pre-commit and pull requests

`--staged` and `--diff REV` still analyse the whole project (auth middleware and helpers in unchanged
files count) but report only findings on added or changed lines.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Ashin-06/vibeaudit
    rev: v0.3.0
    hooks:
      - id: vibeaudit
```

```bash
vibeaudit scan . --diff origin/main --fail-on high
```

## GitHub Action

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
      - uses: Ashin-06/vibeaudit@v0.3.0
        with:
          fail-on: high
          args: --diff origin/main   # optional: only changed lines
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: vibeaudit.sarif
```

Inputs: `path`, `fail-on`, `sarif`, `args`, `setup-python`, `python-version`. While the repository is
private, other repositories need access to it (or vendor the action).

## MCP server for coding agents

`vibeaudit mcp` runs a Model Context Protocol server on stdio, so Claude Code, Cursor and other agents can
audit their own changes before handing them back. Tools: `scan_project` (optionally only changed lines),
`scan_file`, `list_routes`, `check_package` (does it exist, is it brand new, is it a typosquat, known CVEs)
and `explain_rule`. All tools are read-only.

```json
{ "mcpServers": { "vibeaudit": { "command": "vibeaudit", "args": ["mcp"] } } }
```

```bash
claude mcp add vibeaudit -- vibeaudit mcp
```

## Routes inventory

`vibeaudit routes [PATH] [--format text|json|md]` lists every HTTP entry point the scanners found, with
method, path, location, framework and whether it has a visible auth check, writes data or calls a paid AI
API. The JSON report has the same `routes` section.

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

`rule(...)` registers a project-wide check that receives the project and route table. Custom findings show
up in every report format, can be suppressed and baselined like built-in ones, and a failing custom rule
is isolated like any other check. Plugins run your Python code, so they are only loaded from `--plugin` or
your own imports, never from the scanned repository.

Library use:

```python
from vibeaudit import scan, Options

result = scan("path/to/project", Options(offline=True))
print(result.score, result.grade)
for f in result.findings:
    print(f.severity, f.rule_id, f.file, f.line, f.message)
for r in result.routes:
    print(r.methods, r.path, r.has_auth)
```

## Suppressing findings

Inline `# vibeaudit: ignore[AUTH001]` (or `// vibeaudit: ignore`) on the line or the line above;
`--exclude` or `.vibeauditignore` for paths; `--disable` for rules or categories; baselines for
existing debt. An empty `except`/`catch` with an explanatory comment is treated as deliberate.

## How it was validated

- **Fixtures.** Five deliberately vulnerable apps (Flask + OpenAI, Next.js + Supabase, Express +
  MongoDB, FastAPI + LangChain agent with MCP config, config-only) and one clean app. Every expected
  finding is marked with an `expect: RULE` comment; tests compare the exact set of
  `(file, line, rule)`, so a missed finding or a false alarm fails. The clean app must produce zero
  findings. Fake credentials are generated at test time.
- **Property tests.** Every vulnerable fixture is mutated in ways that keep it vulnerable (lines shifted,
  variables renamed, imports reordered, CRLF, tabs and trailing whitespace, the app moved into a monorepo
  subfolder, routes wrapped in a function or moved into a blueprint module) and every finding must stay.
  33 safe rewrites (parameterise the query, add the auth check, set a token limit, use an argument list,
  ...) must each remove exactly the targeted finding and add nothing.
- **Fuzzing.** Thousands of random and malformed inputs with fixed seeds: garbage and truncated
  Python/JS/TS, binary files with code extensions, non-UTF-8, UTF-16 and mixed encodings, empty files,
  3,000-level nesting, 700 KB single-line files, malformed `package.json`, lockfiles, `pyproject.toml`,
  requirements, Supabase SQL, Firebase rules and MCP configs, symlink loops, links out of the project and
  unreadable files. The scan must not crash, hang or produce invalid JSON/SARIF. `VIBEAUDIT_FUZZ_ROUNDS`
  sets the depth (CI runs 6 rounds per platform and 60 on Linux; 300 rounds were run before 0.2.0).
- **Regular expressions.** Every compiled pattern is timed against long runs of the characters that
  cause catastrophic backtracking.
- **Network.** Registry and OSV lookups are tested against timeouts, DNS failures, resets, 403/429/5xx,
  `Retry-After`, HTML error pages, truncated and wrongly typed JSON, and a full outage.
- **Scale.** A generated 10,000-file repository scans in under a minute with about 120 MB peak traced
  memory (CI runs 2,000 files on every platform and 10,000 on Linux).
- **Real projects.** 15 public repositories: mckaywrigley/chatbot-ui, langchain-ai/chat-langchain,
  fastapi/full-stack-fastapi-template, miguelgrinberg/microblog, HackSoftware/Django-Styleguide-Example,
  vercel/ai-chatbot, vercel/nextjs-subscription-payments, hagopj13/node-express-boilerplate,
  gothinkster/node-express-realworld-example-app, run-llama/sec-insights, langchain-ai/opengpts,
  streamlit/llm-examples, supabase-community/chatgpt-your-files, wandb/openui and a public Lovable +
  Supabase AI app. Every high and critical finding outside dependency advisories was checked by hand;
  each false alarm was fixed at the root with a regression test. Confirmed issues included an
  unauthenticated `/api/chat/custom` route in chatbot-ui that loads any user's custom model (and its API
  key) by id with the service-role key, unauthenticated delete endpoints, and edge functions that call a
  paid AI API with JWT verification disabled. High and critical dependency advisories (DEP004) come from
  OSV for the pinned versions and were spot-checked, not reviewed one by one.
- **LLM providers.** Gemini was tested live (triage and review). OpenAI and Anthropic are implemented
  against their documented HTTP APIs and unit-tested with a stubbed transport, not called live.

## Limitations

- Data flow is intra-procedural (plus one level of helper resolution for auth).
- JS/TS analysis is lexer-based, not a full parser.
- Django URLconf views, NestJS and Remix routes are only partly covered.
- "Authenticated" means an auth check is visible, not that it is correct.
- Rate limiting and validation are detected project-wide, so one limiter anywhere counts.
- The per-file time budget is cooperative: it is checked between regex matches and statements. A single
  regex step cannot be interrupted, which is why every module-level pattern is tested for linear time.
- Memory grows with the size of the repository (file text and lexer views are kept for cross-file
  analysis); about 12 KB per source file in the scale test.

## Development

```bash
pip install -e ".[dev]"
```

```bash
python -m pytest -q
```

```bash
python tools/check_ascii.py
```

Deeper runs: `VIBEAUDIT_FUZZ_ROUNDS=300` for the fuzzer and `VIBEAUDIT_PERF_FILES=10000` for the scale
test.

## License and data sources

MIT, see [LICENSE](LICENSE). Popular-package lists derive from
[top-pypi-packages](https://github.com/hugovk/top-pypi-packages) and
[npm-high-impact](https://github.com/wooorm/npm-high-impact); vulnerability data comes from
[OSV.dev](https://osv.dev).
