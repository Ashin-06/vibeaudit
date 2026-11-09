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
- 73 rules in 8 categories, mapped to CWE, OWASP Top 10 and the OWASP Top 10 for LLM Applications 2025.

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
| `--report FORMAT[:PATH]` | `json`, `sarif`, `md` or `html` (repeatable). `json:-` writes JSON to stdout. |
| `--fail-on SEVERITY` | Exit 1 when a finding is at least this severe (default `high`; `none` never fails). |
| `--min-severity SEVERITY` | Hide findings below this severity (default `low`). |
| `--offline` | No network: skip registry, new-package and CVE lookups (typosquat check still runs). |
| `--exclude GLOB` | Skip paths (repeatable); `.vibeauditignore` is read too. |
| `--disable RULE_OR_CATEGORY` | For example `--disable QA002` or `--disable quality`. |
| `--baseline FILE` / `--write-baseline FILE` | Report only findings that are new since the baseline. |
| `--external auto\|none\|LIST` | Run installed gitleaks, bandit, osv-scanner, semgrep and merge results. |
| `--llm gemini\|openai\|anthropic` | Model triage of findings; `--llm-review` adds a review of the riskiest files. |

Exit codes: `0` clean at the `--fail-on` level, `1` findings, `2` usage error. In a git checkout,
ignored files are not scanned (a local ignored `.env` is where secrets belong). Vendor folders, build
output and minified bundles are skipped. In test files only real credentials are reported.

`vibeaudit rules` lists every rule (`--format json` includes the full why and fix text).

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

## Using it in CI

```yaml
- run: pip install git+https://github.com/Ashin-06/vibeaudit.git
- run: vibeaudit scan . --report sarif:vibeaudit.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: vibeaudit.sarif
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
- **Real projects.** Run on mckaywrigley/chatbot-ui, langchain-ai/chat-langchain and a public Lovable +
  Supabase AI app, with every finding checked by hand. Confirmed issues included an unauthenticated
  `/api/chat/custom` route in chatbot-ui that loads any user's custom model (and its API key) by id with
  the service-role key, model routes without rate limits, and edge functions that call a paid AI API
  with JWT verification disabled. False alarms found on the first runs were fixed at the root.
- **LLM providers.** Gemini was tested live (triage and review). OpenAI and Anthropic are implemented
  against their documented HTTP APIs and unit-tested with a stubbed transport, not called live.

## Limitations

- Data flow is intra-procedural (plus one level of helper resolution for auth).
- JS/TS analysis is lexer-based, not a full parser.
- Django URLconf views, NestJS and Remix routes are only partly covered.
- "Authenticated" means an auth check is visible, not that it is correct.
- Rate limiting and validation are detected project-wide, so one limiter anywhere counts.

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

## License and data sources

MIT, see [LICENSE](LICENSE). Popular-package lists derive from
[top-pypi-packages](https://github.com/hugovk/top-pypi-packages) and
[npm-high-impact](https://github.com/wooorm/npm-high-impact); vulnerability data comes from
[OSV.dev](https://osv.dev).
