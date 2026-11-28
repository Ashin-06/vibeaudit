# vibeaudit

[![CI](https://github.com/Ashin-06/vibeaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/Ashin-06/vibeaudit/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Ashin-06/vibeaudit/badge)](https://scorecard.dev/viewer/?uri=github.com/Ashin-06/vibeaudit)
[![PyPI](https://img.shields.io/pypi/v/vibeaudit)](https://pypi.org/project/vibeaudit/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/vibeaudit)](https://pypi.org/project/vibeaudit/)
[![GitHub Release](https://img.shields.io/github/v/release/Ashin-06/vibeaudit)](https://github.com/Ashin-06/vibeaudit/releases)
![Python 3.11 to 3.14](https://img.shields.io/badge/python-3.11%20to%203.14-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

**A security and quality audit for apps built with AI coding assistants, and for apps that use LLMs.**

![vibeaudit scanning a vulnerable Flask and OpenAI app](https://raw.githubusercontent.com/Ashin-06/vibeaudit/main/docs/demo.gif)


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
- Pure Python, zero runtime dependencies (Python 3.11+). Linux, macOS and Windows.
  Optional `pip install vibeaudit[parse]` adds a tree-sitter function and parameter index for Go, Rust, Java,
  JavaScript and TypeScript (`vibeaudit doctor` shows which is active; `VIBEAUDIT_PARSER=regex` turns it off).
- **95 stable static rules** (93.6% held-out precision on stable rules; 68.0% across all rules including preview)
  and 84 preview rules across 179 rules in 12 categories + 1 optional LLM check (`AI001`), mapped to CWE,
  the OWASP Top 10 and the OWASP Top 10 for LLM Applications (`vibeaudit rules --format json` prints the full catalogue).
- Terminal output plus JSON, SARIF 2.1.0 (GitHub code scanning), Markdown, HTML, an SVG badge, CycloneDX 1.6 AI-BOM (`-r aibom`), and a fix
  brief you can paste into an AI assistant.
- Fits into CI (GitHub Action, `--diff`), pre-commit (`--staged`) and coding agents (an MCP server).

Contents: [Quickstart](#quickstart) - [Example output](#example-output) - [What it checks](#what-it-checks) - [Use it in CI](#use-it-in-ci) - [Accuracy](#accuracy) - [Documentation](#documentation) - **[Full usage guide](docs/USAGE.md)**

## Quickstart

```bash
pip install vibeaudit
```

```bash
vibeaudit scan path/to/your/project      # or a single file: vibeaudit scan app.py
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
  Domains: Security 0  AI 42  Quality 93  Data 96  Reliability 99  UI 100
```

That project is one of the deliberately vulnerable sample apps in `tests/fixtures/`.

## What it checks

| Category | What it finds |
| --- | --- |
| Secrets (SEC) | provider keys and tokens, private keys, hard-coded or default signing secrets, database URLs with passwords, committed or un-ignored `.env` files, secrets in `NEXT_PUBLIC_`/`VITE_` variables, a Supabase `service_role` key outside the server, secrets in logs, keys baked into committed bundles; in preview: other high-entropy secrets, hard-coded passwords |
| Supply chain (DEP) | packages that do not exist (hallucinated names), typosquats of popular packages, packages first published in the last 30 days, known vulnerabilities (OSV) for pinned versions, missing lockfiles, install scripts that run remote code, unpinned MCP servers; in preview: extra package indexes (dependency confusion), vulnerable transitive dependencies |
| Backend (BE) | SQL and NoSQL injection, SSRF, path traversal, server-side template injection, mass assignment, debug mode, permissive CORS, disabled TLS verification, weak password hashing, insecure randomness, unverified JWTs, leaked error details; in preview: command injection, `eval`/`exec`, unsafe deserialization and open redirects (these four still gate), no server-side validation, payment amounts taken from the client, email header injection, XML external entities (`BE021`), graph and analytics query injection (Cypher / KQL, `BE022`), Python and JS NoSQL filters (`BE010`) |
| Frontend (FE) | LLM APIs called from the browser, authorization decisions in browser storage, `postMessage` without origin checks, tokens in `localStorage`, production source maps; in preview: XSS through raw HTML sinks (still gates), hard-coded localhost URLs, server actions that expose a server secret |
| Auth (AUTH) | endpoints that change data or spend money without authentication, admin routes without a role check, IDOR-shaped handlers, unverified webhooks, tables without Row Level Security, permissive policies, open Firebase rules, auth functions that always return true, CSRF disabled, login without rate limiting; in preview: JWTs accepted without pinned algorithms, session cookies without SameSite or CSRF protection, webhook signatures without replay protection, rate limits keyed on X-Forwarded-For, password changes that keep old sessions, queries not scoped to the tenant, admin or feature-flag endpoints without a role check |
| Config (CFG) | containers running as root, secrets in images, GitHub Actions script injection, `pull_request_target` checking out untrusted code, any Host header accepted, default database passwords, missing security headers, `.env` copied into an image, third-party GitHub Actions not pinned to a commit, unencrypted RDS and EBS storage (Terraform and CloudFormation); in preview: unpinned base images, `permissions: write-all`, privileged or host-mounted Kubernetes containers and missing resource limits, public S3 buckets, admin and database ports open to the internet, secret files or build arguments in the final image, pull request code run with secrets, GCP and Azure Terraform misconfigurations (`CFG020`) |
| LLM and agents (LLM) | untrusted input in the system prompt, model output in a dangerous sink, no token limit, LLM endpoints without rate limiting, agent tools with dangerous capabilities, dangerous agent options, system prompts shipped to the browser, unsafe model loading, unbounded agent loops, vector search without a tenant filter, model output parsed as JSON without error handling, retired model ids, MCP servers with whole-disk access or plain HTTP, secrets in MCP configs, agents that read untrusted content and also have dangerous tools; in preview: coding agents configured to act without asking, streamed completions not cancelled on disconnect, prompts and completions written to logs, model output as a command argument, agent tool loops without a step limit, user text in a prompt without delimiters, retrieved documents stored without cleaning, no per-user cost limit, LLM code without tests or evals, prompt-injection text in an agent instruction file, covert prompt injection in MCP tool descriptions (`LLM027`), dynamic un-allowlisted tool dispatch (`LLM028`) |
| Code completeness (QA) | no CI, TypeScript checking disabled, the same function copied into several files; in preview: no tests, swallowed exceptions, security TODOs, unfinished stubs, imports of files or names that do not exist, packages imported but not declared, Pages Router code in an App Router file, made-up data used as a fallback |
| Data (DATA) | whole user records returned to the client, destructive migrations, money as float, private tables readable by everyone, timestamps without time zone, a database client per request, SQLite on a serverless host; in preview: N+1 queries, env vars missing from the example env file, several writes without a transaction, indexes built without CONCURRENTLY, foreign keys without an index, Redis keys without an expiry, personal data in vector store metadata, cache stampedes, background jobs that are not safe to retry |
| Reliability (REL) | HTTP requests without a timeout, blocking calls in async handlers, webhooks that are not idempotent, uploads without a size limit, in-memory state on serverless hosts, no health-check endpoint |
| UI, UX and accessibility (UI) | images without alt text, click handlers the keyboard cannot reach, unlabeled form fields, controls that do nothing, index keys on changing lists, hydration mismatches, effects without cleanup, lorem ipsum, no error page, missing metadata or viewport, links to pages that do not exist; in preview: deletes without confirmation, no loading or error state, images without width and height, form errors that screen readers do not hear, focus outlines removed without a replacement, links to assets that are not in the public folder |
| Frontend-backend contracts (API) | frontend calls to API paths no route handles, and calls with a method the route does not accept |
| Go, Java/Kotlin and C# (GO, JAVA, CSHARP), all in preview | goroutines started by a handler that never stop (GO001), response bodies never closed (GO002), maps written concurrently without a lock (GO003), SQL built with formatting (GO004); Spring controllers with no security configuration (JAVA001), exposed Actuator endpoints (JAVA002), a security chain that permits every request (JAVA003), polymorphic deserialization without an allow-list (JAVA004); ASP.NET Core with no authorization anywhere (CSHARP001), deserialization that lets the payload pick the type (CSHARP002), the developer error page outside Development (CSHARP003) |

84 of 180 rules are preview; `vibeaudit rules` lists them. Preview findings are reported but do not
fail a build, with one exception: the severe classes (command injection, code execution, unsafe
deserialization, open redirects and XSS) still gate while in preview, so a high-impact bug is never let through
because its rule is new. Findings of any rule in Go, Java/Kotlin, C#, Rust and PHP code are preview; there, SQL
injection, command injection and XSS still gate. [STABILITY.md](STABILITY.md) explains how a rule leaves preview.

Every rule, with its severity, why it matters and how to fix it, is in the
**[rule catalogue (docs/RULES.md)](docs/RULES.md)**; `vibeaudit rules` prints the same list.

Routes are found for Flask, FastAPI, Django REST framework, Express, Fastify, Hono, Next.js (app and pages
routers, server actions), SvelteKit, Supabase edge functions and Firebase functions. Python is analysed on
its syntax tree with taint tracking (request data, model output and agent-tool arguments are followed into
SQL, shell, `eval`, file paths, URLs, templates, redirects and HTML); JavaScript and TypeScript data-flow
analysis uses a lexer that keeps exact offsets, with optional tree-sitter function and parameter indexing via
`vibeaudit[parse]`.

### Why another scanner

Good tools exist, and vibeaudit runs them when they are installed instead of replacing them:

| Tool | Great at | Misses in AI-built apps |
| --- | --- | --- |
| gitleaks, trufflehog | secrets in files and history | secrets exposed by design: `NEXT_PUBLIC_OPENAI_API_KEY`, a `service_role` key in a client component, `dangerouslyAllowBrowser: true` |
| npm audit, pip-audit, OSV-Scanner | known CVEs in real packages | packages that do not exist (hallucinated) or appeared last week (slopsquatting) |
| Bandit, Semgrep, CodeQL | classic injection patterns | whether a route has any auth, whether model output reaches `exec`/SQL/HTML, RLS policies, Firebase rules |
| garak, promptfoo | red-teaming a running model | static code: user input in the system prompt, agent tools with shell access, missing `max_tokens` |

## Use it in CI

**GitHub Action**: findings go to the code scanning tab and the job summary; with `comment: "true"` one pull
request comment lists the findings on the changed lines and is updated on every push.

```yaml
name: vibeaudit
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
  pull-requests: write              # only for comment: "true"
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - uses: Ashin-06/vibeaudit@v0.23.0
        with:
          fail-on: high
          comment: "true"
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: vibeaudit.sarif
```

**pre-commit**:

```yaml
repos:
  - repo: https://github.com/Ashin-06/vibeaudit
    rev: v0.23.0
    hooks:
      - id: vibeaudit
```

GitLab CI, Docker, editors (VS Code, Cursor, any LSP client) and coding agents ([MCP setup guide](docs/MCP.md)):
see the [usage guide](docs/USAGE.md#ci-and-pre-commit).

## Documentation

- **[Usage guide](docs/USAGE.md)**: [install](docs/USAGE.md#install), [commands and flags](docs/USAGE.md#commands),
  [automatic fixes](docs/USAGE.md#automatic-fixes-vibeaudit-fix), [configuration](docs/USAGE.md#configuration),
  [CI and pre-commit](docs/USAGE.md#ci-and-pre-commit), [editors](docs/USAGE.md#editors-vs-code-cursor-and-other-lsp-clients),
  [MCP server](docs/USAGE.md#mcp-server-for-coding-agents), [custom rules and the Python API](docs/USAGE.md#custom-rules-and-the-python-api),
  [scoring](docs/USAGE.md#scoring), [false positives](docs/USAGE.md#false-positives-and-suppressing-findings),
  [offline use](docs/USAGE.md#offline-and-air-gapped-use), [limits](docs/USAGE.md#limits-and-what-is-not-covered),
  [verifying a release](docs/USAGE.md#verifying-a-release)
- **[MCP setup guide](docs/MCP.md)**: copy-paste setup and agent prompt for Claude Code, Cursor, and Copilot
- **[Rule catalogue](docs/RULES.md)**: every rule with why it matters and how to fix it
- **[Benchmark results](benchmark/RESULTS.md)** and [how the corpus is labelled](docs/LABELLING.md)
- [Stability policy](STABILITY.md), [roadmap](ROADMAP.md), [changelog](CHANGELOG.md), [privacy](docs/PRIVACY.md)

## Accuracy

<!-- accuracy:start (generated by tools/benchmark.py baseline) -->
Every rule is measured on a labelled benchmark: 142 public repositories pinned to exact commits, where each of the 4,250 findings was read in the code and labelled true or false, plus seeded examples for recall. 96 repositories were used to find and fix false positives; 46 are held out and never used for tuning.

| Precision | Tuned split | Held-out split |
| --- | --- | --- |
| Stable findings (what `--fail-on` acts on) | 93.2% (1254/1345) | 93.6% (426/455) |
| All rules, preview included | 77.6% (2536/3269) | 68.0% (667/981) |

Preview rules are reported but do not gate, and most false positives are theirs. Recall, F1 and the misses: [docs/BENCHMARK.md](docs/BENCHMARK.md).
<!-- accuracy:end -->

### Compared with Semgrep and Bandit

Each tool scanned the same pinned benchmark corpus (community `p/default` rules for Semgrep; Python-only for Bandit)
evaluated with vibeaudit's rubric ([benchmark/compare.json](benchmark/compare.json), [labels](benchmark/compare_labels.json)):

| Tool | Advisory recall | Corpus findings | Measured precision |
| --- | --- | --- | --- |
| vibeaudit | 6/17 | 1,592 | 75% overall (3,203/4,250 labelled; 93.6% on held-out stable rules) |
| Semgrep (community) | 6/17 | 1,615 | ~22% (11/50 random sample) |
| Bandit (Python) | 6/17 | 875 | ~34% (17/50 random sample) |

Methodology, confidence intervals (+-14 pts on 50-finding samples), and shared misses:
[docs/BENCHMARK.md](docs/BENCHMARK.md#compared-with-semgrep-and-bandit).

Precision per rule
on both splits, seeded recall and the status of every rule are in
[benchmark/RESULTS.md](benchmark/RESULTS.md). Every stable rule with at least 5 labelled findings is at
90% or above; rules below that are in preview, and a rule leaves preview only on its held-out precision.
CI fails when a rule's precision drops, a labelled true positive disappears or seeded recall drops.

Reproduce it (the repositories are cloned into `~/.cache/vibeaudit-bench`, never into this one):

```bash
python tools/benchmark.py run --json results.json
```

How the corpus was chosen and how findings are labelled: [benchmark/README.md](benchmark/README.md).
Precision, recall, F1, the misses and the comparison with Semgrep and Bandit:
[docs/BENCHMARK.md](docs/BENCHMARK.md) (`python tools/benchmark.py report`).

**Help wanted: independent labellers.** All labels so far are the maintainers' own. If you can spend an hour or two
labelling a blind sample of 150 findings, see [docs/LABELLING.md](docs/LABELLING.md); every set of answers is
published with its agreement score (Cohen's kappa), disagreements included.

A sample report for a deliberately vulnerable app (HTML and the six compliance reports) is published from
`.github/workflows/pages.yml`.

## Contributing, security and license

- Contributing: see [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports with a minimal example are the most
  useful contribution, especially false positives and missed findings.
- Security issues in vibeaudit itself and our untrusted-repo threat model: see [SECURITY.md](SECURITY.md); please do not open a public issue.
- Privacy and data-handling policy: see [docs/PRIVACY.md](docs/PRIVACY.md).
- License: MIT, see [LICENSE](LICENSE). Popular-package lists derive from
  [top-pypi-packages](https://github.com/hugovk/top-pypi-packages) and
  [npm-high-impact](https://github.com/wooorm/npm-high-impact); vulnerability data comes from
  [OSV.dev](https://osv.dev).
