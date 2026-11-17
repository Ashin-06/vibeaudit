# Roadmap

Status: **done** (released, stable), **preview** (released as a preview rule or feature, see
[STABILITY.md](STABILITY.md)), **planned** (not started). Updated with every release. New rules always ship
as preview first and leave preview only at 90% precision or more on the [benchmark](benchmark/README.md).

## Phase 0: prove the rules are accurate (0.6.0)

| Item | Status |
| --- | --- |
| Labelled benchmark corpus: 54 pinned public repositories (12 held out; pre-fix advisory commits and training apps since 0.8.0), labels per finding | done |
| Precision per rule and seeded recall (`tools/benchmark.py`), table and JSON results | done |
| CI regression gate against a stored baseline, tolerant of network failures | done |
| Rule stability policy and preview rules (`--include-preview`) | done |
| Signed build provenance and CycloneDX SBOM on every release | done |
| Accuracy section in the README | done |

## Phase 1: new checks (done, 0.7.0 to 0.8.8)

| Item | Status |
| --- | --- |
| React server actions leaking secrets or server closures to the client | preview (FE008; 0.8.7) |
| Hydration mismatches: window sizes, `new Date()`, random ids during render (extends UI007) | done (UI007 also covers `window.innerWidth`/`innerHeight` and `crypto.randomUUID()`; 0.7.1) |
| Images without width and height (layout shift) | preview (UI014; 0.7.1, 10 of 11 true on the corpus) |
| Form errors without `aria-describedby` | preview (UI015; 0.7.1, 8 of 8) |
| Focus outlines removed | preview (UI016; 0.7.1, 6 of 6) |
| Asset links (fonts, SVG, favicon, public images) to missing files | preview (UI017; 0.7.1, 2 of 2) |
| CORS wildcard or reflected origin with credentials | done (BE012, narrowed in 0.6.0) |
| Cookie-authenticated state changes without a CSRF token or SameSite=Lax/Strict | preview (AUTH012; 0.7.2) |
| Rate limits keyed on the raw IP behind a proxy | preview (AUTH014, X-Forwarded-For as the key; 0.7.2) |
| Webhooks without a timestamp or replay window | preview (AUTH013; 0.7.2) |
| Payment amounts or prices taken from the client | preview (BE019; 0.7.2) |
| Email header injection | preview (BE020; 0.7.2) |
| Open redirects and SSRF in "fetch this URL" features (extends BE005/BE008) | done (BE005 and BE008 report request data in outbound URLs and redirects; regression tests in 0.8.6) |
| JWT verified without pinned algorithms (alg none, HMAC/RSA confusion) | preview (AUTH011; alg none is BE016; 0.7.2) |
| Password change or reset not revoking sessions and refresh tokens | preview (AUTH015; 0.8.7) |
| Queries not scoped to the current tenant or org (extends AUTH003) | preview (AUTH016; 0.8.7) |
| Feature flags or admin toggles reachable without auth | done for no auth at all (AUTH001); preview for no role check (AUTH017; 0.8.7) |
| User text in prompts without delimiters (extends LLM001) | preview (LLM021; 0.8.6) |
| RAG ingestion storing unsanitised text or instructions (chunk poisoning) | preview (LLM022; 0.8.6) |
| Agent tool loops without a max iteration limit (extends LLM009) | preview (LLM020; 0.8.6) |
| Streaming completions not cancelled when the client disconnects | preview (LLM017; 0.8.1, 13 of 13 true on the corpus) |
| No per-user or per-request cost limit | preview (LLM023 per user; the per-request token cap is LLM003; 0.8.6) |
| Prompts or completions with personal data written to logs | preview (LLM018; 0.8.1) |
| Model output used as SQL, a shell argument or a file path (extends LLM002) | done (LLM002: SQL, shell commands, file paths); preview (LLM019: arguments of programs run without a shell; 0.8.6) |
| LLM features without a test or eval of their prompt | preview (LLM024; 0.8.6) |
| Agent config files granting auto-approve or broad shell and file access | preview (LLM016: Claude Code, Cursor, VS Code, Gemini and Codex settings, MCP autoApprove, skip-permission flags; 0.8.1) |
| Foreign keys without an index | preview (DATA012; 0.8.3) |
| Postgres `CREATE INDEX` without `CONCURRENTLY` in migrations | preview (DATA011; 0.8.3) |
| Vector stores keeping raw personal data in metadata | preview (DATA014; 0.8.8) |
| Redis keys without a TTL | preview (DATA013; 0.8.3) |
| Multi-step cache invalidation without a lock (stampede) | preview (DATA015; 0.8.8) |
| Cron and queue jobs that are not idempotent | preview (DATA016; 0.8.8) |
| Dockerfile multi-stage builds copying secrets into layers | preview (CFG017; 0.8.3) |
| Kubernetes: no resource limits, privileged containers, hostPath | preview (CFG012, CFG013; 0.7.0) |
| Terraform and CloudFormation: public S3, open security groups, unencrypted storage | preview (CFG014, CFG015; 0.7.0, AWS); CFG016 stable since 0.9.0 |
| Third-party GitHub Actions not pinned to a SHA | stable (CFG010; 0.7.0, stable since 0.9.0) |
| Secrets passed to untrusted steps or forks | preview (CFG018, pull_request_target with the head checked out; 0.8.8) |
| Over-broad `GITHUB_TOKEN` | preview (CFG011, `write-all`; 0.7.0) |
| Transitive vulnerabilities from lockfiles, with OSV offline data | preview (DEP009; 0.8.5) |
| Phantom JS dependencies (only transitive in the lockfile) | done (QA007 reports every import missing from package.json); QA007 back in preview since 0.11.0 |
| Registry confusion (private scopes without a registry, `extra-index-url`) | preview (DEP008, pip extra indexes; 0.7.0). npm scopes: done (DEP001 reports a scoped package that is not on npm and has no registry in .npmrc; online; regression test in 0.9.0) |
| Duplicate utility functions across files | stable (QA011; 0.8.4, stable since 0.9.0) |
| Mixed framework idioms (App Router and Pages Router in one app) | preview (QA009; 0.8.4) |
| Fake fallbacks and mock relics in production code | preview (QA010; 0.8.4) |

## Phase 2: `vibeaudit fix` (done, 0.8.6)

| Item | Status |
| --- | --- |
| Codemods (diff by default, `--apply`): request timeouts, output token limits, guarded `JSON.parse` of model output, pinned JWT algorithms, Decimal money columns, CORS credentials | done (0.8.0; REL001, LLM003, LLM011, BE016, AUTH011, DATA004, BE012) |
| Codemod for Redis TTL | done (DATA013; 0.8.6) |
| Codemod for `rel="noopener noreferrer"` | not planned: browsers apply noopener to target=_blank by default since 2021 |
| Agentic patch generator for complex findings (writes a `.patch`, never applies it) | done (`vibeaudit fix --llm`; 0.8.0) |
| MCP `auto_repair` tool returning the diff | done (0.8.0) |

## Phase 3: everywhere it runs (done, 0.8.6)

| Item | Status |
| --- | --- |
| `vibeaudit watch` (incremental re-scan) | done (0.8.1; unchanged files and per-file checks are reused) |
| Language server with diagnostics and code actions | done (`vibeaudit lsp`; 0.8.2) |
| VS Code / Cursor extension (.vsix built in CI, not published) | done (`editors/vscode`; 0.8.2) |
| `vibeaudit studio` local web UI (127.0.0.1 only) | done (routes, data flows, score drill-down; token, Host check, CSP; 0.8.6) |
| PR review bot and `--fail-on-regression N` | done (`vibeaudit review`, action input `review`; 0.8.3) |
| Pre-commit fast path under 150 ms | done (`vibeaudit-secrets` hook, 0.8.3; budget enforced in CI on Linux) |
| MCP tools: audit_current_file, verify_package, simulate_migration | done (0.8.3; auto_repair: done in Phase 2) |
| GitLab CI and CircleCI templates | done (`ci/`; `junit` and `codeclimate` reports; 0.8.5) |
| Monorepo mode | done (`--monorepo`: one project per package, a score per package; 0.8.4) |
| Offline / air-gapped mode with bundled data | done (`update --export/--import`, offline OSV index, no network in `--offline`; 0.8.4) |
| `vibeaudit explain <finding>` | done (rule, code and the data flow traced back from the line; 0.8.5) |

## Phase 4: compliance and threat intelligence (done, 0.9.0)

| Item | Status |
| --- | --- |
| Rule mapping to OWASP Top 10 2021, OWASP LLM Top 10 2025, EU AI Act themes, SOC 2, HIPAA, GDPR (a mapping, not certification or legal advice) | done (data/compliance_map.json; a test requires every rule to have an entry; 0.9.0) |
| `--report compliance:<framework>` (HTML and printable output) | done (0.9.0) |
| Signed threat-intel feed in `vibeaudit update`: slopsquatted names, model sunset calendar, prompt-injection patterns, community submissions; works offline | done (DEP001, LLM012, LLM025; 0.9.0); the packaged data is used, and the signed feed is not active until the maintainer's one-time key setup (docs/THREAT_FEED.md) |

## Completion gate: 0.9.0, "Phases 0-4 complete" (done)

Phases 5 and 6 start only after this gate holds. Order until then: finish Phase 1, then Phase 4 (compliance
mapping and reports first; the threat feed after the Phase 3 items).

| Condition | Status |
| --- | --- |
| Every Phase 0-4 item is done, or marked preview with its measured reason; nothing left planned without a reason | done (0.9.0) |
| Full audit: correctness, adversarial inputs, false-positive sweep on the corpus, docs versus behaviour | done ([docs/AUDIT-0.9.0.md](docs/AUDIT-0.9.0.md)) |
| Packaging: the built wheel in a fresh virtual environment, every command; Python 3.9-3.13 on Linux, macOS and Windows | done (CI matrix and the audit's fresh-environment run) |
| No reproducible high or medium audit finding | done (four medium findings fixed: #30 to #33) |
| Green CI and benchmark gate, then a verified signed release (0.9.0) | done (0.9.0) |

## Independent review follow-ups (0.9.1 to 0.9.3)

| Item | Status |
| --- | --- |
| README accuracy numbers generated from the benchmark, stable and all-rule numbers apart, test on mismatch | done (0.9.1) |
| Recall, F1 and false negatives: advisory ground truth plus seeded cases, per category and framework (docs/BENCHMARK.md) | done (0.9.1) |
| Head-to-head with Semgrep and Bandit on the same corpus, in CI | done (0.9.1; same 6 of 17 advisory locations for all three tools) |
| Public sample report on GitHub Pages | done (0.9.1) |
| Second-labeller kit: blind sample, instructions, Cohen's kappa | done (0.9.1); waiting for volunteer labellers |
| PyPI trusted publishing | done (0.9.1); on since 0.9.3 (docs/PUBLISHING.md) |
| Cross-function taint: Python (0.9.1) and JavaScript/TypeScript (0.9.2) | done |
| Router prefixes for FastAPI, Flask and Express | done (0.9.3) |
| UI checks on Vue and Svelte components | done (0.9.3) |
| Demotions after a fresh held-out repository: AUTH001 (stable again in 0.9.3), UI014 | done; UI014 stays preview (6 of 7 held-out) |

## Phase 5: more languages (done in 0.11.0, as preview until measured on enough held-out findings)

| Item | Status |
| --- | --- |
| Go (net/http, Gin, Echo, Fiber, Chi, GORM) | preview (0.10.0: a lexer, routes with auth middleware, data flow into the generic sinks, go.mod dependencies, GO001-GO004; 10 labelled repositories, 3 held out) |
| Java/Kotlin (Spring Boot, Quarkus) | preview (0.10.0: a lexer, Spring and JAX-RS routes with the security configuration, data flow into the generic sinks, Maven/Gradle dependencies, JAVA001-JAVA004; 10 labelled repositories, 3 held out) |
| C#/.NET (ASP.NET Core, EF Core) | preview (0.11.0: a lexer, controller and minimal-API routes with the authorization model, data flow into the generic sinks, NuGet dependencies, CSHARP001-CSHARP003; 11 labelled repositories, 2 held out) |
| Rust (Actix, Axum) | preview (0.11.0: a lexer, Actix and Axum routes with scopes, nesting and auth middleware, data flow into the generic sinks, Cargo dependencies; 11 labelled repositories, 3 held out) |
| PHP (Laravel, Symfony) | preview (0.11.0: a lexer, Laravel routes with groups, middleware groups and controller middleware, Symfony attributes with IsGranted and access_control, data flow into the generic sinks, Blade output, Composer dependencies; 10 labelled repositories, 3 held out) |

## Phase 6: opt-in extras (done)

| Item | Status |
| --- | --- |
| `vibeaudit test-exploit <finding>`: proof-of-concept request, localhost only, no destructive payloads | done |
| Runtime observability middleware for Express and FastAPI (staging only, off by default) | done |

vibeaudit is on PyPI: each release's attested wheel and sdist are uploaded by trusted publishing from the release
workflow (docs/PUBLISHING.md). The VS Code extension is not on a marketplace.
