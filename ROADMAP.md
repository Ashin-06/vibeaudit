# Roadmap

Status: **done** (released, stable), **preview** (released as a preview rule or feature, see
[STABILITY.md](STABILITY.md)), **planned** (not started). Updated with every release. New rules always ship
as preview first and leave preview only at 90% precision or more on the [benchmark](benchmark/README.md).

## Phase 0: prove the rules are accurate (0.6.0)

| Item | Status |
| --- | --- |
| Labelled benchmark corpus: 53 pinned public repositories (12 held out; pre-fix advisory commits and training apps since 0.8.0), labels per finding | done |
| Precision per rule and seeded recall (`tools/benchmark.py`), table and JSON results | done |
| CI regression gate against a stored baseline, tolerant of network failures | done |
| Rule stability policy and preview rules (`--include-preview`) | done |
| Signed build provenance and CycloneDX SBOM on every release | done |
| Accuracy section in the README | done |

## Phase 1: new checks (0.7.x)

| Item | Status |
| --- | --- |
| React server actions leaking secrets or server closures to the client | planned |
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
| Open redirects and SSRF in "fetch this URL" features (extends BE005/BE008) | planned |
| JWT verified without pinned algorithms (alg none, HMAC/RSA confusion) | preview (AUTH011; alg none is BE016; 0.7.2) |
| Password change or reset not revoking sessions and refresh tokens | planned |
| Queries not scoped to the current tenant or org (extends AUTH003) | planned |
| Feature flags or admin toggles reachable without auth | planned |
| User text in prompts without delimiters (extends LLM001) | planned |
| RAG ingestion storing unsanitised text or instructions (chunk poisoning) | planned |
| Agent tool loops without a max iteration limit (extends LLM009) | planned |
| Streaming completions not cancelled when the client disconnects | planned |
| No per-user or per-request cost limit | planned |
| Prompts or completions with personal data written to logs | planned |
| Model output used as SQL, a shell argument or a file path (extends LLM002) | planned |
| LLM features without a test or eval of their prompt | planned |
| Agent config files granting auto-approve or broad shell and file access | planned |
| Foreign keys without an index | planned |
| Postgres `CREATE INDEX` without `CONCURRENTLY` in migrations | planned |
| Vector stores keeping raw personal data in metadata | planned |
| Redis keys without a TTL | planned |
| Multi-step cache invalidation without a lock (stampede) | planned |
| Cron and queue jobs that are not idempotent | planned |
| Dockerfile multi-stage builds copying secrets into layers | planned |
| Kubernetes: no resource limits, privileged containers, hostPath | preview (CFG012, CFG013; 0.7.0) |
| Terraform and CloudFormation: public S3, open security groups, unencrypted storage | preview (CFG014, CFG015, CFG016; 0.7.0, AWS) |
| Third-party GitHub Actions not pinned to a SHA | preview (CFG010; 0.7.0, 19 of 19 true on the corpus) |
| Secrets passed to untrusted steps or forks | planned |
| Over-broad `GITHUB_TOKEN` | preview (CFG011, `write-all`; 0.7.0) |
| Transitive vulnerabilities from lockfiles, with OSV offline data | planned |
| Phantom JS dependencies (only transitive in the lockfile) | done (QA007 reports every import missing from package.json) |
| Registry confusion (private scopes without a registry, `extra-index-url`) | preview (DEP008, pip extra indexes; 0.7.0). npm scopes: planned |
| Duplicate utility functions across files | planned |
| Mixed framework idioms (App Router and Pages Router in one app) | planned |
| Fake fallbacks and mock relics in production code | planned |

## Phase 2: `vibeaudit fix`

| Item | Status |
| --- | --- |
| Codemods (diff by default, `--apply`): request timeouts, output token limits, guarded `JSON.parse` of model output, pinned JWT algorithms, Decimal money columns, CORS credentials | done (0.8.0; REL001, LLM003, LLM011, BE016, AUTH011, DATA004, BE012) |
| Codemods for `rel="noopener noreferrer"` and Redis TTL | planned (waits for a rule that reports them) |
| Agentic patch generator for complex findings (writes a `.patch`, never applies it) | done (`vibeaudit fix --llm`; 0.8.0) |
| MCP `auto_repair` tool returning the diff | done (0.8.0) |

## Phase 3: everywhere it runs

| Item | Status |
| --- | --- |
| `vibeaudit watch` (incremental re-scan) | done, unreleased (unchanged files and per-file checks are reused) |
| Language server with diagnostics and code actions | planned |
| VS Code / Cursor extension (.vsix built in CI, not published) | planned |
| `vibeaudit studio` local web UI (127.0.0.1 only) | planned |
| PR review bot and `--fail-on-regression N` | planned |
| Pre-commit fast path under 150 ms | planned |
| MCP tools: audit_current_file, verify_package, simulate_migration | planned (auto_repair: done in Phase 2) |
| GitLab CI and CircleCI templates | planned |
| Monorepo mode | planned |
| Offline / air-gapped mode with bundled data | planned |
| `vibeaudit explain <finding>` | planned |

## Phase 4: compliance and threat intelligence

| Item | Status |
| --- | --- |
| Rule mapping to OWASP Top 10 2021, OWASP LLM Top 10 2025, EU AI Act themes, SOC 2, HIPAA, GDPR (a mapping, not certification or legal advice) | planned |
| `--report compliance:<framework>` (HTML and printable output) | planned |
| Signed threat-intel feed in `vibeaudit update`: slopsquatted names, model sunset calendar, prompt-injection patterns, community submissions; works offline | planned |

## Phase 5: more languages (planned, not started)

| Item | Status |
| --- | --- |
| Go (net/http, Gin, Fiber, Chi, GORM) | planned |
| Java/Kotlin (Spring Boot, Quarkus) | planned |
| C#/.NET (ASP.NET Core, EF Core) | planned |
| Rust (Actix, Axum) | planned |
| PHP (Laravel, Symfony) | planned |

## Phase 6: opt-in extras (planned, not started)

| Item | Status |
| --- | --- |
| `vibeaudit test-exploit <finding>`: proof-of-concept request, localhost only, no destructive payloads | planned |
| Runtime observability middleware for Express and FastAPI (staging only, off by default) | planned |

vibeaudit is not published to PyPI or any marketplace by this project; packages are built in CI and
attached to GitHub releases.
