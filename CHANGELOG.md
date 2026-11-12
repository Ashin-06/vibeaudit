# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.8.6] - 2026-11-12

Phase 1 adds the remaining LLM checks; Phases 2 and 3 are complete with `vibeaudit studio` and the Redis TTL codemod.

### Added

- Six preview rules for LLM features:
  - LLM019: model output passed as an argument of a program run without a shell (`git checkout <answer>`),
    where a value such as `--upload-pack=...` becomes an option. Arguments after `--` are not reported.
  - LLM020: an agent loop that calls the model for as long as it asks for tools, with no step limit.
  - LLM021: user text placed in a prompt without delimiters, so instructions inside it read like yours.
  - LLM022: web pages or files loaded into a vector store with no cleaning step (chunk poisoning).
  - LLM023: model calls for signed-in users with nothing tracking tokens or cost per user (apps where users
    bring their own API key are skipped).
  - LLM024: a project with tests, none of which touches its LLM code, and no eval setup.
- Tests that pin down two Phase 1 items existing rules already cover: model output used as SQL, a shell
  command or a file path (LLM002), and "fetch this URL" features and redirects fed by request data (BE005,
  BE008).
- `vibeaudit studio`: a local web UI (127.0.0.1 only, token-protected) with routes, data flows and a score
  drill-down.
- `vibeaudit fix` adds an expiry to Redis keys (DATA013): `ex=3600` / `EX` on `set`, or an
  `expire(key, 3600)` after hash, list, set and sorted-set writes.

### Changed

- The fuzz test's time budget uses the median of three calibration runs, so slow shared CI runners no longer
  fail it; it still catches super-linear paths.

## [0.8.5] - 2026-11-12

Phase 1 adds vulnerable transitive dependencies; Phase 3 adds `vibeaudit explain` and CI templates.

### Added

- DEP009 (preview): packages installed through a lockfile that no manifest names, checked for known
  vulnerabilities: npm, pnpm, yarn and bun lockfiles, and poetry, uv, pdm and Pipfile lockfiles. Packages the
  lockfile marks as development-only are left out. With `--offline` it uses the imported OSV index; online it
  makes its own OSV query, so a failure there never hides the direct dependencies' results.
- `vibeaudit explain FINDING`: the rule, the code and the data flow traced back from the finding's line.
- GitLab CI and CircleCI templates (`ci/`), and `junit` and `codeclimate` report formats.

### Changed

- Vulnerability messages say "1 known vulnerability" instead of "1 known vulnerabilities".

## [0.8.4] - 2026-11-12

Phase 1 adds the AI-slop checks; Phase 3 adds monorepo mode and offline use.

### Added

- Three preview rules for code that AI assistants tend to leave behind:
  - QA009: Pages Router code in an App Router file: `getServerSideProps` and the other Pages Router data
    functions (never called there), `next/router` (throws there), and metadata exported from a
    "use client" file.
  - QA010: mock, fake or dummy data returned when a request fails, or used when a response is empty
    (`?? mockPosts`, `or get_fake_items()`). Mocks behind an explicit switch (`USE_MOCKS`, `NODE_ENV`) and
    stand-ins for optional imports are not reported.
  - QA011: the same function, with the same code, in several files of one package. Benchmark and eval
    scripts, agent skills and separately deployed Supabase functions are each treated as standalone.
- `--monorepo`: every package is scanned as a project of its own, against its own manifest and evidence, with
  a score per package.
- Offline and air-gapped use: `vibeaudit update --export/--import` carry the data, including an OSV
  vulnerability index, to a machine without network; `scan --offline` then checks known vulnerabilities
  against it.

## [0.8.3] - 2026-11-12

Phase 1 continues with data, storage and container checks; Phase 3 adds the pre-commit fast path, the PR review bot, three MCP tools and faster re-scans.

### Added

- Four preview rules for data, storage and containers:
  - DATA011: `CREATE INDEX` without `CONCURRENTLY` on a table that already exists, in a migration that can use
    it (Supabase and Prisma migrations run in a transaction and are skipped).
  - DATA012: a Postgres foreign key column with no index that starts with it. MySQL projects are skipped,
    since InnoDB indexes foreign keys by itself.
  - DATA013: a Redis key written with no expiry (`set`, `hset`, `lpush`, `sadd`, `zadd` and similar on a
    Redis client, with no `ex`/`EX` argument and no `expire` call for the key).
  - CFG017: a secret file (`.npmrc`, `.env`, private keys, cloud credentials) copied into the final image, a
    secret build argument used in the final stage, or a whole folder copied from a stage that held a secret.
- `vibeaudit-hook` and the `vibeaudit-secrets` pre-commit hook: the fast path. It checks only the staged lines
  for secrets, from the staged content and one `git diff` call, without scanning the rest of the project.
  CI holds it under 150 ms on a 3-file commit in a 300-file repository; `tools/hook_latency.py` compares it
  with the full `vibeaudit` hook on corpus repositories.
- `vibeaudit review --diff REV`: pull request review comments for the findings on changed lines, with a
  one-click GitHub suggestion when a `vibeaudit fix` codemod rewrites the line inside the diff. `--post`
  sends them with GITHUB_TOKEN and skips comments an earlier run already posted; the action posts them with
  `review: "true"`. Text from the repository is neutralised (no @mentions, no injected markers).
- `--fail-on-regression N`: fail when the whole project's score drops more than N points below the score in
  the `--baseline` report, computed before `--baseline`, `--diff` and `--staged` hide findings.
- MCP tools `audit_current_file` (unsaved content, incremental), `verify_package` (a block, caution or ok
  verdict, import-name mapping, where the project declares the package) and `simulate_migration` (a static
  PostgreSQL dry run: the lock each statement takes, table rewrites and data loss, with a safer alternative).

### Changed

- `watch`, `vibeaudit lsp` and the MCP `audit_current_file` re-scan only what changed: per-file checks are
  replayed when nothing they depend on changed, and the result still equals a fresh scan. A re-scan after
  one edit takes 0.13 to 0.46 s on the benchmark repositories (was 0.33 to 2.8 s).
- Faster scans of Poetry, uv and PDM projects: a lockfile is parsed once, not once per dependency.
- Dependabot also updates the editor extension's npm build tools; minimatch and glob are pinned to
  patched versions.
- The benchmark labels the new findings on the 53-repository corpus, and the seeded infrastructure app
  has a case for each new rule.

## [0.8.2] - 2026-11-12

Phase 3 continues with the language server and the editor extension; severe preview rules gate again.

### Changed

- Severe preview rules gate again. Command injection (BE002), dynamic code execution (BE003), unsafe
  deserialization (BE004), open redirect (BE008) and XSS (FE001) stay in preview with their measured
  precision, but their findings count toward `--fail-on`, the score and the grade by default: for these bug
  classes a miss costs more than a false alarm ([STABILITY.md](STABILITY.md)). This undoes, for these five
  rules, the default introduced when they moved to preview in 0.6.0 and 0.8.0.
- QA007 no longer reports `require("vscode")` in an editor extension (a package.json with `engines.vscode`).
- Git and external tools now run with stdin closed, so a scan started by a server that reads stdin on
  another thread cannot hang on Windows.

### Added

- `vibeaudit lsp`: a Language Server Protocol server (standard library only) with diagnostics, also for
  unsaved buffers, and the `vibeaudit fix` codemods as quick fixes. It never writes files and accepts only
  files inside the workspace.
- `editors/vscode`: a thin VS Code / Cursor extension that starts `vibeaudit lsp`, built as a `.vsix` in CI
  and not published. It runs only in trusted workspaces, and its server settings are machine-scoped.
- `--no-gate-severe-preview` and the configuration key `gate-severe-preview = false` leave the severe preview
  rules out of `--fail-on` and the score. `--include-preview` is unchanged.
- The `gates_in_preview` rule property, shown in `vibeaudit rules --format json`, docs/RULES.md
  (`preview, gates`) and as `"gates_in_preview": true` on findings in the JSON report.

## [0.8.1] - 2026-11-11

Phase 3 starts with `vibeaudit watch`; also AI agent and LLM checks. The new rules are preview.

### Added

- `vibeaudit watch [PATH]`: scans once, then re-scans when files change and prints the findings that
  appeared (`+`) or were fixed (`-`). Unchanged files keep their parse trees, and per-file checks whose
  inputs did not change replay their findings, so a re-scan matches a fresh scan at a fraction of the cost.
  QA006 also computes a module's exported names once per module, which makes every scan faster.
- LLM016: a coding agent allowed to act without asking: `bypassPermissions` or a bare `Bash` grant in
  `.claude/settings.json`, auto-approve settings for VS Code, Cursor and Gemini, MCP servers with every tool
  pre-approved, Codex `approval_policy = "never"` or `danger-full-access`, and scripts that start an agent
  with `--dangerously-skip-permissions`, `--yolo` and similar flags.
- LLM017: a streamed completion in a route that never passes the request's abort signal (JavaScript) or
  checks for a disconnected client (Python), so the model keeps generating after the user leaves.
  All 13 corpus findings are true (10 tuned, 3 held-out).
- LLM018: prompts, chat history or completions written to logs in files that call a model.

### Fixed

- Files in `.vscode/` were skipped, so the MCP check never read `.vscode/mcp.json`. They are scanned now.

## [0.8.0] - 2026-11-11

Phase 2 starts: `vibeaudit fix` repairs findings that have one obvious fix. The benchmark grows to 53
repositories so that more rules can be measured, and rules that the larger corpus shows under 90% move to
preview. No new rules.

### Added

- `vibeaudit fix`: a unified diff (or `--apply`) that fixes findings with one obvious repair: request
  timeouts (REL001), output token limits (LLM003), guarded parsing of model output (LLM011), pinned JWT
  algorithms (BE016, AUTH011), Decimal money columns (DATA004) and CORS origin allow-lists (BE012). A change
  is kept only when the file still parses; line endings and BOMs are kept.
- `vibeaudit fix --llm`: model-written patches for findings without a codemod, written to a `.patch` file
  and never applied.
- MCP tool `auto_repair`: the `fix` diff for a project or one file; it writes nothing.
- `tools/fix_corpus.py`: runs every codemod over the benchmark corpus and checks that the finding goes away,
  the file parses, nothing new is reported and a second run changes nothing.
- 13 benchmark repositories: 7 pinned to the commit before the fix of a published GitHub advisory
  (alerta, wsgidav, waline, flexible-graphrag, vibe-trading, adx-mcp-server, nodejs-whisper) and 6
  deliberately vulnerable training apps (NodeGoat, DVNA, pygoat, dvpwa, DVGA, damn-vulnerable-llm-agent).
  All 826 new findings were read and labelled; 4 of the repositories are held out.
- RESULTS.md reports precision for stable rules only and without the training apps. Stable rules: 94.7%
  tuned, 93.8% held-out. 50 rules now have at least 5 labelled findings (38 before).

### Changed

- Moved to preview with their measured precision: BE002 command injection (50%), BE003 dynamic code
  execution (36%), BE004 unsafe deserialization (36%), BE008 open redirect (83%), QA004 TODO left in code
  (87%), QA005 unfinished stub (0%), QA006 import that does not resolve (held-out 15%: `.js` imports of
  `.d.ts` files) and SEC011 hard-coded password (89%). They are still reported.

### Fixed

False positives on the tuned split, each with a regression test that fails on 0.7.2:

- A `@permission(...)` decorator now counts as an authentication check (AUTH001), and an authenticated
  webhook route no longer needs a signature (AUTH004).
- Unminified copies of well-known libraries (jQuery, Bootstrap, Materialize and others) are treated as
  vendored code.
- A query formatted from a `for name in ['a', 'b']` loop just above it is not reported as SQL injection.
- Helper scripts that print the token they fetch (SEC010), use a local default secret (SEC004), and
  database reset or seed files with demo users (SEC011) are not reported.
- A webhook view that verifies its sender's signature may be `csrf_exempt` (AUTH009).
- Published npm libraries (with a `files` list) and documentation requirement files need no lockfile (DEP005).

## [0.7.2] - 2026-11-11

Third Phase 1 release: API and auth checks, and a held-out benchmark split. The new rules are preview.

### Added

- AUTH011: `jwt.decode()` in Python without `algorithms`, and algorithm lists that mix HMAC with
  public-key algorithms (key confusion).
- AUTH012: a session cookie set without `SameSite` (or with `SameSite=None`) in a project with no CSRF
  protection.
- AUTH013: a webhook that checks an HMAC signature but no timestamp or event id, so a captured request can
  be replayed.
- AUTH014: a rate limit keyed on `X-Forwarded-For` taken as the client sent it.
- BE019: a payment amount or price read from the request and passed to the payment provider.
- BE020: email headers built by formatting values into the header line, or set straight from request data.
- A held-out benchmark split: 8 new pinned repositories (40 in total) whose findings are labelled but never
  used to tune a rule. Held-out precision is 89.7% (131 of 146); the tuned split is at 88.8%.
  [benchmark/RESULTS.md](benchmark/RESULTS.md) shows both per rule.

### Changed

- A rule now leaves preview only with 90% precision on at least 5 held-out findings
  ([STABILITY.md](STABILITY.md)).
- FE007 (hard-coded localhost URL) is preview: 6 of its 7 labelled findings are true.
- Seeded sample apps no longer pin dependency versions (they raised Dependabot alerts).

## [0.7.1] - 2026-11-11

Second Phase 1 release: frontend and accessibility checks. The new rules are preview.

### Added

- UI014: `<img>` without `width` and `height` or any sizing class or style (layout shift).
- UI015: a field error rendered next to an input with no `aria-describedby`, `role="alert"` or live region
  in the component, so screen readers never announce it.
- UI016: a focus outline removed (`outline-none`, `focus:outline-none`, CSS `outline: none` in a `:focus`
  rule) with no visible replacement. Text fields (the caret shows the focus), parts styled by their
  selected or open state, dialog and popover containers and `.min.css` files are not reported.
- UI017: `src`, `href` or `url()` pointing at an image, font, icon or document that is not in the app's
  `public` folder.
- UI007 also reports `window.innerWidth`/`innerHeight` and `crypto.randomUUID()` in server-rendered markup.
- 27 new labelled findings on the benchmark corpus (26 true, 1 false) and seeded cases for all four rules.

### Changed

- The release workflow can be run by hand to rehearse the build, SBOM and signing steps without creating
  a release. The pinned actions were updated to their current major versions (checkout 7, setup-python 7,
  cache 6, upload-artifact 7, attest-build-provenance 4).
- The fuzz test's time limit is scaled to the machine it runs on.

## [0.7.0] - 2026-11-11

First Phase 1 release: CI, supply-chain and infrastructure-as-code checks. All new rules are preview
([STABILITY.md](STABILITY.md)): reported, but not counted toward `--fail-on` or the score until they have
been measured at 90% or more on the benchmark for at least one release.

### Added

- CFG010: third-party GitHub Actions and reusable workflows used by tag or branch instead of a commit SHA
  (GitHub's own `actions/*` and `github/*` are not reported). 19 findings on the benchmark corpus, all true.
- CFG011: `permissions: write-all` in a workflow.
- DEP008: `--extra-index-url` / `extra-index-url` in requirements files, `pip.conf`, `pip.ini`, `uv.toml`
  and `pyproject.toml` (dependency confusion).
- Kubernetes manifests: CFG012 privileged containers, `hostPath`, `hostNetwork`, `hostPID`, `hostIPC`;
  CFG013 workloads whose containers set no resource limits (templated Helm `resources` is accepted).
- Terraform and CloudFormation (AWS): CFG014 public S3 bucket ACLs and disabled public access blocks;
  CFG015 security groups open to 0.0.0.0/0 or ::/0 on SSH, RDP or a database port (or every port);
  CFG016 RDS and EBS storage without encryption at rest, or encryption switched off.
- Seeded benchmark cases for all eight rules (`benchmark/seeded/infra_app`).

### Changed

- A requirements file with an extra index (for example the PyTorch wheel index) now also reports DEP008.
  That is the setup of the 2022 torchtriton dependency-confusion attack.

## [0.6.0] - 2026-11-11

Measurement and trust: every rule's accuracy is now measured on a labelled benchmark, and the rules were
fixed where it showed false positives. No new rules. Overall precision on the benchmark went from 56% to
88% with no true positive lost; details per rule in [benchmark/README.md](benchmark/README.md).

### Added

- Accuracy benchmark: 32 public repositories pinned to exact commits (AI-built apps, LLM apps,
  well-maintained Python and JavaScript projects, one deliberately vulnerable app), with all 524 findings
  read and labelled, plus seeded sample apps. `tools/benchmark.py` prints precision per rule and seeded
  recall ([benchmark/RESULTS.md](benchmark/RESULTS.md)).
- A CI job that fails when a rule's precision drops, a labelled true positive disappears or seeded recall
  drops. A repository that cannot be fetched is retried, then skipped and listed.
- Preview rules ([STABILITY.md](STABILITY.md)): reported, but not counted toward `--fail-on`, the score or
  the grade unless `--include-preview` (or `include-preview = true`) is given. Rule IDs never change
  meaning and are never reused.
- Releases are built by a workflow from the tag, with a CycloneDX SBOM and signed build provenance (GitHub
  artifact attestations) for the wheel, the sdist and the SBOM. See "Verifying a release" in the README.
- [ROADMAP.md](ROADMAP.md).

### Changed

- Eight rules are now preview because their measured precision is under 90%: BE018, DATA001, DATA007,
  DATA010, FE001, QA003, SEC003, UI006. Their findings are still reported; the reason is in
  `vibeaudit rules --format json` and docs/RULES.md. Pass `--include-preview` to gate on them as before.
- BE012 reports an open or reflected CORS origin only together with credentials (without credentials no
  cookies are sent, so another site cannot act as the logged-in user).
- QA003 reports only bare, `Exception` and `BaseException` handlers; naming a specific exception means the
  failure was expected.
- FE001 reports template `|safe` only on values named like user or model input (`user.bio`, `comment`,
  `answer`), not on CMS fields or generated docs.
- All GitHub Actions in this repository and in `action.yml` are pinned to commit SHAs.

### Fixed

False positives found by labelling the corpus, each with a regression test that fails on 0.5.2:

- Django `tests.py` modules were not treated as tests (and counted as "no tests"); code in a library's
  `examples/` folder was reported as application code (credentials are still reported there).
- Minified files with lines under 500 characters on average, and vendored builds kept readable
  ("Original source: .../dist/x-min.js"), were scanned as application code.
- DATA001 and BE001 in migrations, management commands, seed and setup scripts; BE001 on
  `Promise.all(rows.map(...))`.
- DATA007 on variables read only when set (`"X" in os.environ`, `if x:`, a default assigned on the next
  line, a ternary) and on examples inside prompt strings; a Python f-string interpolation still counts.
- BE008 on `url_for()`, `reverse()`, `redirect(model)` and the request's own origin with a fixed path.
- AUTH005 when a setup script enables Row Level Security; AUTH006 on policies `TO service_role`.
- AUTH001 when the handler calls an imported `getAuthedUser()`; AUTH004 with a constant-time signature
  comparison; AUTH003 on `req.auth?.user?.id`, `current_user().id` and admin-only routes; AUTH010 on
  token-based resets and routes that take no credential.
- SEC004 on an error message naming `cookieParser("secret")` and on base or dev settings that
  `production.py` replaces (also CFG006 and BE011, and dev and test settings files); SEC003 on `pub_` and
  `pk_` public keys; SEC011 in seed data files.
- BE003 on a module's own `eval()` function; BE015 on `random.SystemRandom()`; FE004 on Web Worker message
  channels; FE005 on WebAuthn credential ids; BE018 with `npm:zod` imports.
- UI001 and UI010 inside HTML and Django template comments; UI002 on backdrop overlays that close a
  dialog; QA003 with a comment above `pass`; QA005 on `__setitem__` raising NotImplementedError; QA007 on
  PEP 508 direct references (`name @ git+...`) and `djmoney`; DATA003 on `ALTER COLUMN ... TYPE ... USING`.
- Scanning code with an invalid escape sequence printed Python's SyntaxWarning.

## [0.5.2] - 2026-11-10

Fixes from a fourth external audit and from six audit passes run afterwards (a fresh read of the code,
hostile inputs, a real-repository sweep, long-lived process and concurrency, packaging, docs against
behaviour), plus documentation for public use. No new features. Each fix has a regression test that fails
on 0.5.1.

### Security

- A git revision starting with `-` was passed to git as an option. Through the MCP server
  (`changes: "--output=FILE"`) this made `git diff` write a file. Such revisions are refused.

### Fixed

- Secrets in minified files and in committed bundles under `dist/`, `build/` and `out/` were never checked;
  they now get the precise secret checks (provider keys, private keys, service-role JWTs, database URLs).
- 20,000 findings on one long line took 200 s: the inline ignore comment was searched once per finding.
  The project-wide `ATOMIC_REQUESTS` check was run once per route (98 s instead of 59 s for 10,000 files).
  Both are linear now; the test suite runs in about a third of the time.
- `scan()` called from two threads at once mixed up their settings (auth helpers, time budget); scans now
  run one at a time.
- MCP `scan_project` checks its arguments (a bad `min_severity` raised an internal error; `offline: "no"`
  was read as true); `check_package` rejects a non-string version.
- In a zero-context diff, an added line `++ x` looks like a file header and moved later changes to a file
  called `x`.
- LLM010: `search_kwargs` alone counted as a tenant filter.
- API001: a top-level parameter route (`/<slug>`, `app/[slug]`) was taken as proof of a missing prefix;
  template paths with a nested template literal ended early.
- BE007: `'%s' % request.url` into `render_template_string` was missed; the URL, path and Host are now
  taint sources (redirects to the request's own URL are not reported as open redirects).
- SEC004/SEC011 reported usage examples inside Python docstrings.
- QA005 reported `NotImplementedError` in base classes the project subclasses.
- QA007 reported imports under Python version or platform checks, and imports in `examples/` and `docs/`.
- `vibeaudit feedback` accepts absolute paths and backslashes.
- A cache entry with a non-numeric timestamp crashed saving the cache.
- `project_options()` (API, MCP) defaulted to `min_severity="info"`; it is `low`, as in the CLI.
- vibeaudit's own scan reported one finding on itself; it is clean again.
- BE001 reported SQL built from a variable that holds only fixed SQL text and bind markers
  (`where = f"tx IN ({','.join('?' * n)})"`); found on Rubicon and on sec-insights.
- QA003 reported the "this must raise" idiom (`raise AssertionError(...)` at the end of the try body,
  then `except SomeError: pass`).

### Changed

- Tests marked `network` (live registry and OSV) are opt-in (`python -m pytest -m network`); CI runs them
  in a step that cannot fail the build. The test fixture resets the registry circuit breaker per test.
- CI tests Python 3.10 as well; the action job passes a glob in `args`.

### Documentation

- README rewritten for people who have never seen the project: quickstart, every command and flag,
  configuration, CI, pre-commit, MCP, scoring, false positives, limits and what is not covered.
- New: `docs/RULES.md` (the full rule catalogue, generated by `tools/gen_rules_doc.py`),
  `CONTRIBUTING.md`, `SECURITY.md`, complete package metadata.
- `tests/test_docs.py` checks the docs against the code: flags, rules, config keys, examples, action
  inputs, versions.

### Audit findings that did not reproduce

None: all eight findings of the fourth audit reproduced.

## [0.5.1] - 2026-11-10

Fixes from a third external audit; no new features. Each fix has a regression test that fails on 0.5.0.

### Fixed

- The user cache was not thread-safe: registry lookups run in a thread pool, and a save during lookups
  could raise "dictionary changed size during iteration" or drop entries. Every access now holds the lock.
- `--no-cache` switched the cache off for the rest of the process. It now applies to one scan
  (`Options.cache`) and restores the previous setting.
- `vibeaudit update` had no effect on a running process (the MCP server) until restart: the compiled
  retired-model pattern and the loaded package lists are now dropped after a refresh.
- `vibeaudit feedback` could not mark DEP001, DEP003 or DEP004 (its scan was offline) nor findings from
  another settings file or plugin rules; dependency findings are now looked up online through the cache, and
  `--config` and `--plugin` are accepted.
- LLM010 missed a tenant filter built on the lines before the vector search, and reported the route line
  instead of the line of the search call.
- API001/API002 skipped template literals whose `${...}` parts contain quotes, and skipped
  `fetch("/api/users")` when the backend serves `/users`; that mismatch is now reported (with a hint) unless
  a rewrite or proxy is configured.
- DATA010 counted writes through a transaction client (`await tx.order.create(...)`) as outside a
  transaction.
- The test suite failed without `pip install -e` (the MCP test starts `python -m vibeaudit` in a child
  process, which did not see the checkout). Child processes now get `src` on `PYTHONPATH`, and CI runs the
  suite without installing on Linux and Windows. The test fixture now resets every cache, including LLM
  verdicts.

### Audit findings that did not reproduce

- UI013 and files in `public/` that are never loaded (PDFs, images): links whose last segment has a file
  extension were already skipped. Parallel `@slot` segments were already removed, and an intercepting
  `(.)photo` folder only adds a route next to the real one. Guard tests added.
- REL004 and the `Content-Length` header: the pattern is case-insensitive and its `.` matches both `-` and
  `_`. Guard test added.

## [0.5.0] - 2026-11-10

Learning and updates, plus fixes from a second external audit. Each fix has a regression test that fails
on 0.4.0.

### Added

- `vibeaudit feedback false-positive|confirmed RULE FILE:LINE [--note]` records a verdict in
  `.vibeaudit/feedback.json`; later scans hide findings marked as false positives (they follow the code
  when lines move). `vibeaudit feedback list` shows entries and per-rule counts. Ignored with `--no-config`.
- `vibeaudit update` refreshes the popular-package lists and the retired-model list (now
  `data/retired_models.txt`) from the repository, validating each file before use; `--self` upgrades the
  package with pip.
- Registry answers and OSV advisories are cached for a day ("package missing" for an hour), LLM triage
  verdicts for 30 days. `--no-cache` / `VIBEAUDIT_NO_CACHE=1` turns this off.
- `vibeaudit.project_options(path, **overrides)`; `vibeaudit.scan(path)` without options applies the
  project's configuration.

### Fixed

- The project configuration (`.vibeaudit.toml` / `[tool.vibeaudit]`) now reaches `vibeaudit.scan()`, the
  MCP tools, `vibeaudit routes` and `vibeaudit feedback`, not only `vibeaudit scan`.
- MCP `scan_file` finds the project root through `.vibeaudit.toml`, `pyproject.toml`, `package.json` and
  similar files when there is no `.git`; `check_package` resets the network circuit breaker per call.
- DATA004 checks every `.prisma` file (multi-file schemas), not only `schema.prisma`.
- DATA009 reports a nested `sqlite3.connect` once (it matched the unparsed text of every enclosing call).
- DATA006 follows `import datetime as dt` / `from datetime import datetime as DT` and `now(None)`; in SQL
  it only checks CREATE/ALTER TABLE (a `SELECT created_at timestamp` alias was reported).
- DATA008 covers DRF `@api_view`/`@action` and FastAPI `@api_route` handlers.
- DATA010 covers Python routes (Django ORM, supabase-py) and more JS write styles (`Order.create`, Drizzle
  `db.insert(orders)`, Mongoose `doc.save()`, `supabase.from(t).insert`); SDK calls such as
  `openai.embeddings.create` or `stripe.checkout.sessions.create` are not database writes.
- QA006 compares Python imports with module-level names (and `global` declarations and `__all__`);
  function parameters and locals were counted as exports. JS exports are read without comments, and
  `export { a as b }` exports `b`, not `a`.
- QA007 reports an undeclared package once per project (once per package.json) instead of once per file.
- QA008 reports the line of `@ts-nocheck`, also after a block-comment header, and skips generated files.
- `Containerfile` is checked like a Dockerfile.
- The GitHub Action no longer lets bash expand globs in `args` (for example `--exclude legacy/*`).
- `python -m pytest` works from a checkout without installing (pytest `pythonpath`).
- Dependencies are collected once per scan instead of twice; a duplicate key in the import-to-package map
  and a dead branch in the JS resolver were removed.

### Audit findings that did not reproduce

- Prisma, Netlify, Wrangler, Serverless, SAM, Pipfile, setup.cfg and requirements.in files "never loaded":
  every non-binary file is loaded whatever its type, and the checks match these files by name. The
  serverless and manifest cases have guard tests; the related Prisma gap (other `.prisma` names) is fixed.
- DATA002 with an unbalanced call: the slice was harmless (the follow-up search ran on an empty string);
  an explicit guard was added for clarity.
- DATA007 `os.getenv("X") or "default"` was already treated as having a fallback, and the `env.example`
  branch is reachable (files are matched by name); guard test added.
- The `.astro` extension is already a JS file kind.
- The JS lexer's brace depth can only go negative at the top level, where it is never read; inside a
  template expression it pops at zero.
- The default LLM model ids were reported as invalid; they are current ids and were left unchanged.

## [0.4.0] - 2026-11-10

Whole-app release: beyond security, vibeaudit now checks code completeness, data, reliability, more AI
risks, UI and accessibility, and whether the frontend calls routes that exist. 41 new rules (116 static
rules in 12 categories).

### Added

- Quality: QA005 unfinished stubs, QA006 imports of files or names that do not exist (Python and JS/TS,
  with tsconfig `paths` and `baseUrl`), QA007 packages imported but not declared, QA008 `@ts-nocheck`.
- Data: DATA001 queries in loops (N+1), DATA002 whole user records returned to the client, DATA003
  destructive migrations, DATA004 money as float, DATA005 private tables readable by everyone, DATA006
  timestamps without time zone, DATA007 env vars missing from the example env file, DATA008 a database
  client per request, DATA009 SQLite on a serverless host, DATA010 several writes without a transaction.
- Reliability: REL001 HTTP requests without timeout, REL002 blocking calls in async handlers, REL003
  webhooks that are not idempotent, REL004 uploads without a size limit, REL005 in-memory state on
  serverless hosts, REL006 deployed services without a health check.
- AI: LLM010 vector search without a user or tenant filter, LLM011 model output parsed as JSON without
  error handling (JSON mode and schemas are recognised), LLM012 retired model ids, LLM013 MCP servers with
  whole-disk access or plain HTTP, LLM014 secrets in MCP configs (reported once, instead of the generic
  secret rule), LLM015 agents that read untrusted content and have dangerous tools.
- UI, UX and accessibility: UI001 to UI013 (alt text, keyboard access, labels, dead controls, index keys
  on changing lists with inputs, unconfirmed deletes, hydration mismatches, effects without cleanup,
  missing loading or error states, lorem ipsum, missing Next.js error page, missing metadata or viewport,
  links to Next.js paths no page handles).
- Frontend-backend contracts: API001 calls to API paths no route handles, API002 calls with a method the
  route does not accept.
- A 0-100 score per domain (security, AI, quality, data, reliability, UI) in the terminal, JSON
  (`summary.domains`), Markdown and HTML reports.

### Fixed

- The placeholder pattern used by the secret rules was quadratic on a long run of `<` without `>`
  (2.3 s on 40,000 characters on a CI runner); it is now bounded.

### Notes

- Every new rule was run over the 15 real repositories used since 0.2.0; false alarms were fixed at the
  root, each with a regression test that was confirmed to fail when its fix is reverted.
- The contract rules skip projects whose routes use router prefixes (FastAPI `include_router`, Express
  `app.use`, Flask blueprints, Django URLconfs), because prefixes are not resolved yet.

## [0.3.0] - 2026-11-10

Integration release: vibeaudit now fits into editors, agents, pre-commit, pull requests and custom
policies.

### Added

- Configuration in `.vibeaudit.toml` or `[tool.vibeaudit]`: every scan option plus the project's own
  `auth-helpers`, `sanitizers` and `public-paths`. Flags override the file; unknown keys and wrong types
  are errors. `--config FILE` and `--no-config`.
- `--staged` and `--diff REV`: analyse the whole project, report only findings on added or changed lines.
- `vibeaudit routes`: every HTTP entry point with auth, data-write and AI-call status (text, JSON,
  Markdown); the JSON report gains a `routes` section.
- A GitHub Action (`uses: Ashin-06/vibeaudit@v0.3.0`) and a pre-commit hook (`id: vibeaudit`).
- `vibeaudit mcp`: a Model Context Protocol server with `scan_project`, `scan_file`, `list_routes`,
  `check_package` and `explain_rule`.
- A public Python API (`vibeaudit.scan`, `Options`, `Result`, `Finding`, `Route`) and custom rules
  (`rule`, `route_rule`, `file_rule`) loaded with `--plugin`.
- Report formats `prompt` (a fix brief for AI coding assistants) and `badge` (SVG score badge).

## [0.2.1] - 2026-11-09

Fixes for issues raised by an external review of the code. Each has a regression test that fails when the
fix is reverted.

### Added

- Pinned versions from `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `poetry.lock`, `uv.lock`, `pdm.lock` and
  `Pipfile.lock` are checked against OSV (previously only `package-lock.json` and `==` pins).
- AI001 is a registered rule, so it is listed by `vibeaudit rules` and can be disabled.

### Fixed

- JS lexer: `/>` after an expression (`<C p={1} />`) was read as the start of a regular expression, which
  could hide code on the rest of the line.
- Python: code inside `lambda` bodies was never analysed; lambdas passed to agent tools
  (`Tool(func=lambda cmd: ...)`) now get model-controlled parameters (LLM005).
- Folders named `env/` or `.env/` (for example `src/env/` in T3 and Next.js apps) were skipped as if they
  were virtual environments; only folders containing `pyvenv.cfg` are skipped now.
- JS data flow was per file: a variable tainted in one function was treated as tainted in every function
  of the file. It is now scoped to the function. Parameters of Next.js server actions (exported from a
  `"use server"` file or with an inline directive) are treated as request data.
- `--extra-index-url` (for example PyTorch wheels) no longer switches off the dependency checks for the
  whole requirements file; only `--index-url` / `-i`, which replace PyPI, do.
- The words "places", "replaces" or "workplaces" near a Google API key no longer hide the finding.
- An AWS secret access key ending in `+`, `/` or `=` inside quotes was missed by the AWS pattern.
- A comment mentioning rate limiting (`# TODO: add rate limit`) counted as rate limiting for the whole
  project; comments are now ignored for project-wide evidence.
- Secrets sent to an LLM are redacted more thoroughly: generic secret assignments, hard-coded passwords and
  signing secrets, in addition to provider keys, JWTs, private keys and env assignments.
- `--disable` accepts AI001 and external rule ids such as `bandit:B608`; inline
  `vibeaudit: ignore[...]` rule ids are case-insensitive.
- Two findings of the same rule on identical lines of one file now get distinct fingerprints, so a
  baseline entry cannot hide the other one.
- Documentation stated 73 rules; there are 75 static rules plus AI001. The SEC008 description lists
  NUXT_PUBLIC_ like the check does.

## [0.2.0] - 2026-11-09

Production-hardening release: fuzzing, property tests, a 15-repository false-positive sweep, network
failure tests and a scale test. Every bug below has a regression test that fails when the fix is
reverted.

### Added

- Per-file isolation: a file that triggers a bug no longer stops the scan; it is reported under
  `meta.internal_errors` while every other file is still analysed.
- `--file-timeout` (default 30 s): a cooperative per-file time budget. Files that exceed it, or are nested
  too deeply to parse, are listed under `meta.skipped`.
- Network resilience: retries with backoff for timeouts, resets and 408/425/429/5xx, honouring
  `Retry-After` (capped at 10 s), and a circuit breaker that stops calling a host after five
  consecutive failures. Only a 404 or 410 counts as "package does not exist".
- Test suites: fuzzing (`VIBEAUDIT_FUZZ_ROUNDS`), regular-expression timing, property tests with neutral
  mutations and safe rewrites, stubbed-transport network tests, a scale test (`VIBEAUDIT_PERF_FILES`),
  and a CI stress job.

### Fixed

- Hangs on hostile input: the Python lexer was quadratic on long single-line files (it now uses its own
  linear scanner instead of `tokenize`), and five regular expressions backtracked catastrophically on long
  runs of word characters or blank lines (generic secret assignments, `.env` lines, JS method
  definitions, auth stubs, statement continuation).
- Crashes on malformed `pyproject.toml`, `package-lock.json` and MCP configs, and on registry answers
  with unexpected JSON types.
- HTML reports are plain ASCII whatever the scanned code contains; report files tolerate file names that
  are not valid UTF-8.
- UTF-16 source files are decoded instead of being treated as binary.
- Symbolic links that point outside the project are not followed.
- Non-git folders: `.gitignore` files in subdirectories are honoured (monorepos).
- BE002 no longer flags `subprocess.run([...])` / `execFile(prog, [...])` argument lists; it fires when
  the program itself is controlled (or a shell is used), matching the rule's own fix advice.
- AUTH003 (IDOR) no longer treats the id path parameter itself (for example `user_id`) as proof of an
  ownership check.
- False positives found on real repositories: an AWS access key id alone is medium, not critical;
  database-image default passwords and enum values equal to their key are not hard-coded passwords;
  comparing two submitted passwords is not plaintext storage; `HTMLResponse` of a rendered template is
  not XSS; FastAPI auth through an `Annotated[..., Depends(...)]` alias is recognised; a browser OpenAI
  client pointed at the app's own backend is not a key leak; spreading request data into a model call is
  not mass assignment; `if x in ALLOWED` sanitises; dotted scope names are not secrets; committed `.env`
  templates with only placeholders are not reported; Supabase edge functions that require a bearer token
  (with gateway JWT verification on) count as authenticated.
- A regression introduced during this pass (a local variable shadowing the project in dependency
  collection) was caught by the sweep and fixed before release.

## [0.1.1] - 2026-11-09

### Fixed

- BE001 (SQL injection) no longer reports queries whose only formatted part is a list of bind markers,
  the standard pattern for a variable-length `IN (...)` list, for example
  `f"... IN ({','.join('?' * len(ids))})"`. Recognised forms: `"?" * n`, `["?"] * n`,
  `"?" for _ in ids`, `%s` placeholders via `%` or `.format()`, string concatenation, named or numbered
  markers built from a `range()` or `enumerate()` index (`f":p{i}"`, `f"${i + 1}"`), and the marker
  string or the query built in a separate variable first. Formatting values, identifiers or a join over
  data (`",".join(ids)`) is still reported.
- With `--external auto`, bandit checks that a built-in rule already covers with data flow (B102, B307,
  B201, B301, B506, B501, B602, B605, B608) are left to the built-in rule, so a line vibeaudit judged
  safe is not reported again by bandit. B101 (assert) was already ignored.

## [0.1.0] - 2026-11-09

First release.

### Added

- `vibeaudit scan` command with terminal output and JSON, SARIF 2.1.0, Markdown and HTML reports,
  `--fail-on`, `--min-severity`, `--offline`, `--exclude`, `--disable`, baselines and inline
  `vibeaudit: ignore[RULE]` suppressions.
- `vibeaudit rules` command (text, JSON, Markdown).
- 75 rules in 8 categories: secrets, dependencies and supply chain, backend, frontend,
  authentication and authorization, configuration and deployment, LLM and AI-specific risks, and code
  quality and tests. Mapped to CWE, OWASP Top 10 (2021) and OWASP Top 10 for LLM Applications (2025).
- Python analysis on the AST with taint tracking for request data, model output and agent-tool
  arguments.
- JavaScript and TypeScript (including Vue, Svelte and inline HTML scripts) analysis on
  offset-preserving lexer views, with client/server file classification.
- Route discovery and auth reasoning for Flask, FastAPI, Django REST framework, Express, Fastify, Hono,
  Next.js app router, pages router and server actions, SvelteKit, Supabase edge functions and Firebase
  functions, including middleware, router mounts and imported auth helpers.
- Supply-chain checks: missing packages on PyPI and npm, npm security-holding packages, packages newer
  than 30 days, typosquats of popular packages, and OSV vulnerabilities for pinned versions.
- Configuration checks for Supabase migrations, Firebase rules, Dockerfiles, Docker Compose, GitHub
  Actions and MCP server configs.
- Optional orchestration of gitleaks, osv-scanner, bandit and semgrep, with de-duplication.
- Optional LLM triage and review through Gemini, OpenAI-compatible or Anthropic APIs, with secret
  redaction and a hard request cap. Model verdicts annotate findings and never remove them.
- Test suite with five vulnerable fixture apps and one clean app, compared on exact
  `(file, line, rule)` sets, plus CI on Linux, macOS and Windows for Python 3.9 to 3.13.
