# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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
