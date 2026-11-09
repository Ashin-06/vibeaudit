# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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
- 73 rules in 8 categories: secrets, dependencies and supply chain, backend, frontend,
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
