# 0.9.0 completion-gate audit

This audit ran on main at Phase 4 (the 0.8.8 release plus the threat feed and compliance reports, #28) before
0.9.0. It covers four passes: packaging, docs against behaviour, adversarial input and a security review.
Every high or medium finding has a fix in its own pull request with tests. Low findings are listed at the end;
some were fixed along the way, the rest are open.

## Summary

| ID | Severity | Finding | Fix |
| --- | --- | --- | --- |
| A1 | medium | Input nested too deeply to parse (a `RecursionError`, not a `ValueError`) crashed the scan, hung the LSP server and stopped the MCP server | #30 |
| S1 | medium | On Windows another local process could bind the studio's port and answer in its place (`SO_REUSEADDR`) | #31 |
| S2 | medium | A scanned repository's `.vibeaudit.toml` `llm` key made the LSP server, watch, studio, the MCP tools and the Python API send its code to a model provider | #32 |
| D1 | medium | The VS Code extension's README said `pip install vibeaudit`; the name is unclaimed on PyPI | #33 |
| A2 | low | A forged bundle (zip headers that lie), an unwritable report path and a studio request with too many query parameters ended in a traceback | #34 |

No high findings. Nothing in pass 3 wrote outside the places it should, served a file it should not, or let a
path or symlink escape the project.

## Pass 1: packaging

Built the wheel (`python -m build`), installed it into fresh virtual environments on Python 3.9 and 3.13 and ran
every command from the installed package against copies of two corpus repositories (chatbot-ui, a Next.js app,
and opengpts, a Python and React app), with a private cache folder. 63 checks per Python version:

- The wheel holds every data file (popular-package lists, retired models, threat data, compliance map) and the
  studio assets, and both entry points (`vibeaudit`, `vibeaudit-hook`).
- `--help` for every command, and `--version`.
- `scan` with every report format at once (json, sarif, md, html, prompt, badge, junit, codeclimate and
  `compliance:` for all six frameworks): every file written, and the JSON ones parse. Also `--fail-on`, `--staged`,
  `--diff`, `--include-preview`, `--min-severity`, `--disable`, a baseline round trip and JSON on stdout.
- `routes` (text, json), `rules` (text, json, md), `explain` (by location, by fingerprint, an unknown finding).
- `fix` (dry run, `--apply`, and a second `--apply` that changes nothing); the printed diff applies with `git apply`.
- `review --diff main` on a branch that adds a secret mentions it; nothing is posted without `--post`.
- `feedback` (mark, list), `vibeaudit-hook` (blocks a staged token, passes a clean commit; agrees with
  `scan --staged` on severity).
- `update` (refresh, with no feed key yet: logs it and uses the shipped data), `--export`, `--import`, a junk
  bundle (exit 1), `--osv` without `--export` (exit 2).
- `watch`: a new file with a token is reported as new and its removal as fixed.
- `mcp` over stdio: initialize, tools/list (9 tools), `scan_project`.
- `lsp` over stdio: initialize, didOpen of an unsaved buffer, diagnostics published, shutdown and exit 0.
- `studio`: the page loads, the API answers with the token and returns 403 without it.

Everything passed on both versions. Three early failures were mistakes in the harness (a wrong MCP tool name, an
AWS key id that is rightly only medium, and `input()` in a script, which is not request data), not in vibeaudit.

## Pass 2: docs against behaviour

- Every `vibeaudit` command line in README.md, CONTRIBUTING.md, SECURITY.md, STABILITY.md, docs/THREAT_FEED.md
  and the VS Code README was parsed and each option checked against the real argument parser: all exist.
- Every config key in the README's TOML examples and its "Other keys" list exists in `config.KEYS`, and every key
  is documented.
- The examples were run: the sample scan output matches its counts (45 findings, offline), `fix > fixes.patch &&
  git apply fixes.patch` works, `fix --rule`, `scan --monorepo`, `-r compliance:...`, `watch --interval
  --min-severity`, `feedback ... --note`, `update --export/--import`.
- D1 (medium, #33): `editors/vscode/README.md` said `pip install vibeaudit`. vibeaudit is not on PyPI and the name
  is free, so that command would install whoever registers it, the slopsquatting vibeaudit itself warns about.
- Low, fixed in #33: the README's sample "Domains" line was out of date, and `review --max-comments` and `--path`
  (explain, feedback) were not documented.

## Pass 3: adversarial input

171 cases, plus a separate run of 20 deeply nested files:

- CLI: 41 malformed argument sets (missing paths, bad formats, `compliance:` with no framework, huge numbers,
  NUL and lone surrogates, unknown rules, bad revisions) and 25 random flag combinations. All end with exit 0, 1
  or 2 and a message, except an overlong report path (A2).
- Config: 28 hostile `.vibeaudit.toml` files (wrong types, negative and infinite numbers, NaN, NUL, a BOM, nested
  tables, a 100 KB value): all rejected or applied cleanly.
- MCP: 30 malformed messages (wrong JSON types, wrong argument types for every tool, unknown tools, paths outside
  any project, a 20,000-statement migration, a 5,000-character package name) and a 60 MB line: each gets an error
  reply and the server keeps serving.
- LSP: 15 cases (negative and huge Content-Length, headers without a colon, a 20 KB header, binary and short
  bodies, wrong parameter types, URIs outside the workspace, UNC and `..` URIs, huge ranges, object ids).
  Malformed frames stop the server with exit 1, never a hang. A client that sets the workspace root to a whole
  drive gets a whole-drive scan (L2).
- Studio HTTP: 20 raw requests (`..` and encoded `..`, absolute and outside paths in `/api/code`, a symlink out of
  the project, wrong and non-ASCII tokens, `Host` variants, a 70 KB URL, 200 headers, OPTIONS and TRACE, a huge
  Content-Length, a TLS hello, HTTP/0.9). Nothing outside the scanned files is served, the server stays up, and
  only a request with more than ten query parameters raised in the handler (A2).
- Bundles: names with `..`, absolute paths, duplicate members, a 300 MB member and a zip whose headers declare a
  smaller size than the data. Nothing is written or escapes, and all but the last are rejected with a message;
  that one ended in `BadZipFile` (A2).
- `fix --apply` does not follow a symlink to a file outside the project.
- Deep nesting (A1, medium, #30): a `package.json`, `tsconfig.json`, `pyproject.toml`, config, feedback or baseline
  file, a bundle manifest, the threat feed, an installed OSV index or a cache file nested 100,000 levels deep
  crashed vibeaudit with a `RecursionError`. One such file in a scanned repository hid every finding. The same input
  killed the LSP reader thread (the server then hung) and stopped the MCP server.

## Pass 4: security review

- **Studio:** binds 127.0.0.1 only, needs the token on every API request (constant-time comparison), checks the
  `Host` header (DNS rebinding), serves only files the scan listed, sends a strict CSP and renders repository text
  with `textContent`. A cross-site POST cannot reach `/api/rescan`, because the token header forces a preflight
  the server does not answer.
  - S1 (medium, #31): `http.server` sets `SO_REUSEADDR`, and on Windows that let a second process bind the same
    port (verified). That process would receive the browser's requests and could serve a page that reads the
    token from the URL.
- **LSP and MCP:** messages are size-capped, handler errors are answered, URIs outside the workspace are ignored,
  and the MCP tools check every argument's type. Neither honours `--no-config`, which matters for:
  - S2 (medium, #32): the `llm` keys of the scanned repository's own config were applied by `project_options`, so
    opening an untrusted repository in an editor running `vibeaudit lsp` (or in studio, or an agent calling the
    MCP tools) sent its code to a model provider on the user's key at every re-scan. Now only `vibeaudit scan`,
    which has `--no-config`, reads them. The VS Code extension already refuses untrusted workspaces.
- **Feed verification:** RSA PKCS#1 v1.5 with SHA-256, standard library only. The whole encoded block is rebuilt
  and compared in constant time, rather than parsed. The signature covers the version and expiry; `update` rejects
  tampered, wrong-key, expired and older feeds; scans fall back to the shipped data with a warning. Low points:
  L5, L6.
- **Review bot:** the API URL must be https; pagination follows only links on the API host; earlier comments are
  recognised only from bot accounts, so a pull request author cannot pre-post the marker; `@` mentions and HTML
  comments in repository text are neutralised. Low point: L1.

## Low findings

| ID | Finding | Status |
| --- | --- | --- |
| A2 | Damaged bundle, unwritable report path and an oversized studio query ended in a traceback | fixed in #34 |
| L1 | A suggested fix containing a run of four or more backticks closes the review comment's suggestion fence early, so the rest renders as Markdown with mentions not neutralised (the pull request author could post the same mentions directly) | open |
| L2 | The LSP server scans whatever root the client sends, including a whole drive; the client chooses it | open, by design |
| L3 | The LSP server caps each open document at 32 MB but not how many are open; the editor is the only client | open |
| L4 | The MCP tools accept any directory and return finding snippets from it; the agent calling them can read those files anyway | open, by design |
| L5 | The feed's public key size is not checked (the shipped key is 3072-bit) | open |
| L6 | A bundle may install a validly signed feed that is older than the installed one (only within its 30-day validity); `update` refuses this, `--import` does not | open |
| L7 | Studio uses one thread per connection with no timeout for slow clients; it is reachable from this computer only | open |
| L8 | An AWS access key id alone is medium, so the hook's default `--fail-on high` lets it be committed (a secret key next to it is high and blocks); the same severity as `scan` | open, by design |
| L9 | Unused imports in datascan.py, explain.py, opsscan.py and projectscan.py | open |
| L10 | The README's sample "Domains" line was out of date; `review --max-comments` and `--path` were undocumented | fixed in #33 |

## How to reproduce

The harnesses live outside the repository (they build virtual environments and copy corpus repositories). Pass 1
is a driver around the installed wheel and the corpus cache from `tools/benchmark.py fetch`. Pass 3 drives the
same entry points in-process and over sockets. The regression tests that came out of the findings are in
`tests/test_deep_nesting.py`, `tests/test_config_llm_scope.py`, `tests/test_input_errors.py`, `tests/test_studio.py`
and `tests/test_lsp.py`.
